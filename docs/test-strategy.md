# sabiden テスト戦略

> Status: Draft v1 (Issue #47)
> 対象範囲: `src/**` の Rust コード、`frontend/**` の SolidJS PWA、`workers/**` の Cloudflare Worker、CI (GitHub Actions)。
> 関連: [docs/ARCHITECTURE.md](ARCHITECTURE.md) (アーキテクチャ概要)、Issue #42 (mock ハーネス整理)、Issue #46 (architecture.md 詳細化、並列作成中)。

## 0. このドキュメントの位置づけ

sabiden は NTT ひかり電話 (NGN) を直接喋る SIP/RTP 実装である。仕様の一部は NTT のクセ (Via に rport を付けない、Session Timer 必須、IPv6 P-CSCF、DSCP 32 等) に強く依存しており、**「実機接続して気付くバグ」と「RFC を読めば分かるバグ」が混ざっている。** このため:

1. RFC で決まる挙動 → 高密度のユニットテスト + 引用付きコメント (失敗時に「RFC のどこ違反か」が読み取れる)
2. NGN/IMS のクセ → pcap fixture + 結合テスト (仕様書だけでは表に出ない挙動)
3. 全体の通話 → orchestrator 結合テスト + 実機 manual テスト

本書はこの 3 層の責務分担、カバレッジ目標、モック方針、CI 統合を **単一情報源** として定義する。以後すべてのテスト追加 PR はこの文書を参照し、必要なら本書を更新してから実装する。

現状 (2026-05-09) の集計:

- Rust テスト関数 ≒ **178 件** (`grep -rn "#\[test\]\|#\[tokio::test\]" src/`)
- フロントエンド/Worker テスト: **0 件**
- E2E (実機) テスト: 未自動化、INSTALL.md の手動手順のみ
- カバレッジ計測: 未導入

数字が「現在 202 テスト」と issue 本文に書かれているのは執筆時点の見積もりで、本書執筆時点の実測は 178。Issue #42 で集約完了後に再集計する。

---

## 1. 目的とテスト分類

### 1.1 目的

| 目的 | 手段 |
|------|------|
| **RFC 準拠の保証** (SIP 3261 / SDP 4566 / RTP 3550 / Digest 2617 / Session Timer 4028 / DHCP Opt 120 3361) | ユニット + 引用コメント |
| **NGN 直収のクセに対する回帰防止** (Via rport 抑止、IPv6 P-CSCF、DSCP 32、PCMU 固定、PPI/PAI ヘッダ等) | pcap fixture + 結合テスト |
| **通話成立 (E2E)** の保証 | orchestrator 結合 + 実機手動 |
| **観測性 (metrics / trace) の正しさ** | 観測点をユニットで pin |
| **PR ごとの fast feedback** | `cargo test` < 30s で全部通る範囲を unit に置く |

### 1.2 分類

```
┌─────────────────────────────────────────────────────────────────┐
│ Manual / 実機テスト  : NGN 接続 + Linphone + PWA、CI 対象外    │
├─────────────────────────────────────────────────────────────────┤
│ E2E                  : orchestrator + Mock NGN + Mock UA       │
│                        ≪ tokio::test、in-process socket ≫       │
├─────────────────────────────────────────────────────────────────┤
│ 結合 (Integration)   : 複数モジュール、in-process UDP / WS     │
│                        ≪ #[tokio::test] + 127.0.0.1:0 ≫         │
├─────────────────────────────────────────────────────────────────┤
│ ユニット (Unit)      : 1 モジュール内、純粋関数 / 構造体        │
│                        ≪ #[test]、外部 IO なし、< 1ms ≫        │
└─────────────────────────────────────────────────────────────────┘
```

| 種別 | 配置 | アノテーション | 特徴 | 想定ランタイム |
|------|------|----------------|------|----------------|
| Unit | `src/<mod>.rs` の `#[cfg(test)] mod tests` | `#[test]` | 外部 IO なし、純粋ロジック (パーサ・計算・ID 生成) | < 1 ms / 件 |
| Integration | 同上、または将来の `tests/` クレート | `#[tokio::test]` | UDP/TCP/WS は `127.0.0.1:0` でバインドして同一プロセス通信 | < 1 s / 件 |
| E2E | `src/call/orchestrator.rs::tests`、将来の `tests/e2e/` | `#[tokio::test]` | NGN → 内線 → RTP ブリッジまで全部繋ぐ (mock NGN UAS + mock 内線 UA + ブリッジ確認) | < 5 s / 件 |
| Manual | `docs/INSTALL.md` のチェックリスト | (なし) | 実 NGN P-CSCF、実 Linphone/Zoiper、実 ONU、実 IPv6 | 数分 / シナリオ |

### 1.3 「どのレイヤに置くか」決定木

```
新しい挙動を検証したい
  │
  ├── 外部 IO 必要?
  │     ├── No  → ユニット (純粋関数として書ける形にリファクタすべきサイン)
  │     └── Yes
  │           ├── 単一モジュール内で 127.0.0.1:0 だけで再現可能?
  │           │     ├── Yes → 結合
  │           │     └── No
  │           │           ├── orchestrator 全部繋がないと意味ないか?
  │           │           │     ├── Yes → E2E (in-process)
  │           │           │     └── No  → 結合に分割可能、まず分割を検討
  │           │           └── 実 NGN/実端末/実 ICE が必須?
  │           │                 → Manual (CI 対象外、INSTALL.md のチェックリストに追加)
```

`tokio::test` で再現できないものだけ Manual に落とす。「不安定だから tokio::test じゃなくて手動」は禁止 (flaky test を放置しない)。

---

## 2. 各分類の責務

### 2.1 ユニットでカバーすべきもの

純粋関数 / 純粋構造体ロジック / 計算 / シリアライズ / RFC ベクタ。

| 例 | 既存テスト |
|----|-----------|
| HTTP Digest 計算 (RFC 2617 公式ベクタ) | `src/sip/auth.rs:273` `test_digest_compute_rfc2617_example` |
| SDP パーサ (有効/無効 SDP) | `src/sdp/mod.rs:251` `parse_ipv4_sdp`, `:292` `mismatched_addrtype_rejected` |
| Dialog の ACK 構築 (RFC 3261 §13.2.2.4) | `src/sip/dialog.rs:512` `ack_for_2xx_uses_invite_cseq_and_new_branch` |
| Transaction ID 計算 (branch + via-sent-by + cseq-method) | `src/sip/transaction.rs:605` `test_transaction_id_match` |
| RTP パケット roundtrip | `src/rtp/packet.rs:103` `test_rtp_packet_roundtrip` |
| RTCP SR/RR シリアライズ | `src/rtp/rtcp.rs:263` `sr_roundtrip` |
| Opus エンコード/デコード roundtrip | `src/rtp/codec/opus.rs:118` `encode_decode_roundtrip_produces_audible_signal` |
| Resampler (8k↔48k) 信号保存 | `src/rtp/codec/resample.rs:146` `upsample_then_downsample_preserves_signal` |
| Webrtc auth トークン (HS256) | `src/webrtc/auth.rs:154` `issue_then_verify_round_trip` |
| Config (TOML) 解析 | `src/config/mod.rs:579` `toml_parses_without_local_addr` |
| メトリクス文字列レンダ | `src/observability/mod.rs:535` `metrics_render_contains_all_series` |
| ログサニタイザ (Authorization 秘匿) | `src/observability/mod.rs:571` `sanitize_redacts_authorization_header` |

ガイドライン:

- **外部 IO (UDP / TCP / WS / ファイル) を一切起動しない**
- 1 件あたり < 1 ms で完了するよう、ループや sleep を避ける
- RFC 直接引用ベクタ (DigestRFC 2617 公式ベクタ等) は最優先で書く
- パーサは「成功」「正常な失敗」「異常な失敗 (panic しない)」の 3 系統を必ず作る

### 2.2 結合 (Integration) でカバーすべきもの

複数モジュールが組み合わさって初めて意味が出る挙動。**実 socket は使うが、相手は同一プロセス内 mock UA**。

| 例 | 既存テスト |
|----|-----------|
| REGISTER + Digest 認証往復 | `src/sip/uas.rs:508` `register_with_digest_succeeds` |
| INVITE → 200 OK → ACK + Dialog 形成 | `src/sip/uac.rs:416` `invite_2xx_establishes_dialog_and_sends_ack` |
| INVITE → 4xx | `src/sip/uac.rs:506` `invite_4xx_returns_failed_outcome` |
| CANCEL が INVITE と同じ branch を共有する (RFC 3261 §9.1) | `src/sip/uac.rs:539` `cancel_sends_cancel_with_invite_branch` |
| Transaction Layer のレスポンス分配 | `src/sip/transaction.rs:706` `test_layer_dispatches_response_by_id` |
| Client transaction Timer B タイムアウト | `src/sip/transaction.rs:653` `test_client_transaction_timeout_b` (※私有関数、別途 grep で確認) |
| Call Manager のフォーク (最初の応答勝ち) | `src/call/manager.rs:487` `multiple_extensions_first_to_answer_wins` |
| Call Manager 全員 Busy → all-failed | `src/call/manager.rs:529` `all_extensions_busy_returns_all_failed` |
| RTP ブリッジ双方向転送 | `src/call/bridge.rs:239` `bridges_rtp_in_both_directions` |
| WebRTC signaling REGISTER → 内線レジストラ更新 | `src/webrtc/signaling.rs:390` `register_message_writes_to_extension_registrar` |
| Health/readyz が REGISTER 後に 200 になる | `src/health/mod.rs:185` `readyz_registered_returns_200` |

ガイドライン:

- `127.0.0.1:0` または `::1` で port 0 バインド (テスト並列実行で衝突しない)
- IPv6 単独では行わない (CI 環境が IPv6 不可のことがある、`bind_addr_dual_stack` で吸収)
- mock 側 UA は **`UdpSocket` を直接読み書きする最小実装** にする (mock SIP スタックを作らない)
- タイムアウトを必ず付ける (`tokio::time::timeout`)。ネットワーク IO のテストで無限待ちは禁止
- mock 側がトランスポート層で見えるバイト列を直接 assert する (例: 「Via に rport が付いていないこと」)

### 2.3 E2E (orchestrator 全体) でカバーすべきもの

**「NGN 着信から内線着信、RTP ブリッジ確立、BYE まで」の全部繋がった経路。**

| 例 | 既存テスト |
|----|-----------|
| NGN INVITE が内線に転送され 200 OK が NGN に返る | `src/call/orchestrator.rs:914` `ngn_invite_forwards_200_back` |
| 内線が居ないとき NGN に 480 が返る | `src/call/orchestrator.rs:1008` `ngn_invite_with_no_extensions_returns_480` |
| 内線 INVITE が NGN に proxy される (UAS event handler) | `src/call/orchestrator.rs:1095` `uas_event_proxies_invite_to_ngn` |
| NGN inbound + Call Manager + RTP ブリッジ + SDP rewrite | `src/call/orchestrator.rs:1254` `ngn_inbound_with_call_manager_starts_rtp_bridge_and_rewrites_sdp` |
| 内線発信 + Call Manager + RTP ブリッジ起動 | `src/call/orchestrator.rs:1444` `uas_event_with_call_manager_starts_rtp_bridge` |
| WS signaling end-to-end (REGISTER → BYE) | `src/webrtc/signaling.rs:579` `end_to_end_ws_register_then_bye` |

ガイドライン:

- mock NGN は **「INVITE 受信 → 200 OK 返す → ACK drop」だけ書く**。フル SIP スタックを mock 側に作らない
- 「contact / via / from / to のどのヘッダが NGN に届いたか」を mock 側で assert することで、production 側の挙動を pin する
- E2E は遅い (≒ 数百 ms ～ 5s) ので 10 件以下に絞る。同じ経路を試すバリエーションは結合に置く
- `tokio::time::pause()` を使ってタイマーを操作するときは、socket IO と混ぜない (`pause` 中は実時間進行が止まり IO デッドロックする)

### 2.4 Manual / 実機

CI で再現できないもの:

| 項目 | 確認手順 |
|------|---------|
| 実 NGN P-CSCF への REGISTER | `INSTALL.md` の手順、`tcpdump -i <iface> -nn 'port 5060'` で REGISTER → 200 OK 確認 |
| 実 NGN からの着信 (PSTN 番号 → ひかり電話番号) | 別線から発信して Linphone/PWA に着信表示・通話確認 |
| 実 NGN への発信 (070/080/090 → 任意番号) | Linphone/PWA から発信、相手側で着信確認、双方向音声 |
| DSCP 32 が実際に付いているか | NGN 接続中の `tcpdump -v` で TOS=0x80 / Traffic Class 確認 |
| Session Timer 200 OK / re-INVITE | 通話を 30 分以上維持し re-INVITE / 200 が定期的に流れること |
| 実 Linphone との互換性 | iOS/Android Linphone でレジストレーションと通話 |
| 実 PWA + WebRTC | iOS Safari / Chrome で PWA 経由通話、Cloudflare Worker 経由 |

これらは `docs/INSTALL.md` のチェックリストとして個別に列挙する (本書からは参照のみ)。リリース PR では Manual チェックリストの結果を PR 本文に貼ること。

### 2.5 「結合と E2E」の境界

```
結合: SIP の何かのレイヤを 1〜2 層 + 相手 mock socket
E2E : SIP UAS + Call Manager + UAC + RTP bridge を全部 + 上下 mock
```

迷ったときは「**bug を追加したらどのテストが落ちるか**」で決める。Bug が orchestrator にしか出せないなら E2E、トランザクション層でも再現できるなら結合。

---

## 3. モック方針

### 3.1 原則

1. **production code を曲げてテスト用フックを足さない** (過去違反例: `ResponderHandle::__test_new` が `src/sip/uas.rs` に `pub + #[doc(hidden)]` で露出していた。Issue #106 / PR #176 で撤去し、`crate::testing::builders::responder_handle_for_test` (`#[cfg(test)]` ゲート) に集約済。CLAUDE.md §9 履歴も参照)
2. **trait 境界でモックする**、内部関数の上書きはしない
3. **socket / 時刻 / 乱数の依存はコンストラクタで注入する** (現状: socket は注入済み、時刻と乱数は `tokio::time::pause` / RNG 引数化が課題)
4. **同じ trait に対する mock 実装は 1 箇所** (現在 `LegInviter` の `ScriptedInviter` が `manager.rs:400` と `orchestrator.rs:872` の 2 箇所に重複。Issue #42 で `tests/common/` に集約)
5. **mock SIP スタックを作らない**。相手側は「raw `UdpSocket` で受け取って、生バイトで返す」最小実装に留める。これで「テストの嘘」を物理的に減らす

### 3.2 既存 mock の棚卸し

| Mock | 場所 | 用途 |
|------|------|------|
| `ScriptedInviter` (LegInviter 実装) | `src/call/manager.rs:400`, `src/call/orchestrator.rs:872` (重複) | フォーク先内線 UA の応答シナリオを script 化 |
| `StubPeerSession` | `src/webrtc/peer.rs:74` | str0m を使わない WebRTC peer (現在の本番経路でも使われているので「mock」というより「stub 実装」) |
| fake NGN UDP server | `src/call/orchestrator.rs:1102` 等 inline | INVITE/REGISTER を 1 発受けて固定応答を返す匿名 task |
| fake 内線 UA UDP server | `src/sip/register.rs:236`, `src/sip/uas.rs::tests` 等 inline | REGISTER の往復、INVITE の往復を script |

**集約方針 (Issue #42 で実施):**
- `tests/common/mock_ngn.rs` (NGN P-CSCF mock)、`tests/common/mock_ua.rs` (内線 UA mock)、`tests/common/scripted_inviter.rs` を作る
- 単発匿名 task は `MockNgn::expect_invite().respond_200()` のようなビルダ API に変える
- 本ドキュメントは Issue #42 完了後に「§3.2 集約後の Mock 一覧」として更新

### 3.3 「mock してよいもの」「使ってはダメなもの」

| 項目 | mock | 実物 | 理由 |
|------|------|------|------|
| NGN P-CSCF (相手 SIP UAS) | OK | -- | CI で実機接続不可 |
| 内線 UA (Linphone/Zoiper) | OK | -- | 同上 |
| WebRTC ブラウザ | OK (str0m を使った in-process peer は Issue #28 完了済) | -- | CI でブラウザを起動しない |
| `UdpSocket` | -- | **実物** | port 0 バインドで衝突回避できるので mock する理由がない |
| SDP パーサ | -- | **実物** | パーサのバグごと隠れる |
| SIP メッセージシリアライザ | -- | **実物** | 同上 |
| 時刻 (`tokio::time`) | OK (`pause()`) | -- | 32 秒の Timer B を実時間で待たない |
| 乱数 (`rand`) | -- (今のところ) | **実物** | branch / tag / call-id 生成は OS 乱数を使い、テストでは「形式が合っていれば良い」検証に留める |
| ファイルシステム (trace writer) | -- | `tempfile` で一時ディレクトリ | mock するより一時ディレクトリの方が忠実度が高い |

### 3.4 アンチパターン

- **production code に `cfg(test)` で挙動を切り替える if 文** を入れる ⇒ 禁止
- **mock 同士が独自プロトコルを話し合う** (mock NGN と mock 内線 UA が「テスト用 magic ヘッダ」をやり取りする) ⇒ 禁止
- **mock の応答が production の期待と違うのに通る** ⇒ mock が production を gold-plate していないか、「mock がこう返したら production はこう動くべき」を `assert!` で書き留める
- **「テストのために trait を 1 メソッドだけ抽出」** ⇒ 既存 trait に統合できないか先に検討、無理なら OK

---

## 4. カバレッジ目標

### 4.1 目標値

| 範囲 | 目標 (line) | 目標 (branch) | 根拠 |
|------|-------------|---------------|------|
| 全体 (`src/**/*.rs`) | **70%** | -- | 業界相場 (OSS 中規模 Rust プロジェクト平均)。低くしすぎると「カバレッジ無いほうがマシ」、高くしすぎるとテストの儀式化 |
| **コア** (`src/sip/transaction.rs`, `src/sip/dialog.rs`, `src/sip/auth.rs`, `src/call/orchestrator.rs`, `src/call/manager.rs`) | **85%** | 80% | RFC 違反は実機で重大事故になる。再送・タイマ・分岐の網羅が必要 |
| **重要パス** (REGISTER + Digest 認証 / INVITE 200 OK / BYE) | **100%** | 100% | 1 経路でも漏れたら通話が成立しない。回帰検出最優先 |
| `src/main.rs`, `src/observability/mod.rs` の renderer | 60% | -- | 配線コードはテストしづらい。観測点だけ pin する |
| `src/dhcp/mod.rs` | 50% | -- | OS 依存 (raw socket、CAP_NET_RAW)。実機 manual 比率高め |
| `frontend/src/**` | 60% (Issue #50 想定) | -- | UI 層は manual 比率が高くて良い |
| `workers/**` | 80% | -- | エッジ実行はデバッグが効かないのでロジック層は厚く |

### 4.2 「重要パス」の定義 (100% 必達)

通話成立に必須な以下の経路は 1 行も未カバレッジを残さない:

1. NGN への REGISTER 認証 (401 → Authorization → 200) -- `src/sip/register.rs`, `src/sip/auth.rs`
2. NGN からの INVITE → 内線フォーク → 200 OK → ACK -- `src/call/orchestrator.rs::handle_ngn_invite`, `src/call/manager.rs::fork_to_extensions`
3. 内線からの INVITE → NGN proxy → 200 OK → ACK -- `src/sip/uas.rs::handle_invite`, `src/sip/uac.rs::invite`
4. 双方向 RTP ブリッジ起動 -- `src/call/bridge.rs::run`
5. BYE (双方向、誰が起点でも) -- dialog の終了処理

これらは「未カバレッジ行の検出」を CI で fail にする (実装は別 issue、§9 参照)。

### 4.3 計測コマンド

`cargo llvm-cov` を採用。理由: tarpaulin より速く、Rust 公式ツールチェーン (rustc -Cinstrument-coverage) ベース。

```bash
# インストール (1 回)
cargo install cargo-llvm-cov

# ローカル計測 (HTML レポート)
cargo llvm-cov --html --open

# CI 用 (lcov 出力)
cargo llvm-cov --lcov --output-path target/llvm-cov.lcov

# 重要パスだけ
cargo llvm-cov --lib --html -- --include-fn-pattern '(register|invite|bye|fork)'
```

### 4.4 README への追記案 (実装は別 issue)

```markdown
## 開発: テストとカバレッジ

### テスト実行
- `cargo test` -- ユニット + 結合
- `cargo test --release` -- リリースビルドでも通ることを確認 (Opus / 数値計算)

### カバレッジ計測
- `cargo install cargo-llvm-cov` で 1 回インストール
- `cargo llvm-cov --html --open` で HTML レポートを開く
- 詳細とポリシーは [docs/test-strategy.md](docs/test-strategy.md) §4 を参照
```

### 4.5 段階的な達成ロードマップ

1. (現在) 178 テスト、計測なし
2. (Issue #X1) `cargo llvm-cov` 導入 + ベースライン取得 → 数値を本書に反映
3. (Issue #X2) 重要パスを 100% に持ち上げる
4. (Issue #X3) コアモジュール 85% に到達
5. (Issue #X4) CI で「カバレッジ低下を fail にする」しきい値運用 (Codecov 等)

---

## 5. 命名規則

### 5.1 関数名

```
<scenario>_<expected_behavior>
```

例 (既存テストから採用):

- `invite_2xx_establishes_dialog_and_sends_ack` -- `src/sip/uac.rs:416`
- `register_with_wrong_password_rejected` -- `src/sip/uas.rs:562`
- `bridges_rtp_in_both_directions` -- `src/call/bridge.rs:239`
- `seq_wraparound_handled` -- `src/rtp/jitter.rs:314`

避けるべき例 (現状残っているもの。Issue #42 の整理対象):

- `test_digest_parse` (`src/sip/auth.rs:264`) -- `test_` prefix は冗長 (cargo test 出力で「tests::tests::tests::test_digest_parse」になりがち)
- `test_ulaw_roundtrip` (`src/rtp/mod.rs:115`) -- 同上

新規テストは `test_` を **付けない**。既存の `test_` は触る PR ついでに rename する (大規模 rename 専用 PR は作らない)。

### 5.2 RFC 引用

`#[test]` 直前または関数内コメントで該当 RFC を引用する。

```rust
/// RFC 3261 §17.1.1.3 Timer B (64*T1 = 32s)
/// "If timer B fires while the client transaction is still in the 'Calling' state,
///  the client transaction SHOULD inform the TU that a timeout has occurred."
#[tokio::test]
async fn test_client_transaction_timeout_b() { ... }
```

ベクタ系は出典を必ず記載:

```rust
// RFC 2617 §3.5 の公式テストベクタ
// HA1 = MD5("Mufasa:testrealm@host.com:Circle Of Life") = "939e7578ed9e3c518a452acee763bce9"
```

### 5.3 Failure メッセージ

`assert!`、`assert_eq!` には常に説明を付ける。**「expected: X, got: Y」だけでなく「なぜそれが期待値か」を書く**。

```rust
// 良い
assert!(
    !via.contains("rport"),
    "RFC違反: NGN は rport 付き Via を 489/487 で拒否する。Via='{}'",
    via,
);

// 悪い
assert!(!via.contains("rport"));
```

`assert_eq!` でも同様:

```rust
assert_eq!(
    resp.status, 401,
    "認証なし REGISTER は 401 で challenge されるべき (RFC 3261 §22.4)。実際は status={}, reason='{}'",
    resp.status, resp.reason,
);
```

### 5.4 モジュール / ファイル分割

- ユニット + 結合は **同一ファイル末尾の `#[cfg(test)] mod tests`** に置く (Rust 慣習)
- E2E のうち、複数モジュールにまたがって長くなるものは将来 `tests/e2e/` トップレベルクレートに分離 (Issue #42 で実施候補)
- フィクスチャは `tests/fixtures/` に格納 (pcap、SDP サンプル等)

---

## 6. 境界値 / エラーパス

### 6.1 SIP パーサのファジング (proptest 検討)

現状: proptest は dev-dependencies に**未追加**。手書きの異常系ベクタのみ。

提案: `src/sip/message.rs::parse_message`、`src/sdp/parser.rs::parse_sdp` の 2 箇所に `proptest` を導入。

```toml
# Cargo.toml [dev-dependencies] への追加 (実装は別 issue)
proptest = "1"
```

```rust
// 例: 「任意の bytes を渡して panic しない」
proptest! {
    #[test]
    fn parse_message_never_panics(input: Vec<u8>) {
        let _ = sabiden::sip::message::parse_message(&input); // Result でも Err でも OK、panic だけ NG
    }
}
```

優先度:

1. `parse_message` (RFC 3261 全構文) -- 高 (NGN から想定外メッセージが来たら無限ループ NG)
2. `parse_sdp` (RFC 4566) -- 高 (同上)
3. `Authorization` ヘッダパーサ -- 中
4. RTP/RTCP デシリアライザ -- 低 (既に手書きの「短すぎる」「version 違反」テストあり)

### 6.2 Timer 境界値

`src/sip/transaction.rs` で T1 = 500ms、Timer B = 64*T1 = 32s。境界値テスト:

| 境界 | テスト方針 | 状態 |
|------|-----------|------|
| Timer B 直前 (31.9s) で 200 受信 → 成功 | `tokio::time::pause()` + `advance(31_900ms)` で確認 | 部分カバー (`test_client_transaction_provisional_then_final` `:676`) |
| Timer B 直後 (32.1s) で 200 受信 → タイムアウト | 同 | カバー (`test_client_transaction_timeout_b` `:653`) |
| T1 = 500ms 直後の再送 (Timer A) | 再送回数 6 回 (RFC 3261 §17.1.1.2) | **未カバー、要追加** |
| Session Timer (RFC 4028) re-INVITE 直前 | 30 分維持テスト、現実時間ではなく `pause` で | **未カバー、要追加** |

### 6.3 エラーパス網羅

NGN は以下を返してくる可能性がある:

| ステータス | 理由 | 対応 |
|-----------|------|------|
| 401 / 407 | Digest challenge | `auth_round_trip` で再送 (`src/sip/register.rs`) |
| 403 | 認証失敗 (固定) | 再送せず諦める |
| 404 | 番号間違い | アプリ層に通知 |
| 408 | Request Timeout | リトライポリシ要 (現状: 諦める) |
| 480 / 486 | Busy / Not Available | アプリ層 (現状: そのまま転送) |
| 487 | Request Cancelled | CANCEL 後の正常終了 |
| 489 | Bad Event (rport 関連で過去発生) | パーサ側で予防 |
| 503 | Service Unavailable | リトライ |
| 6xx | Global Failure | 諦める |

各ステータスに対して **最低 1 件の結合テスト** を持つ目標。現状カバー済:
- 401: `register_with_digest_succeeds`, `register_with_wrong_password_rejected`
- 403: `unknown_user_gets_403`
- 480: `ngn_invite_with_no_extensions_returns_480`
- 486: `all_extensions_busy_returns_all_failed`

未カバー (要追加 candidate, 別 issue):
- 408 / 503 / 6xx の処理経路

### 6.4 Socket close / 異常切断

- `UdpSocket` は connectionless だが、bind 解除や peer 不達はテストすべき
- `tokio::net::TcpStream` (workers との WS) は close 検知が必要。現状 `bye_unregisters_aor_and_closes_peer` (`src/webrtc/signaling.rs:494`) でカバー。

---

## 7. テスト実行フロー

### 7.1 ローカル開発時

```bash
# (1) 高速フィードバック (~ 30s)
cargo test --lib

# (2) 結合 + E2E 含めた全部 (~ 60s)
cargo test

# (3) リリースビルドでも通ること (Opus 等の最適化差異)
cargo test --release

# (4) clippy
cargo clippy --all-targets --all-features -- -D warnings

# (5) format
cargo fmt --all -- --check
```

`pre-commit` フック (任意、後述 §9.4) では (1) + (4) + (5) のみ。(2)(3) は CI に任せる。

### 7.2 PR 提出時 (CI)

GitHub Actions が `.github/workflows/ci.yml` で自動実行:

1. `fmt` job: `cargo fmt --all -- --check`
2. `clippy` job: `cargo clippy --all-targets --all-features -- -D warnings`
3. `test` job: `cargo test --all-features --verbose`
4. `build` job: `cargo build --release`
5. `docker` job: コンテナビルド

詳細と提案は §9 を参照。

### 7.3 リリース前 (Manual)

`docs/INSTALL.md` のチェックリスト:

1. 実 NGN への REGISTER (1 件)
2. 実 NGN への発信 (070/080/090 → 任意番号、1 件以上)
3. 実 NGN からの着信 (PSTN → ひかり電話番号、1 件以上)
4. 通話品質 (30 分以上、Session Timer re-INVITE が 2 回以上発生)
5. Linphone / Zoiper 1 端末以上で内線として動作
6. PWA + WebRTC で 1 端末以上で発着信

PR 本文に該当チェック結果を貼る。

---

## 8. リグレッション防止

### 8.1 「過去にバグだった挙動を再発防止テスト化する」ルール

Bug fix PR は **必ず failing test を先に追加**して、その PR でテストが green になるパターンに従う:

```
1. Bug 報告 / 発見 (実機 / Issue)
2. failing test を追加 (commit A: "test: failing test for bug N")
3. fix を当てる (commit B: "fix: bug N")
4. PR で commit A + B をまとめる
5. レビュアは「commit A だけ checkout して fail することを確認」できる
```

### 8.2 PPI / PAI の例 (issue 本文より)

`P-Preferred-Identity` (PPI) は NGN 直収で必要。過去に「場当たり的に追加」された経緯がある。再発防止として:

```rust
#[test]
fn ngn_register_includes_p_preferred_identity_when_configured() {
    let req = build_register_for_ngn_direct(...);
    assert!(
        req.headers.get("P-Preferred-Identity").is_some(),
        "RFC 3325 + NTT NGN 仕様: 直収モードでは PPI が必須 (#XX 参照)"
    );
}
```

「PPI を消すリファクタ」が来たらこのテストが落ちる → レビュアが背景を理解できる。

### 8.3 pcap fixture によるスナップショットテスト

実機で取った SIP メッセージを `tests/fixtures/pcap/` に保存し、パーサがそのまま読めることを確認する。

```
tests/fixtures/sip/
├── ngn-register-401-challenge.txt   # NGN からの 401
├── ngn-register-200-ok.txt          # 認証後 200
├── ngn-invite-pcsf-uri.txt          # P-CSCF からの INVITE
├── ngn-bye-pstn-side.txt            # PSTN 側からの BYE
└── ngn-487-cancelled.txt            # CANCEL 後の 487
```

`include_bytes!` で取り込んでパースを検証:

```rust
const REG_401: &[u8] = include_bytes!("../fixtures/sip/ngn-register-401-challenge.txt");

#[test]
fn parser_handles_real_ngn_401() {
    let msg = parse_message(REG_401).expect("実機 401 メッセージのパース失敗");
    // 構造を assert (callee アドレス、Via ホスト、auth scheme 等)
}
```

### 8.4 個人情報の取り扱い

実機 pcap には以下が含まれる可能性がある。**fixture に保存する前に必ず redact する**:

- 電話番号 (From / To / P-Preferred-Identity の user 部)
- IPv6 アドレス (NGN 内 prefix で個人特定可能)
- Call-ID (時刻 + ホスト名から逆引き可能)
- Authorization の username

redact ルール (本書に列挙、Issue #42 でスクリプト化):

| 元 | redact 後 |
|----|-----------|
| `0312345678` | `0312345678` (固定値、テストベクタとして公知) |
| 実 NGN IPv6 | `2001:db8:1::1` (ドキュメント用 prefix) |
| 個人ホスト名 | `client.example` |
| 実 nonce / cnonce | 任意の固定値 |

### 8.5 「Implicit な NTT クセ」のリスト

以下は RFC からは出てこない、実機で発見された制約。各々に対して結合テストを置く:

| クセ | 対応コード | テスト |
|------|-----------|--------|
| Via に rport を付けない | `src/sip/uac.rs` (`invite_plan_includes_session_timer_and_no_rport`) | `:398` カバー済 |
| Via に rport が来たら無視せず close (489) | パーサ側 | **要追加** |
| Session Timer 必須 | `src/sip/uac.rs` | `:398` カバー済 |
| DSCP 32 / TOS 0x80 | `src/sip/transport.rs` (将来) | **要追加 (実機 manual 含む)** |
| PCMU 固定 (G.711 μ-law のみ) | `src/sdp/builder.rs` | パーサテストでカバー、ネゴ拒否は **要追加** |
| IPv6 P-CSCF | `src/sip/transport.rs` | **要追加** |
| DHCP Option 120 で SIP サーバ取得 | `src/dhcp/mod.rs` | OS 依存で manual 寄り |
| User-Agent ベンダ class | `src/config/mod.rs` (`toml_ngn_vendor_class_can_be_overridden` `:630`) | カバー済 |
| 認証なしモード (Issue #38) | `src/config/mod.rs` (`toml_parses_without_password_for_ngn_direct` `:595`) | カバー済 |

---

## 9. CI 統合

### 9.1 現状分析 (`.github/workflows/ci.yml`)

```yaml
jobs:
  fmt     -- cargo fmt --all -- --check
  clippy  -- cargo clippy --all-targets --all-features -- -D warnings
  test    -- cargo test --all-features --verbose
  build   -- cargo build --release + artifact upload
  docker  -- container build (needs: test, clippy)
```

評価:

| 項目 | 状態 | コメント |
|------|------|---------|
| `fmt --check` | OK | 既に強制 |
| `clippy -D warnings` | OK | 既に強制、`RUSTFLAGS: "-D warnings"` も設定済 |
| `cargo test` | OK | unit + 結合 + E2E (in-process) を全部実行 |
| カバレッジ計測 | **欠** | Codecov / Coveralls / 直接アーティファクトいずれも未導入 |
| フロントエンド lint / build | **欠** | `frontend/` の `npm run lint` / `npm run build` が CI 未実行 |
| Worker テスト | **欠** | `workers/` のテスト job 未定義 (現状コードベースに wrangler test なし) |
| Manual checklist | **欠** | リリース PR で人間が確認 (自動化不可) |
| Docker build | OK | `needs: [test, clippy]` で前提も正しい |
| Auto-merge | OK (`auto-merge.yml`) | label ベースの自動マージ |

### 9.2 提案: `ci.yml` への追加 job (実装は別 issue)

```yaml
  frontend:
    name: frontend (lint + build)
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: frontend
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: frontend/package-lock.json
      - run: npm ci
      - run: npm run lint
      - run: npm run format:check
      - run: npm run build

  coverage:
    name: coverage (cargo llvm-cov)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - run: sudo apt-get update && sudo apt-get install -y --no-install-recommends libopus-dev
      - uses: Swatinem/rust-cache@v2
      - run: cargo install cargo-llvm-cov --locked
      - run: cargo llvm-cov --lcov --output-path target/llvm-cov.lcov
      - uses: codecov/codecov-action@v4
        with:
          files: target/llvm-cov.lcov
          fail_ci_if_error: false  # 初期は warn-only
```

### 9.3 強化提案サマリ

1. ✅ 既に `cargo fmt --check`、`cargo clippy --deny warnings`、`cargo test` は CI 必須
2. ⏳ `frontend` の `npm run lint` / `npm run build` を CI に追加 (Issue 別建て)
3. ⏳ `cargo llvm-cov` でカバレッジ計測、Codecov に upload (Issue 別建て)
4. ⏳ `cargo audit` (依存先 CVE チェック) を週次 cron で別 workflow (Issue 別建て)
5. ⏳ proptest 用に `cargo test --release` も CI に追加 (代表的な fuzz は debug より release で速いケースあり) (Issue 別建て)

### 9.4 Pre-commit (任意)

`.git/hooks/pre-commit` (既定では未設定):

```bash
#!/usr/bin/env bash
set -e
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --lib  # 高速版
```

CI と二重になるが、ローカルで早く失敗する利点。導入は個人裁量、推奨はする。

---

## 10. 既存テストの分類例

`grep -rn "#\[test\]\|#\[tokio::test\]" src/` の結果から代表 20 件を分類。**全件分類は Issue #42 で実施**。

### 10.1 ユニット (純粋関数)

| 分類 | テスト | RFC / 仕様 |
|------|--------|-----------|
| Unit | `src/sip/auth.rs:273` `test_digest_compute_rfc2617_example` | RFC 2617 §3.5 公式ベクタ |
| Unit | `src/sip/transaction.rs:605` `test_transaction_id_match` | RFC 3261 §17.2.3 |
| Unit | `src/sip/dialog.rs:512` `ack_for_2xx_uses_invite_cseq_and_new_branch` | RFC 3261 §13.2.2.4 |
| Unit | `src/sip/dialog.rs:533` `ack_via_does_not_contain_rport` | NTT NGN 制約 |
| Unit | `src/sdp/mod.rs:251` `parse_ipv4_sdp` | RFC 4566 |
| Unit | `src/sdp/mod.rs:292` `mismatched_addrtype_rejected` | RFC 4566 §5.7 |
| Unit | `src/rtp/packet.rs:103` `test_rtp_packet_roundtrip` | RFC 3550 §5.1 |
| Unit | `src/rtp/jitter.rs:259` `ordered_pull_after_buffer_fill` | jitter buffer 内部仕様 |
| Unit | `src/rtp/codec/opus.rs:118` `encode_decode_roundtrip_produces_audible_signal` | libopus 仕様 |
| Unit | `src/webrtc/auth.rs:154` `issue_then_verify_round_trip` | HS256 (RFC 7515) |
| Unit | `src/observability/mod.rs:571` `sanitize_redacts_authorization_header` | 内部仕様 |

### 10.2 結合 (複数モジュール、in-process)

| 分類 | テスト | カバー範囲 |
|------|--------|-----------|
| Integration | `src/sip/uas.rs:508` `register_with_digest_succeeds` | UAS + Auth + Registrar |
| Integration | `src/sip/uas.rs:646` `invite_without_handler_returns_503` | UAS + Transaction Layer |
| Integration | `src/sip/uac.rs:416` `invite_2xx_establishes_dialog_and_sends_ack` | UAC + Transaction + Dialog |
| Integration | `src/sip/uac.rs:539` `cancel_sends_cancel_with_invite_branch` | UAC + Cancel handling (RFC 3261 §9.1) |
| Integration | `src/call/manager.rs:487` `multiple_extensions_first_to_answer_wins` | Call Manager + LegInviter mock |
| Integration | `src/call/bridge.rs:239` `bridges_rtp_in_both_directions` | RTP Bridge (純 UDP relay) |
| Integration | `src/health/mod.rs:185` `readyz_registered_returns_200` | HTTP health + RegisterState |
| Integration | `src/webrtc/signaling.rs:474` `ice_continue_no_reply` | WS signaling + str0m_session |

### 10.3 E2E (orchestrator 全体)

| 分類 | テスト | カバー範囲 |
|------|--------|-----------|
| E2E | `src/call/orchestrator.rs:914` `ngn_invite_forwards_200_back` | NGN→UAS→Manager→200→NGN |
| E2E | `src/call/orchestrator.rs:1095` `uas_event_proxies_invite_to_ngn` | 内線→UAS→UAC→NGN |
| E2E | `src/call/orchestrator.rs:1254` `ngn_inbound_with_call_manager_starts_rtp_bridge_and_rewrites_sdp` | + RTP bridge + SDP rewrite |
| E2E | `src/webrtc/signaling.rs:579` `end_to_end_ws_register_then_bye` | WS REGISTER → BYE 全シーケンス |

### 10.4 分類のサマリ (見立て)

`grep` 件数 178 件のうち、ファイル別の傾向:

| ファイル | 件数 | 主分類 |
|---------|------|-------|
| `src/sip/auth.rs` | 6 | Unit |
| `src/sip/dialog.rs` | 16 | Unit |
| `src/sip/transaction.rs` | 8 (うち 3 件 async) | Unit + Integration |
| `src/sip/uac.rs` | 5 | Unit + Integration |
| `src/sip/uas.rs` | 9 | Integration (Unit 4 件は parse helper) |
| `src/sip/register.rs` | 3 | Integration |
| `src/sip/registrar.rs` | 4 | Integration (storage 層) |
| `src/sdp/*` | 11 | Unit |
| `src/rtp/*` | 30+ | Unit (codec/packet/jitter/rtcp) + Integration (session) |
| `src/webrtc/*` | 25+ | Mix (auth は Unit、signaling/peer は Integration、str0m_session は Integration) |
| `src/call/manager.rs` | 9 | Integration |
| `src/call/bridge.rs` | 2 | Integration |
| `src/call/orchestrator.rs` | 6 | E2E |
| `src/call/transcoder.rs` | 6 | Unit + Integration |
| `src/health/mod.rs` | 6 | Integration |
| `src/observability/mod.rs` | 11 | Unit (うち 3 件 `tokio::test` で trace writer 検証 = Integration 寄り) |
| `src/config/mod.rs` | 8 | Unit |

おおよそ **Unit 60% / Integration 30% / E2E 6% / Stub-Integration (健康診断系) 4%**。テストピラミッド比率としては健全。E2E が薄いのはコードカバレッジ目標 (§4) と整合する (E2E は厚くしすぎると CI が遅い)。

---

---

## 付録 0: テストパターンの代表例 (コピー元テンプレ)

### 0.1 ユニット (RFC ベクタ)

```rust
// RFC 2617 §3.5 の公式テストベクタ。
// HA1 = MD5("Mufasa:testrealm@host.com:Circle Of Life")
//     = "939e7578ed9e3c518a452acee763bce9"
// HA2 = MD5("GET:/dir/index.html")
//     = "39aff3a2bab6126f332b942af96d3366"
// response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
//          = "6629fae49393a05397450978507c4ef1"
#[test]
fn digest_response_matches_rfc2617_vector() {
    let creds = DigestCredentials {
        username: "Mufasa".into(),
        password: "Circle Of Life".into(),
    };
    let challenge = DigestChallenge {
        realm: "testrealm@host.com".into(),
        nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".into(),
        qop: Some("auth".into()),
        opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".into()),
        algorithm: None,
    };
    let response = compute_response(
        &creds, &challenge, "GET", "/dir/index.html", 1, "0a4f113b",
    );
    assert_eq!(
        response, "6629fae49393a05397450978507c4ef1",
        "RFC 2617 §3.5 公式ベクタに一致しない (algorithm 規定が変わった可能性あり)"
    );
}
```

### 0.2 結合 (in-process socket)

```rust
// RFC 3261 §10.3: REGISTER に WWW-Authenticate なしで 401 が返ったら
// クライアントは諦めずに retry すべきか? -> retry すると無限ループに
// なるので、本実装では 1 回で諦める。
#[tokio::test]
async fn register_bails_on_401_without_password() {
    // mock 側: 401 を Authorization なしで返し続ける
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let req = parse_message(&buf[..n]).unwrap();
            // 認証情報なしで 401 を返す
            // (production は再送せず error を返すべき)
            ...
        }
    });

    // production 側
    let result = register_to(server_addr, /* no password */).await;
    assert!(
        result.is_err(),
        "認証情報なしで 401 を受けたら諦めるべき (無限ループ防止)"
    );
}
```

### 0.3 E2E (orchestrator)

```rust
// 内線→UAS→UacEventHandler→NGN UAC→fake NGN の end-to-end。
// Issue #15 の主目的である UAS event ハンドラのプロキシ動作を確認。
#[tokio::test]
async fn uas_event_proxies_invite_to_ngn() {
    // (1) fake NGN: INVITE を 1 回受けて 200 OK を返す
    // (2) NGN UAC: TransactionLayer + Uac
    // (3) 内線 UAS: bind + with_handler
    // (4) UasEventHandler を起動
    // (5) fake 内線 UA から INVITE を送る
    // (6) fake NGN 側で INVITE が観測されること、200 OK が内線 UA まで戻ること
    //     を assert する
}
```

(コード本体は `src/call/orchestrator.rs:1095` を参照)

### 0.4 fixture を使ったパーサテスト

```rust
const NGN_REGISTER_401: &[u8] = include_bytes!(
    "../fixtures/sip/ngn-register-401-challenge.txt"
);

#[test]
fn parse_real_ngn_401_challenge() {
    let msg = parse_message(NGN_REGISTER_401)
        .expect("実機 401 メッセージのパース失敗 (構造変更?)");
    let SipMessage::Response(resp) = msg else {
        panic!("Response でない");
    };
    assert_eq!(resp.status, 401);
    let auth = resp.headers.get("WWW-Authenticate")
        .expect("401 には WWW-Authenticate が必須 (RFC 3261 §22.2)");
    assert!(auth.contains("Digest"), "Digest scheme 必須");
    assert!(auth.contains("nonce="), "nonce パラメータ必須");
}
```

---

## 付録 A: 用語

| 用語 | 定義 |
|------|------|
| Unit | 1 モジュール内、外部 IO なし、`#[test]`、< 1ms |
| Integration | 複数モジュール、in-process socket / mock、`#[tokio::test]` |
| E2E | orchestrator 全体、上下 mock、in-process でフルパス |
| Manual | 実機 (NGN / Linphone / PWA)、CI 対象外 |
| RFC ベクタ | RFC 本文に記載されているテスト用入出力 (Digest 認証等) |
| pcap fixture | 実機で取得した SIP メッセージを redact してテスト入力にしたもの |
| LegInviter | 内線への INVITE を抽象化した trait、production は `UacForker`、test は `ScriptedInviter` |
| Mock NGN | テスト用に NGN P-CSCF の最小応答 (REGISTER 200 / INVITE 200 等) を返す UDP server |

## 付録 B: 関連 issue / 関連 PR

- Issue #42 -- mock ハーネス整理 (本書 §3 と並列)
- Issue #46 -- architecture.md 詳細化 (本書からリンク予定)
- Issue #47 -- 本書 (test-strategy.md 作成)
- Issue #28 -- 実 ICE/DTLS-SRTP 終端 (str0m バックエンド) → §3.3 「WebRTC ブラウザ mock」の前提
- Issue #38 -- NGN 直収モード (auth=none) → §6.3 / §8.5 のクセ一覧

## 付録 C: 変更履歴

| 日付 | 変更 |
|------|------|
| 2026-05-09 | v1 初版 (Issue #47) |
