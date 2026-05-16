# CLAUDE.md — Claude Code / サブエージェント用ガイド

> このファイルは Claude Code 起動時に自動で context に注入され、サブエージェントの runtime にも伝播する **単一情報源**。
> 各 agent prompt で「NGN 仕様」「band-aid 禁止」「テスト戦略」「触ってよい / 触ってはいけないファイル」「ビルドコマンド」を毎回繰り返す代わりに、本ファイルへ参照を一本化する。
> 詳細仕様は本書では **重複させず**、`docs/**` の各 doc にリンクする。

---

## 1. プロジェクト概要

**sabiden** = Rust 製 NTT NGN 直収 SIP B2BUA + WebRTC ゲートウェイ。

- HGW (PR-500/600 等のホームゲートウェイ) を**介さず**、ONU 直収のホストから NTT ひかり電話 (NGN) に SIP REGISTER して発着信する。
- 内線として複数のスマホ・SIP 端末・WebRTC PWA を収容し、Asterisk 風フォーク着信を行う。
- `sabi (錆 = Rust)` + `den (電話)`。
- 現在 **Phase 4 (PWA フロントエンド + Cloudflare Workers デプロイ) 進行中**。Phase 1〜3 は完了 (`README.md` ステータス表参照)。

詳細は [`README.md`](README.md) と [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

---

## 2. アーキテクチャ概要

主要モジュールの責務 (1 文ずつ):

| モジュール | 責務 |
|---|---|
| `src/sip/` | SIP プロトコル層 (RFC 3261 メッセージ / トランザクション / ダイアログ / REGISTER / UAC / UAS / Digest 認証) |
| `src/sdp/` | SDP パース・ビルダー (RFC 4566) と Offer/Answer 補助 (RFC 3264) |
| `src/rtp/` | RTP/RTCP (RFC 3550) と コーデック (G.711 μ-law / Opus / 8k↔48k リサンプラ) |
| `src/dhcp/` | DHCP Option 120 (RFC 3361) で P-CSCF アドレスを取得 |
| `src/call/` | B2BUA orchestration (`orchestrator.rs`)、フォーク INVITE (`manager.rs`)、RTP ブリッジ (`bridge.rs`)、Opus⇔G.711 トランスコード (`transcoder.rs`) |
| `src/webrtc/` | WS シグナリング (`signaling.rs`) と ICE/DTLS-SRTP 終端 (`str0m_session.rs`)、HMAC 認証 (`auth.rs`) |
| `src/observability/` | 自前メトリクス + SIP メッセージトレース (Authorization redact 済) |
| `src/health/` | K8s liveness/readyz HTTP probe + Prometheus メトリクス出力 |
| `src/config/` | TOML + 環境変数オーバライド (Secret マウント対応) |

詳細図と通話フロー → [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。
リファクタ計画 (Phase R1〜R6 と責務マトリクス) → [`docs/refactor-plan.md`](docs/refactor-plan.md)。

---

## 3. ビルド・テスト・実行コマンド

### Rust (cargo)

```bash
cargo build                  # debug build (main bin に必ず必要)
cargo build --release        # 本番ビルド
cargo test                   # 全テスト (ユニット + 結合 + E2E)
cargo fmt                    # フォーマット (CI でチェック)
cargo clippy -- -D warnings  # CI と同じ厳しさで lint
```

**重要 (cargo build 必須)**: `cargo test` は test bin だけをビルドする。**修正後に sabiden を起動するなら必ず `cargo build` (もしくは `cargo build --release`) を再実行する**。`cargo test` だけだと `target/debug/sabiden` (main bin) は古いままで、修正が反映されない罠がある。

### sabiden 起動 (常駐用 subshell + nohup レシピ)

実機運用 / 開発検証で常駐させる場合、Claude Code セッション終了の SIGTERM に巻き添え死しないよう **完全 detach** する:

```bash
# 完全 detach: subshell に閉じ込め、nohup で stdin/stdout/stderr を切る
( sudo nohup ./target/debug/sabiden register --config /etc/sabiden/config.toml \
    > /tmp/sabiden.log 2>&1 & )

# 開発時 (前景 + デバッグログ)
RUST_LOG=sabiden=debug ./target/debug/sabiden register --config config.toml
```

### フロントエンド (PWA)

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173 (sabiden /signal を proxy)
npm run build      # dist/ にバンドル
npm run lint       # eslint
```

### WebRTC 開発トークン発行

```bash
scripts/dev-token.sh <ext_id> [ttl_seconds] [secret_hex_or_path]
# 出力: <ext_id>.<expiry_unix>.<base64url(hmac-sha256(secret, "ext.expiry"))>
# secret 引数省略時は ../config.toml の secret_hex を抽出
```

PWA の URL に `#token=<token>` を付けると自動取込される。

---

## 4. 開発フロー

`main` は保護ブランチ。**直 push 禁止**。必ず PR 経由で squash merge する。

```
1. Issue を立てる / アサインを受ける
2. branch を切る: <type>/issue-N-<slug>
   - feat/issue-N-slug         (新機能)
   - fix/issue-N-slug          (バグ修正)
   - refactor/issue-N-slug     (リファクタ)
   - docs/issue-N-slug         (ドキュメント)
   - test/issue-N-slug         (テスト追加)
   - chore/issue-N-slug        (CI / build / dep)
3. 実装 + テスト追加 + cargo fmt + cargo clippy + cargo test
4. PR 作成: タイトルに type prefix、body に "Closes #N"
5. CI 通過 + レビュー → squash merge
```

worktree (`.claude/worktrees/`) で並列作業する。同じファイルを複数 agent が同時に編集しない。

詳細 → [`CONTRIBUTING.md`](CONTRIBUTING.md)。

---

## 5. NGN 実機制約 (絶対遵守)

NTT NGN P-CSCF 直収では「RFC で許される複数解釈のうち、NGN/Asterisk が実際に通る形」だけが正解。**`docs/asterisk-real-invite.md` の pcap 由来の確定事項に従うこと**。推測で実装しない。

| 項目 | 値 / 制約 | 根拠 |
|---|---|---|
| 送信元 UDP port | **5060 必須**。それ以外だと NGN は応答しない | `docs/asterisk-real-invite.md` §3 |
| Request-URI host | **P-CSCF IP+port** (例 `118.177.125.1:5060`)。ドメイン名 (`ntt-east.ne.jp`) は不可 | 同 §5.1 |
| To URI host | Request-URI と整合 (= P-CSCF IP) | 同 §5.1 |
| Via に `rport` | あっても無くても 200 OK が返る (両対応) | 同 §3 |
| SDP `c=` / `o=` IP | **eth1 (NGN 側) IPv4**。LAN 私設 IP / 内線端末 IP は厳禁 | 同 §5.2 |
| SDP `o=` username | `-` を推奨 (`iphone` のような端末名は軽微差分) | 同 §2 |
| SDP `m=audio` port | sabiden が NGN 側に open した RTP socket port | 同 §5.2 |
| 音声コーデック | **PCMU (RFC 3551 PT 0) only**。PCMA / G.722 / Opus は NGN レッグでは流さない | 同 §2, [`docs/refactor-plan.md`](docs/refactor-plan.md) §1.4 |
| DSCP | NGN SIP / RTP ともに **DSCP 32 (TOS 0x80)** | `src/main.rs::set_dscp`、NGN 公開仕様 |
| compact ヘッダ | 受信は展開、送信は full form (`Via:` `From:` `To:` 等) で正規化 | `docs/refactor-plan.md` §1.5 |
| `P-Preferred-Identity` / `Privacy` | **不要**。Asterisk は両方無しで 200 OK 取得済 | `docs/asterisk-real-invite.md` §5.3 |
| Session-Timer (RFC 4028) | INVITE には載るが値は緩い (`1800` 秒等)。NGN は refresher 指定なしで通る | 同 §2 |
| `Allow` ヘッダ | 過不足とも実害なし (Asterisk と sabiden で内容が違っても 200 OK が返る) | 同 §4 表 |

Asterisk ソース解析 (どこで何を組み立てているか) → [`docs/asterisk-ngn-invite-spec.md`](docs/asterisk-ngn-invite-spec.md)。

---

## 6. コーディング規約・禁止事項

### 6.1 場当たり (band-aid) 禁止

- **「実機未検証で追加 / 削除」は禁止**。例: PPI/Privacy のような IMS ヘッダを「IMS だから必要だろう」で入れない。**必ず Asterisk pcap 等の実機証拠で確証を取ってから入れる/外す**。
- やむなく場当たり対処を入れる場合、必ず以下のコメントで明記する:
  ```rust
  // TODO(本流対応): <現象> を <issue#> で根本対処する。今は <暫定対処> で凌ぐ。
  ```
- band-aid を発見したら `docs/refactor-plan.md` §4 (「場当たり実装の棚卸し」) に追記する。

### 6.2 RFC 引用必須

- 新規ロジックには RFC 引用付き docstring を付ける。例:
  ```rust
  /// RFC 3261 §13.2.2.4: ACK for 2xx is a separate transaction with the
  /// INVITE CSeq number and a fresh branch.
  pub fn build_ack_for_2xx(...) { ... }
  ```
- テスト名にも RFC 番号と section を埋める: `rfc3261_17_1_1_3_non2xx_ack_uses_response_to_tag` (Phase R1 で導入予定の規約)。詳細 → `docs/refactor-plan.md` §3.5。

### 6.3 production-side test hook 禁止

- `__test_new` のようなテスト専用コンストラクタを production 型に生やさない。テストヘルパは `#[cfg(test)] mod tests` 内に閉じ込めるか、将来の `tests/common/` に置く。
- mock UA / mock NGN は production 型を mock しない。`UdpSocket` を直接読み書きする最小実装で書く (`docs/test-strategy.md` §2.2)。

### 6.4 推測 PR 禁止

- 実機証拠が無いのに「これで通るはず」で書かない。NGN 直収はクセが強く、RFC 解釈の範囲内でも通らないパターンが多い。
- pcap が無ければ Asterisk を立てて取得する手順は [`docs/asterisk-real-invite.md`](docs/asterisk-real-invite.md) §1 にある。

### 6.5 その他規約 (`CONTRIBUTING.md` から抜粋)

- `cargo fmt` 必須 (CI でチェック)
- `cargo clippy -- -D warnings` 必須
- `panic!` / `unwrap` / `expect` は production code で禁止 (`Result` で握る、テストは可)
- public API には `///` で docstring 必須
- エラーは `anyhow::Result` または独自エラー型
- WHY を書く、WHAT は書かない (コメント方針)
- TODO/FIXME は **必ず Issue 番号付き**

---

## 7. テスト方針

詳細 → [`docs/test-strategy.md`](docs/test-strategy.md)。

サマリ:

- **Unit** (純粋関数) / **Integration** (`127.0.0.1:0` で in-process socket) / **E2E** (orchestrator 全部繋ぐ) / **Manual** (実 NGN, INSTALL.md チェックリスト) の 4 層。
- `cargo test` は全部通って **30 秒以内**を目標。
- RFC 直接引用ベクタ (Digest RFC 2617 公式ベクタ等) は最優先。
- 重要パス (REGISTER / INVITE / BYE / CANCEL / ACK / Re-INVITE / RTP ブリッジ / Digest 認証) は **100% カバー**を目指す。
- pcap fixture は NGN 実機由来 (`docs/asterisk-real-invite.md` §2) を test vector に取り込む。
- `tokio::test` で再現できないものだけ Manual に落とす。**「不安定だから手動」は禁止** (flaky は放置しない)。

---

## 8. 触ってはいけない領域 (sub-agent 向け)

以下は本タスクと直接関係ない限り**触らない**。触る必要があれば事前に Issue で議論する。

| 領域 | 理由 |
|---|---|
| `deploy/k8s/`, `deploy/systemd/`, `deploy/docker/` | 本番デプロイ資材。実機検証済の構成。 |
| `src/sip/register.rs` | NGN REGISTER の動作確認済本体。直収/HGW 両対応の分岐があり、相応の理由なく変更しない。 |
| `Cargo.lock` | **手動編集禁止**。依存追加は `cargo add` / `cargo update -p` 経由。 |
| `.github/workflows/*.yml` | CI 整備は **独立 Issue** で扱う。機能 PR の中で同時に弄らない。 |
| `frontend/dist/`, `frontend/dev-dist/`, `frontend/node_modules/` | ビルド成果物。`.gitignore` 済。 |
| `workers/.wrangler/`, `workers/node_modules/` | Wrangler / npm 由来生成物。 |
| 既存 `docs/*.md` (HLD `docs/ARCHITECTURE.md` を**除く**) | レビュー済の単一情報源。修正は別 Issue で。CLAUDE.md からはリンクのみ。 |
| `docs/ARCHITECTURE.md` (= HLD) | **本流の単一設計ソース**。 機能 PR と一緒に必ず更新する (CLAUDE.md §13)。 設計を変えたのに HLD が古い PR は reject。 |
| `config.toml` (= 実環境の secret) | `.gitignore` 済。`config.example.toml` だけが repo に入る。 |

---

## 9. 既知の場当たり / 撤去済み履歴

過去に入れて撤去した band-aid を記録する。**再発防止用**。新しい同種の修正を入れる前に、必ずここを確認する。

| 場当たり | 経緯 | 結論 |
|---|---|---|
| `P-Preferred-Identity` / `Privacy: none` ヘッダの追加 | 「IMS なら必須だろう」で投入 → 403 が解消しなかった | **撤去**。Asterisk pcap で両方無しで 200 OK が返ることを確認 (`docs/asterisk-real-invite.md` §5.3)。 |
| `webrtc.local` という偽ホスト名でのフィルタ | フォーク先 binding を SIP / WebRTC で分けるための kludge | **撤去**。`ExtTransport` enum と trait object に置換 (`src/call/orchestrator.rs:3023` のテストコメントに痕跡)。 |
| `ResponderHandle::__test_new` (production-side test hook、 §6.3 違反) | テスト容易化のため `src/sip/uas.rs` に `pub + #[doc(hidden)]` で露出していた。 `src/call/orchestrator.rs` 13 箇所 + e2e harness から呼ばれていた | **撤去** (Issue #106 / PR #176)。 `crate::testing::builders::responder_handle_for_test` (`#[cfg(test)]` ゲート、 `src/testing.rs`) に集約。 `ResponderHandle::new` は `pub(crate)` に変更。 `docs/test-strategy.md` §3.1 も更新済。 |
| `SipMethod::Other(String)` を全部 405 で返す | NOTIFY / PRACK / UPDATE / MESSAGE をまとめて拒否していた | **解消済 (NGN inbound: PR #189 / Issue #110、 内線 UAS: PR #274 / Issue #273)**。 NGN 側 (`src/call/orchestrator.rs::handle_inbound`) と内線側 (`src/sip/uas.rs::handle_request`) 両方で method 別 status (NOTIFY→481 / SUBSCRIBE→489 / PRACK→481 / PUBLISH→200 (内線) or 489 (NGN) / UPDATE→481 / MESSAGE→200 / REFER→405 / Other→405) + `Allow` ヘッダ付きで応答する。`docs/refactor-plan.md` §4.4。 |
| `restrict_audio_to_pcmu` の attribute ブラックリスト混在 | PCMU only 化と「WebRTC 由来属性の剥離」を 1 関数で実装 | **未対応 (Phase R3 で `Negotiator` 分離)**。`docs/refactor-plan.md` §1.4 / §4.2。 |
| `static CSEQ` (`src/sip/register.rs:23`) | プロセス全体で 1 つの REGISTER CSeq | **未対応**。多回線対応時に衝突。`docs/refactor-plan.md` §1.1 register.rs 行。 |
| `normalize_request_uri_for_ngn` 定義のみで callsite なし | commit `cba1cd2` の主機能が結線されていない | **解消済** (2026-05-15)。 `src/call/orchestrator.rs:3182` (NGN inbound) と `:4532` (PWA outbound) で結線済、 NGN 直収 Request-URI = P-CSCF IP rewrite が動作中。 `docs/refactor-plan.md` §4.1 の note は古い。 |

---

## 10. メモリ / 関連ドキュメント索引

### 10.1 リポジトリ内 docs

| ファイル | 内容 |
|---|---|
| [`README.md`](README.md) | プロジェクト概要、ステータス、クイックスタート |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | branch / PR / commit / コーディング規約 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | アーキテクチャ概要・通話フロー・Phase 計画・デプロイ形態 |
| [`docs/refactor-plan.md`](docs/refactor-plan.md) | Phase 1-4 場当たり累積を解消する R1〜R6 計画と責務マトリクス |
| [`docs/test-strategy.md`](docs/test-strategy.md) | Unit/Integration/E2E/Manual 4 層のテスト方針 |
| [`docs/asterisk-real-invite.md`](docs/asterisk-real-invite.md) | NGN 仕様の **実機証拠** (pcap 由来) |
| [`docs/asterisk-ngn-invite-spec.md`](docs/asterisk-ngn-invite-spec.md) | Asterisk PJSIP ソース解析 |
| [`docs/INSTALL.md`](docs/INSTALL.md) | 実機インストールガイド (NGN 直収 + systemd/Docker/K8s) |
| [`docs/CLOUDFLARE.md`](docs/CLOUDFLARE.md) | Cloudflare Tunnel + Workers デプロイ |
| [`frontend/README.md`](frontend/README.md) | PWA 開発手順 |
| [`config.example.toml`](config.example.toml) | 設定ファイルサンプル |

### 10.2 RFC 索引

| RFC | 内容 | 主に関係するモジュール |
|---|---|---|
| 3261 | SIP: Session Initiation Protocol | `src/sip/{message,transaction,dialog,uac,uas}.rs` |
| 3262 | Reliability of Provisional Responses (100rel/PRACK) | UAS PRACK ハンドラ (Phase R2 予定) |
| 3264 | SDP Offer/Answer Model | `src/sdp/builder.rs`、Negotiator (Phase R3) |
| 3265 | SIP-Specific Event Notification (SUBSCRIBE/NOTIFY) | UAS NOTIFY 受信 (Phase R2 予定) |
| 3311 | UPDATE method | `src/sip/uac.rs` UPDATE (将来) |
| 3325 | P-Asserted-Identity / P-Preferred-Identity | **不要** (`docs/asterisk-real-invite.md` §5.3) |
| 3361 | DHCP Option 120 (SIP Servers) | `src/dhcp/mod.rs` |
| 3515 | REFER method | (将来、call transfer) |
| 3550 | RTP/RTCP | `src/rtp/{packet,rtcp,session}.rs` |
| 3551 | RTP Profile (PCMU PT 0 等) | `src/rtp/codec/ulaw.rs` |
| 3903 | PUBLISH method | (将来、presence) |
| 4028 | Session Timers in SIP | `src/sip/register.rs`、UAC INVITE |
| 4566 | SDP | `src/sdp/parser.rs` |
| 6026 | Correct Transaction Handling for 2xx INVITE | Timer L (Phase R5 予定) |
| 7616 | HTTP Digest (SHA-256) | (将来、現状 MD5 のみ) |
| 2617 | HTTP Digest (MD5) | `src/sip/auth.rs` |

---

## 11. サブエージェント prompt テンプレ

新しい sub-agent を起動するとき、親 Claude が cite するための雛形:

```
Issue #<N> の実装を担当: https://github.com/aoki-taquan/sabiden/issues/<N>
タイトル: <Issue タイトル>

issue を `gh issue view <N> --json title,body,labels,state` で読んでから着手してください。

## 触ってよい領域
- <具体的なファイル / ディレクトリ>

## 触らない領域
- CLAUDE.md §8 に列挙された禁止領域
- 既存 docs (相互リンクのみ)
- <この Issue と無関係な src/**>

## 強制ルール (CLAUDE.md §6 参照)
- 場当たり禁止: 実機未検証の追加/削除をしない
- RFC 引用必須: 新規ロジックは RFC 番号 §section 引用付き docstring
- band-aid に印: やむなく入れる時は `// TODO(本流対応): ...`
- branch 命名: <type>/issue-<N>-<slug>
- main 直 push 禁止 (PR 経由)
- cargo build 必須: sabiden 起動なら cargo test だけでなく cargo build で main bin 再ビルド
- HLD 同時更新必須 (CLAUDE.md §13): 設計が変わるなら `docs/ARCHITECTURE.md` を **同 PR 内** で更新。 sequence diagram / module table / state machine / SDP 仕様の差分も漏らさず反映
- worktree path 厳守 (CLAUDE.md §12.8): 作業開始時に `pwd` を確認、 絶対パスは worktree 配下のみ。 main repo (`/home/aoki/sabiden/src/...`) を絶対パスで触らない

## 完了条件
- <この Issue 固有の DoD>
- cargo fmt / cargo clippy -- -D warnings / cargo test 通過
- HLD (`docs/ARCHITECTURE.md`) を PR で更新 (該当する箇所のみ。 純 typo fix 等の例外は PR body に明記)
- PR を立てて Closes #<N> を body に記載
- レビュー対応: 親 Claude が新規 review エージェントを起動するので、 review 結果を受けて修正→再レビュー (詳細 §13)

## branch / PR
- branch: <type>/issue-<N>-<slug>
- 完了時:
  ```bash
  git add <files>
  git commit -m "<type>: <subject> (closes #<N>)"
  git push -u origin <type>/issue-<N>-<slug>
  gh pr create --title "..." --body "Closes #<N>. <要約>" --base main
  ```

worktree mode、最後にサマリと PR URL を返す。
```

---

## 12. 環境固有の注意 (本リポジトリ運用)

開発機の物理環境 (NGN 直収検証用) と Claude Code セッション運用で踏みやすい罠:

### 12.1 ネットワーク

- **eth1 = NGN 側**。HGW WAN MAC を spoof している (`2C:FF:65:3E:67:86`)。
- 電話番号: `0191349809` / ドメイン: `ntt-east.ne.jp` / NGN 認証なし (回線認証ベース、`[ngn] direct_mode = true`)。
- DHCPv4 で `118.177.72.242/30` を取得、P-CSCF は `118.177.125.1:5060`。
- **eth1 の IPv6 default route 罠**: NGN 側の RA を `accept_ra_defrtr=0` で無視させないと、NGN 側 NIC が default route を奪い、外向き IPv6 通信が NGN に吸われる。
  ```sh
  sudo sysctl -w net.ipv6.conf.eth1.accept_ra_defrtr=0
  ```

### 12.2 sabiden プロセスの常駐起動

Claude Code セッション終了時の SIGTERM 巻き添え死を避けるため、subshell + nohup で完全 detach する (§3 のレシピ):

```bash
( sudo nohup ./target/debug/sabiden register --config /etc/sabiden/config.toml \
    > /tmp/sabiden.log 2>&1 & )
```

Bare な `&` だと bash job table に残り、セッション終了時に SIGTERM が飛ぶ。

### 12.3 ビルドと起動の不整合

- `cargo test` は **main bin をビルドしない**。`cargo test` だけ実行して `./target/debug/sabiden` を起動すると、修正前の古いバイナリが動く。
- 修正後は必ず `cargo build` (debug) または `cargo build --release` (release) を再実行する。
- systemd 経由なら `sudo systemctl restart sabiden` で `/usr/local/bin/sabiden` をビルド成果物で上書きしてから restart。

### 12.4 Asterisk との 5060 排他

NGN 直収検証で Asterisk を立てる場合、sabiden を完全停止して 5060 を空ける必要がある (NGN は送信元 UDP 5060 でないと応答しない、`docs/asterisk-real-invite.md` §3):

```sh
sudo pkill -9 -f 'sabiden register'
sudo ss -ulnp | grep -E ':(5060|5070)'   # 何も出ないことを確認
```

### 12.5 worktree ライフサイクル

`.claude/worktrees/agent-<hash>/` に各 sub-agent の作業ツリーがある (`.gitignore` 済)。並列 agent が同じ branch を取らないよう、branch 名に Issue 番号を必ず含める (`<type>/issue-<N>-<slug>`)。

**累積禁止 (Issue #129 由来 / 2026-05-09 ENOSPC 事故再発防止):**

- 各 worktree の `target/` は cargo build 毎に **〜4 GB** 育つ。 27 worktree 残ると 100 GB 超で disk full → bash 全停止 → mid-Edit truncate で main repo まで破壊した実績あり。
- **PR merge 直後に親 Claude が worktree remove する**:
  ```sh
  git worktree remove --force .claude/worktrees/agent-<hash>
  ```
- agent 完了通知を受けたら、 PR が無い (= 失敗) ものも含めて未使用 worktree は即削除。
- 並列度は **同時 4 体まで** を上限。 5 体目を起動する前に既存 1 体の merge を待つ。
- 起動中の agent worktree でも target/ が膨らむので、 `du -sh .claude/worktrees/agent-*/target 2>/dev/null | sort -h | tail` で 4 GB 超を見つけたら、 該当 agent が idle なら `cargo clean` 相当を促す (ただし build 中は触らない)。

### 12.6 Secret の扱い

- `config.toml` (実環境用) は `.gitignore` 済。コミットしない。
- WebRTC `secret_hex`、`SABIDEN_SIP_PASSWORD` は環境変数 / Secret マウント経由で渡す。チャットや Issue にも貼らない。
- Cloudflare Access service token (`CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`) は `npx wrangler secret put` で投入し、リポジトリには入れない (`docs/CLOUDFLARE.md`)。

### 12.7 Disk hygiene (Issue #129)

ENOSPC は agent 並列運用で頻発する事故源。 親 Claude は以下を **定期** (新 agent dispatch / merge 直後 / 1 時間に 1 度の checkpoint) で実行:

```sh
df -h /home                                  # 残量確認、 5 GB 切ったら停止
du -sh .claude/worktrees/agent-*/target \
  2>/dev/null | sort -h | tail              # 大物 worktree 特定
du -sh /tmp/claude-1000/-home-aoki-sabiden/*/tasks/ \
  2>/dev/null | sort -h | tail              # task output 累積確認
```

**ENOSPC 兆候:**

- agent から `Bash` exit 1 が連発する → bash 環境 (snapshot 書込み) が disk fail
- `Edit` ツール返値で `ENOSPC` / `no space left on device`
- mid-Edit で truncate → 後続テストが compile fail

**回復手順:**

1. ユーザに disk 解放を依頼 (`find .claude/worktrees -name target -exec rm -rf {} +`)
2. main repo の truncated 未コミット変更を確認: `wc -l <file>` で末尾途切れ検出
3. truncated なら `git checkout HEAD -- <file>` で復旧 (uncommitted 変更は捨てる)
4. agent 進行中の worktree は中身を保護 (stash で隔離)
5. merged worktree は `git worktree remove --force` で即削除

### 12.8 絶対パス Edit の事故防止

agent (および親 Claude) が `/home/aoki/sabiden/src/...` のような絶対パスで Edit を呼ぶと、 worktree 内で作業しているつもりでも **main repo を編集する**。 過去事例:

- bundle agent (#87+#91+#121) が main repo の `src/call/bridge.rs` を truncate
- 486 fix agent (#68) が main repo を一時的に書換、 後でファイルコピーで復旧

**ルール:**

- agent は **作業開始時に必ず `pwd` で worktree path を確認**。
- 絶対パスを使う場合は `/home/aoki/sabiden/.claude/worktrees/agent-<hash>/...` を使う。 main repo の `/home/aoki/sabiden/src/...` を絶対パスで触らない。
- 親 Claude は agent 起動 prompt で worktree path を **明示的に渡す** (`isolation: "worktree"` 使用時はランタイムが切替えるが、 agent 自身が `cd` で他に移ると無効化される)。

---

## 13. コードレビュー必須ループ (新運用)

実装エージェントが「テスト通った / PR 立てた」だけで merge する旧運用は、 **シーケンス読み違い系のバグ** (例: PR #50 str0m 統合漏れで NGN→PWA 着信が壊れた) を防げなかった。 そのため **PR は必ずレビューエージェントを通す**。

### 13.1 ループ構造

```
[実装 agent] ──── 実装 + テスト + HLD 更新 + PR ────►
                                                    │
                                                    ▼
                            [レビュー agent (新規 fresh context)]
                            ・ Issue 突合 (DoD を満たすか)
                            ・ HLD 整合 (sequence diagram / module 表が新挙動と一致するか)
                            ・ シーケンス精査 (実機通信フローを 1 step ずつ追えるか)
                            ・ band-aid / RFC 引用 / production-side test hook 違反
                            ・ 既存 117 通話パス / REGISTER パスへの regression 可能性
                                                    │
                                                    ▼
                            ┌── OK ────────────────► merge
                            │
                            └── NG ─► 修正 agent (実装 agent と別/同じ worktree)
                                          │
                                          ▼
                                  **新規** レビュー agent (前と同じ ID は使わない、 fresh context)
                                          │
                                          ▼
                                          ループ
```

### 13.2 ルール

1. **レビューエージェントは毎回 fresh context で起動**。 同じ agent を SendMessage で再利用しない (前回判断のバイアスが残るため)。
2. **修正後は必ず新規レビュー agent**。 「軽微だから skip」は禁止。 OK が出るまで永遠ループ。
3. **不適切な指摘は親 Claude が判断で無視可**。 例: 「band-aid じゃないのに band-aid と誤認」「不要な抽象化提案」「scope 外の改善要求」「既知済みの場当たり (CLAUDE.md §9) を再指摘」 — これらは親が判断して無視 / レビュー agent に再説明する権限を持つ。
4. **指摘を入れる優先度**:
   - 🔴 **Must fix**: シーケンス誤読 / 既存通話パス regression / RFC 違反 / HLD 不整合 / DoD 未達
   - 🟡 **Should fix**: テスト不足 / docstring 漏れ / 命名一貫性
   - 🟢 **Nice to have**: 局所的な refactor 余地 — これは親 Claude が無視しがち
5. **レビュー agent への入力**: PR URL + Issue URL + 触ったファイル一覧 + HLD 該当章節。 fresh context なので前提全部含める。
6. **レビュー agent の出力**: `🔴 / 🟡 / 🟢` 区分の指摘リスト + Approve / Request changes の判定。

### 13.3 親 Claude のフロー

```
1. issue 起票 → 実装 agent dispatch (worktree)
2. 実装 agent から PR URL 受領 → CI green 確認
3. **review agent #1 dispatch** (PR URL + Issue + HLD で精査)
4. review = NG なら:
   a. 不適切指摘は無視 (理由を残す)
   b. 残った Must fix を fix agent に委譲 (実装 agent を SendMessage 再利用 OK)
   c. fix 完了 PR 更新 → CI green 再確認
   d. **review agent #2 (新規) dispatch** ← ここを必ず新規にする
   e. NG なら 4 へ戻る
5. review = OK なら squash merge + delete branch + memory 更新 + **`git worktree remove --force` で agent worktree 削除** (CLAUDE.md §12.5)
```

### 13.4 Review agent prompt 雛形

```
PR #<N> のレビューを担当: <PR URL>
Closes Issue #<M>: <Issue URL>

fresh context でこの PR を精査せよ。 既存実装の知識は持ち込まない (CLAUDE.md と PR / Issue / HLD のみ参照)。

## 必読
1. `/home/aoki/sabiden/CLAUDE.md` (特に §5 NGN 制約 / §6 規約 / §9 band-aid 履歴 / §13 本セクション)
2. PR の diff 全体: `gh pr diff <N>`
3. Issue 本文: `gh issue view <M>`
4. HLD 該当章節: `docs/ARCHITECTURE.md` (PR が触った機能の sequence diagram / module 表)

## 観点
- **シーケンス精査**: PR の挙動を実機メッセージ flow (REGISTER / INVITE / ACK / BYE / RTP / WS シグナリング etc) で 1 step ずつ追えるか。 step を skip / 順序入れ替えしていないか。
- **HLD 整合**: PR が設計を変えたなら HLD が同 PR で更新されているか。 sequence diagram / module 責務表 / state machine が新コードと一致するか。
- **Issue DoD 突合**: Issue 本文の要件を全部満たしているか。 一部だけ実装で他は将来 PR、 となっていないか (なってるなら PR body に明記必要)。
- **既存パス regression**: 117 通話 (PCMU↔PCMU SIP-only)、 NGN REGISTER、 既存 E2E テストが壊れていないか。
- **band-aid / 推測実装**: CLAUDE.md §6 違反 (実機未検証の追加 / 削除、 RFC 引用なし、 production-side test hook、 panic/unwrap)。
- **テストカバレッジ**: 新ロジックの分岐に unit / integration / E2E のいずれかが当たっているか。
- **CLAUDE.md §9 既知 band-aid**: 新規 PR が同種の場当たりを再導入していないか。

## 出力フォーマット

```
## Review of PR #<N>

### 🔴 Must fix (<件数>)
1. <ファイル:行> — <指摘> — <根拠 (RFC / HLD / Issue DoD)>
...

### 🟡 Should fix (<件数>)
...

### 🟢 Nice to have (<件数>)
...

### Verdict
[ ] Approve  
[ ] Request changes  

理由: ...
```

不適切指摘 (scope 外、 既知 band-aid、 推測ベース) は親 Claude が無視するので、 自信を持って指摘してよい。 ただし 🔴 と 🟡 は **必ず根拠** (RFC / HLD / Issue DoD のどれか) を添える。
```

---

## Assumptions

本ファイル執筆時点 (2026-05-09) の前提:

- `docs/ARCHITECTURE.md` は既存。Issue #46 で並列に内容拡充されている可能性があるため、参照側は更新を取り込む。
- `docs/test-strategy.md` は merge 済 (Issue #47)。
- `docs/refactor-plan.md` の Phase R1〜R6 はまだ未着手 (本 Issue 時点)。Phase 表記の進捗は別途追跡。
- §11 の prompt テンプレは「short-form」。詳細プロンプト (具体的タスク指示) は親 Claude 側で個別に追記する想定。
- §5 の NGN 制約は `docs/asterisk-real-invite.md` (2026-05-09 取得 pcap) 由来。今後別レンジ / 別 P-CSCF で検証して差分が出たら本書ではなく `docs/asterisk-real-invite.md` を更新し、本書はリンクのみ維持する。
