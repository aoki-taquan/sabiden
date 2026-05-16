# sabiden リファクタ計画書

> Phase 1-4 の場当たり修正の累積を解消し、テスト整合性と RFC 準拠度を回復する設計レビュー兼リファクタ計画。
> 対象 commit base: `01aa9b4` (merge: ACK + Request-URI 正規化)。
> 想定読者: 後続のエージェントチーム (R1〜R6 を分担実装)。

## Table of Contents

- [1. 責務分離レビュー](#1-責務分離レビュー)
  - [1.1 モジュール責務 マトリクス](#11-モジュール責務-マトリクス)
  - [1.2 重複・層越境の指摘](#12-重複層越境の指摘)
  - [1.3 B2BUA 状態機械の整理](#13-b2bua-状態機械の整理)
  - [1.4 SDP コーデック交渉の現状](#14-sdp-コーデック交渉の現状)
  - [1.5 ヘッダ操作の二重管理](#15-ヘッダ操作の二重管理)
  - [1.6 Transaction ↔ TU 層の分離](#16-transaction--tu-層の分離)
- [2. RFC 3261 カバレッジマトリクス](#2-rfc-3261-カバレッジマトリクス)
- [3. テストアーキテクチャ評価](#3-テストアーキテクチャ評価)
  - [3.1 単体 / 結合 / E2E の分類](#31-単体--結合--e2e-の分類)
  - [3.2 Mock の重複定義](#32-mock-の重複定義)
  - [3.3 ハードコード SocketAddr / Call-ID / branch](#33-ハードコード-socketaddr--call-id--branch)
  - [3.4 欠落シナリオ](#34-欠落シナリオ)
  - [3.5 RFC 引用が無いテスト](#35-rfc-引用が無いテスト)
- [4. 場当たり実装の棚卸し](#4-場当たり実装の棚卸し)
- [5. リファクタ計画 (フェーズ分け)](#5-リファクタ計画-フェーズ分け)
  - [Phase R1: テスト共通ハーネス](#phase-r1-テスト共通ハーネス)
  - [Phase R2: SIP メッセージ層整理](#phase-r2-sip-メッセージ層整理)
  - [Phase R3: SDP ネゴシエーション層](#phase-r3-sdp-ネゴシエーション層)
  - [Phase R4: B2BUA 状態機械の明文化](#phase-r4-b2bua-状態機械の明文化)
  - [Phase R5: Timer / 再送ロジック整合](#phase-r5-timer--再送ロジック整合)
  - [Phase R6: WebRTC レッグ完成](#phase-r6-webrtc-レッグ完成)
  - [5.7 並列エージェントへの prompt 草案](#57-並列エージェントへの-prompt-草案)
- [6. 緊急実機バグの優先度](#6-緊急実機バグの優先度)
- [Appendix A. dead/half-wired コード一覧](#appendix-a-deadhalf-wired-コード一覧)
- [Appendix B. assumption リスト](#appendix-b-assumption-リスト)

---

## 1. 責務分離レビュー

### 1.1 モジュール責務 マトリクス

| モジュール | 想定責務 (RFC) | 実装行数 | 評価 | 主要な逸脱 |
|---|---|---|---|---|
| `src/sip/message.rs` | RFC 3261 §7 メッセージ表現・パース・URI | 447 | ▲ | `SipMethod::Other(String)` は §27.4 IANA 登録メソッドの discriminator として使うべきで、unknown を 405 にする方針には逆効果 (§8.2.1)。`parse_sip_uri` は §19.1 の subset (`userinfo`, `parameters`, `headers` の dequote, `password`, `phone-context` 等を未対応)。 |
| `src/sip/transaction.rs` | RFC 3261 §17 トランザクション層 (Timer A/B/D/E/F/G/H/I/J/K) | 1125 | ▲ | UAC 側 Timer A/B/D は実装。**Timer E/F (non-INVITE 再送)** は `ClientState::Trying` 分岐で実装済だが INVITE と同じ "倍々 → T2 cap" のみ。**Timer G/H/I/J/K (server tx)** は未実装 (`ServerTransaction::handle_retransmit` は呼ばれるだけで自動駆動なし)。INVITE 2xx ACK 単発送出は `Uac` 側に実装され dialog 層責務として分離されているが、これは §13.2.2.4 では正しい。 |
| `src/sip/dialog.rs` | RFC 3261 §12, §13 ダイアログ・in-dialog request 構築 | 816 | ◎ | UAC/UAS 双方の dialog 構築まである。`build_reinvite` は実装済だが UAC 側だけで、**UAS 側 Re-INVITE 受信ハンドラは未実装** (`uas.rs::handle_request` の Invite 分岐が dialog の有無を見ない)。Route ヘッダ name-addr 判定 (line 406) は heuristic で `<` の出現位置のみ見ている。 |
| `src/sip/uac.rs` | RFC 3261 §8 / §13 UAC | 626 | ▲ | INVITE は `TransactionLayer::send_request` (Timer B 1 本) に投げるだけで、ACK 後の Timer L (RFC 6026 §7.1) は無い。`build_invite` 内で `Allow` ヘッダに NOTIFY / INFO を含めるが、UAS 側で 405 を返す `SipMethod::Other` 経路と矛盾。Re-INVITE では `parse_cseq_number` を `dialog.rs` と二重管理 (line 347 vs `dialog.rs:451`)。 |
| `src/sip/uas.rs` | RFC 3261 §8.2 UAS + §10 内線 Registrar 統合 | 883 | ▲ | `_layer: Arc<TransactionLayer>` を保持しているが、`ServerTransaction` を `tx_table` に登録する処理が無い。同一リクエストの再送 (Timer J 内) を `last_response` から自動再送する経路が無い。Auth は In-line で write されており §22 Authentication Framework の責務を `auth.rs` に分離しきれていない。~~`SipMethod::Other` を全部 405 で返している (line 314)~~ → 解消済 (Issue #273、 §4.4)。 |
| `src/sip/register.rs` | RFC 3261 §10 (UAC 側 REGISTER) + RFC 4028 (なし) | 323 | ◎ | NGN 直収 (auth=none) を綺麗に分岐済。だが `static CSEQ` (line 23) は **プロセス全体で 1 つ**: 多回線対応時に衝突する。Session Timer (RFC 4028) は REGISTER に乗らないので不要だが、コメントが誤誘導。再送 30 秒固定は §10.3 step 6 の "min interval" を考慮していない。 |
| `src/sip/registrar.rs` | RFC 3261 §10.3 (内線側 Registrar) | 238 | ◎ | API が `register` と `register_with_transport` の二重化 (line 98 vs 110)。**`register` 側は内部で `register_with_transport` を呼ぶラッパなので統合可能**。`Binding` に `transport: ExtTransport` を持ったため `contact_uri` が WebRTC では意味を持たない (`webrtc.peer` ダミー)。 |
| `src/sip/auth.rs` | RFC 2617 / RFC 7616 Digest | 339 | ◎ | MD5 only (RFC 7616 SHA-256 / SHA-512-256 未対応)。`auth-int` 未対応。`build_www_authenticate` の nonce が `new_call_id()` 由来で **再利用検出 (stale=true)** が実装されていない (常に固定 nonce 形式)。 |
| `src/sip/addr.rs` | NGN 直収用 source IP 検出 | 78 | ◎ | UDP `connect` トリックで一発取得。重複なし。 |
| `src/sip/utils.rs` | branch / Call-ID / tag 生成 | 16 | ◎ | 16 行のミニ helper。問題なし。 |
| `src/sdp/parser.rs` | RFC 4566 §5 パース | 242 | ◎ | media-level `c=` の order 制約 (b=, k= の前) は緩く解釈。multicast `<addr>/<ttl>` 未対応。**RFC 4566 §5.14 で proto は spec 化されていて (`UDP/TLS/RTP/SAVPF` 等) チェックすべきだが、生 string 保持**。 |
| `src/sdp/builder.rs` | RFC 4566 シリアライズ + RFC 3264 Offer/Answer 補助 | 382 | ✗ | **`restrict_audio_to_pcmu` (line 131) は §3 Offer/Answer 違反**。「片側で形式リストを切り詰める」操作は、本来 SDP answer 生成時に対応 PT を返すべきところを **proxy が offer 自体を改竄** している。これは B2BUA としては SDP オファ側を NGN 仕様に合わせ直す行為で、正しくは "媒介する SBC の SDP 翻訳" (RFC 5853) として記述するべき。 |
| `src/sdp/mod.rs` | SDP データ構造 | 365 | ◎ | `RtpMap` は `as_rtpmap()` でアクセス可能だが、`fmtp` / `ptime` / `direction` の構造化アクセサが無い (callers は `attributes.iter().find` で文字列比較)。 |
| `src/call/orchestrator.rs` | NGN ⇔ 内線 B2BUA orchestration | **3188** | ✗ | **巨大すぎる**。`NgnInboundHandler` (NGN 着信), `UasEventHandler` (内線発信), `OutboundCallRegistry` (B2BUA レジストリ), `fork_to_bindings` (transport-aware fork), `run_webrtc_leg` (WebRTC leg ハンドラ), 多数の helper を 1 ファイルで保持。テスト (3000 行中 ~1900 行) もここに同居。`normalize_request_uri_for_ngn` (line 539) が **定義のみで未使用** (commit `cba1cd2` の主機能が結線されていない)。 |
| `src/call/manager.rs` | フォーク INVITE + 通話状態テーブル | 624 | ▲ | `fork_to_extensions` (SIP-only) と `orchestrator::fork_to_bindings` (transport-aware) が並存。**前者は orchestrator では使われず**、テストからのみ呼ばれる。 |
| `src/call/bridge.rs` | RTP リレー (G.711 transparent) | 355 | ◎ | 設計はクリーン。late-binding peer learning も適切。 |
| `src/call/transcoder.rs` | Opus ↔ G.711 トランスコード | 676 | ◎ | bridge.rs と並列にあるが responsibilities がはっきり分かれている。**しかし `orchestrator.rs` から `TranscodingBridge` は呼ばれていない**。WebRTC binding の経路で結線されるべきところがそのまま `RtpBridge` (G.711 透過) に流れている。これは **Phase 4 の致命的欠落**。 |
| `src/webrtc/signaling.rs` | WS シグナリング JSON プロトコル | 930 | ◎ | `process_client_message` を分離してテスト容易性を確保している。**ただし PendingAnswers は `signaling.rs` 内部の Public API として漏れて registrar.rs / orchestrator.rs に再 import されている** (層越境)。 |
| `src/webrtc/peer.rs` | PeerSession trait + stub | 222 | ◎ | trait 設計は良い。 |
| `src/webrtc/str0m_session.rs` | str0m バックエンド | 559 | ▲ | ICE-Lite で接続まで動くが、**`Event::MediaData` を drop している (line 386 TODO #29)**。受信 RTP を CallManager / TranscodingBridge へ橋渡しする経路が結線されていない。IPv6 public_ip は未対応 (line 405)。 |
| `src/webrtc/auth.rs` | HMAC-SHA256 トークン | 212 | ◎ | 簡潔。 |
| `src/observability/mod.rs` | メトリクス + SIP トレース | 713 | ◎ | 自前実装で外部依存なし。`Authorization` redact あり。 |
| `src/health/mod.rs` | K8s probe + Prometheus | 263 | ◎ | clean。 |
| `src/config/mod.rs` | TOML + env override | 644 | ◎ | NGN 直収モード分岐あり。 |
| `src/dhcp/mod.rs` | DHCP Option 120 | 51 | ◎ | 環境変数 / lease ファイル両対応。 |

凡例: ◎ = 概ね責務適切、▲ = 改善余地あり、✗ = 責務逸脱・大規模リファクタ必要。

### 1.2 重複・層越境の指摘

| # | 重複箇所 | 重複先 | 統合先 | 優先度 |
|---|---|---|---|---|
| D1 | `extract_uri` (name-addr / addr-spec から URI 抽出) | `src/sip/dialog.rs:422`, `src/sip/uas.rs:503` (`extract_uri_from_contact`), `src/call/orchestrator.rs:1319` (`extract_uri_from_addr`) | `src/sip/header.rs::extract_uri` (新設) | 高 |
| D2 | `ensure_to_tag` (To に tag 付与) | `src/sip/uas.rs:515`, `src/call/orchestrator.rs:571` | `src/sip/header.rs::ensure_to_tag` | 高 |
| D3 | `parse_cseq_number` | `src/sip/uac.rs:347`, `src/sip/dialog.rs:451` | `src/sip/header.rs::parse_cseq_number` | 高 |
| D4 | `parse_tag` | `src/sip/dialog.rs:440` のみだが extract_uri と一緒に集約すべき | `src/sip/header.rs::parse_tag` | 中 |
| D5 | `normalize_header_key` (compact 展開) と `canonical_header_name` (lower→Title) | `src/sip/message.rs:183` と `:213` の 2 表 (片方向ずつ) | 1 つの `HeaderName` enum + lookup table へ | 中 |
| D6 | `parse_via` (transaction.rs 内 private), branch 取り出し | `src/sip/transaction.rs:93` | header.rs に公開 helper として移動 | 中 |
| D7 | mock NGN UAS / mock 内線 UAS / mock WebRTC peer | `src/call/orchestrator.rs::tests` 内に各テスト関数で個別定義 (~5 種) + `src/sip/transaction.rs::tests` + `src/sip/uac.rs::tests` + `src/sip/uas.rs::tests` | `tests/common/mod.rs` に集約 (Phase R1) | 高 |
| D8 | mock `ScriptedInviter` | `src/call/manager.rs::tests` と `src/call/orchestrator.rs::tests` で **別構造体** (フィールド構成も別) | `tests/common/scripted_inviter.rs` (Phase R1) | 高 |
| D9 | `extract_rtp_endpoint` の helper | `src/call/manager.rs:324` のみだが `orchestrator.rs::tests` で reimport している | OK (公開関数として正しい) | - |
| D10 | `register` と `register_with_transport` API 二重化 | `src/sip/registrar.rs:98, 110` | `register_with_transport` 1 本に統合 (デフォルト transport 引数化) | 中 |
| D11 | `wire_ngn_inbound` / `wire_ngn_inbound_with_metrics` / `wire_ngn_inbound_with_manager` | `src/call/orchestrator.rs:1584-1632` | builder pattern (`NgnInboundConfig::wire().with_manager(...).with_metrics(...).spawn(...)`) | 低 |
| D12 | `set_dscp` (NGN SIP) と `set_rtp_dscp` (RTP) | `src/main.rs:391` と `src/rtp/mod.rs:80` (ほぼ同一実装) | `src/net/dscp.rs::set_dscp(socket, dscp)` に共通化 | 低 |

層越境:
- `src/sip/registrar.rs` が `crate::webrtc::peer::PeerSession` と `crate::webrtc::signaling::{PendingAnswers, WsSink}` を **直接 import** (line 22-23)。SIP レイヤが WebRTC レイヤに依存してはならない。`ExtTransport::WebRtc` バリアントを registrar.rs から外し、代わりに `Box<dyn ExtCallTarget + Send + Sync>` のような **trait object 越し**にすべき。
- `src/call/orchestrator.rs::run_webrtc_leg` (line 1500) で SIP `Via` ヘッダに `SIP/2.0/WS webrtc.peer` という **嘘の値**を入れ偽の SipResponse を組み立てている (line 1549-1561)。fork_to_bindings 内部の dispatch 結果として SipResponse を再構築するのは抽象化漏れで、**LegOutcome に SDP body だけ詰めて返す形**が正しい。

### 1.3 B2BUA 状態機械の整理

現状の B2BUA は 2 つの handler に分散している:

```
内線 → sabiden ──┐
                ├─── UasEventHandler::handle_event
                │      ├── Invite     → ngn_uac.invite + registry.insert_pending → registry.insert_confirmed
                │      ├── Bye        → registry.remove_by_ext + ngn_dlg.send_bye
                │      ├── Cancel     → registry.get_pending + ngn_uac.cancel_pending
                │      └── Ack        → registry.lookup_by_ext (status check only)
                └── handle_ngn_bye (NGN→内線方向; Forwarder trait 経由)

NGN  → sabiden ──┐
                └─── NgnInboundHandler::handle_inbound
                       ├── Invite  → fork_to_bindings → 200 OK + RTP bridge
                       ├── Bye     → outbound_forwarder.try_forward_bye OR 既存 inbound active を消す
                       ├── Ack     → pending を 1 つ消す
                       └── Cancel  → 200 OK + (元 INVITE を 487 で閉じる責務は呼び出し側)
```

問題点:

1. **状態遷移が 2 つの構造体 × 4 つの HashMap (`pending` / `active` / `by_ext` / `ngn_to_ext`) に分散**しており、1 通話のライフサイクルが追えない。
2. **`active` (NGN→内線) と `by_ext` / `ngn_to_ext` (内線→NGN) が別レジストリ**。NGN→内線 BYE は `outbound_forwarder.try_forward_bye` で内線→NGN 経路を先に試し、ヒットしなければ `active` を見るという 2 段ルックアップ構造で、判定漏れが出やすい。
3. **CANCEL race の保護が `cancelled_flag` AtomicBool 1 個**。NGN INVITE が 200 OK 成立直前に CANCEL が来た場合、`Uac::invite` の future が完了して `Established` を返した時点で `was_cancelled` を確認し、立っていたら NGN BYE を発射する (line 938-951)。これは正しいが **race の検証テストが 1 個 (`ext_cancel_propagates_to_ngn_and_returns_487`) だけ**で、**「CANCEL 200 vs INVITE 200 の glare race」** は未テスト。
4. **`OutboundCallEntry::ext_dialog: Mutex<Dialog>` と `ngn_dialog: Mutex<UacDialog>` を別 Mutex で持っている**。BYE 連動時に lock 順序を間違えるとデッドロックが起きうる (現状は同時 lock しないので OK だが、コードレビュー耐性なし)。
5. **Re-INVITE / UPDATE 対応なし**。`UasEventHandler::handle_event` の match arm に Re-INVITE 用分岐がない。`uas.rs::handle_invite` も dialog 既存判定をせず、Re-INVITE が来たら新規 INVITE 扱いで二度発信する。
6. **ACK 確認なし**。RFC 3261 §13.3.1.4 では UAS は ACK が来るまで Timer H で 2xx を再送する責務があるが、内線レッグの sabiden は ACK を受けても `lookup_by_ext` で確認するだけで、Timer H 駆動はしていない。

提案: **`B2buaCall` 単一構造体で 1 通話を管理**する (Phase R4 で実施)。

```rust
// 提案: src/call/b2bua.rs
pub struct B2buaCall {
    id: CallId,
    ext_call_id: String,
    ngn_call_id: String,
    state: B2buaState,                        // OutboundProgressing | InboundProgressing | Connected | Terminating
    legs: B2buaLegs,                          // ext: ExtLeg, ngn: NgnLeg
    bridge: Option<BridgeKind>,               // RtpBridge | TranscodingBridge
    direction: B2buaDirection,                // Outbound (内線→NGN) | Inbound (NGN→内線)
    cancel_flag: tokio::sync::Notify,
}

pub struct B2buaRegistry {                    // 内線/NGN/Call-ID 全部から引ける単一レジストリ
    by_call_id: HashMap<CallId, Arc<B2buaCall>>,
    by_ext_call_id: HashMap<String, CallId>,
    by_ngn_call_id: HashMap<String, CallId>,
}
```

### 1.4 SDP コーデック交渉の現状

`restrict_audio_to_pcmu` の置き場所:
- `src/sdp/builder.rs:131` (定義)
- `src/call/orchestrator.rs:909` (内線→NGN INVITE 直前で適用): **唯一の callsite**

これは **本来 SDP Offer/Answer (RFC 3264) 層の責務**で、現在の構成は以下の問題がある:

1. **NGN → 内線方向で同等の絞り込みが存在しない**。NGN が PCMU only の offer を出しても、内線 (Linphone) はすでに対応するので問題は出ないが、Re-INVITE で内線が PCMU 以外を含む answer を返したら NGN は 488 になる。
2. **B2BUA は本来 offer/answer を再構築すべき** (RFC 5853 §3.5 "Topology Hiding"): 内線が出した multi-codec offer を NGN レッグでは PCMU only の **新しい offer** に置き換え、NGN からの PCMU answer を内線レッグでは内線が出した formats のうち PCMU を選んだ **新しい answer** に置き換えるのが正しい。
3. `restrict_audio_to_pcmu` の WebRTC 系属性ブラックリスト (`fingerprint`, `setup`, `ice-*`, `candidate`, `rtcp-mux` 等) は **PCMU only 化と直交する別の処理** で、命名と責務が不一致。NGN は AVP しか喋らないのでこれらを剥がす必要があるが、本来は `sdp::translate_for_ngn(offer)` のような専用関数で行うべき。
4. NGN→内線方向の **SDP rewrite (sabiden の RTP socket を指す)** は `rewrite_rtp_endpoint` (builder.rs) で適切に実装されているが、`restrict_audio_to_pcmu` と sequence で呼ばれるため (orchestrator.rs:909 の直前で `prepare_outbound_bridge` が `rewrite_rtp_endpoint` を呼び、その後で `restrict_audio_to_pcmu` が走る) **どちらが先か順序依存**。

提案: `src/sdp/negotiation.rs` を新設し、Offer/Answer 専用 API を提供する (Phase R3)。

```rust
// 提案: src/sdp/negotiation.rs
pub struct Negotiator { allowed_codecs: Vec<RtpCodec> }
impl Negotiator {
    pub fn for_ngn() -> Self { /* PCMU only */ }
    pub fn rewrite_offer_for_ngn(&self, offer: &[u8]) -> Result<Vec<u8>>;
    pub fn rewrite_answer_for_ext(&self, ext_offer: &[u8], ngn_answer: &[u8]) -> Result<Vec<u8>>;
    pub fn relay_endpoint(&self, sdp: &[u8], local: SocketAddr) -> Result<Vec<u8>>;
}
```

### 1.5 ヘッダ操作の二重管理

- `normalize_header_key` (`message.rs:183`): compact form (`v` → `via` 等) を **入口で展開**
- `canonical_header_name` (`message.rs:213`): lower-case 内部表現を **出口で大文字化**

問題:
1. 2 表が独立メンテで、`p-asserted-identity` のような hyphen 入りヘッダを片方だけ書き忘れるリスクがある。
2. `normalize_header_key` の compact 展開リストには `o → event` (RFC 3265) があるが、`canonical_header_name` には `event → Event` の逆引きが無いため、Event ヘッダが小文字で出力される。これは仕様上は許容 (case-insensitive) だが NGN 互換のため統一すべき。
3. compact `j → reject-contact` などは P-CSCF が使わない可能性が高く、対応する `canonical_header_name` の逆引きも整備されていない。

提案: `enum HeaderName { Via, From, To, ... }` + `&'static str <-> HeaderName` の両方向 lookup table を 1 つの `header_name.rs` に集約 (Phase R2)。

### 1.6 Transaction ↔ TU 層の分離

現状:
- TransactionLayer は `inbound_tx: mpsc::UnboundedSender<InboundRequest>` で **TU (= 上位層) にすべての受信リクエストを生送り** している。
- 同一リクエストの再送 (UDP では起こりえる) を **検出しない**。`recv_loop` (line 527) は来たメッセージを毎回 TU に渡し、TU 側 (UAS / NgnInboundHandler) が `pending` HashMap で重複検出する責務を持つ。
- これは RFC 3261 §17.2.3 違反: **"Each request matches a server transaction or creates a new one"** であり、**transaction layer が server tx を保持して再送 → 最後の応答再送** を行うべき。

具体的な穴:
- `NgnInboundHandler::handle_invite` で同じ Call-ID (= 同じ INVITE 再送) が来ると、毎回 `ServerTransaction::new` で新しい server tx を作り、`pending.insert(call_id, ...)` で **上書き** (line 301)。これは「Call-ID 単位での重複排除」であり、本来は `TransactionId (branch + sent-by + method)` 単位であるべき。
- 結果、同じ INVITE の 2 回目以降の再送に対して 100 Trying を再生成して送り返している (NGN 側ピアが 32s 以内に多重 INVITE すると、200 OK 完了後の再送に対しても新 server tx が作られる)。

提案 (Phase R5):
- `TransactionLayer` 内に `server_tx_table: HashMap<TransactionId, Arc<Mutex<ServerTransaction>>>` を持たせ、recv_loop で server tx をマッチさせる。
- マッチしたら **最後に送った応答を再送** (`ServerTransaction::handle_retransmit`)。新規なら inbound_tx に流す。
- `NgnInboundHandler`/`ExtensionUas` は `pending` テーブルを廃止し、TU としては `ServerTransaction` のハンドルを受け取るだけにする。

---

## 2. RFC 3261 カバレッジマトリクス

凡例: ✓ = 実装済 / △ = 部分実装 / ✗ = 未実装 / N/A = sabiden として不要。

| Section | 内容 | 状態 | 実装ファイル | band-aid / メモ |
|---|---|---|---|---|
| §6 | Definitions | ✓ | (定義のみ) | |
| §7.1 | Requests | ✓ | `message.rs::SipRequest` | `to_bytes` で必ず Content-Length を付与 |
| §7.2 | Responses | ✓ | `message.rs::SipResponse` | |
| §7.3 | Header Fields | △ | `message.rs::SipHeaders` | compact↔full 二重管理 (§1.5)。Q-value, comma-separated 値の split は不完全 (Route のみ split_route_header で対応) |
| §7.3.1 | Header Field Format | △ | `parse_message` (line 303) | 改行折り返し (LWS) で値が複数行になるケース未対応 |
| §7.3.3 | Compact Form | ✓ | `normalize_header_key` | NGN 受信のため必須 |
| §7.4 | Bodies | ✓ | `parse_message` body 抽出 | multipart 未対応 (NGN では不要) |
| §8.1.1.1 | Request-URI | △ | UAC は `target_uri` を直に使う | `normalize_request_uri_for_ngn` 定義済だが **未呼出** (commit `cba1cd2` 失効状態) |
| §8.1.1.2 | To | ✓ | dialog.rs / register.rs | NGN ドメインへの正規化は機能していない (上記と連動) |
| §8.1.1.3 | From | ✓ | tag 付与 utils::new_tag | |
| §8.1.1.4 | Call-ID | ✓ | utils::new_call_id | |
| §8.1.1.5 | CSeq | △ | dialog.rs::Dialog::local_cseq, register.rs static CSEQ | REGISTER の static CSEQ がプロセス全体で 1 つ → 多回線で衝突 |
| §8.1.1.6 | Max-Forwards | ✓ | 各 builder が "70" を設定 | |
| §8.1.1.7 | Via | ✓ | dialog.rs / register.rs / uac.rs | rport 不付与 (NGN 制約)。複数 Via の rotate (proxy 中継時) は未対応 (sabiden は B2BUA のみ) |
| §8.1.1.8 | Contact | △ | uac.rs::contact_uri / register.rs | name-addr で `<>` 必須だが addr-spec 形式の Contact (UA からの REGISTER で `;` 含む) のパースは `extract_uri_from_contact` (uas.rs:503) のみ。Contact パラメータ (q, expires) の扱いが parse_register_expires (line 485) でのみ処理。 |
| §8.1.1.9 | Supported / Require / Allow | △ | uac.rs build_invite に `Supported: timer` / `Allow: INVITE,...` | UAS 側で送信側 Allow を読まない → 100rel / replaces 等の協調なし |
| §8.1.2 | Sending the Request | ✓ | TransactionLayer::send_request | |
| §8.1.3 | Processing Responses | △ | UAC は最終応答を受信して終了 | 3xx redirect (Contact follow) 未対応 |
| §8.1.3.5 | Processing 4xx Responses | △ | 401 → Authorization 再送 (REGISTER のみ) | INVITE で 401/407 を受けた場合の再送経路なし (`Uac::invite` は Failed として返すだけ) |
| §8.2 | UAS Behavior | △ | uas.rs / orchestrator.rs::NgnInboundHandler | 100 Trying は INVITE のみ (REGISTER でも要らないので OK)。merged request 検出 §8.2.2.2 未対応。 |
| §8.2.1 | Method Inspection | ✓ | uas.rs::handle_request で method 別 status | Issue #273 で解消。 NOTIFY→481 / SUBSCRIBE→489 / PRACK→481 / PUBLISH→200 / UPDATE→481 / MESSAGE→200 / REFER→405 / Other→405、 すべて `Allow` ヘッダ付き (§4.4 参照)。 |
| §8.2.2.1 | To/From/Call-ID/CSeq | ✓ | build_response_skeleton | |
| §8.2.2.2 | Merged Requests | ✗ | なし | 同一 (Request-URI, From-tag, Call-ID, CSeq) の重複検出 |
| §8.2.3 | Adjusting the Header Field Values | △ | dialog.rs Record-Route reverse 等 | sabiden は Proxy ではなく UA なので Record-Route 自身が記録する経路は無い |
| §8.2.5 | Stateful Forwarding | N/A | sabiden は B2BUA (proxy ではない) | |
| §8.2.6.1 | Sending a Provisional Response | ✓ | uas.rs `responder.quick(100, "Trying")` | |
| §8.2.6.2 | Headers and Tags (To-tag) | ✓ | ensure_to_tag (uas.rs / orchestrator.rs 重複) | |
| §10 | REGISTER | ✓ | register.rs (UAC) / uas.rs+registrar.rs (UAS) | NGN 直収モードあり |
| §10.2.4 | Refreshing Bindings | ✓ | register.rs `run` ループで `expires*0.9` で再送 | |
| §10.3.6 | RegisterEvent | ✗ | なし | NOTIFY reg-event を受け付けない |
| §12 | Dialogs | ✓ | dialog.rs | UAC/UAS 両方の dialog 確立。ただし Early dialog の状態 (1xx with to-tag) と forking dialog の追跡は弱い (1 INVITE につき 1 Dialog 前提) |
| §12.2.1.1 | UAC In-Dialog Request | ✓ | dialog.rs::build_bye / build_reinvite / build_ack_for_2xx | strict-routing 対応あり |
| §12.2.1.2 | Sending Within a Dialog | △ | UacDialog::send_bye / send_reinvite | 401 in-dialog 受信時の再認証経路なし |
| §13 | Initiating a Session | △ | uac.rs::Uac::invite | フル INVITE 駆動。3xx/4xx 401/407/422 経路はなし |
| §13.2.1 | Creating Initial INVITE | ✓ | uac.rs::build_invite | |
| §13.2.2.1 | 1xx Provisional | ✓ | TransactionLayer ClientState::Proceeding | early dialog 確立 (`Dialog::from_uac_response` で 1xx with to-tag を Early に) |
| §13.2.2.2 | 3xx Redirection | ✗ | なし | |
| §13.2.2.3 | 4xx, 5xx, 6xx Final | ✓ | uac.rs::InviteOutcome::Failed | |
| §13.2.2.4 | 2xx Final + ACK | ✓ | uac.rs invite() + dialog.rs::build_ack_for_2xx | 2xx ACK は再送制御なし (TU 責務だが本実装は単発送出のみ) |
| §13.3.1.4 | UAS 200 OK 再送 (Timer H) | ✗ | なし | UAS 側で ACK 待ちタイマがない |
| §14 | Modifying an Existing Session | ✗ | UAC のみ build_reinvite で構築可、UAS 受信ハンドラなし | Re-INVITE 受信は §1.3 #5 |
| §15.1.1 | UAC Sending BYE | ✓ | UacDialog::send_bye | |
| §15.1.2 | UAS Receiving BYE | ✓ | uas.rs handle_bye / orchestrator.rs handle_ext_bye | |
| §16 | Proxy Behavior | N/A | sabiden は proxy ではない | |
| §17.1.1 | INVITE Client Transaction | ✓ | transaction.rs ClientTransaction | Timer A (再送), Timer B (タイムアウト 32s), Timer D (32s) は実装。Calling/Proceeding/Completed/Terminated 状態あり |
| §17.1.1.3 | non-2xx ACK 自動送出 | ✓ | transaction.rs build_non2xx_ack | commit `03e4564` で実装済 |
| §17.1.2 | non-INVITE Client Transaction | △ | transaction.rs ClientTransaction (同じ駆動) | Timer E は INVITE と同じ "倍々→T2 cap" で実装。Timer F (タイムアウト) は Timer B と同じ TIMER_B 定数 (64*T1) で代用しているが、§17.1.2.2 では Timer F は 64*T1 で正しい。Timer K (5s) は **未実装** |
| §17.2.1 | INVITE Server Transaction | △ | ServerTransaction + state | Timer G (200 OK 再送) と Timer H (ACK タイムアウト) と Timer I は **未実装** |
| §17.2.2 | non-INVITE Server Transaction | △ | ServerTransaction | Timer J (response retransmit absorption) は未実装 (`handle_retransmit` 関数はあるが driver なし) |
| §17.2.3 | Matching Requests to Server Transactions | ✗ | transaction.rs に server tx table が無い | §1.6 で詳述。`pending` HashMap (Call-ID 単位) で代用しているのが band-aid |
| §18 | Transport | △ | UDP のみ | TCP/TLS 未対応 (NGN は UDP のみ) |
| §18.1.2 | Sending Responses | ✓ | response の Via top で得た rport/received は使わず Via sent-by で送る (NGN 制約) | |
| §18.3 | Framing | ✓ | UDP datagram = 1 メッセージ | |
| §19.1 | SIP and SIPS URI | △ | message.rs::parse_sip_uri | userinfo password 部、headers 部、escape (`%` 16進) 未対応 |
| §22.1 | HTTP Authentication | △ | auth.rs Digest MD5 / qop=auth | RFC 7616 SHA-256 未対応。`auth-int` 未対応。stale=true 時の挙動なし |
| §22.4 | Authorization | ✓ | uas.rs handle_register / handle_invite | |
| §23 | S/MIME | N/A | | |
| §24 | Examples | N/A | | |
| §25 | ABNF | N/A | | |
| §26 | Security | △ | observability で Authorization redact あり | TLS 未対応 |
| §27 | IANA Considerations | N/A | | |

その他関連 RFC:
| RFC | 内容 | 状態 | 実装/メモ |
|-----|---|---|---|
| RFC 2617 / 7616 | HTTP Digest | △ | MD5 only |
| RFC 3262 (PRACK / 100rel) | Reliable Provisional Responses | ✗ | NGN 通常運用では不要だが PSTN gateway 経路で 183 Session Progress + PRACK が来る場合あり |
| RFC 3264 | SDP Offer/Answer Model | △ | builder.rs に補助はあるが Negotiator 不在 (§1.4) |
| RFC 3265 | Event Notification (SUBSCRIBE/NOTIFY) | ✗ | Linphone presence で送信される PUBLISH/NOTIFY を 405 化 |
| RFC 3311 | UPDATE | ✗ | 405 化 (uas.rs:314) |
| RFC 3327 (Path) | Path ヘッダ | ✗ | NGN P-CSCF が REGISTER で要求する場合あり (要 SIP Trace 確認) |
| RFC 3550 | RTP | ✓ | rtp/ |
| RFC 3551 | RTP Profile (PCMU PT=0) | ✓ | rtp::encode_ulaw / decode_ulaw |
| RFC 3581 (rport) | Symmetric Response Routing | ✗ | NGN は rport を拒否するため**意図的に未実装** |
| RFC 3960 (early media) | Early Media | △ | 1xx with SDP の処理は dialog.rs Early state までで止まる。RTP ブリッジは 200 OK まで起動しない |
| RFC 4028 | Session Timer | △ | UAC build_reinvite に `Session-Expires: 300;refresher=uac` 設定済。**422 Session Interval Too Small への自動再交渉なし**。**Refresher 送信タイマ駆動なし** (Session-Expires 期限到達時に Re-INVITE を自動送出する loop が存在しない) |
| RFC 4566 | SDP | ✓ | sdp/ |
| RFC 5626 (Outbound) | Managing Client-Initiated Connections | ✗ | NGN 直収では不要 |
| RFC 5853 | SBC | △ | B2BUA + SDP 翻訳 (Topology Hiding) を **暗黙に** 実装しているが命名・責務分離なし |
| RFC 6026 (Timer L) | INVITE Server Tx | ✗ | Timer L (= 64*T1, ACK 受領後の Confirmed 維持) 未実装 |
| RFC 8835 (WebRTC requirements) | WebRTC + SIP Interop | △ | 関連実装は webrtc/、ICE/DTLS-SRTP は str0m で動くが G.711↔Opus トランスコードは未結線 |

---

## 3. テストアーキテクチャ評価

### 3.1 単体 / 結合 / E2E の分類

| 種別 | 場所 | 件数概算 | コメント |
|---|---|---|---|
| 単体 (純関数) | sip/message.rs, sip/auth.rs, sdp/parser.rs, sdp/builder.rs, sip/utils.rs, observability/, webrtc/auth.rs | ~40 | 純粋ロジックで OK |
| 単体 (async, mock socket) | sip/transaction.rs, sip/dialog.rs, sip/uac.rs, sip/uas.rs, sip/registrar.rs, rtp/jitter.rs, rtp/session.rs, rtp/codec/* | ~50 | tokio::test + UdpSocket loopback |
| 結合 (B2BUA round trip) | call/orchestrator.rs::tests | ~12 | 巨大。1 テストが 200-300 行 |
| 結合 (RTP relay) | call/bridge.rs::tests, call/transcoder.rs::tests | ~8 | OK |
| E2E (HTTP + WS) | webrtc/signaling.rs::end_to_end_ws_* | ~2 | axum + tokio-tungstenite |
| 統合 (実機 SIP) | なし (`tests/` ディレクトリ未使用) | 0 | **欠落**。`Cargo.toml` で integration test 用の `tests/` クレートが空 |

### 3.2 Mock の重複定義

**`ScriptedInviter`** が 2 箇所で **別構造体** として定義されている:

| 定義場所 | フィールド | 振る舞い |
|---|---|---|
| `src/call/manager.rs:349` | `scripts: HashMap<target → ScriptedAction>`, `called: Vec<String>`, `invocation_count: AtomicUsize`, `ScriptedAction { ImmediateStatus, DelayedStatus, NeverRespond }` | per-target 振る舞い指定 |
| `src/call/orchestrator.rs:1647` | `status: u16`, `body: Vec<u8>`, `called: AtomicUsize`, `seen_targets: Mutex<Vec<String>>` | 全 target で同じ status 返す |

→ Phase R1 で `tests/common/scripted_inviter.rs` に統合し、両用途を満たす API に。

**Mock NGN UAS** (フェイク NGN サーバ):
- `transaction.rs:1014` (`test_invite_non2xx_triggers_ack_and_absorbs_retransmits`)
- `uac.rs:421` (`invite_2xx_establishes_dialog_and_sends_ack`)
- `uac.rs:543` (`cancel_sends_cancel_with_invite_branch`)
- `register.rs:228` (`register_succeeds_without_password_when_200`)
- `register.rs:278` (`register_bails_on_401_without_password`)
- `orchestrator.rs:1885` (`uas_event_proxies_invite_to_ngn`)
- `orchestrator.rs:2240` (`uas_event_with_call_manager_starts_rtp_bridge`)
- `orchestrator.rs:2452` (`ext_bye_propagates_to_ngn`)
- `orchestrator.rs:2641` (`ngn_bye_propagates_to_ext`)
- `orchestrator.rs:2814` (`ext_cancel_propagates_to_ngn_and_returns_487`)

→ いずれも `tokio::spawn` で `UdpSocket::bind("127.0.0.1:0")` → `recv_from` で INVITE 受信 → 任意ステータスを返す、というパターン。**Phase R1 で `tests/common/mock_ngn.rs` に集約**:

```rust
pub struct MockNgn { sock: Arc<UdpSocket>, addr: SocketAddr }
impl MockNgn {
    pub async fn bind() -> Self { ... }
    pub fn addr(&self) -> SocketAddr { self.addr }
    pub fn run_scenario(self, scenarios: Vec<Scenario>) -> JoinHandle<MockNgnReport>;
}
pub enum Scenario {
    Expect(Method) -> Send(StatusCode, SdpAnswer),
    Expect(Method) -> SendDelayed(Duration, StatusCode, SdpAnswer),
    SendInvite(Address, ...),
    Disconnect,
}
```

**Mock 内線 UAS / 内線 UA**:
- `orchestrator.rs::tests` で `phone_sock = UdpSocket::bind` + 手書き INVITE を毎テスト書いている (~10 箇所)
- → `tests/common/mock_ext.rs::MockExtension::send_invite(target, sdp_offer)`, `recv_response()` 等

**Mock WebRTC peer**:
- `peer.rs::StubPeerSession`: 既に存在しているが `cfg(test)` ではなく **prod コードに置いている**。これは prod ビルドに無駄なコードが入る (現状 `webrtc.backend = "stub"` でも使われるので削れない)
- Phase R6 でバックエンド完成後、stub は test only に隔離

### 3.3 ハードコード SocketAddr / Call-ID / branch

| 種別 | 出現箇所 (代表例) | 件数概算 |
|---|---|---|
| `"127.0.0.1:0"` (loopback bind) | 全テスト | 90+ |
| `"127.0.0.1:9999"` (架空 dst) | orchestrator.rs:3008 | 数件 |
| `"192.0.2.1"`, `"2001:db8::1"` (RFC 5737/3849 doc IP) | dialog.rs, transaction.rs, uac.rs | 30+ |
| Call-ID `"scripted-callid"`, `"ngn-bridge-cid"`, `"ext-bye-cid"`, `"ngn-webrtc-cid"` 等 | orchestrator.rs テスト | 15+ |
| branch `"z9hG4bKtest"`, `"z9hG4bKngn1"`, `"z9hG4bKbridge1"`, `"z9hG4bKextbye1"` 等 | テストごとに手書き | 30+ |

→ Phase R1 で `tests/common/fixtures.rs::{call_id_for_test, branch_for_test, doc_ipv6, doc_ipv4}` を提供し、**意味付け付き** にする (`call_id_for_test("ngn-bye")` 等)。

### 3.4 欠落シナリオ

| シナリオ | 重要度 | 補足 |
|---|---|---|
| **Re-INVITE (Session Timer 自動更新)** | 高 | `dialog::build_reinvite` のテストはあるが、`Dialog::confirm` で session-expires が更新されるパスは未テスト。422 Session Interval Too Small 受信時の再交渉はそもそも実装なし |
| **Re-INVITE 受信 (UAS 側)** | 高 | UAS handle_invite が dialog 既存判定をしないバグの回帰テストなし |
| **UPDATE (RFC 3311)** | 中 | NGN 一部キャリアで session refresh に UPDATE が来る |
| **CANCEL race (200 OK と CANCEL の glare)** | 高 | `cancelled_flag` の検証は orchestrator.rs:2808 に 1 つあるが、200 OK が CANCEL より先に届くケース未テスト |
| **BYE 競合 (両側同時 BYE)** | 中 | 内線と NGN がほぼ同時に BYE を送るケースの動作未保証 |
| **401 再認証 (INVITE)** | 高 | UAC は INVITE で 401/407 を Failed にする (`Uac::invite` line 184)。実機では起こりうるので再認証経路がほしい |
| **REGISTER 401 → 401 (nonce stale)** | 中 | 再 nonce 取得経路なし |
| **NGN 100rel/PRACK** | 低 | NGN フレッツ標準では出ないが、海外接続経路で混入する可能性 |
| **Forking response** | 低 | 1 INVITE → 複数 dialog (同 Call-ID, 異 To-tag) は B2BUA では考慮不要だが将来 |
| **REGISTER 500 サーバ過負荷再送バックオフ** | 中 | 30 秒固定はリトライストームを起こし得る |
| **Timer A 再送が 2xx 受信前に N 回失敗 → アプリ層通知** | 中 | TIMER_B 満了時の error 通知経路はあるが、I/O エラーは reception loop 終了まで返らない |
| **メッセージ パース失敗 → 400 Bad Request** | 低 | 現状は parse 失敗を warn だけして drop。RFC §17.2 では 400 を返すケースがある |
| **Content-Length 不一致 / overflow** | 中 | parse_message は CRLFCRLF 後を全部 body とみなす。Content-Length より長いメッセージで誤動作可能性あり |
| **大きなメッセージ (UDP datagram size > 8192 = `recv_loop` の buf)** | 中 | `transaction.rs:528` で固定 8192 バイト。NGN の 200 OK が大きい場合 (Path / Service-Route 多段) で truncate |
| **IPv6 dual-stack の Linphone 内線** | 中 | 内線レッグの bind が `127.0.0.1` 固定 (main.rs:381) |
| **WebRTC ICE failed の中断パス** | 中 | `Str0mPeerSession` で ICE failure 時の close と pending answer cancel の連動なし |
| **WebRTC trickle ICE 中断 (browser disconnect)** | 中 | local_cand_rx が drop されたときの run_loop の終了条件は disconnect のみ |
| **NGN INVITE without SDP body** | 中 | 着信フォーク時に offer SDP 空で `extract_rtp_endpoint` が err を投げ "RTP ブリッジ起動失敗 → SDP 透過で続行" になるが、その場合の RTP は流れない |

### 3.5 RFC 引用が無いテスト

`grep -n 'RFC' src/**/tests` 相当で確認:
- 引用あり: `transaction.rs::test_build_non2xx_ack_copies_headers_per_rfc3261_17_1_1_3` (RFC 3261 §17.1.1.3 をテスト名に明記)
- 引用あり: `dialog.rs::ack_via_does_not_contain_rport` ("NTT NGN 制約" コメント)
- 引用あり: `dialog.rs::record_route_is_reversed_for_uac` ("RFC 3261 §12.1.2")
- **引用なし**: `transaction.rs` の他の全テスト, `uac.rs::cancel_sends_cancel_with_invite_branch` (RFC 3261 §9.1 を引くべき), `uas.rs::register_with_digest_succeeds` (RFC 2617/3261 §22), `register.rs::register_succeeds_without_password_when_200` (Issue #37 への参照のみ。RFC 引用なし)
- **引用なし**: `orchestrator.rs::tests` の全テスト (B2BUA は標準化されていないので "RFC 5853 §3" を引くのが適切)

→ Phase R1 で **テスト名付与規約** を導入: `<rfc>_<section>_<scenario_in_japanese>`。例: `rfc3261_17_1_1_3_non2xx_ack_uses_response_to_tag`。

---

## 4. 場当たり実装の棚卸し

### 4.1 TODO / FIXME / XXX / HACK

| 場所 | 内容 | カテゴリ |
|---|---|---|
| `src/lib.rs:8` | `// (TODO: モジュール毎に絞る)` | 残課題 |
| `src/main.rs:254-258` | `// 実装簡略化のため、forker の各 leg は target URI のホスト部を解決して送る...` | 残課題 (Issue #16) |
| `src/main.rs:379-381` | `/// Phase 1 では LAN 内ループバック想定で簡略化する` (`ext_registrar_local_ip_or_loopback`) | band-aid |
| `src/sip/registrar.rs:8` | "Issue #4 の Phase 1 では in-memory のみで十分" | 残課題 |
| `src/webrtc/str0m_session.rs:386` | `// TODO(#29): Opus → G.711 トランスコード経由で内線/NGN 側 RTP に` | **致命的欠落** |
| `src/webrtc/str0m_session.rs:405` | `IpAddr::V6(_) => return Err(...)` IPv6 public_ip 未対応 | TODO |
| `src/webrtc/signaling.rs:44` | "実 INVITE 送信は別 PR で結線する (TODO)" | 残課題 |
| `src/config/mod.rs:172` | "実際の TURN allocate は TODO" | 残課題 |
| `src/call/orchestrator.rs:2182` | "ここでは簡略化のため、逆方向は省略する" (テスト) | テスト弱体化 |
| `src/call/orchestrator.rs:3023` | "バンドエイドだった `webrtc.local` フィルタの代替動作を保証するテスト" | 過去の band-aid 痕跡 |
| `src/call/orchestrator.rs:539` | `fn normalize_request_uri_for_ngn` 定義のみ・**callsite なし** | dead code (commit cba1cd2 が結線しそびれ) |

### 4.2 `restrict_audio_to_pcmu` の置き場所

定義: `src/sdp/builder.rs:131`
唯一の callsite: `src/call/orchestrator.rs:909` (内線→NGN INVITE 直前)

問題:
1. 本来 SDP Offer/Answer ネゴシエーション層で「PCMU 以外の codec は拒否する」ロジックを書くべき (§1.4 で詳述)。
2. **NGN→内線 200 OK の SDP body には適用されない**。NGN は基本 PCMU only なのでたまたま動くが、NGN が PCMA(8) や G.722 を返してきたら内線が困る。
3. `restrict_audio_to_pcmu` 内のブラックリスト attribute (`fingerprint`, `setup`, `ice-*`, `candidate`, `rtcp-mux` 等) は **WebRTC 由来属性の剥離** という別責務で、命名と内容が不一致。

→ Phase R3 で `Negotiator::rewrite_offer_for_ngn` / `Negotiator::strip_webrtc_attributes` の 2 関数に分離。

### 4.3 compact ヘッダ正規化の二重管理

§1.5 で詳述。`normalize_header_key` (in→canonical) と `canonical_header_name` (canonical→display) の 2 表が独立。

### 4.4 `SipMethod::Other(String)` で 405 化 [**解消済**]

**NGN inbound 側**: Issue #110 / PR #154 で `src/call/orchestrator.rs::handle_inbound` を method 別 status に整理済。

**内線 UAS 側**: Issue #273 / PR #XXX で `src/sip/uas.rs::handle_request` を以下の通り個別 status に整理済 (RFC 引用付き):

| Method | 応答 | 根拠 |
|---|---|---|
| `NOTIFY` | 481 Subscription Does Not Exist + `Allow` | RFC 3265 §3.2 / RFC 6665 §3.2 |
| `SUBSCRIBE` | 489 Bad Event + `Allow` | RFC 6665 §4.1.4 |
| `PRACK` | 481 Call/Transaction Does Not Exist + `Allow` | RFC 3262 §4 / §7.1 |
| `PUBLISH` | 200 OK + `Allow` (本文破棄、 受け流し) | RFC 3903 §6 |
| `UPDATE` | 481 + `Allow` | RFC 3311 §5.2 |
| `MESSAGE` | 200 OK + `Allow` (本文破棄、 再送ストーム抑止) | RFC 3428 §7 |
| `REFER` | 405 Method Not Allowed + `Allow` | RFC 3515 §4.5 |
| `Other(_)` | 405 + `Allow` | RFC 3261 §8.2.1 |

`Allow` ヘッダは sabiden が処理経路を持つ method (`INVITE, ACK, BYE, CANCEL, OPTIONS`) のみ列挙する (定数 `SUPPORTED_METHODS_ALLOW` in `src/sip/uas.rs`)。

PUBLISH が NGN 側 (489) と内線側 (200 OK) で異なるのは: NGN 側は carrier IMS が EventStateCompositor を期待する一方、 内線側 UA は presence publish を盲目的に 200 OK で吸って再送を止めるのが推奨されるため (RFC 3903 §6、 Issue #273 DoD)。

### 4.5 Timer A/B/D/E/F/G/H/I/J/K の実装漏れ

| Timer | RFC ref | 実装状況 | 補足 |
|---|---|---|---|
| Timer A | §17.1.1.2 INVITE 再送 (UAC) | ✓ | T1 から倍々 |
| Timer B | §17.1.1.2 INVITE タイムアウト (UAC) | ✓ | 64*T1 = 32s |
| Timer D | §17.1.1.2 non-2xx response 再送吸収 (UAC) | ✓ | UDP=32s 固定 |
| Timer E | §17.1.2.2 non-INVITE 再送 (UAC) | ✓ | T1→T2 cap |
| Timer F | §17.1.2.2 non-INVITE タイムアウト (UAC) | ✓ | 64*T1 (= TIMER_B 流用) |
| Timer K | §17.1.2.2 non-INVITE response 再送吸収 (UAC) | ✗ | **本来 5s 必要だが未実装**。`drop_client` が即削除 |
| Timer G | §17.2.1 INVITE 200 再送 (UAS) | ✗ | UAS は 200 を 1 回送って終わり。ACK 待ち状態の Timer G なし |
| Timer H | §17.2.1 ACK 待ちタイムアウト (UAS) | ✗ | UAS は ACK が来なくても 200 OK を保持し続けるだけ |
| Timer I | §17.2.1 ACK 受信後の最終待機 (UAS) | ✗ | `Confirmed` 状態が ServerTransaction にあるが遷移先がない |
| Timer J | §17.2.2 non-INVITE response 再送吸収 (UAS) | ✗ | `handle_retransmit` 関数はあるが driver なし |
| Timer L | RFC 6026 §7.1 Accepted state | ✗ | INVITE 2xx ACK 受領後の保持 |

加えて:
- `register.rs:90` で `time::sleep(Duration::from_secs(30))` 固定。指数バックオフなし
- `uas.rs:229` で 30 秒間隔 purge ループ。`tokio::time::interval` だが背景タスク終了経路なし

### 4.6 `ExtensionRegistrar::register` / `register_with_transport` API 二重化

`src/sip/registrar.rs:98` と `:110`。前者は内部で後者を `ExtTransport::Sip` で呼ぶラッパ。

→ Phase R2 で `register` を deprecate し、`register_with_transport` のデフォルト引数化、または `ExtTransport::Sip` の `Default` impl で吸収。

### 4.7 `_unused` プレフィックス / `#[allow(dead_code)]`

| 場所 | 内容 | 推奨対応 |
|---|---|---|
| `src/main.rs:2-17` | 全 `mod` に `#[allow(dead_code)]` | bin と lib を分けたので不要。`use sabiden::xxx` に書き換えれば消せる (lib.rs に既に pub mod があるので `bin/main.rs` から参照可能) |
| `src/sip/uas.rs:158` | `_layer: Arc<TransactionLayer>` | Drop guard なら `#[allow(dead_code)]` を付けて意図明示。実は `layer()` メソッドで返却しているので命名から `_` を外すべき |
| `src/call/orchestrator.rs:1345-1357` | `LegResult::*` の `aor: String` フィールドに `#[allow(dead_code)]` | デバッグログには使うので `#[allow(dead_code)]` でなく `#[doc = "デバッグ用"]` の方が意図明瞭 |
| `src/call/orchestrator.rs:1585, 1605, 1620` | `_layer: Arc<TransactionLayer>` 引数 | `wire_ngn_inbound*` で受け取っているが内部で使っていない。**API consumer のために残しているが実は不要**。シグネチャから消すべき (commit `f843356` の名残) |
| `src/rtp/rtcp.rs:210` | テスト用フィールド | OK |
| `src/rtp/mod.rs:12, 14` `src/webrtc/mod.rs:29-38` | `pub use` の `#[allow(unused_imports)]` | crate ユーザがいない開発段階の暫定。lib.rs で公開 API を絞るタイミングで消す |

---

## 5. リファクタ計画 (フェーズ分け)

依存関係:
```
                  R1 (test harness)
                   │
         ┌─────────┼──────────┐
         │         │          │
        R2        R3         R5
   (SIP layer) (SDP)      (timers)
         │         │          │
         └────┬────┴──────────┘
              │
              R4 (B2BUA state machine)
              │
              R6 (WebRTC backend wiring)
```

R1 は他全ての前提。R2/R3/R5 は **並列実行可能** (worktree で分離)。R4 は R2 と R3 完了後。R6 は R4 完了後。

### Phase R1: テスト共通ハーネス

**目標**: ハードコードを排し、Mock を 1 箇所に集約してテスト保守性を回復する。**コード削減なしでも成功**。

触るファイル:
- 新規: `tests/common/mod.rs`, `tests/common/mock_ngn.rs`, `tests/common/mock_ext.rs`, `tests/common/mock_webrtc.rs`, `tests/common/scripted_inviter.rs`, `tests/common/fixtures.rs`
- 既存改修: `src/call/orchestrator.rs::tests` (mock helper を `tests/common` 経由に置換), `src/sip/transaction.rs::tests`, `src/sip/uac.rs::tests`, `src/sip/uas.rs::tests`, `src/sip/register.rs::tests`, `src/call/manager.rs::tests`

追加するテスト:
- `tests/integration/sip_b2bua_basic.rs`: Inbound (NGN→内線) と Outbound (内線→NGN) を `MockNgn` + `MockExtension` で 1 ファイル各 1 シナリオ
- `tests/integration/registration_flow.rs`: REGISTER (HGW Digest / NGN 直収) を 1 ファイル

削除/統合するテスト:
- `src/call/manager.rs::tests::ScriptedInviter` を `tests/common::ScriptedInviter` に置換 (構造体は最小公分母で再設計)
- `src/call/orchestrator.rs::tests::ScriptedInviter` (別物) を統合

並列実行可能性: **低** (R2/R3/R4/R5/R6 全てが R1 に依存するため最初に直列で完了させる必要がある)

#### 並列エージェント prompt 草案 (R1)

```text
あなたは sabiden (Rust NGN 直収 SIP/WebRTC B2BUA) のテスト基盤専任エージェントです。

タスク: テスト共通ハーネスの導入。実装変更は禁止 (src/ 配下のロジックには触らない)。
        テストが落ちる場合は **テスト側だけ** 修正する。

step 1: tests/common/ を作成し、以下を実装:
  - MockNgn: UdpSocket loopback bind + シナリオベースで INVITE/BYE を受けて応答する
            mock NGN サーバ。Scenario enum で {ExpectMethod->Send, SendInvite, Drop} を表現
  - MockExtension: 同様に内線 UA を擬似化
  - ScriptedInviter: src/call/manager.rs と src/call/orchestrator.rs に二重定義された
            Mock を統合。per-target の振る舞い指定 (ImmediateStatus / DelayedStatus /
            NeverRespond) と、全 target 共通の status 指定の両方を満たす API
  - fixtures: branch_for_test(name), call_id_for_test(name), doc_ipv4(), doc_ipv6() 等
            意味付きファクトリ。RFC 5737/3849 のドキュメント用 IP を使う

step 2: 既存の src/**/tests を tests/common 経由に書き換え。
        - SipRequest / SipResponse builder helper を common/sip_builder.rs に集約
        - "127.0.0.1:0" loopback bind は MockNgn::bind() / MockExtension::bind() に置換

step 3: tests/integration/ を新設し、上記階層に E2E レベルの結線テスト 2 件を追加:
        - sip_b2bua_basic.rs: Inbound と Outbound のミニマム 1 シナリオずつ
        - registration_flow.rs: HGW Digest / NGN 直収 / 401 stale の 3 シナリオ

step 4: cargo test --no-run でビルドが通ることを確認。
        cargo test で既存テストが全部 pass すること (移行時の挙動変更ゼロが要件)。

完了判定: tests/common/ に集約された mock 数 >= 4、ハードコード "127.0.0.1:" が
          src/ 配下から減少する (mocks は tests/common にしか持たない)。
```

### Phase R2: SIP メッセージ層整理

**目標**: header / URI 操作を 1 箇所に集約し、`SipMethod::Other` の整理。RFC 3261 §7-§19 の API 表面を整える。

触るファイル:
- 新規: `src/sip/header.rs` (既存の helper を集約: `extract_uri`, `parse_tag`, `parse_cseq_number`, `ensure_to_tag`, `parse_via`, `normalize_header_key`, `canonical_header_name`)
- 既存改修: `src/sip/message.rs` (SipMethod 拡張: Notify/Subscribe/Publish/Update/Prack/Refer/Message), `src/sip/dialog.rs` (helper 重複削除), `src/sip/uas.rs` (extract_uri_from_contact / ensure_to_tag を header.rs から import + handle_request の match を拡張), `src/sip/uac.rs`, `src/call/orchestrator.rs` (extract_uri_from_addr / ensure_to_tag 削除)

追加するテスト:
- `header.rs::tests` で extract_uri / parse_tag / parse_cseq の単体 (各 5+ ケース)
- `uas.rs::tests::handle_notify_returns_481_when_no_dialog`
- `uas.rs::tests::handle_publish_returns_200_ok` (PUA 互換)
- `uas.rs::tests::handle_update_in_dialog_returns_200_ok`

削除するテスト: なし (既存の dialog.rs::extract_uri_handles_name_addr 等は header.rs::tests に移動)

並列実行可能性: **高** (R3 / R5 と独立。worktree で並走可)

#### 並列エージェント prompt 草案 (R2)

```text
あなたは sabiden の SIP プロトコル層整理エージェントです。
前提: Phase R1 の tests/common ハーネスが完成している前提で作業。

タスク 1: src/sip/header.rs を新設し以下を集約:
  - extract_uri(name-addr or addr-spec) -> String
  - parse_tag(header_value) -> Option<&str>
  - parse_cseq_number(header_value) -> Result<u32>
  - ensure_to_tag(&mut SipResponse)
  - parse_via(via_value) -> Result<(branch, sent_by)>
  - HeaderName enum: Via, From, To, ..., Other(String) で IANA 登録ヘッダを網羅
  - normalize / canonical の lookup table を 1 つに集約

タスク 2: SipMethod に Notify / Subscribe / Publish / Update / Prack / Refer / Message
        を追加。Other(String) は本当に未知のメソッド専用。

タスク 3: ExtensionUas::handle_request の match arm を拡張:
  - Notify: dialog 既存判定 → 200 OK or 481
  - Publish: 200 OK (PUA 互換)
  - Update: dialog 既存判定 + Re-INVITE 同等の SDP 処理 (R3 で本格対応)
  - Prack: 100rel を実装していないので 481 (要検討、暫定 200 OK でも可)
  - Refer / Message: 405 (本実装スコープ外)

タスク 4: NgnInboundHandler::handle_inbound にも同等の分岐を追加。

タスク 5: 全 import 修正。dialog.rs / uac.rs / uas.rs / orchestrator.rs の
        重複 helper を消し header.rs から再 import。

タスク 6: ExtensionRegistrar::register と register_with_transport の API 統合。
        register_with_transport(... transport: Option<ExtTransport>) を主とし、
        register は #[deprecated] でラッパ存続。

完了判定: cargo test 全 pass。grep -n 'fn extract_uri\|fn parse_tag\|fn parse_cseq_number\|fn ensure_to_tag' src/ で
        各 1 箇所のみヒットすること (header.rs)。
```

### Phase R3: SDP ネゴシエーション層

**目標**: PCMU 絞りを `Negotiator` に集約し、Offer/Answer モデル (RFC 3264) に準拠。

触るファイル:
- 新規: `src/sdp/negotiation.rs` (`Negotiator`, `NegotiatorBuilder`, `RtpCodec` enum, `NegotiationError`)
- 既存改修: `src/sdp/builder.rs` (restrict_audio_to_pcmu を deprecate して `Negotiator::rewrite_offer_for_ngn` の内部実装に移動。`rewrite_rtp_endpoint` も Negotiator にメソッド化), `src/sdp/mod.rs` (Attribute に `as_fmtp`, `as_ptime`, `as_direction` の構造化アクセサを追加), `src/call/orchestrator.rs` (`restrict_audio_to_pcmu` callsite を Negotiator API に置換), `src/webrtc/peer.rs` (build_minimal_answer も Negotiator 経由に)

追加するテスト:
- `negotiation.rs::tests`:
  - `rewrite_offer_for_ngn_drops_opus_and_keeps_pcmu` (既存の linphone trace ベースを移植)
  - `rewrite_offer_for_ngn_drops_webrtc_attributes` (`fingerprint`, `setup` 等が消える)
  - `rewrite_answer_for_ext_picks_codec_intersection` (内線 offer に PCMU/Opus、NGN answer は PCMU only → 内線へ返す answer は PCMU)
  - `rewrite_answer_for_ext_fails_when_no_intersection` (PCMU が両側にない → 488 を返すべき信号)
  - `relay_endpoint_rewrites_session_and_media_c_lines` (rewrite_rtp_endpoint の test を移植)

削除するテスト:
- `src/sdp/builder.rs::restrict_pcmu_tests::*` を `negotiation.rs::tests` に統合

並列実行可能性: **高** (R2 / R5 と独立)

#### 並列エージェント prompt 草案 (R3)

```text
あなたは sabiden の SDP ネゴシエーション層エージェントです。

タスク 1: src/sdp/negotiation.rs を新設:
  pub struct Negotiator {
      allowed_audio: Vec<RtpCodec>,    // PCMU(0) / PCMA(8) / Opus(dynamic)
      strip_webrtc_attrs: bool,
      strip_ice_dtls: bool,
  }

  impl Negotiator {
      pub fn for_ngn() -> Self;          // PCMU only + strip_webrtc + strip_ice_dtls
      pub fn for_ext(codecs: Vec<RtpCodec>) -> Self;
      pub fn rewrite_offer(&self, sdp: &[u8]) -> Result<Vec<u8>>;
      pub fn rewrite_answer(&self, ext_offer: &[u8], ngn_answer: &[u8]) -> Result<Vec<u8>>;
      pub fn relay_endpoint(&self, sdp: &[u8], ip: IpAddr, port: u16) -> Result<Vec<u8>>;
  }

タスク 2: src/sdp/builder.rs の restrict_audio_to_pcmu と rewrite_rtp_endpoint を
        Negotiator の内部実装にし、本体は #[deprecated] でラッパ存続。

タスク 3: orchestrator.rs の SDP 操作経路を全部 Negotiator API に置換:
  - prepare_outbound_bridge: ext_offer を Negotiator::for_ngn().rewrite_offer() で NGN 用に
  - finalize_outbound_bridge: NGN answer を Negotiator::for_ext(...).rewrite_answer() で内線用に
  - start_bridge_for_inbound: 同様

タスク 4: webrtc/peer.rs の build_minimal_answer も Negotiator::for_webrtc() 経由に
        (codec は Opus/PCMU 両対応)。

タスク 5: 「PCMU が両側に無い → 488」を InviteOutcome 構造に追加して NGN レッグから
        488 を返せるようにする。

完了判定: cargo test 全 pass。grep -n 'restrict_audio_to_pcmu\|rewrite_rtp_endpoint' src/ が
        sdp/builder.rs (deprecated wrapper) のみで他では呼ばれていないこと。
        Linphone trace SDP に対し negotiator.rewrite_offer は PCMU only + WebRTC 属性
        ゼロの SDP を出すこと。
```

### Phase R4: B2BUA 状態機械の明文化 + Re-INVITE/UPDATE 対応

**目標**: 1 通話 1 構造体 (`B2buaCall`) に集約し、`OutboundCallRegistry` / `pending` / `active` / `outbound_forwarder` の 4 種ルックアップを単一 `B2buaRegistry` に統合。Re-INVITE / UPDATE / glare race を実装。

触るファイル:
- 新規: `src/call/b2bua.rs` (`B2buaCall`, `B2buaState`, `B2buaRegistry`, `B2buaDirection`, `B2buaLeg{Ngn,Ext}`)
- 既存大改修: `src/call/orchestrator.rs` (NgnInboundHandler / UasEventHandler を `B2buaRegistry` 経由に書き換え。3188 行 → 2000 行程度に削減見込み。テストは tests/integration へ大量移動)
- 既存改修: `src/call/mod.rs` (CallState を B2buaState で代替できないか検討)
- 既存軽微: `src/sip/uas.rs` (Re-INVITE / UPDATE の dispatch を `UasEvent::Reinvite` / `UasEvent::Update` 追加)

追加するテスト:
- `b2bua.rs::tests::register_lookup_by_three_keys` (call_id, ext_call_id, ngn_call_id から同じエントリを引ける)
- `b2bua.rs::tests::cancel_glare_when_200_arrives_first` (200 OK が先, CANCEL が後 → NGN BYE 即発射)
- `b2bua.rs::tests::cancel_glare_when_cancel_arrives_first` (現状動作の確認)
- `b2bua.rs::tests::reinvite_outbound_session_timer_refresh` (内線→NGN 通話の 150 秒後に Re-INVITE)
- `b2bua.rs::tests::reinvite_inbound_received_returns_200` (NGN→内線 通話で NGN が Re-INVITE してきた)
- `b2bua.rs::tests::update_session_refresh` (RFC 3311)

削除するテスト:
- `orchestrator.rs::tests::outbound_registry_lookup_by_either_call_id` → b2bua.rs::tests に移動
- B2BUA 系 E2E テスト (~5 個) を `tests/integration/b2bua_signaling.rs` に分離

並列実行可能性: **不可** (R2 / R3 完了が前提)

#### 並列エージェント prompt 草案 (R4)

```text
あなたは sabiden の B2BUA 状態機械専任エージェントです。
前提: Phase R1 / R2 / R3 が完了済み。Negotiator API と header.rs と
      tests/common::{MockNgn, MockExtension} が利用可能。

タスク 1: src/call/b2bua.rs を新設し、以下の構造で 1 通話を表現:
  pub enum B2buaDirection { Outbound, Inbound }
  pub enum B2buaState {
      EarlyOutbound { plan: InvitePlan, cancel: Notify },  // 内線→NGN 進行中
      EarlyInbound { stx: Arc<Mutex<ServerTransaction>> }, // NGN→内線 進行中
      Connected,
      Terminating,
  }
  pub struct B2buaCall {
      id: CallId,
      direction: B2buaDirection,
      state: Mutex<B2buaState>,
      ext_call_id: String,
      ngn_call_id: String,
      ext_dialog: Mutex<Dialog>,        // sabiden=UAS dialog
      ngn_dialog: Mutex<Option<UacDialog>>, // sabiden=UAC dialog (NGN レッグ)
      bridge: Mutex<Option<RtpBridge>>,
  }
  pub struct B2buaRegistry { /* by_call_id / by_ext / by_ngn を 1 つの構造体で */ }

タスク 2: orchestrator.rs を書き直し:
  - OutboundCallRegistry / pending / active / outbound_forwarder を全部 B2buaRegistry に統合
  - NgnInboundHandler::handle_invite / handle_bye / handle_cancel が B2buaRegistry 経由に
  - UasEventHandler::handle_invite / handle_ext_bye / handle_ext_cancel も B2buaRegistry 経由に
  - try_forward_bye / OutboundDialogForwarder trait を廃止 (registry を共有するだけで足りる)

タスク 3: Re-INVITE / UPDATE 受信ハンドラを実装:
  - UasEvent::Reinvite / UasEvent::Update を追加 (uas.rs)
  - B2buaCall::handle_reinvite で SDP 再ネゴシエーション + 反対側へ Re-INVITE 伝搬

タスク 4: CANCEL race 完全対応:
  - cancel_flag を Notify から enum CancelState { None, Cancelled, GlareWith2xx } に拡張
  - 200 OK 受信時に CancelState::Cancelled なら NGN BYE 即発射 (現状の挙動を維持)

タスク 5: orchestrator.rs::tests のうち B2BUA 系を tests/integration/b2bua_signaling.rs に移動。
        テスト名は `rfc3261_15_1_2_ext_bye_propagates_to_ngn` のように RFC 引用付き。

完了判定: cargo test 全 pass。orchestrator.rs の行数が 2200 行以下。
        b2bua.rs に Re-INVITE / UPDATE / glare race テストが各 1+ 件。
```

### Phase R5: Timer / 再送ロジック整合 (RFC 3261 §17)

**目標**: Timer A/B/D/E/F/G/H/I/J/K/L を網羅実装し、TransactionLayer に server tx table を入れる。

触るファイル:
- 既存大改修: `src/sip/transaction.rs` (`server_tx_table: HashMap<TransactionId, Arc<Mutex<ServerTransaction>>>` を追加, recv_loop で server tx マッチング, Timer G/H/I/J/K/L 駆動 task spawn)
- 既存改修: `src/sip/uas.rs` (`pending` HashMap を廃止し ServerTransaction の所有を TransactionLayer に委譲), `src/call/orchestrator.rs` (`pending` HashMap を同様に廃止)
- 既存改修: `src/sip/register.rs` (CSEQ static を Registrar struct field に, 30 秒固定再送を指数バックオフに)

追加するテスト:
- `transaction.rs::tests::timer_g_uas_resends_2xx_until_ack` (1xx 不要の REGISTER では呼ばれないので INVITE シナリオ)
- `transaction.rs::tests::timer_h_uas_aborts_when_no_ack` (32s で server tx 終了)
- `transaction.rs::tests::timer_j_uas_absorbs_request_retransmits` (2 度送られた non-INVITE で同じ応答を返す)
- `transaction.rs::tests::timer_k_uac_drops_after_5s` (UDP non-INVITE Completed → Terminated)
- `transaction.rs::tests::server_tx_table_dedupe_by_transaction_id` (同じ branch+sent-by+method の重複検出)
- `transaction.rs::tests::request_retransmit_returns_last_response` (再送 → 既送出応答コピーで返す)

削除するテスト:
- `orchestrator.rs::tests::ngn_invite_with_no_extensions_returns_480` 等で `pending` 動作を暗黙確認していたものを TransactionLayer level の test に移動

並列実行可能性: **中** (R1 完了後、R2/R3 と並列。ただし R4 は R5 完了後に行うのが望ましい)

#### 並列エージェント prompt 草案 (R5)

```text
あなたは sabiden の SIP トランザクション層 RFC 3261 §17 完全実装エージェントです。

タスク 1: TransactionLayer に server_tx_table を追加:
  - HashMap<TransactionId, Arc<Mutex<ServerTransaction>>>
  - recv_loop で受信リクエストを TransactionId.match() し、既存があれば
    handle_retransmit、なければ inbound_tx に流す + テーブル登録

タスク 2: Timer G/H/I を ServerTransaction に実装:
  - INVITE 200 送信時に Timer G (T1 から倍々, T2 cap, 64*T1 で停止) を spawn
  - Timer H (= 64*T1) で ACK が来なければ Confirmed 状態にして Timer I (T4=5s)
  - Timer I 満了で server_tx_table から削除

タスク 3: Timer J を ServerTransaction (non-INVITE) に実装:
  - 最終応答送信後 Timer J (= 64*T1) で server_tx_table 保持
  - Timer J 満了で削除

タスク 4: Timer K を ClientTransaction (non-INVITE) に実装:
  - 最終応答受信後 Timer K (UDP=T4=5s) で client_tx_table 保持
  - 現状は send_request で Ok 後即 drop_client しているが、Timer K の間
    response 再送を吸収する必要がある

タスク 5: Timer L (RFC 6026 §7.1) を ServerTransaction (INVITE 2xx) に実装:
  - 2xx 送信後 64*T1 の Accepted state で保持

タスク 6: TransactionId に "merged request" 検出ロジック追加 (RFC 3261 §8.2.2.2):
  - Request-URI + From-tag + Call-ID + CSeq の 4 タプルでも検出

タスク 7: NgnInboundHandler::pending と ExtensionUas で持っている重複検出を撤廃。
        ServerTransaction を inbound_rx 経由で受け取る形にシグネチャ変更。

タスク 8: register.rs:
  - static CSEQ を Registrar struct field (AtomicU32) に
  - 30 秒固定再送を指数バックオフ (5/10/20/40/60s, 60 cap) に

完了判定: cargo test 全 pass。Timer G/H/I/J/K/L 各 1+ テスト。
        重複リクエスト (同じ branch + sent-by + method) で server_tx_table が
        dedupe する unit test。
```

### Phase R6: WebRTC レッグ完成 (str0m + Opus トランスコード結線)

**目標**: str0m バックエンドの `Event::MediaData` を `TranscodingBridge` に流し込み、ブラウザ ↔ NGN の双方向音声を成立させる。

触るファイル:
- 既存大改修: `src/webrtc/str0m_session.rs` (`Event::MediaData` から RTP を取り出して `media_in_tx: mpsc::Sender<RtpBytes>` に流す。`media_out_rx: mpsc::Receiver<RtpBytes>` を追加して `Rtc::write_rtp` で送信)
- 既存改修: `src/webrtc/peer.rs` (`PeerSession` trait に `take_media_io() -> Option<(Sender, Receiver)>` を追加。stub は None)
- 既存改修: `src/call/orchestrator.rs::run_webrtc_leg` (winner 確定時に `TranscodingBridge` を起動して NGN レッグ socket と PeerSession の `media_io` を結線)
- 既存改修: `src/sip/registrar.rs` (`ExtTransport::WebRtc` の bind 構築は webrtc/ 側に閉じ込める。registrar は trait object 越しに使う)

追加するテスト:
- `tests/integration/webrtc_b2bua.rs::ngn_to_webrtc_bridge_relays_via_transcoder` (NGN PCMU → str0m → Opus を browser 側で受信できる)
- `tests/integration/webrtc_b2bua.rs::webrtc_to_ngn_bridge_relays_via_transcoder` (browser Opus → str0m → NGN PCMU)
- `tests/integration/webrtc_b2bua.rs::webrtc_ice_failure_propagates_487` (ICE 失敗で NGN INVITE に 487)
- `tests/integration/webrtc_b2bua.rs::webrtc_register_with_str0m_backend` (現状の signaling.rs::tests::end_to_end_ws_register_then_bye を str0m バックエンドで再走)

削除/統合するテスト:
- `orchestrator.rs::tests::ngn_invite_to_webrtc_binding_offer_push_and_answer_round_trip` を tests/integration/webrtc_b2bua.rs に移植 (現状はインライン SDP テストだけで RTP 流れていない)

並列実行可能性: **不可** (R4 完了前提。Negotiator + B2buaCall + ServerTransaction 整合が無いと結線できない)

#### 並列エージェント prompt 草案 (R6)

```text
あなたは sabiden の WebRTC バックエンド完全結線エージェントです。
前提: R1-R5 完了済。B2buaRegistry + Negotiator + TransactionLayer 完成形が利用可能。

タスク 1: PeerSession trait に media io API を追加:
  trait PeerSession {
      ...
      async fn take_media_io(&self) -> Option<(MediaSender, MediaReceiver)>;
  }
  type MediaSender = mpsc::UnboundedSender<MediaPacket>;  // ブラウザに送る
  type MediaReceiver = mpsc::UnboundedReceiver<MediaPacket>; // ブラウザから受信
  pub struct MediaPacket { pub pt: u8, pub payload: Vec<u8>, pub timestamp: u32, pub seq: u16 }

タスク 2: Str0mPeerSession::run_loop 改修:
  - Event::MediaData -> media_in_tx に MediaPacket を送出
  - media_out_rx から取り出して rtc.write_rtp() で送信

タスク 3: orchestrator.rs::run_webrtc_leg を改修し、winner 確定時に
        TranscodingBridge::start を起動。NGN 側 socket は B2buaCall::ngn_socket、
        WebRTC 側は MediaSender/MediaReceiver から RtpPacket を取り出すアダプタ。

タスク 4: SDP rewrite を Negotiator::for_webrtc() で行う:
  - browser からの WebRTC offer (UDP/TLS/RTP/SAVPF + Opus + DTLS fingerprint) を
    NGN 用 (RTP/AVP + PCMU only) に変換
  - NGN からの PCMU answer を browser 用 (Opus offer に対する answer) に変換

タスク 5: ICE failure ハンドラ:
  - Str0mPeerSession::close 時に B2buaCall に通知 → NGN レッグで CANCEL 発射

タスク 6: registrar.rs から webrtc 直接依存を削除:
  - ExtTransport::WebRtc を Box<dyn ExtCallTarget> に置き換え
  - ExtCallTarget trait は src/sip/ 配下で定義し、webrtc 実装は src/webrtc/binding.rs

タスク 7: tests/integration/webrtc_b2bua.rs に E2E 4 シナリオを追加 (上記)。

完了判定: ブラウザから接続 → NGN 着信を browser で取り、双方向 Opus⇔PCMU が
        統合テスト内で確認できる。grep -n 'use crate::webrtc' src/sip/ で
        ヒットゼロ (層越境解消)。
```

### 5.7 並列エージェントへの prompt 草案

各 Phase の prompt は上記の **`#### 並列エージェント prompt 草案 (Rx)`** 節に格納済。親エージェントは以下のように launch する想定:

```text
worktree: refactor/r1-test-harness    → R1 prompt
worktree: refactor/r2-sip-message     → R2 prompt (R1 merge 後)
worktree: refactor/r3-sdp-negotiation → R3 prompt (R1 merge 後, R2 と並走可)
worktree: refactor/r5-timers          → R5 prompt (R1 merge 後, R2/R3 と並走可)
worktree: refactor/r4-b2bua-state     → R4 prompt (R2/R3/R5 merge 後)
worktree: refactor/r6-webrtc-wiring   → R6 prompt (R4 merge 後)
```

各 worktree は **独立 PR** として上げ、CI が緑になったら親で順次 merge。

---

## 6. 緊急実機バグの優先度

実機 (Linphone 内線 117 番から発信) で 200 OK 通っても切れる事象に対する仮説。

### P0: Linphone 117 が 200 OK 通っても切れる根本原因

複数の仮説:

**仮説 A: NGN 200 OK の SDP が NGN PCMU のみで、内線へ返す answer に rtpmap:0 PCMU/8000 が無い**

- 現状: `UasEventHandler::finalize_outbound_bridge` (orchestrator.rs:1270) で `rewrite_rtp_endpoint(ext_offer, sabiden_ext_addr...)` を実行している。**`ext_offer` (内線が出した SDP) を base に rewrite している**。
- 問題: 内線が出した offer は multi-codec (PCMU + Opus + telephone-event) を含む `formats` を持つので、内線へ返す answer に **形式上は OK** だが、`m=audio` の formats は `["0", "8", "96", "97", "98", "101"]` 等となり、内線視点では「sabiden は Opus 96 も受けられる」と誤解する。実際 sabiden は NGN レッグで PCMU しか流さないので、内線が Opus を投げてくると詰む。
- 検証: SIP trace の `sent_RESP-200-INVITE_<ext-call-id>.txt` を読み、内線へ返した answer の `m=audio` formats と `a=rtpmap` 列を確認する。
- 修正: Negotiator (R3) で `rewrite_answer_for_ext` を実装し、内線が出した offer の formats のうち NGN answer が選んだ PT (= 0) のみを残す。

**仮説 B: 200 OK の Contact / Record-Route 不整合で内線の ACK が sabiden に届かない**

- 現状: `build_2xx_to_ext` (orchestrator.rs:1308) で内線 INVITE に対する 200 OK を組み立て、`Contact` を **設定していない**。
- 問題: `Dialog::from_uas_invite` で構築する内線レッグ dialog の `local_contact` は `format!("sip:sabiden@{}", sent_by)` だが、200 OK 自体には Contact が乗らないため、内線は **dialog target を確定できない**。dialog 仕様上 Contact 必須 (RFC 3261 §12.1.2)。
- 修正: `build_2xx_to_ext` で Contact を必ず付与。
- 検証コード: `assert!(resp.headers.get("contact").is_some())` を追加。

**仮説 C: NGN INVITE の ACK が NGN P-CSCF のホスト名解決失敗で送れていない**

- 現状: `Uac::invite` 内で 2xx ACK を `self.layer.send_request_no_wait(ack, self.server_addr)` (uac.rs:170) で送る。`self.server_addr` は **NGN P-CSCF アドレス固定**。
- 問題: NGN 200 OK の Contact が `[2001:A7FF:...]:5060` で来ても、ACK は P-CSCF アドレスに送る。これは loose routing 想定では正しいが、NGN P-CSCF が `Record-Route: <sip:...;lr>` を付けている場合 dialog.route_set は埋まる。**Dialog::build_ack_for_2xx の compute_request_uri_and_route は loose routing でちゃんと remote_target に送る**。これは正しい。
- だが `send_request_no_wait` は **dialog の remote_target に送るのではなく `server_addr` (P-CSCF) に送っている**。loose routing なら Route ヘッダ経由で P-CSCF が次ホップに飛ばすので OK だが、Record-Route が無いケース (= direct) では dialog.remote_target に送るべき。
- 修正案: `Uac::invite` の 2xx ACK を `dialog.build_ack_for_2xx` で組み立てた後、宛先を **dialog の compute_request_uri_and_route の Request-URI ホスト or Route 先頭ホスト** から解決する。
- 検証: SIP trace の `sent_ACK_<call-id>.txt` の宛先を確認 (現状 trace は宛先 SocketAddr を記録していないので、`SipTraceWriter` に `peer_addr` フィールド追加が要る)。

**仮説 D: Session Timer 期限切れで 32s 後に NGN が BYE してくる**

- 現状: `UacDialog::send_reinvite` は **手動でしか呼ばれない**。Session-Expires=300 を NGN に通告しているが、refresher = uac (sabiden 側がリフレッシュ責任) なのに sabiden は Re-INVITE を自動送出しない。
- 問題: NGN 側が `Session-Expires/2` (=150 秒) で timeout し BYE してくる可能性。実機テストで「200 OK 通っても切れる」が **150 秒前後** で切れているなら高確度でこれ。
- 修正: `UacDialog` に `start_refresh_timer` を入れ、`Session-Expires/2` で Re-INVITE を spawn (Phase R4 で B2buaCall に統合)。

**仮説 E: 200 OK 再送に対する ACK が再送されない (RFC 3261 §13.3.1.4)**

- 現状: NGN は 200 OK 再送を Timer T1 から倍々で送ってくる可能性。sabiden 側は `send_request_no_wait` で 1 回だけ送って終わり。
- 問題: NGN は ACK が来るまで 200 OK を 64*T1=32s 再送し続けるので、その間 ACK 1 回送るだけだと NGN は途中の ACK ロスを許容できない。
- 修正: 2xx ACK は `TransactionLayer` 内で **再送吸収** (Timer L 同等) を行う。Phase R5 の Timer L 実装と同期。

**優先度**: B (Contact 漏れ) は **即修正**。次 D (Session Timer) と E (2xx ACK 再送)。A (formats) は 200 OK が通った後の RTP 流通失敗で発症するが BYE は来ない (内線が Opus 投げて NGN が 488 を返すと内線側で別 SIP trace が出る)。

### P1: ACK + Request-URI 修正後の実機未確認項目

`commit cba1cd2` (Request-URI / To を NGN ドメインに正規化) は **コードに残っているが結線されていない** (`normalize_request_uri_for_ngn` is dead code)。これを早急に修正:

- `UasEventHandler::handle_invite` (orchestrator.rs:874-913) で `let target = request.uri.clone();` の直後に
  `let target = normalize_request_uri_for_ngn(&target, &self.ngn_uac.config().domain, &server_host);` を入れる
- `To` ヘッダの host も同様に NGN ドメインに正規化する API が必要 (現状 normalize_request_uri_for_ngn は Request-URI のみ)
- 単体テスト: `normalize_request_uri_for_ngn_replaces_lan_ip_with_ngn_domain` 等 (現状 commit に test がない)

### P2: 着信 (NGN→内線) フローの実機未確認

- NGN→内線フォーク経路は orchestrator.rs::tests には統合テストが揃っているが、実機ログ (Linphone での着信成立) のレポートが README / docs にない
- 検証手順 (実機投入時):
  1. NGN から固定電話で sabiden の電話番号にダイヤル
  2. SIP trace に `recv_INVITE_<call-id>.txt` が記録されること
  3. 100 Trying / 200 OK / ACK の往復を観測
  4. 内線 (Linphone 117) でリンガが鳴り、応答すると音声が聞こえるか
- `bridge_ngn_bind_ip` は config 未指定で `IpAddr::V4(LOCALHOST)` フォールバック (orchestrator.rs:506)。**NGN は IPv6 経路の可能性が高いので、loopback v4 ではブリッジが届かない**。`config.toml` の `[webrtc] public_ip` に倣って `[bridge] ngn_bind_ip` のような明示設定が必要。

### P3: WebRTC str0m バックエンドの NGN PCMU SDP 受け付け問題

- str0m 0.19 の `accept_offer` は WebRTC SDP (UDP/TLS/RTP/SAVPF + DTLS-SRTP + ICE) を期待。NGN INVITE の SDP は `RTP/AVP` + PCMU の vanilla SDP。
- 仮説: orchestrator.rs::run_webrtc_leg (line 1517) で `peer.handle_offer(&offer_text)` に NGN SDP を直接渡している → str0m が `m=audio ... RTP/AVP 0` を解釈失敗
- ログ: `"WebRTC leg: peer.handle_offer 失敗 (継続)"` の debug ログが出るはずだが、その後 WS 経由で browser に offer 文字列を **そのまま** push するので browser 側で `RTCPeerConnection.setRemoteDescription` が必ず失敗
- 修正: Phase R6 で Negotiator::for_webrtc() による SDP rewrite を必須化。NGN PCMU offer → browser 向けに `UDP/TLS/RTP/SAVPF` + Opus を追加した複合 offer に変換。

### P4: 0xN/A の事項

- IPv6 dual-stack 内線レッグ (main.rs:381 で v4 loopback 固定) → v6 のみの環境で UAS が刺さる
- `recv_loop` の buf 8192 バイト固定 (transaction.rs:528) → NGN 200 OK が大きい場合 truncate

---

## Appendix A. dead/half-wired コード一覧

| 関数/フィールド | 場所 | 問題 |
|---|---|---|
| `fn normalize_request_uri_for_ngn` | orchestrator.rs:539 | 定義のみ・呼び出されていない (commit `cba1cd2` 結線漏れ) |
| `fn copy_via_to_response_headers` | dialog.rs:502 | no-op stub。残骸 |
| `_layer: Arc<TransactionLayer>` (引数) | orchestrator.rs:1585, 1605, 1620 | `wire_ngn_inbound*` の引数として受け取るが内部で未使用 |
| `_layer: Arc<TransactionLayer>` (フィールド) | uas.rs:158 | Drop guard 用だが命名不明瞭 |
| `pub fn fork_to_extensions` | manager.rs:144 | orchestrator では使われない (transport-aware の `fork_to_bindings` が後継) |
| `pub fn make_forker` | orchestrator.rs:1573 | テストでしか使われていない (main.rs は直接 `Arc::new(UacForker { ... })` を組む) |
| `pub fn wire_ngn_inbound_with_manager` | orchestrator.rs:1619 | main.rs で使われていない (CallManager 経路は orchestrator 内では結線されているがバイナリには未統合) |
| `Event::RtpPacket(_)` arm | str0m_session.rs:389 | コメント上 "到達しない" と明示されている dead arm |
| `LegResult::Errored { aor: ..., #[allow(dead_code)] aor }` | orchestrator.rs:1357 | aor をログ用に保持しているはずが allow で潰している |

## Appendix B. assumption リスト

リファクタを進めるにあたり、検証なしに前提とした事項:

1. **NGN 直収モードでは Session-Expires は P-CSCF が拒否しない** — RFC 4028 ヘッダは sip-extensions として transparent に扱われるはず。実機で 422 が返らないのは偶然かもしれない (要 SIP trace 確認)。
2. **Linphone 117 番からの発信 SDP は常に PCMU を含む** — 最近の Linphone は audio codec preference に PCMU が無効化されている設定があり得る。`config.toml` で内線側 codec policy を強制する必要があるかも。
3. **NGN P-CSCF は IPv4/IPv6 どちらの ACK も受ける** — `IPV6_TCLASS` と `IP_TOS` 両方セットしているが、NGN 直収モード (Issue #37) では IPv4 path で REGISTER している。実機 deploy/k8s 環境次第。
4. **str0m 0.19 の `RtcConfig::set_ice_lite(true)` は ICE-Lite を完全実装** — Cloudflare Tunnel 配下では問題ないが、direct connection で TURN 必須になる可能性。
5. **Linphone のフォーク着信 race で先着 200 OK 採用が常に正しい** — 実は着信履歴の整合 (どの内線が応答したか) のために `winner_uri` を CallManager に保存する必要があるかもしれない (現状は単に SipResponse を返すだけ)。
6. **`RtpBridge::stop` を呼ばないと socket が閉じない** — `Drop` impl で abort しているが、UDP socket の RAII 解放のみで十分か未検証。
7. **`OutboundCallRegistry` の Mutex 1 個でも contention は問題にならない** — 1 通話あたり数イベントしか走らないため。同時通話 100 件超では再評価が必要。

> 計画書終わり。実装は別途 Phase R1 から順次着手。
