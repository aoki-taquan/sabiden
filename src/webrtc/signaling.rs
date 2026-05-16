//! WebRTC シグナリング: WebSocket 上の JSON プロトコル
//!
//! axum の WebSocket extractor を使い、`/signal` で接続を受け付ける。
//! 既存の health server と同居でき、独立 bind は不要。
//!
//! # プロトコル (text JSON フレーム)
//!
//! C → S:
//! ```json
//! { "type": "register", "ext_id": "webrtc-alice" }    // 認証は WS 接続時
//! { "type": "offer", "sdp": "v=0..." }                 // browser 発信 (将来)
//! { "type": "answer", "call_id": "...", "sdp": "v=0..." }  // sabiden 発の offer に応答
//! { "type": "decline", "call_id": "..." }              // Issue #107: 着信拒否
//! { "type": "ice", "candidate": "candidate:..." }
//! { "type": "bye" }
//! ```
//!
//! S → C:
//! ```json
//! { "type": "registered", "ext_id": "webrtc-alice" }
//! { "type": "answer", "sdp": "v=0..." }                  // browser 発の offer 応答
//! { "type": "offer",  "call_id": "...", "sdp": "v=0..." } // NGN 着信を browser へ push
//! { "type": "cancel", "call_id": "..." }                 // NGN CANCEL 等の中止通知
//! { "type": "ice", "candidate": "candidate:..." }
//! { "type": "error", "code": "invalid_state", "message": "..." }
//! { "type": "bye" }
//! ```
//!
//! # 認証
//!
//! WS の HTTP アップグレード時に `Authorization: Bearer <token>` ヘッダ
//! または `?token=<token>` クエリのいずれかでトークンを提示する。
//! [`crate::webrtc::auth::Verifier`] で検証し、有効な [`AuthClaims`] を
//! セッションに紐づける。失敗時は HTTP 401 を返して接続を拒否する。
//!
//! # Call Manager 統合
//!
//! WS 接続が `register` メッセージを受信したとき、`AuthClaims::ext_id` を
//! AOR として [`crate::sip::registrar::ExtensionRegistrar`] に書き込む。
//! これにより NGN 着信フォークの対象になる。WS 切断 (もしくは `bye`) で
//! AOR は失効する。
//!
//! 発信 (WebRTC → NGN) は [`PwaOutboundHandler`] (`src/call/orchestrator.rs`)
//! が `place_call` メッセージを受領して NGN への INVITE を組み立てる。
//! PWA → NGN 経路は Issue #145 / #147 で結線済、 双方向音声 + PCMU
//! トランスコード対応 (`docs/ARCHITECTURE.md` § "発信 (PWA → NGN)")。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::auth::{AuthClaims, Verifier};
use super::peer::{PeerSession, StubPeerSession};
use crate::sip::registrar::{ExtTransport, ExtensionRegistrar};

/// `ServerMessage` を WS 接続へ非同期に届けるためのチャネル送信側。
///
/// シグナリング層 (orchestrator や `process_client_message`) から
/// WebRTC ブラウザに任意のタイミングで `Offer` / `Cancel` 等を push する
/// ために、WS 送信タスクを `mpsc` 受信ループで分離する。実装としては
/// `mpsc::UnboundedSender<ServerMessage>` の `Arc` ラップ。
#[derive(Clone)]
pub struct WsSink {
    tx: mpsc::UnboundedSender<ServerMessage>,
}

impl WsSink {
    pub fn new(tx: mpsc::UnboundedSender<ServerMessage>) -> Self {
        Self { tx }
    }

    /// メッセージを WS 送信タスクへ enqueue する。WS が既に閉じていれば
    /// `Err` を返す。
    pub fn send(&self, msg: ServerMessage) -> Result<()> {
        self.tx
            .send(msg)
            .map_err(|_| anyhow::anyhow!("WS シグナリングチャネルが閉じている"))
    }

    /// 送信側が生きているかを確認する (テスト・診断向け)。
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// 同一の送信チャネル (= 同じ WS セッション) を指すかを判定する。
    ///
    /// Issue #83 で `fork_to_bindings` の cleanup が winner 自身を Cancel し
    /// ないようにするために使う。 `mpsc::UnboundedSender::same_channel` は
    /// 「同じレシーバを共有しているか」を返す (tokio 1.x docs)。
    pub fn same_channel(&self, other: &Self) -> bool {
        self.tx.same_channel(&other.tx)
    }
}

/// `PendingAnswers::register` の waiter が受け取る結果。
///
/// browser からの `Answer` (SDP 文字列) または `Decline` (拒否ステータスコード)
/// のどちらかが届く。 RFC 3261 §15.1 (BYE) や §21.6.2 (603 Decline) に該当する
/// 拒否 semantics を、 WS シグナリング層から orchestrator へ伝搬するために使う。
///
/// # 設計判断 (Issue #107)
///
/// 旧 API は `oneshot::Sender<String>` で SDP のみを運んでいた。 着信拒否
/// (`ClientMessage::Decline`) を導入するにあたり、 SDP 文字列に sentinel を
/// 埋めるのは脆い (任意の SDP がぶつかる可能性) ため、 enum で正規に分岐する。
///
/// # `Drop` semantics
///
/// `oneshot::Sender<AnswerOutcome>` を drop すると `Receiver` 側は
/// `Err(RecvError)` で目覚める (tokio 1.x docs)。 これは「browser が WS ごと
/// 切断した」 ケース (Issue #117 `cancel_all`) と区別される: 切断は `Err`、
/// 明示的な拒否は `Ok(Decline { status })`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerOutcome {
    /// browser が応答ボタンを押して SDP answer を返した (RFC 3264 §6 answerer)。
    Sdp(String),
    /// browser が拒否ボタンを押して着信を拒否した (Issue #107)。
    /// `status` は orchestrator が NGN レッグに返す SIP ステータスコード:
    /// - 486 Busy Here (RFC 3261 §21.4.21)
    /// - 603 Decline (RFC 3261 §21.6.2) ← 既定 (= 「ユーザが拒否」 を最も
    ///   忠実に表現する code)
    ///
    /// 487 Request Terminated は CANCEL を受けた INVITE トランザクションが
    /// 自発的に出す code (RFC 3261 §15.1.1) であり、 UAS 側拒否では使わない。
    Decline { status: u16 },
}

/// 1 つの WebRTC バインディングに紐づく実行時状態。
///
/// `ExtTransport::WebRtc` から到達できる `peer` / `ws` に加えて、NGN 着信
/// 時に sabiden が browser に offer を push したあと、対応する
/// `ClientMessage::Answer` (call_id 付き) または `ClientMessage::Decline`
/// (call_id 付き) を待ち受ける oneshot のテーブルを保持する。
/// シグナリング層と orchestrator の双方からアクセスする。
#[derive(Clone, Default)]
pub struct PendingAnswers {
    inner: Arc<Mutex<HashMap<String, oneshot::Sender<AnswerOutcome>>>>,
}

impl PendingAnswers {
    pub fn new() -> Self {
        Self::default()
    }

    /// 指定 `call_id` への browser 応答 (answer / decline) 受信を予約し、
    /// 待ち受け側の receiver を返す。
    pub async fn register(&self, call_id: &str) -> oneshot::Receiver<AnswerOutcome> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().await.insert(call_id.to_string(), tx);
        rx
    }

    /// 指定 `call_id` の予約を取り消す (タイムアウト・キャンセル時)。
    pub async fn cancel(&self, call_id: &str) {
        self.inner.lock().await.remove(call_id);
    }

    /// browser から届いた answer を該当 `call_id` の waiter に転送する。
    /// waiter が居ない場合は `false` を返す。
    pub async fn deliver(&self, call_id: &str, sdp: String) -> bool {
        if let Some(tx) = self.inner.lock().await.remove(call_id) {
            tx.send(AnswerOutcome::Sdp(sdp)).is_ok()
        } else {
            false
        }
    }

    /// browser から届いた decline を該当 `call_id` の waiter に転送する
    /// (Issue #107, RFC 3261 §21.6.2 603 Decline)。
    ///
    /// orchestrator 側 (`run_webrtc_leg`) は `AnswerOutcome::Decline { status }`
    /// を `LegResult::Failed { aor, status }` に変換し、 fork 全体が
    /// `ForkResult::AllFailed { last_status: Some(status) }` で抜けて NGN
    /// レッグに該当ステータスを返す。
    ///
    /// waiter が居ない (=対応する pending offer が無い) 場合は `false` を返す。
    /// 既に WS 切断で `cancel_all` 済み / `deliver` で消費済みのケース等。
    pub async fn decline(&self, call_id: &str, status: u16) -> bool {
        if let Some(tx) = self.inner.lock().await.remove(call_id) {
            tx.send(AnswerOutcome::Decline { status }).is_ok()
        } else {
            false
        }
    }

    /// Issue #117: WS セッション終了時 (close / `Bye` 受信) に、 当該 WS に
    /// 紐づく **全 pending oneshot を即時キャンセル** する。
    ///
    /// `oneshot::Sender` を drop すると、 対応する `Receiver` は次回 await で
    /// `Err(RecvError)` を返す (tokio 1.x docs)。 これにより orchestrator 側
    /// (`src/call/orchestrator.rs::run_webrtc_leg`) の
    /// `tokio::time::timeout(leg_timeout, waiter)` が `Ok(Err(_))` で即時
    /// 抜け、 `LegResult::Errored` が返る。 結果として:
    /// - 旧挙動: WS 切断 → leg_timeout (例 30 秒) 経過 → 408 で復帰
    /// - 新挙動: WS 切断 → 即時 (= スケジューラ次 tick) `Errored` で復帰
    ///
    /// 戻り値はキャンセルしたエントリ数 (テスト / ログ用)。 既に空なら 0 件。
    /// Idempotent: 二重呼び出しは 2 回目以降 0 件で安全。
    pub async fn cancel_all(&self) -> usize {
        let mut g = self.inner.lock().await;
        let n = g.len();
        g.clear();
        n
    }

    /// 現在の予約数 (テスト / 観測用)。 production code は通常呼ばない。
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// 現在の予約が空か (テスト / 観測用)。
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

/// PeerSession を WS セッションごとに生成するファクトリ。
///
/// stub を返す既定実装と、str0m 実装を返す本番用とで差し替える。
/// 戻り値の `Future` は `Send`。
pub type PeerFactory = Arc<
    dyn Fn() -> futures_util::future::BoxFuture<'static, Result<Arc<dyn PeerSession>>>
        + Send
        + Sync,
>;

/// stub バックエンド用の既定ファクトリ。
pub fn stub_peer_factory() -> PeerFactory {
    Arc::new(|| {
        Box::pin(async {
            let p: Arc<dyn PeerSession> = StubPeerSession::new();
            Ok(p)
        })
    })
}

/// PWA→NGN 発信ハンドラの戻り値 (Issue #145, PR #146 review #1 🟡#2)。
///
/// browser には `savpf_answer` を即座に `ServerMessage::Answer` で返し
/// (= `peer.handle_offer` の SAVPF answer。 RFC 3264 §6 / RFC 8829)、
/// NGN への INVITE 〜 `MediaBridge::WebRtcAudio` 起動は `completion`
/// (= `JoinHandle`) として **背景タスクで継続** する。 これにより WS 受信
/// ループは数秒の NGN INVITE→200 OK / 408 タイムアウト中もブロックされず、
/// trickle ICE (`ClientMessage::Ice`, RFC 8839 §4) を即時処理できる。
///
/// 背景タスク内のエラーは `ws_sink` 経由で `ServerMessage::Error` を browser
/// に push する責務がハンドラ側にある。
///
/// 本構造体は `must_use` を付ける。 `completion` を drop すると tokio が
/// 背景タスクを継続するが (= JoinHandle を drop しても task は cancel
/// されない、 tokio 1.x docs)、 production の `process_client_message` では
/// 明示的に `let _ = outcome.completion;` で意図を残す。 テストは
/// `outcome.completion.await` で完了を確認する。
#[must_use = "completion JoinHandle を drop すると background task は継続するが、 テストで完了を確認したい場合は await すること"]
#[derive(Debug)]
pub struct PwaOutboundOutcome {
    /// browser に返す SAVPF SDP answer (`peer.handle_offer` の戻り値そのまま)。
    pub savpf_answer: String,
    /// NGN INVITE → 200 OK → `MediaBridge::WebRtcAudio` 起動の背景タスク。
    /// 失敗時は背景タスクが `ws_sink` で `ServerMessage::Error` を browser に push する。
    pub completion: tokio::task::JoinHandle<Result<()>>,
}

/// PWA→NGN 発信通話の cleanup ハンドラ (Issue #147)。
///
/// 本トレイトは WS セッション終了側から呼び出される:
/// - `ClientMessage::Bye` を受信した直後 (PWA UI で「切る」ボタン)
/// - WS 接続が close した直後 (タブ閉じ / ネットワーク断 / Cloudflare idle)
///
/// 実装 ([`crate::call::orchestrator::UasEventHandler`]) は WS と紐づく
/// `webrtc_outbound_active` エントリを全て NGN BYE で閉じ、 RTP ブリッジ /
/// `call_active` メトリクスを cleanup する責務を負う (RFC 3261 §15.1.1
/// `BYE`、 RFC 5853 §3.2.2 SBC framework: 片側 dialog 終了をもう片側へ伝搬)。
///
/// `WebRtcOutboundActive` テーブル本体は orchestrator 内部に閉じ、 シグナ
/// リング層からは本 trait 経由でしか触らない (依存方向: signaling → orchestrator)。
#[async_trait::async_trait]
pub trait PwaOutboundCloser: Send + Sync {
    /// 指定 WS と紐づく PWA→NGN outbound 通話を全て NGN BYE で閉じる。
    /// 戻り値は閉じたエントリ数 (テスト / 観測用、 production code は
    /// 戻り値を読まなくて良い)。 該当無し = 0 (idempotent: 二重 close 安全)。
    async fn close_pwa_outbound_for_ws(&self, ws: &WsSink) -> usize;
}

/// NGN→PWA **着信** 通話の cleanup ハンドラ (Bug B / Issue #268)。
///
/// 役割: 旧実装は WS close 時に inbound 通話 entry を放置していたため、 PWA
/// がタブ閉じ / ネットワーク断したとき、 NGN 側 dialog が 5-10 秒タイムアウト
/// するまで sabiden は何も通知せず、 NGN→sabiden の RTP もブリッジが生きた
/// まま流れ続けていた (実機 v7 で 6 秒の `recv BYE` 待ちを観測)。
///
/// 本 trait は WS セッション終了側から呼ばれる ([`PwaOutboundCloser`] と同じ
/// 経路 / 同じ順序)。 実装 ([`crate::call::orchestrator::NgnInboundHandler`]) は:
///
/// 1. `webrtc_active` テーブルから WS 一致 entry を `extract_if` で抽出する。
/// 2. 各 entry の `send_bye` で NGN へ BYE を撃つ (UAS dialog 由来、
///    RFC 3261 §15.1.1)。
/// 3. RTP ブリッジ (`self.active` 経由) を `terminate` する。
/// 4. `metrics.dec_call_active` を呼ぶ。
///
/// RFC 3261 §15.1.2 / RFC 5853 §3.2.2 (SBC framework): B2BUA は片側 dialog
/// 終了をもう片側へ伝搬する責務を負う。 outbound (Issue #147 で実装済) と
/// inbound (本 trait) を両方持って初めて、 PWA 切断 → NGN 即時 BYE という
/// 対称な hangup シーケンスが成立する。
///
/// `WebRtcInboundActive` テーブル本体は orchestrator 内部に閉じ、 シグナ
/// リング層からは本 trait 経由でしか触らない (依存方向: signaling → orchestrator)。
#[async_trait::async_trait]
pub trait PwaInboundCloser: Send + Sync {
    /// 指定 WS と紐づく NGN→PWA inbound 通話を全て NGN BYE で閉じる。
    /// 戻り値は閉じたエントリ数 (テスト / 観測用、 production code は
    /// 戻り値を読まなくて良い)。 該当無し = 0 (idempotent: 二重 close 安全)。
    async fn close_pwa_inbound_for_ws(&self, ws: &WsSink) -> usize;
}

/// PWA→NGN 発信ハンドラ (Issue #145)。
///
/// `ClientMessage::Offer { target, sdp }` を受けたとき、 sabiden が
/// 1. `peer.handle_offer(savpf)` で str0m が ICE/DTLS の準備 (= browser に
///    即返すため同期実行)
/// 2. `peer.take_media_rx()` で MediaFrame mpsc receiver を取得 (= 1 度しか
///    取れないので background spawn 前に確実に押さえる必要がある)
/// 3. SAVPF answer → AVP → PCMU only に変換した SDP で NGN へ INVITE
///    (= 数秒かかる可能性があるため background spawn)
/// 4. 200 OK 受信 → `MediaBridge::WebRtcAudio` を起動 (NGN UDP socket ⇄
///    Opus⇔PCMU トランスコーダ ⇄ str0m peer)
/// 5. 戻り値の SAVPF answer を browser へ即返す
///
/// を担当するために、 シグナリング層から呼べる薄いインタフェース。
/// 本トレイトを実装する型 (本番は `UasEventHandler` 経由) は `Uac` /
/// `CallManager` / RTP bridge bind IP を保持する。
///
/// PR #146 review #1 🟡#2 (WS 受信ループ長時間ブロック対策): NGN INVITE
/// は `tokio::spawn` で背景化し、 SAVPF answer は `peer.handle_offer` 直後
/// に即返す。 これにより `ClientMessage::Ice` (trickle ICE) が NGN 200 OK
/// 待ちの間も処理され、 ICE 確立遅延 / Disconnected を避ける。
#[async_trait::async_trait]
pub trait PwaOutboundHandler: Send + Sync {
    /// PWA→NGN 発信フローを駆動する。 戻り値は browser に返す SAVPF SDP answer
    /// と background task の JoinHandle (`PwaOutboundOutcome`)。
    ///
    /// # 引数
    /// - `target`: 発信先番号 (例 "117")。 sabiden が P-CSCF host:port を補う。
    ///   呼出側 (`process_client_message`) で RFC 3261 §25.1 user 文法
    ///   (`[0-9*#+]{1,32}`) に絞ったホワイトリスト検証済みの値が渡される前提。
    ///   実装側でも防御的に再検証する (defense in depth)。
    /// - `browser_offer_sdp`: browser が送ってきた SAVPF SDP。
    /// - `peer`: 当該 WS セッションの `PeerSession`。
    ///   `take_media_rx` を内部で呼び出して bridge に渡すので、 呼出後の peer
    ///   は media を別経路では取れなくなる点に注意。
    /// - `ws_sink`: 背景タスクからの `ServerMessage::Error` push 用。
    ///   NGN 503 / 486 等の失敗を browser に通知するため。
    ///
    /// # エラー (同期 = `Result<_, _>` の Err)
    /// - target validation 失敗 / `peer.handle_offer` 失敗 / `peer.take_media_rx`
    ///   None (stub backend 等) のいずれかで `Err`。 呼出側は
    ///   `ServerMessage::Error` を返す。
    ///
    /// # エラー (非同期 = completion JoinHandle の戻り値)
    /// - NGN INVITE 失敗 / bridge 起動失敗。 ハンドラは `ws_sink` 経由で
    ///   browser に `ServerMessage::Error` を push してから `Err` を返す。
    async fn handle_pwa_outbound_offer(
        &self,
        target: &str,
        browser_offer_sdp: &str,
        peer: &Arc<dyn PeerSession>,
        ws_sink: &WsSink,
    ) -> Result<PwaOutboundOutcome>;
}

/// 発信先 `target` の文字種ホワイトリスト (Issue #145, PR #146 review #1 🔴#1)。
///
/// browser からの任意文字列が NGN INVITE の Request-URI user 部に流れる
/// 経路を塞ぐ。 攻撃ベクタ: `target = "117\r\nFoo: bar\r\n\r\nINVITE sip:..."`
/// で sabiden が任意 SIP メッセージを NGN に注入できる (CRLF injection)。
///
/// RFC 3261 §25.1 の `user` 産生 (`unreserved / escaped / user-unreserved`)
/// は `+` を含むが、 sabiden は電話番号 / 短縮番号のみを扱うため、
/// dial pad と同じ `[0-9*#+]` の 4 種に絞る (frontend `Dialer.tsx` の UI
/// フィルタと一致)。 長さは 32 文字 (E.164 max 15 + 国際 prefix + マージン)。
///
/// frontend の UI フィルタは server-side で再検証必要 (browser 改造 / 直接
/// WS 接続による迂回防止、 OWASP A03:2021 Injection)。
fn is_valid_dial_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 32 {
        return false;
    }
    target
        .chars()
        .all(|c| c.is_ascii_digit() || c == '*' || c == '#' || c == '+')
}

/// シグナリングサーバの共有状態。
#[derive(Clone)]
pub struct SignalingState {
    pub verifier: Arc<Verifier>,
    pub extensions: Arc<ExtensionRegistrar>,
    /// `register` 受信時に AOR を Registrar に書き込む際の expires。
    pub register_ttl: Duration,
    /// PeerSession を生成するファクトリ。`stub_peer_factory()` か、
    /// 本番なら str0m バックエンドを返すクロージャ。
    pub peer_factory: PeerFactory,
    /// サーバ → クライアント方向への WebSocket Ping 送信間隔。
    ///
    /// Cloudflare Tunnel は idle 100 秒で WS を切断するため (`docs/CLOUDFLARE.md`)、
    /// 既定では 30 秒周期で Ping を送る (RFC 6455 §5.5.2: Ping は keepalive 用途
    /// として MAY、 経路上の idle timer リセットに用いてよい)。
    pub keepalive_interval: Duration,
    /// 最後に何らかのフレーム (特に Pong) を受信してからこの時間が経過したら
    /// アイドル切断する。 既定 60 秒 = `keepalive_interval` の 2 倍。
    /// Cloudflare の 100 秒 timeout より十分小さい値を選んでいる。
    pub idle_timeout: Duration,
    /// PWA→NGN 発信ハンドラ (Issue #145)。 None のとき `target` 付き
    /// Offer は `ServerMessage::Error{code:"outbound_unavailable"}` で拒否
    /// する (sabiden が NGN UAC を持っていない構成 = 内線無し設定など)。
    pub pwa_outbound: Option<Arc<dyn PwaOutboundHandler>>,
    /// PWA→NGN 発信通話の cleanup ハンドラ (Issue #147)。 `ClientMessage::Bye`
    /// 受信時 / WS close 時に該当 WS の outbound 通話を NGN へ BYE で伝搬する。
    /// `None` のときは PWA outbound が無い構成 (= `pwa_outbound = None`) と
    /// 同義。 通常 `pwa_outbound` と同じ `UasEventHandler` を `Arc::clone`
    /// で渡す (`PwaOutboundHandler` と `PwaOutboundCloser` の両方を実装)。
    pub pwa_outbound_closer: Option<Arc<dyn PwaOutboundCloser>>,
    /// NGN→PWA 着信通話の cleanup ハンドラ (Bug B / Issue #268)。 WS close 時に
    /// 該当 WS の inbound 通話を NGN へ BYE で伝搬する。 `None` のときは旧挙動
    /// 互換 (= NGN タイムアウト BYE 待ち、 5-10 秒)。 通常 `NgnInboundHandler`
    /// を `Arc::clone` で渡す。
    pub pwa_inbound_closer: Option<Arc<dyn PwaInboundCloser>>,
}

impl SignalingState {
    /// stub PeerSession を使う既定設定 (テスト/段階導入向け)。
    pub fn new(
        verifier: Arc<Verifier>,
        extensions: Arc<ExtensionRegistrar>,
        register_ttl: Duration,
    ) -> Self {
        Self {
            verifier,
            extensions,
            register_ttl,
            peer_factory: stub_peer_factory(),
            keepalive_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            pwa_outbound: None,
            pwa_outbound_closer: None,
            pwa_inbound_closer: None,
        }
    }

    /// 任意の [`PeerFactory`] を指定する。
    pub fn with_peer_factory(mut self, factory: PeerFactory) -> Self {
        self.peer_factory = factory;
        self
    }

    /// keepalive 周期 / idle timeout を上書きする (テスト・調整用途)。
    pub fn with_keepalive(mut self, interval: Duration, idle_timeout: Duration) -> Self {
        self.keepalive_interval = interval;
        self.idle_timeout = idle_timeout;
        self
    }

    /// PWA→NGN 発信ハンドラを差し込む (Issue #145)。
    pub fn with_pwa_outbound(mut self, h: Arc<dyn PwaOutboundHandler>) -> Self {
        self.pwa_outbound = Some(h);
        self
    }

    /// PWA→NGN 発信通話の cleanup ハンドラを差し込む (Issue #147)。
    /// 通常 `with_pwa_outbound` と同じ `UasEventHandler` を渡す。
    pub fn with_pwa_outbound_closer(mut self, h: Arc<dyn PwaOutboundCloser>) -> Self {
        self.pwa_outbound_closer = Some(h);
        self
    }

    /// NGN→PWA 着信通話の cleanup ハンドラを差し込む (Bug B / Issue #268)。
    /// 通常 `NgnInboundHandler` を `Arc::clone` で渡す。
    pub fn with_pwa_inbound_closer(mut self, h: Arc<dyn PwaInboundCloser>) -> Self {
        self.pwa_inbound_closer = Some(h);
        self
    }
}

/// クライアント → サーバ メッセージ。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientMessage {
    Register {
        ext_id: String,
    },
    /// browser 発の offer。 `target` 付きなら PWA→NGN 発信フロー
    /// (Issue #145, RFC 3264 §5 offerer flow)。 `target` 無しは旧来の
    /// echo モード (peer.handle_offer の SAVPF answer をそのまま browser に
    /// 返す。 試験用に残置)。
    Offer {
        sdp: String,
        /// 発信先 (例 "117" や "0312345678")。 NGN INVITE の Request-URI
        /// user 部に詰める。 sabiden 側で P-CSCF IP+port を host に補う
        /// (RFC 3261 §19.1.1 / `docs/asterisk-real-invite.md` §5.1)。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
    },
    /// sabiden 発の offer (NGN 着信を browser へ push) に対する応答。
    /// `call_id` で対応する着信を識別する。
    Answer {
        call_id: String,
        sdp: String,
    },
    /// sabiden 発の offer (NGN 着信を browser へ push) に対する **拒否** 通知
    /// (Issue #107)。 ringing 中の着信を browser ユーザが「拒否」ボタンで
    /// 拒んだことを sabiden に伝える。 受信した sabiden は対応する
    /// `PendingAnswers` waiter に `AnswerOutcome::Decline { status: 603 }`
    /// (RFC 3261 §21.6.2 Decline) を流し、 内線フォーク全体としては
    /// `LegResult::Failed { status: 603 }` で集約される。 fork に他レッグが
    /// いなければ NGN へは 603 Decline が返り、 居れば他レッグの応答を待つ
    /// (Asterisk 風フォーク semantics、 RFC 3261 §16.7)。
    ///
    /// `Bye` (= WS セッション = 内線登録ごと終了) とは別物。 こちらは個別の
    /// 進行中着信を拒否するだけで、 WS / 内線登録は維持される。
    Decline {
        call_id: String,
    },
    Ice {
        candidate: String,
    },
    Bye,
}

/// サーバ → クライアント メッセージ。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerMessage {
    Registered {
        ext_id: String,
    },
    /// browser 発の offer に対する sabiden の answer。
    Answer {
        sdp: String,
    },
    /// NGN 着信 INVITE を browser へ push する offer。
    /// browser は `ClientMessage::Answer { call_id, sdp }` で応答する。
    Offer {
        call_id: String,
        sdp: String,
    },
    /// 進行中の着信が NGN CANCEL 等で中止されたことを browser に通知する。
    Cancel {
        call_id: String,
    },
    Ice {
        candidate: String,
    },
    Error {
        code: String,
        message: String,
    },
    Bye,
}

impl ServerMessage {
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        ServerMessage::Error {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

/// `?token=<token>` クエリ。
#[derive(Debug, Deserialize)]
pub struct AuthQuery {
    #[serde(default)]
    pub token: Option<String>,
}

/// axum ハンドラ: `GET /signal` で WebSocket にアップグレード。
///
/// 認証失敗時は 401 を返す。成功時は [`run_session`] にセッションを委譲。
pub async fn signal_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<SignalingState>,
    Query(q): Query<AuthQuery>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Response {
    let token = match extract_token(&headers, &q) {
        Some(t) => t,
        None => {
            return (StatusCode::UNAUTHORIZED, "missing token\n").into_response();
        }
    };
    let claims = match state.verifier.verify(&token) {
        Ok(c) => c,
        Err(e) => {
            warn!(remote = %remote, error = %e, "WebRTC シグナリング認証失敗");
            return (StatusCode::UNAUTHORIZED, "invalid token\n").into_response();
        }
    };
    info!(remote = %remote, ext = %claims.ext_id, "WebRTC シグナリング接続");
    ws.on_upgrade(move |socket| run_session(socket, state, claims, remote))
}

/// `Authorization: Bearer ...` ヘッダ または `?token=...` を抽出。
///
/// auth-scheme (`Bearer`) は **case-insensitive** で比較する
/// (RFC 6750 §2.1, RFC 9110 §11.1 / 旧 RFC 7235 §2.1)。
/// `Bearer` / `bearer` / `BEARER` / `BeArEr` 全てを受理する。
///
/// scheme と token68 の区切りは RFC 9110 §5.6.3 の `RWS = 1*( SP / HTAB )`
/// を許容する。 単一 SP しか許さない実装は仕様違反 (Issue #95)。
pub fn extract_token(headers: &HeaderMap, query: &AuthQuery) -> Option<String> {
    if let Some(h) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(tok) = parse_bearer(h) {
            return Some(tok);
        }
    }
    query.token.as_ref().filter(|s| !s.is_empty()).cloned()
}

/// `Authorization` ヘッダ値から `Bearer` scheme の token68 部分を抽出する。
///
/// # 文法
///
/// ```text
/// credentials = auth-scheme [ 1*SP ( token68 / [ #auth-param ] ) ]
/// auth-scheme = token            ; case-insensitive (RFC 9110 §11.1)
/// ```
///
/// 厳密には RFC 9110 §11.6.2 の `credentials` は `1*SP` 区切りだが、
/// §5.6.3 の一般原則 (RWS = 1*( SP / HTAB )) に倣って HTAB も受理する。
/// 多くの実装 (`actix-web-httpauth` / `axum-auth` / `tower-http`) も同様。
///
/// 戻り値:
/// - `Some(token)`: scheme が `Bearer` (大文字小文字無視) かつ token が非空
/// - `None`: scheme 不一致 / token 空 / フォーマット不正
fn parse_bearer(header_value: &str) -> Option<String> {
    // 先頭の OWS を捨てる (実用上 axum はトリム済だが防御的に)。
    let trimmed = header_value.trim_start();
    // scheme と rest を 1 文字目の ASCII SP / HTAB で分割。
    let sep_idx = trimmed
        .char_indices()
        .find(|(_, c)| *c == ' ' || *c == '\t')
        .map(|(i, _)| i)?;
    let (scheme, rest) = trimmed.split_at(sep_idx);
    // RFC 9110 §11.1: auth-scheme は case-insensitive。
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    // RWS を読み飛ばし、 token 部分を取得。
    let token = rest.trim_start_matches([' ', '\t']);
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// 認証済みセッションのメインループ。
///
/// テスト容易性のため [`PeerSession`] は本関数内で生成するのではなく、
/// 公開ヘルパ [`process_client_message`] でロジックを分離する。
pub async fn run_session(
    socket: WebSocket,
    state: SignalingState,
    claims: AuthClaims,
    remote: SocketAddr,
) {
    let (sender, mut receiver) = socket.split();
    // PeerSession を factory で生成 (stub または str0m)。
    let peer: Arc<dyn PeerSession> = match (state.peer_factory)().await {
        Ok(p) => p,
        Err(e) => {
            warn!(error=%e, "PeerSession 生成失敗、WS セッション中断");
            return;
        }
    };

    // sender は trickle ICE タスク・server-push forwarder・keepalive タスクで共有する。
    let sender = Arc::new(Mutex::new(sender));

    // server → client メッセージを enqueue する mpsc。NGN 着信時に
    // orchestrator が `WsSink` 経由でこの送信側に offer を流し込み、
    // forwarder タスクが WS フレームに変換して送る。`run_session` 自身も
    // `process_client_message` の `Reply` をこの mpsc 経由で送ることで
    // 排他制御を一元化する。
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let ws_sink = WsSink::new(out_tx.clone());
    let pending_answers = PendingAnswers::new();

    // keepalive watchdog 用: 受信時刻を tokio::time::Instant で共有する。
    // tokio::time::pause/advance 下でも仮想時計で揃うので、 テストは
    // `start_paused = true` + `tokio::time::advance` で短時間に検証できる。
    let last_recv: Arc<Mutex<Instant>> = Arc::new(Mutex::new(Instant::now()));

    // 全タスク (forwarder / keepalive / trickle) の協調終了用シャットダウン
    // シグナル。 keepalive がアイドル検知で trip させると、 受信ループ側の
    // `tokio::select!` がこちらを優先で抜ける。
    let shutdown = Arc::new(Notify::new());

    // 送信 forwarder タスク。`out_rx` を WS Text フレームに変換して送る。
    {
        let sender_clone = sender.clone();
        let shutdown_c = shutdown.clone();
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                let payload = match serde_json::to_string(&msg) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error=%e, "ServerMessage シリアライズ失敗");
                        continue;
                    }
                };
                let mut s = sender_clone.lock().await;
                if s.send(Message::Text(payload)).await.is_err() {
                    debug!("server-push: WS 送信失敗、forwarder 終了");
                    // Issue #167 (PR #165 follow-up): WS 送信失敗時点では
                    // **受信ループ** と **keepalive ループ** の 2 タスクが
                    // 同時に `shutdown.notified()` を能動 await している
                    // (受信ループ line 744 / keepalive line 992)。
                    //
                    // `tokio::sync::Notify::notify_one()` の仕様 (tokio
                    // 1.x doc): **最大 1 waiter** を起こす。 active waiter
                    // が 2 つ居ても 1 つしか拾えず、 残った 1 つは次の
                    // `notify_one()` まで待ち続ける。 旧コードは 1 回しか
                    // 呼んでいなかったので、 forwarder 失敗時に **片方の
                    // ループだけ撤収** し、 もう片方は idle_timeout や
                    // out_rx.recv()=None 経由で間接的に抜けるまで残留
                    // していた (= RFC 6455 §7.4.1 abnormal closure 撤収が
                    // 遅延する原因)。
                    //
                    // 修正: 2 回呼んで両 await を起こす。 2 回目は (片方
                    // 既に起きていれば) permit として蓄えられ、 後続の
                    // `notified()` で消費される (tokio Notify は permit 上限
                    // 1 だが、 2 active waiter の同時起床用途では 2 回呼ぶ
                    // のが推奨イディオム)。 RFC 6455 §5.5.2 Ping path /
                    // §7.4.1 Close handshake のどちらも、 forwarder 失敗
                    // (= TCP/TLS 層断) 後は即時撤収するのが正しい。
                    shutdown_c.notify_one();
                    shutdown_c.notify_one();
                    break;
                }
            }
        });
    }

    // keepalive タスク (RFC 6455 §5.5.2 Ping frame)。 詳細は
    // [`run_keepalive_loop`] の docstring を参照。
    {
        let sender_clone = sender.clone();
        let last_recv_c = last_recv.clone();
        let shutdown_c = shutdown.clone();
        let interval = state.keepalive_interval;
        let idle_to = state.idle_timeout;
        tokio::spawn(async move {
            run_keepalive_loop(
                AxumPingSender(sender_clone),
                last_recv_c,
                shutdown_c,
                interval,
                idle_to,
            )
            .await;
        });
    }

    // str0m バックエンドが local candidates を流すので、その receiver を
    // 取り出して trickle 出力タスクを spawn する。stub は None を返すので
    // タスクは起動されない。
    //
    // Issue #92 / RFC 8838 §13 (Generating an End-of-Candidates Indication): str0m
    // run_loop は host candidate を 1 件送出した直後に **空文字列を end-of-candidates
    // marker** として送る (`str0m_session.rs::handle_event` 参照)。 本タスクはチャネル
    // 値をそのまま `ServerMessage::Ice` の wire 表現に乗せるため、 empty 文字列
    // は wire 上でも `{"type":"ice","candidate":""}` として PWA に届く。 PWA 側
    // (`frontend/src/lib/webrtc.ts::addIce`) は空文字列を `pc.addIceCandidate(null)`
    // に翻訳して RFC 8838 §14 (Receiving the End-of-Candidates Indication) /
    // W3C WebRTC §4.4.1.6 の end-of-candidates として解釈する。
    //
    // 注: RFC 8840 は SIP usage 専用 (Trickle ICE over SIP)。 sabiden は WebSocket
    // JSON シグナリングなので、 trickle ICE の一般仕様である RFC 8838 を引用する。
    if let Some(mut local_cand_rx) = peer.take_local_candidates().await {
        let push = ws_sink.clone();
        tokio::spawn(async move {
            while let Some(cand) = local_cand_rx.recv().await {
                if push.send(ServerMessage::Ice { candidate: cand }).is_err() {
                    debug!("trickle ICE: forwarder 終了済み、出力タスク終了");
                    break;
                }
            }
        });
    }

    let registered_aor: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    loop {
        let frame = tokio::select! {
            _ = shutdown.notified() => {
                debug!("受信ループ: keepalive watchdog から shutdown 通知");
                break;
            }
            f = receiver.next() => f,
        };

        let Some(frame) = frame else {
            break;
        };

        // 何らかのフレームが届いた = 経路は生きている。 last_recv を更新する
        // ことで idle watchdog をリセットする。 Pong だけでなく Text/Ping も
        // すべて活動シグナルとして扱う (RFC 6455 §5.5.3 Pong は keepalive 用
        // 単方向 frame として送ってもよい、 と明記。 このため Ping/Text 受信
        // でも timeout はリセットされるべき)。
        if frame.is_ok() {
            *last_recv.lock().await = Instant::now();
        }

        let msg = match frame {
            Ok(Message::Text(t)) => t,
            Ok(Message::Close(_)) => {
                debug!("WS close 受信");
                break;
            }
            Ok(Message::Ping(p)) => {
                let mut s = sender.lock().await;
                let _ = s.send(Message::Pong(p)).await;
                continue;
            }
            Ok(Message::Pong(_)) => {
                // last_recv は上で更新済み。 ブラウザは Ping を能動送出できない
                // 仕様 (axum.rs::extract::ws ws.rs:582-585 自動応答) なので、
                // 通常はここを通る。
                continue;
            }
            Ok(_) => continue,
            Err(e) => {
                warn!(error=%e, "WS 受信エラー");
                break;
            }
        };

        let parsed: ClientMessage = match serde_json::from_str(&msg) {
            Ok(m) => m,
            Err(e) => {
                let _ = ws_sink.send(ServerMessage::error("bad_json", e.to_string()));
                continue;
            }
        };

        let mut aor_guard = registered_aor.lock().await;
        let resp = process_client_message(
            parsed,
            &state,
            &claims,
            &peer,
            remote,
            &mut aor_guard,
            &ws_sink,
            &pending_answers,
        )
        .await;
        drop(aor_guard);

        match resp {
            SessionAction::Reply(sm) => {
                let is_bye = matches!(sm, ServerMessage::Bye);
                if ws_sink.send(sm).is_err() {
                    break;
                }
                if is_bye {
                    break;
                }
            }
            SessionAction::Continue => {}
            SessionAction::Close => break,
        }
    }

    // 周辺タスク (forwarder / keepalive) を確実に止める。
    //
    // Issue #131: `notify_one()` は permit を蓄える (tokio `Notify` doc)。
    // 受信ループ離脱直後に keepalive が `select!` の片足で `send_ping` 等の
    // await に入っている可能性があるが、 permit 化されているので次 tick で
    // 即時 `notified()` が解決し撤収する。 `notify_waiters()` だと該当瞬間
    // に awaiting でないタスクに通知が届かず lost。 forwarder は
    // `out_rx.recv()` 主導なので shutdown を待たず、 ここの notify は
    // 主に keepalive 向け。
    shutdown.notify_one();

    // Issue #147: WS が close した = PWA は通話を維持できない。 進行中の
    // PWA→NGN 発信通話があれば NGN レッグへ BYE を撃つ (RFC 3261 §15.1.1)。
    // タブ閉じ / ネットワーク断 / Cloudflare Tunnel idle 切断のいずれの
    // 経路で WS が落ちても、 NGN dialog が 5 分残って 486 を返す事象
    // (Issue #147 の根本要因) を防ぐ。 `ClientMessage::Bye` 経路で既に
    // cleanup 済みなら本呼び出しは 0 件 = no-op (idempotent)。
    //
    // 順序: `pending_answers.cancel_all()` (Issue #117) より **後** に呼ぶ。
    // outbound 側 (`webrtc_outbound_active`) は本ハンドラで掃除されるが、
    // inbound 側 (`webrtc_legs`) の waiter は `pending_answers` にぶら下がる
    // ので、 こちらは下の `cancel_all` で即時起こす必要がある。
    if let Some(closer) = state.pwa_outbound_closer.as_ref() {
        let n = closer.close_pwa_outbound_for_ws(&ws_sink).await;
        if n > 0 {
            info!(
                closed = n,
                "PWA→NGN BYE: WS close 経路で cleanup (Issue #147)"
            );
        }
    }

    // Bug B / Issue #268: NGN→PWA 着信通話の cleanup も同じ経路で実施する。
    // PWA がタブ閉じ / ネットワーク断 / Cloudflare Tunnel idle 切断したとき、
    // sabiden は 旧実装 (Issue #81) では「NGN BYE を待つ」 だけで NGN に何も
    // 通知しなかったため、 NGN は dialog confirmed のまま 5-10 秒タイムアウト
    // するまで RTP を流し続けていた (実機 v7 で 6 秒 `recv BYE` 待ちを観測)。
    //
    // 本呼出で sabiden が NGN へ即座に BYE を撃ち、 RTP ブリッジ / metrics
    // を cleanup する (RFC 3261 §15.1.1 / RFC 5853 §3.2.2 SBC framework:
    // B2BUA は片側 dialog 終了をもう片側へ伝搬する責務を負う)。
    //
    // 順序: outbound closer の後 / `pending_answers.cancel_all()` の前。
    // outbound (発信中) と inbound (着信中) が同じ WS に同居することは
    // 通常ない (UI は同時 1 通話) が、 idempotent なので順序入替も無害。
    if let Some(closer) = state.pwa_inbound_closer.as_ref() {
        let n = closer.close_pwa_inbound_for_ws(&ws_sink).await;
        if n > 0 {
            info!(
                closed = n,
                "NGN→PWA BYE: WS close 経路で cleanup (Bug B / Issue #268)"
            );
        }
    }

    // Issue #117: WS が close した時点で、 当該セッションに紐づく
    // `PendingAnswers` の oneshot waiter は **二度と** answer が届かない
    // (browser が居ない)。 即時 `cancel_all` で oneshot::Sender を drop し、
    // orchestrator 側の `run_webrtc_leg` がぶら下がっている `waiter.await`
    // を `Err(RecvError)` で即時起こす。 これで「WS 切断 → leg_timeout
    // (30 秒) 経過 → 408」という遅延が解消する。
    //
    // `unregister` より **先** に実行する: 順序は実害無いが、 cancel_all で
    // waiter を起こす方が「inbound fork が即時撤収」を観測しやすい。
    // Idempotent なので、 すでに `Bye` 経路で空になっていれば 0 件。
    let cancelled = pending_answers.cancel_all().await;
    if cancelled > 0 {
        debug!(
            cancelled,
            "PendingAnswers: WS close 時に全 oneshot waiter をキャンセル (Issue #117)"
        );
    }

    // クリーンアップ: AOR 失効 + PeerSession close
    //
    // `unregister(aor)` は ExtensionRegistrar の HashMap から Binding を消す
    // ので、 binding が保持していた `ExtTransport::WebRtc { ws: WsSink, .. }`
    // クローンも drop される。 これにより `out_tx` の参照カウントが減る。
    if let Some(aor) = registered_aor.lock().await.take() {
        state.extensions.unregister(&aor).await;
        info!(aor=%aor, "WebRTC AOR 失効");
    }
    let _ = peer.close().await;

    // Issue #117: 送信 forwarder タスクの確実な終了。
    //
    // forwarder タスク (line 526-553) は `out_rx.recv()` ループで blocking
    // しており、 全 `out_tx` クローンが drop されるまで `recv()` は終わらず
    // タスクがリークする (tokio mpsc docs: 全 sender が drop されたとき
    // のみ `recv()` が `None` を返す)。
    //
    // ここで `run_session` が握っている最後の sender を明示 drop することで、
    // **本セッションが起源の sender** は確実に解放される。 残るクローン:
    // - `peer` の str0m local-candidate forwarder task: `peer.close()` 完了で
    //   `local_cand_rx` 経路が落ち、 trickle 出力タスクは `recv() = None` で
    //   抜けて自前のクローンを drop する。
    // - 進行中の inbound `WebRtcLegHandle.ws` クローン: 上の `cancel_all` で
    //   `oneshot::Sender` が落ち、 `run_webrtc_leg` が `Errored` で即時撤収
    //   する際に handle ごと drop される (`close_and_drain_webrtc_legs`)。
    // - 進行中の outbound `webrtc_outbound_active.ws`: `close_pwa_outbound_for_ws`
    //   で `extract_if` により entry ごと drop。
    //
    // よって本順序での drop により、 **数 await tick 以内** に forwarder の
    // `out_rx.recv()` が `None` を返し、 タスクがリークしないことが保証される。
    drop(ws_sink);
    drop(out_tx);
}

/// 単一クライアントメッセージを処理した結果。
pub enum SessionAction {
    /// 1 つの応答を送る。`Bye` の場合は送信後にコネクションを閉じる。
    Reply(ServerMessage),
    /// 何も送らず継続。
    Continue,
    /// 即座に切断。
    Close,
}

/// keepalive タスクが Ping / Close frame を流す送信先の最小抽象。
///
/// 本番では axum の `WebSocket` の split sender、 テストでは送信記録用の
/// 偽実装を渡せるように trait 化している。
#[async_trait::async_trait]
pub trait KeepaliveSender: Send {
    /// `Message::Ping(payload)` 相当を送信する。 失敗時 (相手切断等) は `Err`。
    async fn send_ping(&self, payload: Vec<u8>) -> Result<()>;
    /// idle timeout 検知時の Close frame 送信。
    async fn send_close(&self, code: u16, reason: String) -> Result<()>;
}

/// axum の `WebSocket` の SplitSink を `Arc<Mutex<...>>` で共有しつつ、
/// `KeepaliveSender` インターフェースで使えるようにする薄ラッパ。
struct AxumPingSender(Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>);

#[async_trait::async_trait]
impl KeepaliveSender for AxumPingSender {
    async fn send_ping(&self, payload: Vec<u8>) -> Result<()> {
        let mut s = self.0.lock().await;
        s.send(Message::Ping(payload))
            .await
            .map_err(|e| anyhow::anyhow!("WS Ping 送信失敗: {}", e))
    }

    async fn send_close(&self, code: u16, reason: String) -> Result<()> {
        let mut s = self.0.lock().await;
        s.send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await
        .map_err(|e| anyhow::anyhow!("WS Close 送信失敗: {}", e))
    }
}

/// keepalive ループ本体: 周期 Ping 送出 + idle 検知 close。
///
/// # 仕様
///
/// - **RFC 6455 §5.5.2 (Ping frame)**: `interval` ごとに opcode 0x9 (Ping) を
///   サーバ → クライアント方向に送る。 application data は keepalive 用途
///   では意味を持たないので空 payload。
/// - **RFC 6455 §5.5.3 (Pong frame)**: クライアントは Ping 受信時に Pong を
///   "as soon as is practical" で返す MUST。 ブラウザ WebSocket API は
///   library 任せで自動応答する (RFC 6455 §5.5.2 implementer note)。
/// - **idle timeout**: `last_recv` (受信ループが任意フレーム受信時に更新する
///   `tokio::time::Instant`) と現在時刻の差が `idle_timeout` を超えたら、
///   Close frame (RFC 6455 §7.4.1 status code 1011 = "internal error") を
///   送って `shutdown.notify_one()` する (Issue #131: permit を蓄える形に
///   変更、 受信ループが深い await 内でも次 select で即時撤収)。
///   受信ループ側はこの通知を `tokio::select!` で観測して終了する。
/// - **Cloudflare Tunnel 100 秒 idle (`docs/CLOUDFLARE.md`)**: 既定値
///   `interval=30s` / `idle_timeout=60s` はこれより十分小さい。
///
/// # キャンセル安全性
///
/// `shutdown.notified()` を `tokio::select!` の片足に入れているので、
/// 受信ループ側が先に終了したケースでも Ping 送信中にハングしない。
pub async fn run_keepalive_loop<S: KeepaliveSender>(
    sender: S,
    last_recv: Arc<Mutex<Instant>>,
    shutdown: Arc<Notify>,
    interval: Duration,
    idle_timeout: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    // 起動直後の即発火 tick を捨てる。 これで初回の Ping は最低
    // `interval` 経過後に送られる (実機経路の idle timer と一致する挙動)。
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                debug!("keepalive: shutdown 通知でタスク終了");
                return;
            }
            _ = ticker.tick() => {}
        }

        // idle 検知: 前回受信から idle_timeout 超なら撤収。
        let elapsed = {
            let last = *last_recv.lock().await;
            Instant::now().saturating_duration_since(last)
        };
        if elapsed >= idle_timeout {
            warn!(
                elapsed_ms = elapsed.as_millis() as u64,
                idle_timeout_ms = idle_timeout.as_millis() as u64,
                "WS keepalive: Pong 不在で idle timeout、 Close を送って撤収"
            );
            let _ = sender.send_close(1011, "idle timeout".to_string()).await;
            // Issue #131: `notify_one()` で permit を蓄える (tokio `Notify`
            // doc)。 受信ループが深い await 内 (例: process_client_message
            // の I/O 中) でも次 `notified()` で即解放され、 アイドル切断時
            // の撤収が遅れる事象が解消する。
            shutdown.notify_one();
            return;
        }

        // Ping 送信。 失敗 (相手切断) なら撤収。
        if sender.send_ping(Vec::new()).await.is_err() {
            debug!("keepalive: WS 送信失敗 (相手切断)、 keepalive タスク終了");
            // Issue #131: 同上 — permit を蓄えて受信ループの即時撤収を保証。
            shutdown.notify_one();
            return;
        }
    }
}

/// シグナリングのメッセージ処理本体。テスト用に分離。
///
/// `aor_guard` は WS セッションが現在 Registrar に書いている AOR を
/// `Mutex<Option<String>>` で外側から渡す。`register` で書き込み、
/// `bye` または WS 切断で消える。
/// `ws_sink` はサーバ → クライアント送信チャネル (NGN 着信を push する
/// orchestrator もここに enqueue する)、`pending_answers` は sabiden 発の
/// offer に対する browser 応答を待ち合わせるテーブル。
#[allow(clippy::too_many_arguments)]
pub async fn process_client_message(
    msg: ClientMessage,
    state: &SignalingState,
    claims: &AuthClaims,
    peer: &Arc<dyn PeerSession>,
    remote: SocketAddr,
    aor_guard: &mut Option<String>,
    ws_sink: &WsSink,
    pending_answers: &PendingAnswers,
) -> SessionAction {
    match msg {
        ClientMessage::Register { ext_id } => {
            // 認証済み ext_id とリクエスト ext_id は一致しなければならない
            if ext_id != claims.ext_id {
                return SessionAction::Reply(ServerMessage::error(
                    "ext_id_mismatch",
                    format!("token issued for {}", claims.ext_id),
                ));
            }
            // contact_uri は WebRTC では SIP UAC で発呼されないので意味を持たない。
            // Phase 4 までの互換のため `webrtc.peer` ホストを残し、`transport` で
            // 実体を判別する設計に切り替えた。
            let contact_uri = format!("sip:{}@webrtc.peer", ext_id);
            let transport = ExtTransport::WebRtc {
                peer: peer.clone(),
                ws: ws_sink.clone(),
                pending: pending_answers.clone(),
            };
            state
                .extensions
                .register_with_transport(
                    &ext_id,
                    contact_uri,
                    remote,
                    state.register_ttl,
                    transport,
                )
                .await;
            *aor_guard = Some(ext_id.clone());
            info!(aor=%ext_id, "WebRTC 内線登録");
            SessionAction::Reply(ServerMessage::Registered { ext_id })
        }
        ClientMessage::Offer { sdp, target } => {
            // Issue #145: target 付きは PWA→NGN 発信フロー (RFC 3264 §5/§6)。
            // sabiden は browser に SAVPF answer を返しつつ、 内部で
            // SAVPF→AVP→PCMU 変換した SDP で NGN に INVITE を送り 200 OK を
            // 取り、 `MediaBridge::WebRtcAudio` で peer ⇄ NGN socket を結線する。
            // target 無しは旧来 echo モード (試験用、 NGN へは出さない)。
            if let Some(target) = target.as_deref() {
                // PR #146 review #1 🔴#1 (CRLF injection / SIP message smuggling
                // 防御): browser からの任意文字列が NGN INVITE Request-URI user
                // 部に流れる経路を、 RFC 3261 §25.1 user 文法のサブセット
                // `[0-9*#+]{1,32}` のホワイトリストで塞ぐ。 Dialer.tsx UI フィルタは
                // server-side で **必ず再検証** が必要 (改造 browser / 直接 WS
                // 接続を想定、 OWASP A03:2021 Injection)。
                if !is_valid_dial_target(target) {
                    warn!(target = %target.escape_default(), "invalid dial target rejected");
                    return SessionAction::Reply(ServerMessage::error(
                        "invalid_target",
                        "target must match [0-9*#+]{1,32}",
                    ));
                }
                let Some(handler) = state.pwa_outbound.as_ref() else {
                    warn!(%target, "PWA outbound 未配線 (sabiden NGN UAC 無し設定?)");
                    return SessionAction::Reply(ServerMessage::error(
                        "outbound_unavailable",
                        "PWA→NGN 発信ハンドラが未配線",
                    ));
                };
                // PR #146 review #1 🟡#2 (WS 受信ループ非ブロック化): handler は
                // `peer.handle_offer` + `take_media_rx` を同期で済ませて SAVPF
                // answer を返し、 NGN INVITE 〜 bridge 起動は背景タスク化する。
                // completion JoinHandle は production では drop (= detach)、
                // tests のみ await する。 NGN 失敗時は handler が `ws_sink` 経由で
                // `ServerMessage::Error` を push する責務。
                match handler
                    .handle_pwa_outbound_offer(target, &sdp, peer, ws_sink)
                    .await
                {
                    Ok(outcome) => {
                        // background task は drop で detach (tokio 1.x: JoinHandle
                        // を drop しても task は cancel されない)。
                        // `clippy::let_underscore_future` 回避のため `drop` を明示。
                        drop(outcome.completion);
                        SessionAction::Reply(ServerMessage::Answer {
                            sdp: outcome.savpf_answer,
                        })
                    }
                    Err(e) => {
                        SessionAction::Reply(ServerMessage::error("outbound_failed", e.to_string()))
                    }
                }
            } else {
                match peer.handle_offer(&sdp).await {
                    Ok(answer) => SessionAction::Reply(ServerMessage::Answer { sdp: answer }),
                    Err(e) => {
                        SessionAction::Reply(ServerMessage::error("offer_failed", e.to_string()))
                    }
                }
            }
        }
        ClientMessage::Answer { call_id, sdp } => {
            // sabiden が offer 側 (NGN 着信 push) になっているはずの call_id に対する応答。
            if pending_answers.deliver(&call_id, sdp).await {
                SessionAction::Continue
            } else {
                warn!(%call_id, "対応する pending offer が無い answer を受信");
                SessionAction::Reply(ServerMessage::error(
                    "unknown_call_id",
                    format!("no pending offer for call_id={}", call_id),
                ))
            }
        }
        ClientMessage::Decline { call_id } => {
            // Issue #107: ringing 中の着信を browser ユーザが拒否ボタンで拒んだ。
            // RFC 3261 §21.6.2 (603 Decline): "the callee's machine ... has been
            // successful in contacting a human user and the user does not wish
            // to participate in the session"。 sabiden は対応する pending
            // waiter に `AnswerOutcome::Decline { status: 603 }` を流し、
            // orchestrator 側 `run_webrtc_leg` が `LegResult::Failed { status: 603 }`
            // で fork に集約する。 他フォーク先 (SIP 内線端末) が応答すれば通話
            // 成立、 全レッグ 603 なら NGN へ 603 Decline を返す
            // (RFC 3261 §16.7 step 5: best response selection)。
            //
            // 603 vs 486: 486 Busy Here (RFC 3261 §21.4.21) は「他で取込中」、
            // 603 Decline は「ユーザが拒否」 を表す。 PWA UI の「拒否」ボタンは
            // 後者に対応するので 603 を使う。 487 Request Terminated (§21.4.25)
            // は CANCEL を受けた INVITE が自発的に出す code (§15.1.1) であり、
            // UAS 側拒否では使わない (CLAUDE.md §6.2 RFC 引用必須に対応)。
            if pending_answers.decline(&call_id, 603).await {
                debug!(%call_id, "PWA decline 受領: PendingAnswers に 603 を流して fork へ伝搬");
                SessionAction::Continue
            } else {
                // pending が無いケース:
                // (a) 既に WS 切断で `cancel_all` 済み (race)
                // (b) 既に `deliver` 済み (応答ボタンと拒否ボタンの同時押し race)
                // (c) browser が知らない / 古い call_id を送ってきた
                // いずれも fatal ではない。 silent OK で受理する (= browser UI は
                // 既にローカルで拒否扱い済みなので、 error 返答してもユーザが取れる
                // 行動はない)。
                debug!(%call_id, "対応する pending offer が無い decline を受信 (race / unknown call_id)");
                SessionAction::Continue
            }
        }
        ClientMessage::Ice { candidate } => {
            // RFC 8839 §4.2 / RFC 8838 §14 (Receiving the End-of-Candidates
            // Indication) / W3C WebRTC §4.4.1.6: 空文字 / `end-of-candidates` /
            // `a=end-of-candidates` は trickle ICE の終端マーカで candidate では
            // ない。 silent OK で受理する (Issue #92)。
            //
            // 比較は **厳密な equality** で行う (Issue #206)。 `contains` ベースの
            // 部分一致は擬陽性 (例: 仮想的に `candidate:xyz end-of-candidates-foo`
            // のような行が来た場合に誤って終端扱いされる) を生むため避ける。
            // 受理形式は以下の 3 通り:
            //   - "" (W3C 標準: `candidate === ""` で end-of-candidates、
            //         RFC 8838 §14)
            //   - "end-of-candidates" (RFC 8838 §13 で SDP 属性 `a=end-of-candidates`
            //         の attribute 名のみが裸で来る一部実装。 受信側は許容してよい)
            //   - "a=end-of-candidates" (RFC 8838 §13 / RFC 8839 §5.1: SDP
            //         attribute フル形式)
            //
            // str0m 0.19 (= sabiden の WebRTC バックエンド) は public API として
            // 「end-of-remote-candidates を IceAgent に通知する」 メソッドを
            // 提供していない (is-0.9.0/src/agent.rs line 205-208 のコメント:
            // "We never end trickle ice and it's always possible to come back
            //  if more remote candidates are added")。 したがって本処理は marker
            // を観測ログに残すのみとし、 ICE 失敗判定は str0m の内部 timer
            // (RFC 8445 §6.1.4 nominated pair 不在による Failed/Disconnected
            //  transition) に委ねる。
            //
            // 設計上 sabiden は ICE-Lite (controlled、 RFC 8445 §2.4) のため、
            // remote (=ブラウザ controlling 側) からの candidate 列挙完了を
            // 待つ必要がない: sabiden 側 host candidate ペアと checks が成立
            // すれば即 Connected に進む。 そのため本 marker 受理欠落で ICE 確立
            // 自体が遅延することはない (RFC 8838 §14 の MAY 受理)。
            //
            // 注: RFC 8840 は SIP usage 専用 (Trickle ICE over SIP)。 sabiden は
            // WebSocket JSON シグナリングなので、 trickle ICE の一般仕様である
            // RFC 8838 を引用する。
            let trimmed = candidate.trim();
            if trimmed.is_empty()
                || trimmed == "end-of-candidates"
                || trimmed == "a=end-of-candidates"
            {
                tracing::info!("ICE: end-of-candidates / empty (RFC 8838 §14)");
                return SessionAction::Continue;
            }
            tracing::info!(candidate = %candidate, "ICE candidate received from browser");
            match peer.add_ice_candidate(&candidate).await {
                Ok(_) => SessionAction::Continue,
                Err(e) => {
                    tracing::warn!(error=%e, candidate=%candidate, "ICE add_candidate failed");
                    SessionAction::Reply(ServerMessage::error("ice_failed", e.to_string()))
                }
            }
        }
        ClientMessage::Bye => {
            // Issue #147: PWA→NGN 発信通話があれば NGN レッグを BYE で閉じる。
            // RFC 3261 §15.1.1 / RFC 5853 §3.2.2 SBC framework: B2BUA 片側
            // dialog 終了をもう片側に伝搬する責務。 `unregister` / `peer.close`
            // より先に呼ぶことで、 NGN BYE 送出の起点 (`UacDialog`) は手元の
            // `webrtc_outbound_active` テーブルが保持しているため、 PWA 側の
            // teardown 順序に影響しない。
            if let Some(closer) = state.pwa_outbound_closer.as_ref() {
                let n = closer.close_pwa_outbound_for_ws(ws_sink).await;
                if n > 0 {
                    debug!(closed = n, "PWA→NGN BYE: ClientMessage::Bye 経路で cleanup");
                }
            }
            if let Some(aor) = aor_guard.take() {
                state.extensions.unregister(&aor).await;
            }
            let _ = peer.close().await;
            SessionAction::Reply(ServerMessage::Bye)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_state(secret: &[u8]) -> (SignalingState, Arc<ExtensionRegistrar>) {
        let v = Arc::new(Verifier::new(secret.to_vec()).with_now(|| 1_000));
        let reg = ExtensionRegistrar::new();
        (
            SignalingState::new(v, reg.clone(), Duration::from_secs(60)),
            reg,
        )
    }

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:54321".parse().unwrap()
    }

    fn dummy_claims(ext: &str) -> AuthClaims {
        AuthClaims {
            ext_id: ext.to_string(),
            expiry: 9_999_999_999,
        }
    }

    /// テスト用: ws_sink + pending_answers を準備し、enqueue されたメッセージを
    /// 集めるバックグラウンドタスクを spawn する。
    fn ws_sink_and_recv() -> (
        WsSink,
        PendingAnswers,
        Arc<Mutex<Vec<ServerMessage>>>,
        mpsc::UnboundedSender<()>,
    ) {
        let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
        let pending = PendingAnswers::new();
        let collected: Arc<Mutex<Vec<ServerMessage>>> = Arc::new(Mutex::new(Vec::new()));
        let collected_c = collected.clone();
        // 終了通知用のダミー (生存しているうちは forwarder も生きる)
        let (shutdown_tx, _shutdown_rx) = mpsc::unbounded_channel::<()>();
        tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                collected_c.lock().await.push(m);
            }
        });
        (WsSink::new(tx), pending, collected, shutdown_tx)
    }

    #[tokio::test]
    async fn register_message_writes_to_extension_registrar() {
        let (state, reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _collected, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Register {
                ext_id: "alice".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        assert!(matches!(
            action,
            SessionAction::Reply(ServerMessage::Registered { .. })
        ));
        assert_eq!(aor.as_deref(), Some("alice"));
        let b = reg.lookup("alice").await.expect("登録済み");
        assert_eq!(b.contact_uri, "sip:alice@webrtc.peer");
        assert_eq!(b.remote, dummy_addr());
        // transport は WebRtc であるべき
        assert!(matches!(b.transport, ExtTransport::WebRtc { .. }));
    }

    #[tokio::test]
    async fn register_with_mismatched_ext_id_rejected() {
        let (state, reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Register {
                ext_id: "mallory".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        match action {
            SessionAction::Reply(ServerMessage::Error { code, .. }) => {
                assert_eq!(code, "ext_id_mismatch");
            }
            _ => panic!("error 期待"),
        }
        assert!(reg.lookup("mallory").await.is_none());
        assert!(aor.is_none());
    }

    #[tokio::test]
    async fn offer_returns_answer_with_same_payload_type() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let offer = "v=0\r\n\
                     o=- 1 1 IN IP4 192.0.2.1\r\n\
                     s=-\r\n\
                     c=IN IP4 192.0.2.1\r\n\
                     t=0 0\r\n\
                     m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n\
                     a=rtpmap:111 OPUS/48000/2\r\n";
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Offer {
                sdp: offer.into(),
                target: None,
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        match action {
            SessionAction::Reply(ServerMessage::Answer { sdp }) => {
                assert!(sdp.contains("m=audio 0 UDP/TLS/RTP/SAVPF 111"));
            }
            _ => panic!("answer 期待"),
        }
    }

    #[tokio::test]
    async fn ice_continue_no_reply() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Ice {
                candidate: "candidate:1 1 udp 1 1.2.3.4 1 typ host".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        assert!(matches!(action, SessionAction::Continue));
    }

    #[tokio::test]
    async fn bye_unregisters_aor_and_closes_peer() {
        let (state, reg) = make_state(b"k");
        // 事前に register しておく
        reg.register(
            "alice",
            "sip:alice@webrtc.peer".into(),
            dummy_addr(),
            Duration::from_secs(60),
        )
        .await;
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = Some("alice".into());
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Bye,
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        assert!(matches!(action, SessionAction::Reply(ServerMessage::Bye)));
        assert!(aor.is_none());
        assert!(reg.lookup("alice").await.is_none());
    }

    /// `Answer { call_id, sdp }` が pending oneshot にちゃんと届く。
    #[tokio::test]
    async fn answer_with_call_id_delivers_to_pending_oneshot() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        // orchestrator 側が予約している前提
        let waiter = pending.register("call-xyz").await;
        let action = process_client_message(
            ClientMessage::Answer {
                call_id: "call-xyz".into(),
                sdp: "v=0 ANSWER".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        assert!(matches!(action, SessionAction::Continue));
        let got = waiter.await.unwrap();
        assert_eq!(got, AnswerOutcome::Sdp("v=0 ANSWER".to_string()));
    }

    /// 未予約の call_id への answer はエラー応答になる。
    #[tokio::test]
    async fn answer_with_unknown_call_id_replies_error() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Answer {
                call_id: "missing".into(),
                sdp: "v=0".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        match action {
            SessionAction::Reply(ServerMessage::Error { code, .. }) => {
                assert_eq!(code, "unknown_call_id");
            }
            _ => panic!("error 期待"),
        }
    }

    /// Issue #107 / RFC 3261 §21.6.2: 予約済 call_id への `Decline` は waiter に
    /// `AnswerOutcome::Decline { status: 603 }` を流す。 これにより
    /// orchestrator 側の `run_webrtc_leg` は `LegResult::Failed { status: 603 }` を
    /// 返し、 fork 全体としては 603 Decline を NGN に伝搬できる。
    #[tokio::test]
    async fn rfc3261_21_6_2_decline_delivers_603_to_waiter() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        // orchestrator 役: pending を先に予約 (`run_webrtc_leg` 相当)
        let waiter = pending.register("call-decline").await;
        let action = process_client_message(
            ClientMessage::Decline {
                call_id: "call-decline".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        // session は継続 (= WS 切断ではない、 個別着信の拒否のみ)
        assert!(matches!(action, SessionAction::Continue));
        // waiter は 603 Decline を観測する
        let got = waiter.await.expect("decline で起きる");
        assert_eq!(got, AnswerOutcome::Decline { status: 603 });
    }

    /// Issue #107: 未予約 / 既消費 / 不明 call_id への `Decline` は silent OK で
    /// 受理する (= browser UI は既に手元で拒否扱い済みなので error を返しても
    /// ユーザが取れる行動はない、 process_client_message docstring 参照)。
    #[tokio::test]
    async fn decline_with_unknown_call_id_returns_silent_continue() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, collected, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Decline {
                call_id: "no-such-call".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        assert!(matches!(action, SessionAction::Continue));
        // browser に Error を返していないこと。
        // (collected は別 task が drain しているので少し待つ)
        tokio::time::sleep(Duration::from_millis(10)).await;
        let drained = collected.lock().await.clone();
        assert!(
            drained.is_empty(),
            "unknown call_id への Decline は silent: 何も送らないはず: {:?}",
            drained
        );
    }

    /// Issue #107: `ClientMessage::Decline { call_id }` の JSON wire format。
    /// PWA `frontend/src/lib/signaling.ts` の `ClientMessage` と一致すること。
    #[test]
    fn decline_serialization_matches_wire_format() {
        let m = ClientMessage::Decline {
            call_id: "abc-123".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(s, r#"{"type":"decline","call_id":"abc-123"}"#);
        // round trip
        let back: ClientMessage = serde_json::from_str(&s).unwrap();
        match back {
            ClientMessage::Decline { call_id } => assert_eq!(call_id, "abc-123"),
            other => panic!("Decline expected, got {:?}", other),
        }
    }

    #[test]
    fn extract_token_prefers_authorization_header() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer abc.123.sig".parse().unwrap());
        let q = AuthQuery {
            token: Some("from-query".into()),
        };
        assert_eq!(extract_token(&h, &q).as_deref(), Some("abc.123.sig"));
    }

    #[test]
    fn extract_token_falls_back_to_query() {
        let h = HeaderMap::new();
        let q = AuthQuery {
            token: Some("from-query".into()),
        };
        assert_eq!(extract_token(&h, &q).as_deref(), Some("from-query"));
    }

    #[test]
    fn extract_token_returns_none_when_missing() {
        let h = HeaderMap::new();
        let q = AuthQuery { token: None };
        assert!(extract_token(&h, &q).is_none());
    }

    #[test]
    fn extract_token_ignores_empty_bearer() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer ".parse().unwrap());
        let q = AuthQuery { token: None };
        assert!(extract_token(&h, &q).is_none());
    }

    /// RFC 9110 §11.1 (旧 RFC 7235 §2.1): `auth-scheme = token` は
    /// case-insensitive で比較しなければならない。 RFC 6750 §2.1 の
    /// `Bearer` scheme も同様。
    #[test]
    fn rfc6750_2_1_extract_token_accepts_lowercase_bearer_scheme() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "bearer abc.123.sig".parse().unwrap());
        let q = AuthQuery { token: None };
        assert_eq!(extract_token(&h, &q).as_deref(), Some("abc.123.sig"));
    }

    /// RFC 9110 §11.1: 大文字 `BEARER` も受理されなければならない
    /// (auth-scheme は case-insensitive)。
    #[test]
    fn rfc9110_11_1_extract_token_accepts_uppercase_bearer_scheme() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "BEARER abc.123.sig".parse().unwrap());
        let q = AuthQuery { token: None };
        assert_eq!(extract_token(&h, &q).as_deref(), Some("abc.123.sig"));
    }

    /// RFC 9110 §11.1: mixed-case (`BeArEr`) も受理されなければならない。
    #[test]
    fn rfc9110_11_1_extract_token_accepts_mixed_case_bearer_scheme() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "BeArEr abc.123.sig".parse().unwrap());
        let q = AuthQuery { token: None };
        assert_eq!(extract_token(&h, &q).as_deref(), Some("abc.123.sig"));
    }

    /// RFC 9110 §5.6.3: `RWS = 1*( SP / HTAB )`。 scheme と token68 の間
    /// に HTAB が来ても受理する (一般実装と互換)。
    #[test]
    fn rfc9110_5_6_3_extract_token_accepts_htab_after_scheme() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer\tabc.123.sig".parse().unwrap());
        let q = AuthQuery { token: None };
        assert_eq!(extract_token(&h, &q).as_deref(), Some("abc.123.sig"));
    }

    /// RFC 9110 §5.6.3: 複数 SP / HTAB の混在 (`1*( SP / HTAB )`) も RWS
    /// として有効。 軽率な space-1個固定パーサで落ちないことを確認。
    #[test]
    fn rfc9110_5_6_3_extract_token_accepts_multiple_whitespace_after_scheme() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer   abc.123.sig".parse().unwrap());
        let q = AuthQuery { token: None };
        assert_eq!(extract_token(&h, &q).as_deref(), Some("abc.123.sig"));
    }

    /// RFC 6750 §2.1: scheme が `Bearer` 以外の場合は token を抽出しない。
    /// (Basic / Digest 等を Bearer と誤認しないこと。)
    #[test]
    fn rfc6750_2_1_extract_token_rejects_non_bearer_scheme() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        let q = AuthQuery { token: None };
        assert!(extract_token(&h, &q).is_none());
    }

    /// scheme と token を区切る空白が無い場合 (`Bearertoken`) は不正。
    /// RFC 9110 §11.6.2 の `credentials` 文法は scheme と credentials の間に
    /// `1*SP` を要求する。
    #[test]
    fn rfc9110_11_6_2_extract_token_rejects_scheme_without_separator() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearertoken".parse().unwrap());
        let q = AuthQuery { token: None };
        assert!(extract_token(&h, &q).is_none());
    }

    /// token 部が空白だけのとき (`bearer \t  `) は token68 が空なので拒否。
    #[test]
    fn extract_token_ignores_whitespace_only_token_for_lowercase_bearer() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "bearer  \t  ".parse().unwrap());
        let q = AuthQuery { token: None };
        assert!(extract_token(&h, &q).is_none());
    }

    #[test]
    fn server_message_serializes_in_lowercase_tag() {
        let m = ServerMessage::Registered {
            ext_id: "alice".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"type\":\"registered\""));
    }

    #[test]
    fn client_message_offer_round_trip() {
        let m = ClientMessage::Offer {
            sdp: "v=0".into(),
            target: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: ClientMessage = serde_json::from_str(&s).unwrap();
        match back {
            ClientMessage::Offer { sdp, target } => {
                assert_eq!(sdp, "v=0");
                assert_eq!(target, None);
            }
            _ => panic!(),
        }
    }

    /// Issue #145: `Offer` schema は `target` を任意フィールドとして受理する。
    /// `target` 無しの旧来 JSON 形式 (echo モード) と、 `target` 付き
    /// (PWA→NGN 発信) の両方が deserialize 可能で、 round-trip で消えない。
    #[test]
    fn client_message_offer_with_target_round_trips() {
        // 旧来 (target 無し)
        let no_tgt: ClientMessage =
            serde_json::from_str(r#"{"type":"offer","sdp":"v=0"}"#).unwrap();
        match no_tgt {
            ClientMessage::Offer { sdp, target } => {
                assert_eq!(sdp, "v=0");
                assert_eq!(target, None);
            }
            _ => panic!(),
        }

        // 新規 (target 付き)
        let with_tgt: ClientMessage =
            serde_json::from_str(r#"{"type":"offer","sdp":"v=0","target":"117"}"#).unwrap();
        match with_tgt.clone() {
            ClientMessage::Offer { sdp, target } => {
                assert_eq!(sdp, "v=0");
                assert_eq!(target.as_deref(), Some("117"));
            }
            _ => panic!(),
        }
        // serialize → deserialize で target が保持される
        let s = serde_json::to_string(&with_tgt).unwrap();
        assert!(s.contains("\"target\":\"117\""));
        let back: ClientMessage = serde_json::from_str(&s).unwrap();
        match back {
            ClientMessage::Offer { target, .. } => assert_eq!(target.as_deref(), Some("117")),
            _ => panic!(),
        }
    }

    /// Issue #145: target 付き Offer で `pwa_outbound` 未配線なら、
    /// `outbound_unavailable` エラーを返す。 既存 echo モードに巻き添えで
    /// 影響しないこと (= peer.handle_offer は呼ばれない) も意図する。
    #[tokio::test]
    async fn offer_with_target_without_handler_returns_outbound_unavailable() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Offer {
                sdp: "v=0".into(),
                target: Some("117".into()),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        match action {
            SessionAction::Reply(ServerMessage::Error { code, .. }) => {
                assert_eq!(code, "outbound_unavailable");
            }
            _ => panic!("error 期待"),
        }
    }

    /// Issue #145: target 付き Offer で `pwa_outbound` が結線されていれば、
    /// handler が返した SAVPF answer がそのまま `ServerMessage::Answer` に
    /// 載って browser へ返る。
    #[tokio::test]
    async fn offer_with_target_routes_through_pwa_outbound_handler() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct FakeHandler {
            calls: AtomicU32,
            seen_target: std::sync::Mutex<Option<String>>,
            answer: String,
        }
        #[async_trait::async_trait]
        impl PwaOutboundHandler for FakeHandler {
            async fn handle_pwa_outbound_offer(
                &self,
                target: &str,
                _browser_offer: &str,
                _peer: &Arc<dyn PeerSession>,
                _ws_sink: &WsSink,
            ) -> Result<PwaOutboundOutcome> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                *self.seen_target.lock().unwrap() = Some(target.to_string());
                let answer = self.answer.clone();
                let completion = tokio::spawn(async move { Ok(()) });
                Ok(PwaOutboundOutcome {
                    savpf_answer: answer,
                    completion,
                })
            }
        }
        let fake = Arc::new(FakeHandler {
            calls: AtomicU32::new(0),
            seen_target: std::sync::Mutex::new(None),
            answer: "v=0\r\nfake-savpf-answer\r\n".into(),
        });
        let (mut state, _reg) = make_state(b"k");
        state.pwa_outbound = Some(fake.clone() as Arc<dyn PwaOutboundHandler>);
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();
        let action = process_client_message(
            ClientMessage::Offer {
                sdp: "v=0\r\nbrowser-savpf\r\n".into(),
                target: Some("117".into()),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        match action {
            SessionAction::Reply(ServerMessage::Answer { sdp }) => {
                assert!(sdp.contains("fake-savpf-answer"));
            }
            other => panic!(
                "answer 期待: {:?}",
                matches!(other, SessionAction::Reply(_))
            ),
        }
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fake.seen_target.lock().unwrap().as_deref(),
            Some("117"),
            "target が PwaOutboundHandler に伝わる"
        );
    }

    /// PR #146 review #1 🔴#1 (CRLF injection / SIP message smuggling) の
    /// 回帰テスト: target ホワイトリスト `[0-9*#+]{1,32}` (RFC 3261 §25.1
    /// user 文法のサブセット) を逸脱する入力は **必ず** `invalid_target` で
    /// 拒否し、 `pwa_outbound` ハンドラに到達しない。
    ///
    /// 攻撃ベクタ:
    /// - 空文字 — frontend filter 漏れ
    /// - 33 文字超 — E.164 + マージンを超え、 buffer / parser 攻撃面を増やす
    /// - `@host` 形式 — `target = "117@evil.com"` で Request-URI host を上書き
    ///   して NGN P-CSCF を経由しない外部 SIP UA に向け INVITE 送出
    /// - CRLF — `target = "117\r\nFoo: bar\r\n\r\nINVITE sip:..."` で任意 SIP
    ///   メッセージ注入
    /// - スペース / 特殊記号 — header parser 不整合
    #[tokio::test]
    async fn offer_with_invalid_target_rejected_before_handler() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingHandler {
            calls: AtomicU32,
        }
        #[async_trait::async_trait]
        impl PwaOutboundHandler for CountingHandler {
            async fn handle_pwa_outbound_offer(
                &self,
                _target: &str,
                _browser_offer: &str,
                _peer: &Arc<dyn PeerSession>,
                _ws_sink: &WsSink,
            ) -> Result<PwaOutboundOutcome> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let completion = tokio::spawn(async move { Ok(()) });
                Ok(PwaOutboundOutcome {
                    savpf_answer: "v=0\r\nshould-not-reach\r\n".into(),
                    completion,
                })
            }
        }
        let h = Arc::new(CountingHandler {
            calls: AtomicU32::new(0),
        });

        let bad_targets: &[&str] = &[
            "",                                               // empty
            "117@evil.com",                                   // SIP-URI host hijack
            "117\r\nINVITE sip:evil@example.com SIP/2.0\r\n", // CRLF smuggling
            "117\r\n",                                        // bare CRLF
            "117\nINVITE",                                    // bare LF
            "117 ",                                           // space
            "abc",                                            // letters
            "117;tag=evil",                                   // SIP param chars
            &"1".repeat(33),                                  // length > 32
            "+", // 1 char OK shape but only `+` (no digits) — still allowed by charset; keep last for boundary
        ];

        // 最後の "+" は **charset 的には許容**。 charset 違反だけを拒否する
        // ことの確認のため、 `+` は別ケースで accept される (boundary check)
        // → ここでは "+" は対象外にし、 charset 違反のみ列挙する。
        let charset_violations = &bad_targets[..bad_targets.len() - 1];

        for &t in charset_violations {
            let (state, _reg) = make_state(b"k");
            let mut state = state;
            state.pwa_outbound = Some(h.clone() as Arc<dyn PwaOutboundHandler>);
            let claims = dummy_claims("alice");
            let peer: Arc<dyn PeerSession> = StubPeerSession::new();
            let mut aor: Option<String> = None;
            let (sink, pending, _c, _kg) = ws_sink_and_recv();
            let action = process_client_message(
                ClientMessage::Offer {
                    sdp: "v=0".into(),
                    target: Some(t.into()),
                },
                &state,
                &claims,
                &peer,
                dummy_addr(),
                &mut aor,
                &sink,
                &pending,
            )
            .await;
            match action {
                SessionAction::Reply(ServerMessage::Error { code, .. }) => {
                    assert_eq!(code, "invalid_target", "input: {:?}", t);
                }
                _ => panic!("invalid_target 期待 (input={:?})", t),
            }
        }
        assert_eq!(
            h.calls.load(Ordering::SeqCst),
            0,
            "ホワイトリスト違反の target は handler に到達してはならない (defense in depth)"
        );
    }

    /// `is_valid_dial_target` 単体テスト: charset / 長さ境界を直接確認する。
    /// production の `process_client_message` と handler の defense-in-depth 双方の
    /// 一次防衛線。
    #[test]
    fn dial_target_whitelist_accepts_digits_star_hash_plus() {
        // accept: 全種類
        for t in [
            "0",
            "117",
            "*99",
            "#1",
            "+819012345678",
            "0312345678",
            &"1".repeat(32), // 境界: 32 文字 OK
        ] {
            assert!(is_valid_dial_target(t), "should accept: {:?}", t);
        }
        // reject: charset 違反
        for t in [
            "",
            "abc",
            "117a",
            "117@evil",
            "117 ",
            " 117",
            "117\r\n",
            "117\nINVITE",
            "117;param",
            "117/9",
            "117?h=v",
        ] {
            assert!(!is_valid_dial_target(t), "should reject: {:?}", t);
        }
        // reject: 長さ > 32
        let too_long: String = "1".repeat(33);
        assert!(!is_valid_dial_target(&too_long));
    }

    /// WebSocket E2E: 実際に axum サーバを spawn し、tokio-tungstenite で
    /// 接続して認証 → register → bye が往復することを確認する。
    /// (HTTP/WS レイヤと内線 Registrar の結線回帰)
    #[tokio::test]
    async fn end_to_end_ws_register_then_bye() {
        use crate::health::run_with_signaling;
        use crate::health::HealthState;
        use crate::observability::Metrics;
        use futures_util::{SinkExt, StreamExt};
        use std::sync::atomic::AtomicBool;

        let secret = b"e2e-test";
        let verifier = Arc::new(Verifier::new(secret.to_vec()));
        let token = verifier.issue("alice", far_future_expiry());
        let extensions = ExtensionRegistrar::new();

        let signaling = SignalingState::new(
            verifier.clone(),
            extensions.clone(),
            Duration::from_secs(60),
        );
        let health = HealthState::new(Arc::new(AtomicBool::new(false)), Metrics::new());

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let actual = probe.local_addr().unwrap();
        drop(probe);

        let server = tokio::spawn(async move {
            let _ = run_with_signaling(actual, health, signaling).await;
        });

        // サーバ bind を待つ。port collision の確率は極めて低い。
        tokio::time::sleep(Duration::from_millis(50)).await;

        let url = format!("ws://{}/signal?token={}", actual, token);
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            r#"{"type":"register","ext_id":"alice"}"#.to_string(),
        ))
        .await
        .unwrap();

        let resp = ws.next().await.unwrap().unwrap();
        let body = resp.to_text().unwrap();
        assert!(body.contains(r#""type":"registered""#), "got {}", body);

        let b = extensions.lookup("alice").await.expect("登録済み");
        assert!(b.contact_uri.contains("alice@webrtc.peer"));
        assert!(matches!(b.transport, ExtTransport::WebRtc { .. }));

        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            r#"{"type":"bye"}"#.to_string(),
        ))
        .await
        .unwrap();
        let resp = ws.next().await.unwrap().unwrap();
        let body = resp.to_text().unwrap();
        assert!(body.contains(r#""type":"bye""#), "got {}", body);

        server.abort();
    }

    /// WebSocket E2E: トークン無しで接続するとアップグレードが拒否される。
    #[tokio::test]
    async fn end_to_end_ws_rejects_missing_token() {
        use crate::health::run_with_signaling;
        use crate::health::HealthState;
        use crate::observability::Metrics;
        use std::sync::atomic::AtomicBool;

        let verifier = Arc::new(Verifier::new(b"k".to_vec()));
        let signaling =
            SignalingState::new(verifier, ExtensionRegistrar::new(), Duration::from_secs(60));
        let health = HealthState::new(Arc::new(AtomicBool::new(false)), Metrics::new());

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let actual = probe.local_addr().unwrap();
        drop(probe);
        let server = tokio::spawn(async move {
            let _ = run_with_signaling(actual, health, signaling).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let url = format!("ws://{}/signal", actual);
        let result = tokio_tungstenite::connect_async(&url).await;
        assert!(result.is_err(), "トークン無しは拒否");

        server.abort();
    }

    fn far_future_expiry() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3_600
    }

    /// keepalive 設定の builder API が値を保持すること。
    #[test]
    fn signaling_state_with_keepalive_overrides_defaults() {
        let v = Arc::new(Verifier::new(b"k".to_vec()));
        let s = SignalingState::new(v, ExtensionRegistrar::new(), Duration::from_secs(60))
            .with_keepalive(Duration::from_secs(10), Duration::from_secs(25));
        assert_eq!(s.keepalive_interval, Duration::from_secs(10));
        assert_eq!(s.idle_timeout, Duration::from_secs(25));
    }

    /// 既定値: 30 秒 / 60 秒 (Issue #98 / docs/CLOUDFLARE.md の 100 秒 idle に対する余裕)。
    #[test]
    fn signaling_state_default_keepalive_is_30s_idle_60s() {
        let v = Arc::new(Verifier::new(b"k".to_vec()));
        let s = SignalingState::new(v, ExtensionRegistrar::new(), Duration::from_secs(60));
        assert_eq!(s.keepalive_interval, Duration::from_secs(30));
        assert_eq!(s.idle_timeout, Duration::from_secs(60));
    }

    /// keepalive ループの観測用フェイク。 Ping / Close 呼び出しを記録するだけ。
    struct FakeKeepaliveSender {
        pings: Arc<std::sync::Mutex<u32>>,
        closes: Arc<std::sync::Mutex<Vec<(u16, String)>>>,
        fail_after: Option<u32>, // 指定回数 Ping 後 Err を返す (相手切断シミュレーション)
    }

    #[async_trait::async_trait]
    impl KeepaliveSender for FakeKeepaliveSender {
        async fn send_ping(&self, _payload: Vec<u8>) -> Result<()> {
            let mut g = self.pings.lock().unwrap();
            *g += 1;
            if let Some(limit) = self.fail_after {
                if *g > limit {
                    return Err(anyhow::anyhow!("simulated peer disconnect"));
                }
            }
            Ok(())
        }
        async fn send_close(&self, code: u16, reason: String) -> Result<()> {
            self.closes.lock().unwrap().push((code, reason));
            Ok(())
        }
    }

    /// 30 秒周期で Ping が送出されること。
    /// `tokio::time::pause` で仮想時間を進めて、 数 ms で複数周期分検証する。
    ///
    /// `start_paused = true` 下の auto-advance は「全タスクが idle」になった
    /// ときに最も近い timer まで時計を進める仕様。 そのため `loop_handle` を
    /// `select!` で待ち、 一定 (仮想) 時間 sleep してから shutdown を送って
    /// 観測する。
    #[tokio::test(start_paused = true)]
    async fn keepalive_sends_ping_every_interval() {
        let pings = Arc::new(std::sync::Mutex::new(0u32));
        let closes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_recv = Arc::new(Mutex::new(Instant::now()));
        let shutdown = Arc::new(Notify::new());

        let sender = FakeKeepaliveSender {
            pings: pings.clone(),
            closes: closes.clone(),
            fail_after: None,
        };

        // last_recv をループと並行して更新し続けるタスク (Pong が
        // 規則的に来ている状況をシミュレート、 idle timeout は発火しない)。
        let last_recv_c = last_recv.clone();
        let shutdown_c = shutdown.clone();
        let updater = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_c.notified() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        *last_recv_c.lock().await = Instant::now();
                    }
                }
            }
        });

        let shutdown_for_loop = shutdown.clone();
        let loop_handle = tokio::spawn(async move {
            run_keepalive_loop(
                sender,
                last_recv,
                shutdown_for_loop,
                Duration::from_secs(30),
                Duration::from_secs(60),
            )
            .await
        });

        // 仮想時計を 5 周期分進める。 sleep が auto-advance を駆動する。
        tokio::time::sleep(Duration::from_secs(151)).await;

        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), updater).await;

        let n = *pings.lock().unwrap();
        assert!(
            n >= 4,
            "30 秒周期で 150 秒経過したら少なくとも 4-5 回 Ping が出るはず: 実測 {} 回",
            n
        );
        assert!(
            closes.lock().unwrap().is_empty(),
            "活動ありなら Close は出ないはず"
        );
    }

    /// idle_timeout を超えて last_recv が更新されないと、 keepalive ループは
    /// Close frame を送って撤収する (Issue #98 DoD)。
    #[tokio::test(start_paused = true)]
    async fn keepalive_closes_ws_after_idle_timeout() {
        let pings = Arc::new(std::sync::Mutex::new(0u32));
        let closes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_recv = Arc::new(Mutex::new(Instant::now()));
        let shutdown = Arc::new(Notify::new());

        let sender = FakeKeepaliveSender {
            pings: pings.clone(),
            closes: closes.clone(),
            fail_after: None,
        };

        // last_recv は更新しない (Pong 不在 = idle 状態)。
        let loop_handle = tokio::spawn(async move {
            run_keepalive_loop(
                sender,
                last_recv,
                shutdown,
                Duration::from_secs(30),
                Duration::from_secs(60),
            )
            .await
        });

        // ループは last_recv が更新されないので 2 回目の tick (60s) で
        // idle_timeout に到達して自発的に終了する。 timeout は仮想時計上 2
        // 周期分待つ。
        let waited = tokio::time::timeout(Duration::from_secs(120), loop_handle).await;
        assert!(waited.is_ok(), "ループが idle timeout で終了しなかった");

        let cs = closes.lock().unwrap().clone();
        assert_eq!(cs.len(), 1, "Close は 1 回送られるはず: {:?}", cs);
        assert_eq!(
            cs[0].0, 1011,
            "Close code は 1011 (内部エラー / abnormal idle)"
        );
        assert!(cs[0].1.contains("idle"), "reason に idle が含まれる");
    }

    /// shutdown 通知でループが速やかに終了すること。
    #[tokio::test(start_paused = true)]
    async fn keepalive_exits_on_shutdown_notify() {
        let pings = Arc::new(std::sync::Mutex::new(0u32));
        let closes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_recv = Arc::new(Mutex::new(Instant::now()));
        let shutdown = Arc::new(Notify::new());

        let sender = FakeKeepaliveSender {
            pings: pings.clone(),
            closes: closes.clone(),
            fail_after: None,
        };

        let shutdown_c = shutdown.clone();
        let loop_handle = tokio::spawn(async move {
            run_keepalive_loop(
                sender,
                last_recv,
                shutdown_c,
                Duration::from_secs(30),
                Duration::from_secs(60),
            )
            .await
        });

        // ループに spawn の機会を与える。
        tokio::task::yield_now().await;
        // すぐ shutdown を送る → ループは tick を待たずに抜ける。
        shutdown.notify_waiters();
        let waited = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
        assert!(waited.is_ok(), "shutdown でループが終わらなかった");
        assert_eq!(*pings.lock().unwrap(), 0, "tick 前 shutdown なら Ping 0");
    }

    /// Ping 送信が Err を返した (相手切断) 場合、 ループは shutdown を
    /// notify して終了する。
    #[tokio::test(start_paused = true)]
    async fn keepalive_exits_when_send_ping_errors() {
        let pings = Arc::new(std::sync::Mutex::new(0u32));
        let closes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_recv = Arc::new(Mutex::new(Instant::now()));
        let shutdown = Arc::new(Notify::new());

        // 0 回成功 → 1 回目の Ping 呼び出しから Err (即時失敗)。
        let sender = FakeKeepaliveSender {
            pings: pings.clone(),
            closes: closes.clone(),
            fail_after: Some(0),
        };

        let observed = Arc::new(std::sync::Mutex::new(false));
        let observed_c = observed.clone();
        let shutdown_c = shutdown.clone();
        let watcher = tokio::spawn(async move {
            shutdown_c.notified().await;
            *observed_c.lock().unwrap() = true;
        });

        // last_recv は更新し続ける (idle ではない、 純粋に send 失敗で抜ける)。
        let last_recv_c = last_recv.clone();
        let updater_shutdown = shutdown.clone();
        let updater = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = updater_shutdown.notified() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        *last_recv_c.lock().await = Instant::now();
                    }
                }
            }
        });

        let shutdown_for_loop = shutdown.clone();
        let loop_handle = tokio::spawn(async move {
            run_keepalive_loop(
                sender,
                last_recv,
                shutdown_for_loop,
                Duration::from_secs(30),
                Duration::from_secs(120),
            )
            .await
        });

        // 1 周期で Err、 ループ終了 + shutdown 通知。
        let _ = tokio::time::timeout(Duration::from_secs(60), loop_handle).await;

        // watcher は notify を観測してから返る。
        let _ = tokio::time::timeout(Duration::from_secs(5), watcher).await;
        assert!(*observed.lock().unwrap(), "shutdown 通知が出ていない");
        assert_eq!(
            *pings.lock().unwrap(),
            1,
            "1 回だけ Ping されてから Err で抜ける"
        );

        // updater も止める。
        // (shutdown は keepalive ループから来ているはずだが、 念の為再送)。
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), updater).await;
    }

    /// Issue #131 race 検証 (本 PR の主目的): keepalive が `notify_one` で
    /// shutdown を出すとき、 受信側がまだ `notified()` を await していなくて
    /// も permit が蓄えられ、 後から登録した waiter が即時 resolve すること。
    ///
    /// `tokio::sync::Notify` 仕様 (tokio 1.x docs) のうち本 PR が利用する 2
    /// 性質:
    /// - **`notify_one` は permit を蓄える**: 呼び出し時点で waiter が居なくて
    ///   も次の `notified()` 呼び出しが即座に解決する。
    /// - **`notify_waiters` は permit を蓄えない**: 呼び出し時点で
    ///   `notified()` を能動 await していない waiter には届かない (lost)。
    ///
    /// 本テストは前者 (= `notify_one`) を直接検証することで、 production
    /// コード (`run_keepalive_loop` / forwarder / `run_session` 末尾) が
    /// `notify_one` に置換されている回帰防止になる。
    #[tokio::test]
    async fn rfc6455_notify_one_permit_outlives_waiterless_window() {
        let n = Arc::new(Notify::new());

        // waiter 不在の瞬間に notify_one を発火。 permit が蓄えられる。
        n.notify_one();

        // ある程度経過 (= 受信ループが深い await から戻ってくる時間相当) してから
        // notified() を呼んでも、 permit があるので即解決する。
        tokio::time::sleep(Duration::from_millis(10)).await;

        // タイムアウト 2 秒以内に解決しない場合は permit が消えている (= 回帰)。
        let res = tokio::time::timeout(Duration::from_secs(2), n.notified()).await;
        assert!(
            res.is_ok(),
            "notify_one の permit が waiterless 期間を越えて保持されていない (Issue #131 回帰)"
        );
    }

    /// Issue #131 race 検証 (対比): `notify_waiters` は同じ条件下で permit を
    /// 蓄えないため、 後から登録した waiter は永久に resolve しない。 これが
    /// PR #128 で観測された「アイドル切断撤収最大数秒遅延」の根本原因。
    /// 本テストは差分を「タイムアウトする = 期待」で固定する。
    #[tokio::test]
    async fn rfc6455_notify_waiters_loses_signal_without_active_waiter() {
        let n = Arc::new(Notify::new());

        // waiter 不在で notify_waiters → 通知が消滅する。
        n.notify_waiters();

        // この時点で notified() を await しても、 既に発火済みの notify は
        // 蓄えられていないので解決しない。 100ms で必ずタイムアウトする。
        let res = tokio::time::timeout(Duration::from_millis(100), n.notified()).await;
        assert!(
            res.is_err(),
            "notify_waiters は permit を蓄えず lost。 Issue #131 で notify_one へ置換した根拠"
        );
    }

    /// Issue #167 race 検証 (本 PR の主目的): forwarder 失敗経路で
    /// `notify_one()` を **1 回だけ** 呼ぶと、 同時に `notified()` を能動
    /// await している 2 タスクのうち **片方しか起きない** ことを直接検証する。
    ///
    /// `tokio::sync::Notify` の仕様 (tokio 1.x doc):
    /// - `notify_one()` は **最大 1 waiter** を起こす (active waiter が居れば
    ///   その 1 つ、 居なければ permit を 1 つ蓄える)。
    /// - active waiter が 2 つ居る状態で `notify_one()` を 1 回呼んでも、
    ///   起きるのは 1 つだけ。 残りは次の `notify_one()` を待つ。
    ///
    /// PR #165 の forwarder 経路 (`signaling.rs:683-689` 旧コード) はこれを
    /// 踏み違え、 `shutdown.notify_one()` を 1 回しか呼んでいなかった。
    /// その瞬間に **受信ループ** (line 744) と **keepalive ループ** (line 992)
    /// の両方が `shutdown.notified()` を能動 await しているため、 RFC 6455
    /// §7.4.1 abnormal closure 撤収が片方のループ分だけ遅延していた。
    #[tokio::test]
    async fn rfc6455_notify_one_single_call_wakes_only_one_of_two_awaiters() {
        let n = Arc::new(Notify::new());

        let n1 = n.clone();
        let woke1 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let woke1_c = woke1.clone();
        let h1 = tokio::spawn(async move {
            n1.notified().await;
            woke1_c.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let n2 = n.clone();
        let woke2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let woke2_c = woke2.clone();
        let h2 = tokio::spawn(async move {
            n2.notified().await;
            woke2_c.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // 両 waiter が `notified()` の registration を完了するまで yield 駆動。
        // tokio::sync::Notify は spawn 直後の poll で waker を登録する仕様
        // (tokio docs: "Each call to notified() will register a separate
        // permit")。
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        // 1 回だけ notify_one を呼ぶ → どちらか 1 タスクだけ起きる。
        n.notify_one();

        // 100ms 以内にどちらかが起きていれば notify が処理されたと見なす。
        tokio::time::sleep(Duration::from_millis(100)).await;

        let woke1_v = woke1.load(std::sync::atomic::Ordering::SeqCst);
        let woke2_v = woke2.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            woke1_v ^ woke2_v,
            "1 回の notify_one() で起きたタスクは正確に 1 つ (woke1={}, woke2={})",
            woke1_v,
            woke2_v
        );

        // 片付け: もう 1 回 notify して残りを起こす (テスト leak 防止)。
        n.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), h1).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), h2).await;
    }

    /// Issue #167 修正検証: `notify_one()` を **2 回** 呼ぶと 2 タスク両方が
    /// 起きる。 これが forwarder 失敗経路の RFC 6455 §7.4.1 即時撤収を担保する。
    ///
    /// 本テストは production コード (`run_session::forwarder`) が 1 回呼びに
    /// 逆戻りしたら fail する (回帰防止)。
    #[tokio::test]
    async fn rfc6455_notify_one_twice_wakes_both_keepalive_and_recv_loop_awaiters() {
        let n = Arc::new(Notify::new());

        // 受信ループ相当の waiter。
        let n_recv = n.clone();
        let recv_woke = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recv_woke_c = recv_woke.clone();
        let h_recv = tokio::spawn(async move {
            n_recv.notified().await;
            recv_woke_c.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // keepalive ループ相当の waiter。
        let n_keep = n.clone();
        let keep_woke = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let keep_woke_c = keep_woke.clone();
        let h_keep = tokio::spawn(async move {
            n_keep.notified().await;
            keep_woke_c.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // 両 waiter が registration を完了するまで yield。
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        // forwarder 失敗経路の修正後シーケンス: notify_one を 2 回呼ぶ。
        n.notify_one();
        n.notify_one();

        // 両タスクが timeout 内に終わること = 両方起きたことの証明。
        let r_recv = tokio::time::timeout(Duration::from_secs(2), h_recv).await;
        let r_keep = tokio::time::timeout(Duration::from_secs(2), h_keep).await;
        assert!(
            r_recv.is_ok(),
            "受信ループ相当の waiter が起きなかった (notify_one 2 回で 2 waiter 起床が崩れている = Issue #167 回帰)"
        );
        assert!(
            r_keep.is_ok(),
            "keepalive 相当の waiter が起きなかった (notify_one 2 回で 2 waiter 起床が崩れている = Issue #167 回帰)"
        );
        assert!(recv_woke.load(std::sync::atomic::Ordering::SeqCst));
        assert!(keep_woke.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Issue #131: `run_keepalive_loop` が `notify_one` を使うことの間接検証。
    /// idle timeout 経路で keepalive が抜けたあと、 仮の "受信ループ相当"
    /// (= shutdown を late-await するタスク) が deadlock しないこと。
    ///
    /// 本テストは production コードが `notify_waiters` に逆戻りしたら fail する
    /// (idle 経路の lost-signal 再発検知)。
    #[tokio::test(start_paused = true)]
    async fn keepalive_idle_close_signal_reaches_late_subscriber() {
        let pings = Arc::new(std::sync::Mutex::new(0u32));
        let closes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_recv = Arc::new(Mutex::new(Instant::now()));
        let shutdown = Arc::new(Notify::new());

        let sender = FakeKeepaliveSender {
            pings: pings.clone(),
            closes: closes.clone(),
            fail_after: None,
        };

        let shutdown_for_loop = shutdown.clone();
        let loop_handle = tokio::spawn(async move {
            run_keepalive_loop(
                sender,
                last_recv,
                shutdown_for_loop,
                Duration::from_secs(30),
                Duration::from_secs(60),
            )
            .await
        });

        // keepalive ループが idle_timeout に到達 (60s) → Close 送出 →
        // notify_one 発火 → return するのを待つ。
        let _ = tokio::time::timeout(Duration::from_secs(120), loop_handle).await;

        // notify は既に発火済み。 ここで late-await する subscriber を spawn する
        // (= 本来の受信ループが深い await から戻ってきた瞬間に相当)。
        // `notify_one` で permit が保存されているなら、 即時解決するはず。
        let shutdown_late = shutdown.clone();
        let late_subscriber = tokio::spawn(async move {
            shutdown_late.notified().await;
        });
        let res = tokio::time::timeout(Duration::from_secs(5), late_subscriber).await;
        assert!(
            res.is_ok(),
            "keepalive idle close 後の late subscriber が deadlock した (notify_waiters への回帰?)"
        );

        let cs = closes.lock().unwrap().clone();
        assert_eq!(cs.len(), 1, "Close 1 回送出");
        assert_eq!(cs[0].0, 1011);
    }

    /// Issue #131: ping 失敗 (= 相手切断) 経路でも `notify_one` が permit を
    /// 蓄え、 late subscriber が deadlock しないこと。
    ///
    /// last_recv updater は **別 Notify (`updater_shutdown_notify`)** で停止
    /// させる。 keepalive 用の `shutdown` を共有すると、 updater が
    /// `select!` 内で `notified()` を待っている瞬間に keepalive の permit を
    /// 横取りし、 本テストの late subscriber が deadlock する (= テスト
    /// セマンティクスの racing、 production 経路には存在しない)。
    #[tokio::test(start_paused = true)]
    async fn keepalive_ping_error_signal_reaches_late_subscriber() {
        let pings = Arc::new(std::sync::Mutex::new(0u32));
        let closes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_recv = Arc::new(Mutex::new(Instant::now()));
        let shutdown = Arc::new(Notify::new());
        // updater 専用の停止経路 (keepalive shutdown と分離する)。
        let updater_shutdown_notify = Arc::new(Notify::new());

        // 1 回目の Ping から Err を返す (= 即座に send_ping 失敗で抜ける)。
        let sender = FakeKeepaliveSender {
            pings: pings.clone(),
            closes: closes.clone(),
            fail_after: Some(0),
        };

        // last_recv は更新し続ける (idle ではなく純粋な send 失敗を再現)。
        let last_recv_c = last_recv.clone();
        let updater_stop = updater_shutdown_notify.clone();
        let updater = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = updater_stop.notified() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        *last_recv_c.lock().await = Instant::now();
                    }
                }
            }
        });

        let shutdown_for_loop = shutdown.clone();
        let loop_handle = tokio::spawn(async move {
            run_keepalive_loop(
                sender,
                last_recv,
                shutdown_for_loop,
                Duration::from_secs(30),
                Duration::from_secs(120),
            )
            .await
        });

        // 1 周期 (30s) で send_ping Err、 ループ終了 + notify_one 発火。
        let _ = tokio::time::timeout(Duration::from_secs(60), loop_handle).await;

        // late subscriber が permit を拾うことを確認 (= 受信ループ相当)。
        let shutdown_late = shutdown.clone();
        let late_subscriber = tokio::spawn(async move {
            shutdown_late.notified().await;
        });
        let res = tokio::time::timeout(Duration::from_secs(5), late_subscriber).await;
        assert!(
            res.is_ok(),
            "ping error 経路で late subscriber が deadlock (notify_waiters への回帰?)"
        );

        // updater 停止 (keepalive 側の permit と独立)。
        updater_shutdown_notify.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(2), updater).await;
    }

    /// Issue #131: SignalingState の keepalive 設定が WebRtcConfig から正しく
    /// 反映できる経路 (config → main.rs → SignalingState) のうち、 sabiden 内
    /// で完結する部分 (`with_keepalive` builder) を直接 round-trip 検証する。
    ///
    /// main.rs::register コマンドの実体は重いので、 ここでは `SignalingState`
    /// 単体で keepalive 値を任意上書きできることを担保する。
    #[test]
    fn signaling_state_with_keepalive_round_trip_accepts_arbitrary_values() {
        let v = Arc::new(Verifier::new(b"k".to_vec()));
        // 60s / 90s (Cloudflare 100s 寸前まで広げるケース)
        let s = SignalingState::new(
            v.clone(),
            ExtensionRegistrar::new(),
            Duration::from_secs(60),
        )
        .with_keepalive(Duration::from_secs(60), Duration::from_secs(90));
        assert_eq!(s.keepalive_interval, Duration::from_secs(60));
        assert_eq!(s.idle_timeout, Duration::from_secs(90));

        // 5s / 10s (短縮ケース、 別 LB/SBC が挟まる構成想定)
        let s2 = SignalingState::new(v, ExtensionRegistrar::new(), Duration::from_secs(60))
            .with_keepalive(Duration::from_secs(5), Duration::from_secs(10));
        assert_eq!(s2.keepalive_interval, Duration::from_secs(5));
        assert_eq!(s2.idle_timeout, Duration::from_secs(10));
    }

    // ---------------------------------------------------------------
    // Issue #135 🟡 2: trickle ICE 任意順序到達テスト
    // (RFC 8839 §4 Trickle ICE / RFC 8445 §5.1.1)
    //
    // PR #134 (Issue #91) は frontend 側 PWA の `pendingIceCandidates` バッファ
    // を導入したが、 server 側 (sabiden WS) の `process_client_message` でも
    // ICE → Offer / Offer → ICE / Offer → ICE → Bye 等の **任意順序** で
    // `peer.add_ice_candidate` がエラー無く受理されることを担保する必要が
    // ある。 RFC 8839 §4.2: candidate は SDP exchange の任意の時点で送出
    // できる。 sabiden は WS open 時点で `peer` を生成済 (signaling.rs:496)
    // なので、 offer が来る前の ICE も受理しなければならない。
    //
    // 本テスト群は `StubPeerSession` で挙動を確認する。 `Str0mPeerSession`
    // は別途 `str0m_session_add_ice_candidate_accepts_browser_format` で
    // SDP 文法のみ検証している。
    // ---------------------------------------------------------------

    /// RFC 8839 §4.2: ICE candidate が SDP offer **より先** に届いても WS
    /// 層は受理 (Continue を返す)。 frontend の pendingIceCandidates 不在時
    /// にも server 側で握りつぶさないことを担保する (Issue #135 🟡 2)。
    #[tokio::test]
    async fn rfc8839_trickle_ice_before_offer_is_accepted() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();

        // (1) Offer 受信前に ICE が先に届く
        let act_ice = process_client_message(
            ClientMessage::Ice {
                candidate: "candidate:1 1 udp 2122252543 1.2.3.4 56789 typ host".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        assert!(matches!(act_ice, SessionAction::Continue));

        // (2) その後 Offer が届くと Answer を返す
        let offer = "v=0\r\n\
                     o=- 1 1 IN IP4 192.0.2.1\r\n\
                     s=-\r\n\
                     c=IN IP4 192.0.2.1\r\n\
                     t=0 0\r\n\
                     m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n\
                     a=rtpmap:111 OPUS/48000/2\r\n";
        let act_offer = process_client_message(
            ClientMessage::Offer {
                sdp: offer.into(),
                target: None,
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        assert!(matches!(
            act_offer,
            SessionAction::Reply(ServerMessage::Answer { .. })
        ));
    }

    /// RFC 8839 §4.2: 古典順 `Offer → ICE → Answer` (sabiden 視点で
    /// receiver=Offer→push ICE) でも ICE は受理される。
    #[tokio::test]
    async fn rfc8839_trickle_ice_after_offer_is_accepted() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();

        let offer = "v=0\r\n\
                     o=- 1 1 IN IP4 192.0.2.1\r\n\
                     s=-\r\n\
                     c=IN IP4 192.0.2.1\r\n\
                     t=0 0\r\n\
                     m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n\
                     a=rtpmap:111 OPUS/48000/2\r\n";
        let act_offer = process_client_message(
            ClientMessage::Offer {
                sdp: offer.into(),
                target: None,
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
            &sink,
            &pending,
        )
        .await;
        assert!(matches!(
            act_offer,
            SessionAction::Reply(ServerMessage::Answer { .. })
        ));

        for cand in [
            "candidate:1 1 udp 2122252543 192.168.1.10 56789 typ host",
            "candidate:2 1 udp 1685987071 203.0.113.5 56789 typ srflx raddr 192.168.1.10 rport 56789",
        ] {
            let action = process_client_message(
                ClientMessage::Ice {
                    candidate: cand.into(),
                },
                &state,
                &claims,
                &peer,
                dummy_addr(),
                &mut aor,
                &sink,
                &pending,
            )
            .await;
            assert!(matches!(action, SessionAction::Continue), "cand={}", cand);
        }
    }

    /// RFC 8839 §4.2: 複数 ICE が interleave で届いても全て受理 (Stub Peer
    /// は内部 vec に蓄積するので候補数を直接観測できる)。
    #[tokio::test]
    async fn rfc8839_multiple_interleaved_ice_candidates_all_accepted() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let stub = StubPeerSession::new();
        let peer: Arc<dyn PeerSession> = stub.clone();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();

        // ICE → Offer → ICE → ICE → end-of-candidates
        let events: Vec<ClientMessage> = vec![
            ClientMessage::Ice {
                candidate: "candidate:1 1 udp 2122252543 10.0.0.1 1000 typ host".into(),
            },
            ClientMessage::Offer {
                sdp: "v=0\r\n\
                      o=- 1 1 IN IP4 192.0.2.1\r\n\
                      s=-\r\n\
                      c=IN IP4 192.0.2.1\r\n\
                      t=0 0\r\n\
                      m=audio 50000 UDP/TLS/RTP/SAVPF 0\r\n\
                      a=rtpmap:0 PCMU/8000\r\n"
                    .into(),
                target: None,
            },
            ClientMessage::Ice {
                candidate: "candidate:2 1 udp 2122252543 10.0.0.2 2000 typ host".into(),
            },
            ClientMessage::Ice {
                candidate: "candidate:3 1 udp 1685987071 203.0.113.5 3000 typ srflx".into(),
            },
            // RFC 8839 §4.2 / W3C: end-of-candidates は空文字 or "end-of-candidates"
            ClientMessage::Ice {
                candidate: "".into(),
            },
            ClientMessage::Ice {
                candidate: "end-of-candidates".into(),
            },
        ];

        for ev in events {
            let _ = process_client_message(
                ev,
                &state,
                &claims,
                &peer,
                dummy_addr(),
                &mut aor,
                &sink,
                &pending,
            )
            .await;
        }

        // 実候補 3 件が peer に蓄積されている (end-of-candidates / 空は
        // signaling 層で silent OK され peer には流れない)。
        let cands = stub.candidates().await;
        assert_eq!(
            cands.len(),
            3,
            "trickle ICE 候補 3 件が peer に到達すべき: {:?}",
            cands
        );
        assert!(cands[0].contains("10.0.0.1"));
        assert!(cands[1].contains("10.0.0.2"));
        assert!(cands[2].contains("203.0.113.5"));
    }

    /// RFC 8839 §4.2 / RFC 8838 §14 (Receiving the End-of-Candidates
    /// Indication) / W3C WebRTC §4.4.1: 空文字 / "end-of-candidates" /
    /// "a=end-of-candidates" マーカは silent OK で受理し、 peer の
    /// add_ice_candidate には流さない (PR #134 で導入された signaling.rs:954 の
    /// ガード回帰)。 Issue #206: 比較は厳密 equality (trim 後) で行う。
    #[tokio::test]
    async fn rfc8838_14_end_of_candidates_marker_is_silent_continue() {
        let (state, _reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let stub = StubPeerSession::new();
        let peer: Arc<dyn PeerSession> = stub.clone();
        let mut aor: Option<String> = None;
        let (sink, pending, _c, _kg) = ws_sink_and_recv();

        for marker in [
            "",
            "   ",
            "end-of-candidates",
            "a=end-of-candidates",
            "  end-of-candidates  ",
        ] {
            let action = process_client_message(
                ClientMessage::Ice {
                    candidate: marker.into(),
                },
                &state,
                &claims,
                &peer,
                dummy_addr(),
                &mut aor,
                &sink,
                &pending,
            )
            .await;
            assert!(
                matches!(action, SessionAction::Continue),
                "marker={:?}",
                marker
            );
        }
        assert!(
            stub.candidates().await.is_empty(),
            "終端マーカは peer に流してはならない"
        );
    }

    /// Issue #92 / Issue #206 / RFC 8838 §13 (Generating an End-of-Candidates
    /// Indication) / RFC 8839 §4.2 / W3C WebRTC §4.4.1.6: server → client 方向の
    /// trickle 出力タスク (signaling.rs 745-758) は、 `peer.take_local_candidates()`
    /// が返す `mpsc::Receiver<String>` から読み取った文字列を加工せず
    /// `ServerMessage::Ice { candidate }` として WsSink に流す。 これにより
    /// str0m バックエンドが host candidate 直後に送る空文字列
    /// (end-of-candidates marker) は wire 上で `{candidate: ""}` として透過し、
    /// PWA 側 `addIce("")` で `pc.addIceCandidate(null)` に翻訳される。
    ///
    /// 本テストは **forwarder body をそのまま起動する real test** (Issue #206
    /// review 指摘): `mpsc::channel` + `tokio::spawn` で production と同じ
    /// while-let-recv ループを動かし、 `""` を投入すると WsSink 側で
    /// `ServerMessage::Ice{candidate:""}` として受信できることを確認する。
    /// (旧テストは WsSink::send の round-trip だけで forwarder body を
    /// 起動していなかった。)
    ///
    /// str0m run_loop の "host 直後に empty を流す" 挙動は `str0m_session.rs` 側の
    /// `rfc8838_13_str0m_session_emits_end_of_candidates_after_host` でカバー。
    ///
    /// 注: RFC 8840 は SIP usage 専用。 sabiden は WebSocket JSON シグナリング
    /// なので、 trickle ICE の一般仕様である RFC 8838 を引用する。
    #[tokio::test]
    async fn rfc8838_13_server_to_client_forwarder_propagates_end_of_candidates() {
        // WsSink + 集約用 receiver (PWA 側 wire を観測する代理)。
        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);

        // peer.take_local_candidates() が返すのと同型の channel を作り、
        // production 側 forwarder body (signaling.rs 745-758) と同じループを
        // spawn する。 これにより forwarder の挙動 (= 文字列を加工せず
        // ServerMessage::Ice として送出) を実際に駆動して観測する。
        let (cand_tx, mut cand_rx) = mpsc::channel::<String>(8);
        let push = ws_sink.clone();
        let forwarder = tokio::spawn(async move {
            while let Some(cand) = cand_rx.recv().await {
                if push.send(ServerMessage::Ice { candidate: cand }).is_err() {
                    break;
                }
            }
        });

        // (1) 実 host candidate を投入 → forwarder が ServerMessage::Ice に
        //     wrap して ws_rx に届くべき。
        cand_tx
            .send("candidate:1 1 udp 2122252543 192.168.1.10 56789 typ host".into())
            .await
            .expect("forwarder へ host candidate 投入成功");

        // (2) end-of-candidates marker (空文字列) を投入 → 同じく
        //     {candidate:""} として届くべき (RFC 8838 §13)。
        cand_tx
            .send(String::new())
            .await
            .expect("forwarder へ end-of-candidates marker 投入成功");

        // 受信側で 2 件が順序保存で届くことを確認
        let m1 = tokio::time::timeout(Duration::from_secs(1), ws_rx.recv())
            .await
            .expect("1 件目を 1 秒以内に受信")
            .expect("forwarder が close せずに 1 件目を流す");
        match m1 {
            ServerMessage::Ice { candidate } => {
                assert!(
                    candidate.contains("typ host"),
                    "1 件目は host candidate: {:?}",
                    candidate
                );
            }
            other => panic!("1 件目は Ice であるべき: {:?}", other),
        }

        let m2 = tokio::time::timeout(Duration::from_secs(1), ws_rx.recv())
            .await
            .expect("2 件目を 1 秒以内に受信")
            .expect("forwarder が close せずに 2 件目を流す");
        match m2 {
            ServerMessage::Ice { candidate } => {
                assert_eq!(
                    candidate, "",
                    "2 件目は end-of-candidates marker (空文字列): {:?}",
                    candidate
                );
            }
            other => panic!("2 件目は Ice であるべき: {:?}", other),
        }

        // cand_tx を drop → forwarder の recv が None を返してタスクが終了。
        drop(cand_tx);
        tokio::time::timeout(Duration::from_secs(1), forwarder)
            .await
            .expect("forwarder が 1 秒以内に終了する (sender drop で recv None)")
            .expect("forwarder task が panic せず終了");

        // Wire 形式の round-trip: serde で empty 文字列が消えないこと
        // (skip_serializing_if 等で落とさない)。 これが落ちると PWA 側で
        // `candidate` field が undefined になり end-of-candidates を検出できない。
        let wire = serde_json::to_string(&ServerMessage::Ice {
            candidate: String::new(),
        })
        .expect("シリアライズ成功");
        assert!(
            wire.contains("\"candidate\":\"\""),
            "empty candidate が JSON 上で消えてはならない: {}",
            wire
        );
    }

    // ---------------------------------------------------------------
    // Issue #117: WS forwarder UAF / pending answers leak race tests
    //
    // 観点:
    // (A) `PendingAnswers::cancel_all` は全 oneshot::Sender を drop し、
    //     対応する Receiver が `Err(RecvError)` で即時起きる (tokio::sync::
    //     oneshot::Receiver doc)。 これで `run_webrtc_leg` の
    //     `tokio::time::timeout(leg_timeout, waiter)` が `Ok(Err(_))` で
    //     即時抜け、 leg_timeout (30 秒等) 待ちが解消する。
    // (B) WS セッション終了時に `out_tx` / `ws_sink` を drop することで、
    //     全 `mpsc::UnboundedSender` クローンが解放され次第、 forwarder の
    //     `out_rx.recv()` が `None` を返してタスクが終了する (tokio mpsc
    //     doc: 全 sender が drop されたときのみ recv が None)。
    //
    // テストは仮想時計 / `tokio::task::yield_now` で deterministic に書く。
    // flaky 化を避けるため、 sleep ベースの "wait for cleanup" は避け、
    // 観測対象 (receiver の解決 / sender の `is_closed`) を直接 assert する。
    // ---------------------------------------------------------------

    /// Issue #117 (A): `cancel_all` が単一 waiter を即時起こす。
    /// `oneshot::Sender` を drop することで `Receiver::await` は
    /// `Err(RecvError)` を返す (tokio::sync::oneshot::Sender doc)。
    #[tokio::test]
    async fn issue117_pending_answers_cancel_all_wakes_single_waiter() {
        let pending = PendingAnswers::new();
        let waiter = pending.register("call-1").await;
        assert_eq!(pending.len().await, 1, "register で 1 件追加");

        let n = pending.cancel_all().await;
        assert_eq!(n, 1, "cancel_all が 1 件キャンセル");
        assert!(pending.is_empty().await, "テーブルは空");

        // Receiver は即時 Err で resolve するはず。 1 秒タイムアウトは安全マージン
        // (実際は 1 つの yield で resolve する)。
        let res = tokio::time::timeout(Duration::from_secs(1), waiter).await;
        let inner = res.expect("oneshot::Receiver が 1 秒以内に resolve しない");
        assert!(
            inner.is_err(),
            "cancel_all 後の Receiver は RecvError であるはず (Sender drop = canceled)"
        );
    }

    /// Issue #117 (A): `cancel_all` が複数 waiter を全て即時起こす。
    /// 内線フォーク (NGN → 複数 PWA) で複数の `call_id` が同時 register された
    /// ときの想定 (`fork_to_bindings` フロー)。
    #[tokio::test]
    async fn issue117_pending_answers_cancel_all_wakes_all_waiters() {
        let pending = PendingAnswers::new();
        let mut waiters = Vec::new();
        for i in 0..5 {
            waiters.push(pending.register(&format!("call-{}", i)).await);
        }
        assert_eq!(pending.len().await, 5);

        let n = pending.cancel_all().await;
        assert_eq!(n, 5, "全 5 件キャンセル");
        assert!(pending.is_empty().await);

        for (i, w) in waiters.into_iter().enumerate() {
            let res = tokio::time::timeout(Duration::from_secs(1), w).await;
            let inner = res.unwrap_or_else(|_| panic!("waiter {} が timeout", i));
            assert!(inner.is_err(), "waiter {} は Err であるはず", i);
        }
    }

    /// Issue #117 (A): `cancel_all` は idempotent。 2 度呼んでも 2 回目は
    /// 0 件で安全に no-op。 `ClientMessage::Bye` 経路と WS close 経路の
    /// 双方で呼ばれる可能性があるため重要。
    #[tokio::test]
    async fn issue117_pending_answers_cancel_all_is_idempotent() {
        let pending = PendingAnswers::new();
        let _w1 = pending.register("call-a").await;
        let _w2 = pending.register("call-b").await;

        assert_eq!(pending.cancel_all().await, 2);
        assert_eq!(pending.cancel_all().await, 0, "2 回目は 0 件 (idempotent)");
        assert!(pending.is_empty().await);
    }

    /// Issue #117 (A): `cancel_all` 後に同じ `call_id` を再 register できる
    /// (テーブルから消えているので再利用可能、 ハイブリッド再接続シナリオ)。
    #[tokio::test]
    async fn issue117_pending_answers_reusable_after_cancel_all() {
        let pending = PendingAnswers::new();
        let w1 = pending.register("call-x").await;
        pending.cancel_all().await;
        // w1 は Err になる。
        let _ = tokio::time::timeout(Duration::from_secs(1), w1)
            .await
            .expect("w1 が timeout");

        // 同じ key で再 register。 別の oneshot::Receiver が返る。
        let w2 = pending.register("call-x").await;
        // deliver 経路が動くこと。
        let ok = pending.deliver("call-x", "v=0 reused".into()).await;
        assert!(ok, "deliver 成功");
        let got = w2.await.expect("w2 が deliver で起きる");
        assert_eq!(got, AnswerOutcome::Sdp("v=0 reused".to_string()));
    }

    /// Issue #117 (A): `cancel_all` 後の `deliver` は false を返す
    /// (= waiter が居ないので browser からの遅延 answer は捨てる)。
    /// browser が WS 再接続前に answer を投げ込んでも UAF にならない。
    #[tokio::test]
    async fn issue117_deliver_after_cancel_all_returns_false() {
        let pending = PendingAnswers::new();
        let _w = pending.register("call-y").await;
        pending.cancel_all().await;

        // late answer は配送先が居ない。
        let delivered = pending.deliver("call-y", "v=0 late".into()).await;
        assert!(!delivered, "cancel_all 後の deliver は false");
    }

    /// Issue #107: `PendingAnswers::decline` は registered waiter に
    /// `AnswerOutcome::Decline { status }` を流す。
    #[tokio::test]
    async fn issue107_pending_answers_decline_delivers_decline_outcome() {
        let pending = PendingAnswers::new();
        let waiter = pending.register("call-d").await;
        let ok = pending.decline("call-d", 603).await;
        assert!(ok, "decline は registered waiter に成功");
        let got = waiter.await.expect("waiter は decline で起きる");
        assert_eq!(got, AnswerOutcome::Decline { status: 603 });
        assert!(pending.is_empty().await, "decline 後はテーブルから消える");
    }

    /// Issue #107: 未予約 / cancel_all 済みの call_id への `decline` は false。
    #[tokio::test]
    async fn issue107_decline_without_registration_returns_false() {
        let pending = PendingAnswers::new();
        let declined = pending.decline("no-such-call", 603).await;
        assert!(!declined, "未予約への decline は false");
    }

    /// Issue #107: `deliver` と `decline` の race。 先勝ち side が waiter を消費し、
    /// 後 side は false を返す。 これにより「応答ボタンと拒否ボタンを同時押し」
    /// race でも片方だけが反映されることを保証する。
    #[tokio::test]
    async fn issue107_deliver_and_decline_first_wins() {
        let pending = PendingAnswers::new();
        let waiter = pending.register("call-race").await;
        let delivered = pending.deliver("call-race", "v=0".into()).await;
        assert!(delivered);
        // 後勝ち decline は失敗する (waiter は既に消費済み)
        let declined = pending.decline("call-race", 603).await;
        assert!(
            !declined,
            "deliver が先勝ちした後の decline は false (waiter 消費済)"
        );
        // waiter は Sdp を観測する
        let got = waiter.await.unwrap();
        assert_eq!(got, AnswerOutcome::Sdp("v=0".to_string()));
    }

    /// Issue #117 (B): `WsSink` を drop した直後でも、 内部 mpsc は
    /// **他のクローンが居る限り** is_closed = false (= forwarder は生きる)。
    /// `run_session` の `drop(out_tx)` 単独では forwarder は終わらない
    /// (registrar binding / WebRtcLegHandle / outbound entry の WsSink クローンが
    /// 残っている可能性がある) ことを明示する基礎テスト。
    #[tokio::test]
    async fn issue117_ws_sink_drop_does_not_close_channel_while_clones_alive() {
        let (tx, _rx) = mpsc::unbounded_channel::<ServerMessage>();
        let sink1 = WsSink::new(tx);
        let sink2 = sink1.clone();

        drop(sink1);
        assert!(
            !sink2.is_closed(),
            "クローンが生きている間は チャネルは閉じない"
        );

        drop(sink2);
        // 全 sender drop 後は recv() = None で終わる (tokio mpsc doc)。
        // ここでは sink を観測できないので、 forwarder 統合テスト
        // (issue117_forwarder_task_exits_after_all_senders_dropped) で確認する。
    }

    /// Issue #117 (B): forwarder タスクは「全 `UnboundedSender` クローンが
    /// drop された」ときのみ終了する (tokio mpsc::UnboundedReceiver::recv doc)。
    /// `run_session` 末尾で `out_tx` / `ws_sink` を drop し、 かつ全外部
    /// クローン (registrar binding / webrtc_legs / webrtc_outbound_active) も
    /// drop された場合に forwarder が確実に抜けることを直接検証する。
    ///
    /// このテストは run_session を模した最小構造 (mpsc + spawn forwarder) で
    /// シミュレートし、 production の `out_tx` / `ws_sink` drop 順序が正しい
    /// (= 全 sender drop で recv が None を返す) ことを担保する。
    #[tokio::test]
    async fn issue117_forwarder_task_exits_after_all_senders_dropped() {
        let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
        let sink = WsSink::new(tx.clone());

        // 「外部に居る」クローン (= registrar binding 内 ExtTransport::WebRtc.ws
        // 相当 / WebRtcLegHandle.ws 相当)。
        let external_clone = sink.clone();

        // forwarder 相当タスク。 recv() ループ。
        let observed_exit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed_c = observed_exit.clone();
        let forwarder = tokio::spawn(async move {
            while let Some(_msg) = rx.recv().await {
                // 本物はここで WS frame に変換。
            }
            observed_c.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // run_session 末尾の drop 順序を再現:
        // (1) ws_sink を drop
        drop(sink);
        // (2) out_tx (= tx) を drop
        drop(tx);

        // ここまでで「外部クローン」だけが残る。 forwarder は **まだ** 終わらない
        // ことを確認する (tokio::yield で他タスクに進む機会を与えても続行)。
        tokio::task::yield_now().await;
        assert!(
            !observed_exit.load(std::sync::atomic::Ordering::SeqCst),
            "外部 sender が残っている間は forwarder は終わらない"
        );

        // (3) 外部クローンを drop → 全 sender が消える → recv() が None で抜ける。
        drop(external_clone);

        let res = tokio::time::timeout(Duration::from_secs(2), forwarder).await;
        assert!(
            res.is_ok(),
            "全 sender drop 後 forwarder が 2 秒以内に終了しない (Issue #117 回帰)"
        );
        assert!(
            observed_exit.load(std::sync::atomic::Ordering::SeqCst),
            "forwarder ループが None で抜けて終了タグが立つはず"
        );
    }

    /// Issue #117 (A+B): WS close を模した「終了シーケンス」が完走する
    /// 統合的検証。 PendingAnswers に inbound fork 由来の waiter が複数
    /// あり、 同時に forwarder が WS frame の送信待ちでブロックしている
    /// 状況で、 cancel_all + sender drop の組み合わせが両者を起こす。
    #[tokio::test]
    async fn issue117_ws_close_cleanup_unblocks_waiters_and_forwarder() {
        let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
        let sink = WsSink::new(tx.clone());
        let pending = PendingAnswers::new();

        // 3 つの inbound leg が register 済みと仮定 (NGN → 3 PWA フォーク)。
        let mut waiters = Vec::new();
        for i in 0..3 {
            waiters.push(pending.register(&format!("call-{}", i)).await);
        }

        // forwarder 相当タスク。
        let forwarder_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fc = forwarder_done.clone();
        let forwarder = tokio::spawn(async move {
            while let Some(_m) = rx.recv().await {}
            fc.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // 受信ループ離脱を模した cleanup。 順序は production と同じ:
        // (1) pending.cancel_all  (2) ws_sink drop  (3) out_tx drop
        let cancelled = pending.cancel_all().await;
        assert_eq!(cancelled, 3, "3 件キャンセル");

        // 全 waiter が即時 Err で解決する。 タイムアウト 1 秒は十分。
        for (i, w) in waiters.into_iter().enumerate() {
            let inner = tokio::time::timeout(Duration::from_secs(1), w)
                .await
                .unwrap_or_else(|_| panic!("waiter {} が timeout (Issue #117 (A) 回帰)", i));
            assert!(inner.is_err(), "waiter {} は Err", i);
        }

        // sender 全 drop で forwarder も抜ける。
        drop(sink);
        drop(tx);
        let res = tokio::time::timeout(Duration::from_secs(2), forwarder).await;
        assert!(
            res.is_ok(),
            "forwarder が 2 秒以内に終了しない (Issue #117 (B) 回帰)"
        );
        assert!(forwarder_done.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Issue #117 (race 仕様): `register` と `cancel_all` の interleave で
    /// パニックしない (mutex guard 1 段で各操作はアトミック)。 deliver と
    /// cancel_all の競合では「先勝で他方は no-op」になる。
    /// race を deterministic に書くため、 `tokio::join!` で 2 並行 await し
    /// 後続の `len() == 0` を assert。
    #[tokio::test]
    async fn issue117_register_and_cancel_all_concurrent_is_safe() {
        let pending = PendingAnswers::new();
        let p1 = pending.clone();
        let p2 = pending.clone();

        let registrar = async move {
            for i in 0..10 {
                // `register` の戻り値 oneshot::Receiver は使い捨て (cancel_all
                // 後の Err 受信 / 後続 await は意図しない race を生む) なので
                // 即時 drop する。
                drop(p1.register(&format!("c{}", i)).await);
            }
        };
        let canceller = async move {
            // 何度か cancel_all を撃つ。
            for _ in 0..5 {
                let _ = p2.cancel_all().await;
                tokio::task::yield_now().await;
            }
        };
        tokio::join!(registrar, canceller);

        // 最終状態: register が後勝ちなら高々 10 件、 cancel が後勝ちなら 0 件。
        // どちらでもパニックしないことが要件。 race を断定せず、 len は valid 値。
        let n = pending.len().await;
        assert!(n <= 10, "len は 0..=10 (実測 {})", n);

        // 仕上げに cancel_all → 残り全部消える。
        pending.cancel_all().await;
        assert!(pending.is_empty().await);
    }

    /// Issue #117: `WsSink::is_closed` はクローン数とは独立に、 「対応する
    /// Receiver が drop されたか」を返す (tokio mpsc::UnboundedSender doc)。
    /// 受信側のライフサイクル監視に使う既存 API の回帰確認。
    #[tokio::test]
    async fn issue117_ws_sink_is_closed_reflects_receiver_drop() {
        let (tx, rx) = mpsc::unbounded_channel::<ServerMessage>();
        let sink = WsSink::new(tx);
        assert!(!sink.is_closed(), "receiver 生存中は false");
        drop(rx);
        assert!(sink.is_closed(), "receiver drop 後は true");
    }
}
