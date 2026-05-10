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
//! 発信 (WebRTC → NGN) は本 PR では offer 受信時に SDP answer を返す
//! 動作のみを実装し、実 INVITE 送信は Issue #25 (Opus 並行) と協調しつつ
//! 別 PR で結線する (TODO)。

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

/// 1 つの WebRTC バインディングに紐づく実行時状態。
///
/// `ExtTransport::WebRtc` から到達できる `peer` / `ws` に加えて、NGN 着信
/// 時に sabiden が browser に offer を push したあと、対応する
/// `ClientMessage::Answer` (call_id 付き) を待ち受ける oneshot のテーブル
/// を保持する。シグナリング層と orchestrator の双方からアクセスする。
#[derive(Clone, Default)]
pub struct PendingAnswers {
    inner: Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>,
}

impl PendingAnswers {
    pub fn new() -> Self {
        Self::default()
    }

    /// 指定 `call_id` への answer 受信を予約し、待ち受け側の receiver を返す。
    pub async fn register(&self, call_id: &str) -> oneshot::Receiver<String> {
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
            tx.send(sdp).is_ok()
        } else {
            false
        }
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
pub fn extract_token(headers: &HeaderMap, query: &AuthQuery) -> Option<String> {
    if let Some(h) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(rest) = h.strip_prefix("Bearer ") {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    query.token.as_ref().filter(|s| !s.is_empty()).cloned()
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
                    // Issue #131: `notify_one()` は permit を蓄える (tokio
                    // `Notify` doc) ので、 受信ループが select! の外 (深い
                    // await) にいる瞬間でも次の `notified()` 評価で即解放
                    // される。 `notify_waiters()` は現に awaiting でない
                    // タスクには届かず、 アイドル撤収が最大数秒遅れていた
                    // 原因。
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
    if let Some(closer) = state.pwa_outbound_closer.as_ref() {
        let n = closer.close_pwa_outbound_for_ws(&ws_sink).await;
        if n > 0 {
            info!(
                closed = n,
                "PWA→NGN BYE: WS close 経路で cleanup (Issue #147)"
            );
        }
    }

    // クリーンアップ: AOR 失効 + PeerSession close
    if let Some(aor) = registered_aor.lock().await.take() {
        state.extensions.unregister(&aor).await;
        info!(aor=%aor, "WebRTC AOR 失効");
    }
    let _ = peer.close().await;
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
        ClientMessage::Ice { candidate } => {
            // RFC 8839 §4.2 / W3C WebRTC §4.4.1: 空文字 / `end-of-candidates` は
            // trickle ICE の終端マーカで candidate ではない。 silent OK で受理する。
            if candidate.trim().is_empty() || candidate.contains("end-of-candidates") {
                tracing::info!("ICE: end-of-candidates / empty");
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
        assert_eq!(got, "v=0 ANSWER");
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
}
