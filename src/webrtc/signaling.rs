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
}

/// クライアント → サーバ メッセージ。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientMessage {
    Register {
        ext_id: String,
    },
    /// browser 発の offer (将来: WebRTC → NGN 発信用)
    Offer {
        sdp: String,
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
                    shutdown_c.notify_waiters();
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
    shutdown.notify_waiters();

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
///   Close frame (code 1011) を送って `shutdown.notify_waiters()` する。
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
            shutdown.notify_waiters();
            return;
        }

        // Ping 送信。 失敗 (相手切断) なら撤収。
        if sender.send_ping(Vec::new()).await.is_err() {
            debug!("keepalive: WS 送信失敗 (相手切断)、 keepalive タスク終了");
            shutdown.notify_waiters();
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
        ClientMessage::Offer { sdp } => match peer.handle_offer(&sdp).await {
            Ok(answer) => SessionAction::Reply(ServerMessage::Answer { sdp: answer }),
            Err(e) => SessionAction::Reply(ServerMessage::error("offer_failed", e.to_string())),
        },
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
        ClientMessage::Ice { candidate } => match peer.add_ice_candidate(&candidate).await {
            Ok(_) => SessionAction::Continue,
            Err(e) => SessionAction::Reply(ServerMessage::error("ice_failed", e.to_string())),
        },
        ClientMessage::Bye => {
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
            ClientMessage::Offer { sdp: offer.into() },
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
        let m = ClientMessage::Offer { sdp: "v=0".into() };
        let s = serde_json::to_string(&m).unwrap();
        let back: ClientMessage = serde_json::from_str(&s).unwrap();
        match back {
            ClientMessage::Offer { sdp } => assert_eq!(sdp, "v=0"),
            _ => panic!(),
        }
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
}
