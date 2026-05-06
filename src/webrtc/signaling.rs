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
//! { "type": "offer", "sdp": "v=0..." }
//! { "type": "ice", "candidate": "candidate:..." }
//! { "type": "bye" }
//! ```
//!
//! S → C:
//! ```json
//! { "type": "registered", "ext_id": "webrtc-alice" }
//! { "type": "answer", "sdp": "v=0..." }
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

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::auth::{AuthClaims, Verifier};
use super::peer::{PeerSession, StubPeerSession};
use crate::sip::registrar::ExtensionRegistrar;

/// シグナリングサーバの共有状態。
#[derive(Clone)]
pub struct SignalingState {
    pub verifier: Arc<Verifier>,
    pub extensions: Arc<ExtensionRegistrar>,
    /// `register` 受信時に AOR を Registrar に書き込む際の expires。
    pub register_ttl: Duration,
}

impl SignalingState {
    pub fn new(
        verifier: Arc<Verifier>,
        extensions: Arc<ExtensionRegistrar>,
        register_ttl: Duration,
    ) -> Self {
        Self {
            verifier,
            extensions,
            register_ttl,
        }
    }
}

/// クライアント → サーバ メッセージ。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientMessage {
    Register { ext_id: String },
    Offer { sdp: String },
    Answer { sdp: String },
    Ice { candidate: String },
    Bye,
}

/// サーバ → クライアント メッセージ。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerMessage {
    Registered { ext_id: String },
    Answer { sdp: String },
    Ice { candidate: String },
    Error { code: String, message: String },
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
    let (mut sender, mut receiver) = socket.split();
    let peer: Arc<dyn PeerSession> = StubPeerSession::new();

    let registered_aor: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    while let Some(frame) = receiver.next().await {
        let msg = match frame {
            Ok(Message::Text(t)) => t,
            Ok(Message::Close(_)) => {
                debug!("WS close 受信");
                break;
            }
            Ok(Message::Ping(p)) => {
                let _ = sender.send(Message::Pong(p)).await;
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
                let err = ServerMessage::error("bad_json", e.to_string());
                let _ = sender
                    .send(Message::Text(serde_json::to_string(&err).unwrap()))
                    .await;
                continue;
            }
        };

        let mut aor_guard = registered_aor.lock().await;
        let resp =
            process_client_message(parsed, &state, &claims, &peer, remote, &mut aor_guard).await;
        drop(aor_guard);

        match resp {
            SessionAction::Reply(sm) => {
                let payload = serde_json::to_string(&sm).unwrap();
                if sender.send(Message::Text(payload)).await.is_err() {
                    break;
                }
                if matches!(sm, ServerMessage::Bye) {
                    break;
                }
            }
            SessionAction::Continue => {}
            SessionAction::Close => break,
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

/// シグナリングのメッセージ処理本体。テスト用に分離。
///
/// `aor_guard` は WS セッションが現在 Registrar に書いている AOR を
/// `Mutex<Option<String>>` で外側から渡す。`register` で書き込み、
/// `bye` または WS 切断で消える。
pub async fn process_client_message(
    msg: ClientMessage,
    state: &SignalingState,
    claims: &AuthClaims,
    peer: &Arc<dyn PeerSession>,
    remote: SocketAddr,
    aor_guard: &mut Option<String>,
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
            let contact_uri = format!("sip:{}@webrtc.local", ext_id);
            state
                .extensions
                .register(&ext_id, contact_uri, remote, state.register_ttl)
                .await;
            *aor_guard = Some(ext_id.clone());
            info!(aor=%ext_id, "WebRTC 内線登録");
            SessionAction::Reply(ServerMessage::Registered { ext_id })
        }
        ClientMessage::Offer { sdp } => match peer.handle_offer(&sdp).await {
            Ok(answer) => SessionAction::Reply(ServerMessage::Answer { sdp: answer }),
            Err(e) => SessionAction::Reply(ServerMessage::error("offer_failed", e.to_string())),
        },
        ClientMessage::Answer { .. } => {
            // sabiden が offer 側になるケースは Phase 4.5 (発信プッシュ) で対応
            SessionAction::Reply(ServerMessage::error(
                "not_implemented",
                "sabiden-initiated offer は未対応",
            ))
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

    #[tokio::test]
    async fn register_message_writes_to_extension_registrar() {
        let (state, reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let action = process_client_message(
            ClientMessage::Register {
                ext_id: "alice".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
        )
        .await;
        assert!(matches!(
            action,
            SessionAction::Reply(ServerMessage::Registered { .. })
        ));
        assert_eq!(aor.as_deref(), Some("alice"));
        let b = reg.lookup("alice").await.expect("登録済み");
        assert_eq!(b.contact_uri, "sip:alice@webrtc.local");
        assert_eq!(b.remote, dummy_addr());
    }

    #[tokio::test]
    async fn register_with_mismatched_ext_id_rejected() {
        let (state, reg) = make_state(b"k");
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = None;
        let action = process_client_message(
            ClientMessage::Register {
                ext_id: "mallory".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
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
        let action = process_client_message(
            ClientMessage::Offer { sdp: offer.into() },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
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
        let action = process_client_message(
            ClientMessage::Ice {
                candidate: "candidate:1 1 udp 1 1.2.3.4 1 typ host".into(),
            },
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
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
            "sip:alice@webrtc.local".into(),
            dummy_addr(),
            Duration::from_secs(60),
        )
        .await;
        let claims = dummy_claims("alice");
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let mut aor: Option<String> = Some("alice".into());
        let action = process_client_message(
            ClientMessage::Bye,
            &state,
            &claims,
            &peer,
            dummy_addr(),
            &mut aor,
        )
        .await;
        assert!(matches!(action, SessionAction::Reply(ServerMessage::Bye)));
        assert!(aor.is_none());
        assert!(reg.lookup("alice").await.is_none());
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
        assert!(b.contact_uri.contains("alice@webrtc.local"));

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
}
