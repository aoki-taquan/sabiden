//! WebRTC ゲートウェイ (Issue #23, Phase 4)
//!
//! ブラウザ/PWA から sabiden 内線として接続できる WebRTC↔SIP ブリッジ。
//! WebSocket シグナリング (`/signal`) を既存 axum health server と同居
//! させ、認証・登録された WebRTC UA を仮想内線として
//! [`crate::sip::registrar::ExtensionRegistrar`] に書き込む。
//! NGN 着信は通常の `fork_to_extensions` 経由で WebRTC 端末にも配信される。
//!
//! # モジュール構成
//!
//! - [`auth`] HMAC-SHA256 トークン検証
//! - [`peer`] PeerConnection 抽象 + stub
//! - [`signaling`] WebSocket JSON プロトコル + axum ハンドラ
//!
//! # Phase 4 残作業 (本 PR スコープ外)
//!
//! - 実 ICE/DTLS-SRTP 終端 (`webrtc-rs` バックエンド)
//! - Opus ↔ G.711 トランスコード (Issue #25 と並行)
//! - WebRTC → NGN 発信時の INVITE 結線 (Call Manager 連動)
//! - JWT (Cloudflare Zero Trust) 認証

pub mod auth;
pub mod peer;
pub mod signaling;

// 上位層 (main.rs / health) からの利便性のために再エクスポート。
// 全部使い切らない場合があるので unused_imports を抑止 (Phase 4 の途中段階)。
#[allow(unused_imports)]
pub use auth::{AuthClaims, AuthError, Verifier};
#[allow(unused_imports)]
pub use peer::{PeerSession, StubPeerSession};
#[allow(unused_imports)]
pub use signaling::{
    process_client_message, signal_ws_handler, ClientMessage, ServerMessage, SessionAction,
    SignalingState,
};
