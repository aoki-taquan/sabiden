//! sabiden を **in-process** に組み立てるテストハーネス。
//!
//! production binary (`sabiden register`) は呼ばず、 NGN inbound 経路の
//! 必須コンポーネントだけを `wire_ngn_inbound` で結線する。
//!
//! 役割:
//! 1. `TransactionLayer` を 1 本立てる (NGN 側 UDP socket)。
//! 2. `ExtensionRegistrar` に内線 UA mock を **手動で登録** する
//!    (REGISTER フローは本シーケンステストの主題ではないので簡略化)。
//! 3. [`crate::leg_inviter::TestLegInviter`] を `LegInviter` として渡す。
//! 4. `wire_ngn_inbound` で `NgnInboundHandler` を spawn し、 NGN socket addr
//!    を返す。 carrier mock はこの addr に INVITE を送る。
//!
//! main.rs と違い WebRTC / 内線 UAS / RTP ブリッジ実体は持たない
//! (SIP のみ精査が本テストの scope。 RTP/PWA は別 E2E が担当)。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use sabiden::call::orchestrator::{wire_ngn_inbound, NgnInboundConfig, NgnInboundHandler};
use sabiden::sip::registrar::ExtensionRegistrar;
use sabiden::sip::transaction::TransactionLayer;

use crate::leg_inviter::TestLegInviter;
use crate::mock_extension_ua::MockExtensionUa;

/// sabiden harness ハンドル。 各テストはここから NGN addr / inviter / handler を取り出す。
pub struct SabidenHarness {
    pub ngn_addr: SocketAddr,
    pub leg_inviter: Arc<TestLegInviter>,
    pub extensions: Arc<ExtensionRegistrar>,
    /// `wire_ngn_inbound` から返る `NgnInboundHandler`。 keep-alive 用に保持。
    _handler: Arc<NgnInboundHandler>,
    /// NGN 側 UDP socket。 keep-alive 用に保持 (drop すると `TransactionLayer` の
    /// recv_loop が `recv_from` で error → 即終了する)。
    _socket: Arc<UdpSocket>,
}

impl SabidenHarness {
    /// 1 件以上の内線 UA mock を登録した状態で sabiden を起動する。
    ///
    /// `extensions_to_register` の各 (aor, mock_ua) について `ExtensionRegistrar`
    /// に SIP transport で binding を作る。 `LegInviter` は target_uri →
    /// 物理 SocketAddr の解決テーブルを持つので、 mock_ua の `contact_uri()` を
    /// そのまま target_uri に使う。
    pub async fn start_with_mock_extensions(extensions_to_register: &[&MockExtensionUa]) -> Self {
        // (1) NGN 側 UDP socket と TransactionLayer。
        let ngn_socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind ngn socket"),
        );
        let ngn_addr = ngn_socket.local_addr().expect("ngn local addr");
        let (layer, inbound_rx) = TransactionLayer::spawn(ngn_socket.clone());

        // (2) ExtensionRegistrar に手動で SIP binding を登録。
        let extensions = ExtensionRegistrar::new();
        let mut targets: HashMap<String, SocketAddr> = HashMap::new();
        for ext in extensions_to_register {
            let contact_uri = ext.contact_uri();
            targets.insert(contact_uri.clone(), ext.addr());
            extensions
                .register(&ext.aor, contact_uri, ext.addr(), Duration::from_secs(300))
                .await;
        }

        // (3) TestLegInviter で SIP fork を駆動する。
        let leg_inviter = TestLegInviter::start(targets).await;

        // (4) NGN 側に返す 200 OK の Contact は eth1 IP を載せるのが production
        // だが、 テストは loopback なので NGN socket の local_addr をそのまま使う
        // (`ngn_local_addr = None` で local_addr() にフォールバック)。
        let cfg = NgnInboundConfig {
            fork_timeout: Duration::from_secs(5),
            realm: "sabiden-test".to_string(),
            bridge_ngn_bind_ip: None,
            bridge_ext_bind_ip: None,
            ngn_local_addr: None,
            webrtc_active_sweep_interval: Duration::from_secs(30),
            // Issue #288: harness は留守録未使用なので None で旧挙動 (失敗 status)。
            voicemail_recorder: None,
        };

        // (5) `wire_ngn_inbound` で NgnInboundHandler を spawn する。
        let handler = wire_ngn_inbound(
            layer,
            ngn_socket.clone(),
            inbound_rx,
            leg_inviter.clone(),
            extensions.clone(),
            cfg,
        );

        Self {
            ngn_addr,
            leg_inviter,
            extensions,
            _handler: handler,
            _socket: ngn_socket,
        }
    }
}
