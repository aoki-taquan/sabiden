//! Issue #313 / PR #314 review fix: 内線間 direct dial (intercom) の
//! **本物の integration test**。
//!
//! production の [`UasEventHandler`] を組み立て、 [`IntercomService`] を
//! `set_intercom_service` で結線した状態で、 公開 trait
//! [`PwaOutboundHandler::handle_pwa_outbound_offer`] を呼ぶ。 dispatcher が
//! NGN 経路を経由せず内線間 dial に振り分けることを、 実通信フロー
//! (caller の SAVPF answer 受領 → callee WS Offer push → answer 配送 →
//! WebRtcRelayBridge attach → `InternalCallRegistry` 登録) で検証する。
//!
//! # テスト層 (PR #314 review #2 fix で明示化)
//!
//! 本 file の test は 2 層に分かれている:
//!
//! - **trait-API direct** (大半): `PwaOutboundHandler::handle_pwa_outbound_offer`
//!   を直接呼ぶ。 WS 入口 ([`process_client_message`]) の
//!   [`is_valid_dial_target`] (charset `[0-9*#+]{1,32}`、 CRLF injection 防御)
//!   を **bypass** するため、 AOR 文字種に制約が無く `"alice"` / `"bob"` 等の
//!   alphabetic AOR を直接 dispatcher に流せる。 dispatcher 単体の挙動
//!   (admit / SDP / bridge attach / registry insert) を独立に検証するのが目的。
//!
//! - **WS-entry e2e**:
//!   [`ws_entry_numeric_aor_e2e_dispatches_to_intercom_not_ngn`] のみ。 production
//!   入口 ([`process_client_message`]) を実 `pwa_outbound` ハンドラに結線して
//!   ClientMessage::Offer { target: "101" } を流す。 数字 AOR
//!   (`[0-9*#+]{1,32}`、 RFC 3261 §25.1 user 文法のサブセット) のみが WS validator を
//!   通過し dispatcher まで到達することを示す。
//!
//! 本 PR scope (PWA→PWA production 到達経路) は **numeric AOR** のみ対応する
//! (HLD `docs/ARCHITECTURE.md` 「内線間 direct dial」 節)。 alphabetic AOR
//! 対応は follow-up Issue (WS validator 拡張 or `[extensions]` alias map)。
//!
//! # 防御効果
//!
//! - **NGN regression 防止**: テスト中の sabiden NGN UAC は「絶対に応答しない」
//!   `127.0.0.1:0`-bind fake socket に向けて発射する。 dispatcher が正しく
//!   internal 経路に分岐していれば NGN socket には INVITE が 1 通も到達しない。
//!   分岐が壊れて NGN 経路に落ちると、 NGN UAC は応答待ちで timeout → test も
//!   timeout で失敗する。
//!
//! - **WS Offer/Answer の実通信**: callee 側 PWA は registrar に
//!   `ExtTransport::WebRtc { peer, ws, pending }` で登録され、 dispatcher が
//!   sabiden 発 SAVPF Offer を `ServerMessage::Offer { call_id, sdp }` で
//!   callee `ws` に push、 受信側がそれに対する `pending.deliver(call_id, answer_sdp)`
//!   を呼んで answer を返す経路を模擬する。
//!
//! # RFC 引用
//!
//! - RFC 3261 §13.2.1 / RFC 5853 §3.2.2 (SBC framework): B2BUA は dial target
//!   が同一管理ドメイン内なら外部 (NGN) へプロキシしない選択を取れる。
//! - RFC 3261 §25.1 (user 文法): WS validator は `unreserved / escaped /
//!   user-unreserved` のサブセット (`[0-9*#+]`) を許容。
//! - RFC 3264 §6 / RFC 8829: SAVPF offer/answer (browser ↔ sabiden)。
//! - RFC 3551 §4.5.14 PCMU PT 0 / 8kHz: 媒体面 relay の素材。
//! - RFC 8827 §5: caller と callee の DTLS-SRTP context は独立 (sabiden は
//!   decoded MediaFrame だけを relay する)。
//! - RFC 8829 §5.1 (Connection Cleanup): SHOULD send shutdown when tearing down.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use sabiden::call::intercom::{IntercomConfig, IntercomService};
use sabiden::call::manager::CallManager;
use sabiden::call::orchestrator::UasEventHandler;
use sabiden::sip::registrar::{ExtTransport, ExtensionRegistrar};
use sabiden::sip::transaction::TransactionLayer;
use sabiden::sip::uac::{Uac, UacConfig};
use sabiden::webrtc::auth::{AuthClaims, Verifier};
use sabiden::webrtc::peer::{MediaFrame, PeerSession};
use sabiden::webrtc::signaling::{
    process_client_message, ClientMessage, PendingAnswers, PwaOutboundHandler, ServerMessage,
    SessionAction, SignalingState, WsSink,
};

/// Test-only `PeerSession` that records `send_media` frames and returns
/// trivial SDP from `handle_offer` / `create_offer`. `take_media_rx` is
/// backed by a single `mpsc` channel given at construction time so the
/// test driver can inject upstream frames.
struct RecordingPeer {
    upstream_rx: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
    received: Mutex<Vec<MediaFrame>>,
    received_count: AtomicU32,
    /// Issue #313: callee 側だけが create_offer を呼ばれる。 caller 側は
    /// handle_offer だけが呼ばれる。 SDP は実 str0m を介さないので形だけ整える。
    sdp_marker: &'static str,
}

impl RecordingPeer {
    fn new(
        _label: &'static str,
        upstream_rx: mpsc::Receiver<MediaFrame>,
        sdp_marker: &'static str,
    ) -> Self {
        Self {
            upstream_rx: Mutex::new(Some(upstream_rx)),
            received: Mutex::new(Vec::new()),
            received_count: AtomicU32::new(0),
            sdp_marker,
        }
    }
}

#[async_trait::async_trait]
impl PeerSession for RecordingPeer {
    async fn handle_offer(&self, _sdp: &str) -> Result<String> {
        // SDP 完全形 (RFC 4566 §5): v=/o=/s=/t= 必須、 m=audio + c= で media
        // も提供する。 Issue #316 で導入された PWA→SIP UA 経路は
        // `convert_savpf_to_avp` でこの SDP を AVP に変換するため、 t=0 0 と
        // m=/c= が欠けると `t= 行が必須` 等で parse 失敗する。 SAVPF プロファイル
        // を模した最小形 (SDP 内容自体はテストの検証対象ではない: sdp_marker で
        // 経路をトレースする用途)。
        Ok(format!(
            "v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s={}-answer\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=audio 40000 RTP/SAVPF 0\r\n\
a=rtpmap:0 PCMU/8000\r\n",
            self.sdp_marker
        ))
    }
    async fn create_offer(&self) -> Result<String> {
        Ok(format!(
            "v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s={}-offer\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=audio 40000 RTP/SAVPF 0\r\n\
a=rtpmap:0 PCMU/8000\r\n",
            self.sdp_marker
        ))
    }
    async fn accept_answer(&self, _sdp: &str) -> Result<()> {
        Ok(())
    }
    async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
        Ok(())
    }
    async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
        self.upstream_rx.lock().await.take()
    }
    async fn send_media(&self, frame: MediaFrame) -> Result<()> {
        self.received_count.fetch_add(1, Ordering::SeqCst);
        self.received.lock().await.push(frame);
        Ok(())
    }
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// fake NGN socket を 1 個用意し、 sabiden の NGN UAC `server_addr` をその
/// addr に向ける。 テスト中に NGN socket に INVITE が届いたらすぐ検出できるよう、
/// receive task は到達回数を atomic で公開する。
async fn build_fake_ngn() -> (Arc<UdpSocket>, SocketAddr, Arc<AtomicU32>) {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let hit_count = Arc::new(AtomicU32::new(0));
    let hit_clone = hit_count.clone();
    let sock_clone = sock.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, _peer)) = sock_clone.recv_from(&mut buf).await {
            // sabiden が NGN へ何か発射したら hit。 200 OK は返さない
            // (= dispatcher が正しく動けば NGN は本来呼ばれない)。
            if n > 0 {
                hit_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (sock, addr, hit_count)
}

/// sabiden NGN UAC を fake NGN に向ける構成で `UasEventHandler` を起動する。
async fn build_uas_handler(
    fake_ngn_addr: SocketAddr,
    ext_registrar: Arc<ExtensionRegistrar>,
    intercom_enabled: bool,
    intercom_max: usize,
) -> (Arc<UasEventHandler>, Arc<CallManager>) {
    let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
    let ngn_uac = Arc::new(Uac::new(
        UacConfig {
            local_uri: "sip:test-aor@ntt-east.ne.jp".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            local_addr: ngn_client_sock.local_addr().unwrap(),
            user_agent: "sabiden-test/0.1".to_string(),
            auth_username: None,
            auth_password: None,
        },
        ngn_layer,
        fake_ngn_addr,
    ));
    let call_manager = CallManager::new(ext_registrar.clone());
    let h = UasEventHandler::with_call_manager_and_metrics(
        ngn_uac,
        call_manager.clone(),
        None,
        None,
        sabiden::observability::Metrics::new(),
    );
    // (重要) PR #314 review fix: ext_registrar を attach。 旧テストではこれが無く
    // dispatcher 内 `self.ext_registrar.lock().await.clone()` が常に None で
    // dispatcher が dormant になっていた。
    {
        use sabiden::call::manager::UacForker;
        let ext_send_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ext_layer, _ext_rx) = TransactionLayer::spawn(ext_send_sock.clone());
        let ext_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:sabiden@internal".to_string(),
                domain: "internal".to_string(),
                local_addr: ext_send_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ext_layer,
            "127.0.0.1:1".parse().unwrap(),
        ));
        let forker = Arc::new(UacForker {
            uac: ext_uac,
            targets: std::collections::HashMap::new(),
        });
        h.attach_ext_inviter(forker, ext_registrar.clone()).await;
    }
    // intercom service 注入 (main.rs と同じ pattern)。
    let svc = IntercomService::new(IntercomConfig {
        enabled: intercom_enabled,
        max_concurrent_internal_calls: intercom_max,
    });
    h.set_intercom_service(svc).await;
    (h, call_manager)
}

/// 内線 PWA callee を `ExtTransport::WebRtc { peer, ws, pending }` で
/// registrar に登録する helper。 callee の WS 受信側 (= sabiden が push する
/// `ServerMessage::Offer` を受け取る) は test driver 側で観測する。
async fn register_pwa_callee(
    registrar: &ExtensionRegistrar,
    aor: &str,
    callee_peer: Arc<dyn PeerSession>,
) -> (
    mpsc::UnboundedReceiver<ServerMessage>,
    PendingAnswers,
    WsSink,
) {
    let (callee_ws_tx, callee_ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let callee_ws_sink = WsSink::new(callee_ws_tx);
    let callee_pending = PendingAnswers::new();
    registrar
        .register_with_transport(
            aor,
            format!("sip:{}@webrtc.peer", aor),
            "127.0.0.1:5060".parse().unwrap(),
            Duration::from_secs(300),
            ExtTransport::WebRtc {
                peer: callee_peer,
                ws: callee_ws_sink.clone(),
                pending: callee_pending.clone(),
            },
        )
        .await;
    (callee_ws_rx, callee_pending, callee_ws_sink)
}

/// DoD: PWA→PWA 内線通話で、 dispatcher 経由で
/// 1. caller に SAVPF answer が返る
/// 2. callee の WS に `ServerMessage::Offer { call_id, sdp }` が届く
/// 3. callee が `pending.deliver(call_id, answer_sdp)` で応答すると
///    `InternalCallRegistry` にエントリが入る
/// 4. NGN socket には何も飛ばない (band-aid 防止の決定的証拠)
/// 5. caller→callee の `MediaFrame` が `WebRtcRelayBridge` 経由で届く
///
/// テスト層: **trait-API direct** (`handle_pwa_outbound_offer` を直接呼ぶ)。 WS
/// 入口の `is_valid_dial_target` (charset `[0-9*#+]`) を bypass するため、
/// alphabetic AOR (`"bob"`) を dispatcher に直接流す。 dispatcher の挙動を
/// AOR 文字種制約と独立に検証することが目的。
/// WS 入口を含む production 到達経路は
/// [`ws_entry_numeric_aor_e2e_dispatches_to_intercom_not_ngn`] (numeric AOR
/// `"101"`) で検証する。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc5853_pwa_to_pwa_dispatcher_e2e_no_ngn_traffic_and_bridge_forwards_media() {
    // (a) fake NGN socket (応答しない、 hit count を監視)
    let (_ngn_sock, fake_ngn_addr, ngn_hit_count) = build_fake_ngn().await;

    // (b) registrar に callee PWA を WebRtc transport で登録
    let registrar = ExtensionRegistrar::new();
    let (callee_up_tx, callee_up_rx) = mpsc::channel::<MediaFrame>(8);
    let callee_peer_inner = Arc::new(RecordingPeer::new("callee", callee_up_rx, "callee"));
    let callee_peer: Arc<dyn PeerSession> = callee_peer_inner.clone();
    let (mut callee_ws_rx, callee_pending, _callee_ws_sink) =
        register_pwa_callee(&registrar, "bob", callee_peer.clone()).await;

    // (c) UasEventHandler を組み立て (IntercomService 注入済)
    let (uas_handler, call_manager) =
        build_uas_handler(fake_ngn_addr, registrar.clone(), true, 4).await;

    // (d) caller PWA peer (PR の dispatch_pwa_internal_call は handle_offer を
    //     呼んで answer を取得し、 take_media_rx で MediaFrame source を吸う)
    let (caller_up_tx, caller_up_rx) = mpsc::channel::<MediaFrame>(8);
    let caller_peer_inner = Arc::new(RecordingPeer::new("caller", caller_up_rx, "caller"));
    let caller_peer: Arc<dyn PeerSession> = caller_peer_inner.clone();

    // caller 側 WS sink (sabiden が caller に push する Error 等を観測)
    let (caller_ws_tx, mut caller_ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let caller_ws_sink = WsSink::new(caller_ws_tx);

    // (e) PwaOutboundHandler trait で dispatcher を駆動
    //     target = "bob" → ext_registrar に bob は登録済 → classify_dial_target
    //     が Internal { aor: "bob", binding: WebRtc{..} } を返す。
    let handler_trait: Arc<dyn PwaOutboundHandler> = uas_handler.clone();
    let outcome = handler_trait
        .handle_pwa_outbound_offer(
            "bob",
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=caller-offer\r\n",
            &caller_peer,
            &caller_ws_sink,
        )
        .await
        .expect("dispatcher returned Err");

    // (f) caller には SAVPF answer (RecordingPeer の handle_offer 戻り値) が即時に返る
    //     RFC 3264 §6 / RFC 8829: caller は SAVPF answer を即時受領。
    assert!(
        outcome.savpf_answer.contains("caller-answer"),
        "caller SAVPF answer が dispatcher から返らない: {}",
        outcome.savpf_answer
    );

    // (g) callee WS に sabiden 発 SAVPF Offer が push される
    //     RFC 8829 §5.2: sabiden は callee に対する offerer。
    let pushed = timeout(Duration::from_secs(3), callee_ws_rx.recv())
        .await
        .expect("callee WS に Offer が push されない (dispatcher が callee WS を呼んでいない疑い)")
        .expect("callee WS rx closed prematurely");
    let callee_call_id = match pushed {
        ServerMessage::Offer { call_id, sdp } => {
            assert!(
                sdp.contains("callee-offer"),
                "callee に push された SDP が `callee_peer.create_offer()` の戻り値でない: {}",
                sdp
            );
            call_id
        }
        other => panic!(
            "callee WS で受け取った最初の ServerMessage が Offer ではない: {:?}",
            other
        ),
    };

    // (h) callee が answer を返す (= 通常の PWA `ClientMessage::Answer` が
    //     `pending.deliver` で oneshot に流れるのを再現)
    let delivered = callee_pending
        .deliver(
            &callee_call_id,
            "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=callee-answered\r\n".to_string(),
        )
        .await;
    assert!(
        delivered,
        "callee の pending.deliver が waiter を見つけられなかった (race)"
    );

    // (i) background completion を待つ (bridge attach + registry insert)
    outcome
        .completion
        .await
        .expect("completion JoinHandle paniced")
        .expect("background completion returned Err (orchestration が失敗)");

    // (j) NGN socket には何も到達していないこと
    //     PR #314 review #2/#3 直接の防御: dispatcher が壊れて NGN proxy 経路に
    //     落ちると、 ngn_uac.invite が fake_ngn に発射 → hit_count が増える。
    assert_eq!(
        ngn_hit_count.load(Ordering::SeqCst),
        0,
        "dispatcher 失敗の決定的証拠: 内線 AOR dial だったのに NGN socket に \
         {} 通の SIP message が飛んだ (NGN regression)",
        ngn_hit_count.load(Ordering::SeqCst)
    );

    // (k) caller→callee MediaFrame relay 確認 (WebRtcRelayBridge attach 確認)
    //     PCMU PT 0 / 160 byte / 20ms (RFC 3551 §4.5.14)。
    use std::time::Instant;
    caller_up_tx
        .send(MediaFrame {
            pt: 0,
            rtp_time: 160,
            payload: vec![0xAA; 160],
            network_time: Instant::now(),
        })
        .await
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    while callee_peer_inner.received_count.load(Ordering::SeqCst) == 0 {
        if Instant::now() > deadline {
            panic!(
                "caller→callee MediaFrame が WebRtcRelayBridge を経由して callee に届かない \
                 (bridge attach failed?)"
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got = callee_peer_inner.received.lock().await;
    assert_eq!(got[0].payload, vec![0xAA; 160]);
    drop(got);

    // (l) caller WS には Error が一切流れていない (PWA→PWA 経路が成功した証拠)
    let no_error = timeout(Duration::from_millis(200), caller_ws_rx.recv()).await;
    if let Ok(Some(ServerMessage::Error { code, message })) = no_error {
        panic!(
            "PWA→PWA 内線 dispatch が成功したはずなのに caller WS に Error が流れた: code={} msg={}",
            code, message
        );
    }

    // (m) IntercomService registry に entry が 1 件入っている
    //     intercom_service Arc を再取得するため UasEventHandler の getter は無い。
    //     代わりに call_manager 側の `len()` (= bridge 件数) を見る。
    assert_eq!(
        call_manager.len().await,
        1,
        "CallManager に bridge が 1 件 attach されているべき (intercom relay bridge)"
    );

    // 後始末
    let _ = caller_up_tx;
    let _ = callee_up_tx;
}

/// Issue #316 DoD: PWA → SIP UA 内線通話の **本物の e2e integration test**。
///
/// dispatcher が PWA caller の SAVPF leg と内線 SIP UA leg を WebRtcAudioBridge
/// で結合し、 NGN を介さず双方向 PCMU 通信を成立させる full multi-leg orchestration
/// を検証する。 fake SIP UA は `UdpSocket` 直叩きで実装 (CLAUDE.md §6.3 / PR #176:
/// production-side test hook 禁止)、 INVITE を受信して 200 OK + SDP を返し、
/// その後 PCMU RTP を sabiden の bridge 経由で送受信できることを確認する。
///
/// # 検証項目
///
/// 1. caller (PWA) には SAVPF answer (= `caller-answer`) が同期で返る
/// 2. fake SIP UA に INVITE が届く (= dispatcher が NGN ではなく SIP UA leg に分岐)
/// 3. fake SIP UA からの 200 OK (PCMU SDP) を sabiden が受領
/// 4. NGN socket に hit が 1 件も無い (band-aid 防止)
/// 5. PWA caller → SIP UA 方向の MediaFrame が PCMU RTP として SIP UA に届く
/// 6. SIP UA → PWA caller 方向の RTP が PCMU MediaFrame として caller peer に届く
/// 7. `InternalCallRegistry` (intercom service) に entry が 1 件入る
///
/// # RFC 引用
///
/// - RFC 3261 §17.1 / §13: client transaction → 200 OK → dialog 確立。 ACK は
///   `Uac::invite_to` 内で送出。
/// - RFC 3551 §4.5.14 / PT 0: PCMU 8 kHz / 160 sample = 20 ms。
/// - RFC 8829 §5.1: caller cleanup; Err path で `caller_peer.close()` 必須。
/// - RFC 5853 §3.2.2: B2BUA で両 leg を anchoring。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue316_pwa_to_sip_ua_full_multi_leg_e2e_bidirectional_pcmu_no_ngn_traffic() {
    use sabiden::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
    use sabiden::sip::message::{parse_message, SipHeaders, SipMessage};

    // (a) fake NGN (応答しない、 hit count を監視)
    let (_ngn_sock, fake_ngn_addr, ngn_hit_count) = build_fake_ngn().await;

    // (b) fake SIP UA: SIP signaling socket と RTP socket を別 port で bind する。
    //     SIP signaling は INVITE を受け取り 200 OK を返す (PCMU SDP 付き)。
    //     RTP は別 port で待ち受け、 sabiden が bridge 経由で送ってくる PCMU を観測。
    let fake_ua_sip_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fake_ua_sip_addr = fake_ua_sip_sock.local_addr().unwrap();
    let fake_ua_rtp_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let fake_ua_rtp_addr = fake_ua_rtp_sock.local_addr().unwrap();

    let invite_received = Arc::new(AtomicU32::new(0));
    let invite_received_clone = invite_received.clone();
    let fake_ua_sip_clone = fake_ua_sip_sock.clone();
    let fake_ua_rtp_addr_for_resp = fake_ua_rtp_addr;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match fake_ua_sip_clone.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let msg = match parse_message(&buf[..n]) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let req = match msg {
                SipMessage::Request(r) => r,
                SipMessage::Response(_) => continue,
            };
            // INVITE / ACK / BYE 等の振分。 本テストでは INVITE に 200 OK を
            // 返すだけで他は no-op (ACK 受信は parse して数えるだけ)。
            let method_str = req.method.as_str();
            if method_str != "INVITE" {
                continue;
            }
            invite_received_clone.fetch_add(1, Ordering::SeqCst);

            // 200 OK 応答を組み立てる (RFC 3261 §8.2.6.2)。
            //   - Via / From / To / Call-ID / CSeq は INVITE から echo
            //   - To に tag を付加 (RFC 3261 §12.1.1)
            //   - Contact は fake UA SIP addr
            //   - SDP body: PCMU only AVP (RTP は fake_ua_rtp_sock の port)
            let mut headers = SipHeaders::new();
            if let Some(v) = req.headers.get("via") {
                headers.set("Via", v);
            }
            if let Some(f) = req.headers.get("from") {
                headers.set("From", f);
            }
            // To に tag を付加
            let to_with_tag = match req.headers.get("to") {
                Some(t) if !t.contains(";tag=") => format!("{};tag=fakeua-tag-1", t),
                Some(t) => t.to_string(),
                None => continue,
            };
            headers.set("To", &to_with_tag);
            if let Some(c) = req.headers.get("call-id") {
                headers.set("Call-ID", c);
            }
            if let Some(cs) = req.headers.get("cseq") {
                headers.set("CSeq", cs);
            }
            headers.set("Contact", format!("<sip:fakeua@{}>", fake_ua_sip_addr));
            let sdp = format!(
                "v=0\r\n\
o=- 1 1 IN IP4 {ip}\r\n\
s=fake-ua\r\n\
c=IN IP4 {ip}\r\n\
t=0 0\r\n\
m=audio {port} RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=ptime:20\r\n",
                ip = fake_ua_rtp_addr_for_resp.ip(),
                port = fake_ua_rtp_addr_for_resp.port(),
            );
            headers.set("Content-Type", "application/sdp");
            let resp = sabiden::sip::message::SipResponse {
                status_code: 200,
                reason: "OK".to_string(),
                headers,
                body: sdp.into_bytes(),
            };
            let bytes = resp.to_bytes();
            let _ = fake_ua_sip_clone.send_to(&bytes, peer).await;
        }
    });

    // (c) registrar に SIP UA callee を登録 (binding.remote = fake UA SIP addr)
    let registrar = ExtensionRegistrar::new();
    registrar
        .register(
            "linphone-bob",
            format!("sip:linphone-bob@{}", fake_ua_sip_addr),
            fake_ua_sip_addr,
            Duration::from_secs(300),
        )
        .await;

    // (d) UasEventHandler を組み立て (ext_inviter / intercom service 注入済)
    let (uas_handler, call_manager) =
        build_uas_handler(fake_ngn_addr, registrar.clone(), true, 4).await;

    // (e) caller PWA peer (RecordingPeer は SAVPF SDP を返す)
    let (caller_up_tx, caller_up_rx) = mpsc::channel::<MediaFrame>(8);
    let caller_peer_inner = Arc::new(RecordingPeer::new("caller", caller_up_rx, "caller"));
    let caller_peer: Arc<dyn PeerSession> = caller_peer_inner.clone();
    let (caller_ws_tx, _caller_ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let caller_ws_sink = WsSink::new(caller_ws_tx);

    // (f) dispatcher 駆動
    let handler_trait: Arc<dyn PwaOutboundHandler> = uas_handler.clone();
    let outcome = handler_trait
        .handle_pwa_outbound_offer(
            "linphone-bob",
            // 完全形 SDP (RFC 4566): v=/o=/s=/t=/c=/m= 揃える
            "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=caller-offer\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=audio 30000 RTP/SAVPF 0\r\n\
a=rtpmap:0 PCMU/8000\r\n",
            &caller_peer,
            &caller_ws_sink,
        )
        .await
        .expect("dispatcher 同期 path で Err");

    // (g) caller には SAVPF answer が即時に返る
    assert!(
        outcome.savpf_answer.contains("caller-answer"),
        "caller SAVPF answer が dispatcher から返らない: {}",
        outcome.savpf_answer
    );

    // (h) background completion を待つ (INVITE → 200 OK → bridge attach → registry insert)
    outcome
        .completion
        .await
        .expect("completion JoinHandle paniced")
        .expect("background completion returned Err (PWA→SIP UA orchestration が失敗)");

    // (i) NGN socket には何も到達していない (= dispatcher が NGN proxy 経路に
    //     落ちていない、 band-aid 防止の決定的証拠)
    assert_eq!(
        ngn_hit_count.load(Ordering::SeqCst),
        0,
        "PWA→SIP UA dispatch だったのに NGN socket に {} 通の SIP message が漏れた \
         (CLAUDE.md §6.1 band-aid 防止 / NGN regression 防御)",
        ngn_hit_count.load(Ordering::SeqCst)
    );

    // (j) fake SIP UA は少なくとも 1 通の INVITE を受領している (= dispatcher が
    //     ext_inviter.invite_intercom 経由で SIP UA leg を確実に呼んだ証拠)
    assert!(
        invite_received.load(Ordering::SeqCst) >= 1,
        "fake SIP UA に INVITE が届かない (dispatcher が SIP UA leg を呼ばなかった可能性)"
    );

    // (k) CallManager に bridge が 1 件 attach 済 (= WebRtcAudioBridge attach 成功)
    assert_eq!(
        call_manager.len().await,
        1,
        "PWA→SIP UA full orchestration で CallManager に bridge が 1 件あるべき"
    );

    // (l) caller → SIP UA 方向の MediaFrame が WebRtcAudioBridge 経由で PCMU RTP
    //     として fake SIP UA RTP socket に届くこと (RFC 3551 PT 0)。
    use std::time::Instant;
    let caller_payload = vec![0xAB; 160];
    caller_up_tx
        .send(MediaFrame {
            pt: 0,
            rtp_time: 160,
            payload: caller_payload.clone(),
            network_time: Instant::now(),
        })
        .await
        .unwrap();
    let mut rtp_buf = vec![0u8; 1500];
    let (n, _src) = timeout(
        Duration::from_secs(3),
        fake_ua_rtp_sock.recv_from(&mut rtp_buf),
    )
    .await
    .expect("caller→SIP UA RTP が fake UA に届かない (WebRtcAudioBridge attach 失敗?)")
    .unwrap();
    let recv_rtp = RtpPacket::from_bytes(&rtp_buf[..n]).expect("RTP parse");
    assert_eq!(
        recv_rtp.payload_type, PAYLOAD_TYPE_ULAW,
        "caller→SIP UA は PCMU PT 0 で届くべき (RFC 3551)"
    );
    assert_eq!(
        recv_rtp.payload, caller_payload,
        "PCMU payload が変質している (transcode bug)"
    );

    // (m) SIP UA → caller 方向の RTP が PCMU MediaFrame として caller peer に届く
    //     (`WebRtcAudioBridge::ngn_to_peer` 方向の検証)。 fake UA は sabiden 内線
    //     RTP socket に向けて送る。 sabiden 内線 socket の addr は `recv_rtp` の
    //     送信元 (RTP packet 受信時の `_src`) と一致する。
    let sabi_rtp_addr = _src;
    let pkt = RtpPacket {
        payload_type: PAYLOAD_TYPE_ULAW,
        marker: false,
        sequence: 100,
        timestamp: 0,
        ssrc: 0xBEEF,
        payload: vec![0xCD; 160],
    }
    .to_bytes();
    fake_ua_rtp_sock.send_to(&pkt, sabi_rtp_addr).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while caller_peer_inner.received_count.load(Ordering::SeqCst) == 0 {
        if Instant::now() > deadline {
            panic!("SIP UA→caller RTP が WebRtcAudioBridge 経由で caller peer に届かない");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got = caller_peer_inner.received.lock().await;
    assert_eq!(got[0].pt, 0, "caller peer に届く MediaFrame は PCMU PT 0");
    assert_eq!(got[0].payload, vec![0xCD; 160], "PCMU payload 透過");
    drop(got);

    // 後始末
    let _ = caller_up_tx;
}

/// DoD: 同時通話上限超過 (`max_concurrent_internal_calls = 1`) のとき、 2 件目
/// の PWA→内線 dial は `intercom_busy` で reject される (RFC 3261 §21.4.20)。
///
/// テスト層: **trait-API direct** (WS validator bypass、 alphabetic AOR を使う)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3261_21_4_20_intercom_capacity_overflow_rejects_with_intercom_busy_error() {
    let (_ngn_sock, fake_ngn_addr, ngn_hit_count) = build_fake_ngn().await;

    let registrar = ExtensionRegistrar::new();
    let (_up_tx_a, up_rx_a) = mpsc::channel::<MediaFrame>(8);
    let callee_a: Arc<dyn PeerSession> = Arc::new(RecordingPeer::new("a", up_rx_a, "a"));
    let (mut ws_rx_a, pending_a, _ws_a) =
        register_pwa_callee(&registrar, "a", callee_a.clone()).await;

    let (_up_tx_b, up_rx_b) = mpsc::channel::<MediaFrame>(8);
    let callee_b: Arc<dyn PeerSession> = Arc::new(RecordingPeer::new("b", up_rx_b, "b"));
    let (_ws_rx_b, _pending_b, _ws_b) =
        register_pwa_callee(&registrar, "b", callee_b.clone()).await;

    // max_concurrent_internal_calls = 1
    let (uas_handler, _mgr) = build_uas_handler(fake_ngn_addr, registrar.clone(), true, 1).await;
    let handler_trait: Arc<dyn PwaOutboundHandler> = uas_handler.clone();

    // 1 件目: caller → a を確立 (admit OK)
    let (_c1_up_tx, c1_up_rx) = mpsc::channel::<MediaFrame>(8);
    let caller1: Arc<dyn PeerSession> = Arc::new(RecordingPeer::new("c1", c1_up_rx, "c1"));
    let (ws_tx_1, _ws_rx_1) = mpsc::unbounded_channel::<ServerMessage>();
    let outcome1 = handler_trait
        .handle_pwa_outbound_offer(
            "a",
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=caller-offer\r\n",
            &caller1,
            &WsSink::new(ws_tx_1),
        )
        .await
        .expect("1 件目 dispatcher が同期 Err");

    // 1 件目の callee WS に Offer が push される → answer 返す → registry 1
    let call_id_1 = match timeout(Duration::from_secs(3), ws_rx_a.recv()).await {
        Ok(Some(ServerMessage::Offer { call_id, .. })) => call_id,
        other => panic!("callee a の WS に Offer が来ない: {:?}", other),
    };
    pending_a
        .deliver(&call_id_1, "v=0\r\ns=answer\r\n".to_string())
        .await;
    outcome1.completion.await.unwrap().unwrap();

    // 2 件目: caller2 → b は容量 1 のため admit 拒否
    let (_c2_up_tx, c2_up_rx) = mpsc::channel::<MediaFrame>(8);
    let caller2: Arc<dyn PeerSession> = Arc::new(RecordingPeer::new("c2", c2_up_rx, "c2"));
    let (ws_tx_2, mut ws_rx_2) = mpsc::unbounded_channel::<ServerMessage>();
    let res2 = handler_trait
        .handle_pwa_outbound_offer(
            "b",
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=caller2-offer\r\n",
            &caller2,
            &WsSink::new(ws_tx_2),
        )
        .await;
    assert!(res2.is_err(), "2 件目は admit 拒否で Err 期待");

    // caller2 WS には intercom_busy が push されている
    let pushed = timeout(Duration::from_secs(1), ws_rx_2.recv()).await;
    match pushed {
        Ok(Some(ServerMessage::Error { code, .. })) => {
            assert_eq!(code, "intercom_busy");
        }
        other => panic!("intercom_busy Error 期待だが {:?}", other),
    }

    // NGN には引き続き何も飛ばない
    assert_eq!(ngn_hit_count.load(Ordering::SeqCst), 0);
}

// NOTE: SIP UA → 内線 AOR dispatcher gate (= `handle_invite` 冒頭で 480 を
// 返す) のテストは lib 内 (`#[cfg(test)] mod`) で実装する。 `ResponderHandle::new`
// は `pub(crate)` (CLAUDE.md §9 / PR #176 で production-side test hook を撤去
// した経緯あり) のため、 外部 `tests/` クレートからは構築できない。
// 該当 test 名は `src/call/orchestrator.rs` 内
// `rfc3261_21_4_18_sip_ua_to_internal_aor_returns_480_temporarily_unavailable`。

/// PR #314 review #2 🟡#1 fix: **WS 入口 (`process_client_message`) を経由した
/// e2e 検証**。 trait-API direct な他の test とは違い、 WS 入口の
/// [`is_valid_dial_target`] (charset `[0-9*#+]{1,32}`) を通過する **numeric AOR**
/// (`"101"`) で dispatcher までの full path を検証する。
///
/// 本 PR scope: PWA→PWA full multi-leg orchestration が numeric AOR 経由でのみ
/// production 到達可能であることを担保 (HLD `docs/ARCHITECTURE.md` 「内線間
/// direct dial」 節)。 alphabetic AOR (`"alice"` 等) は WS validator で reject
/// され、 follow-up Issue で WS validator 拡張 or `[extensions]` alias map に
/// よって対応する。
///
/// # DoD
///
/// 1. `process_client_message(Offer { target: "101" })` が WS validator を通過
/// 2. dispatcher が Internal 経路に分岐 (NGN socket には何も飛ばない)
/// 3. callee (= ext_id `"101"` で registrar に登録された PWA) の WS に
///    `ServerMessage::Offer` が push される
/// 4. caller には `ServerMessage::Answer { sdp }` が SessionAction::Reply で返る
///
/// # RFC 引用
///
/// - RFC 3261 §25.1 (user 文法): WS validator が許容するサブセット
///   `[0-9*#+]{1,32}`。
/// - RFC 5853 §3.2.2 (SBC): 同一管理ドメイン内の dial は外部にプロキシしない選択肢。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_entry_numeric_aor_e2e_dispatches_to_intercom_not_ngn() {
    // (a) fake NGN socket (応答しない、 hit count を監視)
    let (_ngn_sock, fake_ngn_addr, ngn_hit_count) = build_fake_ngn().await;

    // (b) registrar に callee PWA `"101"` (numeric AOR) を登録
    let registrar = ExtensionRegistrar::new();
    let (callee_up_tx, callee_up_rx) = mpsc::channel::<MediaFrame>(8);
    let callee_peer_inner = Arc::new(RecordingPeer::new("callee101", callee_up_rx, "callee101"));
    let callee_peer: Arc<dyn PeerSession> = callee_peer_inner.clone();
    let (mut callee_ws_rx, callee_pending, _callee_ws_sink) =
        register_pwa_callee(&registrar, "101", callee_peer.clone()).await;

    // (c) UasEventHandler を組み立て、 pwa_outbound に Arc<UasEventHandler> を結線
    let (uas_handler, _call_manager) =
        build_uas_handler(fake_ngn_addr, registrar.clone(), true, 4).await;
    let pwa_outbound: Arc<dyn PwaOutboundHandler> = uas_handler.clone();

    // (d) SignalingState を組み立てて pwa_outbound を結線 (= main.rs と同じ pattern)
    let verifier = Arc::new(Verifier::new(b"test-secret".to_vec()));
    let state = SignalingState::new(verifier, registrar.clone(), Duration::from_secs(60))
        .with_pwa_outbound(pwa_outbound);

    // (e) caller PWA peer (`peer.handle_offer` / `take_media_rx` を呼ばれる)
    let (_caller_up_tx, caller_up_rx) = mpsc::channel::<MediaFrame>(8);
    let caller_peer: Arc<dyn PeerSession> =
        Arc::new(RecordingPeer::new("caller", caller_up_rx, "caller"));

    // (f) caller 側 WS sink + PendingAnswers (= process_client_message の引数)
    let (caller_ws_tx, _caller_ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let caller_ws_sink = WsSink::new(caller_ws_tx);
    let pending_answers = PendingAnswers::new();

    let claims = AuthClaims {
        ext_id: "caller-pwa".to_string(),
        expiry: 9_999_999_999,
    };
    let mut aor_guard: Option<String> = None;
    let remote: SocketAddr = "127.0.0.1:54321".parse().unwrap();

    // (g) WS 入口を駆動: target = "101" → validator 通過 → dispatcher → Internal
    let action = process_client_message(
        ClientMessage::Offer {
            sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=caller-offer\r\n".into(),
            target: Some("101".into()),
        },
        &state,
        &claims,
        &caller_peer,
        remote,
        &mut aor_guard,
        &caller_ws_sink,
        &pending_answers,
    )
    .await;

    // (h) caller には ServerMessage::Answer が返る (SessionAction::Reply 経由)
    //     RFC 3264 §6 / RFC 8829: caller は SAVPF answer を即時受領。
    match action {
        SessionAction::Reply(ServerMessage::Answer { sdp }) => {
            assert!(
                sdp.contains("caller-answer"),
                "WS 入口経由で caller に Answer が返るべき (SAVPF answer): {}",
                sdp
            );
        }
        SessionAction::Reply(other) => panic!(
            "numeric AOR `\"101\"` (validator pass) で ServerMessage::Answer が \
             期待値 — Internal dispatcher 未到達: reply={:?}",
            other
        ),
        SessionAction::Continue => {
            panic!("expected Reply(Answer), got Continue")
        }
        SessionAction::Close => {
            panic!("expected Reply(Answer), got Close")
        }
    }

    // (i) callee WS に sabiden 発 Offer が push される (= dispatcher が
    //     numeric AOR の binding を引き当て internal 経路に分岐した証拠)
    let pushed = timeout(Duration::from_secs(3), callee_ws_rx.recv())
        .await
        .expect("callee `\"101\"` WS に Offer が push されない (WS validator が numeric AOR を弾いた可能性、 dispatcher 未到達)")
        .expect("callee WS rx closed prematurely");
    let callee_call_id = match pushed {
        ServerMessage::Offer { call_id, sdp } => {
            assert!(
                sdp.contains("callee101-offer"),
                "callee に push された SDP が callee_peer.create_offer 戻り値でない: {}",
                sdp
            );
            call_id
        }
        other => panic!(
            "callee WS で受け取った最初の ServerMessage が Offer ではない: {:?}",
            other
        ),
    };

    // (j) callee answer (= 通常 PWA `ClientMessage::Answer` を再現)
    callee_pending
        .deliver(
            &callee_call_id,
            "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=callee101-answered\r\n".to_string(),
        )
        .await;

    // (k) NGN socket には到達 0 件 (band-aid 防止の決定的証拠)
    //     dispatcher が numeric AOR の binding を引けずに NGN 経路に落ちると
    //     fake_ngn_addr に INVITE が飛び hit_count が増える。
    assert_eq!(
        ngn_hit_count.load(Ordering::SeqCst),
        0,
        "WS 入口経由 numeric AOR でも NGN socket に内線 AOR が漏れている: \
         {} 通到達 (intercom dispatcher gate 破綻)",
        ngn_hit_count.load(Ordering::SeqCst)
    );

    // 後始末
    let _ = callee_up_tx;
}

/// PR #314 review #2 🟡#2 fix: dispatch_pwa_internal_call の callee 側失敗
/// (= 30s answer timeout) で **caller_peer.close() が呼ばれる** ことを確認。
///
/// caller cleanup が抜けると caller 側 str0m peer (DTLS-SRTP / ICE) が live
/// 残り、 PWA は「呼んだ後即切れたのに caller 側だけ alive」 状態になる。
/// 再発呼すると `take_media_rx` が既に取られている等の race を引く。
///
/// # シーケンス
///
/// 1. registrar に callee PWA を登録するが、 callee answer は **送らない**
///    (= 30s timeout 経路にする)
/// 2. timeout 短縮のため `tokio::time::pause` + `advance` を使う
/// 3. background completion が Err で完了し、 caller の
///    `close_called` カウンタが 1 になることを確認
///
/// # RFC 引用
///
/// - RFC 8829 §5.1 (Connection Cleanup): "When a connection is being torn
///   down, the local peer SHOULD send a shutdown message"。 sabiden は
///   `caller_peer.close().await` を best-effort で呼ぶ。
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn dispatch_pwa_internal_call_closes_caller_peer_on_callee_timeout() {
    use std::sync::atomic::AtomicBool;

    /// `close()` カウントを取る peer (他 method は RecordingPeer と同等の
    /// 最小実装。 caller cleanup 専用なので別 struct で簡潔化)。
    struct CallerWithCloseCounter {
        media_rx: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
        close_called: AtomicBool,
    }
    #[async_trait::async_trait]
    impl PeerSession for CallerWithCloseCounter {
        async fn handle_offer(&self, _sdp: &str) -> Result<String> {
            Ok("v=0\r\ns=caller-answer\r\n".to_string())
        }
        async fn create_offer(&self) -> Result<String> {
            Ok("v=0\r\ns=caller-offer\r\n".to_string())
        }
        async fn accept_answer(&self, _sdp: &str) -> Result<()> {
            Ok(())
        }
        async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
            Ok(())
        }
        async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
            self.media_rx.lock().await.take()
        }
        async fn send_media(&self, _frame: MediaFrame) -> Result<()> {
            Ok(())
        }
        async fn close(&self) -> Result<()> {
            self.close_called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    // (a) fake NGN
    let (_ngn_sock, fake_ngn_addr, _ngn_hit_count) = build_fake_ngn().await;

    // (b) callee PWA は registrar に登録するが answer は返さない
    let registrar = ExtensionRegistrar::new();
    let (_callee_up_tx, callee_up_rx) = mpsc::channel::<MediaFrame>(8);
    let callee_peer_inner = Arc::new(RecordingPeer::new("callee", callee_up_rx, "callee"));
    let callee_peer: Arc<dyn PeerSession> = callee_peer_inner.clone();
    let (mut _callee_ws_rx, _callee_pending, _callee_ws_sink) =
        register_pwa_callee(&registrar, "bob-timeout", callee_peer.clone()).await;

    // (c) UasEventHandler
    let (uas_handler, _call_manager) =
        build_uas_handler(fake_ngn_addr, registrar.clone(), true, 4).await;

    // (d) caller peer (close 検出用)
    let (_caller_up_tx, caller_up_rx) = mpsc::channel::<MediaFrame>(8);
    let caller_peer_inner = Arc::new(CallerWithCloseCounter {
        media_rx: Mutex::new(Some(caller_up_rx)),
        close_called: AtomicBool::new(false),
    });
    let caller_peer: Arc<dyn PeerSession> = caller_peer_inner.clone();

    let (caller_ws_tx, mut caller_ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let caller_ws_sink = WsSink::new(caller_ws_tx);

    // (e) dispatcher 駆動 — callee answer は送らないので 30s で timeout
    let handler_trait: Arc<dyn PwaOutboundHandler> = uas_handler.clone();
    let outcome = handler_trait
        .handle_pwa_outbound_offer(
            "bob-timeout",
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=caller-offer\r\n",
            &caller_peer,
            &caller_ws_sink,
        )
        .await
        .expect("dispatcher 同期 path で Err");

    // caller の SAVPF answer は同期で返る (= caller peer は活きた状態で background へ)
    assert!(outcome.savpf_answer.contains("caller-answer"));
    // この時点では caller_peer.close() は呼ばれていない (livelock 防止確認)
    assert!(!caller_peer_inner.close_called.load(Ordering::SeqCst));

    // (f) 仮想時計を 30s 進める → callee answer timeout → caller cleanup 発火
    //     注: `start_paused = true` + `tokio::time::sleep` を内部で使う dispatcher の
    //     `tokio::time::timeout(30s, ...)` が経過する。
    tokio::time::advance(Duration::from_secs(31)).await;

    // (g) background completion が Err で完了する
    let join = outcome.completion.await.expect("completion paniced");
    assert!(join.is_err(), "callee timeout → Err 期待");

    // (h) caller WS に intercom_callee_timeout Error が push されている
    //     (background での send は仮想時計でも実 IO されるため、 短い実時間で受け取れる)
    let pushed = timeout(Duration::from_secs(1), caller_ws_rx.recv()).await;
    match pushed {
        Ok(Some(ServerMessage::Error { code, .. })) => {
            assert_eq!(code, "intercom_callee_timeout");
        }
        other => panic!("intercom_callee_timeout Error 期待だが {:?}", other),
    }

    // (i) ★ caller_peer.close() が呼ばれた (= 本 fix のコア)
    assert!(
        caller_peer_inner.close_called.load(Ordering::SeqCst),
        "caller cleanup 漏れ: callee 30s timeout 後に caller_peer.close() が \
         呼ばれていない (RFC 8829 §5.1 違反)"
    );
}
