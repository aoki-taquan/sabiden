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
        // 受信した SAVPF offer に対する answer は固定文字列で十分 (テストは
        // SDP 内容ではなく dispatcher の挙動と媒体 relay を見る)。
        Ok(format!(
            "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns={}-answer\r\n",
            self.sdp_marker
        ))
    }
    async fn create_offer(&self) -> Result<String> {
        Ok(format!(
            "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns={}-offer\r\n",
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

/// DoD: PWA→SIP UA 内線通話は本 PR scope 外 (follow-up)。 dispatcher は
/// `ServerMessage::Error { code: "intercom_sip_callee_unsupported" }` を
/// caller に返し、 NGN 経路に流れないことを確認する。
///
/// これは「band-aid 防止 (CLAUDE.md §6.1)」 を担保する重要なテスト: dispatcher
/// が落ちると NGN に内線 AOR が漏れて 404 が帰る band-aid 経路に逆戻りする。
///
/// テスト層: **trait-API direct** (WS validator bypass、 alphabetic AOR を使う)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pwa_to_sip_callee_intercom_returns_unsupported_error_and_no_ngn_traffic() {
    // (a) fake NGN
    let (_ngn_sock, fake_ngn_addr, ngn_hit_count) = build_fake_ngn().await;

    // (b) registrar に SIP UA callee を登録 (= ExtTransport::Sip)
    let registrar = ExtensionRegistrar::new();
    registrar
        .register(
            "linphone-bob",
            "sip:linphone-bob@192.0.2.10:5060".to_string(),
            "192.0.2.10:5060".parse().unwrap(),
            Duration::from_secs(300),
        )
        .await;

    // (c) UasEventHandler を組み立て
    let (uas_handler, _call_manager) =
        build_uas_handler(fake_ngn_addr, registrar.clone(), true, 4).await;

    // (d) caller PWA peer
    let (_caller_up_tx, caller_up_rx) = mpsc::channel::<MediaFrame>(8);
    let caller_peer: Arc<dyn PeerSession> =
        Arc::new(RecordingPeer::new("caller", caller_up_rx, "caller"));
    let (caller_ws_tx, mut caller_ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let caller_ws_sink = WsSink::new(caller_ws_tx);

    // (e) dispatcher を駆動
    let handler_trait: Arc<dyn PwaOutboundHandler> = uas_handler.clone();
    let outcome = handler_trait
        .handle_pwa_outbound_offer(
            "linphone-bob",
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=caller-offer\r\n",
            &caller_peer,
            &caller_ws_sink,
        )
        .await
        .expect("dispatcher returned Err");

    // (f) caller には answer が返る (intercom_sip_callee_unsupported でも
    //     handle_offer は実行されるので savpf_answer は確定する)。
    assert!(outcome.savpf_answer.contains("caller-answer"));

    // (g) caller WS に intercom_sip_callee_unsupported Error が push される
    let pushed = timeout(Duration::from_secs(1), caller_ws_rx.recv())
        .await
        .expect("caller WS に Error が push されない")
        .expect("caller WS rx closed");
    match pushed {
        ServerMessage::Error { code, message: _ } => {
            assert_eq!(
                code, "intercom_sip_callee_unsupported",
                "PWA→SIP UA 内線経路は follow-up 待ちのため intercom_sip_callee_unsupported が期待値"
            );
        }
        other => panic!("Error 期待だが {:?}", other),
    }

    // (h) NGN socket には何も飛ばない (band-aid 防止 — 内線 AOR が NGN に
    //     漏れる経路は dispatcher が遮断する)。
    let _ = outcome.completion.await;
    assert_eq!(
        ngn_hit_count.load(Ordering::SeqCst),
        0,
        "PWA→SIP UA は follow-up 待ちだが NGN に内線 AOR を漏らしてはならない \
         (CLAUDE.md §6.1 band-aid 防止)"
    );
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
