//! Issue #45: NGN→内線 着信フローの E2E テスト集約。
//!
//! `docs/architecture.md` §4.2 (NGN→内線 着信シーケンス) と §5.7 (Inbound 状態機械)
//! に従い、`NgnInboundHandler` を実 UDP socket 越しに駆動する。テスト方針は
//! `docs/test-strategy.md` §3 "E2E (orchestrator 全部繋ぐ)" に揃える。
//!
//! 各テストは以下の不変条件を確認する:
//!
//! - **正常系 (round trip)**: NGN INVITE → 100 → 200 → ACK → BYE → 200 までを
//!   1 本で確認 (`mock_ngn_invites_to_extension_full_round_trip`)。
//! - **内線不在**: `ExtensionRegistrar` が空のとき NGN へ 480 Temporarily
//!   Unavailable を返す (`mock_ngn_invite_with_no_extension_returns_480`)。
//! - **fork timeout**: 内線が応答しないとき 408 Request Timeout を返す
//!   (RFC 3261 §17.2.1, `docs/architecture.md` §5.7,
//!   `mock_ngn_invite_fork_timeout_returns_408`)。
//! - **内線レッグ全部 4xx**: 全内線が拒否したとき直近の status (デフォルト 486)
//!   を NGN へ返す (`mock_ngn_invite_all_extensions_busy_returns_486`)。
//! - **NGN CANCEL race**: INVITE 進行中に NGN が CANCEL を出した場合、
//!   sabiden は内線フォークを打ち切り NGN INVITE には 487 Request Terminated を
//!   返す (RFC 3261 §9.1 / §9.2,
//!   `mock_ngn_cancel_during_fork_returns_487`)。
//! - **WebRTC peer fork**: WebRTC 内線 binding に対しても fork が走り、
//!   browser が返した answer SDP がそのまま 200 OK の body に詰まる
//!   (PR #50 の `fork_to_bindings::run_webrtc_leg` を退化させない,
//!   `mock_ngn_invite_to_webrtc_only_binding_uses_browser_answer`)。

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::call::orchestrator::{wire_ngn_inbound, NgnInboundConfig, NgnInboundHandler};
use crate::sip::message::{parse_message, SipMessage};
use crate::sip::registrar::{ExtTransport, ExtensionRegistrar};
use crate::sip::transaction::TransactionLayer;
use crate::testing::builders;
use crate::testing::fixtures;
use crate::testing::scripted::{ScriptedAction, ScriptedInviter};

/// テスト用に sabiden の NGN 側 UDP socket を bind し、フェイク NGN ピアと
/// `NgnInboundHandler` を立ち上げる。
struct InboundFixture {
    sabiden_addr: std::net::SocketAddr,
    ngn_peer: UdpSocket,
    ngn_peer_addr: std::net::SocketAddr,
    inviter: Arc<ScriptedInviter>,
    _handler: Arc<NgnInboundHandler>,
}

impl InboundFixture {
    /// `inviter` と `extensions` から NGN 着信ハンドラを spawn する。
    /// `cfg` で fork_timeout 等を上書きできる。
    async fn start(
        inviter: Arc<ScriptedInviter>,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
    ) -> Self {
        let sabiden_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_peer = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            cfg,
        );
        Self {
            sabiden_addr,
            ngn_peer,
            ngn_peer_addr,
            inviter,
            _handler: handler,
        }
    }

    /// NGN ピアから sabiden へ INVITE を送る。
    async fn send_invite_with_body(&self, call_id: &str, branch: &str, body: Vec<u8>) {
        let invite = builders::invite_from_ngn(
            &self.ngn_peer_addr,
            "sip:0312345678@sabiden",
            call_id,
            branch,
            body,
        );
        self.ngn_peer
            .send_to(&invite.to_bytes(), self.sabiden_addr)
            .await
            .unwrap();
    }

    /// NGN ピアで応答を 1 件受信する (parse 済み SipMessage を返す)。
    async fn recv_message(&self, deadline: Duration) -> Option<SipMessage> {
        let mut buf = vec![0u8; 8192];
        match timeout(deadline, self.ngn_peer.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => parse_message(&buf[..n]).ok(),
            _ => None,
        }
    }

    /// 期待ステータスが届くまで複数応答を読み飛ばす。`expected` が来たら
    /// その response を返す。途中で error/timeout なら panic。
    async fn await_status(&self, expected: u16) -> crate::sip::message::SipResponse {
        for _ in 0..6 {
            match self.recv_message(Duration::from_secs(3)).await {
                Some(SipMessage::Response(r)) => {
                    if r.status_code == expected {
                        return r;
                    }
                    // 1xx 等は読み飛ばす
                }
                Some(SipMessage::Request(req)) => {
                    panic!("予期せぬ Request: {:?}", req.method);
                }
                None => break,
            }
        }
        panic!("status {} が NGN 側に届かない", expected);
    }
}

// =============================================================================
// 1. 正常系: INVITE → 100 → 200 → ACK → BYE → 200
// =============================================================================

/// NGN 着信フルラウンドトリップ (RFC 3261 §13.2 + §15.1)。
///
/// `docs/architecture.md` §4.2 のシーケンス図を 1 本のテストでなぞる:
///
/// 1. NGN → sabiden に INVITE (PCMU offer)
/// 2. sabiden → NGN に 100 Trying (RFC 3261 §17.2.1)
/// 3. sabiden が内線フォーク → ScriptedInviter が 200 OK + PCMU answer
/// 4. sabiden → NGN に 200 OK (Contact + To-tag 付き)
/// 5. NGN → sabiden に ACK
/// 6. NGN → sabiden に BYE → sabiden は 200 OK で応答
#[tokio::test]
async fn mock_ngn_invites_to_extension_full_round_trip() {
    // 内線 1 件登録
    let extensions = ExtensionRegistrar::new();
    extensions
        .register(
            "iphone",
            "sip:iphone@127.0.0.1:6101".to_string(),
            "127.0.0.1:6101".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await;

    // 内線レッグは即 200 OK + PCMU SDP answer を返す
    let answer_sdp = fixtures::sdp_pcmu("127.0.0.1:30000".parse().unwrap()).into_bytes();
    let inviter = ScriptedInviter::builder()
        .default_action(ScriptedAction::ok())
        .default_body(answer_sdp.clone())
        .build();

    let fix = InboundFixture::start(inviter, extensions, NgnInboundConfig::default()).await;

    let offer = fixtures::sdp_pcmu("127.0.0.1:20000".parse().unwrap()).into_bytes();
    let cid = "ngn-roundtrip-cid";
    fix.send_invite_with_body(cid, "z9hG4bKngn-rt", offer).await;

    // 100 Trying と 200 OK
    // Issue #249: 100 Trying の後に 180 Ringing も流れるので、 受信ループは
    // provisional を許容する (RFC 3261 §13.3.1.4)。
    let mut got_100 = false;
    let mut answer_response = None;
    for _ in 0..6 {
        match fix.recv_message(Duration::from_secs(3)).await {
            Some(SipMessage::Response(r)) => match r.status_code {
                100 => got_100 = true,
                180 => {} // RFC 3261 §13.3.1.4: 180 Ringing (Issue #249)
                200 => {
                    answer_response = Some(r);
                    break;
                }
                other => panic!("予期しない status {}", other),
            },
            _ => break,
        }
    }
    assert!(got_100, "100 Trying が NGN へ届くべき (RFC 3261 §17.2.1)");
    let resp = answer_response.expect("200 OK が NGN へ届くべき (RFC 3261 §13.2.2.4)");
    assert!(!resp.body.is_empty(), "200 OK には SDP body があるべき");
    let to = resp
        .headers
        .get("to")
        .expect("To header is required (RFC 3261 §8.1.1.2)");
    assert!(
        to.contains("tag="),
        "To には tag が必須 (RFC 3261 §8.2.6.2)"
    );
    let contact = resp
        .headers
        .get("contact")
        .expect("Contact header on 2xx is required (RFC 3261 §13.3.1.4)");
    assert!(contact.contains("sip:sabiden@"), "Contact は sabiden 自身");

    // 内線フォークが 1 回呼ばれた
    assert_eq!(fix.inviter.call_count(), 1, "内線へ INVITE が 1 回飛ぶ");

    // ACK 送信 (RFC 3261 §17.1.1.3 / §13.2.2.4: 2xx ACK は別 transaction)
    // Mock の ServerTransaction は ACK を pending から消すだけなので、
    // ここでは ACK の到達確認だけする (応答は無い)。
    let ack_branch = "z9hG4bKngn-ack";
    let mut ack = builders::invite_from_ngn(
        &fix.ngn_peer_addr,
        "sip:0312345678@sabiden",
        cid,
        ack_branch,
        Vec::new(),
    );
    ack.method = crate::sip::message::SipMethod::Ack;
    ack.headers.set("CSeq", "1 ACK");
    fix.ngn_peer
        .send_to(&ack.to_bytes(), fix.sabiden_addr)
        .await
        .unwrap();

    // BYE → 200 OK (RFC 3261 §15.1.2)
    let bye = builders::bye(
        &fix.ngn_peer_addr,
        "sip:0312345678@sabiden",
        cid,
        "z9hG4bKngn-bye",
        "ngn-test",
        "local",
    );
    fix.ngn_peer
        .send_to(&bye.to_bytes(), fix.sabiden_addr)
        .await
        .unwrap();
    let bye_200 = fix.await_status(200).await;
    assert_eq!(
        bye_200.status_code, 200,
        "BYE 200 OK が必須 (RFC 3261 §15.1.2)"
    );
}

// =============================================================================
// 2. 内線不在 → 480 Temporarily Unavailable
// =============================================================================

/// 登録内線 0 件のとき NGN へ 480 Temporarily Unavailable を返す。
/// `docs/architecture.md` §4.2 「登録内線ゼロの場合」 / §5.7 `AllRejected` 経路。
#[tokio::test]
async fn mock_ngn_invite_with_no_extension_returns_480() {
    let extensions = ExtensionRegistrar::new();
    let inviter = ScriptedInviter::builder().build(); // default 486 (呼ばれないが念のため)

    let fix = InboundFixture::start(inviter, extensions, NgnInboundConfig::default()).await;

    fix.send_invite_with_body("ngn-noext-e2e", "z9hG4bKngn-noext", Vec::new())
        .await;

    let resp = fix.await_status(480).await;
    assert_eq!(
        resp.status_code, 480,
        "登録内線 0 件は 480 Temporarily Unavailable (RFC 3261 §21.4.18)"
    );
    assert_eq!(
        fix.inviter.call_count(),
        0,
        "内線が無いので inviter は呼ばれない"
    );
}

// =============================================================================
// 3. fork timeout → 408 Request Timeout
// =============================================================================

/// 内線が応答しないとき 408 Request Timeout を返す。
/// `docs/architecture.md` §5.7 `ForkTimeout` 経路 (RFC 3261 §17.2.1, Timer C 相当)。
#[tokio::test]
async fn mock_ngn_invite_fork_timeout_returns_408() {
    let extensions = ExtensionRegistrar::new();
    extensions
        .register(
            "silent",
            "sip:silent@127.0.0.1:6102".to_string(),
            "127.0.0.1:6102".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await;

    // 内線は応答しない (NeverRespond) → fork_timeout 経過 → 408 期待
    let inviter = ScriptedInviter::builder()
        .default_action(ScriptedAction::NeverRespond)
        .build();
    let cfg = NgnInboundConfig {
        fork_timeout: Duration::from_millis(200),
        ..Default::default()
    };
    let fix = InboundFixture::start(inviter, extensions, cfg).await;

    fix.send_invite_with_body("ngn-timeout-e2e", "z9hG4bKngn-timeout", Vec::new())
        .await;

    let resp = fix.await_status(408).await;
    assert_eq!(
        resp.status_code, 408,
        "fork timeout は 408 Request Timeout (RFC 3261 §21.4.8)"
    );
}

// =============================================================================
// 4. 内線レッグ全部 4xx → 486 (or 直近 status)
// =============================================================================

/// 全内線が 486 Busy Here を返したら NGN へ 486 を返す。
/// `docs/architecture.md` §5.7 `AllRejected` 経路。
#[tokio::test]
async fn mock_ngn_invite_all_extensions_busy_returns_486() {
    let extensions = ExtensionRegistrar::new();
    extensions
        .register(
            "busy_a",
            "sip:busy_a@127.0.0.1:6103".to_string(),
            "127.0.0.1:6103".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await;
    extensions
        .register(
            "busy_b",
            "sip:busy_b@127.0.0.1:6104".to_string(),
            "127.0.0.1:6104".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await;

    let inviter = ScriptedInviter::builder()
        .script("sip:busy_a@127.0.0.1:6103", ScriptedAction::busy())
        .script("sip:busy_b@127.0.0.1:6104", ScriptedAction::busy())
        .default_action(ScriptedAction::busy())
        .build();
    let fix = InboundFixture::start(inviter, extensions, NgnInboundConfig::default()).await;

    fix.send_invite_with_body("ngn-allbusy-e2e", "z9hG4bKngn-allbusy", Vec::new())
        .await;

    let resp = fix.await_status(486).await;
    assert_eq!(
        resp.status_code, 486,
        "全内線 486 → NGN へも 486 Busy Here (RFC 3261 §21.4.21)"
    );
    assert_eq!(
        fix.inviter.call_count(),
        2,
        "両内線へ INVITE が飛ぶ (フォーク並列)"
    );
}

// =============================================================================
// 5. NGN CANCEL race → 487 Request Terminated
// =============================================================================

/// INVITE 進行中に NGN が CANCEL を撃つと sabiden は内線フォークを打ち切り、
/// INVITE には 487 Request Terminated を返す (RFC 3261 §9.1 / §9.2 /
/// `docs/architecture.md` §4.4b・§5.7 の race 想定)。
#[tokio::test]
async fn mock_ngn_cancel_during_fork_returns_487() {
    let extensions = ExtensionRegistrar::new();
    extensions
        .register(
            "slow",
            "sip:slow@127.0.0.1:6105".to_string(),
            "127.0.0.1:6105".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await;
    // 内線レッグは応答しない → CANCEL がレースに勝つ
    let inviter = ScriptedInviter::builder()
        .default_action(ScriptedAction::NeverRespond)
        .build();
    // fork_timeout は十分大きく (CANCEL race を確実にレースさせる)
    let cfg = NgnInboundConfig {
        fork_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let fix = InboundFixture::start(inviter, extensions, cfg).await;

    // INVITE 送信
    let cid = "ngn-cancel-e2e";
    fix.send_invite_with_body(cid, "z9hG4bKngn-cancel-inv", Vec::new())
        .await;

    // 100 Trying 受信を待つ (sabiden が in_flight を登録した直後)
    let mut got_100 = false;
    for _ in 0..3 {
        if let Some(SipMessage::Response(r)) = fix.recv_message(Duration::from_secs(2)).await {
            if r.status_code == 100 {
                got_100 = true;
                break;
            }
        }
    }
    assert!(got_100, "CANCEL race の前提として 100 Trying が必要");

    // CANCEL 送信 (RFC 3261 §9.1: 元 INVITE と同じ Call-ID / branch / CSeq number)
    let mut cancel = builders::invite_from_ngn(
        &fix.ngn_peer_addr,
        "sip:0312345678@sabiden",
        cid,
        "z9hG4bKngn-cancel-inv",
        Vec::new(),
    );
    cancel.method = crate::sip::message::SipMethod::Cancel;
    cancel.headers.set("CSeq", "1 CANCEL");
    fix.ngn_peer
        .send_to(&cancel.to_bytes(), fix.sabiden_addr)
        .await
        .unwrap();

    // 期待: CANCEL に 200 OK + INVITE に 487 Request Terminated
    let mut got_cancel_200 = false;
    let mut got_487 = false;
    for _ in 0..6 {
        match fix.recv_message(Duration::from_secs(3)).await {
            Some(SipMessage::Response(r)) => match r.status_code {
                200 => got_cancel_200 = true,
                487 => {
                    got_487 = true;
                    if got_cancel_200 {
                        break;
                    }
                }
                100 => {} // 多重 100 は無視
                // Issue #249: CANCEL race で 180 Ringing 出力が先行する可能性
                180 => {}
                other => panic!("予期しない status {}", other),
            },
            _ => break,
        }
        if got_cancel_200 && got_487 {
            break;
        }
    }
    assert!(got_cancel_200, "CANCEL に 200 OK (RFC 3261 §9.2)");
    assert!(got_487, "INVITE に 487 Request Terminated (RFC 3261 §9.1)");
}

// =============================================================================
// 6. WebRTC peer fork (#50 退化防止)
// =============================================================================

/// WebRTC binding しか登録されていない場合に、`fork_to_bindings::run_webrtc_leg`
/// (PR #50) 経由で browser の answer SDP がそのまま 200 OK の body に詰まる。
///
/// 過去の trace で「fork target が WebRTC のみ → 480」が観測された
/// (Issue #45 背景 / `docs/architecture.md` §4.3 既知ギャップ表) ので、
/// この経路の回帰確認。
#[tokio::test]
async fn mock_ngn_invite_to_webrtc_only_binding_uses_browser_answer() {
    use crate::webrtc::peer::{PeerSession, StubPeerSession};
    use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
    use tokio::sync::mpsc;

    let extensions = ExtensionRegistrar::new();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let ws_sink = WsSink::new(out_tx);
    let pending = PendingAnswers::new();
    let peer: Arc<dyn PeerSession> = StubPeerSession::new();
    extensions
        .register_with_transport(
            "alice",
            "sip:alice@webrtc.peer".to_string(),
            "127.0.0.1:65535".parse().unwrap(),
            Duration::from_secs(60),
            ExtTransport::WebRtc {
                peer: peer.clone(),
                ws: ws_sink.clone(),
                pending: pending.clone(),
            },
        )
        .await;

    // SIP 経路は使われないが ExtInviter 引数は必要
    let inviter = ScriptedInviter::builder().build();
    let fix = InboundFixture::start(inviter, extensions, NgnInboundConfig::default()).await;

    // browser シミュレーション: Offer 受信 → 同じ call_id で Answer を deliver する
    let answer_sdp = fixtures::sdp_pcmu("127.0.0.1:31000".parse().unwrap());
    let answer_sdp_for_browser = answer_sdp.clone();
    let pending_for_browser = pending.clone();
    let browser_task = tokio::spawn(async move {
        let msg = timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .expect("browser へ offer push が来ない")
            .expect("WS チャネル閉鎖");
        match msg {
            ServerMessage::Offer { call_id, sdp: _ } => {
                let delivered = pending_for_browser
                    .deliver(&call_id, answer_sdp_for_browser)
                    .await;
                assert!(delivered, "PendingAnswers::deliver 成功すべき");
            }
            other => panic!("offer 以外を受信: {:?}", other),
        }
    });

    let offer = fixtures::sdp_pcmu("127.0.0.1:20000".parse().unwrap()).into_bytes();
    let cid = "ngn-webrtc-only-e2e";
    fix.send_invite_with_body(cid, "z9hG4bKngn-webrtc", offer)
        .await;

    // 100 → 180 → 200 OK の流れ (RFC 3261 §13.3.1.4, Issue #249)
    let mut got_100 = false;
    let mut got_200_body: Option<Vec<u8>> = None;
    for _ in 0..7 {
        match fix.recv_message(Duration::from_secs(3)).await {
            Some(SipMessage::Response(r)) => match r.status_code {
                100 => got_100 = true,
                180 => {} // RFC 3261 §13.3.1.4 (Issue #249)
                200 => {
                    got_200_body = Some(r.body);
                    break;
                }
                other => panic!("予期しない status {}", other),
            },
            _ => break,
        }
    }
    assert!(got_100, "100 Trying が NGN 側に届くべき");
    let body = got_200_body.expect("200 OK が NGN 側に届くべき");
    assert!(!body.is_empty(), "WebRTC binding の 200 OK にも SDP body");
    let body_str = std::str::from_utf8(&body).expect("UTF-8");
    // browser の answer SDP を起源にしているはずだが、`restrict_audio_to_pcmu` を
    // 通すため m=audio と c= は残る。重要なのは PCMU PT 0 が残っていること。
    assert!(
        body_str.contains("RTP/AVP 0"),
        "200 OK SDP は PCMU PT 0 を含むべき (NGN 側互換): {body_str}"
    );
    assert!(
        body_str.contains("a=rtpmap:0 PCMU/8000"),
        "PCMU rtpmap が必須: {body_str}"
    );
    assert_eq!(
        fix.inviter.call_count(),
        0,
        "WebRTC のみの場合 SIP fork inviter は呼ばれない (PR #50 経路)"
    );

    browser_task.await.unwrap();
}

// =============================================================================
// 7. PWA Decline (Issue #107): browser が `ClientMessage::Decline` を送って
//    着信を拒否したとき、 NGN へ 603 Decline が返る (RFC 3261 §21.6.2)。
// =============================================================================

/// Issue #107: WebRTC のみの fork で browser が拒否 → NGN へ 603 Decline。
///
/// `docs/ARCHITECTURE.md` §4.2 着信フローの拒否分岐。 browser PWA の「拒否」
/// ボタンが `pending.decline(call_id, 603)` 経由で `run_webrtc_leg` の waiter を
/// `AnswerOutcome::Decline { status: 603 }` で起こし、 `LegResult::Failed { status: 603 }`
/// → `ForkResult::AllFailed { last_status: Some(603) }` → NGN へ 603 Decline
/// (RFC 3261 §16.7 best response selection, §21.6.2 603 Decline)。
///
/// 旧挙動 (Issue #107 修正前) は browser が何も送らず、 fork_timeout (`leg_timeout`)
/// が来るまで NGN に応答が無く、 NGN 側 INVITE トランザクションが 30 秒程度
/// 保留される `407` 等の遅延が発生していた。 本テストは数百 ms で 603 が返る
/// ことで根本対処を確認する。
#[tokio::test]
async fn issue107_pwa_decline_returns_603_to_ngn() {
    use crate::webrtc::peer::{PeerSession, StubPeerSession};
    use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
    use tokio::sync::mpsc;

    let extensions = ExtensionRegistrar::new();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerMessage>();
    let ws_sink = WsSink::new(out_tx);
    let pending = PendingAnswers::new();
    let peer: Arc<dyn PeerSession> = StubPeerSession::new();
    extensions
        .register_with_transport(
            "alice",
            "sip:alice@webrtc.peer".to_string(),
            "127.0.0.1:65535".parse().unwrap(),
            Duration::from_secs(60),
            ExtTransport::WebRtc {
                peer: peer.clone(),
                ws: ws_sink.clone(),
                pending: pending.clone(),
            },
        )
        .await;

    // SIP 経路は使われないが ExtInviter 引数は必要
    let inviter = ScriptedInviter::builder().build();
    let fix = InboundFixture::start(inviter, extensions, NgnInboundConfig::default()).await;

    // browser シミュレーション: Offer 受信 → 同じ call_id で Decline を返す
    let pending_for_browser = pending.clone();
    let browser_task = tokio::spawn(async move {
        let msg = timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .expect("browser へ offer push が来ない")
            .expect("WS チャネル閉鎖");
        match msg {
            ServerMessage::Offer { call_id, sdp: _ } => {
                // RFC 3261 §21.6.2: 603 Decline = "user does not wish to
                // participate in the session"。 PWA UI の「拒否」ボタンに対応。
                let declined = pending_for_browser.decline(&call_id, 603).await;
                assert!(declined, "PendingAnswers::decline 成功すべき");
            }
            other => panic!("offer 以外を受信: {:?}", other),
        }
    });

    let offer = fixtures::sdp_pcmu("127.0.0.1:20000".parse().unwrap()).into_bytes();
    let cid = "ngn-decline-e2e";
    fix.send_invite_with_body(cid, "z9hG4bKngn-decline", offer)
        .await;

    // 100 → 180 → 603 の流れ (RFC 3261 §13.3.1.4 / §21.6.2、 Issue #249)
    let mut got_100 = false;
    let mut got_603 = false;
    for _ in 0..7 {
        match fix.recv_message(Duration::from_secs(3)).await {
            Some(SipMessage::Response(r)) => match r.status_code {
                100 => got_100 = true,
                180 => {} // RFC 3261 §13.3.1.4 (Issue #249)
                603 => {
                    got_603 = true;
                    break;
                }
                // 4xx / 5xx 観測時は明示的に panic させる: テストの目的は 603
                // 経路の確認なので、 486 / 408 が来ていたら根本問題。
                other => panic!("予期しない status {} (期待: 100/180/603)", other),
            },
            _ => break,
        }
    }
    assert!(got_100, "100 Trying が NGN 側に届くべき (RFC 3261 §17.2.1)");
    assert!(
        got_603,
        "603 Decline が NGN 側に届くべき (RFC 3261 §21.6.2)"
    );

    browser_task.await.unwrap();
}
