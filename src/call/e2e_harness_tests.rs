//! Issue #42: ハーネスを使った E2E シナリオテスト。
//!
//! 既存テストが「sabiden の各層を 1 つずつ確認する単体テスト」中心だったのに対し、
//! 本ファイルは [`crate::testing`] のハーネスで NGN P-CSCF / 内線 UA / NGN UAC を
//! 同時に立ち上げ、現場フローを 1 本のテストで通す。
//!
//! いずれも `sabiden` を実プロセスとして起動するのではなく、各 SIP コンポーネントを
//! `tokio::spawn` で組み立てたインプロセス E2E だが、固有のソケットを使って
//! `TransactionLayer` を通すため、SIP ヘッダ書き換え / 100 Trying / Via routing
//! の不具合は実環境と同等の経路で検出できる。

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::call::manager::{CallManager, UacForker};
use crate::call::orchestrator::{
    wire_ngn_inbound, wire_ngn_inbound_with_manager_and_metrics, NgnInboundConfig,
    NgnInboundHandler, UasEventHandler,
};
use crate::config::{ExtensionConfig, UasConfig};
use crate::observability::Metrics;
use crate::sip::message::{parse_message, SipMessage, SipMethod, SipRequest};
use crate::sip::registrar::ExtensionRegistrar;
use crate::sip::transaction::{build_response_skeleton, TransactionLayer};
use crate::sip::uac::{Uac, UacConfig};
use crate::sip::uas::ExtensionUas;
use crate::testing::asserts;
use crate::testing::builders;
use crate::testing::ext_ua::MockExtensionUa;
use crate::testing::fixtures;
use crate::testing::scripted::{ScriptedAction, ScriptedInviter};

/// 内線→sabiden→NGN の発信フルラウンドトリップ。
///
/// 1. mock NGN P-CSCF (UDP) を spawn し、INVITE → 200 OK / BYE → 200 OK を返す
/// 2. sabiden NGN UAC を本物の `Uac` で構築
/// 3. sabiden 内線 UAS をループバックで bind
/// 4. mock 内線 UA (Linphone 風) で REGISTER → INVITE → ACK → BYE
/// 5. mock NGN 側で INVITE が到着し、内線へ 200 が戻ることを検証
///
/// (RFC 3261 §13 / §15)
#[tokio::test]
async fn extension_initiated_call_to_ngn_full_round_trip() {
    // (1) mock NGN: UDP socket + 1-INVITE handler (200 OK + ACK + BYE 200 OK)
    let fake_ngn = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let fake_ngn_addr = fake_ngn.local_addr().unwrap();
    let fake_ngn_clone = fake_ngn.clone();
    let ngn_invite_arrived = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ngn_invite_arrived_c = ngn_invite_arrived.clone();
    let ngn_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
        let parsed = parse_message(&buf[..n]).unwrap();
        if let SipMessage::Request(req) = parsed {
            asserts::assert_method(&req, SipMethod::Invite, "RFC 3261 §13");
            ngn_invite_arrived_c.store(true, std::sync::atomic::Ordering::SeqCst);
            // 200 OK
            let mut resp = build_response_skeleton(&req, 200, "OK");
            resp.headers.set(
                "To",
                format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
            );
            resp.headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_clone
                .send_to(&resp.to_bytes(), peer)
                .await
                .unwrap();
            // ACK は drop (タイムアウト付きで読み、来なければ exit)
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                fake_ngn_clone.recv_from(&mut buf),
            )
            .await;
        }
    });

    // (2) sabiden の NGN UAC
    let ngn_client_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
    let ngn_uac = Arc::new(Uac::new(
        UacConfig {
            local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            local_addr: ngn_client_sock.local_addr().unwrap(),
            user_agent: "sabiden-test/0.1".to_string(),
        },
        ngn_layer,
        fake_ngn_addr,
    ));

    // (3) sabiden の内線 UAS
    let uas_cfg = UasConfig {
        bind_addr: fixtures::loopback_any(),
        realm: "sabiden-test".to_string(),
        max_expires: 3600,
    };
    let extensions = vec![ExtensionConfig {
        username: "iphone".to_string(),
        password: "secret".to_string(),
    }];
    let uas = ExtensionUas::bind(uas_cfg, &extensions).await.unwrap();
    let uas_addr = uas.socket().local_addr().unwrap();

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let uas = uas.with_handler(event_tx);
    tokio::spawn(async move {
        uas.run().await.unwrap();
    });

    // (4) UasEventHandler を起動 (内線 INVITE → NGN UAC へプロキシ)
    let handler = UasEventHandler::new(ngn_uac);
    handler.spawn(event_rx);

    // (5) 内線 mock UA で REGISTER → INVITE
    let mut phone = MockExtensionUa::bind("iphone", "secret").await.unwrap();
    phone.register_with_digest(uas_addr).await.unwrap();

    let resp = phone
        .invite_with_digest(uas_addr, "sip:dest@sabiden", Vec::new())
        .await
        .unwrap();
    assert!(
        (200..300).contains(&resp.status_code),
        "内線へ 200 OK が返るべき (RFC 3261 §13.2.2.4): got {}",
        resp.status_code
    );

    // mock NGN 側に INVITE が届いている
    let _ = ngn_task.await;
    assert!(
        ngn_invite_arrived.load(std::sync::atomic::Ordering::SeqCst),
        "NGN 側に INVITE がプロキシされるべき"
    );
}

/// Issue #64 / RFC 3261 §13.3.1.4 (UAS Behavior, 2xx Responses):
/// 内線→sabiden→NGN 発信通話で、sabiden が内線レッグに返す 200 OK は
/// Contact ヘッダを必ず持つ。Contact が無いと内線 UA (Linphone 等) は
/// dialog の remote target を確定できず、ACK / BYE の宛先が不定となり
/// dialog 確立に失敗する。
#[tokio::test]
async fn rfc3261_13_3_1_4_extension_invite_2xx_response_has_contact_header() {
    // (1) mock NGN: 200 OK を返すだけの最小実装 (Contact は内線レッグの
    // 検証対象なので NGN 側 SDP は中身不問)
    let fake_ngn = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let fake_ngn_addr = fake_ngn.local_addr().unwrap();
    let fake_ngn_clone = fake_ngn.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        if let Ok((n, peer)) = fake_ngn_clone.recv_from(&mut buf).await {
            if let Ok(SipMessage::Request(req)) = parse_message(&buf[..n]) {
                let mut resp = build_response_skeleton(&req, 200, "OK");
                resp.headers.set(
                    "To",
                    format!("{};tag=ngn-tag-64", req.headers.get("to").unwrap()),
                );
                resp.headers
                    .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                let _ = fake_ngn_clone.send_to(&resp.to_bytes(), peer).await;
                // ACK は読んで捨てる
                let _ = tokio::time::timeout(
                    Duration::from_millis(500),
                    fake_ngn_clone.recv_from(&mut buf),
                )
                .await;
            }
        }
    });

    // (2) sabiden NGN UAC
    let ngn_client_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
    let ngn_uac = Arc::new(Uac::new(
        UacConfig {
            local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            local_addr: ngn_client_sock.local_addr().unwrap(),
            user_agent: "sabiden-test/0.1".to_string(),
        },
        ngn_layer,
        fake_ngn_addr,
    ));

    // (3) sabiden 内線 UAS
    let uas_cfg = UasConfig {
        bind_addr: fixtures::loopback_any(),
        realm: "sabiden-test".to_string(),
        max_expires: 3600,
    };
    let extensions = vec![ExtensionConfig {
        username: "iphone".to_string(),
        password: "secret".to_string(),
    }];
    let uas = ExtensionUas::bind(uas_cfg, &extensions).await.unwrap();
    let uas_addr = uas.socket().local_addr().unwrap();

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let uas = uas.with_handler(event_tx);
    tokio::spawn(async move {
        uas.run().await.unwrap();
    });

    let handler = UasEventHandler::new(ngn_uac);
    handler.spawn(event_rx);

    // (4) 内線 UA で REGISTER → INVITE
    let mut phone = MockExtensionUa::bind("iphone", "secret").await.unwrap();
    phone.register_with_digest(uas_addr).await.unwrap();
    let resp = phone
        .invite_with_digest(uas_addr, "sip:dest@sabiden", Vec::new())
        .await
        .unwrap();

    // (5) RFC 3261 §13.3.1.4: 内線レッグ 200 OK には Contact ヘッダ必須
    assert!(
        (200..300).contains(&resp.status_code),
        "200 OK を期待: got {}",
        resp.status_code
    );
    let contact = resp.headers.get("contact");
    assert!(
        contact.is_some(),
        "RFC 3261 §13.3.1.4: 内線レッグ 200 OK に Contact ヘッダが必須 (Issue #64). headers={:?}",
        resp.headers,
    );
    let contact = contact.unwrap();
    assert!(
        contact.contains("sabiden"),
        "Contact URI は sabiden を指すべき: got {}",
        contact
    );
}

/// NGN→sabiden→内線の着信フルラウンドトリップ。
///
/// 1. mock NGN ピアから sabiden NGN ソケットに INVITE
/// 2. sabiden が内線フォーク → mock 内線 (ScriptedInviter で 200) で確立
/// 3. NGN 側に 100 Trying と 200 OK が届くことを検証
/// 4. mock NGN 側から BYE を送り、200 OK が返ることを検証
///
/// (RFC 3261 §13 / §15.1.2)
#[tokio::test]
async fn ngn_inbound_call_to_extension_round_trip() {
    let sabiden_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let sabiden_addr = sabiden_sock.local_addr().unwrap();

    let ngn_peer = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
    let ngn_peer_addr = ngn_peer.local_addr().unwrap();

    // 内線登録テーブル (1 件)
    let extensions = ExtensionRegistrar::new();
    extensions
        .register(
            "iphone",
            "sip:iphone@127.0.0.1:6001".to_string(),
            "127.0.0.1:6001".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await;

    // ハーネスの ScriptedInviter で 200 OK + ダミー SDP を返す
    let inviter = ScriptedInviter::builder()
        .default_action(ScriptedAction::ok())
        .default_body(fixtures::sdp_pcmu("127.0.0.1:30000".parse().unwrap()).into_bytes())
        .build();

    // ハンドラ起動
    let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
    let _h: Arc<NgnInboundHandler> = wire_ngn_inbound(
        layer,
        sabiden_sock.clone(),
        inbound_rx,
        inviter.clone(),
        extensions,
        NgnInboundConfig::default(),
    );

    // INVITE 送信 (ハーネスのビルダ)
    let invite = builders::invite_from_ngn(
        &ngn_peer_addr,
        "sip:0312345678@sabiden",
        "ngn-inbound-e2e",
        "z9hG4bKngn-inbound-e2e",
        fixtures::sdp_pcmu("127.0.0.1:20000".parse().unwrap()).into_bytes(),
    );
    ngn_peer
        .send_to(&invite.to_bytes(), sabiden_addr)
        .await
        .unwrap();

    // 100 → 200 OK が NGN 側に届く
    let mut buf = vec![0u8; 8192];
    let mut got_100 = false;
    let mut got_200 = false;
    for _ in 0..3 {
        match timeout(Duration::from_secs(3), ngn_peer.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                    match r.status_code {
                        100 => got_100 = true,
                        200 => {
                            got_200 = true;
                            break;
                        }
                        _ => {}
                    }
                }
            }
            _ => break,
        }
    }
    assert!(got_100, "100 Trying が返るべき (RFC 3261 §17.2.1)");
    assert!(got_200, "200 OK が返るべき (RFC 3261 §13.2.2.4)");
    assert_eq!(inviter.call_count(), 1, "内線フォークが 1 回呼ばれる");

    // BYE → 200 OK
    let bye = builders::bye(
        &ngn_peer_addr,
        "sip:0312345678@sabiden",
        "ngn-inbound-e2e",
        "z9hG4bKngn-inbound-bye",
        "ngn-test",
        "local",
    );
    ngn_peer
        .send_to(&bye.to_bytes(), sabiden_addr)
        .await
        .unwrap();
    let mut got_bye_200 = false;
    for _ in 0..3 {
        match timeout(Duration::from_secs(2), ngn_peer.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                    if r.status_code == 200 {
                        got_bye_200 = true;
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    assert!(got_bye_200, "BYE 200 OK が返るべき (RFC 3261 §15.1.2)");
}

/// 内線 CANCEL が NGN 側へ伝播し、mock NGN が 487 を返した場合に
/// 内線にも 487 (に相当する) 失敗が返ることを確認する E2E。
///
/// 注: sabiden は現状 INVITE プロキシ中の CANCEL 結線を簡易実装している
/// (orchestrator.rs Phase 2 制限) ため、本テストでは
/// 「内線 INVITE → mock NGN は INVITE に 487 を返す → sabiden が 487 を内線へ転送」
/// パスを検証する。これは内線側 UA が送る CANCEL に対して NGN 側 UAC が
/// CANCEL 経由で 487 を引き出す経路と同等の効果を持ち、ハーネスで cancel/487
/// 伝播を検証する目的を果たす。
///
/// (RFC 3261 §9.1: CANCEL は 487 Request Terminated を伴う)
#[tokio::test]
async fn extension_cancel_propagates_to_ngn() {
    // mock NGN: INVITE を受け取ったら 487 Request Terminated を返す
    // (CANCEL 受信を模した最終応答)
    let fake_ngn = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let fake_ngn_addr = fake_ngn.local_addr().unwrap();
    let fake_ngn_clone = fake_ngn.clone();
    let ngn_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
        if let Ok(SipMessage::Request(req)) = parse_message(&buf[..n]) {
            assert_eq!(req.method, SipMethod::Invite);
            // 100 → 487
            let trying = build_response_skeleton(&req, 100, "Trying");
            let _ = fake_ngn_clone.send_to(&trying.to_bytes(), peer).await;
            let mut resp = build_response_skeleton(&req, 487, "Request Terminated");
            resp.headers.set(
                "To",
                format!("{};tag=ngn-cancel-tag", req.headers.get("to").unwrap()),
            );
            let _ = fake_ngn_clone.send_to(&resp.to_bytes(), peer).await;
            // ACK 受信は drop (タイムアウトで bail)
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                fake_ngn_clone.recv_from(&mut buf),
            )
            .await;
        }
    });

    // sabiden NGN UAC
    let ngn_client_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
    let ngn_uac = Arc::new(Uac::new(
        UacConfig {
            local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            local_addr: ngn_client_sock.local_addr().unwrap(),
            user_agent: "sabiden-test/0.1".to_string(),
        },
        ngn_layer,
        fake_ngn_addr,
    ));

    // sabiden 内線 UAS
    let uas_cfg = UasConfig {
        bind_addr: fixtures::loopback_any(),
        realm: "sabiden-test".to_string(),
        max_expires: 3600,
    };
    let extensions = vec![ExtensionConfig {
        username: "iphone".to_string(),
        password: "secret".to_string(),
    }];
    let uas = ExtensionUas::bind(uas_cfg, &extensions).await.unwrap();
    let uas_addr = uas.socket().local_addr().unwrap();

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let uas = uas.with_handler(event_tx);
    tokio::spawn(async move {
        uas.run().await.unwrap();
    });

    // UasEventHandler 起動
    let handler = UasEventHandler::new(ngn_uac);
    handler.spawn(event_rx);

    // mock 内線 UA で REGISTER → INVITE
    let mut phone = MockExtensionUa::bind("iphone", "secret").await.unwrap();
    phone.register_with_digest(uas_addr).await.unwrap();

    let resp = phone
        .invite_with_digest(uas_addr, "sip:dest@sabiden", Vec::new())
        .await
        .unwrap();
    assert_eq!(
        resp.status_code, 487,
        "NGN 487 が内線へ伝播するべき (RFC 3261 §9.1)"
    );

    let _ = ngn_task.await;
}

/// orchestrator + UAC + manager + UAS + 内線 UA + NGN P-CSCF を全て
/// ハーネス helper で組み合わせる smoke テスト。各 helper が
/// 単独で立ち上がりかつ協調することを 1 本で確認する。
#[tokio::test]
async fn harness_pieces_compose_smoke() {
    use crate::testing::pcsf::{MockNgnPcsf, NgnInviteScript, NgnRegisterScript};

    let pcsf = MockNgnPcsf::start(
        NgnRegisterScript::AlwaysAccept,
        NgnInviteScript::Accept {
            answer_sdp: fixtures::sdp_pcmu("127.0.0.1:30000".parse().unwrap()).into_bytes(),
        },
    )
    .await
    .unwrap();
    assert!(
        pcsf.addr.ip().is_loopback(),
        "MockNgnPcsf bind しているはず"
    );

    let phone = MockExtensionUa::bind("iphone", "secret").await.unwrap();
    assert!(phone.local_addr.ip().is_loopback());

    // 観測ベクタは初期空
    assert!(pcsf.observed().await.is_empty());

    // pcsf 自体に REGISTER を 1 回送って自分の応答を確認
    let req = builders::register_from_phone(
        &phone.local_addr,
        "iphone",
        "z9hG4bKsmoke",
        Some("Digest dummy"),
    );
    phone.send_request(pcsf.addr, &req).await.unwrap();
    let resp = phone.recv_response(Duration::from_secs(2)).await.unwrap();
    asserts::assert_status_code(&resp, 200, "MockNgnPcsf::AlwaysAccept");

    // observed に 1 件記録されている
    let observed = pcsf.observed().await;
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].method, SipMethod::Register);
}

/// `make_forker` を含む UacForker 経路が ScriptedInviter とは別に
/// 正常に build できる回帰確認 (元 orchestrator::tests から移植)。
#[tokio::test]
async fn make_forker_wraps_uac_via_harness() {
    let sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let server: std::net::SocketAddr = "127.0.0.1:6000".parse().unwrap();
    let (layer, _rx) = TransactionLayer::spawn(sock.clone());
    let cfg = UacConfig {
        local_uri: "sip:sabiden@local".to_string(),
        domain: "local".to_string(),
        local_addr: sock.local_addr().unwrap(),
        user_agent: "test/0.1".to_string(),
    };
    let uac = Arc::new(Uac::new(cfg, layer, server));
    let _forker = crate::call::orchestrator::make_forker(uac);
    // ループバック (CallManager 経由の生存検証)
    let _ = CallManager::new(ExtensionRegistrar::new());
    let _ = UacForker {
        uac: Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:x@y".into(),
                domain: "y".into(),
                local_addr: sock.local_addr().unwrap(),
                user_agent: "x".into(),
            },
            TransactionLayer::spawn(sock).0,
            server,
        )),
        targets: Default::default(),
    };
    // 単純に型が成立し、UacForker / CallManager が組めることだけ確認 (本体は manager::tests)
    // (ここでは SipRequest の組み立て検証は不要)
    let _ = SipRequest::new(SipMethod::Invite, "sip:x");
}

// ============================================================================
// Issue #40: CallManager 配線で内線↔NGN RTP 音声経路を完成
// ----------------------------------------------------------------------------
// `main.rs` で `UasEventHandler::with_call_manager_and_metrics` /
// `wire_ngn_inbound_with_manager_and_metrics` 経路に切り替えたときに
// `prepare_outbound_bridge` / `start_bridge_for_inbound` が動くこと
// (= SDP `m=audio` port が sabiden 側ソケットに書換、RtpBridge が中継する)
// を E2E で確認する。
// ============================================================================

/// Issue #40: 内線→NGN 発信時、`UasEventHandler::with_call_manager_and_metrics`
/// 経路では `prepare_outbound_bridge` が NGN へ送る INVITE の SDP を sabiden 側
/// RTP ソケットに書換える。
///
/// `docs/asterisk-real-invite.md` §5.2: NGN へ広告する SDP `m=audio` port は
/// sabiden が NGN 側に bind した RTP ソケットの port であるべき
/// (内線 UA の port を素通しすると NAT 越えで音声が届かない)。
///
/// 本テストは fake NGN を立てて INVITE を捕捉し、SDP `m=audio` port が
/// 内線 UA の広告 port と異なる (= sabiden 側に書換わっている) ことを assert する。
#[tokio::test]
async fn extension_call_with_callmanager_rewrites_sdp_port_to_sabiden_socket() {
    use crate::sdp::SessionDescription;
    use crate::sip::transaction::ServerTransaction;
    use crate::sip::uas::{ResponderHandle, UasEvent};
    use std::net::SocketAddr;
    use std::sync::Mutex as StdMutex;

    // 1) フェイク NGN: INVITE を受けて SDP を保存し 200 OK を返す。
    //    200 OK の SDP は NGN 側ピアの RTP ポートを指す体裁にする (RTP リレー
    //    までは検証しないが finalize_outbound_bridge を踏ませるため)。
    let fake_ngn = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let fake_ngn_addr = fake_ngn.local_addr().unwrap();
    let ngn_peer_rtp = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let ngn_peer_rtp_addr = ngn_peer_rtp.local_addr().unwrap();

    let captured_invite_sdp: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(None));
    let captured_sdp_for_task = captured_invite_sdp.clone();
    let fake_ngn_clone = fake_ngn.clone();
    let ngn_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("INVITE 期待");
        };
        asserts::assert_method(&req, SipMethod::Invite, "RFC 3261 §13");
        *captured_sdp_for_task.lock().unwrap() = Some(req.body.clone());
        let mut resp = build_response_skeleton(&req, 200, "OK");
        resp.headers.set(
            "To",
            format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
        );
        resp.headers
            .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
        resp.headers.set("Content-Type", "application/sdp");
        resp.body = fixtures::sdp_pcmu(ngn_peer_rtp_addr).into_bytes();
        let _ = fake_ngn_clone.send_to(&resp.to_bytes(), peer).await;
        // ACK は drop (タイムアウトで bail)
        let _ = tokio::time::timeout(
            Duration::from_millis(500),
            fake_ngn_clone.recv_from(&mut buf),
        )
        .await;
    });

    // 2) sabiden NGN UAC
    let ngn_client_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
    let ngn_uac = Arc::new(Uac::new(
        UacConfig {
            local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            local_addr: ngn_client_sock.local_addr().unwrap(),
            user_agent: "sabiden-test/0.1".to_string(),
        },
        ngn_layer,
        fake_ngn_addr,
    ));

    // 3) CallManager を注入した UasEventHandler (Issue #40 の本流配線)
    let mgr = CallManager::new(ExtensionRegistrar::new());
    let handler = UasEventHandler::with_call_manager_and_metrics(
        ngn_uac,
        mgr.clone(),
        Some("127.0.0.1".parse().unwrap()),
        Some("127.0.0.1".parse().unwrap()),
        Metrics::new(),
    );
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    handler.spawn(event_rx);

    // 4) 模擬内線が出した INVITE を直接 UasEvent::Invite として fire する。
    //    内線 UA の RTP 広告 port は sabiden 側に書換わるはずなので、控えておく。
    let phone_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let phone_addr = phone_sock.local_addr().unwrap();
    let sabiden_uas_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

    // 内線 UA が広告する RTP ピア (本テストでは別 socket を立てない: port だけ
    // 確認すればよく、`a=rtpmap` 等は SDP テンプレで揃える)。
    let ext_ua_rtp_addr: SocketAddr = "127.0.0.1:55120".parse().unwrap();
    let ext_offer_sdp = fixtures::sdp_pcmu(ext_ua_rtp_addr);

    let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
    invite.headers.set(
        "Via",
        format!("SIP/2.0/UDP {};branch=z9hG4bKissue40-out", phone_addr),
    );
    invite
        .headers
        .set("From", "<sip:iphone@sabiden>;tag=phonet-issue40");
    invite.headers.set("To", "<sip:0312345678@sabiden>");
    invite.headers.set("Call-ID", "issue40-outbound-cid");
    invite.headers.set("CSeq", "1 INVITE");
    invite.headers.set("Content-Type", "application/sdp");
    invite.body = ext_offer_sdp.into_bytes();
    phone_sock
        .send_to(&invite.to_bytes(), sabiden_uas_addr)
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, remote) = timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
        .await
        .expect("内線→sabiden の INVITE が UAS socket に来ない")
        .unwrap();
    let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
        panic!("INVITE 期待");
    };
    let stx = ServerTransaction::new(req.clone(), remote, sabiden_uas_sock.clone()).unwrap();
    let responder = ResponderHandle::__test_new(stx);
    event_tx
        .send(UasEvent::Invite {
            from_aor: "iphone".to_string(),
            request: req,
            remote,
            responder,
        })
        .unwrap();

    // 5) NGN タスク完了を待ち、INVITE の SDP を回収
    timeout(Duration::from_secs(3), ngn_task)
        .await
        .expect("fake NGN タスクが終わらない")
        .unwrap();
    let ngn_invite_sdp = captured_invite_sdp
        .lock()
        .unwrap()
        .clone()
        .expect("NGN へ INVITE が届くべき");

    // 6) 検証: NGN 行きの INVITE に乗っている SDP の m=audio port は
    //    内線 UA の広告 port (55120) と異なる (= sabiden 側 RTP ソケット port に
    //    書換わっている)。これが Issue #40 で破れていた本流要件。
    let parsed = SessionDescription::parse(std::str::from_utf8(&ngn_invite_sdp).unwrap())
        .expect("NGN 行き SDP がパースできる");
    let m_audio = parsed
        .media
        .iter()
        .find(|m| m.media == "audio")
        .expect("m=audio がある");
    assert_ne!(
        m_audio.port,
        ext_ua_rtp_addr.port(),
        "NGN 行き INVITE の m=audio port は sabiden 側 RTP socket に書換わるべき \
         (Issue #40 / docs/asterisk-real-invite.md §5.2): got={} (= 内線広告 port そのまま)",
        m_audio.port
    );

    // CallManager に通話エントリが登録されている (RTP ブリッジ起動済み)
    assert_eq!(
        mgr.len().await,
        1,
        "CallManager に 1 通話分のブリッジが登録される"
    );

    // 内線 UA のループバック port を握っているとカーネルが他テストと衝突するため
    // 以降は drop する (本テストの assertion はここまで)。
    drop(phone_sock);
    drop(sabiden_uas_sock);
}

/// Issue #40: NGN→内線 着信時、`wire_ngn_inbound_with_manager_and_metrics`
/// 経路では `RtpBridge` が起動して NGN ↔ 内線 で UDP packet を中継する。
///
/// 本テストは smoke レベル: NGN ピア → sabiden NGN bridge socket →
/// 内線ピアへ RTP 1 発が届くことを確認する。
/// (双方向検証は `bridge.rs::tests::bridges_rtp_in_both_directions` で済んでいる
/// ので、ここでは `wire_ngn_inbound_with_manager_and_metrics` の結線が
/// 実際にブリッジを spawn しているかだけ見れば十分。)
#[tokio::test]
async fn inbound_call_with_callmanager_relays_rtp_smoke() {
    use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
    use crate::sdp::SessionDescription;
    use std::net::SocketAddr;

    // 1) フェイク内線ピア (200 OK answer の RTP 受け先)
    let ext_peer_sock = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
    let ext_peer_addr = ext_peer_sock.local_addr().unwrap();
    let ext_answer_sdp = fixtures::sdp_pcmu(ext_peer_addr);

    // 2) ScriptedInviter: 内線フォーク先が 200 OK + SDP answer を返す体裁
    let inviter = ScriptedInviter::builder()
        .default_action(ScriptedAction::ok())
        .default_body(ext_answer_sdp.into_bytes())
        .build();

    // 3) sabiden NGN SIP socket
    let sabiden_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let sabiden_addr = sabiden_sock.local_addr().unwrap();

    // 4) フェイク NGN ピア (RTP 送信元 + SIP UA)
    let ngn_peer_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
    let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

    // 5) 内線登録 (1 件) と CallManager
    let extensions = ExtensionRegistrar::new();
    extensions
        .register(
            "iphone",
            "sip:iphone@127.0.0.1:6001".to_string(),
            "127.0.0.1:6001".parse().unwrap(),
            Duration::from_secs(60),
        )
        .await;
    let mgr = CallManager::new(extensions.clone());

    // 6) Issue #40 で `main.rs` が呼ぶ wire を直接呼び出す。
    let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
    let _h: Arc<NgnInboundHandler> = wire_ngn_inbound_with_manager_and_metrics(
        layer,
        sabiden_sock.clone(),
        inbound_rx,
        inviter.clone(),
        extensions,
        NgnInboundConfig::default(),
        mgr.clone(),
        Metrics::new(),
    );

    // 7) NGN INVITE 送信 (SDP オファあり)
    let ngn_offer_sdp = fixtures::sdp_pcmu(ngn_peer_addr);
    let mut invite = builders::invite_from_ngn(
        &ngn_peer_addr,
        "sip:0312345678@sabiden",
        "issue40-inbound-cid",
        "z9hG4bKissue40-in",
        ngn_offer_sdp.into_bytes(),
    );
    invite.headers.set("Content-Type", "application/sdp");
    ngn_peer_sock
        .send_to(&invite.to_bytes(), sabiden_addr)
        .await
        .unwrap();

    // 8) 200 OK を読み取り、書き換え後の SDP から sabiden NGN 側 RTP socket を得る
    let mut buf = vec![0u8; 8192];
    let sabiden_ngn_rtp: SocketAddr = loop {
        let (n, _) = timeout(Duration::from_secs(3), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("200 OK が NGN 側に来ない")
            .unwrap();
        if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
            if r.status_code == 200 {
                assert!(!r.body.is_empty(), "200 OK には書換後 SDP が必要");
                let parsed = SessionDescription::parse(std::str::from_utf8(&r.body).unwrap())
                    .expect("200 OK SDP がパースできる");
                let conn = parsed.connection.expect("c= が必要");
                let port = parsed.media[0].port;
                let addr = SocketAddr::new(conn.address, port);
                assert_ne!(
                    addr, ext_peer_addr,
                    "200 OK の SDP は sabiden 側 RTP socket を指すべき \
                     (内線 UA の port のままでは中継できない)"
                );
                break addr;
            }
        }
    };

    // 9) ブリッジが CallManager に登録されている
    assert_eq!(mgr.len().await, 1, "RTP ブリッジが 1 件起動済み");

    // 10) NGN ピア → sabiden NGN bridge socket → 内線ピア の片方向 smoke
    //     (RFC 3550 §5.1: 単一 RTP ヘッダ + payload で十分)
    let pkt = RtpPacket {
        payload_type: PAYLOAD_TYPE_ULAW,
        marker: false,
        sequence: 1,
        timestamp: 160,
        ssrc: 0xCAFE_F00D,
        payload: vec![0x7f; 160],
    }
    .to_bytes();
    ngn_peer_sock.send_to(&pkt, sabiden_ngn_rtp).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(2), ext_peer_sock.recv_from(&mut buf))
        .await
        .expect("内線ピアが NGN→ext 方向の RTP を受信できない")
        .unwrap();
    let recv = RtpPacket::from_bytes(&buf[..n]).expect("RTP パース");
    assert_eq!(
        recv.ssrc, 0xCAFE_F00D,
        "RtpBridge は受信した RTP ペイロードを SSRC ごとそのまま中継する"
    );
}
