//! 初期 4 件の E2E SIP シナリオ。
//!
//! 各シナリオは `mock_ngn_carrier` (NGN P-CSCF) → sabiden →
//! `mock_extension_ua` (内線 UA) の **両側 UDP socket** を通る完全パスを駆動し、
//! INVITE→100→180→200→ACK→BYE→200 の通話シーケンスを 1 test で再現する。
//!
//! 本ファイルの test 命名規約は CLAUDE.md §6.2 に従い `rfc<NUM>_<sec>_...` で
//! RFC 番号と section を埋め込む。
//!
//! 参考 RFC:
//! - RFC 3261 §13 (INVITE-initiated Session) / §17.2.1 (Server tx 100 Trying)
//! - RFC 3261 §13.3.1.4 (2xx Contact target refresh)
//! - RFC 3261 §12.1.1 (Dialog ID = Call-ID + From-tag + To-tag)
//! - RFC 3264 §6.1 (Answer は Offer の subset)
//! - RFC 4028 §7 / §10 (Session-Expires echo / Min-SE 422 + Min-SE)

use std::time::Duration;

use sabiden::sip::message::SipMessage;

use crate::mock_extension_ua::MockExtensionUa;
use crate::mock_ngn_carrier::{
    expect_invite_2xx_with, extract_to_tag, Expect2xx, InviteOpts, MockNgnCarrier,
};
use crate::sabiden_harness::SabidenHarness;

/// PCMU-only SDP offer (RFC 4566 §5 / RFC 3551 PT 0)。
fn sdp_offer_pcmu(ip: &str, port: u16) -> Vec<u8> {
    format!(
        "v=0\r\n\
         o=- 1 1 IN IP4 {ip}\r\n\
         s=-\r\n\
         c=IN IP4 {ip}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=ptime:20\r\n",
        ip = ip,
        port = port
    )
    .into_bytes()
}

/// PCMU + PCMA + telephone-event offer (RFC 3551 / RFC 4733)。
fn sdp_offer_pcmu_pcma_ptime(ip: &str, port: u16, ptime: u32) -> Vec<u8> {
    format!(
        "v=0\r\n\
         o=- 1 1 IN IP4 {ip}\r\n\
         s=-\r\n\
         c=IN IP4 {ip}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0 8\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=ptime:{ptime}\r\n",
        ip = ip,
        port = port,
        ptime = ptime
    )
    .into_bytes()
}

/// 内線 UA が返す PCMU answer SDP。
fn sdp_answer_pcmu(ip: &str, port: u16) -> Vec<u8> {
    format!(
        "v=0\r\n\
         o=- 2 2 IN IP4 {ip}\r\n\
         s=-\r\n\
         c=IN IP4 {ip}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=ptime:20\r\n",
        ip = ip,
        port = port
    )
    .into_bytes()
}

// =============================================================================
// (a) RFC 3261 §13 INVITE → 100 → 180 → 200 → ACK → BYE → 200 full sequence
// =============================================================================

/// `mock_carrier --INVITE--> sabiden --INVITE--> mock_ext_ua --200 OK-->
/// sabiden --200 OK--> mock_carrier --ACK--> sabiden --BYE--> sabiden --200 OK
/// --> mock_carrier`
///
/// RFC 3261 §13.2.2.4 (UAS 2xx) / §17.2.1 (100 Trying SHOULD) /
/// §13.3.1.4 (180 Ringing SHOULD before 2xx) / §15.1.1 (BYE) を 1 本で精査。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3261_inbound_invite_full_sequence_succeeds() {
    let ext_ua = MockExtensionUa::start("iphone").await;
    let harness = SabidenHarness::start_with_mock_extensions(&[&ext_ua]).await;
    let carrier = MockNgnCarrier::start().await;

    // (1) carrier 側から INVITE 注入 (Session-Expires + Min-SE 付き)。
    let injected = carrier
        .inject_inbound_invite(
            harness.ngn_addr,
            InviteOpts {
                sdp_offer: sdp_offer_pcmu("127.0.0.1", 20000),
                ..Default::default()
            },
        )
        .await;

    // (2) 内線 UA に INVITE が forward される (sabiden の fork 経路)。
    let inbound = ext_ua.expect_inbound_invite(Duration::from_secs(5)).await;

    // (3) 内線 UA が 200 OK + SDP answer を返す。
    let _ext_tag = ext_ua
        .answer_with(&inbound, sdp_answer_pcmu("127.0.0.1", 30000))
        .await;

    // (4) carrier 側で 100 → 180 → 200 の順序で応答を受領 (RFC 3261 §13.3.1.4)。
    let responses = carrier.collect_responses_until(8, 200).await;
    let codes: Vec<u16> = responses.iter().map(|r| r.status_code).collect();
    assert!(
        codes.contains(&100),
        "RFC 3261 §17.2.1: 100 Trying が必要 (got codes: {:?})",
        codes
    );
    assert!(
        codes.contains(&200),
        "RFC 3261 §13.2.2.4: 200 OK が必要 (got codes: {:?})",
        codes
    );
    // 180 と 200 OK は最後尾近く。 180 が出ていない場合は SHOULD 違反だが、
    // sabiden は Issue #249 で実装済なので必須として扱う。
    assert!(
        codes.contains(&180),
        "RFC 3261 §13.3.1.4: 180 Ringing が SHOULD (got codes: {:?})",
        codes
    );

    let final_resp = responses
        .iter()
        .find(|r| r.status_code == 200)
        .expect("200 OK 必須");

    // (5) 200 OK の MUST/SHOULD: Session-Expires echo (RFC 4028 §7) + SDP body
    // (RFC 3264) + Contact (RFC 3261 §13.3.1.4)。 Allow/Date は audit 起票済
    // gap (= sabiden 未実装) なので opt-out しておき、 fix が入ったら ON に戻す。
    let expect = Expect2xx {
        expect_session_timer: true,
        expect_sdp_body: true,
        expect_allow: false, // TODO(audit fix): RFC 3261 §20.5 Allow 追加後に true
        expect_date: false,  // TODO(audit fix): RFC 3261 §20.17 Date 追加後に true
        expect_ptime: Some(20),
        ..Default::default()
    };
    expect_invite_2xx_with(final_resp, &expect);

    // (6) carrier → sabiden ACK (RFC 3261 §13.2.2.4: 2xx は別 transaction)。
    let to_tag = extract_to_tag(final_resp).expect("To-tag が必須");
    carrier.send_ack(harness.ngn_addr, &injected, &to_tag).await;

    // (7) carrier → sabiden BYE → 200 OK (RFC 3261 §15.1.1)。
    carrier.send_bye(harness.ngn_addr, &injected, &to_tag).await;
    let (bye_200, _) = carrier.await_status(200, 6).await;
    assert_eq!(
        bye_200.status_code, 200,
        "RFC 3261 §15.1.2: BYE には 200 OK 必須"
    );

    // (8) leg_inviter が 1 回呼ばれ、 2xx ACK を送信したか確認。
    let calls = harness
        .leg_inviter
        .call_count
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(calls, 1, "fork は内線 1 件に 1 回 INVITE を送るはず");
    let acks = harness
        .leg_inviter
        .acks_sent
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        acks, 1,
        "RFC 3261 §13.2.2.4: 2xx INVITE 後に内線レッグへ ACK 1 件"
    );
}

// =============================================================================
// (b) RFC 4028 Session-Timer negotiation (Session-Expires echo + Min-SE 422)
// =============================================================================

/// INVITE が `Session-Expires: 300;refresher=uac` を持って来たら、 sabiden は
/// 200 OK で **Session-Expires を echo MUST** + **Require: timer** を付ける
/// (RFC 4028 §7.1)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc4028_inbound_invite_negotiates_session_timer() {
    let ext_ua = MockExtensionUa::start("iphone").await;
    let harness = SabidenHarness::start_with_mock_extensions(&[&ext_ua]).await;
    let carrier = MockNgnCarrier::start().await;

    let injected = carrier
        .inject_inbound_invite(
            harness.ngn_addr,
            InviteOpts {
                sdp_offer: sdp_offer_pcmu("127.0.0.1", 20000),
                session_expires: Some(300),
                session_expires_refresher: Some("uac"),
                min_se: Some(300),
                ..Default::default()
            },
        )
        .await;

    let inbound = ext_ua.expect_inbound_invite(Duration::from_secs(5)).await;
    let _ = ext_ua
        .answer_with(&inbound, sdp_answer_pcmu("127.0.0.1", 30000))
        .await;

    let (final_resp, _) = carrier.await_status(200, 8).await;

    // Session-Expires + Require: timer MUST。
    let se = final_resp
        .headers
        .get("session-expires")
        .expect("RFC 4028 §7.1: 2xx で Session-Expires echo MUST");
    // RFC 4028 §4: 値は delta-seconds (300) を含むこと。
    let se_secs: u32 = se
        .split(';')
        .next()
        .and_then(|s| s.trim().parse().ok())
        .expect("Session-Expires の delta-seconds パース失敗");
    assert!(
        se_secs >= 90,
        "RFC 4028 §10: Min-SE (90) 以上であるべき (got: {})",
        se_secs
    );
    let require = final_resp
        .headers
        .get("require")
        .expect("RFC 4028 §7: Session-Expires echo 時は Require: timer MUST");
    assert!(
        require
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("timer")),
        "RFC 4028 §7: Require に timer タグが必要 (got: {:?})",
        require
    );

    // teardown (RFC 3261 §15.1.1)。
    let to_tag = extract_to_tag(&final_resp).expect("To-tag");
    carrier.send_ack(harness.ngn_addr, &injected, &to_tag).await;
    carrier.send_bye(harness.ngn_addr, &injected, &to_tag).await;
    let _ = carrier.await_status(200, 6).await;
}

/// RFC 4028 §10: 初回 INVITE で `Session-Expires < Min-SE` の場合、 UAS は
/// **422 Session Interval Too Small + Min-SE ヘッダ** で reject する。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc4028_inbound_invite_below_min_se_returns_422() {
    let ext_ua = MockExtensionUa::start("iphone").await;
    let harness = SabidenHarness::start_with_mock_extensions(&[&ext_ua]).await;
    let carrier = MockNgnCarrier::start().await;

    let _injected = carrier
        .inject_inbound_invite(
            harness.ngn_addr,
            InviteOpts {
                sdp_offer: sdp_offer_pcmu("127.0.0.1", 20000),
                // Min-SE 90 未満を要求 → 422 が返るはず (RFC 4028 §10)。
                session_expires: Some(60),
                session_expires_refresher: Some("uac"),
                min_se: Some(60),
                ..Default::default()
            },
        )
        .await;

    let (resp, _) = carrier.await_status(422, 6).await;
    let min_se = resp
        .headers
        .get("min-se")
        .expect("RFC 4028 §10: 422 には Min-SE ヘッダ MUST");
    let v: u32 = min_se
        .trim()
        .parse()
        .expect("Min-SE は delta-seconds (RFC 4028 §4)");
    assert!(
        v >= 90,
        "Min-SE は sabiden 側 Min-SE (90 以上) のはず (got: {})",
        v
    );
}

// =============================================================================
// (c) RFC 3261 §13.3.1.4 180 Ringing before 200 OK (early dialog == confirmed)
// =============================================================================

/// 100 Trying → 180 Ringing → 200 OK の **順序保証** と、 180 と 200 OK の
/// **To-tag 一致** (= early dialog == confirmed dialog、 RFC 3261 §12.1.1)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3261_inbound_invite_sends_180_ringing_before_200() {
    let ext_ua = MockExtensionUa::start("iphone").await;
    let harness = SabidenHarness::start_with_mock_extensions(&[&ext_ua]).await;
    let carrier = MockNgnCarrier::start().await;

    let injected = carrier
        .inject_inbound_invite(
            harness.ngn_addr,
            InviteOpts {
                sdp_offer: sdp_offer_pcmu("127.0.0.1", 20000),
                ..Default::default()
            },
        )
        .await;

    let inbound = ext_ua.expect_inbound_invite(Duration::from_secs(5)).await;
    let _ = ext_ua
        .answer_with(&inbound, sdp_answer_pcmu("127.0.0.1", 30000))
        .await;

    let responses = carrier.collect_responses_until(8, 200).await;
    let codes: Vec<u16> = responses.iter().map(|r| r.status_code).collect();

    // 順序: 100 が 180 より前、 180 が 200 より前。
    let pos_100 = codes.iter().position(|&c| c == 100).expect("100 が必要");
    let pos_180 = codes.iter().position(|&c| c == 180).expect("180 が必要");
    let pos_200 = codes.iter().position(|&c| c == 200).expect("200 が必要");
    assert!(
        pos_100 < pos_180,
        "RFC 3261 §17.2.1: 100 Trying は 180 より前 (codes: {:?})",
        codes
    );
    assert!(
        pos_180 < pos_200,
        "RFC 3261 §13.3.1.4: 180 Ringing は 200 より前 (codes: {:?})",
        codes
    );

    // RFC 3261 §12.1.1: 180 と 200 OK で To-tag 一致 (early == confirmed dialog)。
    let tag_180 = extract_to_tag(&responses[pos_180]).expect("180 の To-tag");
    let tag_200 = extract_to_tag(&responses[pos_200]).expect("200 の To-tag");
    assert_eq!(
        tag_180, tag_200,
        "RFC 3261 §12.1.1: 180 と 200 OK の To-tag が同じ (early == confirmed dialog ID)"
    );

    // 後始末 (carrier 視点で stale state を残さない)。
    carrier
        .send_ack(harness.ngn_addr, &injected, &tag_200)
        .await;
    carrier
        .send_bye(harness.ngn_addr, &injected, &tag_200)
        .await;
    let _ = carrier.await_status(200, 6).await;
}

// =============================================================================
// (d) RFC 3264 SDP answer is subset of offer (sabiden が NGN へ返す 200 OK SDP)
// =============================================================================

/// offer = PCMU + PCMA + ptime → ext_ua answer = PCMU only → sabiden が NGN
/// へ返す 200 OK SDP も PCMU only + ptime (intersection、 PR #243 同様の挙動)。
///
/// RFC 3264 §6.1: "The answer to an offer MUST contain the same number of
/// `m=' lines as the offer. ... If a media format listed is not supported,
/// it MUST NOT be listed in the answer." (= answer は offer の subset)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3264_inbound_invite_sdp_answer_subsets_offer() {
    let ext_ua = MockExtensionUa::start("iphone").await;
    let harness = SabidenHarness::start_with_mock_extensions(&[&ext_ua]).await;
    let carrier = MockNgnCarrier::start().await;

    // Offer: PCMU + PCMA + ptime:20
    let offer = sdp_offer_pcmu_pcma_ptime("127.0.0.1", 20000, 20);
    let injected = carrier
        .inject_inbound_invite(
            harness.ngn_addr,
            InviteOpts {
                sdp_offer: offer,
                ..Default::default()
            },
        )
        .await;

    let inbound = ext_ua.expect_inbound_invite(Duration::from_secs(5)).await;
    // ext_ua answer: PCMU のみ
    let _ = ext_ua
        .answer_with(&inbound, sdp_answer_pcmu("127.0.0.1", 30000))
        .await;

    let (final_resp, _) = carrier.await_status(200, 8).await;
    let body = std::str::from_utf8(&final_resp.body).expect("SDP body は UTF-8");

    // m= 行に PT 0 (PCMU) が含まれる。
    let m_line = body
        .lines()
        .find(|l| l.starts_with("m=audio"))
        .expect("m=audio 行が必要 (RFC 4566 §5.14)");
    let parts: Vec<&str> = m_line.split_whitespace().collect();
    // m=audio <port> RTP/AVP <fmt-list>
    assert!(parts.len() >= 4, "m=audio 行が不正: {:?}", m_line);
    let fmts: Vec<&str> = parts[3..].to_vec();
    assert!(
        fmts.contains(&"0"),
        "RFC 3264 §6.1: PCMU (PT 0) が answer に含まれること (m=: {:?})",
        m_line
    );
    // PCMA (PT 8) が answer に含まれていないこと (subset 制約)。
    assert!(
        !fmts.contains(&"8"),
        "RFC 3264 §6.1: ext_ua が PCMA を answer しない以上、 NGN 200 OK にも PCMA が無いこと (m=: {:?})",
        m_line
    );
    // ptime:20 が answer に echo されていること (PR #243 / RFC 4566 §6.10)。
    assert!(
        body.lines().any(|l| l.trim() == "a=ptime:20"),
        "RFC 4566 §6.10: offer の ptime:20 が answer に echo (body: {})",
        body
    );

    // 後始末。
    let to_tag = extract_to_tag(&final_resp).expect("To-tag");
    carrier.send_ack(harness.ngn_addr, &injected, &to_tag).await;
    carrier.send_bye(harness.ngn_addr, &injected, &to_tag).await;
    let _ = carrier.await_status(200, 6).await;
}

// =============================================================================
// Smoke test: harness が立ち上がるだけの最低限テスト (CI 健全性確認用)
// =============================================================================

/// 何も注入せず、 harness の起動だけ確認する smoke test。 wire_ngn_inbound が
/// panic せず、 socket addr が確保できることを保証する (regression 用)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harness_starts_without_panic() {
    let ext_ua = MockExtensionUa::start("iphone").await;
    let harness = SabidenHarness::start_with_mock_extensions(&[&ext_ua]).await;
    let _carrier = MockNgnCarrier::start().await;
    assert_ne!(
        harness.ngn_addr.port(),
        0,
        "ngn socket addr が解決できているはず"
    );

    // Optionally drain any messages that arrived in 100ms.
    let carrier = MockNgnCarrier::start().await;
    if let Some(m) = carrier.recv_message(Duration::from_millis(100)).await {
        // Smoke test 中は何も来ない想定。 来たら fail-fast。
        match m {
            (SipMessage::Request(req), _) => panic!("予期しない Request: {:?}", req.method),
            (SipMessage::Response(resp), _) => {
                panic!("予期しない Response: {}", resp.status_code)
            }
        }
    }
}
