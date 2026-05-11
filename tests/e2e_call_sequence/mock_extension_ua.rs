//! 内線 SIP UA mock (PWA-like、 ただし UDP UA)。
//!
//! 本ハンドルは sabiden の `fork_to_bindings` が UDP で送ってくる INVITE を
//! 受け取り、 200 OK + SDP answer を返す。 また、 dialog 確立後に内線側
//! BYE を撃つヘルパも提供する。
//!
//! 注意: sabiden の `ExtensionRegistrar` に UDP UA として登録するため、
//! このハンドルの UDP socket addr を `Binding::remote` に紐付けする。
//! sabiden の `fork_to_bindings` (`ExtTransport::Sip`) は `binding.contact_uri`
//! を target_uri にして `LegInviter::invite` を呼ぶ。 テストでは
//! `crate::leg_inviter::TestLegInviter` がそれを受けて、 ext_ua の UDP addr
//! 宛に INVITE を送る (= sabiden 本流 `UacForker` と等価な経路)。
//!
//! RFC 3261 §13.3.1.4 (UAS Behavior 2xx) / §15.1.1 (BYE) 準拠。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use sabiden::sip::message::{parse_message, SipMessage, SipMethod, SipRequest, SipResponse};

/// 内線 UA mock ハンドル。
pub struct MockExtensionUa {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    pub aor: String,
}

/// 直近に受信した INVITE から抽出した dialog identifier。
/// 200 OK / BYE 構築時に使う (RFC 3261 §12.1.1: dialog ID 3-tuple)。
#[derive(Debug, Clone)]
pub struct ReceivedInvite {
    pub raw: SipRequest,
    pub call_id: String,
    pub from: String,
    pub to_without_tag: String,
    pub branch: String,
    pub cseq: String,
    pub remote: SocketAddr,
}

impl MockExtensionUa {
    /// `127.0.0.1:0` で bind して内線 UA ハンドルを返す。 `aor` は
    /// `ExtensionRegistrar` 登録用 AOR (例 "iphone")。
    pub async fn start(aor: &str) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind ext ua");
        let local_addr = socket.local_addr().expect("local addr");
        Self {
            socket: Arc::new(socket),
            local_addr,
            aor: aor.to_string(),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// `ExtensionRegistrar` に紐付ける Contact URI (テスト便宜)。
    pub fn contact_uri(&self) -> String {
        format!("sip:{}@{}", self.aor, self.local_addr)
    }

    /// sabiden から fork されてきた INVITE を受信する。
    /// `deadline` 内に来なければ panic (テスト失敗を fail-fast)。
    ///
    /// RFC 3261 §13.3.1.4: UAS が INVITE を受けたら 100 → 180 → 200 を返すのが
    /// 標準。 本 mock は INVITE を返したあと `answer_with` 呼出時に 200 OK のみ
    /// (provisional は付けない) で応答する。 sabiden 側 NgnInboundHandler が
    /// NGN 向けの 100/180 は別途生成するため、 内線レッグでは 200 だけで十分。
    pub async fn expect_inbound_invite(&self, deadline: Duration) -> ReceivedInvite {
        let mut buf = vec![0u8; 16 * 1024];
        let (n, peer) = timeout(deadline, self.socket.recv_from(&mut buf))
            .await
            .expect("ext ua: inbound INVITE timeout")
            .expect("ext ua: socket recv error");
        let parsed = parse_message(&buf[..n]).expect("ext ua: parse fail");
        let req = match parsed {
            SipMessage::Request(r) => r,
            SipMessage::Response(r) => {
                panic!("ext ua: 期待 Request, got Response {}", r.status_code)
            }
        };
        assert_eq!(
            req.method,
            SipMethod::Invite,
            "ext ua: 期待 INVITE, got {:?}",
            req.method
        );

        let via = req
            .headers
            .get("via")
            .expect("RFC 3261 §8.1.1: Via 必須")
            .to_string();
        let branch = extract_branch(&via).expect("Via に branch=z9hG4bK 必須 (RFC 3261 §8.1.1.7)");
        let call_id = req
            .headers
            .get("call-id")
            .expect("RFC 3261 §8.1.1.4: Call-ID 必須")
            .to_string();
        let from = req
            .headers
            .get("from")
            .expect("RFC 3261 §8.1.1.3: From 必須")
            .to_string();
        let to_without_tag = req
            .headers
            .get("to")
            .expect("RFC 3261 §8.1.1.2: To 必須")
            .to_string();
        let cseq = req
            .headers
            .get("cseq")
            .expect("RFC 3261 §8.1.1.5: CSeq 必須")
            .to_string();

        ReceivedInvite {
            raw: req,
            call_id,
            from,
            to_without_tag,
            branch,
            cseq,
            remote: peer,
        }
    }

    /// 200 OK + SDP answer を返す (= 内線ユーザが応答ボタン押下相当)。
    ///
    /// RFC 3261 §13.3.1.4 + §8.2.6.2: To-tag MUST、 Contact MUST。
    /// 戻り値は付与した To-tag (carrier 側 ACK でこれを使う tracking 用、
    /// ただしこのテストでは sabiden 側 dialog tag の方を使う)。
    pub async fn answer_with(&self, inv: &ReceivedInvite, sdp_answer: Vec<u8>) -> String {
        let to_tag = format!("ext-{}", rand_hex(6));
        let mut resp = SipResponse {
            status_code: 200,
            reason: "OK".to_string(),
            headers: sabiden::sip::message::SipHeaders::new(),
            body: Vec::new(),
        };
        // Via / From / Call-ID / CSeq はそのまま echo (RFC 3261 §8.2.6)。
        resp.headers.set("Via", inv.raw.headers.get("via").unwrap());
        resp.headers.set("From", &inv.from);
        resp.headers
            .set("To", format!("{};tag={}", inv.to_without_tag, to_tag));
        resp.headers.set("Call-ID", &inv.call_id);
        resp.headers.set("CSeq", &inv.cseq);
        resp.headers
            .set("Contact", format!("<{}>", self.contact_uri()));
        // RFC 3261 §20.5 + §20.17: Allow / Date を載せておく (carrier-compliance、
        // sabiden NGN レッグ 2xx は別経路で組まれるが、 ここは内線レッグ視点)。
        resp.headers
            .set("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS");
        resp.headers.set("Date", http_date_now());

        if !sdp_answer.is_empty() {
            resp.headers.set("Content-Type", "application/sdp");
            resp.body = sdp_answer;
        }

        self.socket
            .send_to(&resp.to_bytes(), inv.remote)
            .await
            .expect("ext ua: send 200 OK");
        to_tag
    }

    /// 任意の status code で拒否 (busy / decline 検証用)。
    pub async fn reject_with(&self, inv: &ReceivedInvite, code: u16, reason: &str) {
        let to_tag = format!("ext-{}", rand_hex(6));
        let mut resp = SipResponse {
            status_code: code,
            reason: reason.to_string(),
            headers: sabiden::sip::message::SipHeaders::new(),
            body: Vec::new(),
        };
        resp.headers.set("Via", inv.raw.headers.get("via").unwrap());
        resp.headers.set("From", &inv.from);
        resp.headers
            .set("To", format!("{};tag={}", inv.to_without_tag, to_tag));
        resp.headers.set("Call-ID", &inv.call_id);
        resp.headers.set("CSeq", &inv.cseq);
        self.socket
            .send_to(&resp.to_bytes(), inv.remote)
            .await
            .expect("ext ua: send reject");
    }

    /// 内線→sabiden 方向の任意リクエスト (BYE 等) を送る。
    pub async fn send_request(&self, target: SocketAddr, req: &SipRequest) {
        self.socket
            .send_to(&req.to_bytes(), target)
            .await
            .expect("ext ua: send_request");
    }

    /// 内線側で受信するメッセージを 1 件読む (ACK / BYE 等)。
    pub async fn recv_message(&self, deadline: Duration) -> Option<(SipMessage, SocketAddr)> {
        let mut buf = vec![0u8; 16 * 1024];
        match timeout(deadline, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, peer))) => match parse_message(&buf[..n]) {
                Ok(m) => Some((m, peer)),
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// `recv_message` の Request 専用 version。
    pub async fn recv_request(&self, deadline: Duration) -> Option<(SipRequest, SocketAddr)> {
        match self.recv_message(deadline).await? {
            (SipMessage::Request(r), peer) => Some((r, peer)),
            (SipMessage::Response(r), _) => {
                panic!("ext ua: 期待 Request, got Response {}", r.status_code)
            }
        }
    }
}

fn extract_branch(via: &str) -> Option<String> {
    for seg in via.split(';') {
        let seg = seg.trim();
        if let Some(v) = seg.strip_prefix("branch=") {
            return Some(v.to_string());
        }
    }
    None
}

fn rand_hex(n_bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// RFC 7231 §7.1.1.1 IMF-fixdate (例 "Sun, 06 Nov 1994 08:49:37 GMT")。
/// テスト用の固定 stub で十分 (carrier 側で日付値検証はしない)。
fn http_date_now() -> String {
    // 値は固定 (deterministic test 性)。 RFC 5322/7231 fixdate format。
    "Sun, 11 May 2026 00:00:00 GMT".to_string()
}
