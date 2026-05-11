//! NTT NGN P-CSCF mock (carrier 側 SIP peer)。
//!
//! `tokio::net::UdpSocket` を bind し、 `docs/asterisk-real-invite.md` および
//! `/tmp/sabiden-080-inbound-v4.pcap` 由来の実機挙動を再現する:
//!
//! - **INVITE 注入**: 080→sabiden 着信を模擬。 RFC 4028 Session-Expires
//!   (`x: 300;refresher=uac`)、 Min-SE: 300、 Supported: timer,100rel、
//!   Allow: INVITE,ACK,BYE,CANCEL,PRACK,UPDATE、 anonymous@anonymous.invalid、
//!   Record-Route、 P-Called-Party-ID を付ける。
//! - **応答受信**: sabiden が返す 100 Trying / 180 Ringing / 200 OK / 4xx を
//!   1 件ずつ取り出す API を提供。
//! - **2xx MUST/SHOULD assertion DSL**: `expect_invite_2xx_with` で
//!   Allow / Date / Session-Expires / Require: timer / Contact /
//!   Content-Type / Record-Route / ptime を一括 assert。
//! - **ACK / BYE 送出**: dialog teardown を carrier 側から駆動するヘルパ。
//!
//! 実装方針: production 型は使わず、 `SipRequest` / `SipResponse` の
//! `to_bytes` / `parse_message` だけを公開 API として利用する。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use sabiden::sip::message::{
    parse_message, SipHeaders, SipMessage, SipMethod, SipRequest, SipResponse,
};

/// 注入する INVITE の特徴を変えるオプション。
///
/// 既定値は「080 着信の NGN 実機キャプチャ相当」 を再現する:
/// `Session-Expires: 300;refresher=uac` / `Min-SE: 300` / `Supported: timer,100rel` /
/// `Allow: INVITE,ACK,BYE,CANCEL,PRACK,UPDATE` / `From: <sip:anonymous@anonymous.invalid>` /
/// `Record-Route: <sip:<carrier_addr>;lr>` / `P-Called-Party-ID: <0191349809@ntt-east.ne.jp>`。
#[derive(Debug, Clone)]
pub struct InviteOpts {
    /// Request-URI の宛先 (sabiden の AOR 等)。 既定は `sip:0191349809@sabiden`。
    pub request_uri: String,
    /// From URI / display-name 部 (anonymous でない発信者を指定したい場合用)。
    pub from_uri: String,
    /// Call-ID 値。 既定はランダム生成。
    pub call_id: Option<String>,
    /// 最上位 Via の branch。 既定はランダム。
    pub branch: Option<String>,
    /// `Session-Expires` の delta-seconds。 None なら付けない。
    pub session_expires: Option<u32>,
    /// `Session-Expires` refresher パラメータ ("uac" / "uas")。
    pub session_expires_refresher: Option<&'static str>,
    /// `Min-SE` 値。 None なら付けない。
    pub min_se: Option<u32>,
    /// SDP body (空なら body 無し)。
    pub sdp_offer: Vec<u8>,
}

impl Default for InviteOpts {
    fn default() -> Self {
        Self {
            request_uri: "sip:0191349809@sabiden".to_string(),
            from_uri: "sip:anonymous@anonymous.invalid".to_string(),
            call_id: None,
            branch: None,
            session_expires: Some(300),
            session_expires_refresher: Some("uac"),
            min_se: Some(300),
            sdp_offer: Vec::new(),
        }
    }
}

/// NGN carrier mock ハンドル。
pub struct MockNgnCarrier {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl MockNgnCarrier {
    /// `127.0.0.1:0` で bind してハンドルを返す。 受信ループは持たず、
    /// テスト側が `recv_response` 等で **同期的に** 読み出す (deterministic)。
    pub async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind ngn mock");
        let local_addr = socket.local_addr().expect("local addr");
        Self {
            socket: Arc::new(socket),
            local_addr,
        }
    }

    /// このカリアーが listen している UDP アドレス。
    pub fn addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 共有 socket への参照 (低レベル送信用)。
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// sabiden へ 080 inbound 風 INVITE を 1 件送る。 戻り値は (call-id, branch, from-tag)。
    ///
    /// RFC 3261 §8.1.1: Via / From / To / Call-ID / CSeq / Max-Forwards 必須。
    /// RFC 4028 §4: Session-Expires + Min-SE は INVITE で carrier 側がよく付ける。
    pub async fn inject_inbound_invite(
        &self,
        sabiden_addr: SocketAddr,
        opts: InviteOpts,
    ) -> InjectedInvite {
        let call_id = opts
            .call_id
            .clone()
            .unwrap_or_else(|| format!("ngn-e2e-{}", rand_hex(16)));
        let branch = opts
            .branch
            .clone()
            .unwrap_or_else(|| format!("z9hG4bK-ngn-{}", rand_hex(8)));
        let from_tag = format!("ngn-{}", rand_hex(6));

        let mut req = SipRequest::new(SipMethod::Invite, opts.request_uri.clone());
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};rport;branch={}", self.local_addr, branch),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", format!("<{}>;tag={}", opts.from_uri, from_tag));
        req.headers.set("To", format!("<{}>", opts.request_uri));
        req.headers.set("Call-ID", &call_id);
        req.headers.set("CSeq", "1 INVITE");
        req.headers
            .set("Contact", format!("<sip:caller@{}>", self.local_addr));
        // RFC 4028 §4: Session-Expires + Min-SE。
        if let Some(se) = opts.session_expires {
            let refresher = opts.session_expires_refresher.unwrap_or("uac");
            req.headers
                .set("Session-Expires", format!("{};refresher={}", se, refresher));
        }
        if let Some(min_se) = opts.min_se {
            req.headers.set("Min-SE", min_se.to_string());
        }
        // RFC 3261 §20.5 / RFC 3262 / RFC 4028 §3: Supported オプション タグ。
        req.headers.set("Supported", "timer,100rel");
        // RFC 3261 §20.5: Allow ヘッダ (実機 NGN 080 着信に倣う)。
        req.headers
            .set("Allow", "INVITE,ACK,BYE,CANCEL,PRACK,UPDATE");
        // Asterisk pcap §5 由来: NGN P-CSCF は Record-Route を 1 行付ける。
        req.headers
            .set("Record-Route", format!("<sip:{};lr>", self.local_addr));
        // NGN 着信の典型 P-Called-Party-ID (実機 080 着信 pcap 由来)。
        req.headers
            .set("P-Called-Party-ID", format!("<{}>", opts.request_uri));
        if !opts.sdp_offer.is_empty() {
            req.headers.set("Content-Type", "application/sdp");
            req.body = opts.sdp_offer.clone();
        }

        self.socket
            .send_to(&req.to_bytes(), sabiden_addr)
            .await
            .expect("send invite");

        InjectedInvite {
            call_id,
            branch,
            from_tag,
            request_uri: opts.request_uri,
            from_uri: opts.from_uri,
        }
    }

    /// sabiden から次の 1 件の SIP メッセージ (応答 or 要求) を受け取る。
    /// `deadline` 内に来なければ `None`。
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

    /// Response のみ 1 件取り出す (Request は panic で fail-fast)。
    pub async fn recv_response(&self, deadline: Duration) -> Option<(SipResponse, SocketAddr)> {
        match self.recv_message(deadline).await? {
            (SipMessage::Response(r), peer) => Some((r, peer)),
            (SipMessage::Request(req), _) => panic!("予期しない Request: {:?}", req.method),
        }
    }

    /// 指定 status が来るまで複数応答を読み飛ばし、 該当応答 + 送信元 addr を返す。
    /// 来なければ panic。 100/180 等を「無視して 200 まで進める」 という用途を想定。
    pub async fn await_status(
        &self,
        expected: u16,
        max_attempts: usize,
    ) -> (SipResponse, SocketAddr) {
        for _ in 0..max_attempts {
            match self.recv_response(Duration::from_secs(3)).await {
                Some((r, peer)) => {
                    if r.status_code == expected {
                        return (r, peer);
                    }
                }
                None => break,
            }
        }
        panic!("status {} が NGN へ届かない", expected);
    }

    /// 受信した順序通りに **すべての** 応答を集める。 100/180/200 等の順序検証用。
    /// `max_status` を受け取った時点で打ち切る (これが「最終応答」想定)。
    pub async fn collect_responses_until(
        &self,
        max_attempts: usize,
        terminal_status: u16,
    ) -> Vec<SipResponse> {
        let mut out = Vec::new();
        for _ in 0..max_attempts {
            match self.recv_response(Duration::from_secs(3)).await {
                Some((r, _)) => {
                    let code = r.status_code;
                    out.push(r);
                    if code == terminal_status {
                        return out;
                    }
                }
                None => break,
            }
        }
        out
    }

    /// sabiden 宛に ACK を送る (200 OK 受領後の dialog 確立用、 RFC 3261 §13.2.2.4)。
    ///
    /// `to_tag` は sabiden の 200 OK に乗っていた To-tag を渡す。 dialog ID を
    /// (Call-ID, From-tag, To-tag) で確立する RFC 3261 §12.1.1 準拠。
    /// 2xx ACK は **新規 transaction** (RFC 3261 §17.1.1.3) なので branch も新規にする。
    pub async fn send_ack(
        &self,
        sabiden_addr: SocketAddr,
        injected: &InjectedInvite,
        to_tag: &str,
    ) {
        let branch = format!("z9hG4bK-ack-{}", rand_hex(8));
        let mut ack = SipRequest::new(SipMethod::Ack, injected.request_uri.clone());
        ack.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};rport;branch={}", self.local_addr, branch),
        );
        ack.headers.set("Max-Forwards", "70");
        ack.headers.set(
            "From",
            format!("<{}>;tag={}", injected.from_uri, injected.from_tag),
        );
        ack.headers
            .set("To", format!("<{}>;tag={}", injected.request_uri, to_tag));
        ack.headers.set("Call-ID", &injected.call_id);
        ack.headers.set("CSeq", "1 ACK");
        self.socket
            .send_to(&ack.to_bytes(), sabiden_addr)
            .await
            .expect("send ack");
    }

    /// sabiden へ BYE を送る (dialog teardown、 RFC 3261 §15.1.1)。
    /// `to_tag` は 200 OK で確立した dialog の To-tag。
    pub async fn send_bye(
        &self,
        sabiden_addr: SocketAddr,
        injected: &InjectedInvite,
        to_tag: &str,
    ) {
        let branch = format!("z9hG4bK-bye-{}", rand_hex(8));
        let mut bye = SipRequest::new(SipMethod::Bye, injected.request_uri.clone());
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};rport;branch={}", self.local_addr, branch),
        );
        bye.headers.set("Max-Forwards", "70");
        // BYE の方向: caller (NGN) → sabiden (UAS)。 RFC 3261 §15.1.1:
        // BYE は dialog 内 request なので、 From-tag / To-tag は INVITE と
        // 同じ向きで使う。 inject INVITE は from=caller / to=sabiden だったので
        // BYE も同じ。
        bye.headers.set(
            "From",
            format!("<{}>;tag={}", injected.from_uri, injected.from_tag),
        );
        bye.headers
            .set("To", format!("<{}>;tag={}", injected.request_uri, to_tag));
        bye.headers.set("Call-ID", &injected.call_id);
        bye.headers.set("CSeq", "2 BYE");
        self.socket
            .send_to(&bye.to_bytes(), sabiden_addr)
            .await
            .expect("send bye");
    }
}

/// 注入した INVITE の identifier セット (後続 ACK/BYE で再利用する)。
#[derive(Debug, Clone)]
pub struct InjectedInvite {
    pub call_id: String,
    pub branch: String,
    pub from_tag: String,
    pub request_uri: String,
    pub from_uri: String,
}

/// 2xx 応答の MUST/SHOULD ヘッダを一括 assert する DSL ヘルパ。
///
/// チェック項目:
/// - `Contact`: RFC 3261 §13.3.1.4 (UAS が dialog target を確定するために MUST)。
/// - `To` に tag: RFC 3261 §8.2.6.2 (100 以外で UAS は tag を付ける MUST)。
/// - `Allow`: RFC 3261 §20.5 (SHOULD on 2xx response)。
/// - `Date`: RFC 3261 §20.17 (SHOULD on responses)。
/// - `Session-Expires` + `Require: timer`: RFC 4028 §7.1 (INVITE に
///   Session-Expires が乗っていれば 2xx で echo MUST)。
/// - `Content-Type: application/sdp`: SDP body がある 2xx なら MUST (RFC 3261 §20.15)。
///
/// `expect_session_timer`: 注入した INVITE に Session-Expires が乗っていたかどうか。
/// `expect_sdp_body`: 200 OK に SDP answer body が乗っているはずかどうか。
/// `expect_allow`: Allow ヘッダの存在を要求するか (RFC 3261 §20.5 — SHOULD)。
/// `expect_date`: Date ヘッダの存在を要求するか (RFC 3261 §20.17 — SHOULD)。
///
/// 既定の `Default` は **carrier-compliant 200 OK の正解形** (= 全要件 ON、
/// `expect_session_timer = true`、 `expect_sdp_body = true`、
/// `expect_allow = true`、 `expect_date = true`) を表す。 sabiden の現状実装が
/// 一部 SHOULD を満たしていない期間は、 個別シナリオで `expect_allow = false`
/// 等で **明示的に opt-out** して通す (gap 棚卸しが見える化される)。
/// audit fix が入ったらシナリオ側の opt-out を外して regression を縛る。
pub struct Expect2xx {
    pub expect_session_timer: bool,
    pub expect_sdp_body: bool,
    pub expect_allow: bool,
    pub expect_date: bool,
    /// 期待する ptime (RFC 4566 §6.10、 None ならチェックしない)。
    pub expect_ptime: Option<u32>,
    /// `Allow` ヘッダが含むべきメソッド名 (大文字、 例 "INVITE", "BYE")。
    pub allow_must_include: &'static [&'static str],
}

impl Default for Expect2xx {
    fn default() -> Self {
        Self {
            expect_session_timer: true,
            expect_sdp_body: true,
            expect_allow: true,
            expect_date: true,
            expect_ptime: None,
            allow_must_include: &["INVITE", "ACK", "BYE", "CANCEL"],
        }
    }
}

/// `Expect2xx` で 2xx 応答を一括 assert する。 失敗時は RFC 引用付きで panic。
pub fn expect_invite_2xx_with(resp: &SipResponse, expect: &Expect2xx) {
    assert!(
        (200..300).contains(&resp.status_code),
        "RFC 3261 §13.2.2.4: 2xx を期待 (got {})",
        resp.status_code,
    );

    // To-tag は dialog ID 確立に必須 (RFC 3261 §8.2.6.2 + §12.1.1)。
    let to = resp
        .headers
        .get("to")
        .expect("RFC 3261 §8.1.1.2: To header 必須");
    assert!(
        to.contains("tag="),
        "RFC 3261 §8.2.6.2: 2xx の To には tag が必須 (got: {:?})",
        to
    );

    // Contact: UAS が dialog の remote target を確定するために MUST (RFC 3261 §13.3.1.4)。
    let contact = resp
        .headers
        .get("contact")
        .expect("RFC 3261 §13.3.1.4: 2xx の Contact は MUST (in-dialog target refresh)");
    assert!(
        !contact.is_empty(),
        "Contact 空: RFC 3261 §13.3.1.4 違反 (got: {:?})",
        contact
    );

    // Allow: RFC 3261 §20.5 — SHOULD on final responses。 INVITE 2xx は特に
    // ピア側が次にどのメソッドを使えるか判断する根拠になるので、 BYE / CANCEL /
    // ACK を含めるのが期待される。
    if expect.expect_allow {
        let allow = resp
            .headers
            .get("allow")
            .expect("RFC 3261 §20.5: 2xx で Allow ヘッダ SHOULD (carrier-compliant)");
        for method in expect.allow_must_include {
            assert!(
                allow_includes(allow, method),
                "RFC 3261 §20.5: Allow に {} が含まれるべき (got: {:?})",
                method,
                allow
            );
        }
    }

    // Date: RFC 3261 §20.17 — SHOULD on responses。 carrier 互換性 (Asterisk /
    // NGN 等) で 1xx を除く応答に Date を期待することがある。
    if expect.expect_date {
        let date = resp
            .headers
            .get("date")
            .expect("RFC 3261 §20.17: 2xx で Date ヘッダ SHOULD (carrier-compliant)");
        assert!(!date.is_empty(), "Date 空 (RFC 3261 §20.17): {:?}", date);
    }

    // Session-Expires + Require: timer: RFC 4028 §7.1。 INVITE に
    // Session-Expires が乗っていれば UAS は 2xx に echo MUST。
    if expect.expect_session_timer {
        let se = resp
            .headers
            .get("session-expires")
            .expect("RFC 4028 §7.1: INVITE に Session-Expires があれば 2xx で echo MUST");
        assert!(
            !se.is_empty(),
            "Session-Expires 値が空 (RFC 4028 §4): {:?}",
            se
        );
        let require = resp
            .headers
            .get("require")
            .expect("RFC 4028 §7: Session-Expires echo 時は Require: timer MUST");
        assert!(
            require
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("timer")),
            "RFC 4028 §7: Require に 'timer' タグが必要 (got: {:?})",
            require
        );
    }

    // SDP body: 200 OK に SDP answer がある場合の Content-Type 整合。
    if expect.expect_sdp_body {
        assert!(
            !resp.body.is_empty(),
            "RFC 3264 §5.1: INVITE に SDP offer があれば 2xx に SDP answer (= body 非空) MUST"
        );
        let ct = resp
            .headers
            .get("content-type")
            .expect("RFC 3261 §20.15: SDP body 付き応答は Content-Type MUST");
        assert!(
            ct.eq_ignore_ascii_case("application/sdp"),
            "Content-Type が application/sdp ではない: {:?}",
            ct
        );
        // ptime チェック (RFC 4566 §6.10)。
        if let Some(p) = expect.expect_ptime {
            let body_str = std::str::from_utf8(&resp.body).expect("SDP body は UTF-8");
            let needle = format!("a=ptime:{}", p);
            assert!(
                body_str.lines().any(|l| l.trim() == needle),
                "RFC 4566 §6.10: SDP answer に {} 行が必要 (body: {:?})",
                needle,
                body_str
            );
        }
    }
}

fn allow_includes(allow_header: &str, method: &str) -> bool {
    allow_header
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(method))
}

fn rand_hex(n_bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// `SipHeaders` を空 header set として返す (To-tag 抽出失敗時等のフォールバック)。
#[allow(dead_code)]
pub fn empty_headers() -> SipHeaders {
    SipHeaders::new()
}

/// 200 OK の To ヘッダから tag 値だけ抜き出す。
/// (`<sip:foo>;tag=abc;other` → `"abc"`)
pub fn extract_to_tag(resp: &SipResponse) -> Option<String> {
    let to = resp.headers.get("to")?;
    to.split(';').find_map(|seg| {
        let seg = seg.trim();
        seg.strip_prefix("tag=").map(|v| v.to_string())
    })
}
