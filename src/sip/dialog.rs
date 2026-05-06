//! SIP ダイアログ層 (RFC 3261 §12)
//!
//! ダイアログは Call-ID + local-tag + remote-tag の三組で同定され、
//! UAC/UAS の双方が局所的に状態 (Early / Confirmed / Terminated) を持つ。
//! 本実装は UAC (発信側) のダイアログ管理に責務を限定する。
//!
//! 主な責務:
//! - ダイアログ ID 生成 (Call-ID, local-tag, remote-tag)
//! - CSeq の単調増加管理 (RFC 3261 §12.2.1.1)
//! - Route Set の確立 (Record-Route の逆順, RFC 3261 §12.1.2)
//! - Remote Target (Contact) と Remote URI 管理
//! - ACK / BYE / Re-INVITE / CANCEL の組み立て (RFC 3261 §13, §15.1, RFC 4028)
//!
//! NTT NGN 制約: Via ヘッダに `rport` を付けない (拒否される)。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};

use super::message::{SipHeaders, SipMethod, SipRequest, SipResponse};
use super::utils::new_branch;

/// ダイアログ状態 (RFC 3261 §12)。
///
/// - `Early`: 1xx (101..=199 で to-tag を持つもの) を受けた状態
/// - `Confirmed`: 2xx を受けた状態
/// - `Terminated`: BYE 送受信、CANCEL 又はエラーで破棄された状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    Early,
    Confirmed,
    Terminated,
}

/// ダイアログ ID (RFC 3261 §12)。
///
/// UAC では (Call-ID, local-tag = From-tag, remote-tag = To-tag) で一意。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

/// UAC ダイアログ (RFC 3261 §12.1.2 / §12.2.1)。
///
/// `Arc<AtomicU32>` で CSeq を共有しつつ、Re-INVITE / BYE / CANCEL 等の
/// in-dialog リクエスト生成 API を提供する。
#[derive(Debug)]
pub struct Dialog {
    /// ダイアログ ID
    id: DialogId,
    /// 状態 (Early / Confirmed / Terminated)
    state: DialogState,
    /// local URI (From). Display name 等は付けない素のアドレス。
    local_uri: String,
    /// remote URI (To)
    remote_uri: String,
    /// remote target = Contact ヘッダから抽出した URI (RFC 3261 §12.1.2)
    remote_target: String,
    /// Route Set: Record-Route の逆順 (UAC), 全 URI のリスト。
    /// 空ならば direct (Request-URI = remote-target) で送る。
    route_set: Vec<String>,
    /// CSeq 番号生成器 (RFC 3261 §12.2.1.1)
    local_cseq: Arc<AtomicU32>,
    /// 発信時に確定したローカル Contact ヘッダ値 (URI 部のみ)。
    local_contact: String,
    /// Via 用 sent-by (例: "[2001:db8::1]:5060")
    sent_by: String,
}

/// ダイアログ生成に必要な情報をまとめた入力。
///
/// 通常は INVITE 送信前に決定する固定パラメータ。
#[derive(Debug, Clone)]
pub struct DialogConfig {
    pub local_uri: String,
    pub remote_uri: String,
    pub local_contact: String,
    pub sent_by: String,
}

impl Dialog {
    /// 2xx 応答 (or 早期 1xx with to-tag) からダイアログを確立する。
    ///
    /// `request` は INVITE 自体 (CSeq の元), `response` は受信した
    /// 1xx (with to-tag) または 2xx 応答。
    ///
    /// RFC 3261 §12.1.2:
    /// - Route set は Record-Route ヘッダの **逆順**
    /// - Remote target は Contact ヘッダ
    /// - Remote sequence number は空 (UAS からの in-dialog リクエストを
    ///   受けたとき初めて確定する)
    /// - Local sequence number は INVITE の CSeq + 1 から開始
    pub fn from_uac_response(
        request: &SipRequest,
        response: &SipResponse,
        cfg: DialogConfig,
    ) -> Result<Self> {
        let call_id = request
            .headers
            .get("call-id")
            .ok_or_else(|| anyhow!("INVITE に Call-ID がない"))?
            .to_string();
        let from = request
            .headers
            .get("from")
            .ok_or_else(|| anyhow!("INVITE に From がない"))?;
        let to = response
            .headers
            .get("to")
            .ok_or_else(|| anyhow!("応答に To がない"))?;
        let local_tag = parse_tag(from)
            .ok_or_else(|| anyhow!("INVITE From に tag がない: {}", from))?
            .to_string();
        let remote_tag = parse_tag(to)
            .ok_or_else(|| anyhow!("応答 To に tag がない (early dialog ではない): {}", to))?
            .to_string();
        let remote_target = response
            .headers
            .get("contact")
            .map(extract_uri)
            .ok_or_else(|| anyhow!("応答に Contact がない"))?;
        // Record-Route は UAC から見ると逆順 (RFC 3261 §12.1.2)
        let mut route_set: Vec<String> = response
            .headers
            .get_all("record-route")
            .into_iter()
            .flat_map(split_route_header)
            .collect();
        route_set.reverse();

        // 起点 CSeq は INVITE のもの。次の in-dialog リクエストではこれ + 1。
        let invite_cseq = parse_cseq_number(
            request
                .headers
                .get("cseq")
                .ok_or_else(|| anyhow!("INVITE に CSeq がない"))?,
        )?;
        let local_cseq = Arc::new(AtomicU32::new(invite_cseq + 1));

        let state = if response.status_code >= 200 && response.status_code < 300 {
            DialogState::Confirmed
        } else if response.status_code >= 100 && response.status_code < 200 {
            DialogState::Early
        } else {
            return Err(anyhow!(
                "ダイアログを作れない応答コード: {}",
                response.status_code
            ));
        };

        Ok(Self {
            id: DialogId {
                call_id,
                local_tag,
                remote_tag,
            },
            state,
            local_uri: cfg.local_uri,
            remote_uri: cfg.remote_uri,
            remote_target,
            route_set,
            local_cseq,
            local_contact: cfg.local_contact,
            sent_by: cfg.sent_by,
        })
    }

    /// Early ダイアログを Confirmed に昇格させる (2xx 受信時)。
    /// route_set / remote_target は 2xx の値で更新する (RFC 3261 §13.2.2.4)。
    pub fn confirm(&mut self, response: &SipResponse) -> Result<()> {
        let remote_target = response
            .headers
            .get("contact")
            .map(extract_uri)
            .ok_or_else(|| anyhow!("2xx に Contact がない"))?;
        let mut route_set: Vec<String> = response
            .headers
            .get_all("record-route")
            .into_iter()
            .flat_map(split_route_header)
            .collect();
        route_set.reverse();
        self.remote_target = remote_target;
        self.route_set = route_set;
        // To-tag は 2xx で確定済み (Early と同じはず)。
        if let Some(to) = response.headers.get("to") {
            if let Some(tag) = parse_tag(to) {
                self.id.remote_tag = tag.to_string();
            }
        }
        self.state = DialogState::Confirmed;
        Ok(())
    }

    pub fn id(&self) -> &DialogId {
        &self.id
    }

    pub fn state(&self) -> DialogState {
        self.state
    }

    pub fn terminate(&mut self) {
        self.state = DialogState::Terminated;
    }

    /// 2xx に対する ACK (RFC 3261 §13.2.2.4 / §17.1.1.3)。
    ///
    /// - Request-URI / Route は ダイアログの remote_target / route_set
    /// - Via は新規 branch
    /// - From/To/Call-ID はダイアログのもの
    /// - CSeq は INVITE と同じ番号 + method=ACK
    /// - 2xx ACK は新規トランザクションであり再送制御は TU (本層) の責任。
    pub fn build_ack_for_2xx(&self, invite_cseq: u32) -> SipRequest {
        let (request_uri, route_headers) = self.compute_request_uri_and_route();
        let mut req = SipRequest::new(SipMethod::Ack, request_uri);
        self.fill_common_headers(&mut req, "ACK", invite_cseq, &route_headers, false);
        req
    }

    /// BYE (RFC 3261 §15.1.1)。
    pub fn build_bye(&self) -> SipRequest {
        let cseq = self.local_cseq.fetch_add(1, Ordering::SeqCst);
        let (request_uri, route_headers) = self.compute_request_uri_and_route();
        let mut req = SipRequest::new(SipMethod::Bye, request_uri);
        self.fill_common_headers(&mut req, "BYE", cseq, &route_headers, true);
        req
    }

    /// Re-INVITE。Session Timer (RFC 4028) の更新用にも使う。
    ///
    /// - `sdp_body`: Offer SDP (なければ空)
    /// - `session_expires_secs`: Session-Expires 値 (UAC refresher)
    /// - `min_se_secs`: Min-SE
    pub fn build_reinvite(
        &self,
        sdp_body: Option<&[u8]>,
        session_expires_secs: u32,
        min_se_secs: u32,
    ) -> SipRequest {
        let cseq = self.local_cseq.fetch_add(1, Ordering::SeqCst);
        let (request_uri, route_headers) = self.compute_request_uri_and_route();
        let mut req = SipRequest::new(SipMethod::Invite, request_uri);
        self.fill_common_headers(&mut req, "INVITE", cseq, &route_headers, true);
        // RFC 4028 Session Timer
        req.headers.set(
            "Session-Expires",
            format!("{};refresher=uac", session_expires_secs),
        );
        req.headers.set("Min-SE", min_se_secs.to_string());
        req.headers.set("Supported", "timer");
        if let Some(body) = sdp_body {
            req.headers.set("Content-Type", "application/sdp");
            req.body = body.to_vec();
        }
        req
    }

    /// 現在の local CSeq 値 (次に発行される値)。テスト用。
    pub fn next_cseq(&self) -> u32 {
        self.local_cseq.load(Ordering::SeqCst)
    }

    pub fn route_set(&self) -> &[String] {
        &self.route_set
    }

    pub fn remote_target(&self) -> &str {
        &self.remote_target
    }

    /// Route set の先頭 URI が `lr` (loose router) を含むかで Request-URI と
    /// Route ヘッダの組み立て方が変わる (RFC 3261 §12.2.1.1).
    ///
    /// 戻り値: (Request-URI, Route ヘッダ値リスト)
    fn compute_request_uri_and_route(&self) -> (String, Vec<String>) {
        if self.route_set.is_empty() {
            return (self.remote_target.clone(), Vec::new());
        }
        if route_uri_has_lr(&self.route_set[0]) {
            // loose routing: Request-URI = remote target, Route = route_set
            (self.remote_target.clone(), self.route_set.clone())
        } else {
            // strict routing: Request-URI = 先頭 Route, Route = 残り + remote target
            // (RFC 3261 §12.2.1.1 互換動作)
            let request_uri = extract_uri(&self.route_set[0]);
            let mut route = self.route_set[1..].to_vec();
            route.push(format!("<{}>", self.remote_target));
            (request_uri, route)
        }
    }

    /// 共通ヘッダを埋める。
    fn fill_common_headers(
        &self,
        req: &mut SipRequest,
        method_name: &str,
        cseq: u32,
        route_headers: &[String],
        with_contact: bool,
    ) {
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch={}", self.sent_by, new_branch()),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers.set(
            "From",
            format!("<{}>;tag={}", self.local_uri, self.id.local_tag),
        );
        req.headers.set(
            "To",
            format!("<{}>;tag={}", self.remote_uri, self.id.remote_tag),
        );
        req.headers.set("Call-ID", &self.id.call_id);
        req.headers.set("CSeq", format!("{} {}", cseq, method_name));
        for route in route_headers {
            // Route ヘッダは name-addr (山括弧付き) 形式を期待。
            // route_set に既に山括弧が付いていればそのまま、なければ付ける。
            if route.starts_with('<') {
                req.headers.add("Route", route);
            } else {
                req.headers.add("Route", format!("<{}>", route));
            }
        }
        if with_contact {
            req.headers
                .set("Contact", format!("<{}>", self.local_contact));
        }
        req.headers.set("User-Agent", "hikari-sip/0.1");
    }
}

/// `name-addr` 形式 ("Display" <sip:...;param>) または `addr-spec` から
/// URI 部 (`sip:user@host;params`) を取り出す。`?` 等の追加パラメータは保持。
fn extract_uri(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start + 1..].find('>') {
            return trimmed[start + 1..start + 1 + end].to_string();
        }
    }
    // パラメータ ; を URI から除去するのは name-addr では誤りなので、
    // addr-spec 形式 (山括弧なし) のときに限り tag 等のパラメータを切り落とす。
    // RFC 3261 §20.10: Contact が addr-spec のときヘッダ パラメータと URI
    // パラメータの区別がつかないので山括弧推奨。互換のため最初の ; までを採用。
    if let Some((uri, _)) = trimmed.split_once(';') {
        return uri.trim().to_string();
    }
    trimmed.to_string()
}

/// `From: "x" <sip:..>;tag=abc` 等から tag 値を取り出す。
fn parse_tag(value: &str) -> Option<&str> {
    for part in value.split(';').skip(1) {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("tag=") {
            return Some(rest);
        }
    }
    None
}

/// `12 INVITE` から番号 12 を取り出す。
fn parse_cseq_number(value: &str) -> Result<u32> {
    let num = value
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("CSeq が空"))?;
    num.parse::<u32>()
        .map_err(|_| anyhow!("CSeq 番号が数値でない: {}", value))
}

/// 1 ヘッダ行に複数 Route がある (`<sip:a>, <sip:b>`) ケースを分割する。
fn split_route_header(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = value.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b',' if depth == 0 => {
                let slice = value[start..i].trim();
                if !slice.is_empty() {
                    out.push(slice.to_string());
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = value[start..].trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

/// Route URI が `;lr` パラメータを含むか (loose routing)。
fn route_uri_has_lr(value: &str) -> bool {
    // <sip:proxy;lr> または <sip:proxy>;lr どちらにも対応。
    if let Some(start) = value.find('<') {
        if let Some(end) = value[start + 1..].find('>') {
            let inside = &value[start + 1..start + 1 + end];
            if inside.split(';').any(|p| p.trim() == "lr") {
                return true;
            }
        }
    }
    value.split(';').any(|p| p.trim() == "lr")
}

/// ダイアログ生成や Re-INVITE で使う共通 SIP ヘッダ用ユーティリティ。
pub fn copy_via_to_response_headers(_resp: &SipHeaders) {
    // ダイアログ層では応答生成は行わないので no-op。
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::{SipMethod, SipRequest, SipResponse};

    fn invite_request() -> SipRequest {
        let mut req = SipRequest::new(SipMethod::Invite, "sip:0312345678@ntt-east.ne.jp");
        req.headers.set(
            "Via",
            "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKinvite1",
        );
        req.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=alice");
        req.headers.set("To", "<sip:0312345678@ntt-east.ne.jp>");
        req.headers.set("Call-ID", "callid-xyz@hikari-sip");
        req.headers.set("CSeq", "100 INVITE");
        req.headers
            .set("Contact", "<sip:caller@[2001:db8::1]:5060>");
        req
    }

    fn ok_response_with_route() -> SipResponse {
        let mut headers = SipHeaders::new();
        headers.set(
            "Via",
            "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKinvite1",
        );
        headers.set("From", "<sip:caller@ntt-east.ne.jp>;tag=alice");
        headers.set("To", "<sip:0312345678@ntt-east.ne.jp>;tag=bob");
        headers.set("Call-ID", "callid-xyz@hikari-sip");
        headers.set("CSeq", "100 INVITE");
        headers.set("Contact", "<sip:0312345678@[2001:db8::99]:5060>");
        headers.add("Record-Route", "<sip:proxy1.ntt-east.ne.jp;lr>");
        headers.add("Record-Route", "<sip:proxy2.ntt-east.ne.jp;lr>");
        SipResponse {
            status_code: 200,
            reason: "OK".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    fn cfg() -> DialogConfig {
        DialogConfig {
            local_uri: "sip:caller@ntt-east.ne.jp".to_string(),
            remote_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
            local_contact: "sip:caller@[2001:db8::1]:5060".to_string(),
            sent_by: "[2001:db8::1]:5060".to_string(),
        }
    }

    #[test]
    fn dialog_built_from_2xx_is_confirmed() {
        let inv = invite_request();
        let resp = ok_response_with_route();
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        assert_eq!(dlg.state(), DialogState::Confirmed);
        assert_eq!(dlg.id().call_id, "callid-xyz@hikari-sip");
        assert_eq!(dlg.id().local_tag, "alice");
        assert_eq!(dlg.id().remote_tag, "bob");
        assert_eq!(dlg.remote_target(), "sip:0312345678@[2001:db8::99]:5060");
    }

    #[test]
    fn record_route_is_reversed_for_uac() {
        let inv = invite_request();
        let resp = ok_response_with_route();
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        // 受信順は proxy1, proxy2。UAC から見た route_set は逆順 (proxy2, proxy1)
        assert_eq!(
            dlg.route_set(),
            vec![
                "<sip:proxy2.ntt-east.ne.jp;lr>".to_string(),
                "<sip:proxy1.ntt-east.ne.jp;lr>".to_string(),
            ]
        );
    }

    #[test]
    fn early_dialog_from_180_with_to_tag() {
        let inv = invite_request();
        let mut resp = ok_response_with_route();
        resp.status_code = 180;
        resp.reason = "Ringing".to_string();
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        assert_eq!(dlg.state(), DialogState::Early);
    }

    #[test]
    fn ack_for_2xx_uses_invite_cseq_and_new_branch() {
        let inv = invite_request();
        let resp = ok_response_with_route();
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        let ack = dlg.build_ack_for_2xx(100);
        assert_eq!(ack.method, SipMethod::Ack);
        assert_eq!(ack.headers.get("cseq").unwrap(), "100 ACK");
        // 新しい branch (元 INVITE と異なる)
        let via = ack.headers.get("via").unwrap();
        assert!(via.contains("branch=z9hG4bK"));
        assert!(!via.contains("z9hG4bKinvite1"));
        // Loose routing: Request-URI = remote target
        assert_eq!(ack.uri, "sip:0312345678@[2001:db8::99]:5060");
        // Route ヘッダがロード順 (UAC 視点) で並ぶ
        let routes = ack.headers.get_all("route");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0], "<sip:proxy2.ntt-east.ne.jp;lr>");
        assert_eq!(routes[1], "<sip:proxy1.ntt-east.ne.jp;lr>");
    }

    #[test]
    fn ack_via_does_not_contain_rport() {
        // NTT NGN 制約: rport 不付与
        let inv = invite_request();
        let resp = ok_response_with_route();
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        let ack = dlg.build_ack_for_2xx(100);
        let via = ack.headers.get("via").unwrap();
        assert!(
            !via.contains("rport"),
            "Via に rport があってはいけない: {}",
            via
        );
    }

    #[test]
    fn bye_increments_local_cseq() {
        let inv = invite_request();
        let resp = ok_response_with_route();
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        // 起点 CSeq は INVITE の 100 + 1 = 101
        let bye = dlg.build_bye();
        assert_eq!(bye.method, SipMethod::Bye);
        assert_eq!(bye.headers.get("cseq").unwrap(), "101 BYE");
        // 二度目はインクリメントされる
        let bye2 = dlg.build_bye();
        assert_eq!(bye2.headers.get("cseq").unwrap(), "102 BYE");
    }

    #[test]
    fn bye_uses_loose_routing_set() {
        let inv = invite_request();
        let resp = ok_response_with_route();
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        let bye = dlg.build_bye();
        assert_eq!(bye.uri, "sip:0312345678@[2001:db8::99]:5060");
        let routes = bye.headers.get_all("route");
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn reinvite_emits_session_timer_headers() {
        let inv = invite_request();
        let resp = ok_response_with_route();
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        let body = b"v=0\r\n";
        let reinv = dlg.build_reinvite(Some(body), 300, 90);
        assert_eq!(reinv.method, SipMethod::Invite);
        assert_eq!(
            reinv.headers.get("session-expires").unwrap(),
            "300;refresher=uac"
        );
        assert_eq!(reinv.headers.get("min-se").unwrap(), "90");
        assert_eq!(reinv.headers.get("supported").unwrap(), "timer");
        assert_eq!(
            reinv.headers.get("content-type").unwrap(),
            "application/sdp"
        );
        assert_eq!(reinv.body, body.to_vec());
        assert!(reinv.headers.get("contact").is_some());
    }

    #[test]
    fn strict_routing_rewrites_request_uri() {
        // RFC 3261 §12.2.1.1: 先頭 Route が ;lr を含まないとき strict routing
        let inv = invite_request();
        let mut resp = ok_response_with_route();
        // Record-Route を strict のものだけにする
        // SipHeaders は同名追加可能だが set/add で既存上書きはできないので
        // 直接全消去してから入れ直す。
        let mut new_headers = SipHeaders::new();
        for (k, v) in resp.headers.iter() {
            if k != "record-route" {
                new_headers.add(k, v);
            }
        }
        new_headers.add("Record-Route", "<sip:strict.example.com>");
        resp.headers = new_headers;

        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        let bye = dlg.build_bye();
        // strict: Request-URI = 先頭 Route
        assert_eq!(bye.uri, "sip:strict.example.com");
        // Route には残り (なし) + remote target
        let routes = bye.headers.get_all("route");
        assert_eq!(routes.len(), 1);
        assert!(routes[0].contains("[2001:db8::99]:5060"));
    }

    #[test]
    fn empty_route_set_uses_remote_target_directly() {
        let inv = invite_request();
        let mut resp = ok_response_with_route();
        // Record-Route を全削除
        let mut new_headers = SipHeaders::new();
        for (k, v) in resp.headers.iter() {
            if k != "record-route" {
                new_headers.add(k, v);
            }
        }
        resp.headers = new_headers;
        let dlg = Dialog::from_uac_response(&inv, &resp, cfg()).unwrap();
        let bye = dlg.build_bye();
        assert_eq!(bye.uri, "sip:0312345678@[2001:db8::99]:5060");
        assert!(bye.headers.get("route").is_none());
    }

    #[test]
    fn confirm_upgrades_early_dialog() {
        let inv = invite_request();
        let mut early_resp = ok_response_with_route();
        early_resp.status_code = 183;
        early_resp.reason = "Session Progress".to_string();
        let mut dlg = Dialog::from_uac_response(&inv, &early_resp, cfg()).unwrap();
        assert_eq!(dlg.state(), DialogState::Early);

        let final_resp = ok_response_with_route();
        dlg.confirm(&final_resp).unwrap();
        assert_eq!(dlg.state(), DialogState::Confirmed);
    }

    #[test]
    fn route_header_with_lr_param_outside_brackets() {
        assert!(route_uri_has_lr("<sip:proxy>;lr"));
        assert!(route_uri_has_lr("<sip:proxy;lr>"));
        assert!(!route_uri_has_lr("<sip:proxy>"));
    }

    #[test]
    fn extract_uri_handles_name_addr() {
        assert_eq!(extract_uri("\"Alice\" <sip:a@x>"), "sip:a@x");
        assert_eq!(extract_uri("<sip:a@x>"), "sip:a@x");
        assert_eq!(extract_uri("sip:a@x;tag=1"), "sip:a@x");
    }

    #[test]
    fn split_route_header_handles_multi_value_line() {
        let split = split_route_header("<sip:a;lr>, <sip:b;lr>");
        assert_eq!(split, vec!["<sip:a;lr>", "<sip:b;lr>"]);
    }
}
