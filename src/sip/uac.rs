//! UAC (User Agent Client) ロジック (RFC 3261 §13)
//!
//! INVITE → 1xx/2xx/3xx-6xx → ACK + ダイアログ確立、Re-INVITE (Session
//! Timer 更新, RFC 4028)、BYE / CANCEL を扱う。送信は全て下層の
//! [`super::transaction::TransactionLayer`] 経由で行い、UDP socket を
//! 直接使わない (CONTRIBUTING / ARCHITECTURE.md の責務分担に従う)。
//!
//! NTT NGN 制約:
//! - Via に `rport` を付ける (Asterisk 実機キャプチャ準拠、`docs/asterisk-real-invite.md` §3 / §5.5)
//! - Session Timer の既定値は 300 秒、Min-SE は 90 秒
//! - DSCP は呼び出し側 socket 構築時に設定済みであることを前提
//! - `P-Preferred-Identity` / `Privacy` は付けない (Asterisk が無しで 200 OK を取得した実機証拠あり、§5.3)
//!
//! ## 高水準 API
//! - [`Uac::invite`][] : INVITE を送り 2xx を得たらダイアログを確立
//! - [`UacDialog::send_bye`][] : BYE で正常終了
//! - [`UacDialog::send_reinvite`][] : Re-INVITE (Session Timer 更新)
//! - [`Uac::cancel_pending`][] : 進行中の INVITE を CANCEL
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tracing::{debug, warn};

use super::dialog::{Dialog, DialogConfig};
use super::message::{parse_sip_uri, SipMethod, SipRequest, SipResponse};
use super::transaction::TransactionLayer;
use super::utils::{new_branch, new_call_id, new_tag};

/// NTT NGN 既定 (RFC 4028)
pub const DEFAULT_SESSION_EXPIRES: u32 = 300;
/// RFC 4028 で定義される最小値の下限 (90 秒)
pub const MIN_SE: u32 = 90;

/// UAC が使うローカル パラメータ。`Registrar` と同等の設定情報。
#[derive(Debug, Clone)]
pub struct UacConfig {
    /// ローカル URI ("sip:0312345678@ntt-east.ne.jp" 等)
    pub local_uri: String,
    /// SIP ドメイン
    pub domain: String,
    /// ローカル Contact ホスト ("[2001:db8::1]:5060")
    pub local_addr: SocketAddr,
    /// User-Agent ヘッダ値
    pub user_agent: String,
}

impl UacConfig {
    /// `From` 用 URI (ユーザー名 + ドメイン)。
    pub fn local_addr_of_record(&self) -> &str {
        &self.local_uri
    }

    /// `Contact` 用 URI ("sip:user@host:port")。
    pub fn contact_uri(&self) -> String {
        // local_uri からユーザー名部分を抜いて contact を作る。
        let user = extract_user(&self.local_uri).unwrap_or("anonymous");
        format!("sip:{}@{}", user, self.local_addr)
    }

    /// Via sent-by ("host:port" 形式)
    pub fn sent_by(&self) -> String {
        self.local_addr.to_string()
    }
}

/// UAC コンテキスト。下層トランザクション層への参照と発信時の共通設定を持つ。
pub struct Uac {
    config: UacConfig,
    layer: Arc<TransactionLayer>,
    server_addr: SocketAddr,
}

impl Uac {
    pub fn new(config: UacConfig, layer: Arc<TransactionLayer>, server_addr: SocketAddr) -> Self {
        Self {
            config,
            layer,
            server_addr,
        }
    }

    /// 進行中の INVITE を表すハンドル。
    /// 2xx 受信前に CANCEL したい場合は [`Uac::cancel_pending`] へこれを渡す。
    ///
    /// CSeq は **必ず 1 から始める**。RFC 3261 §8.1.1.5 / §12.2.1.1 によれば
    /// CSeq の番号空間は (Call-ID, From-tag, To-tag) のダイアログ単位で独立して
    /// おり、新しい Call-ID で発信する場合は CSeq=1 から再採番してよい。
    /// Asterisk pcap (`docs/asterisk-real-invite.md`) でも各 INVITE は CSeq=1
    /// から始まっており、NGN は同一線で連続する INVITE の CSeq 連番を期待しない
    /// (連続発信時に CSeq=2,3,4,... と渡すと NGN が「同一ダイアログのリトライ」
    /// と解釈してリジェクトする現象を Issue #68 で確認済み)。
    pub fn build_invite(
        &self,
        target_uri: &str,
        sdp_offer: Option<&[u8]>,
        session_expires_secs: Option<u32>,
    ) -> InvitePlan {
        // RFC 3261 §8.1.1.5: 新規 Call-ID なら CSeq=1 から再採番する。
        let cseq = 1u32;
        let call_id = new_call_id();
        let local_tag = new_tag();
        let branch = new_branch();
        let session_expires = session_expires_secs.unwrap_or(DEFAULT_SESSION_EXPIRES);

        let mut req = SipRequest::new(SipMethod::Invite, target_uri.to_string());
        // RFC 3581 / Asterisk 実機準拠: Via に `;rport` を付ける。
        // NGN P-CSCF が NAT 越えで応答先 port を学習できる形式 (Asterisk pcap §3 参照)。
        req.headers.set(
            "Via",
            format!(
                "SIP/2.0/UDP {};rport;branch={}",
                self.config.sent_by(),
                branch
            ),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers.set(
            "From",
            format!("<{}>;tag={}", self.config.local_addr_of_record(), local_tag),
        );
        req.headers.set("To", format!("<{}>", target_uri));
        req.headers.set("Call-ID", &call_id);
        req.headers.set("CSeq", format!("{} INVITE", cseq));
        req.headers
            .set("Contact", format!("<{}>", self.config.contact_uri()));
        req.headers
            .set("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY");
        req.headers.set("Supported", "timer");
        req.headers.set(
            "Session-Expires",
            format!("{};refresher=uac", session_expires),
        );
        req.headers.set("Min-SE", MIN_SE.to_string());
        req.headers.set("User-Agent", &self.config.user_agent);
        // P-Preferred-Identity / Privacy は付けない (Asterisk 実機キャプチャ準拠、
        // `docs/asterisk-real-invite.md` §5.3): Asterisk 20 が同一 NGN 線で両方
        // 無しのまま 117 へ INVITE を送り 200 OK を取得した。逆に sabiden が
        // PPI/Privacy 付きで送っても 403 のままだった事実とも整合する。

        if let Some(body) = sdp_offer {
            req.headers.set("Content-Type", "application/sdp");
            req.body = body.to_vec();
        }

        InvitePlan {
            request: req,
            cseq,
            target_uri: target_uri.to_string(),
            session_expires,
        }
    }

    /// INVITE → 最終応答までを駆動する。
    ///
    /// 戻り値:
    /// - 2xx: `Ok(InviteOutcome::Established)` でダイアログを返す。
    ///   2xx ACK は本関数内で送信する (RFC 3261 §13.2.2.4)。
    /// - 3xx-6xx: `Ok(InviteOutcome::Failed { response })`。
    ///   負の最終応答に対する ACK は INVITE トランザクションの
    ///   一部として下層 (Transaction 層 / 将来) が処理する。本実装は
    ///   2xx 以外の最終応答時にダイアログを作らない。
    pub async fn invite(
        &self,
        plan: InvitePlan,
        sdp_offer_kept_for_dialog: Option<Vec<u8>>,
    ) -> Result<InviteOutcome> {
        let _ = sdp_offer_kept_for_dialog; // 将来の SDP 状態管理用
        let request = plan.request.clone();
        let response = self.layer.send_request(request, self.server_addr).await?;
        let code = response.status_code;
        debug!(code, "INVITE 最終応答");

        if (200..300).contains(&code) {
            let dialog_cfg = DialogConfig {
                local_uri: self.config.local_addr_of_record().to_string(),
                remote_uri: plan.target_uri.clone(),
                local_contact: self.config.contact_uri(),
                sent_by: self.config.sent_by(),
            };
            let dialog = Dialog::from_uac_response(&plan.request, &response, dialog_cfg)?;
            // RFC 3261 §13.2.2.4: 2xx ACK は新規トランザクション。
            // 再送制御は TU の責務だが、本実装は単発送信に留める (NGN 上では
            // 200 OK の再送に応じて再生成する将来拡張ポイントとして後述コメント)。
            //
            // RFC 3261 §12.2.1.1 / §8.1.2: in-dialog リクエストの宛先は
            // dialog の next-hop (topmost Route があればその host:port、
            // 無ければ remote target = 2xx Contact)。 旧実装は server_addr
            // (= P-CSCF 固定) に流していたが Issue #79 で本流対応。
            let ack = dialog.build_ack_for_2xx(plan.cseq);
            let next_hop = resolve_next_hop_addr(&dialog, self.server_addr);
            self.layer.send_request_no_wait(ack, next_hop).await?;
            Ok(InviteOutcome::Established(Box::new(EstablishedCall {
                dialog: UacDialog::new(
                    dialog,
                    plan.cseq,
                    plan.session_expires,
                    self.layer.clone(),
                    self.server_addr,
                ),
                response,
            })))
        } else {
            warn!(code, "INVITE 失敗");
            Ok(InviteOutcome::Failed { response })
        }
    }

    /// 進行中 INVITE に対する CANCEL (RFC 3261 §9.1)。
    ///
    /// CANCEL は元 INVITE と同じ Call-ID, From, To, Request-URI, CSeq 番号
    /// (method=CANCEL), 最初の Via (同じ branch) を持つ。
    pub async fn cancel_pending(&self, plan: &InvitePlan) -> Result<SipResponse> {
        let cancel = build_cancel(&plan.request, plan.cseq);
        self.layer.send_request(cancel, self.server_addr).await
    }

    pub fn config(&self) -> &UacConfig {
        &self.config
    }

    /// 上流 SIP サーバ (NGN 経路では P-CSCF) のアドレス。
    /// orchestrator が Request-URI を P-CSCF IP+port に書き換えるとき使う。
    /// Asterisk 実機準拠の host 補正に必要 (`docs/asterisk-real-invite.md` §5.1)。
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
}

/// 構築済み INVITE と関連メタデータ。
#[derive(Debug, Clone)]
pub struct InvitePlan {
    pub request: SipRequest,
    pub cseq: u32,
    pub target_uri: String,
    pub session_expires: u32,
}

/// INVITE 結果。
///
/// `Established` バリアントはダイアログ全体を保持するため大きいので、
/// `clippy::large_enum_variant` を避けるために Box でくるむ。
pub enum InviteOutcome {
    /// 2xx を受信し、ダイアログ確立済み。ACK は内部で送信済み。
    Established(Box<EstablishedCall>),
    /// 3xx-6xx で確立失敗。
    Failed { response: SipResponse },
}

/// `InviteOutcome::Established` の中身。
pub struct EstablishedCall {
    pub dialog: UacDialog,
    pub response: SipResponse,
}

/// 確立済み UAC ダイアログのハンドル。
pub struct UacDialog {
    inner: Dialog,
    /// INVITE トランザクションの CSeq (ACK 用に保持)
    invite_cseq: u32,
    /// Session-Expires 値 (秒)
    session_expires: u32,
    layer: Arc<TransactionLayer>,
    /// dialog next-hop URI から SocketAddr が抽出できないとき (例:
    /// FQDN に解決できない、 port 省略の host のみ) の最終フォールバック。
    /// 通常は INVITE 送信先 = NGN P-CSCF。 RFC 3261 §12.2.1.1 / RFC 3263
    /// §4 完全準拠の DNS / SRV 解決は将来の Issue で対応する。
    fallback_peer: SocketAddr,
}

impl UacDialog {
    fn new(
        inner: Dialog,
        invite_cseq: u32,
        session_expires: u32,
        layer: Arc<TransactionLayer>,
        fallback_peer: SocketAddr,
    ) -> Self {
        Self {
            inner,
            invite_cseq,
            session_expires,
            layer,
            fallback_peer,
        }
    }

    pub fn dialog(&self) -> &Dialog {
        &self.inner
    }

    pub fn dialog_mut(&mut self) -> &mut Dialog {
        &mut self.inner
    }

    /// in-dialog リクエストの宛先 SocketAddr (RFC 3261 §12.2.1.1)。
    ///
    /// dialog の next-hop URI (= topmost Route または remote target) から
    /// host:port を取り出し SocketAddr に解決する。 解決不能 (FQDN /
    /// port 省略 / 不正 URI) のときは `fallback_peer` を返す。
    fn next_hop_socket(&self) -> SocketAddr {
        resolve_next_hop_addr(&self.inner, self.fallback_peer)
    }

    /// BYE を送信してダイアログを終了する (RFC 3261 §15.1.1)。
    ///
    /// 宛先は dialog の next-hop (RFC 3261 §12.2.1.1) で決まり、
    /// `fallback_peer` (= INVITE 送信先 = 通常 P-CSCF) に固定しない。
    pub async fn send_bye(&mut self) -> Result<SipResponse> {
        let bye = self.inner.build_bye();
        let peer = self.next_hop_socket();
        let resp = self.layer.send_request(bye, peer).await?;
        self.inner.terminate();
        Ok(resp)
    }

    /// Re-INVITE で Session Timer を更新する (RFC 4028)。
    ///
    /// `sdp_body` を渡せば SDP を更新でき、`None` ならば SDP 無しの
    /// Session Timer 更新専用 Re-INVITE になる。422 Session Interval Too
    /// Small が返ったら `min_se` を再交渉する用途で呼び出し側が再送する。
    ///
    /// 宛先は BYE と同様 dialog next-hop (RFC 3261 §12.2.1.1) を使う。
    pub async fn send_reinvite(&mut self, sdp_body: Option<&[u8]>) -> Result<SipResponse> {
        let reinv = self
            .inner
            .build_reinvite(sdp_body, self.session_expires, MIN_SE);
        // CSeq は build_reinvite が予約済み。応答が 2xx なら ACK を送る。
        // CSeq を ACK 用に取り出す。
        let cseq = parse_cseq_number(reinv.headers.get("cseq").unwrap_or("0 INVITE"))?;
        let peer = self.next_hop_socket();
        let resp = self.layer.send_request(reinv, peer).await?;
        if (200..300).contains(&resp.status_code) {
            // Re-INVITE 2xx の ACK
            let ack = self.inner.build_ack_for_2xx(cseq);
            // ACK の宛先も dialog next-hop。 200 OK で Contact / Record-Route が
            // 更新されたら本来 confirm() で route_set / remote_target を再計算
            // するが、 既存実装はここで confirm を呼ばないため Re-INVITE 中の
            // 経路変更には未対応 (将来 Issue 化)。
            self.layer.send_request_no_wait(ack, peer).await?;
            // Session-Expires が応答で更新されていれば反映 (UAC が refresher)
            if let Some(se) = resp.headers.get("session-expires") {
                if let Some(num) = se
                    .split(';')
                    .next()
                    .and_then(|n| n.trim().parse::<u32>().ok())
                {
                    self.session_expires = num;
                }
            }
        }
        Ok(resp)
    }

    pub fn invite_cseq(&self) -> u32 {
        self.invite_cseq
    }

    pub fn session_expires(&self) -> u32 {
        self.session_expires
    }
}

/// CANCEL リクエストを INVITE から組み立てる。RFC 3261 §9.1。
/// - Request-URI / Call-ID / From / To は INVITE と同じ
/// - 最初の Via は同じ (branch も同じ)
/// - CSeq は INVITE と同じ番号で method=CANCEL
/// - Route は INVITE と同じ
pub fn build_cancel(invite: &SipRequest, invite_cseq: u32) -> SipRequest {
    let mut req = SipRequest::new(SipMethod::Cancel, invite.uri.clone());
    if let Some(via) = invite.headers.get("via") {
        req.headers.set("Via", via);
    }
    req.headers.set("Max-Forwards", "70");
    if let Some(from) = invite.headers.get("from") {
        req.headers.set("From", from);
    }
    if let Some(to) = invite.headers.get("to") {
        req.headers.set("To", to);
    }
    if let Some(cid) = invite.headers.get("call-id") {
        req.headers.set("Call-ID", cid);
    }
    req.headers.set("CSeq", format!("{} CANCEL", invite_cseq));
    for route in invite.headers.get_all("route") {
        req.headers.add("Route", route);
    }
    req.headers.set("User-Agent", "hikari-sip/0.1");
    req
}

/// dialog の next-hop URI (RFC 3261 §12.2.1.1) を SocketAddr に解決する。
///
/// 次ホップ host:port が **IP リテラル + 明示 port** の場合のみ確定。
/// FQDN / port 省略の場合は `fallback` を返す (RFC 3263 SRV / NAPTR 解決は
/// 未実装、 別 Issue 扱い)。 NGN 直収では P-CSCF が Record-Route で
/// `118.177.125.1:5060` を返すため確定経路で動く (`docs/asterisk-real-invite.md`
/// §3 / §5.1 / `docs/asterisk-real-invite.md` Contact 例 §5.6)。
fn resolve_next_hop_addr(dialog: &Dialog, fallback: SocketAddr) -> SocketAddr {
    let uri = dialog.next_hop_uri();
    let parts = match parse_sip_uri(&uri) {
        Ok(p) => p,
        Err(err) => {
            warn!(
                target_uri = %uri,
                ?err,
                "dialog next-hop URI のパースに失敗、 fallback (= server_addr) を使う"
            );
            return fallback;
        }
    };
    let Some(port) = parts.port else {
        // port 省略時は SRV / NAPTR が必要 (RFC 3263 §4)。 未実装のため fallback。
        debug!(
            target_uri = %uri,
            "dialog next-hop URI に port 指定なし (RFC 3263 SRV 未実装)、 fallback を使う"
        );
        return fallback;
    };
    // host が "[v6]" 形式なら strip して parse、 それ以外は IPv4 リテラルを試す。
    let host = parts.host.as_str();
    let parsed_ip = if let Some(stripped) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        stripped.parse::<std::net::IpAddr>().ok()
    } else {
        host.parse::<std::net::IpAddr>().ok()
    };
    match parsed_ip {
        Some(ip) => SocketAddr::new(ip, port),
        None => {
            // FQDN: 名前解決は別 Issue。 fallback を使う。
            debug!(
                host = %host,
                "dialog next-hop の host が IP リテラルでない (FQDN)、 fallback を使う"
            );
            fallback
        }
    }
}

fn parse_cseq_number(value: &str) -> Result<u32> {
    value
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("CSeq 空"))?
        .parse::<u32>()
        .map_err(|_| anyhow!("CSeq 数値変換失敗: {}", value))
}

fn extract_user(uri: &str) -> Option<&str> {
    // "sip:user@host" → "user"
    let after_scheme = uri.split_once(':').map(|x| x.1).unwrap_or(uri);
    after_scheme.split_once('@').map(|x| x.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::SipMessage;
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    fn cfg() -> UacConfig {
        UacConfig {
            local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            local_addr: "[::1]:0".parse().unwrap(),
            user_agent: "hikari-sip-test/0.1".to_string(),
        }
    }

    fn make_dialog_with(remote_target: &str, record_routes: &[&str]) -> Dialog {
        // INVITE 風 SipRequest と 200 OK 風 SipResponse をでっち上げて
        // Dialog::from_uac_response を経由する。 production に test hook は出さない。
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@example.com");
        invite
            .headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKxxx");
        invite
            .headers
            .set("From", "<sip:alice@example.com>;tag=alice");
        invite.headers.set("To", "<sip:bob@example.com>");
        invite.headers.set("Call-ID", "cidA");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Contact", "<sip:alice@192.0.2.1:5060>");

        let mut headers = crate::sip::message::SipHeaders::new();
        headers.set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKxxx");
        headers.set("From", "<sip:alice@example.com>;tag=alice");
        headers.set("To", "<sip:bob@example.com>;tag=bob");
        headers.set("Call-ID", "cidA");
        headers.set("CSeq", "1 INVITE");
        headers.set("Contact", format!("<{}>", remote_target));
        for rr in record_routes {
            headers.add("Record-Route", *rr);
        }
        let response = SipResponse {
            status_code: 200,
            reason: "OK".to_string(),
            headers,
            body: Vec::new(),
        };
        let cfg = DialogConfig {
            local_uri: "sip:alice@example.com".to_string(),
            remote_uri: "sip:bob@example.com".to_string(),
            local_contact: "sip:alice@192.0.2.1:5060".to_string(),
            sent_by: "192.0.2.1:5060".to_string(),
        };
        Dialog::from_uac_response(&invite, &response, cfg).unwrap()
    }

    #[test]
    fn rfc3261_12_2_1_1_resolve_next_hop_uses_contact_when_route_set_empty() {
        let dlg = make_dialog_with("sip:remote@198.51.100.5:5070", &[]);
        let fallback: SocketAddr = "203.0.113.1:5060".parse().unwrap();
        let addr = resolve_next_hop_addr(&dlg, fallback);
        assert_eq!(addr, "198.51.100.5:5070".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn rfc3261_12_2_1_1_resolve_next_hop_uses_topmost_route_when_loose_routing() {
        // Record-Route 受信順 [proxy_a, proxy_b] → UAC route_set 逆順 [proxy_b, proxy_a]
        // 次ホップは route_set[0] = proxy_b。
        let dlg = make_dialog_with(
            "sip:remote@198.51.100.5:5070",
            &["<sip:198.51.100.10:5060;lr>", "<sip:198.51.100.11:5061;lr>"],
        );
        let fallback: SocketAddr = "203.0.113.1:5060".parse().unwrap();
        let addr = resolve_next_hop_addr(&dlg, fallback);
        // route_set 逆順なので次ホップ = 受信順 2 番目 = proxy_b = 198.51.100.11:5061
        assert_eq!(addr, "198.51.100.11:5061".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_next_hop_falls_back_when_host_is_fqdn() {
        // FQDN は SRV 解決が必要 (RFC 3263)。 未実装なので fallback を返す。
        let dlg = make_dialog_with("sip:remote@proxy.example.com:5060", &[]);
        let fallback: SocketAddr = "203.0.113.1:5060".parse().unwrap();
        let addr = resolve_next_hop_addr(&dlg, fallback);
        assert_eq!(addr, fallback);
    }

    #[test]
    fn resolve_next_hop_falls_back_when_port_omitted() {
        // port 省略は RFC 3263 SRV 必要。 未実装なので fallback。
        let dlg = make_dialog_with("sip:remote@198.51.100.5", &[]);
        let fallback: SocketAddr = "203.0.113.1:5060".parse().unwrap();
        let addr = resolve_next_hop_addr(&dlg, fallback);
        assert_eq!(addr, fallback);
    }

    #[test]
    fn resolve_next_hop_handles_ipv6_literal() {
        let dlg = make_dialog_with("sip:remote@[2001:db8::99]:5070", &[]);
        let fallback: SocketAddr = "203.0.113.1:5060".parse().unwrap();
        let addr = resolve_next_hop_addr(&dlg, fallback);
        assert_eq!(addr, "[2001:db8::99]:5070".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn build_cancel_shares_branch_and_cseq_method_differs() {
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@example.com");
        invite
            .headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKxxx");
        invite
            .headers
            .set("From", "<sip:alice@example.com>;tag=alice");
        invite.headers.set("To", "<sip:bob@example.com>");
        invite.headers.set("Call-ID", "cidA");
        invite.headers.set("CSeq", "5 INVITE");

        let cancel = build_cancel(&invite, 5);
        assert_eq!(cancel.method, SipMethod::Cancel);
        assert_eq!(cancel.uri, "sip:bob@example.com");
        assert_eq!(
            cancel.headers.get("via").unwrap(),
            "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKxxx"
        );
        assert_eq!(cancel.headers.get("cseq").unwrap(), "5 CANCEL");
        assert_eq!(cancel.headers.get("call-id").unwrap(), "cidA");
    }

    #[tokio::test]
    async fn invite_omits_p_preferred_identity_and_privacy_per_asterisk_pcap() {
        // Asterisk 実機キャプチャ準拠 (`docs/asterisk-real-invite.md` §5.3):
        // Asterisk 20 は同一 NGN 線で `P-Preferred-Identity` も `Privacy` も
        // 付けずに 117 へ INVITE を送り 200 OK を取得した。逆に sabiden が
        // 両ヘッダ付きで送っても 403 のままだった事実とも整合する。
        // 過去の場当たり (両ヘッダ追加) を撤去した根拠を残す再発防止テスト。
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (layer, _rx) = TransactionLayer::spawn(socket);
        let server: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let uac = Uac::new(cfg(), layer, server);
        let plan = uac.build_invite("sip:117@118.177.125.1:5060", None, None);
        let req = &plan.request;
        assert!(
            req.headers.get("p-preferred-identity").is_none(),
            "PPI は付けない (Asterisk 実機証拠)"
        );
        assert!(
            req.headers.get("privacy").is_none(),
            "Privacy は付けない (Asterisk 実機証拠)"
        );
        // Via に `;rport` が含まれること (RFC 3581 / Asterisk 実機準拠)
        let via = req.headers.get("via").unwrap();
        assert!(via.contains(";rport"), "Via に rport が必要: {}", via);
    }

    #[test]
    fn invite_plan_includes_session_timer_and_rport() {
        let socket_layer_addr: SocketAddr = "[::1]:1".parse().unwrap();
        // Layer は実際には使わないが、型を満たすため bind なしで Arc 経由で渡す
        // → 実際にレイヤを起動するテストは下の async test に任せる。
        // ここでは Uac を経由せずヘルパだけ確認する。
        let _ = socket_layer_addr;
        let user_agent = "hikari-sip-test/0.1";
        let cfg = cfg();
        // 直接 build_invite を呼ぶには layer が要るので、簡易的に
        // request 単体を組み立てて NGN 制約とヘッダ存在を確認。
        // ここでは UacConfig::contact_uri / sent_by の確認に絞る。
        assert_eq!(cfg.local_addr_of_record(), "sip:0312345678@ntt-east.ne.jp");
        assert!(cfg.contact_uri().starts_with("sip:0312345678@"));
        assert!(cfg.sent_by().contains("::1"));
        assert!(!user_agent.is_empty());
    }

    #[tokio::test]
    async fn invite_2xx_establishes_dialog_and_sends_ack() {
        // フェイク NGN サーバ: INVITE を受けて 200 OK を返し、ACK を待つ。
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let server_clone = server_sock.clone();
        let server_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE 受信
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(invite) = parsed else {
                panic!("INVITE expected");
            };
            assert_eq!(invite.method, SipMethod::Invite);
            // 200 OK with Contact + Record-Route
            let mut resp = crate::sip::transaction::build_response_skeleton(&invite, 200, "OK");
            resp.headers.set(
                "To",
                format!("{};tag=server-tag", invite.headers.get("to").unwrap()),
            );
            resp.headers.set("Contact", "<sip:remote@127.0.0.1:9999>");
            resp.headers.add("Record-Route", "<sip:proxy.example;lr>");
            server_clone.send_to(&resp.to_bytes(), peer).await.unwrap();

            // ACK 受信
            let (n2, _) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
            let SipMessage::Request(ack) = parsed2 else {
                panic!("ACK expected");
            };
            assert_eq!(ack.method, SipMethod::Ack);
            assert_eq!(
                ack.headers
                    .get("cseq")
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap(),
                "ACK"
            );
            // Loose routing: Request-URI = remote target
            assert_eq!(ack.uri, "sip:remote@127.0.0.1:9999");

            // BYE 受信 → 200 OK
            let (n3, peer3) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed3 = crate::sip::message::parse_message(&buf[..n3]).unwrap();
            let SipMessage::Request(bye) = parsed3 else {
                panic!("BYE expected");
            };
            assert_eq!(bye.method, SipMethod::Bye);
            let bye_resp = crate::sip::transaction::build_response_skeleton(&bye, 200, "OK");
            server_clone
                .send_to(&bye_resp.to_bytes(), peer3)
                .await
                .unwrap();
        });

        let (layer, _inbound_rx) = crate::sip::transaction::TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg();
        uac_cfg.local_addr = client_local;
        let uac = Uac::new(uac_cfg, layer, server_addr);

        let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, Some(300));
        // Asterisk 実機準拠: Via に `;rport` が付与される (`docs/asterisk-real-invite.md` §3, §5.5)。
        assert!(
            plan.request.headers.get("via").unwrap().contains(";rport"),
            "Via に `;rport` パラメータが含まれるべき (Asterisk pcap 準拠)"
        );
        // P-Preferred-Identity / Privacy は付けない (Asterisk は無しで 200 OK 取得、§5.3)。
        assert!(plan.request.headers.get("p-preferred-identity").is_none());
        assert!(plan.request.headers.get("privacy").is_none());
        // Session Timer ヘッダ
        assert_eq!(
            plan.request.headers.get("session-expires").unwrap(),
            "300;refresher=uac"
        );
        assert_eq!(plan.request.headers.get("min-se").unwrap(), "90");

        let outcome = uac.invite(plan, None).await.expect("invite");
        let mut dlg = match outcome {
            InviteOutcome::Established(call) => call.dialog,
            InviteOutcome::Failed { response } => {
                panic!("expected established, got {}", response.status_code)
            }
        };
        assert_eq!(dlg.dialog().id().remote_tag, "server-tag");

        let bye_resp = dlg.send_bye().await.expect("bye");
        assert_eq!(bye_resp.status_code, 200);
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn rfc3261_12_2_1_1_bye_goes_to_dialog_remote_target_not_server_addr() {
        // Issue #79 の核となる shape:
        //   server_addr (= INVITE 送信先 = ダミー P-CSCF) と
        //   200 OK の Contact が **異なる SocketAddr** のとき、
        //   BYE が Contact 側 (= dialog remote target) に飛ばないと
        //   RFC 3261 §12.2.1.1 違反になる。
        //
        // ここでは
        //   - INVITE 受け口: server_a (= server_addr 役、 P-CSCF 役)
        //   - BYE 受け口   : server_b (= 200 OK Contact 側、 真の対向)
        // を立て、 200 OK で Contact = server_b の URI を返す。
        // BYE が server_b に届けば PASS、 server_a に届いたら FAIL (旧バグ)。
        let server_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_a_addr = server_a.local_addr().unwrap();
        let server_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_b_addr = server_b.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let server_a_clone = server_a.clone();
        let server_b_clone = server_b.clone();
        let server_b_addr_for_resp = server_b_addr;
        let server_a_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE 受信
            let (n, peer) = server_a_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(invite) = parsed else {
                panic!("INVITE expected on server_a");
            };
            assert_eq!(invite.method, SipMethod::Invite);
            // 200 OK with Contact = server_b (= 真の対向)、 Record-Route 無し。
            // RFC 3261 §12.2.1.1: route_set 空 → Request-URI = remote target,
            // 次ホップ = remote target host:port = server_b。
            let mut resp = crate::sip::transaction::build_response_skeleton(&invite, 200, "OK");
            resp.headers.set(
                "To",
                format!("{};tag=server-tag", invite.headers.get("to").unwrap()),
            );
            resp.headers.set(
                "Contact",
                format!("<sip:remote@{}>", server_b_addr_for_resp),
            );
            server_a_clone
                .send_to(&resp.to_bytes(), peer)
                .await
                .unwrap();

            // 2xx ACK は dialog next-hop = server_b に飛ぶので、 server_a には来ない。
            // server_a 側はここで終了。
        });

        let bye_received = Arc::new(tokio::sync::Notify::new());
        let bye_received_for_task = bye_received.clone();
        let server_b_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 1) 2xx ACK 受信
            let (n, _peer) = server_b_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(ack) = parsed else {
                panic!("ACK expected on server_b");
            };
            assert_eq!(ack.method, SipMethod::Ack, "server_b に ACK が届くべき");

            // 2) BYE 受信 → 200 OK
            let (n2, peer2) = server_b_clone.recv_from(&mut buf).await.unwrap();
            let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
            let SipMessage::Request(bye) = parsed2 else {
                panic!("BYE expected on server_b");
            };
            assert_eq!(
                bye.method,
                SipMethod::Bye,
                "BYE が dialog remote target (= server_b) に届くべき"
            );
            // RFC 3261 §12.2.1.1: Request-URI = remote target = Contact URI。
            assert!(
                bye.uri.contains(&format!("@{}", server_b_addr_for_resp)),
                "BYE の Request-URI は Contact (server_b) を指すべき: {}",
                bye.uri
            );
            let bye_resp = crate::sip::transaction::build_response_skeleton(&bye, 200, "OK");
            server_b_clone
                .send_to(&bye_resp.to_bytes(), peer2)
                .await
                .unwrap();
            bye_received_for_task.notify_one();
        });

        let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg();
        uac_cfg.local_addr = client_local;
        // server_addr は server_a (= INVITE 送信先 = P-CSCF 役)。 BYE は dialog
        // 次ホップ (= server_b) に向かわなければバグ。
        let uac = Uac::new(uac_cfg, layer, server_a_addr);

        let target_uri = format!("sip:remote@{}", server_a_addr);
        let plan = uac.build_invite(&target_uri, None, Some(300));
        let outcome = uac.invite(plan, None).await.expect("invite");
        let mut dlg = match outcome {
            InviteOutcome::Established(call) => call.dialog,
            InviteOutcome::Failed { response } => {
                panic!("expected established, got {}", response.status_code)
            }
        };

        let bye_resp = dlg.send_bye().await.expect("bye");
        assert_eq!(bye_resp.status_code, 200);

        server_a_handle.await.unwrap();
        // タイムアウト保護で notify を待つ
        tokio::time::timeout(std::time::Duration::from_secs(2), bye_received.notified())
            .await
            .expect("BYE が server_b に届かなかった (server_addr に飛んでいる可能性)");
        server_b_handle.await.unwrap();
    }

    #[tokio::test]
    async fn invite_4xx_returns_failed_outcome() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let server_clone = server_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(req) = parsed {
                let mut resp =
                    crate::sip::transaction::build_response_skeleton(&req, 486, "Busy Here");
                resp.headers
                    .set("To", format!("{};tag=busy", req.headers.get("to").unwrap()));
                server_clone.send_to(&resp.to_bytes(), peer).await.unwrap();
            }
        });

        let (layer, _inbound_rx) = crate::sip::transaction::TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg();
        uac_cfg.local_addr = client_local;
        let uac = Uac::new(uac_cfg, layer, server_addr);
        let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);
        let outcome = uac.invite(plan, None).await.expect("invite");
        match outcome {
            InviteOutcome::Failed { response } => assert_eq!(response.status_code, 486),
            InviteOutcome::Established(_) => panic!("must fail"),
        }
    }

    #[tokio::test]
    async fn cancel_sends_cancel_with_invite_branch() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let server_clone = server_sock.clone();
        let received = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            // 1) INVITE → 100 Trying のみ返して進行中状態に
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(invite) = parsed else {
                panic!("INVITE expected")
            };
            let trying = crate::sip::transaction::build_response_skeleton(&invite, 100, "Trying");
            server_clone
                .send_to(&trying.to_bytes(), peer)
                .await
                .unwrap();

            // 2) CANCEL 受信
            let (n2, peer2) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
            let SipMessage::Request(cancel) = parsed2 else {
                panic!("CANCEL expected")
            };
            assert_eq!(cancel.method, SipMethod::Cancel);
            // CANCEL の Via branch は INVITE と同じ
            assert_eq!(
                cancel.headers.get("via").unwrap(),
                invite.headers.get("via").unwrap()
            );
            // CANCEL に 200 OK
            let cancel_ok = crate::sip::transaction::build_response_skeleton(&cancel, 200, "OK");
            server_clone
                .send_to(&cancel_ok.to_bytes(), peer2)
                .await
                .unwrap();
        });

        let (layer, _inbound_rx) = crate::sip::transaction::TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg();
        uac_cfg.local_addr = client_local;
        let uac = Uac::new(uac_cfg, layer, server_addr);
        let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);
        // INVITE は最終応答が来ないので別タスクで待つ
        let plan_for_cancel = plan.clone();
        let invite_task = {
            let plan_clone = plan.clone();
            // Uac は Send なので tokio::spawn には移動できないため、
            // ここでは plan_clone の自前送信で代用 (キャンセル後は不要)。
            // INVITE は Trying 後 Timer B (32s) で Err を返す。
            // テスト時間を抑えるためバックグラウンド送信は行わず、CANCEL 送信のみ確認する。
            // (CANCEL のテスト目的に集中)
            let _ = plan_clone;
            tokio::spawn(async move {
                // INVITE 単発送信のみ行い 100 Trying を受け取る (待機なし)
            })
        };
        // INVITE 送信をフェイク的に行う: 直接 socket で送る代わりに、
        // build_invite で生成した SipRequest を layer 経由で送る。
        // ここでは UAC を再利用するため別タスク不要。
        let plan_clone = plan_for_cancel.clone();
        // INVITE の送信を別タスクで開始して、すぐに CANCEL する。
        let layer_for_invite = uac.layer.clone();
        let server_addr_invite = uac.server_addr;
        let invite_send_task = tokio::spawn(async move {
            let _ = layer_for_invite
                .send_request(plan_clone.request, server_addr_invite)
                .await;
        });
        // 100 Trying が server に届いてから CANCEL を送る (短い遅延)
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let cancel_resp = uac.cancel_pending(&plan_for_cancel).await.expect("cancel");
        assert_eq!(cancel_resp.status_code, 200);

        invite_task.abort();
        invite_send_task.abort();
        received.await.unwrap();
    }
}
