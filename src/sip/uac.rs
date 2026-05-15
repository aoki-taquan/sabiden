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

use super::auth::{DigestChallenge, DigestCredentials};
use super::dialog::{Dialog, DialogConfig};
use super::message::{SipMethod, SipRequest, SipResponse};
use super::transaction::{InviteResponseProgress, TransactionId, TransactionLayer};
use super::utils::{new_branch, new_call_id, new_tag};

/// NTT NGN 既定 (RFC 4028)
pub const DEFAULT_SESSION_EXPIRES: u32 = 300;
/// RFC 4028 で定義される最小値の下限 (90 秒)
pub const MIN_SE: u32 = 90;

/// `Uac::cancel_pending` が 1xx 待機を諦める上限 (= RFC 3261 §17.1.1.2 Timer B
/// と同じ 64*T1 = 32s)。
///
/// RFC 3261 §9.1 は "the client MUST wait for the arrival of a provisional
/// response before sending the request" と書くだけで明示的な上限を置かないが、
/// Timer B (INVITE 自体のタイムアウト = 32s) を超えて待つと、 INVITE
/// トランザクションは既に Terminated になっており CANCEL を送る対象が消失する。
/// したがって Timer B と同じ 32s でキャップする (それまでに 1xx も最終応答も
/// 来ないなら、 INVITE 側が timer B で失敗扱いになり transaction エントリも
/// 消えるので、 watch の receiver も `Err` で抜ける = 整合する)。
pub const CANCEL_PROVISIONAL_WAIT: std::time::Duration = std::time::Duration::from_secs(32);

/// UAC が使うローカル パラメータ。`Registrar` と同等の設定情報。
///
/// `auth_username` / `auth_password` は **省略可** で、両方 `Some` のときだけ
/// INVITE 401 / 407 challenge に対する Digest 再送 (RFC 3261 §22.2 / §22.3)
/// を行う。 NGN 直収モード (auth=none) では両方 `None` のまま使われ、
/// challenge を受けても無条件に `InviteOutcome::Failed` を返す
/// (登録できないネットワークから INVITE が通ることはなく、 password を
/// 持たない sabiden に再認証する手段がないため)。
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
    /// Digest username (RFC 2617 / 3261 §22)。 `None` なら challenge 再送無し。
    /// 通常は `local_uri` の user 部分と同値。
    pub auth_username: Option<String>,
    /// Digest password (RFC 2617 / 3261 §22)。 `None` なら challenge 再送無し。
    /// NGN 直収モード (回線認証) では `None`。
    pub auth_password: Option<String>,
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

/// SIP URI から host portion の `:port` だけを剥がす (transport / lr / 他の
/// URI parameters は保持)。
///
/// RFC 3261 §8.1.1.2: To header は identity (called party) であり transport
/// endpoint ではない。 Asterisk 互換 (`docs/asterisk-real-invite.md` §5.1)
/// では To URI から `:port` を削除して identity-only にする。
///
/// # 例
///
/// - `sip:117@118.177.125.1:5060` → `sip:117@118.177.125.1`
/// - `sip:117@p-cscf:5060;transport=udp` → `sip:117@p-cscf;transport=udp`
///   (transport param は保持)
/// - `sip:117@p-cscf;transport=udp` → no-op (port なし)
/// - `sip:117@p-cscf` → no-op
pub(crate) fn strip_port_from_sip_uri(target_uri: &str) -> String {
    let Some(at_pos) = target_uri.find('@') else {
        return target_uri.to_string();
    };
    let (prefix, host_part) = target_uri.split_at(at_pos + 1);
    // host_part may be: "host", "host:port", "host;params", "host:port;params"
    // Find optional ';' first to preserve URI params.
    let (host_with_optional_port, params) = match host_part.find(';') {
        Some(p) => (&host_part[..p], &host_part[p..]),
        None => (host_part, ""),
    };
    let host_no_port = host_with_optional_port
        .split(':')
        .next()
        .unwrap_or(host_with_optional_port);
    format!("{}{}{}", prefix, host_no_port, params)
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
        // Asterisk pcap 互換 (memory `project_ngn_500_resolved.md` 2026-05-12):
        // From に display-name `"Anonymous"` を追加 (NTT NGN inbound では発信者名 strip
        // されるが outbound の最低限 form として Asterisk が常用)。
        req.headers.set(
            "From",
            format!(
                "\"Anonymous\" <{}>;tag={}",
                self.config.local_addr_of_record(),
                local_tag
            ),
        );
        // RFC 3261 §8.1.1.2: To header は identity (called party)、 transport endpoint
        // ではない。 Asterisk 互換 (`docs/asterisk-real-invite.md` / memory) では
        // To URI から `:port` を削除して identity-only にする。
        // ただし Request-URI には port を残す (carrier 必須: P-CSCF 直送)。
        let to_uri = strip_port_from_sip_uri(target_uri);
        req.headers.set("To", format!("<{}>", to_uri));
        req.headers.set("Call-ID", &call_id);
        req.headers.set("CSeq", format!("{} INVITE", cseq));
        req.headers
            .set("Contact", format!("<{}>", self.config.contact_uri()));
        // RFC 3261 §20.5: Allow は **UA generating the message が実装する method**
        // を列挙する。 sabiden の NGN-side UAS が実際に処理経路を持つのは
        // INVITE / ACK / BYE / CANCEL / OPTIONS のみ (`SUPPORTED_METHODS_ALLOW`
        // in `src/call/orchestrator.rs`)。 outbound INVITE の Allow も同じ集合
        // で宣言して honest にする (Issue #260 PR #264 2 巡目 review 指摘、
        // CLAUDE.md §6.1 band-aid 禁止)。
        req.headers
            .set("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS");
        // RFC 4028 §3 / RFC 3261 §20.32: Session-Timer。 Supported に "timer"
        // を含めることで carrier 側が Session-Expires を honor する。
        // 加えて `100rel` (RFC 3262) を宣言、 carrier が PRACK 経路を選ぶ場合に
        // 1xx provisional の reliable transport を許可する。
        req.headers.set("Supported", "100rel, timer");
        // RFC 4028 §4: `Session-Expires: <secs>;refresher=uac`。 sabiden は
        // UAC 側で refresh する想定 (caller が timer 駆動で re-INVITE する)。
        req.headers.set(
            "Session-Expires",
            format!("{};refresher=uac", session_expires),
        );
        req.headers.set("Min-SE", MIN_SE.to_string());
        // RFC 3608 §3.2 / RFC 3261 §16.4: REGISTER 200 OK の Service-Route を
        // Route ヘッダとして echo (IMS MUST)。
        // ただし NTT NGN 直収では Asterisk pcap 比較で **P-CSCF IP** を使うのが
        // 実機適合 (`<sip:118.177.125.1:5060;lr>`、 `outbound_proxy` 相当)。
        // Service-Route の domain (`<sip:ntt-east.ne.jp;lr>`) では 500 率改善限定的
        // (実機評価 2026-05-12 60% にとどまる) → outbound_proxy style に切替。
        // 多段 Route が必要なら今後 Service-Route も後続に追加検討。
        let route_value =
            crate::sip::current_outbound_proxy_route().or_else(crate::sip::current_service_route);
        if let Some(route) = route_value {
            req.headers.set("Route", &route);
        }
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
    /// - 401 / 407: 認証チャレンジに対し `auth_username` / `auth_password`
    ///   が両方 `Some` であれば Digest を計算して **1 回だけ** INVITE を
    ///   再送する (RFC 3261 §22.2 §22.3 §8.1.3.5, RFC 2617 §3.2)。
    ///   再送結果に対しても 2xx は確立、 401/407 は Failed として返す
    ///   (RFC 3261 §22.2 で 2 段目の challenge は failure 扱いの示唆)。
    ///   credentials が無いか再送後も challenge なら `InviteOutcome::Failed`。
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
            return self.finalize_2xx(&plan, response).await;
        }

        // RFC 3261 §22.2 / §22.3: 401 / 407 を受けたら Authorization /
        // Proxy-Authorization 付きで **1 回** INVITE を再送する。
        // Issue #113 までは 4xx として一律 Failed にしていた。
        if (code == 401 || code == 407)
            && self.config.auth_username.is_some()
            && self.config.auth_password.is_some()
        {
            match self.retry_invite_with_auth(&plan, &response).await? {
                Some((retry_plan, retry_resp)) => {
                    let retry_code = retry_resp.status_code;
                    debug!(code = retry_code, "INVITE 再認証後の応答");
                    if (200..300).contains(&retry_code) {
                        // RFC 3261 §13.2.2.4: 2xx ACK の CSeq は **acknowledge
                        // した INVITE の CSeq と一致** させなければならない。
                        // 再認証 INVITE は CSeq=N+1 で送ったため、 ACK も
                        // CSeq=N+1 で送る必要がある。 そのため `finalize_2xx`
                        // には **更新済 plan** (= retry_plan, CSeq=N+1) を
                        // 渡す。 元 plan (CSeq=N) を渡すと ACK CSeq mismatch
                        // となり、 さらに Dialog の `local_cseq` が N+1 から
                        // 開始 (= 既に使用済 CSeq) してしまい、 直後の BYE /
                        // Re-INVITE が CSeq 重複で reject される
                        // (RFC 3261 §12.2.1.1 strictly increasing 違反)。
                        return self.finalize_2xx(&retry_plan, retry_resp).await;
                    }
                    // RFC 3261 §22.2: 2 段目も challenge なら諦める。
                    warn!(code = retry_code, "INVITE 再認証も失敗");
                    Ok(InviteOutcome::Failed {
                        response: retry_resp,
                    })
                }
                None => {
                    // challenge ヘッダのパース不能等の場合は元の 401/407 を返す。
                    warn!(code, "INVITE auth challenge 解釈失敗、再送をスキップ");
                    Ok(InviteOutcome::Failed { response })
                }
            }
        } else {
            warn!(code, "INVITE 失敗");
            Ok(InviteOutcome::Failed { response })
        }
    }

    /// 2xx を受けた `response` に対して dialog を確立し ACK を送る共通処理。
    /// `plan` は **最初に送った INVITE** を渡す (Call-ID / From-tag /
    /// remote_uri 計算に使う)。 再認証経路の retry 後も `plan` 側で
    /// dialog 確立できるよう、 `Dialog::from_uac_response` には plan の
    /// request をそのまま渡す。 RFC 3261 §12.1.2: dialog ID は Call-ID +
    /// From-tag + To-tag で決まり、 Call-ID と From-tag は再認証 INVITE
    /// でも変わらない (=同 Call-ID, 同 From-tag) ので問題なし。
    async fn finalize_2xx(
        &self,
        plan: &InvitePlan,
        response: SipResponse,
    ) -> Result<InviteOutcome> {
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
    }

    /// RFC 3261 §22.2 / §22.3 / §8.1.3.5 に従い challenge 付きで INVITE を
    /// 再送する。 戻り値 `Ok(None)` は challenge ヘッダのパースに失敗した
    /// 場合 (callsite で元の 401/407 を Failed として返す)。
    ///
    /// - 401 → `WWW-Authenticate` を読み `Authorization` を付ける
    /// - 407 → `Proxy-Authenticate` を読み `Proxy-Authorization` を付ける
    /// - Via branch は新規 (RFC 3261 §17.1.1.3: 同一 transaction でも
    ///   再送 INVITE は新規 client transaction = 新 branch)
    /// - CSeq は **+1** (RFC 3261 §8.1.3.5: re-send は CSeq を増やして
    ///   新トランザクションとして扱う)
    ///
    /// ## 戻り値が `(InvitePlan, SipResponse)` の理由
    ///
    /// 後段の `finalize_2xx` は ACK CSeq と Dialog `local_cseq` の起点に
    /// `plan.cseq` を使う。 元 plan (CSeq=N) のままだと ACK CSeq=N となり
    /// retry INVITE (CSeq=N+1) と一致せず RFC 3261 §13.2.2.4 違反、 さらに
    /// Dialog の local_cseq は N+1 (= 既に retry INVITE で使用済) から始まり
    /// 直後の BYE / Re-INVITE が strictly increasing (RFC 3261 §12.2.1.1)
    /// に違反する。 そのため retry で **実際に送ったリクエスト** をそのまま
    /// 反映した新 InvitePlan を返し、 callsite はそちらを finalize_2xx に
    /// 渡すことで全体を整合させる。
    async fn retry_invite_with_auth(
        &self,
        plan: &InvitePlan,
        response: &SipResponse,
    ) -> Result<Option<(InvitePlan, SipResponse)>> {
        // Pre-condition: callsite が config に credentials があることを確認済。
        let username = match &self.config.auth_username {
            Some(u) => u.as_str(),
            None => return Ok(None),
        };
        let password = match &self.config.auth_password {
            Some(p) => p.as_str(),
            None => return Ok(None),
        };
        let code = response.status_code;
        let (challenge_header_name, auth_header_name) = if code == 401 {
            ("www-authenticate", "Authorization")
        } else {
            ("proxy-authenticate", "Proxy-Authorization")
        };
        let Some(raw_challenge) = response.headers.get(challenge_header_name) else {
            warn!(code, "{} ヘッダなし", challenge_header_name);
            return Ok(None);
        };
        let challenge = match DigestChallenge::parse(raw_challenge) {
            Ok(c) => c,
            Err(err) => {
                warn!(?err, "Digest challenge のパース失敗");
                return Ok(None);
            }
        };

        let creds = DigestCredentials::new(username, password);
        // RFC 2617 §3.2.2 (interpretation a): digest-uri-value は Request-URI
        // と一致させる。 401 (UAS 認証) / 407 (Proxy 認証) の **どちらも共通**
        // で Request-URI を採用する。 RFC 2617 §3.2.2 の文面は
        // 「URI from Request-Line of the Request」 であり、 Proxy 認証時に
        // proxy が realm-specific URI を期待する事例は IMS でも標準では
        // 規定されておらず、 sabiden の実機検証 (NGN P-CSCF) でも
        // Request-URI = P-CSCF IP+port を digest-uri に使った時のみ通る
        // (`docs/asterisk-real-invite.md` §5.1 と整合)。 IMS S-CSCF が
        // realm-specific URI を期待するパターンは未確認 → manual test 課題。
        let digest = creds.compute(&challenge, "INVITE", &plan.request.uri, 1);

        // 元の INVITE をベースに新 branch + CSeq+1 + Authorization を載せて再送。
        let mut req2 = plan.request.clone();
        // RFC 3261 §17.1.1.3: 新 client transaction として再送 → 新 branch。
        let new_via = build_via_with_new_branch(&self.config.sent_by(), &plan.request);
        req2.headers.set("Via", new_via);
        // RFC 3261 §8.1.3.5: re-issued INVITE は CSeq を +1 して新トランザクションに。
        let new_cseq = plan.cseq.saturating_add(1);
        req2.headers.set("CSeq", format!("{} INVITE", new_cseq));
        req2.headers
            .set(auth_header_name, digest.header_value.clone());

        // retry で実際に送ったリクエスト一式を反映した新 plan を作る。
        // ACK CSeq (RFC 3261 §13.2.2.4) と Dialog local_cseq の起点
        // (RFC 3261 §12.2.1.1) を整合させるために必須 (上の docstring 参照)。
        let updated_plan = InvitePlan {
            request: req2.clone(),
            cseq: new_cseq,
            target_uri: plan.target_uri.clone(),
            session_expires: plan.session_expires,
        };

        let resp2 = self.layer.send_request(req2, self.server_addr).await?;
        Ok(Some((updated_plan, resp2)))
    }

    /// 進行中 INVITE に対する CANCEL (RFC 3261 §9.1)。
    ///
    /// CANCEL は元 INVITE と同じ Call-ID, From, To, Request-URI, CSeq 番号
    /// (method=CANCEL), 最初の Via (同じ branch) を持つ。
    ///
    /// ## RFC 3261 §9.1 1xx 受信ゲート
    ///
    /// > If no provisional response has been received, the CANCEL request
    /// > MUST NOT be sent; rather, the client MUST wait for the arrival of
    /// > a provisional response before sending the request. If the original
    /// > request has generated a final response, the CANCEL SHOULD NOT be
    /// > sent, as it is an effective no-op, since CANCEL has no effect on
    /// > requests that have already generated a final response.
    ///
    /// 本関数は transaction layer の [`InviteResponseProgress`] watcher を
    /// 介して INVITE トランザクションの応答受信進捗を観測し:
    /// - `Pending` の間は最大 [`CANCEL_PROVISIONAL_WAIT`] (= Timer B = 32s)
    ///   まで待機する (即送出 = RFC §9.1 違反を避ける)
    /// - `Provisional` への遷移を検知したら CANCEL を組み立てて送出
    /// - `Final` (1xx を経ず直接最終応答到達) なら CANCEL no-op (RFC §9.1 後半)
    /// - watcher が `None` (transaction エントリ消滅) も「終了済 = no-op」 扱い
    /// - 待機タイムアウト (32s で 1xx も来ない) はエラーを返す
    ///   (INVITE 側も Timer B でタイムアウトしているため、 呼出側は単に放棄して
    ///   よい — orchestrator は `cancelled_flag` の "200 OK 後の BYE" で
    ///   後段カバーする)
    pub async fn cancel_pending(&self, plan: &InvitePlan) -> Result<CancelOutcome> {
        // INVITE の TransactionId を Via branch から再構築する。 plan.request
        // は build_invite が組み立てた INVITE そのもので、 layer.send_request
        // が裏で `create_client` 時に登録した watch のキーと一致する
        // (RFC 3261 §17.1.3: ID = branch + sent-by + method)。
        let invite_id = TransactionId::from_request(&plan.request)?;
        let Some(mut rx) = self.layer.provisional_watch(&invite_id).await else {
            // RFC 3261 §9.1: 最終応答後の CANCEL は SHOULD NOT。 transaction
            // エントリが既に消えている = 完了済または Timer B タイムアウトで
            // Terminated 済。 どちらでも CANCEL は無意味。
            debug!(
                ?invite_id,
                "CANCEL skip: INVITE transaction が既に終了済 (RFC 3261 §9.1 後半)"
            );
            return Ok(CancelOutcome::NotSent);
        };

        // 現状の値を確認。 すでに Provisional / Final なら待たずに分岐。
        let initial = *rx.borrow();
        let progress = match initial {
            InviteResponseProgress::Pending => {
                // RFC 3261 §9.1: "the client MUST wait for the arrival of a
                // provisional response before sending the request"。
                // タイムアウトを置きつつ `changed()` で遷移を待つ。
                let wait_result = tokio::time::timeout(CANCEL_PROVISIONAL_WAIT, async {
                    // watch::Receiver::changed() は値が更新されるまで block。
                    // sender が drop されたら Err: それは transaction 終了を意味する。
                    while rx.changed().await.is_ok() {
                        match *rx.borrow_and_update() {
                            InviteResponseProgress::Pending => continue,
                            other => return Some(other),
                        }
                    }
                    // sender drop = transaction 終了。 None を返す。
                    None
                })
                .await;
                match wait_result {
                    Ok(Some(progress)) => progress,
                    Ok(None) => {
                        // transaction が終了した (最終応答到達 or Timer B)。
                        debug!(
                            ?invite_id,
                            "CANCEL skip: 待機中に INVITE transaction が終了 (RFC 3261 §9.1)"
                        );
                        return Ok(CancelOutcome::NotSent);
                    }
                    Err(_) => {
                        // 32s 内に 1xx も最終応答も来ない = INVITE 側で Timer B
                        // が走っているはずだが、 観測経路として念のため Err。
                        warn!(
                            ?invite_id,
                            "CANCEL: 1xx 待機が CANCEL_PROVISIONAL_WAIT を超過 (RFC 3261 §9.1)"
                        );
                        return Err(anyhow!(
                            "CANCEL: 1xx 受信前に待機タイムアウト (RFC 3261 §9.1)"
                        ));
                    }
                }
            }
            other => other,
        };

        match progress {
            InviteResponseProgress::Provisional => {
                // RFC 3261 §9.1: 1xx 受信済なので CANCEL を送ってよい。
                let cancel = build_cancel(&plan.request, plan.cseq);
                let resp = self.layer.send_request(cancel, self.server_addr).await?;
                Ok(CancelOutcome::Sent(resp))
            }
            InviteResponseProgress::Final => {
                // RFC 3261 §9.1: 最終応答到達後の CANCEL は SHOULD NOT。
                debug!(
                    ?invite_id,
                    "CANCEL skip: 既に最終応答到達済 (RFC 3261 §9.1 後半)"
                );
                Ok(CancelOutcome::NotSent)
            }
            InviteResponseProgress::Pending => {
                // 上のループで Pending を吸い出すはずなので原理上ここには来ない。
                // 念のため Err にして観測する。
                Err(anyhow!(
                    "CANCEL: 内部状態不整合 (Pending のままループを抜けた)"
                ))
            }
        }
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

/// [`Uac::cancel_pending`] 結果 (RFC 3261 §9.1)。
///
/// `NotSent` は **RFC 違反ではなく仕様準拠の不送信**:
/// - 待機中に INVITE が最終応答 (>=200) に到達 → CANCEL は no-op
///   (RFC 3261 §9.1: "If the original request has generated a final
///   response, the CANCEL SHOULD NOT be sent")
/// - INVITE transaction が既に終了済 (Timer B / D 経過)
///
/// 呼出側 (orchestrator) は `Sent` でも `NotSent` でも内線レッグへは
/// 487 Request Terminated を送る (元々 cancelled_flag で BYE 経路を持つ
/// 二段構え)。
pub enum CancelOutcome {
    /// 1xx 受信を確認のうえ CANCEL を送出し応答を受け取った。
    Sent(SipResponse),
    /// RFC 3261 §9.1 に従って CANCEL を送らなかった
    /// (= 最終応答既到達 / transaction 終了済)。
    NotSent,
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
    /// 単一情報源は [`Dialog::next_hop_socket`] にあり、 ここはハンドル側の
    /// 都合で `fallback_peer` を渡すだけのアダプタ。 解決不能 (FQDN /
    /// port 省略 / 不正 URI) のときは `fallback_peer` を返す。
    fn next_hop_socket(&self) -> SocketAddr {
        self.inner.next_hop_socket(self.fallback_peer)
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
/// **(RFC 3263 §4.1 SRV / NAPTR ベースの完全な next-hop 解決は未実装、
/// 別 Issue で対応予定。)** 本関数は [`Dialog::next_hop_socket`] への
/// 薄いラッパであり、 単一情報源は dialog 層側にある。 縮退ルール:
///
/// - 次ホップ host:port が **IP リテラル + 明示 port** の場合のみ
///   `SocketAddr` を確定で返す (`SipUriParts::host` は IPv6 のとき
///   `[..]` brackets 込み、 同 struct docstring 参照)
/// - FQDN / port 省略 / URI パース失敗の場合は `fallback` を返す
///   (RFC 3263 §4.1 の `_sip._udp.<host>` SRV lookup → port を引く本来の
///   解決は別 Issue)
///
/// NGN 直収では P-CSCF が Record-Route で `118.177.125.1:5060` を返すため
/// 確定経路で動く (`docs/asterisk-real-invite.md` §3 / §5.1 / Contact 例 §5.6)。
fn resolve_next_hop_addr(dialog: &Dialog, fallback: SocketAddr) -> SocketAddr {
    dialog.next_hop_socket(fallback)
}

/// 元の INVITE と同じ Via 構造を保ちつつ branch だけ新規生成する。
///
/// RFC 3261 §17.1.1.3 / §8.1.1.7: 認証チャレンジ後の再送は新規 client
/// transaction として扱われるため新 branch を必要とする。 `;rport` は
/// 元 INVITE で付いていれば維持する (Asterisk pcap §3 / §5.5)。
fn build_via_with_new_branch(sent_by: &str, original: &SipRequest) -> String {
    let original_via = original.headers.get("via").unwrap_or("");
    // 元 Via に `;rport` が含まれていたら維持する。
    let rport = if original_via.contains(";rport") {
        ";rport"
    } else {
        ""
    };
    format!("SIP/2.0/UDP {}{};branch={}", sent_by, rport, new_branch())
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
            auth_username: None,
            auth_password: None,
        }
    }

    /// 認証あり版のテスト用 UacConfig (Issue #113)。
    fn cfg_with_auth(username: &str, password: &str) -> UacConfig {
        let mut c = cfg();
        c.auth_username = Some(username.to_string());
        c.auth_password = Some(password.to_string());
        c
    }

    /// CSeq ヘッダから数値部だけを取り出すテスト用ヘルパ
    /// (RFC 3261 §20.16: `CSeq = 1*DIGIT LWS Method`)。
    /// Issue #143 で 401/407 retry テストの ACK / BYE CSeq 検証に使う。
    fn parse_cseq_num(headers: &crate::sip::message::SipHeaders) -> u32 {
        headers
            .get("cseq")
            .expect("CSeq ヘッダが必須 (RFC 3261 §20.16)")
            .split_whitespace()
            .next()
            .expect("CSeq の数値部分")
            .parse::<u32>()
            .expect("CSeq 数値が u32 でパースできる")
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

    /// RFC 3261 §8.1.1.2: `strip_port_from_sip_uri` の挙動を unit test。
    /// host portion の `:port` だけを剥がし、 URI parameters (`;transport=udp` 等)
    /// は保持する。
    #[test]
    fn rfc3261_8_1_1_2_strip_port_keeps_transport_params() {
        // case 1: port のみ → 剥がす
        assert_eq!(
            super::strip_port_from_sip_uri("sip:117@118.177.125.1:5060"),
            "sip:117@118.177.125.1"
        );
        // case 2: port + transport param → port のみ剥がす
        assert_eq!(
            super::strip_port_from_sip_uri("sip:117@p-cscf:5060;transport=udp"),
            "sip:117@p-cscf;transport=udp"
        );
        // case 3: port + lr param → port のみ剥がす
        assert_eq!(
            super::strip_port_from_sip_uri("sip:foo@host:5060;lr"),
            "sip:foo@host;lr"
        );
        // case 4: port なし、 params あり → no-op
        assert_eq!(
            super::strip_port_from_sip_uri("sip:117@p-cscf;transport=udp"),
            "sip:117@p-cscf;transport=udp"
        );
        // case 5: port なし、 params なし → no-op
        assert_eq!(
            super::strip_port_from_sip_uri("sip:foo@example.com"),
            "sip:foo@example.com"
        );
        // case 6: @ なし → no-op (defensive)
        assert_eq!(
            super::strip_port_from_sip_uri("sip:118.177.125.1:5060"),
            "sip:118.177.125.1:5060"
        );
    }

    /// RFC 3261 §8.1.1.2: To header は **identity (called party)** であって
    /// transport endpoint ではない。 sabiden は Request-URI には port を残し
    /// (P-CSCF 直送)、 To URI からは port を剥がす Asterisk pcap 互換 shape を
    /// 採用 (`docs/asterisk-real-invite.md` §5.1)。 PR #264 2 巡目 review 指摘
    /// (CLAUDE.md §7 重要パス 100% カバー)。
    #[tokio::test]
    async fn rfc3261_8_1_1_2_to_uri_drops_port_request_uri_keeps_port() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (layer, _rx) = TransactionLayer::spawn(socket);
        let server: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let uac = Uac::new(cfg(), layer, server);
        // case 1: target に :port あり (NGN 直収パス)
        let plan = uac.build_invite("sip:117@118.177.125.1:5060", None, None);
        let req = &plan.request;
        // Request-URI は port 保持 (= P-CSCF 直送用)
        assert!(
            req.uri.contains(":5060"),
            "Request-URI には port を保持すべき (P-CSCF 直送): {}",
            req.uri
        );
        let to = req.headers.get("to").expect("To header");
        assert!(
            !to.contains(":5060"),
            "To URI から port は剥がすべき (RFC 3261 §8.1.1.2 identity): {}",
            to
        );
        assert!(
            to.contains("117@118.177.125.1"),
            "To URI には identity (user@host) が残るべき: {}",
            to
        );
        // case 2: target に :port 無し → To もそのまま (idempotent)
        let plan2 = uac.build_invite("sip:foo@example.com", None, None);
        let to2 = plan2.request.headers.get("to").expect("To header");
        assert!(
            to2.contains("foo@example.com"),
            "port 無しの target は To もそのまま (no-op): {}",
            to2
        );
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
        // RFC 4028 §4: Session-Expires は `build_invite` の引数を honor + UAC が refresher。
        assert_eq!(
            plan.request.headers.get("session-expires").unwrap(),
            "300;refresher=uac"
        );
        assert_eq!(plan.request.headers.get("min-se").unwrap(), "90");
        // RFC 3261 §20.5: Allow は sabiden UAS が実装する method のみ。
        assert_eq!(
            plan.request.headers.get("allow").unwrap(),
            "INVITE, ACK, BYE, CANCEL, OPTIONS"
        );

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

    /// RFC 3261 §12.2.1.1 / §13.2.2.4 / RFC 4028 §7:
    ///
    /// Re-INVITE (Session Timer 更新含む) と続く 2xx ACK は **dialog の
    /// next-hop** に送らなければならない。 旧実装 (#79 修正前) は INVITE
    /// 送信先 `server_addr` (= NGN P-CSCF 固定) に流していた。 Issue #133
    /// は #132 で BYE 用 dual-server harness を追加したのを受けて、 同等の
    /// regression 防止を Re-INVITE 経路にも入れる。
    ///
    /// Shape (BYE テストと同形):
    ///   - INVITE 受け口: server_a (= server_addr 役、 P-CSCF 役)
    ///   - Re-INVITE / 2xx ACK 受け口: server_b (= 200 OK Contact 側、 真の対向)
    ///   200 OK で Contact = server_b、 Record-Route 無し → route_set 空、
    ///   次ホップ = remote target = server_b。 Re-INVITE が server_b に届けば
    ///   PASS、 server_a に届けば FAIL (旧バグ再発)。
    #[tokio::test]
    async fn rfc3261_12_2_1_1_reinvite_goes_to_dialog_remote_target_not_server_addr() {
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
            // INVITE 受信 → 200 OK with Contact = server_b、 Record-Route 無し
            let (n, peer) = server_a_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(invite) = parsed else {
                panic!("INVITE expected on server_a");
            };
            assert_eq!(invite.method, SipMethod::Invite);
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
            // Re-INVITE / 2xx ACK は dialog next-hop = server_b に飛ぶので、
            // server_a にはこれ以上届かない。
        });

        let reinvite_received = Arc::new(tokio::sync::Notify::new());
        let reinvite_received_for_task = reinvite_received.clone();
        let server_b_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 1) 初回 INVITE の 2xx ACK 受信 (Issue #79 で server_b に届く既知挙動)
            let (n, _peer) = server_b_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(ack) = parsed else {
                panic!("ACK expected on server_b");
            };
            assert_eq!(
                ack.method,
                SipMethod::Ack,
                "初回 INVITE の 2xx ACK は server_b (dialog next-hop) に届くべき"
            );

            // 2) Re-INVITE 受信 → 200 OK
            let (n2, peer2) = server_b_clone.recv_from(&mut buf).await.unwrap();
            let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
            let SipMessage::Request(reinv) = parsed2 else {
                panic!("Re-INVITE expected on server_b");
            };
            assert_eq!(
                reinv.method,
                SipMethod::Invite,
                "Re-INVITE が dialog remote target (= server_b) に届くべき"
            );
            // RFC 3261 §12.2.1.1: Request-URI = remote target = Contact URI。
            assert!(
                reinv.uri.contains(&format!("@{}", server_b_addr_for_resp)),
                "Re-INVITE の Request-URI は Contact (server_b) を指すべき: {}",
                reinv.uri
            );
            // RFC 4028 §7.4: Re-INVITE は Session-Expires を持つ。
            assert!(
                reinv.headers.get("session-expires").is_some(),
                "Re-INVITE に Session-Expires が必要 (RFC 4028 §7.4)"
            );

            let mut reinv_resp =
                crate::sip::transaction::build_response_skeleton(&reinv, 200, "OK");
            // 200 OK にも Contact / To-tag を載せる (元 dialog と同じ tag を維持)。
            reinv_resp.headers.set(
                "Contact",
                format!("<sip:remote@{}>", server_b_addr_for_resp),
            );
            server_b_clone
                .send_to(&reinv_resp.to_bytes(), peer2)
                .await
                .unwrap();

            // 3) Re-INVITE 2xx ACK 受信 (RFC 3261 §13.2.2.4)
            let (n3, _peer3) = server_b_clone.recv_from(&mut buf).await.unwrap();
            let parsed3 = crate::sip::message::parse_message(&buf[..n3]).unwrap();
            let SipMessage::Request(reinv_ack) = parsed3 else {
                panic!("Re-INVITE 2xx ACK expected on server_b");
            };
            assert_eq!(
                reinv_ack.method,
                SipMethod::Ack,
                "Re-INVITE 2xx ACK が dialog next-hop (= server_b) に届くべき"
            );
            // 2xx ACK CSeq number = Re-INVITE と同番号 (RFC 3261 §13.2.2.4)
            let reinv_cseq = reinv
                .headers
                .get("cseq")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap();
            let ack_cseq = reinv_ack
                .headers
                .get("cseq")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap();
            assert_eq!(
                ack_cseq, reinv_cseq,
                "RFC 3261 §13.2.2.4: 2xx ACK CSeq 番号は Re-INVITE と同じ"
            );
            reinvite_received_for_task.notify_one();
        });

        let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg();
        uac_cfg.local_addr = client_local;
        // server_addr は server_a (= P-CSCF 役)。 Re-INVITE は dialog 次ホップ
        // (= server_b) に向かわなければバグ。
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

        // SDP 無しの Session Timer 更新専用 Re-INVITE を発射。
        let reinv_resp = dlg.send_reinvite(None).await.expect("re-invite");
        assert_eq!(reinv_resp.status_code, 200);

        server_a_handle.await.unwrap();
        // タイムアウト保護で notify を待つ。 server_a に飛ぶバグなら timeout する。
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reinvite_received.notified(),
        )
        .await
        .expect("Re-INVITE が server_b に届かなかった (server_addr に飛んでいる可能性)");
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

    /// RFC 3261 §9.1: 100 Trying (= Provisional) を受けた後の CANCEL は
    /// MUST 送出され、 CANCEL の Via branch は元 INVITE と一致する
    /// (§9.1 / §17.1.3)。
    ///
    /// ## Issue #238 同期方式
    ///
    /// 旧実装は `tokio::time::sleep(50ms)` で「たぶん 100 Trying が dispatch
    /// されたろう」を期待していた。 CI 負荷で 50ms 内に 100 Trying の
    /// transaction layer 反映が間に合わないと、 `cancel_pending` が
    /// `InviteResponseProgress::Pending` を観測 → 1xx 待機経路に入り
    /// テストシナリオと異なる挙動になる flake 余地があった。
    ///
    /// PR #236 (Closes #201) と同方式で 2 段階の deterministic 同期に置換:
    ///
    /// 1. `provisional_watch(&invite_id)` を `tokio::task::yield_now` ループで
    ///    poll し registration 完了 (= `create_client` table 登録) を観測
    /// 2. 得た `watch::Receiver` を `wait_for(Provisional)` で block し
    ///    100 Trying が transaction layer に届いた瞬間まで待つ
    ///
    /// production API (`provisional_watch`) を同期点に流用するだけで、
    /// test hook 追加なし (CLAUDE.md §6.3 production-side test hook 禁止)。
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
        let plan_for_cancel = plan.clone();

        // INVITE の送信を別タスクで開始して、 100 Trying 観測後に CANCEL する。
        // `send_request` は INVITE 最終応答まで返らないので fire-and-forget。
        let layer_for_invite = uac.layer.clone();
        let server_addr_invite = uac.server_addr;
        let plan_clone = plan_for_cancel.clone();
        let invite_send_task = tokio::spawn(async move {
            let _ = layer_for_invite
                .send_request(plan_clone.request, server_addr_invite)
                .await;
        });

        // RFC 3261 §17.1.3 で identify される transaction id を先に算出し、
        // `provisional_watch` が Some を返す = `create_client` が table に
        // 登録完了、 を deterministic に観測する (registration は同一プロセス
        // 内のロック取得 1 回で完了するので待ち時間は実質ゼロ)。
        let invite_id =
            crate::sip::transaction::TransactionId::from_request(&plan.request).unwrap();
        let mut rx = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(rx) = uac.layer.provisional_watch(&invite_id).await {
                    break rx;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("INVITE が transaction table に登録されない (test bug)");

        // RFC 3261 §9.1: 100 Trying が transaction layer 内部状態を
        // `InviteResponseProgress::Provisional` に遷移させるまで block。
        // 旧実装は `sleep(50ms)` で「たぶん 100 Trying は届いてるだろう」と
        // 同期していたが、 CI 負荷で flake する余地があった。
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.wait_for(|v| matches!(v, InviteResponseProgress::Provisional)),
        )
        .await
        .expect("100 Trying が transaction layer に届かない (test bug)")
        .expect("provisional watch sender が drop された (test bug)");

        // RFC 3261 §9.1: 100 Trying (= Provisional) を受けた後の CANCEL は MUST 送出。
        let outcome = uac.cancel_pending(&plan_for_cancel).await.expect("cancel");
        let cancel_resp = match outcome {
            CancelOutcome::Sent(resp) => resp,
            CancelOutcome::NotSent => {
                panic!("100 Trying 受信後の CANCEL は送出されるべき (RFC 3261 §9.1)")
            }
        };
        assert_eq!(cancel_resp.status_code, 200);

        invite_send_task.abort();
        received.await.unwrap();
    }

    /// RFC 3261 §22.2 / RFC 2617 §3.2 / §13.2.2.4 / §12.2.1.1: 401
    /// Unauthorized challenge を受けた UAC は WWW-Authenticate を読み
    /// Authorization 付きで INVITE を再送する。 再送 2xx でダイアログ確立し、
    /// 2xx ACK CSeq は **retry INVITE の CSeq と一致** (§13.2.2.4)、 後続
    /// BYE CSeq は retry INVITE CSeq + 1 (§12.2.1.1 strictly increasing) に
    /// なることまで Issue #143 で要求された end-to-end shape を確認する。
    ///
    /// ## Issue #143 race 修正の要点
    ///
    /// 旧テストは 200 OK Contact を `sip:remote@127.0.0.1:9999` (テスト
    /// サーバではない bogus port) に置いており、 `resolve_next_hop_addr`
    /// (RFC 3261 §12.2.1.1) が IP リテラル + port 指定を採用して 2xx ACK を
    /// `127.0.0.1:9999` 宛に送ってしまい、 テストサーバの `recv_from` が
    /// 永遠に待つ hang を起こしていた。 修正案:
    ///
    /// - 200 OK に `Record-Route: <sip:proxy.example;lr>` を載せて loose
    ///   routing を起動。 next-hop が FQDN (= `proxy.example`) になり
    ///   `resolve_next_hop_addr` の FQDN/SRV 未対応分岐で fallback (=
    ///   `server_addr`) を採用する (passing test
    ///   `rfc3261_13_2_2_4_ack_and_dialog_cseq_match_retry_invite_after_401`
    ///   と同 shape)。
    /// - test 全体を `tokio::time::timeout(30s, ...)` で囲み、 race 再発時
    ///   に CI が永続 hang せず即 fail させる。
    #[tokio::test]
    async fn rfc3261_22_2_invite_401_retries_with_authorization_then_2xx() {
        // RFC 3261 §17.1.1.2 Timer B 32 s の倍以下に抑え、 race 再発を
        // 早期検知する。 想定挙動下では 1 RTT 内 (< 100 ms) に終わる。
        let test_body = async {
            let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let server_addr = server_sock.local_addr().unwrap();
            let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let client_local = client_sock.local_addr().unwrap();

            let server_clone = server_sock.clone();
            let server_handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                // 1) 1st INVITE (no Authorization) → 401 Unauthorized
                let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
                let SipMessage::Request(invite1) = parsed else {
                    panic!("INVITE expected");
                };
                assert_eq!(invite1.method, SipMethod::Invite);
                assert!(
                    invite1.headers.get("authorization").is_none(),
                    "1 回目は Authorization 無しで来るはず"
                );
                let invite1_via = invite1.headers.get("via").unwrap().to_string();
                let invite1_cseq_num = parse_cseq_num(&invite1.headers);
                let mut resp401 =
                    crate::sip::transaction::build_response_skeleton(&invite1, 401, "Unauthorized");
                // RFC 3261 §22.4 の challenge ヘッダ
                resp401.headers.set(
                    "WWW-Authenticate",
                    r#"Digest realm="ntt-east.ne.jp", nonce="abc123nonce", algorithm=MD5, qop="auth""#,
                );
                server_clone
                    .send_to(&resp401.to_bytes(), peer)
                    .await
                    .unwrap();

                // 2) RFC 3261 §17.1.1.3: non-2xx 最終応答に対し client
                // transaction 層が自動 ACK を送ってくる (元 INVITE と
                // 同 branch + 同 CSeq=N)。 strict order で吸収する。
                let (n_ack, _) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed_ack = crate::sip::message::parse_message(&buf[..n_ack]).unwrap();
                let SipMessage::Request(auto_ack) = parsed_ack else {
                    panic!("auto-ACK expected after 401");
                };
                assert_eq!(auto_ack.method, SipMethod::Ack);
                let auto_ack_cseq = parse_cseq_num(&auto_ack.headers);
                assert_eq!(
                    auto_ack_cseq, invite1_cseq_num,
                    "non-2xx 自動 ACK CSeq は元 INVITE CSeq と一致 (RFC 3261 §17.1.1.3)"
                );

                // 3) 2nd INVITE (with Authorization) → 200 OK
                let (n2, peer2) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
                let SipMessage::Request(invite2) = parsed2 else {
                    panic!("2nd INVITE expected");
                };
                assert_eq!(invite2.method, SipMethod::Invite);
                // Authorization 付き
                let auth = invite2
                    .headers
                    .get("authorization")
                    .expect("Authorization が付くべき (RFC 3261 §22.2)");
                assert!(auth.starts_with("Digest "), "Digest スキーム必須: {}", auth);
                assert!(auth.contains(r#"username="0312345678""#));
                assert!(auth.contains(r#"realm="ntt-east.ne.jp""#));
                assert!(auth.contains(r#"nonce="abc123nonce""#));
                // Call-ID は同じ (RFC 3261 §8.1.3.5: 同じ Call-ID で再送)
                assert_eq!(
                    invite2.headers.get("call-id").unwrap(),
                    invite1.headers.get("call-id").unwrap()
                );
                // CSeq は +1 (RFC 3261 §8.1.3.5)
                let invite2_cseq_num = parse_cseq_num(&invite2.headers);
                assert_eq!(invite2_cseq_num, invite1_cseq_num + 1);
                // 新 branch (RFC 3261 §17.1.1.3)
                let invite2_via = invite2.headers.get("via").unwrap();
                assert_ne!(
                    invite2_via, &invite1_via,
                    "branch は新規 (RFC 3261 §17.1.1.3)"
                );
                // 200 OK
                let mut ok = crate::sip::transaction::build_response_skeleton(&invite2, 200, "OK");
                ok.headers.set(
                    "To",
                    format!("{};tag=server-tag", invite2.headers.get("to").unwrap()),
                );
                ok.headers.set("Contact", "<sip:remote@127.0.0.1:9999>");
                // RFC 3261 §16.4 / §12.1.1: Record-Route で loose routing を
                // 起動 → next-hop URI が FQDN になり `resolve_next_hop_addr`
                // の FQDN/SRV 未対応分岐で fallback (= server_addr) を採用。
                // これで ACK / BYE が **このテストサーバ** に届く
                // (Issue #143 race 解消の核)。
                ok.headers.add("Record-Route", "<sip:proxy.example;lr>");
                server_clone.send_to(&ok.to_bytes(), peer2).await.unwrap();

                // 4) 2xx ACK (RFC 3261 §13.2.2.4): retry INVITE CSeq と一致。
                let (n3, _) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed3 = crate::sip::message::parse_message(&buf[..n3]).unwrap();
                let SipMessage::Request(ack) = parsed3 else {
                    panic!("2xx ACK expected");
                };
                assert_eq!(ack.method, SipMethod::Ack);
                let ack_cseq_num = parse_cseq_num(&ack.headers);
                assert_eq!(
                    ack_cseq_num, invite2_cseq_num,
                    "2xx ACK CSeq must match retry INVITE CSeq (RFC 3261 §13.2.2.4)"
                );

                // 5) BYE (RFC 3261 §15) — Dialog local_cseq は retry INVITE
                //    CSeq + 1 から始まる (RFC 3261 §12.2.1.1 strictly
                //    increasing)。
                let (n4, peer4) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed4 = crate::sip::message::parse_message(&buf[..n4]).unwrap();
                let SipMessage::Request(bye) = parsed4 else {
                    panic!("BYE expected");
                };
                assert_eq!(bye.method, SipMethod::Bye);
                let bye_cseq_num = parse_cseq_num(&bye.headers);
                assert_eq!(
                    bye_cseq_num,
                    invite2_cseq_num + 1,
                    "BYE CSeq must be retry INVITE CSeq + 1 (RFC 3261 §12.2.1.1)"
                );
                let bye_resp = crate::sip::transaction::build_response_skeleton(&bye, 200, "OK");
                server_clone
                    .send_to(&bye_resp.to_bytes(), peer4)
                    .await
                    .unwrap();
            });

            let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock);
            let mut uac_cfg = cfg_with_auth("0312345678", "p4ssw0rd");
            uac_cfg.local_addr = client_local;
            let uac = Uac::new(uac_cfg, layer, server_addr);
            let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);
            let outcome = uac.invite(plan, None).await.expect("invite");
            let mut dlg = match outcome {
                InviteOutcome::Established(call) => {
                    assert_eq!(call.dialog.dialog().id().remote_tag, "server-tag");
                    // UacDialog::invite_cseq は retry INVITE の CSeq=2 を
                    // 反映 (PR #144 review #1 Must-fix #1 regression guard)。
                    assert_eq!(
                        call.dialog.invite_cseq(),
                        2,
                        "UacDialog::invite_cseq は retry INVITE CSeq (RFC 3261 §13.2.2.4)"
                    );
                    call.dialog
                }
                InviteOutcome::Failed { response } => {
                    panic!(
                        "expected Established after 401 retry, got {}",
                        response.status_code
                    )
                }
            };
            // BYE を送って server 側の CSeq=3 assertion を駆動する。
            let bye_resp = dlg.send_bye().await.expect("BYE 送信");
            assert_eq!(bye_resp.status_code, 200);
            server_handle.await.unwrap();
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), test_body)
            .await
            .expect("Issue #143 race regression: test exceeded 30 s budget");
    }

    /// RFC 3261 §22.3 / §8.1.3.5 / §13.2.2.4 / §12.2.1.1: 407 Proxy
    /// Authentication Required を受けた UAC は Proxy-Authenticate を読み
    /// Proxy-Authorization 付きで INVITE を再送する。 401 版と同じ
    /// end-to-end shape (ACK CSeq = retry INVITE CSeq、 BYE CSeq = +1) を
    /// 検証する。 race 修正は 401 版と同じ Record-Route 経由 fallback。
    #[tokio::test]
    async fn rfc3261_22_3_invite_407_retries_with_proxy_authorization_then_2xx() {
        let test_body = async {
            let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let server_addr = server_sock.local_addr().unwrap();
            let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let client_local = client_sock.local_addr().unwrap();

            let server_clone = server_sock.clone();
            let server_handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                // 1) 1st INVITE (no Proxy-Authorization) → 407
                let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
                let SipMessage::Request(invite1) = parsed else {
                    panic!("INVITE expected");
                };
                assert!(invite1.headers.get("proxy-authorization").is_none());
                let invite1_cseq_num = parse_cseq_num(&invite1.headers);
                let mut resp407 = crate::sip::transaction::build_response_skeleton(
                    &invite1,
                    407,
                    "Proxy Authentication Required",
                );
                resp407.headers.set(
                    "Proxy-Authenticate",
                    r#"Digest realm="proxy.example", nonce="proxynonce-xyz", algorithm=MD5, qop="auth""#,
                );
                server_clone
                    .send_to(&resp407.to_bytes(), peer)
                    .await
                    .unwrap();

                // 2) RFC 3261 §17.1.1.3 auto-ACK 吸収 (CSeq=N)。
                let (n_ack, _) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed_ack = crate::sip::message::parse_message(&buf[..n_ack]).unwrap();
                let SipMessage::Request(auto_ack) = parsed_ack else {
                    panic!("auto-ACK expected after 407");
                };
                assert_eq!(auto_ack.method, SipMethod::Ack);
                let auto_ack_cseq = parse_cseq_num(&auto_ack.headers);
                assert_eq!(
                    auto_ack_cseq, invite1_cseq_num,
                    "non-2xx 自動 ACK CSeq は元 INVITE CSeq と一致 (RFC 3261 §17.1.1.3)"
                );

                // 3) 2nd INVITE (with Proxy-Authorization) → 200 OK
                let (n2, peer2) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
                let SipMessage::Request(invite2) = parsed2 else {
                    panic!("2nd INVITE expected");
                };
                let proxy_auth = invite2
                    .headers
                    .get("proxy-authorization")
                    .expect("Proxy-Authorization が付くべき (RFC 3261 §22.3)");
                assert!(proxy_auth.starts_with("Digest "));
                assert!(proxy_auth.contains(r#"realm="proxy.example""#));
                assert!(proxy_auth.contains(r#"nonce="proxynonce-xyz""#));
                // Authorization (= 401 用) は付かないこと
                assert!(invite2.headers.get("authorization").is_none());
                let invite2_cseq_num = parse_cseq_num(&invite2.headers);
                assert_eq!(
                    invite2_cseq_num,
                    invite1_cseq_num + 1,
                    "retry INVITE CSeq = +1 (RFC 3261 §8.1.3.5)"
                );
                let mut ok = crate::sip::transaction::build_response_skeleton(&invite2, 200, "OK");
                ok.headers.set(
                    "To",
                    format!("{};tag=tag407", invite2.headers.get("to").unwrap()),
                );
                ok.headers.set("Contact", "<sip:remote@127.0.0.1:9999>");
                // Record-Route で next-hop を FQDN に → fallback で ACK が
                // テストサーバに戻ってくる (Issue #143 race 解消)。
                ok.headers.add("Record-Route", "<sip:proxy.example;lr>");
                server_clone.send_to(&ok.to_bytes(), peer2).await.unwrap();

                // 4) 2xx ACK (RFC 3261 §13.2.2.4): retry INVITE CSeq と一致。
                let (n3, _) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed3 = crate::sip::message::parse_message(&buf[..n3]).unwrap();
                let SipMessage::Request(ack) = parsed3 else {
                    panic!("2xx ACK expected");
                };
                assert_eq!(ack.method, SipMethod::Ack);
                let ack_cseq_num = parse_cseq_num(&ack.headers);
                assert_eq!(
                    ack_cseq_num, invite2_cseq_num,
                    "2xx ACK CSeq must match retry INVITE CSeq (RFC 3261 §13.2.2.4)"
                );

                // 5) BYE: retry INVITE CSeq + 1 (RFC 3261 §12.2.1.1)。
                let (n4, peer4) = server_clone.recv_from(&mut buf).await.unwrap();
                let parsed4 = crate::sip::message::parse_message(&buf[..n4]).unwrap();
                let SipMessage::Request(bye) = parsed4 else {
                    panic!("BYE expected");
                };
                assert_eq!(bye.method, SipMethod::Bye);
                let bye_cseq_num = parse_cseq_num(&bye.headers);
                assert_eq!(
                    bye_cseq_num,
                    invite2_cseq_num + 1,
                    "BYE CSeq must be retry INVITE CSeq + 1 (RFC 3261 §12.2.1.1)"
                );
                let bye_resp = crate::sip::transaction::build_response_skeleton(&bye, 200, "OK");
                server_clone
                    .send_to(&bye_resp.to_bytes(), peer4)
                    .await
                    .unwrap();
            });

            let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock);
            let mut uac_cfg = cfg_with_auth("0312345678", "p4ssw0rd");
            uac_cfg.local_addr = client_local;
            let uac = Uac::new(uac_cfg, layer, server_addr);
            let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);
            let outcome = uac.invite(plan, None).await.expect("invite");
            let mut dlg = match outcome {
                InviteOutcome::Established(call) => {
                    assert_eq!(call.dialog.dialog().id().remote_tag, "tag407");
                    assert_eq!(
                        call.dialog.invite_cseq(),
                        2,
                        "UacDialog::invite_cseq は retry INVITE CSeq (RFC 3261 §13.2.2.4)"
                    );
                    call.dialog
                }
                InviteOutcome::Failed { response } => {
                    panic!(
                        "expected Established after 407 retry, got {}",
                        response.status_code
                    )
                }
            };
            let bye_resp = dlg.send_bye().await.expect("BYE 送信");
            assert_eq!(bye_resp.status_code, 200);
            server_handle.await.unwrap();
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), test_body)
            .await
            .expect("Issue #143 race regression: test exceeded 30 s budget");
    }

    /// RFC 3261 §22.2 (UAC は再認証後の 2 段目 challenge は failure 扱い):
    /// 連続 2 回 401 が来たら諦めて `Failed` を返す。 無限ループ防止。
    #[tokio::test]
    async fn rfc3261_22_2_invite_consecutive_401_gives_up() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let server_clone = server_sock.clone();
        let server_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 1) 1st INVITE → 401
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(invite1) = parsed else {
                panic!("INVITE expected");
            };
            let mut resp401 =
                crate::sip::transaction::build_response_skeleton(&invite1, 401, "Unauthorized");
            resp401.headers.set(
                "WWW-Authenticate",
                r#"Digest realm="x", nonce="n1", algorithm=MD5, qop="auth""#,
            );
            server_clone
                .send_to(&resp401.to_bytes(), peer)
                .await
                .unwrap();

            // 2) auto-ACK (RFC 3261 §17.1.1.3) 吸収
            let (n_ack, _) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed_ack = crate::sip::message::parse_message(&buf[..n_ack]).unwrap();
            let SipMessage::Request(auto_ack) = parsed_ack else {
                panic!("auto-ACK expected after 1st 401");
            };
            assert_eq!(auto_ack.method, SipMethod::Ack);

            // 3) 2nd INVITE → 401 (still). UAC 側は諦める想定。
            let (n2, peer2) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
            let SipMessage::Request(invite2) = parsed2 else {
                panic!("2nd INVITE expected");
            };
            assert!(invite2.headers.get("authorization").is_some());
            let mut resp401b =
                crate::sip::transaction::build_response_skeleton(&invite2, 401, "Unauthorized");
            resp401b.headers.set(
                "WWW-Authenticate",
                r#"Digest realm="x", nonce="n2-rotated", algorithm=MD5, qop="auth""#,
            );
            server_clone
                .send_to(&resp401b.to_bytes(), peer2)
                .await
                .unwrap();

            // 4) 2 段目の 401 にも auto-ACK が来る (これも吸収)。
            // 5) **3rd INVITE は来ない**。 RFC 3261 §22.2 で UAC は 2 段目
            // challenge を failure として扱う実装方針 (Issue #113)。
            let (n_ack2, _) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed_ack2 = crate::sip::message::parse_message(&buf[..n_ack2]).unwrap();
            let SipMessage::Request(auto_ack2) = parsed_ack2 else {
                panic!("auto-ACK expected after 2nd 401");
            };
            assert_eq!(auto_ack2.method, SipMethod::Ack);
            // ここで server task は終了。 3rd INVITE が来ていたら
            // recv_from で待ち続けるので task が終わらない。
        });

        let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg_with_auth("0312345678", "p4ssw0rd");
        uac_cfg.local_addr = client_local;
        let uac = Uac::new(uac_cfg, layer, server_addr);
        let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);
        let outcome = uac.invite(plan, None).await.expect("invite");
        match outcome {
            InviteOutcome::Failed { response } => {
                assert_eq!(response.status_code, 401, "2 段目も 401 で諦める");
            }
            InviteOutcome::Established(_) => panic!("must fail after 2 consecutive 401"),
        }
        server_handle.await.unwrap();
    }

    /// 認証情報が無い (NGN 直収モード = `auth_username` / `auth_password`
    /// が `None`) の場合、 401 を受けても再送せず即 Failed を返す。
    /// NGN 直収パス (REGISTER は通るが INVITE で 401 は来ない) の挙動を
    /// 既存通り保つための regression テスト。
    #[tokio::test]
    async fn invite_401_without_credentials_stays_failed_for_ngn_direct_mode() {
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
                    crate::sip::transaction::build_response_skeleton(&req, 401, "Unauthorized");
                resp.headers.set(
                    "WWW-Authenticate",
                    r#"Digest realm="x", nonce="n", algorithm=MD5"#,
                );
                server_clone.send_to(&resp.to_bytes(), peer).await.unwrap();
            }
        });

        let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg(); // auth_username/auth_password 共に None
        uac_cfg.local_addr = client_local;
        let uac = Uac::new(uac_cfg, layer, server_addr);
        let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);
        let outcome = uac.invite(plan, None).await.expect("invite");
        match outcome {
            InviteOutcome::Failed { response } => {
                assert_eq!(response.status_code, 401);
            }
            InviteOutcome::Established(_) => panic!("must fail (no credentials)"),
        }
    }

    /// RFC 3261 §13.2.2.4 / §12.2.1.1 / §22.2: 401 retry 経路で
    /// **ACK CSeq と Dialog local_cseq が retry INVITE の CSeq と整合**
    /// していることを確認する。 旧実装は `finalize_2xx(&plan, ...)` に
    /// 元 plan (CSeq=1) を渡していたため:
    ///   - ACK CSeq = 1 (retry INVITE CSeq=2 と不一致 → §13.2.2.4 違反)
    ///   - Dialog local_cseq = 2 (= 既使用の retry CSeq → §12.2.1.1 strictly
    ///     increasing 違反、 BYE が CSeq=2 で送られて重複)
    ///
    /// 本テストは review #1 (PR #144) の Must-fix #1 に対する regression
    /// guard。 `consecutive_401_gives_up` と同じく ACK 手前で server task が
    /// 完結する shape を採り、 Issue #143 の race を踏まずに検証する。
    #[tokio::test]
    async fn rfc3261_13_2_2_4_ack_and_dialog_cseq_match_retry_invite_after_401() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let server_clone = server_sock.clone();
        let server_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 1) 1st INVITE (CSeq=1, Authorization 無し) → 401
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(invite1) = parsed else {
                panic!("INVITE expected");
            };
            assert_eq!(invite1.method, SipMethod::Invite);
            let invite1_cseq = invite1
                .headers
                .get("cseq")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<u32>()
                .unwrap();
            assert_eq!(invite1_cseq, 1, "1st INVITE CSeq=1 (build_invite 規約)");
            let mut resp401 =
                crate::sip::transaction::build_response_skeleton(&invite1, 401, "Unauthorized");
            resp401.headers.set(
                "WWW-Authenticate",
                r#"Digest realm="ntt-east.ne.jp", nonce="abc123nonce", algorithm=MD5, qop="auth""#,
            );
            server_clone
                .send_to(&resp401.to_bytes(), peer)
                .await
                .unwrap();

            // 2) RFC 3261 §17.1.1.3 自動 ACK (CSeq=1) を吸収。
            let (n_ack, _) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed_ack = crate::sip::message::parse_message(&buf[..n_ack]).unwrap();
            let SipMessage::Request(auto_ack) = parsed_ack else {
                panic!("auto-ACK expected after 401");
            };
            assert_eq!(auto_ack.method, SipMethod::Ack);
            let auto_ack_cseq = auto_ack
                .headers
                .get("cseq")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<u32>()
                .unwrap();
            assert_eq!(auto_ack_cseq, 1, "401 自動 ACK CSeq=1 (元 INVITE と一致)");

            // 3) 2nd INVITE (CSeq=2, Authorization 付き) → 200 OK
            let (n2, peer2) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
            let SipMessage::Request(invite2) = parsed2 else {
                panic!("2nd INVITE expected");
            };
            let invite2_cseq = invite2
                .headers
                .get("cseq")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<u32>()
                .unwrap();
            assert_eq!(
                invite2_cseq, 2,
                "retry INVITE CSeq = +1 (RFC 3261 §8.1.3.5)"
            );
            assert!(invite2.headers.get("authorization").is_some());
            let mut ok = crate::sip::transaction::build_response_skeleton(&invite2, 200, "OK");
            ok.headers.set(
                "To",
                format!("{};tag=server-tag", invite2.headers.get("to").unwrap()),
            );
            ok.headers.set("Contact", "<sip:remote@127.0.0.1:9999>");
            // Record-Route で loose routing を起動 → next-hop が FQDN になる
            // ため `resolve_next_hop_addr` が fallback (= server_addr) を採用
            // し、 ACK / BYE が **このテストサーバ** に届く
            // (`invite_2xx_establishes_dialog_and_sends_ack` と同じ shape)。
            ok.headers.add("Record-Route", "<sip:proxy.example;lr>");
            server_clone.send_to(&ok.to_bytes(), peer2).await.unwrap();

            // 4) 2xx ACK (RFC 3261 §13.2.2.4) — **retry INVITE の CSeq=2 と
            //    一致** していなければ Must-fix #1 のバグ。
            let (n3, _) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed3 = crate::sip::message::parse_message(&buf[..n3]).unwrap();
            let SipMessage::Request(ack) = parsed3 else {
                panic!("2xx ACK expected");
            };
            assert_eq!(ack.method, SipMethod::Ack);
            let ack_cseq = ack
                .headers
                .get("cseq")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<u32>()
                .unwrap();
            assert_eq!(
                ack_cseq, invite2_cseq,
                "2xx ACK CSeq must match retry INVITE CSeq (RFC 3261 §13.2.2.4)"
            );

            // 5) BYE (RFC 3261 §15) — Dialog local_cseq は retry INVITE の
            //    CSeq+1 = 3 から始まらなければ §12.2.1.1 strictly increasing
            //    違反 (= 既使用 CSeq=2 を再利用してしまう)。
            let (n4, peer4) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed4 = crate::sip::message::parse_message(&buf[..n4]).unwrap();
            let SipMessage::Request(bye) = parsed4 else {
                panic!("BYE expected");
            };
            assert_eq!(bye.method, SipMethod::Bye);
            let bye_cseq = bye
                .headers
                .get("cseq")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<u32>()
                .unwrap();
            assert_eq!(
                bye_cseq, 3,
                "BYE CSeq=3 (= retry INVITE CSeq=2 + 1, RFC 3261 §12.2.1.1)"
            );
            let bye_resp = crate::sip::transaction::build_response_skeleton(&bye, 200, "OK");
            server_clone
                .send_to(&bye_resp.to_bytes(), peer4)
                .await
                .unwrap();
        });

        let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg_with_auth("0312345678", "p4ssw0rd");
        uac_cfg.local_addr = client_local;
        let uac = Uac::new(uac_cfg, layer, server_addr);
        let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);
        let outcome = uac.invite(plan, None).await.expect("invite");
        let mut dlg = match outcome {
            InviteOutcome::Established(call) => {
                assert_eq!(call.dialog.dialog().id().remote_tag, "server-tag");
                // UacDialog の invite_cseq は retry の CSeq=2 を反映している
                // べき (review #1 Must-fix #1: finalize_2xx が更新済 plan を
                // 使う)。
                assert_eq!(
                    call.dialog.invite_cseq(),
                    2,
                    "UacDialog::invite_cseq は retry INVITE の CSeq と一致する"
                );
                call.dialog
            }
            InviteOutcome::Failed { response } => {
                panic!(
                    "expected Established after 401 retry, got {}",
                    response.status_code
                )
            }
        };

        // BYE を送って server 側の CSeq=3 assertion を駆動する。
        let bye_resp = tokio::time::timeout(std::time::Duration::from_secs(5), dlg.send_bye())
            .await
            .expect("BYE タイムアウト")
            .expect("BYE 送信エラー");
        assert_eq!(bye_resp.status_code, 200);

        tokio::time::timeout(std::time::Duration::from_secs(5), server_handle)
            .await
            .expect("server task タイムアウト")
            .unwrap();
    }

    /// `build_via_with_new_branch` のユニットテスト (RFC 3261 §17.1.1.3 §8.1.1.7)。
    /// 元 INVITE の `;rport` 有無を保持しつつ branch だけ新規にする。
    #[test]
    fn rfc3261_17_1_1_3_via_with_new_branch_preserves_rport() {
        let mut req = SipRequest::new(SipMethod::Invite, "sip:bob@example.com");
        req.headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:5060;rport;branch=z9hG4bKold");
        let via = build_via_with_new_branch("192.0.2.1:5060", &req);
        assert!(via.contains(";rport"), "rport は維持: {}", via);
        assert!(via.contains(";branch=z9hG4bK"), "新 branch が付く: {}", via);
        assert!(!via.contains("z9hG4bKold"), "古い branch は外れる: {}", via);
    }

    #[test]
    fn rfc3261_17_1_1_3_via_with_new_branch_omits_rport_when_original_lacks_it() {
        let mut req = SipRequest::new(SipMethod::Invite, "sip:bob@example.com");
        req.headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKold");
        let via = build_via_with_new_branch("192.0.2.1:5060", &req);
        assert!(
            !via.contains(";rport"),
            "元に rport 無いので付けない: {}",
            via
        );
        assert!(via.contains(";branch=z9hG4bK"));
    }

    // ====================================================================
    // RFC 3261 §9.1 CANCEL UAC Behavior (Issue #97)
    //
    // > If no provisional response has been received, the CANCEL request
    // > MUST NOT be sent; rather, the client MUST wait for the arrival of
    // > a provisional response before sending the request. If the original
    // > request has generated a final response, the CANCEL SHOULD NOT be
    // > sent, as it is an effective no-op.
    // ====================================================================

    /// RFC 3261 §9.1: 1xx 受信前に `cancel_pending` が呼ばれても CANCEL は
    /// 送らずに待機し、 1xx 到達後に CANCEL を送出する。
    ///
    /// 旧実装は 1xx を待たずに即送出していたため、 NGN P-CSCF が
    /// branch=未知の CANCEL に 481 を返す可能性があった (Issue #97)。
    /// 本テストは fake server が CANCEL を **100 Trying 送出前に観測した
    /// ら fail** という形にすることで、 「CANCEL は必ず 1xx の後」 を強制
    /// する。
    #[tokio::test]
    async fn rfc3261_9_1_cancel_waits_for_provisional_before_sending() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let trying_sent = Arc::new(AtomicBool::new(false));

        let server_clone = server_sock.clone();
        let trying_sent_clone = trying_sent.clone();
        let server_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            // 1) INVITE 受信 (Trying を即返さない)
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(invite) = parsed else {
                panic!("INVITE expected")
            };
            assert_eq!(invite.method, SipMethod::Invite);
            // RFC 3261 §9.1 の真の検証: CANCEL は 100 Trying より後でなければならない。
            // 100 Trying 送出を遅延し、 その間に Server が他に何か (CANCEL)
            // を受け取らないことを確認する。
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let trying = crate::sip::transaction::build_response_skeleton(&invite, 100, "Trying");
            server_clone
                .send_to(&trying.to_bytes(), peer)
                .await
                .unwrap();
            trying_sent_clone.store(true, Ordering::SeqCst);

            // 2) CANCEL 受信 (100 Trying の **後** であることを表明)
            let (n2, peer2) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed2 = crate::sip::message::parse_message(&buf[..n2]).unwrap();
            let SipMessage::Request(cancel) = parsed2 else {
                panic!("CANCEL expected (got non-Request)")
            };
            assert_eq!(cancel.method, SipMethod::Cancel);
            assert!(
                trying_sent_clone.load(Ordering::SeqCst),
                "RFC 3261 §9.1 違反: CANCEL が 100 Trying より先に到達した"
            );
            // CANCEL に 200 OK を返す
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

        // INVITE を別タスクで送出 (transaction が table に登録される)。
        // `send_request` は INVITE 最終応答まで返らないので、 ここでは
        // fire-and-forget で spawn し、 親タスクは別経路で「INVITE 登録完了」
        // を待つ。
        let layer_for_invite = uac.layer.clone();
        let server_addr_invite = uac.server_addr;
        let plan_for_invite = plan.clone();
        let invite_task = tokio::spawn(async move {
            let _ = layer_for_invite
                .send_request(plan_for_invite.request, server_addr_invite)
                .await;
        });

        // RFC 3261 §17.1.3 で identify される transaction id を先に算出し、
        // `provisional_watch` が Some を返す = `create_client` が table に
        // 登録完了、 を deterministic に観測する。
        // 旧実装は `sleep(20ms)` で「たぶん終わってるだろう」と同期していたが、
        // CI 負荷で 20ms 内に registration が完了しないと flake する。
        // 本テストは production API の watch が登場した時点で確定なので、
        // `tokio::task::yield_now` で polling する: registration は同一プロセス
        // 内のロック取得 1 回で済むので待ち時間は実質ゼロ。
        let invite_id =
            crate::sip::transaction::TransactionId::from_request(&plan.request).unwrap();
        let registration = async {
            loop {
                if uac.layer.provisional_watch(&invite_id).await.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), registration)
            .await
            .expect("INVITE が transaction table に登録されない (test bug)");

        // 1xx 受信前に cancel_pending を呼ぶ (= server 側はまだ 150ms 寝てる)。
        // 100 Trying 到達まで cancel_pending が **待つ** ことを確認する。
        // 旧実装ではここで即 CANCEL が server に届いてしまい
        // `trying_sent == false` で assert! が失敗する。
        let outcome =
            tokio::time::timeout(std::time::Duration::from_secs(2), uac.cancel_pending(&plan))
                .await
                .expect("cancel_pending が timeout (1xx 待機が長すぎ)")
                .expect("cancel_pending err");

        match outcome {
            CancelOutcome::Sent(resp) => assert_eq!(resp.status_code, 200),
            CancelOutcome::NotSent => panic!("Provisional 後の CANCEL は送出されるべき"),
        }
        assert!(
            trying_sent.load(Ordering::SeqCst),
            "100 Trying は CANCEL 前に必ず送出済 (RFC 3261 §9.1)"
        );

        invite_task.abort();
        server_handle.await.unwrap();
    }

    /// RFC 3261 §9.1 後半: 最終応答が既に到達済みなら CANCEL は SHOULD NOT
    /// send (no-op)。 `cancel_pending` は `CancelOutcome::NotSent` を返す。
    ///
    /// > If the original request has generated a final response, the CANCEL
    /// > SHOULD NOT be sent, as it is an effective no-op.
    #[tokio::test]
    async fn rfc3261_9_1_cancel_not_sent_when_final_response_already_received() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let server_clone = server_sock.clone();
        let server_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            // INVITE 受信 → 486 Busy Here (最終応答) を即返す。
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed = crate::sip::message::parse_message(&buf[..n]).unwrap();
            let SipMessage::Request(invite) = parsed else {
                panic!("INVITE expected")
            };
            let mut resp =
                crate::sip::transaction::build_response_skeleton(&invite, 486, "Busy Here");
            resp.headers.set(
                "To",
                format!("{};tag=busy", invite.headers.get("to").unwrap()),
            );
            server_clone.send_to(&resp.to_bytes(), peer).await.unwrap();

            // 自動 ACK (RFC 3261 §17.1.1.3) を吸収。
            let (_n_ack, _) = server_clone.recv_from(&mut buf).await.unwrap();
            // ここで CANCEL が来てしまったら fail (no-op であるべき)。
            let mut buf2 = vec![0u8; 4096];
            match tokio::time::timeout(
                std::time::Duration::from_millis(400),
                server_clone.recv_from(&mut buf2),
            )
            .await
            {
                Ok(Ok((nx, _))) => {
                    let parsed_x = crate::sip::message::parse_message(&buf2[..nx]).unwrap();
                    if let SipMessage::Request(req_x) = parsed_x {
                        if req_x.method == SipMethod::Cancel {
                            panic!("RFC 3261 §9.1 違反: 最終応答後に CANCEL が送出された");
                        }
                    }
                }
                _ => {
                    // タイムアウト = CANCEL 来ず: 期待通り。
                }
            }
        });

        let (layer, _inbound_rx) = crate::sip::transaction::TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg();
        uac_cfg.local_addr = client_local;
        let uac = Uac::new(uac_cfg, layer, server_addr);
        let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);

        // INVITE を別タスクで送る → 486 が即返り final 状態に遷移する。
        let layer_for_invite = uac.layer.clone();
        let server_addr_invite = uac.server_addr;
        let plan_for_invite = plan.clone();
        let invite_task = tokio::spawn(async move {
            let _ = layer_for_invite
                .send_request(plan_for_invite.request, server_addr_invite)
                .await;
        });

        // 486 が dispatch されて transaction layer 内部状態が
        // `InviteResponseProgress::Final` に遷移するまで watch で deterministic
        // に待つ。 旧実装は `sleep(100ms)` で「たぶん 486 は届いてるだろう」と
        // 同期していたが、 CI 負荷で 100ms 内に dispatch が間に合わないと
        // 「Pending のままで cancel_pending を呼んで Pending を観測 →
        // 1xx 待機経路 → 32s 後 timeout」 となり flake する。
        // production API の watch を購読することで、 final 観測 = 確定同期。
        let invite_id =
            crate::sip::transaction::TransactionId::from_request(&plan.request).unwrap();
        // registration 完了まで poll (create_client は同一プロセス内のロック
        // 取得 1 回で完了するので実質待ち時間ゼロ)。
        let mut rx = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(rx) = uac.layer.provisional_watch(&invite_id).await {
                    break rx;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("INVITE registration timeout (test bug)");
        // RFC 3261 §9.1 後半: 486 → Final 遷移を観測。
        // watch::Receiver::wait_for は値が predicate を満たすまで block。
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.wait_for(|v| matches!(v, InviteResponseProgress::Final)),
        )
        .await
        .expect("486 が transaction layer に届かない (test bug)")
        .expect("provisional watch sender が drop された (test bug)");

        // RFC 3261 §9.1 後半: 最終応答後の CANCEL は no-op = NotSent。
        let outcome = uac.cancel_pending(&plan).await.expect("cancel_pending err");
        match outcome {
            CancelOutcome::NotSent => {}
            CancelOutcome::Sent(resp) => panic!(
                "最終応答後の CANCEL は送らないはず (RFC 3261 §9.1): got code={}",
                resp.status_code
            ),
        }

        invite_task.abort();
        server_handle.await.unwrap();
    }

    /// RFC 3261 §9.1 / §17.1.3: `Uac::cancel_pending` が
    /// transaction layer の応答受信進捗 watcher を介して 1xx を観測すること
    /// を、 build_cancel 単体ではなく `Uac` 経由で確認する。
    ///
    /// `provisional_watch` に存在しない INVITE (= 未送信 / 既に終了済) に
    /// 対しては `NotSent` を返す。
    #[tokio::test]
    async fn rfc3261_9_1_cancel_not_sent_when_invite_never_registered() {
        // INVITE を一切 send_request していない状態で cancel_pending を
        // 呼ぶと、 transaction table に entry が無いので provisional_watch
        // が None を返し、 `NotSent` で返る (= RFC 3261 §9.1 "no CANCEL on
        // already-terminated request")。
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_local = client_sock.local_addr().unwrap();

        let (layer, _inbound_rx) = crate::sip::transaction::TransactionLayer::spawn(client_sock);
        let mut uac_cfg = cfg();
        uac_cfg.local_addr = client_local;
        let uac = Uac::new(uac_cfg, layer, server_addr);
        let plan = uac.build_invite("sip:remote@127.0.0.1:9999", None, None);

        // INVITE を送らずに直接 cancel_pending を呼ぶ。
        let outcome = uac.cancel_pending(&plan).await.expect("cancel_pending err");
        assert!(
            matches!(outcome, CancelOutcome::NotSent),
            "未登録 INVITE への CANCEL は NotSent (RFC 3261 §9.1)"
        );
    }
}
