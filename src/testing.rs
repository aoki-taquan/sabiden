//! テスト共通ハーネス (Issue #42, refactor-plan Phase R1)
//!
//! 各モジュールのユニットテスト / 統合テストで重複していた
//! mock UAS / UAC / fake NGN / SIP ビルダ群を 1 か所に集約する。
//!
//! 本モジュールは `#[cfg(test)]` でゲートしてあり、production ビルドには含めない。
//! production コードは触らない (Issue #42 の "触らない" 制約) ため、
//! `crate::sip` / `crate::call` の公開 API のみを利用する。
//!
//! # 構成
//!
//! - [`fixtures`]: テスト用 `ExtensionConfig` / `UasConfig` / SDP テンプレート
//!   等、複数テストで共有したい "魔法定数"。
//! - [`pcsf`]: NTT NGN P-CSCF 模擬 (`MockNgnPcsf`)。`UdpSocket` を bind し、
//!   REGISTER に 200 OK を返し、INVITE に対しては事前スクリプトに従って
//!   100 → 200/4xx/487 を返す。RFC 3261 §17.2.1 に基づく 100 Trying →
//!   最終応答の流れを単一 task で駆動する。
//! - [`ext_ua`]: Linphone 風内線 UA 模擬 (`MockExtensionUa`)。Digest 認証付き
//!   REGISTER → INVITE 発行 → ACK / BYE 受信を 1 ハンドルで完結させる。
//! - [`webrtc_browser`]: axum + tokio-tungstenite による WS シグナリング
//!   ブラウザ模擬 (`MockWebrtcBrowser`)。
//! - [`scripted`]: [`crate::call::manager::LegInviter`] のスクリプト化実装。
//!   既存の orchestrator / manager テストの `ScriptedInviter` 重複を統合する。
//! - [`asserts`]: `assert_sip_header!` 等の RFC 引用付きマクロ。
//!
//! # RFC 参考
//!
//! - RFC 3261 §17.2.1: INVITE Server Transaction (100 Trying)
//! - RFC 3261 §10:    REGISTER / Authentication
//! - RFC 3261 §15.1.1: BYE
//! - RFC 3261 §9.1:    CANCEL は 487 Request Terminated を伴う

#![cfg(test)]
#![allow(dead_code)] // 段階的に各テストへ移行するためダム未使用は許容する

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;
use tracing::debug;

use crate::sip::auth::{build_www_authenticate, DigestChallenge, DigestCredentials};
use crate::sip::message::{
    parse_message, SipHeaders, SipMessage, SipMethod, SipRequest, SipResponse,
};
use crate::sip::transaction::build_response_skeleton;
use crate::sip::utils::{new_call_id, new_tag};

// =============================================================================
// fixtures: 共通の魔法定数 / SDP テンプレ
// =============================================================================

pub mod fixtures {
    //! テスト全体で共有する固定値。
    //!
    //! - `loopback_any()` は `127.0.0.1:0` のショートカット。
    //! - `extension_config()` / `uas_config()` は UAS テストで毎回コピーされていた
    //!   ボイラープレート。
    //! - SDP テンプレ (`sdp_offer_pcmu` 等) は orchestrator テストで毎回手書き
    //!   していた m=audio 行を一発で生成する。

    use super::*;
    use crate::config::{ExtensionConfig, UasConfig};

    /// `127.0.0.1:0` (カーネル ポート割当)。
    pub fn loopback_any() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// テスト共通の内線アカウント (`iphone` / `secret`)。
    pub fn extension_iphone() -> ExtensionConfig {
        extension("iphone", "secret")
    }

    /// 任意ユーザの `ExtensionConfig`。
    pub fn extension(user: &str, password: &str) -> ExtensionConfig {
        ExtensionConfig {
            username: user.to_string(),
            password: password.to_string(),
        }
    }

    /// ループバック上で listen する `UasConfig`。realm は `sabiden-test`。
    pub fn uas_config() -> UasConfig {
        UasConfig {
            bind_addr: loopback_any(),
            realm: "sabiden-test".to_string(),
            max_expires: 3600,
        }
    }

    /// G.711 μ-law (PT 0) の SDP オファ / アンサ。
    /// `c=` と `m=audio` を引数の `addr` に紐付ける。
    /// RFC 4566 §5.7 (connection) / §5.14 (media) 準拠。
    pub fn sdp_pcmu(addr: SocketAddr) -> String {
        format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 {ip}\r\n\
             s=-\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            ip = addr.ip(),
            port = addr.port()
        )
    }

    /// テスト全体で目印になる Call-ID プレフィックス。
    /// 一意性が要らないテストでは `call_id("ngn-inbound")` のように
    /// 短い接頭辞で識別子を作って読みやすくできる。
    pub fn call_id(tag: &str) -> String {
        format!("{tag}-{}", new_call_id())
    }
}

// =============================================================================
// asserts: assert_sip_header! / status code assert (RFC 引用つき)
// =============================================================================

pub mod asserts {
    //! RFC 引用付きの可読 assertion ヘルパ。
    //!
    //! 期待値が一致しないときに「どの RFC 節に違反しているか」をエラーメッセージに
    //! 残すことで、failed test のログだけで原因が当たるようにする。

    use super::*;

    /// SIP ヘッダの値が期待値と一致することを確認する。
    /// (大小文字は内部的に正規化される: `SipHeaders::get` が小文字キーで保持する)
    ///
    /// # 例
    /// ```ignore
    /// assert_sip_header(&req, "CSeq", "1 INVITE", "RFC 3261 §8.1.1.5");
    /// ```
    #[track_caller]
    pub fn assert_sip_request_header(
        req: &SipRequest,
        header: &str,
        expected: &str,
        rfc_ref: &str,
    ) {
        let actual = req
            .headers
            .get(header)
            .unwrap_or_else(|| panic!("ヘッダ {} が無い ({})", header, rfc_ref));
        assert_eq!(
            actual, expected,
            "ヘッダ {} 不一致 ({}): expected={:?}, got={:?}",
            header, rfc_ref, expected, actual
        );
    }

    /// SIP レスポンスのステータスコードが期待値と一致することを確認する。
    #[track_caller]
    pub fn assert_status_code(resp: &SipResponse, expected: u16, rfc_ref: &str) {
        assert_eq!(
            resp.status_code, expected,
            "status code 不一致 ({}): expected={}, got={} ({})",
            rfc_ref, expected, resp.status_code, resp.reason
        );
    }

    /// SIP リクエストのメソッドが期待値と一致することを確認する。
    #[track_caller]
    pub fn assert_method(req: &SipRequest, expected: SipMethod, rfc_ref: &str) {
        assert_eq!(
            req.method, expected,
            "method 不一致 ({}): expected={:?}, got={:?}",
            rfc_ref, expected, req.method
        );
    }

    /// SIP ヘッダ値が期待文字列を **含む** ことを確認する (部分一致用、
    /// 例: `Via: SIP/2.0/UDP host;branch=...` の "branch=z9hG4bK..." 確認)。
    #[track_caller]
    pub fn assert_sip_request_header_contains(
        req: &SipRequest,
        header: &str,
        needle: &str,
        rfc_ref: &str,
    ) {
        let actual = req
            .headers
            .get(header)
            .unwrap_or_else(|| panic!("ヘッダ {} が無い ({})", header, rfc_ref));
        assert!(
            actual.contains(needle),
            "ヘッダ {} に {:?} が含まれていない ({}): got={:?}",
            header,
            needle,
            rfc_ref,
            actual
        );
    }
}

// =============================================================================
// builders: SipRequest/Response を組み立てるヘルパ
// =============================================================================

pub mod builders {
    //! テスト内で頻出する `SipRequest` を組み立てる builder 群。
    //!
    //! - `register_from_phone(...)`:
    //!   内線 UA (Linphone 等) が送る最小限の REGISTER (RFC 3261 §10.2)
    //! - `invite_from_phone(...)`:
    //!   内線 UA → sabiden 向けの INVITE (RFC 3261 §13.1)
    //! - `invite_from_ngn(...)`:
    //!   NGN P-CSCF → sabiden 向けの INVITE
    //! - `bye(...)`, `cancel(...)`:
    //!   既存ダイアログ向けの BYE / CANCEL

    use super::*;

    /// 内線 UA → sabiden UAS 向けの REGISTER。
    /// `authorization` を渡すと `Authorization:` ヘッダを乗せる。
    pub fn register_from_phone(
        local: &SocketAddr,
        user: &str,
        branch: &str,
        authorization: Option<&str>,
    ) -> SipRequest {
        let mut req = SipRequest::new(SipMethod::Register, "sip:sabiden");
        req.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", format!("<sip:{}@sabiden>;tag={}", user, new_tag()));
        req.headers.set("To", format!("<sip:{}@sabiden>", user));
        req.headers.set("Call-ID", new_call_id());
        req.headers.set("CSeq", "1 REGISTER");
        req.headers
            .set("Contact", format!("<sip:{}@{}>", user, local));
        req.headers.set("Expires", "300");
        if let Some(a) = authorization {
            req.headers.set("Authorization", a);
        }
        req
    }

    /// 内線 UA → sabiden UAS 向けの INVITE。
    pub fn invite_from_phone(
        local: &SocketAddr,
        user: &str,
        request_uri: &str,
        branch: &str,
        authorization: Option<&str>,
    ) -> SipRequest {
        let mut req = SipRequest::new(SipMethod::Invite, request_uri);
        req.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", format!("<sip:{}@sabiden>;tag={}", user, new_tag()));
        req.headers.set("To", format!("<{}>", request_uri));
        req.headers.set("Call-ID", new_call_id());
        req.headers.set("CSeq", "1 INVITE");
        req.headers
            .set("Contact", format!("<sip:{}@{}>", user, local));
        if let Some(a) = authorization {
            req.headers.set("Authorization", a);
        }
        req
    }

    /// NGN P-CSCF → sabiden 向けの INVITE。
    /// `body` は SDP オファ (空でもよい)。
    pub fn invite_from_ngn(
        ngn_addr: &SocketAddr,
        request_uri: &str,
        call_id: &str,
        branch: &str,
        body: Vec<u8>,
    ) -> SipRequest {
        let mut req = SipRequest::new(SipMethod::Invite, request_uri);
        req.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", ngn_addr, branch));
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-test");
        req.headers.set("To", format!("<{}>", request_uri));
        req.headers.set("Call-ID", call_id.to_string());
        req.headers.set("CSeq", "1 INVITE");
        if !body.is_empty() {
            req.headers.set("Content-Type", "application/sdp");
        }
        req.body = body;
        req
    }

    /// NGN P-CSCF → sabiden 向けの任意メソッドのリクエスト。
    ///
    /// `NgnInboundHandler` が NOTIFY / SUBSCRIBE / PRACK / PUBLISH / UPDATE /
    /// INFO / MESSAGE / REFER 等を個別に応答するかを検証するためのビルダ
    /// (Issue #110)。 `invite_from_ngn` と同じ最小ヘッダ集合 (Via / From / To /
    /// Call-ID / CSeq / Max-Forwards) を載せる。
    pub fn request_from_ngn(
        ngn_addr: &SocketAddr,
        method: SipMethod,
        request_uri: &str,
        call_id: &str,
        branch: &str,
    ) -> SipRequest {
        let method_str = method.as_str().to_string();
        let mut req = SipRequest::new(method, request_uri);
        req.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", ngn_addr, branch));
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-test");
        req.headers.set("To", format!("<{}>", request_uri));
        req.headers.set("Call-ID", call_id.to_string());
        req.headers.set("CSeq", format!("1 {}", method_str));
        req
    }

    /// 既存ダイアログを終了する BYE (RFC 3261 §15.1.1)。
    pub fn bye(
        from_addr: &SocketAddr,
        request_uri: &str,
        call_id: &str,
        branch: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> SipRequest {
        let mut req = SipRequest::new(SipMethod::Bye, request_uri);
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch={}", from_addr, branch),
        );
        req.headers.set(
            "From",
            format!("<sip:caller@ntt-east.ne.jp>;tag={}", from_tag),
        );
        req.headers
            .set("To", format!("<{}>;tag={}", request_uri, to_tag));
        req.headers.set("Call-ID", call_id.to_string());
        req.headers.set("CSeq", "2 BYE");
        req
    }

    /// 進行中 INVITE を打ち切る CANCEL (RFC 3261 §9.1)。
    /// `invite` の Via / From / To / Call-ID / CSeq 番号を引き継ぎ method=CANCEL。
    pub fn cancel(invite: &SipRequest) -> SipRequest {
        // crate::sip::uac::build_cancel が公開されているのでそれを利用するのが
        // 本来望ましいが、`invite_cseq` を別引数で渡す必要があるため、
        // ここでは CSeq を直接拾う実装にする (テスト専用、production と等価)。
        let cseq = invite
            .headers
            .get("cseq")
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1);
        crate::sip::uac::build_cancel(invite, cseq)
    }

    /// 既存 `ServerTransaction` から [`crate::sip::uas::ResponderHandle`] を
    /// 構築するテスト用ヘルパ (Issue #106)。
    ///
    /// 過去は `ResponderHandle::__test_new` という production-side test hook が
    /// uas.rs に露出していたが、CLAUDE.md §6.3 違反のため撤去し、本ヘルパに
    /// 集約した。`crate::testing` モジュールは `#[cfg(test)]` ゲート済みのため
    /// production ビルドには含まれない (`src/testing.rs:33` の
    /// `#![cfg(test)]` 参照)。
    pub fn responder_handle_for_test(
        tx: crate::sip::transaction::ServerTransaction,
    ) -> crate::sip::uas::ResponderHandle {
        crate::sip::uas::ResponderHandle::new(tx)
    }
}

// =============================================================================
// scripted: LegInviter のスクリプト化実装
// =============================================================================

pub mod scripted {
    //! [`crate::call::manager::LegInviter`] のスクリプト化テストダブル。
    //!
    //! orchestrator.rs / manager.rs にコピペで存在していた `ScriptedInviter`
    //! を 1 つに統合し、`ScriptedInviterBuilder` で振る舞いを宣言的に組み立てる。

    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    use anyhow::Result;
    use async_trait::async_trait;

    use crate::call::manager::{LegInviter, LegOutcome};
    use crate::sip::message::{SipMethod, SipRequest, SipResponse};
    use crate::sip::uac::InvitePlan;

    /// 1 ターゲット に対する応答スクリプト。
    #[derive(Clone)]
    pub enum ScriptedAction {
        /// 即時に指定 status を返す。200 系なら `Established`、それ以外は `Failed`。
        ImmediateStatus(u16),
        /// `delay_ms` 待機してから status を返す。
        DelayedStatus { delay_ms: u64, status: u16 },
        /// 応答を返さない (`fork_to_extensions` のタイムアウト パス検証用)。
        NeverRespond,
    }

    impl ScriptedAction {
        pub fn ok() -> Self {
            Self::ImmediateStatus(200)
        }
        pub fn ok_with_body(body: Vec<u8>) -> ScriptedActionWithBody {
            ScriptedActionWithBody {
                action: Self::ImmediateStatus(200),
                body,
            }
        }
        pub fn busy() -> Self {
            Self::ImmediateStatus(486)
        }
        pub fn delayed_ok(delay_ms: u64) -> Self {
            Self::DelayedStatus {
                delay_ms,
                status: 200,
            }
        }
    }

    /// `ScriptedAction` + 200 OK 時に乗せる SDP body。
    pub struct ScriptedActionWithBody {
        pub action: ScriptedAction,
        pub body: Vec<u8>,
    }

    /// スクリプト化された [`LegInviter`]。
    ///
    /// - target_uri ごとに [`ScriptedAction`] を仕込める。スクリプトに無い
    ///   target は既定 (`default_action`) を返す。
    /// - 200 OK で返す SDP body は `default_body` または `script_with_body`
    ///   で個別指定可能。
    /// - `seen_targets` / `call_count` で観測できる。
    pub struct ScriptedInviter {
        scripts: StdMutex<HashMap<String, ScriptedAction>>,
        bodies: StdMutex<HashMap<String, Vec<u8>>>,
        default_action: ScriptedAction,
        default_body: Vec<u8>,
        seen: StdMutex<Vec<String>>,
        count: AtomicUsize,
    }

    impl ScriptedInviter {
        pub fn builder() -> ScriptedInviterBuilder {
            ScriptedInviterBuilder::default()
        }

        pub fn call_count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }

        pub fn seen_targets(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    /// 宣言的に `ScriptedInviter` を組み立てる Builder。
    #[derive(Default)]
    pub struct ScriptedInviterBuilder {
        scripts: HashMap<String, ScriptedAction>,
        bodies: HashMap<String, Vec<u8>>,
        default_action: Option<ScriptedAction>,
        default_body: Vec<u8>,
    }

    impl ScriptedInviterBuilder {
        /// target_uri に対して特定の応答スクリプトを設定する。
        pub fn script(mut self, target: impl Into<String>, action: ScriptedAction) -> Self {
            self.scripts.insert(target.into(), action);
            self
        }

        /// target_uri に対して 200 OK 応答 + SDP body を設定する。
        pub fn script_with_body(
            mut self,
            target: impl Into<String>,
            action: ScriptedAction,
            body: Vec<u8>,
        ) -> Self {
            let target = target.into();
            self.scripts.insert(target.clone(), action);
            self.bodies.insert(target, body);
            self
        }

        /// デフォルトのアクション (script に無い target で使う)。
        pub fn default_action(mut self, action: ScriptedAction) -> Self {
            self.default_action = Some(action);
            self
        }

        /// 200 OK 応答時に乗せる既定 SDP body。
        pub fn default_body(mut self, body: Vec<u8>) -> Self {
            self.default_body = body;
            self
        }

        pub fn build(self) -> Arc<ScriptedInviter> {
            Arc::new(ScriptedInviter {
                scripts: StdMutex::new(self.scripts),
                bodies: StdMutex::new(self.bodies),
                default_action: self
                    .default_action
                    .unwrap_or(ScriptedAction::ImmediateStatus(486)),
                default_body: self.default_body,
                seen: StdMutex::new(Vec::new()),
                count: AtomicUsize::new(0),
            })
        }
    }

    fn make_response(status: u16, body: Vec<u8>) -> SipResponse {
        let mut headers = SipHeaders::new();
        headers.set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKscripted");
        headers.set("From", "<sip:test>;tag=t");
        headers.set("To", "<sip:test>;tag=ext");
        headers.set("Call-ID", "scripted");
        headers.set("CSeq", "1 INVITE");
        SipResponse {
            status_code: status,
            reason: "Test".to_string(),
            headers,
            body,
        }
    }

    fn make_plan(target: &str) -> InvitePlan {
        let mut req = SipRequest::new(SipMethod::Invite, target);
        req.headers
            .set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKscripted");
        req.headers.set("From", "<sip:test>;tag=t");
        req.headers.set("To", "<sip:test>");
        req.headers.set("Call-ID", "scripted");
        req.headers.set("CSeq", "1 INVITE");
        InvitePlan {
            request: req,
            cseq: 1,
            target_uri: target.to_string(),
            session_expires: 300,
        }
    }

    #[async_trait]
    impl LegInviter for ScriptedInviter {
        async fn invite(&self, target_uri: &str, _sdp: &[u8]) -> Result<LegOutcome> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(target_uri.to_string());

            let action = {
                let mut scripts = self.scripts.lock().unwrap();
                scripts
                    .remove(target_uri)
                    .unwrap_or_else(|| self.default_action.clone())
            };
            let body = self
                .bodies
                .lock()
                .unwrap()
                .remove(target_uri)
                .unwrap_or_else(|| self.default_body.clone());

            match action {
                ScriptedAction::ImmediateStatus(code) => Ok(emit(target_uri, code, body)),
                ScriptedAction::DelayedStatus { delay_ms, status } => {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    Ok(emit(target_uri, status, body))
                }
                ScriptedAction::NeverRespond => {
                    // テスト時間を消費しないよう仮想的に「ずっと待つ」。
                    futures_no_response().await;
                    unreachable!()
                }
            }
        }
    }

    fn emit(target: &str, code: u16, body: Vec<u8>) -> LegOutcome {
        if (200..300).contains(&code) {
            LegOutcome::Established {
                plan: make_plan(target),
                response: make_response(code, body),
            }
        } else {
            LegOutcome::Failed {
                plan: make_plan(target),
                status: code,
            }
        }
    }

    async fn futures_no_response() {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}

// =============================================================================
// pcsf: Mock NTT NGN P-CSCF
// =============================================================================

pub mod pcsf {
    //! NTT NGN P-CSCF (REGISTER 受付 / 着信用 INVITE 発信) を模擬する。
    //!
    //! `MockNgnPcsf::start` で UdpSocket を bind し、別 task で受信ループを
    //! 駆動する。
    //!
    //! - REGISTER 受信時: 設定された `ScriptedInviter` 風スクリプトに従って
    //!   401 → 200 を返すか、即 200 を返す。
    //! - INVITE 受信時: (今のところは bridge / forking の検証で必要十分な)
    //!   100 Trying → 200 OK を返す。事前に `inject_invite` を呼べば
    //!   sabiden に向けて NGN 発の INVITE を流せる。

    use super::*;

    /// NGN 側で REGISTER に対する応答をどうするかのスクリプト。
    pub enum NgnRegisterScript {
        /// 即 200 OK (auth 検証なし、NGN 直収モードを模擬)。
        AlwaysAccept,
        /// 401 → 200 OK (Digest 認証を期待)。
        ExpectDigest {
            realm: String,
            /// nonce は内部で固定値 (テスト再現性のため)。
            nonce: String,
        },
    }

    /// NGN INVITE 受信時の応答スクリプト。
    pub enum NgnInviteScript {
        /// 100 → 200 OK (SDP answer は引数で指定)。
        Accept { answer_sdp: Vec<u8> },
        /// 100 → 4xx で拒否 (例: 486 Busy Here)。
        Reject { code: u16, reason: String },
    }

    /// Mock P-CSCF ハンドル。
    pub struct MockNgnPcsf {
        pub addr: SocketAddr,
        socket: Arc<UdpSocket>,
        /// 直近の REGISTER / INVITE / ACK を蓄積する (テストで検証可能)。
        observed: Arc<Mutex<Vec<SipRequest>>>,
    }

    impl MockNgnPcsf {
        /// 受信ループを spawn して開始する。
        ///
        /// - `register_script`: REGISTER 受信時のロジック。
        /// - `invite_script`: 内線 → NGN 発信 (sabiden が UAC として送ってくる)
        ///   INVITE 受信時のロジック。
        pub async fn start(
            register_script: NgnRegisterScript,
            invite_script: NgnInviteScript,
        ) -> Result<Arc<Self>> {
            let socket = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await?);
            let addr = socket.local_addr()?;
            let observed = Arc::new(Mutex::new(Vec::new()));
            let me = Arc::new(Self {
                addr,
                socket: socket.clone(),
                observed: observed.clone(),
            });
            let driver = me.clone();
            tokio::spawn(async move {
                driver.run(register_script, invite_script).await;
            });
            Ok(me)
        }

        /// これまでに観測したリクエスト。
        pub async fn observed(&self) -> Vec<SipRequest> {
            self.observed.lock().await.clone()
        }

        /// sabiden 宛てに任意の INVITE を能動的に送る (NGN → 内線 着信フロー用)。
        pub async fn inject(&self, target: SocketAddr, request: &SipRequest) -> Result<()> {
            self.socket.send_to(&request.to_bytes(), target).await?;
            Ok(())
        }

        async fn run(self: Arc<Self>, reg_script: NgnRegisterScript, inv_script: NgnInviteScript) {
            let mut buf = vec![0u8; 8192];
            loop {
                let (n, peer) = match self.socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let parsed = match parse_message(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!(error=%e, "MockNgnPcsf: parse 失敗");
                        continue;
                    }
                };
                match parsed {
                    SipMessage::Request(req) => {
                        self.observed.lock().await.push(req.clone());
                        match req.method {
                            SipMethod::Register => {
                                self.handle_register(&req, peer, &reg_script).await;
                            }
                            SipMethod::Invite => {
                                self.handle_invite(&req, peer, &inv_script).await;
                            }
                            SipMethod::Bye => {
                                let mut resp = build_response_skeleton(&req, 200, "OK");
                                ensure_to_tag(&mut resp);
                                let _ = self.socket.send_to(&resp.to_bytes(), peer).await;
                            }
                            SipMethod::Ack => {
                                // RFC 3261 §17.2.7: ACK には応答しない。
                            }
                            SipMethod::Cancel => {
                                let resp = build_response_skeleton(&req, 200, "OK");
                                let _ = self.socket.send_to(&resp.to_bytes(), peer).await;
                            }
                            _ => {
                                let resp = build_response_skeleton(&req, 405, "Method Not Allowed");
                                let _ = self.socket.send_to(&resp.to_bytes(), peer).await;
                            }
                        }
                    }
                    SipMessage::Response(_) => {
                        // 応答は無視 (Mock NGN は応答する側)
                    }
                }
            }
        }

        async fn handle_register(
            &self,
            req: &SipRequest,
            peer: SocketAddr,
            script: &NgnRegisterScript,
        ) {
            match script {
                NgnRegisterScript::AlwaysAccept => {
                    let mut resp = build_response_skeleton(req, 200, "OK");
                    ensure_to_tag(&mut resp);
                    if let Some(c) = req.headers.get("contact") {
                        resp.headers.set("Contact", c);
                    }
                    resp.headers.set("Expires", "3600");
                    let _ = self.socket.send_to(&resp.to_bytes(), peer).await;
                }
                NgnRegisterScript::ExpectDigest { realm, nonce } => {
                    if req.headers.get("authorization").is_some() {
                        // 検証は Mock の責任ではないので 200 OK で受け入れる。
                        let mut resp = build_response_skeleton(req, 200, "OK");
                        ensure_to_tag(&mut resp);
                        let _ = self.socket.send_to(&resp.to_bytes(), peer).await;
                    } else {
                        let mut resp = build_response_skeleton(req, 401, "Unauthorized");
                        ensure_to_tag(&mut resp);
                        // RFC 7616 §3.3: mock server は first-time challenge と
                        // して stale=false / opaque 無しを返す (テスト UA は
                        // 1 回しか challenge を受けない設計)。
                        resp.headers.set(
                            "WWW-Authenticate",
                            build_www_authenticate(realm, nonce, false, None),
                        );
                        let _ = self.socket.send_to(&resp.to_bytes(), peer).await;
                    }
                }
            }
        }

        async fn handle_invite(
            &self,
            req: &SipRequest,
            peer: SocketAddr,
            script: &NgnInviteScript,
        ) {
            // 100 Trying は (RFC 3261 §17.2.1 上) 即送る。
            let trying = build_response_skeleton(req, 100, "Trying");
            let _ = self.socket.send_to(&trying.to_bytes(), peer).await;

            match script {
                NgnInviteScript::Accept { answer_sdp } => {
                    let mut resp = build_response_skeleton(req, 200, "OK");
                    ensure_to_tag(&mut resp);
                    resp.headers
                        .set("Contact", format!("<sip:ngn@{}>", self.addr));
                    if !answer_sdp.is_empty() {
                        resp.headers.set("Content-Type", "application/sdp");
                        resp.body = answer_sdp.clone();
                    }
                    let _ = self.socket.send_to(&resp.to_bytes(), peer).await;
                }
                NgnInviteScript::Reject { code, reason } => {
                    let mut resp = build_response_skeleton(req, *code, reason);
                    ensure_to_tag(&mut resp);
                    let _ = self.socket.send_to(&resp.to_bytes(), peer).await;
                }
            }
        }
    }

    /// レスポンスの To に tag が無ければ付与する (RFC 3261 §8.2.6.2)。
    fn ensure_to_tag(resp: &mut SipResponse) {
        if let Some(to) = resp.headers.get("to") {
            if !to.contains("tag=") {
                let new = format!("{};tag={}", to, new_tag());
                resp.headers.set("To", new);
            }
        }
    }
}

// =============================================================================
// ext_ua: Linphone 風内線 UA 模擬
// =============================================================================

pub mod ext_ua {
    //! Linphone / Zoiper 等の内線 UA を模擬するクライアント。
    //!
    //! 1 ハンドル = 1 UA = 1 UDP socket。`register_with_digest` で REGISTER を
    //! 通し、`send_invite` で INVITE を送り、応答を読む補助メソッドを提供する。

    use super::*;

    /// 内線 UA ハンドル。
    pub struct MockExtensionUa {
        pub local_addr: SocketAddr,
        pub user: String,
        pub password: String,
        socket: UdpSocket,
        cseq_register: u32,
    }

    impl MockExtensionUa {
        /// 新しい UDP ソケットを bind して UA を立てる。
        pub async fn bind(user: &str, password: &str) -> Result<Self> {
            let socket = UdpSocket::bind(fixtures::loopback_any()).await?;
            let local_addr = socket.local_addr()?;
            Ok(Self {
                local_addr,
                user: user.to_string(),
                password: password.to_string(),
                socket,
                cseq_register: 1,
            })
        }

        /// 認証付き REGISTER を 1 往復させる (401 → Authorization → 200)。
        pub async fn register_with_digest(&mut self, server: SocketAddr) -> Result<()> {
            // 1) authless REGISTER → 401
            let req1 = builders::register_from_phone(
                &self.local_addr,
                &self.user,
                &format!("z9hG4bKreg-{}", self.cseq_register),
                None,
            );
            self.socket.send_to(&req1.to_bytes(), server).await?;
            let resp = self.recv_response(Duration::from_secs(2)).await?;
            if resp.status_code != 401 {
                anyhow::bail!("REGISTER: 401 を期待 (got {})", resp.status_code);
            }
            let challenge = DigestChallenge::parse(
                resp.headers
                    .get("www-authenticate")
                    .ok_or_else(|| anyhow::anyhow!("WWW-Authenticate 無し"))?,
            )?;

            // 2) Authorization 付きで再送
            self.cseq_register += 1;
            let creds = DigestCredentials::new(&self.user, &self.password);
            let auth = creds.compute(&challenge, "REGISTER", "sip:sabiden", self.cseq_register);
            let req2 = builders::register_from_phone(
                &self.local_addr,
                &self.user,
                &format!("z9hG4bKreg-{}", self.cseq_register),
                Some(&auth.header_value),
            );
            self.socket.send_to(&req2.to_bytes(), server).await?;
            let resp = self.recv_response(Duration::from_secs(2)).await?;
            if resp.status_code != 200 {
                anyhow::bail!("REGISTER: 200 を期待 (got {})", resp.status_code);
            }
            Ok(())
        }

        /// 内線 → sabiden UAS への INVITE を送り、最終応答 (>=200) を返す。
        ///
        /// Issue #62 / RFC 3261 §22 以降、sabiden UAS は内線 INVITE に対して
        /// Digest challenge を出さない (REGISTER で確立した binding を信用)。
        /// 本ヘルパもそれに合わせ、Authorization ヘッダ無しで 1 発送って 100
        /// を読み飛ばし最終応答を返すだけの実装にする。
        ///
        /// 戻り値は受信した最初の `>=200` レスポンス。
        /// `request_uri` は INVITE の宛先 (例 "sip:0312345678@sabiden")。
        /// `body` は SDP オファ。
        pub async fn invite_with_digest(
            &mut self,
            server: SocketAddr,
            request_uri: &str,
            body: Vec<u8>,
        ) -> Result<SipResponse> {
            let mut req = builders::invite_from_phone(
                &self.local_addr,
                &self.user,
                request_uri,
                "z9hG4bKi1",
                None,
            );
            if !body.is_empty() {
                req.headers.set("Content-Type", "application/sdp");
                req.body = body;
            }
            self.socket.send_to(&req.to_bytes(), server).await?;

            // 100 Trying は読み飛ばし、最初の最終応答を返す。
            for _ in 0..5 {
                let resp = self.recv_response(Duration::from_secs(3)).await?;
                if resp.status_code >= 200 {
                    return Ok(resp);
                }
            }
            anyhow::bail!("最終応答が来ない")
        }

        /// 任意のリクエストをそのまま送る (CANCEL / BYE 等)。
        pub async fn send_request(&self, server: SocketAddr, req: &SipRequest) -> Result<()> {
            self.socket.send_to(&req.to_bytes(), server).await?;
            Ok(())
        }

        /// 任意の SIP メッセージ受信を 1 件読む。
        pub async fn recv_message(&self, deadline: Duration) -> Result<SipMessage> {
            let mut buf = vec![0u8; 8192];
            let (n, _) = time::timeout(deadline, self.socket.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("recv timeout"))?
                .map_err(|e| anyhow::anyhow!("recv err: {e}"))?;
            parse_message(&buf[..n])
        }

        /// `recv_message` を呼び出して `Response` のみを返す。
        pub async fn recv_response(&self, deadline: Duration) -> Result<SipResponse> {
            match self.recv_message(deadline).await? {
                SipMessage::Response(r) => Ok(r),
                SipMessage::Request(_) => anyhow::bail!("期待: Response, got Request"),
            }
        }

        /// `recv_message` を呼び出して `Request` のみを返す。
        pub async fn recv_request(&self, deadline: Duration) -> Result<SipRequest> {
            match self.recv_message(deadline).await? {
                SipMessage::Request(r) => Ok(r),
                SipMessage::Response(r) => {
                    anyhow::bail!("期待: Request, got Response (status={})", r.status_code)
                }
            }
        }

        pub fn socket(&self) -> &UdpSocket {
            &self.socket
        }
    }
}

// =============================================================================
// webrtc_browser: WS シグナリング browser 模擬
// =============================================================================

pub mod webrtc_browser {
    //! `MockWebrtcBrowser`: tokio-tungstenite を使った WebRTC シグナリング
    //! クライアント。
    //!
    //! 既存の `signaling.rs::tests::end_to_end_ws_*` で行っていた手書き
    //! セットアップを 1 ハンドルに集約する。
    //!
    //! - `connect`: `?token=...` で WS upgrade。
    //! - `send`: ClientMessage 互換 JSON を送信。
    //! - `recv`: 受信を 1 件読む。`PendingAnswers` 風: offer 後に answer を
    //!   `recv` で取り出して任意のロジックで検査できる。

    use super::*;

    use anyhow::{anyhow, Result};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

    pub struct MockWebrtcBrowser {
        ws: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    }

    impl MockWebrtcBrowser {
        /// `ws://addr/signal?token=...` に接続する。
        pub async fn connect(addr: SocketAddr, token: &str) -> Result<Self> {
            let url = format!("ws://{}/signal?token={}", addr, token);
            let (ws, _resp) = connect_async(&url)
                .await
                .map_err(|e| anyhow!("WS connect: {e}"))?;
            Ok(Self { ws })
        }

        /// JSON 文字列を送信する (例: `r#"{"type":"register","ext_id":"alice"}"#`)。
        pub async fn send_text(&mut self, text: &str) -> Result<()> {
            self.ws
                .send(WsMessage::Text(text.to_string()))
                .await
                .map_err(|e| anyhow!("WS send: {e}"))
        }

        /// 1 件受信し、テキスト frame を返す (Bin/Close は err)。
        pub async fn recv_text(&mut self) -> Result<String> {
            let frame = self
                .ws
                .next()
                .await
                .ok_or_else(|| anyhow!("WS stream ended"))?
                .map_err(|e| anyhow!("WS recv: {e}"))?;
            match frame {
                WsMessage::Text(t) => Ok(t),
                other => Err(anyhow!("unexpected WS frame: {:?}", other)),
            }
        }

        /// `PendingAnswers::deliver` 風: offer を送り、answer 文字列を待つ。
        pub async fn offer_and_wait_answer(&mut self, sdp_offer: &str) -> Result<String> {
            let payload = format!(
                r#"{{"type":"offer","sdp":{}}}"#,
                serde_json::to_string(sdp_offer)?
            );
            self.send_text(&payload).await?;
            let resp = self.recv_text().await?;
            // answer 形式: {"type":"answer","sdp":"..."}
            let v: serde_json::Value = serde_json::from_str(&resp)?;
            let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if typ != "answer" {
                return Err(anyhow!("expected answer, got: {}", resp));
            }
            Ok(v.get("sdp")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string())
        }
    }
}

// =============================================================================
// テスト: ハーネス自体のスモークテスト
// =============================================================================

#[cfg(test)]
mod self_tests {
    use super::*;
    use crate::call::manager::{fork_to_extensions, ForkResult};
    use scripted::{ScriptedAction, ScriptedInviter};

    /// Builder が空ならデフォルトの 486 で AllFailed。
    #[tokio::test]
    async fn scripted_inviter_default_busy() {
        let inviter = ScriptedInviter::builder().build();
        let result = fork_to_extensions(
            inviter.clone(),
            vec!["sip:a@host".into()],
            b"v=0\r\n".to_vec(),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(
            result,
            ForkResult::AllFailed {
                last_status: Some(486)
            }
        ));
        assert_eq!(inviter.call_count(), 1);
    }

    /// `script(target, ok)` で 200 OK を返せる。
    #[tokio::test]
    async fn scripted_inviter_explicit_ok() {
        let inviter = ScriptedInviter::builder()
            .script("sip:iphone@host", ScriptedAction::ok())
            .default_body(b"v=0\r\n".to_vec())
            .build();
        let result = fork_to_extensions(
            inviter.clone(),
            vec!["sip:iphone@host".into()],
            b"v=0\r\n".to_vec(),
            Duration::from_secs(1),
        )
        .await;
        match result {
            ForkResult::Answered { winner_uri, .. } => {
                assert_eq!(winner_uri, "sip:iphone@host");
            }
            _ => panic!("Answered 期待"),
        }
    }

    /// `assert_sip_request_header` の正常系。
    #[test]
    fn assert_helpers_smoke() {
        let mut req = SipRequest::new(SipMethod::Invite, "sip:dest@host");
        req.headers.set("CSeq", "1 INVITE");
        asserts::assert_sip_request_header(&req, "CSeq", "1 INVITE", "RFC 3261 §8.1.1.5");
        asserts::assert_method(&req, SipMethod::Invite, "RFC 3261 §7.1");
    }

    /// SDP テンプレが妥当な c= / m= を吐ける。
    #[test]
    fn fixtures_sdp_pcmu() {
        let addr: SocketAddr = "192.0.2.10:30000".parse().unwrap();
        let sdp = fixtures::sdp_pcmu(addr);
        assert!(sdp.contains("c=IN IP4 192.0.2.10"));
        assert!(sdp.contains("m=audio 30000 RTP/AVP 0"));
    }

    /// MockNgnPcsf は受信したリクエストを蓄積し、REGISTER に 200 OK を返せる。
    #[tokio::test]
    async fn mock_ngn_pcsf_accepts_register() {
        use crate::testing::pcsf::{MockNgnPcsf, NgnInviteScript, NgnRegisterScript};

        let pcsf = MockNgnPcsf::start(
            NgnRegisterScript::AlwaysAccept,
            NgnInviteScript::Reject {
                code: 486,
                reason: "Busy".into(),
            },
        )
        .await
        .unwrap();
        let phone = ext_ua::MockExtensionUa::bind("iphone", "secret")
            .await
            .unwrap();
        let req =
            builders::register_from_phone(&phone.local_addr, "iphone", "z9hG4bKsmoke-pcsf", None);
        phone.send_request(pcsf.addr, &req).await.unwrap();
        let resp = phone.recv_response(Duration::from_secs(2)).await.unwrap();
        assert_eq!(resp.status_code, 200);
    }
}
