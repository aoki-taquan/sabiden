//! NGN ⇔ 内線 を結ぶ通話オーケストレーション
//!
//! 本モジュールは [`crate::sip::transaction::TransactionLayer`] と
//! [`crate::sip::uas::ExtensionUas`] / [`crate::sip::uac::Uac`] を
//! 結線する糊コードを集約する。これまで `main.rs` で
//! `_inbound_rx` として捨てられていた NGN 着信 INVITE を受け、
//! 内線フォーク (`call::manager::fork_to_extensions`) を通じて
//! 通話を確立する役目を負う。
//!
//! # 役割分担
//!
//! - [`NgnInboundHandler`]: NGN 側 `TransactionLayer` の `inbound_rx`
//!   から INVITE / BYE / ACK を取り出し、`ServerTransaction` の
//!   100 Trying 即返答 → 内線フォーク → 200 OK を NGN へ返すまでを駆動する。
//! - [`UasEventHandler`]: 内線 UAS から流れてくる
//!   [`crate::sip::uas::UasEvent`] を読み、内線発信 INVITE を
//!   NGN 側 [`Uac`] でプロキシする。
//!
//! # Phase 1 の制限
//!
//! - SDP は透過 (sabiden は SDP を書き換えず、内線が NGN とピア to ピアで
//!   RTP を交換するモード)。`RtpBridge` を起動する場合は SDP 書き換えが
//!   必要だが、これは Phase 3 (Issue #6 系) で対応予定。
//! - BYE / CANCEL の B2BUA 連動は最低限。NGN 側ダイアログは UacDialog で
//!   保持するが、内線側ダイアログ状態は UAS 側 ServerTransaction に閉じる。
//! - 1 通話のみ前提 (HashMap で複数通話に拡張済みだが Race を厳密に
//!   保証するには更なるテストが必要)。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use super::manager::{fork_to_extensions, ForkResult, LegInviter, UacForker};
use crate::sip::message::{SipMethod, SipRequest, SipResponse};
use crate::sip::registrar::ExtensionRegistrar;
use crate::sip::transaction::{
    build_response_skeleton, InboundRequest, ServerTransaction, TransactionLayer,
};
use crate::sip::uac::{InviteOutcome, Uac};
use crate::sip::uas::UasEvent;

/// NGN 着信処理の動作パラメータ。
#[derive(Debug, Clone)]
pub struct NgnInboundConfig {
    /// 内線フォーク全体の最大待機時間。これを超えると 408/487 で打ち切る。
    pub fork_timeout: Duration,
    /// `UasConfig` 由来の realm (内線側 To ヘッダ等で使用)。
    pub realm: String,
}

impl Default for NgnInboundConfig {
    fn default() -> Self {
        Self {
            fork_timeout: Duration::from_secs(20),
            realm: "sabiden".to_string(),
        }
    }
}

/// 内線フォーク用 INVITE ビルダ。
///
/// 本番経路では `Uac` を内線側ソケットで構築した [`UacForker`] を渡す。
/// テストでは `Arc<dyn LegInviter>` の Mock を渡せる。
pub type ExtInviter = Arc<dyn LegInviter>;

/// NGN 着信ハンドラ。`TransactionLayer::spawn` の `inbound_rx` を消費する。
pub struct NgnInboundHandler {
    socket: Arc<UdpSocket>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    /// Call-ID → ServerTransaction (BYE/ACK で再利用するため保持する)。
    pending: Arc<Mutex<HashMap<String, Arc<Mutex<ServerTransaction>>>>>,
}

impl NgnInboundHandler {
    pub fn new(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            inviter,
            extensions,
            cfg,
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// `inbound_rx` を駆動するループを spawn する。
    pub fn spawn(self: Arc<Self>, mut inbound_rx: mpsc::UnboundedReceiver<InboundRequest>) {
        tokio::spawn(async move {
            while let Some(inbound) = inbound_rx.recv().await {
                let me = self.clone();
                // 1 INVITE = 1 fork で並列に処理する (BYE 等は軽いので spawn 不要)
                tokio::spawn(async move {
                    if let Err(e) = me.handle_inbound(inbound).await {
                        warn!(error=%e, "NGN 着信処理失敗");
                    }
                });
            }
            debug!("NGN inbound loop 終了");
        });
    }

    async fn handle_inbound(&self, inbound: InboundRequest) -> Result<()> {
        let InboundRequest { request, remote } = inbound;
        match request.method {
            SipMethod::Invite => self.handle_invite(request, remote).await,
            SipMethod::Bye => self.handle_bye(request, remote).await,
            SipMethod::Ack => {
                // RFC 3261 §17.2.7: ACK は応答を要しない。pending を 1 つ消す。
                if let Some(call_id) = request.headers.get("call-id") {
                    let mut pending = self.pending.lock().await;
                    pending.remove(call_id);
                }
                Ok(())
            }
            SipMethod::Cancel => {
                let stx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut tx = stx;
                tx.respond(build_response_skeleton(tx.request(), 200, "OK"))
                    .await?;
                Ok(())
            }
            SipMethod::Options => {
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                tx.respond(build_response_skeleton(tx.request(), 200, "OK"))
                    .await?;
                Ok(())
            }
            ref other => {
                warn!(?other, "NGN 側で未対応メソッド → 405");
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                tx.respond(build_response_skeleton(
                    tx.request(),
                    405,
                    "Method Not Allowed",
                ))
                .await?;
                Ok(())
            }
        }
    }

    async fn handle_invite(&self, request: SipRequest, remote: SocketAddr) -> Result<()> {
        let call_id = request
            .headers
            .get("call-id")
            .ok_or_else(|| anyhow!("Call-ID なし"))?
            .to_string();
        info!(%remote, %call_id, "NGN 着信 INVITE");

        let stx = ServerTransaction::new(request.clone(), remote, self.socket.clone())?;
        let stx = Arc::new(Mutex::new(stx));
        // pending に登録 (ACK / BYE 受信時に同じ ServerTransaction を引けるよう)
        {
            let mut pending = self.pending.lock().await;
            pending.insert(call_id.clone(), stx.clone());
        }

        // RFC 3261 §17.2.1: INVITE に対して 100 Trying を即送信。
        {
            let mut tx = stx.lock().await;
            let trying = build_response_skeleton(tx.request(), 100, "Trying");
            tx.respond(trying).await?;
        }

        // 登録済み内線の AOR 一覧を取得し target URI に変換する
        let bindings = self.extensions.snapshot().await;
        if bindings.is_empty() {
            warn!("登録内線なし → 480 Temporarily Unavailable");
            self.respond(&stx, 480, "Temporarily Unavailable").await?;
            self.pending.lock().await.remove(&call_id);
            return Ok(());
        }
        let targets: Vec<String> = bindings
            .iter()
            .map(|(_, b)| b.contact_uri.clone())
            .collect();

        // フォーク
        let sdp = request.body.clone();
        let result =
            fork_to_extensions(self.inviter.clone(), targets, sdp, self.cfg.fork_timeout).await;

        match result {
            ForkResult::Answered {
                winner_uri,
                response,
            } => {
                info!(%winner_uri, "NGN 側に 200 OK を返す");
                // 内線の 200 OK SDP をそのまま NGN へ転送する (Phase 1 透過)
                let mut tx = stx.lock().await;
                let mut resp_to_ngn = build_response_skeleton(tx.request(), 200, "OK");
                if !response.body.is_empty() {
                    resp_to_ngn.body = response.body;
                    resp_to_ngn.headers.set("Content-Type", "application/sdp");
                }
                // To に tag を必ず付与 (RFC 3261 §8.2.6.2)
                ensure_to_tag(&mut resp_to_ngn);
                // sabiden の Contact (NGN 側ローカル) を載せる
                resp_to_ngn.headers.set(
                    "Contact",
                    format!("<sip:sabiden@{}>", self.socket.local_addr()?),
                );
                tx.respond(resp_to_ngn).await?;
            }
            ForkResult::AllFailed { last_status } => {
                let code = last_status.unwrap_or(486);
                let reason = if code == 486 { "Busy Here" } else { "Declined" };
                self.respond(&stx, code, reason).await?;
                self.pending.lock().await.remove(&call_id);
            }
            ForkResult::Timeout => {
                self.respond(&stx, 408, "Request Timeout").await?;
                self.pending.lock().await.remove(&call_id);
            }
        }
        Ok(())
    }

    async fn handle_bye(&self, request: SipRequest, remote: SocketAddr) -> Result<()> {
        // BYE は新しい transaction で 200 OK を返す。NGN 側ダイアログのテイクダウンは
        // 内線側 dialog 終了処理側で完了済みである前提 (Phase 1 簡易実装)。
        let mut tx = ServerTransaction::new(request.clone(), remote, self.socket.clone())?;
        let resp = build_response_skeleton(tx.request(), 200, "OK");
        tx.respond(resp).await?;
        if let Some(cid) = request.headers.get("call-id") {
            self.pending.lock().await.remove(cid);
        }
        Ok(())
    }

    async fn respond(
        &self,
        stx: &Arc<Mutex<ServerTransaction>>,
        status: u16,
        reason: &str,
    ) -> Result<()> {
        let mut tx = stx.lock().await;
        let mut resp = build_response_skeleton(tx.request(), status, reason);
        ensure_to_tag(&mut resp);
        tx.respond(resp).await
    }
}

/// レスポンスの To に tag が無ければ付与する (RFC 3261 §8.2.6.2)。
fn ensure_to_tag(resp: &mut SipResponse) {
    if let Some(to) = resp.headers.get("to") {
        if !to.contains("tag=") {
            let new = format!("{};tag={}", to, crate::sip::utils::new_tag());
            resp.headers.set("To", new);
        }
    }
}

/// `UasEvent` を捌くハンドラ。内線発信 INVITE / BYE を NGN 側 UAC へ転送する。
pub struct UasEventHandler {
    /// NGN 側 UAC。ここから NGN へ INVITE する。
    ngn_uac: Arc<Uac>,
    /// 確立済み NGN 側ダイアログ (Call-ID → UacDialog)。
    /// 現在は BYE のクリーンアップ用にスロットを確保するのみ。
    /// Phase 2.5: Dialog の本格管理は #5 拡張で対応。
    _dialogs: Arc<Mutex<HashMap<String, ()>>>,
}

impl UasEventHandler {
    pub fn new(ngn_uac: Arc<Uac>) -> Arc<Self> {
        Arc::new(Self {
            ngn_uac,
            _dialogs: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// `event_rx` を駆動する。`mpsc::UnboundedSender<UasEvent>` 側を
    /// `ExtensionUas::with_handler` に渡しておく。
    pub fn spawn(self: Arc<Self>, mut event_rx: mpsc::UnboundedReceiver<UasEvent>) {
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.handle_event(event).await {
                        warn!(error=%e, "UAS event 処理失敗");
                    }
                });
            }
            debug!("UAS event loop 終了");
        });
    }

    async fn handle_event(&self, event: UasEvent) -> Result<()> {
        match event {
            UasEvent::Invite {
                from_aor,
                request,
                remote,
                responder,
            } => {
                info!(%from_aor, %remote, "内線発信 → NGN へプロキシ");
                // 宛先 URI は INVITE Request-URI をそのまま使う (Phase 1 単純化)。
                let target = request.uri.clone();
                let sdp = if request.body.is_empty() {
                    None
                } else {
                    Some(request.body.clone())
                };
                let plan = self.ngn_uac.build_invite(&target, sdp.as_deref(), None);
                let outcome = self.ngn_uac.invite(plan, sdp).await;
                match outcome {
                    Ok(InviteOutcome::Established(call)) => {
                        // Phase 1 透過: 内線側へは `quick(200, "OK")` で簡易 200 OK。
                        // NGN 側 SDP answer を内線へ転送するには
                        // `ResponderHandle::respond_with_body` の追加が必要 (#16 で対応予定)。
                        responder.quick(200, "OK").await?;
                        let _ = call.dialog;
                        let _ = call.response;
                        Ok(())
                    }
                    Ok(InviteOutcome::Failed { response }) => {
                        warn!(code = response.status_code, "NGN 側 INVITE 失敗");
                        responder
                            .quick(response.status_code, response.reason.as_str())
                            .await
                    }
                    Err(e) => {
                        warn!(error=%e, "NGN 側 INVITE トランスポート失敗 → 503");
                        responder.quick(503, "Service Unavailable").await
                    }
                }
            }
            UasEvent::Bye { request, remote } => {
                debug!(%remote, "内線 BYE → NGN にも BYE 必要 (Phase 2.5)");
                let _ = request;
                Ok(())
            }
        }
    }
}

/// 既定の本番経路用 [`UacForker`] を構築するヘルパ。
///
/// 内線網用の別 `UdpSocket` と `TransactionLayer` を持つ `Uac` を内側で
/// 構築する想定。本関数は `main.rs` の起動順序を整えるだけなので、
/// 引数として既に構築済みの `Uac` を受け取るだけでよい。
pub fn make_forker(uac: Arc<Uac>) -> ExtInviter {
    Arc::new(UacForker {
        uac,
        targets: HashMap::new(),
    })
}

/// NGN 側の `TransactionLayer` を使い、`inbound_rx` を駆動して
/// `NgnInboundHandler` を起動する高水準ヘルパ。
///
/// `main.rs` から呼ばれる結線エントリポイント。
pub fn wire_ngn_inbound(
    _layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
) -> Arc<NgnInboundHandler> {
    let handler = NgnInboundHandler::new(socket, inviter, extensions, cfg);
    handler.clone().spawn(inbound_rx);
    handler
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::manager::LegOutcome;
    use crate::sip::message::{parse_message, SipMessage};
    use crate::sip::transaction::TransactionLayer;
    use crate::sip::uac::InvitePlan;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering as AOrd};
    use std::sync::Mutex as StdMutex;
    use tokio::net::UdpSocket;

    /// テスト用 inviter: 全ターゲットに対し指定 status を返す。
    struct ScriptedInviter {
        status: u16,
        body: Vec<u8>,
        called: AtomicUsize,
        seen_targets: StdMutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl LegInviter for ScriptedInviter {
        async fn invite(&self, target: &str, _sdp: &[u8]) -> Result<LegOutcome> {
            self.called.fetch_add(1, AOrd::SeqCst);
            self.seen_targets.lock().unwrap().push(target.to_string());
            let mut headers = crate::sip::message::SipHeaders::new();
            headers.set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKt");
            headers.set("From", "<sip:test>;tag=t");
            headers.set("To", "<sip:test>;tag=ext");
            headers.set("Call-ID", "scripted");
            headers.set("CSeq", "1 INVITE");
            let response = SipResponse {
                status_code: self.status,
                reason: "Test".to_string(),
                headers,
                body: self.body.clone(),
            };
            let mut req = SipRequest::new(SipMethod::Invite, target);
            req.headers
                .set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKt");
            req.headers.set("From", "<sip:test>;tag=t");
            req.headers.set("To", "<sip:test>");
            req.headers.set("Call-ID", "scripted");
            req.headers.set("CSeq", "1 INVITE");
            let plan = InvitePlan {
                request: req,
                cseq: 1,
                target_uri: target.to_string(),
                session_expires: 300,
            };
            if (200..300).contains(&self.status) {
                Ok(LegOutcome::Established { plan, response })
            } else {
                Ok(LegOutcome::Failed {
                    plan,
                    status: self.status,
                })
            }
        }
    }

    /// NGN 着信 INVITE → 内線フォーク (200) → 200 OK が NGN 側に届く。
    #[tokio::test]
    async fn ngn_invite_forwards_200_back() {
        // sabiden の NGN 側ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();

        // フェイク NGN クライアント (UA 役)
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _ngn_addr = ngn_sock.local_addr().unwrap();

        // 内線登録テーブルにダミー内線を 1 件入れておく
        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6001".to_string(),
                "127.0.0.1:6001".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        // モック inviter: 200 OK + ダミー SDP
        let inviter = Arc::new(ScriptedInviter {
            status: 200,
            body: b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n".to_vec(),
            called: AtomicUsize::new(0),
            seen_targets: StdMutex::new(Vec::new()),
        });

        // TransactionLayer + 着信ハンドラを起動
        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
        );

        // フェイク NGN から INVITE を送信
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!(
                "SIP/2.0/UDP {};branch=z9hG4bKngn1",
                ngn_sock.local_addr().unwrap()
            ),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-invite-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\n".to_vec();
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 100 Trying と 200 OK が届くまで複数応答を読む
        let mut buf = vec![0u8; 8192];
        let mut got_100 = false;
        let mut got_200 = false;
        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        match r.status_code {
                            100 => got_100 = true,
                            200 => {
                                got_200 = true;
                                // SDP 透過確認
                                assert!(!r.body.is_empty(), "200 OK には SDP body があるはず");
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_100, "100 Trying が NGN 側に届くべき");
        assert!(got_200, "200 OK が NGN 側に届くべき");
        assert!(
            inviter.called.load(AOrd::SeqCst) >= 1,
            "内線へ INVITE される"
        );
    }

    /// 登録内線が 0 件なら 480 Temporarily Unavailable で返る。
    #[tokio::test]
    async fn ngn_invite_with_no_extensions_returns_480() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        let inviter = Arc::new(ScriptedInviter {
            status: 200,
            body: Vec::new(),
            called: AtomicUsize::new(0),
            seen_targets: StdMutex::new(Vec::new()),
        });

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!(
                "SIP/2.0/UDP {};branch=z9hG4bKngn-noext",
                ngn_sock.local_addr().unwrap()
            ),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-noext-cid");
        invite.headers.set("CSeq", "1 INVITE");
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let mut got_480 = false;
        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(2), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 480 {
                            got_480 = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_480, "480 Temporarily Unavailable が返るべき");
        assert_eq!(
            inviter.called.load(AOrd::SeqCst),
            0,
            "内線が無ければ inviter は呼ばれない"
        );
    }

    /// `make_forker` は与えられた Uac を内包する forker を生成する。
    #[tokio::test]
    async fn make_forker_wraps_uac() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let (layer, _rx) = TransactionLayer::spawn(sock.clone());
        let cfg = crate::sip::uac::UacConfig {
            local_uri: "sip:sabiden@local".to_string(),
            domain: "local".to_string(),
            local_addr: sock.local_addr().unwrap(),
            user_agent: "test/0.1".to_string(),
        };
        let uac = Arc::new(Uac::new(cfg, layer, server));
        let forker = make_forker(uac);
        // 型確認のみ (本体は manager::tests でカバー)
        let _ = forker;
    }

    /// 内線 UA → 内線 UAS → UasEventHandler → NGN UAC → フェイク NGN の
    /// end-to-end 結線テスト。Issue #15 の主目的である UAS event ハンドラの
    /// プロキシ動作を確認する。
    #[tokio::test]
    async fn uas_event_proxies_invite_to_ngn() {
        use crate::config::{ExtensionConfig, UasConfig};
        use crate::sip::auth::{DigestChallenge, DigestCredentials};
        use crate::sip::uas::ExtensionUas;
        use crate::sip::utils::{new_call_id, new_tag};

        // (1) フェイク NGN サーバ: INVITE を受けたら 200 OK を返す
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_invite_seen = Arc::new(StdMutex::new(false));
        let ngn_invite_seen_c = ngn_invite_seen.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE を受信して 200 OK を返す
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(req) = parsed {
                assert_eq!(req.method, SipMethod::Invite);
                *ngn_invite_seen_c.lock().unwrap() = true;
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
                // ACK 受信 (drop)
                let _ = fake_ngn_clone.recv_from(&mut buf).await;
            }
        });

        // (2) NGN 側 UAC: TransactionLayer + Uac
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // (3) 内線 UAS bind
        let uas_cfg = UasConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
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

        // (4) UasEventHandler を起動 (UAS event → NGN UAC)
        let handler = UasEventHandler::new(ngn_uac);
        handler.spawn(event_rx);

        // (5) フェイク内線 UA から INVITE を送る (Digest 認証付き)
        let phone = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let phone_local = phone.local_addr().unwrap();

        // 5-a) 認証なし INVITE → 401
        let mut req = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKuasint1", phone_local),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", format!("<sip:iphone@sabiden>;tag={}", new_tag()));
        req.headers.set("To", "<sip:dest@sabiden>");
        req.headers.set("Call-ID", new_call_id());
        req.headers.set("CSeq", "1 INVITE");
        req.headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        phone.send_to(&req.to_bytes(), uas_addr).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), phone.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!("expected response"),
        };
        assert_eq!(resp.status_code, 401);
        let challenge =
            DigestChallenge::parse(resp.headers.get("www-authenticate").unwrap()).unwrap();

        // 5-b) Authorization 付きで再送
        let creds = DigestCredentials::new("iphone", "secret");
        let auth = creds.compute(&challenge, "INVITE", "sip:dest@sabiden", 1);
        let mut req2 = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        req2.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKuasint2", phone_local),
        );
        req2.headers.set("Max-Forwards", "70");
        req2.headers
            .set("From", format!("<sip:iphone@sabiden>;tag={}", new_tag()));
        req2.headers.set("To", "<sip:dest@sabiden>");
        req2.headers.set("Call-ID", new_call_id());
        req2.headers.set("CSeq", "1 INVITE");
        req2.headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        req2.headers.set("Authorization", &auth.header_value);
        phone.send_to(&req2.to_bytes(), uas_addr).await.unwrap();

        // 100 Trying → 200 OK が届くまで複数応答を読む
        let mut got_2xx = false;
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if (200..300).contains(&r.status_code) {
                            got_2xx = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }

        // 内線側へ 200 OK が返り、フェイク NGN にも INVITE が届いたことを確認
        assert!(got_2xx, "内線へ 200 OK が返るべき");
        let _ = ngn_task.await;
        assert!(
            *ngn_invite_seen.lock().unwrap(),
            "NGN へ INVITE がプロキシされるべき"
        );
    }
}
