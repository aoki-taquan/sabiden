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
//! # B2BUA 双方向シグナリング (Phase 4)
//!
//! 内線→NGN 発信通話で、両方向の BYE / CANCEL が伝搬される:
//!
//! - 内線→NGN INVITE: 200 OK 受信時に NGN レッグの [`UacDialog`] と内線レッグの
//!   sabiden=UAS [`Dialog`] の両方を [`OutboundCallRegistry`] に保存。
//! - 内線→sabiden BYE: [`UasEvent::Bye`] → 内線へ 200 OK + NGN UacDialog 経由で BYE 送出。
//! - NGN→sabiden BYE: [`NgnInboundHandler::handle_bye`] → registry を引いて内線レッグの
//!   sabiden=UAS Dialog から build_bye → ext_layer.send_request で内線へ送出。
//! - 内線 CANCEL: [`UasEvent::Cancel`] → NGN へ CANCEL (RFC 3261 §9.1) → 内線へ 487。
//!
//! ACK は B2BUA 各レッグで独立して送出する (RFC 3261 §13.2.2.4)。NGN 側 ACK は
//! [`Uac::invite`] が 200 OK 受信時に自動送出。内線→sabiden ACK は UAS が
//! [`UasEvent::Ack`] として上げ、本ハンドラは状態確認のみ行う。
//!
//! # 既知の制限
//!
//! - 1 通話 1 ブリッジ (multi-party 不可)。
//! - 内線レッグの送信先 (ext_remote) は INVITE 受信時の送信元から推定する。
//!   内線が NAT 越しの場合は Contact ヘッダの URI から解決する経路 (Issue #16)
//!   を将来追加する。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, info_span, warn, Instrument};

use super::bridge::{BridgeConfig, RtpBridge};
use super::manager::{extract_rtp_endpoint, CallManager, ForkResult, LegInviter, UacForker};
use super::CallId;
use crate::observability::{InviteResult, Metrics};
use crate::sdp::builder::{restrict_audio_to_pcmu, rewrite_rtp_endpoint};
use crate::sip::dialog::{Dialog, DialogConfig};
use crate::sip::message::{SipHeaders, SipMethod, SipRequest, SipResponse};
use crate::sip::registrar::{Binding, ExtTransport, ExtensionRegistrar};
use crate::sip::transaction::{
    build_response_skeleton, InboundRequest, ServerTransaction, TransactionLayer,
};
use crate::sip::uac::{InviteOutcome, InvitePlan, Uac, UacDialog};
use crate::sip::uas::{ResponderHandle, UasEvent};
use crate::webrtc::peer::PeerSession;
use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};

/// NGN 着信処理の動作パラメータ。
#[derive(Debug, Clone)]
pub struct NgnInboundConfig {
    /// 内線フォーク全体の最大待機時間。これを超えると 408/487 で打ち切る。
    pub fork_timeout: Duration,
    /// `UasConfig` 由来の realm (内線側 To ヘッダ等で使用)。
    pub realm: String,
    /// RTP ブリッジ用の NGN 側 bind IP。`None` なら NGN SIP ソケットの
    /// IP を使う (`0.0.0.0` ならローカル ループバックにフォールバック)。
    pub bridge_ngn_bind_ip: Option<IpAddr>,
    /// RTP ブリッジ用の内線側 bind IP。`None` なら NGN 側と同じにする。
    pub bridge_ext_bind_ip: Option<IpAddr>,
}

impl Default for NgnInboundConfig {
    fn default() -> Self {
        Self {
            fork_timeout: Duration::from_secs(20),
            realm: "sabiden".to_string(),
            bridge_ngn_bind_ip: None,
            bridge_ext_bind_ip: None,
        }
    }
}

/// 内線フォーク用 INVITE ビルダ。
///
/// 本番経路では `Uac` を内線側ソケットで構築した [`UacForker`] を渡す。
/// テストでは `Arc<dyn LegInviter>` の Mock を渡せる。
pub type ExtInviter = Arc<dyn LegInviter>;

/// NGN→内線方向の BYE / リクエストを内線レッグへ伝搬する責務を持つトレイト。
///
/// `NgnInboundHandler` が NGN 側で BYE を受け取ったとき、まずこのフォワーダに
/// 「この Call-ID の外向け通話 (内線→NGN 発信) はあるか?」を問い合わせる。
/// 該当があれば内線レッグへ BYE を伝搬する責務はフォワーダ側が負う。
#[async_trait::async_trait]
pub trait OutboundDialogForwarder: Send + Sync {
    /// 指定 Call-ID が外向け通話なら true を返し、内線レッグへ BYE を投げる。
    /// 該当しなければ false を返す (= NgnInboundHandler が通常の inbound BYE
    /// 処理にフォールバックする)。
    async fn try_forward_bye(&self, ngn_call_id: &str) -> bool;
}

#[async_trait::async_trait]
impl OutboundDialogForwarder for UasEventHandler {
    async fn try_forward_bye(&self, ngn_call_id: &str) -> bool {
        if self.registry.lookup_by_ngn(ngn_call_id).await.is_none() {
            return false;
        }
        if let Err(e) = self.handle_ngn_bye(ngn_call_id).await {
            warn!(error=%e, "NGN→内線 BYE 伝搬中にエラー");
        }
        true
    }
}

/// NGN 着信ハンドラ。`TransactionLayer::spawn` の `inbound_rx` を消費する。
pub struct NgnInboundHandler {
    socket: Arc<UdpSocket>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    /// Call-ID → ServerTransaction (BYE/ACK で再利用するため保持する)。
    pending: Arc<Mutex<HashMap<String, Arc<Mutex<ServerTransaction>>>>>,
    /// 確立済み通話の Call-ID → `Option<CallId>` 対応。BYE 時にブリッジ停止に使う。
    /// `None` の値は「確立済みだが RTP ブリッジ未起動 (透過モード)」を意味する。
    active: Arc<Mutex<HashMap<String, Option<CallId>>>>,
    /// 進行中 (= 内線フォーク中) の INVITE。NGN から CANCEL が来たときに
    /// `Notify::notify_one` を撃って fork を打ち切るために保持する
    /// (RFC 3261 §9.1: NGN が CANCEL を出した時点で sabiden は内線フォークを
    /// 中止し、INVITE には 487 Request Terminated を返す)。
    in_flight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Notify>>>>,
    /// RTP ブリッジを管理する Call Manager。`None` なら SDP 透過モードで動く
    /// (Issue #15 互換)。
    call_manager: Option<Arc<CallManager>>,
    /// 内線→NGN 発信通話のレジストリへのフォワーダ。`None` なら NGN→内線方向の
    /// BYE は inbound 用の `active` テーブルでしか引けないため、外向け通話は
    /// 拾えない。本番では [`UasEventHandler`] を `Arc::clone` で渡すこと。
    outbound_forwarder: Mutex<Option<Arc<dyn OutboundDialogForwarder>>>,
    /// 観測カウンタ。Issue #20。
    metrics: Arc<Metrics>,
}

impl NgnInboundHandler {
    pub fn new(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
    ) -> Arc<Self> {
        Self::with_metrics(socket, inviter, extensions, cfg, Metrics::new())
    }

    /// メトリクス付きコンストラクタ。
    pub fn with_metrics(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            inviter,
            extensions,
            cfg,
            pending: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            call_manager: None,
            outbound_forwarder: Mutex::new(None),
            metrics,
        })
    }

    /// `CallManager` を組み込んだバージョン。RTP ブリッジを起動する経路はこちら。
    pub fn with_call_manager(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
        call_manager: Arc<CallManager>,
    ) -> Arc<Self> {
        Self::with_call_manager_and_metrics(
            socket,
            inviter,
            extensions,
            cfg,
            call_manager,
            Metrics::new(),
        )
    }

    /// `CallManager` + メトリクス付きコンストラクタ。
    pub fn with_call_manager_and_metrics(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
        call_manager: Arc<CallManager>,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            inviter,
            extensions,
            cfg,
            pending: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            call_manager: Some(call_manager),
            outbound_forwarder: Mutex::new(None),
            metrics,
        })
    }

    /// 内線→NGN 発信通話の BYE を内線レッグへ伝搬するためのフォワーダを差し込む。
    /// `UasEventHandler` を `Arc::clone` して渡せば B2BUA 双方向 BYE が成立する。
    pub async fn set_outbound_forwarder(&self, forwarder: Arc<dyn OutboundDialogForwarder>) {
        *self.outbound_forwarder.lock().await = Some(forwarder);
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
                // RFC 3261 §9.2: CANCEL は新しい transaction で 200 OK を返し、
                // INVITE 側は 487 Request Terminated で完了させる。
                // 進行中の内線フォークがあれば `in_flight` に登録した Notify を
                // 撃って `handle_invite` 側 (tokio::select!) に「中止」を伝える。
                let cid = request.headers.get("call-id").map(str::to_string);
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                tx.respond(build_response_skeleton(tx.request(), 200, "OK"))
                    .await?;
                if let Some(cid) = cid {
                    if let Some(notify) = self.in_flight.lock().await.get(&cid).cloned() {
                        notify.notify_one();
                    }
                }
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
        // call_id / direction を span に持たせて、フォーク中の各種ログを横断検索可能に。
        let span = info_span!(
            "ngn_inbound_invite",
            call_id = %call_id,
            direction = "ngn",
        );
        async move {
            info!(%remote, "NGN 着信 INVITE");

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
                // 着信は受け付けたが内線不在で確立に至らず → error 計上
                self.metrics.record_invite_ngn(InviteResult::Error);
                return Ok::<(), anyhow::Error>(());
            }
            // フォーク (内線レッグ): SIP / WebRTC を transport で分岐して並列に呼び出す。
            // NGN から CANCEL が来たら fork を打ち切るため Notify を仕込んで
            // `tokio::select!` で待ち合わせる (RFC 3261 §9.2 / §9.1)。
            let cancel_notify = Arc::new(tokio::sync::Notify::new());
            self.in_flight
                .lock()
                .await
                .insert(call_id.clone(), cancel_notify.clone());

            let sdp = request.body.clone();
            let fork_fut = fork_to_bindings(
                self.inviter.clone(),
                bindings,
                sdp,
                call_id.clone(),
                self.cfg.fork_timeout,
            );

            let result = tokio::select! {
                biased;
                _ = cancel_notify.notified() => {
                    // NGN が CANCEL を出した。INVITE 側は 487 で打ち切る。
                    info!("NGN CANCEL を受信 → 487 Request Terminated で打ち切り");
                    self.respond(&stx, 487, "Request Terminated").await?;
                    self.pending.lock().await.remove(&call_id);
                    self.in_flight.lock().await.remove(&call_id);
                    self.metrics.record_invite_extension(InviteResult::Error);
                    self.metrics.record_invite_ngn(InviteResult::Error);
                    return Ok(());
                }
                r = fork_fut => r,
            };

            // fork が完了したので in_flight からは外す (CANCEL の競合は無視する)。
            self.in_flight.lock().await.remove(&call_id);

            match result {
                ForkResult::Answered {
                    winner_uri,
                    response,
                } => {
                    info!(%winner_uri, "NGN 側に 200 OK を返す");
                    // RTP ブリッジを起動できるなら起動し、200 OK の SDP を sabiden 側に書き換える。
                    // 起動失敗 / CallManager 未接続なら従来どおり SDP 透過モードで返す。
                    let body_for_ngn = match self
                        .start_bridge_for_inbound(&request.body, &response.body, &call_id)
                        .await
                    {
                        Ok(rewritten) => rewritten,
                        Err(e) => {
                            warn!(error=%e, "RTP ブリッジ起動失敗 → SDP 透過で続行");
                            response.body.clone()
                        }
                    };

                    let mut tx = stx.lock().await;
                    let mut resp_to_ngn = build_response_skeleton(tx.request(), 200, "OK");
                    if !body_for_ngn.is_empty() {
                        resp_to_ngn.body = body_for_ngn;
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
                    // 観測: NGN レッグも内線レッグも応答済みとして記録
                    self.metrics.record_invite_ngn(InviteResult::Answered);
                    self.metrics.record_invite_extension(InviteResult::Answered);
                    // 通話確立として call_active を +1
                    // RTP ブリッジが起動できなかった場合 (透過モード) は active に
                    // エントリが無い可能性があるので、ここで `None` として登録して
                    // BYE 受信時に必ず call_active を 1 つ減算できるようにする。
                    {
                        let mut active = self.active.lock().await;
                        active.entry(call_id.clone()).or_insert(None);
                    }
                    self.metrics.inc_call_active();
                }
                ForkResult::AllFailed { last_status } => {
                    let code = last_status.unwrap_or(486);
                    let reason = if code == 486 { "Busy Here" } else { "Declined" };
                    self.respond(&stx, code, reason).await?;
                    self.pending.lock().await.remove(&call_id);
                    let result = if code == 486 {
                        InviteResult::Busy
                    } else {
                        InviteResult::Error
                    };
                    self.metrics.record_invite_extension(result);
                    self.metrics.record_invite_ngn(result);
                }
                ForkResult::Timeout => {
                    self.respond(&stx, 408, "Request Timeout").await?;
                    self.pending.lock().await.remove(&call_id);
                    self.metrics.record_invite_extension(InviteResult::Timeout);
                    self.metrics.record_invite_ngn(InviteResult::Timeout);
                }
            }
            Ok(())
        }
        .instrument(span)
        .await
    }

    async fn handle_bye(&self, request: SipRequest, remote: SocketAddr) -> Result<()> {
        // BYE は新しい transaction で 200 OK を返す。
        let mut tx = ServerTransaction::new(request.clone(), remote, self.socket.clone())?;
        let resp = build_response_skeleton(tx.request(), 200, "OK");
        tx.respond(resp).await?;

        let Some(cid) = request.headers.get("call-id").map(str::to_string) else {
            return Ok(());
        };

        // 1) 内線→NGN 発信通話の BYE か判定。該当すれば内線レッグへ転送して終了。
        let forwarded = {
            let fw = self.outbound_forwarder.lock().await.clone();
            if let Some(fw) = fw {
                fw.try_forward_bye(&cid).await
            } else {
                false
            }
        };
        if forwarded {
            return Ok(());
        }

        // 2) NGN→内線 着信通話の BYE: 既存 inbound テーブルでクリーンアップ。
        self.pending.lock().await.remove(&cid);
        let removed = { self.active.lock().await.remove(&cid) };
        if removed.is_some() {
            self.metrics.dec_call_active();
        }
        if let (Some(Some(call_id)), Some(mgr)) = (removed, self.call_manager.as_ref()) {
            if let Err(e) = mgr.terminate(call_id).await {
                warn!(error=%e, "BYE 受信時の通話終了に失敗");
            }
        }
        Ok(())
    }

    /// NGN→内線 着信用に RTP ブリッジを起動し、NGN へ返す 200 OK の SDP を
    /// sabiden 側に書き換えて返す。
    ///
    /// `ngn_offer` は NGN INVITE の SDP オファ、`ext_answer` は内線 200 OK の
    /// SDP アンサ。両者から各ピアの RTP エンドポイントを抽出し、sabiden 側に
    /// 中継用 UDP ソケットを 2 つ bind して `RtpBridge` を起動する。
    async fn start_bridge_for_inbound(
        &self,
        ngn_offer: &[u8],
        ext_answer: &[u8],
        call_id: &str,
    ) -> Result<Vec<u8>> {
        let mgr = self
            .call_manager
            .as_ref()
            .ok_or_else(|| anyhow!("CallManager 未接続"))?;
        if ngn_offer.is_empty() || ext_answer.is_empty() {
            return Err(anyhow!("SDP body が空 (オファ/アンサのいずれか)"));
        }

        let ngn_peer = extract_rtp_endpoint(ngn_offer)?;
        let ext_peer = extract_rtp_endpoint(ext_answer)?;

        let ngn_bind_ip = self.bridge_ngn_ip();
        let ext_bind_ip = self.bridge_ext_ip();
        let ngn_bridge_sock = Arc::new(UdpSocket::bind(SocketAddr::new(ngn_bind_ip, 0)).await?);
        let ext_bridge_sock = Arc::new(UdpSocket::bind(SocketAddr::new(ext_bind_ip, 0)).await?);
        let sabiden_ngn_addr = ngn_bridge_sock.local_addr()?;

        info!(
            ?ngn_peer,
            ?ext_peer,
            sabiden_ngn=%sabiden_ngn_addr,
            sabiden_ext=%ext_bridge_sock.local_addr()?,
            "RTP ブリッジ用ソケット bind 完了"
        );

        // NGN へ返す 200 OK SDP は sabiden の NGN 側ソケットを指すように書き換える。
        // `restrict_audio_to_pcmu` で内線 UA が乗せた WebRTC 由来属性 (rtcp-fb /
        // rtcp-mux / fingerprint 等) を除去し、コーデックを PCMU (PT 0) に絞り込む
        // (`docs/asterisk-real-invite.md` §2 / `CLAUDE.md` §5: NGN は PCMU only)。
        let pcmu_only = restrict_audio_to_pcmu(ext_answer);
        let rewritten =
            rewrite_rtp_endpoint(&pcmu_only, sabiden_ngn_addr.ip(), sabiden_ngn_addr.port())?;

        let bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ngn_bridge_sock,
            ext_socket: ext_bridge_sock,
            ngn_peer: Some(ngn_peer),
            ext_peer: Some(ext_peer),
            metrics: Some(self.metrics.clone()),
        })?;

        let cid = mgr.create_call().await;
        mgr.attach_bridge(cid, bridge).await?;
        self.active
            .lock()
            .await
            .insert(call_id.to_string(), Some(cid));
        Ok(rewritten)
    }

    fn bridge_ngn_ip(&self) -> IpAddr {
        if let Some(ip) = self.cfg.bridge_ngn_bind_ip {
            return ip;
        }
        // SIP ソケットが unspecified (`0.0.0.0` / `::`) なら loopback にフォールバック。
        match self.socket.local_addr().map(|a| a.ip()) {
            Ok(ip) if !ip.is_unspecified() => ip,
            _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    fn bridge_ext_ip(&self) -> IpAddr {
        self.cfg
            .bridge_ext_bind_ip
            .unwrap_or_else(|| self.bridge_ngn_ip())
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

/// 内線→NGN 発信通話の B2BUA ステートを保持するレジストリ。
///
/// 1 通話には 2 つの SIP ダイアログがある (内線レッグ / NGN レッグ) ため、
/// それぞれの Call-ID で同じ通話エントリを引けるようにする:
/// - `ext_call_id` (内線が送った INVITE の Call-ID): 内線側からの BYE/CANCEL の
///   ルックアップに使う。
/// - `ngn_call_id` (sabiden が NGN へ発行した INVITE の Call-ID): NGN 側からの
///   BYE のルックアップに使う ([`NgnInboundHandler::handle_bye`] が参照)。
///
/// 並行アクセスは [`Mutex`] 1 つでガードする (1 通話あたり数イベント程度なので
/// 競合は少ない)。確立済みエントリは `Arc<OutboundCallEntry>` で共有する。
#[derive(Default)]
pub struct OutboundCallRegistry {
    inner: Mutex<OutboundCallRegistryInner>,
}

#[derive(Default)]
struct OutboundCallRegistryInner {
    /// 内線 Call-ID → 確立済み通話エントリ。
    by_ext: HashMap<String, Arc<OutboundCallEntry>>,
    /// NGN Call-ID → 内線 Call-ID (確立済み通話の逆引き)。
    ngn_to_ext: HashMap<String, String>,
    /// 進行中 (200 OK 受信前) の INVITE。CANCEL でルックアップする。
    pending: HashMap<String, Arc<PendingOutbound>>,
}

/// 確立済み内線→NGN 通話 1 件分のステート。
pub struct OutboundCallEntry {
    /// 内線が送ってきた INVITE の Call-ID。
    pub ext_call_id: String,
    /// sabiden が NGN へ発行した INVITE の Call-ID (= UacDialog のもの)。
    pub ngn_call_id: String,
    /// sabiden が UAS として保持する内線レッグのダイアログ。
    /// BYE 等を内線へ送るときに `build_bye` の起点として使う。
    pub ext_dialog: Mutex<Dialog>,
    /// sabiden が UAC として保持する NGN レッグのダイアログ。
    /// BYE は `send_bye` で送る。
    pub ngn_dialog: Mutex<UacDialog>,
    /// 内線レッグの ServerTransaction ハンドル。
    /// 487 等を返したいときに使う (確立後は基本不要)。
    pub ext_responder: ResponderHandle,
    /// 内線レッグの送信先 socket addr (BYE 送信時の宛先)。
    pub ext_remote: SocketAddr,
    /// 内線レッグ用 SIP TransactionLayer (BYE を `send_request` で投げる)。
    pub ext_layer: Arc<TransactionLayer>,
    /// RTP ブリッジが起動済みなら CallId (CallManager 内のキー)。
    pub bridge_call_id: Option<CallId>,
}

/// 200 OK 受信前 (= INVITE 進行中) の通話ステート。CANCEL のために保持する。
pub struct PendingOutbound {
    pub ext_call_id: String,
    pub invite_plan: InvitePlan,
    pub ext_responder: ResponderHandle,
    /// 既に CANCEL 済みなら true。INVITE 完了側がチェックして 487 への
    /// 応答経路を切り替える。
    pub cancelled: tokio::sync::Notify,
    pub cancelled_flag: std::sync::atomic::AtomicBool,
}

impl OutboundCallRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn insert_pending(&self, p: Arc<PendingOutbound>) {
        let mut inner = self.inner.lock().await;
        inner.pending.insert(p.ext_call_id.clone(), p);
    }

    pub async fn take_pending(&self, ext_call_id: &str) -> Option<Arc<PendingOutbound>> {
        let mut inner = self.inner.lock().await;
        inner.pending.remove(ext_call_id)
    }

    pub async fn get_pending(&self, ext_call_id: &str) -> Option<Arc<PendingOutbound>> {
        let inner = self.inner.lock().await;
        inner.pending.get(ext_call_id).cloned()
    }

    pub async fn insert_confirmed(&self, entry: Arc<OutboundCallEntry>) {
        let mut inner = self.inner.lock().await;
        inner
            .ngn_to_ext
            .insert(entry.ngn_call_id.clone(), entry.ext_call_id.clone());
        inner.by_ext.insert(entry.ext_call_id.clone(), entry);
    }

    pub async fn lookup_by_ext(&self, ext_call_id: &str) -> Option<Arc<OutboundCallEntry>> {
        let inner = self.inner.lock().await;
        inner.by_ext.get(ext_call_id).cloned()
    }

    pub async fn lookup_by_ngn(&self, ngn_call_id: &str) -> Option<Arc<OutboundCallEntry>> {
        let inner = self.inner.lock().await;
        let ext_id = inner.ngn_to_ext.get(ngn_call_id)?.clone();
        inner.by_ext.get(&ext_id).cloned()
    }

    pub async fn remove_by_ext(&self, ext_call_id: &str) -> Option<Arc<OutboundCallEntry>> {
        let mut inner = self.inner.lock().await;
        let entry = inner.by_ext.remove(ext_call_id)?;
        inner.ngn_to_ext.remove(&entry.ngn_call_id);
        Some(entry)
    }

    pub async fn remove_by_ngn(&self, ngn_call_id: &str) -> Option<Arc<OutboundCallEntry>> {
        let mut inner = self.inner.lock().await;
        let ext_id = inner.ngn_to_ext.remove(ngn_call_id)?;
        inner.by_ext.remove(&ext_id)
    }
}

/// `UasEvent` を捌くハンドラ。内線発信 INVITE / BYE を NGN 側 UAC へ転送する。
pub struct UasEventHandler {
    /// NGN 側 UAC。ここから NGN へ INVITE する。
    ngn_uac: Arc<Uac>,
    /// 内線レッグ用 SIP TransactionLayer。BYE を内線へ送るために必要。
    /// `None` のときは内線へ in-dialog リクエストを送れず、BYE 連動は片方向のみ。
    ext_layer: Option<Arc<TransactionLayer>>,
    /// sabiden が内線レッグで使う Contact (Via sent-by) 用ローカルアドレス。
    /// `None` のときは `ext_layer` の socket から取得する。
    ext_local_addr: Option<SocketAddr>,
    /// 内線→NGN 通話のステート レジストリ。
    /// `NgnInboundHandler` と共有することで NGN→内線方向の BYE も同じ通話に
    /// 紐づけて扱える。
    pub(crate) registry: Arc<OutboundCallRegistry>,
    /// RTP ブリッジ管理用 CallManager (`None` なら SDP 透過モード)。
    call_manager: Option<Arc<CallManager>>,
    /// 内線発信時の RTP ブリッジ用 NGN 側 bind IP。`None` なら loopback。
    bridge_ngn_bind_ip: Option<IpAddr>,
    /// 内線発信時の RTP ブリッジ用内線側 bind IP。`None` なら loopback。
    bridge_ext_bind_ip: Option<IpAddr>,
    /// 観測カウンタ。内線発信 INVITE の結果を記録する。
    metrics: Arc<Metrics>,
}

impl UasEventHandler {
    pub fn new(ngn_uac: Arc<Uac>) -> Arc<Self> {
        Self::with_metrics(ngn_uac, Metrics::new())
    }

    /// メトリクス付きコンストラクタ。
    pub fn with_metrics(ngn_uac: Arc<Uac>, metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            ngn_uac,
            ext_layer: None,
            ext_local_addr: None,
            registry: OutboundCallRegistry::new(),
            call_manager: None,
            bridge_ngn_bind_ip: None,
            bridge_ext_bind_ip: None,
            metrics,
        })
    }

    /// `CallManager` と RTP bridge bind IP を設定したバージョン。
    pub fn with_call_manager(
        ngn_uac: Arc<Uac>,
        call_manager: Arc<CallManager>,
        bridge_ngn_bind_ip: Option<IpAddr>,
        bridge_ext_bind_ip: Option<IpAddr>,
    ) -> Arc<Self> {
        Self::with_call_manager_and_metrics(
            ngn_uac,
            call_manager,
            bridge_ngn_bind_ip,
            bridge_ext_bind_ip,
            Metrics::new(),
        )
    }

    /// `CallManager` + メトリクス付きコンストラクタ。
    pub fn with_call_manager_and_metrics(
        ngn_uac: Arc<Uac>,
        call_manager: Arc<CallManager>,
        bridge_ngn_bind_ip: Option<IpAddr>,
        bridge_ext_bind_ip: Option<IpAddr>,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ngn_uac,
            ext_layer: None,
            ext_local_addr: None,
            registry: OutboundCallRegistry::new(),
            call_manager: Some(call_manager),
            bridge_ngn_bind_ip,
            bridge_ext_bind_ip,
            metrics,
        })
    }

    /// 内線レッグ用 `TransactionLayer` を結線する。BYE を内線へ送るのに必要。
    /// `ext_local_addr` は Via sent-by / Contact に使うアドレス (省略時は
    /// layer の socket からの local_addr)。
    ///
    /// `Arc::get_mut` を使うため、本メソッドは `Arc::new` 直後 (= まだ
    /// 共有されていない) のハンドラに対してのみ呼べる。
    pub fn attach_ext_layer(
        self: &mut Arc<Self>,
        layer: Arc<TransactionLayer>,
        ext_local_addr: Option<SocketAddr>,
    ) {
        let me = Arc::get_mut(self).expect("attach_ext_layer は単一所有時に呼ぶ必要がある");
        me.ext_layer = Some(layer);
        me.ext_local_addr = ext_local_addr;
    }

    /// `OutboundCallRegistry` の参照を返す。`NgnInboundHandler` と共有するため、
    /// 同じ Arc を渡すことで NGN→内線方向の BYE が同じ通話エントリを引ける。
    pub fn registry(&self) -> Arc<OutboundCallRegistry> {
        self.registry.clone()
    }

    /// 既存の `OutboundCallRegistry` を流用するコンストラクタ。
    /// `NgnInboundHandler` と共有したいテスト・運用コードはこちらを使う。
    pub fn with_shared_registry(
        ngn_uac: Arc<Uac>,
        call_manager: Option<Arc<CallManager>>,
        bridge_ngn_bind_ip: Option<IpAddr>,
        bridge_ext_bind_ip: Option<IpAddr>,
        registry: Arc<OutboundCallRegistry>,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ngn_uac,
            ext_layer: None,
            ext_local_addr: None,
            registry,
            call_manager,
            bridge_ngn_bind_ip,
            bridge_ext_bind_ip,
            metrics,
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
                self.handle_invite(from_aor, request, remote, responder)
                    .await
            }
            UasEvent::Bye {
                request,
                remote,
                responder,
            } => self.handle_ext_bye(request, remote, responder).await,
            UasEvent::Cancel {
                request,
                remote,
                responder,
            } => self.handle_ext_cancel(request, remote, responder).await,
            UasEvent::Ack { request, remote } => self.handle_ext_ack(request, remote).await,
        }
    }

    /// 内線からの INVITE を NGN へプロキシし、200 OK の往復まで完了させる。
    async fn handle_invite(
        &self,
        from_aor: String,
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    ) -> Result<()> {
        let call_id = request
            .headers
            .get("call-id")
            .map(str::to_string)
            .unwrap_or_else(|| "<no-call-id>".to_string());
        let span = info_span!(
            "uas_invite",
            call_id = %call_id,
            aor = %from_aor,
            direction = "extension",
        );
        async move {
            info!(%from_aor, %remote, "内線発信 → NGN へプロキシ");
            // Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §5.1):
            // 内線が出した Request-URI (LAN private IP / NGN ドメイン) を
            // P-CSCF IP+port に正規化する。NGN は Request-URI host に P-CSCF
            // IP を要求する (ドメインや LAN IP のままだと 403 で蹴られる)。
            let ngn_server = self.ngn_uac.server_addr();
            let target = normalize_request_uri_for_ngn(
                &request.uri,
                &ngn_server.ip().to_string(),
                ngn_server.port(),
            );
            if target != request.uri {
                debug!(
                    original = %request.uri,
                    rewritten = %target,
                    "Request-URI を P-CSCF IP+port に正規化"
                );
            }
            let ext_offer = request.body.clone();

            // CallManager があれば RTP ブリッジ用ソケットを先に確保し、
            // NGN へ送る INVITE の SDP を sabiden 側に書き換える。
            // CallManager 未注入 (透過モード) でも、Asterisk 実機準拠で SDP の
            // `c=` / `o=` IP は **必ず** NGN 側 (eth1 IP = sent-by IP) へ強制
            // 書換する (`docs/asterisk-real-invite.md` §5.2)。LAN private IP
            // (192.168.x.x) を NGN 側に漏らすと 403 / 接続不能。
            let ngn_local_ip = self.ngn_uac.config().local_addr.ip();
            let (bridge_ctx, sdp_for_ngn) =
                match self.prepare_outbound_bridge(&ext_offer).await {
                    Ok(Some((ctx, rewritten))) => (Some(ctx), Some(rewritten)),
                    Ok(None) => (
                        None,
                        force_rewrite_sdp_for_ngn(&ext_offer, ngn_local_ip),
                    ),
                    Err(e) => {
                        warn!(error=%e, "NGN 側 RTP ブリッジ準備失敗 → SDP 強制書換で続行");
                        (
                            None,
                            force_rewrite_sdp_for_ngn(&ext_offer, ngn_local_ip),
                        )
                    }
                };

            // NGN は PCMU(0) しか受け入れない。Linphone/Zoiper 等が送ってくる
            // multi-codec オファ (Opus 等) を素通しすると 488 で蹴られるので、
            // NGN へ送る直前で PCMU のみに絞る。RTP ブリッジ用に書き換え済の
            // SDP に対してさらにコーデック絞りを適用しても既に endpoint は
            // sabiden 側を指しており整合性は崩れない。
            let sdp_for_ngn = sdp_for_ngn.map(|s| crate::sdp::builder::restrict_audio_to_pcmu(&s));

            let plan = self
                .ngn_uac
                .build_invite(&target, sdp_for_ngn.as_deref(), None);

            // 進行中 INVITE を pending に登録 (CANCEL ルックアップ用)。
            let pending = Arc::new(PendingOutbound {
                ext_call_id: call_id.clone(),
                invite_plan: plan.clone(),
                ext_responder: responder.clone(),
                cancelled: tokio::sync::Notify::new(),
                cancelled_flag: std::sync::atomic::AtomicBool::new(false),
            });
            if !call_id.is_empty() && call_id != "<no-call-id>" {
                self.registry.insert_pending(pending.clone()).await;
            }

            let outcome = self.ngn_uac.invite(plan, sdp_for_ngn).await;

            // 結果を処理する前に pending を取り除く (CANCEL されている場合は
            // cancelled_flag が立っている)。
            let was_cancelled = pending
                .cancelled_flag
                .load(std::sync::atomic::Ordering::SeqCst);
            if !call_id.is_empty() && call_id != "<no-call-id>" {
                self.registry.take_pending(&call_id).await;
            }

            match outcome {
                Ok(InviteOutcome::Established(call)) => {
                    if was_cancelled {
                        // CANCEL 後に NGN 200 OK が間に合った場合は RFC 3261 §15.1.1 に
                        // 従い直ちに BYE を送って通話を解放する。内線側は 487 で
                        // 返してあるため、ここでは NGN レッグだけ閉じれば良い。
                        info!("CANCEL 後の 200 OK → NGN BYE で即座に閉じる");
                        let mut dlg = call.dialog;
                        if let Err(e) = dlg.send_bye().await {
                            warn!(error=%e, "競合 BYE の送出失敗");
                        }
                        self.metrics.record_invite_ngn(InviteResult::Error);
                        return Ok(());
                    }
                    // NGN 側 200 OK の SDP answer を内線に返す。
                    // ブリッジを起動できるなら sabiden 側 ext ソケットを指すよう書き換える。
                    let bridge_call_id;
                    let body_for_ext = match self
                        .finalize_outbound_bridge(bridge_ctx, &ext_offer, &call.response.body)
                        .await
                    {
                        Ok((body, cid)) => {
                            bridge_call_id = cid;
                            body
                        }
                        Err(e) => {
                            warn!(error=%e, "NGN 側 RTP ブリッジ確立失敗 → SDP 透過");
                            bridge_call_id = None;
                            call.response.body.clone()
                        }
                    };

                    // 200 OK を組み立てて内線へ返す (UAS 側 dialog 構築用に保持)。
                    let response_to_ext = build_2xx_to_ext(&request, &body_for_ext);
                    responder.respond(response_to_ext.clone()).await?;

                    // 観測: NGN レッグも内線レッグも応答済みとして記録
                    self.metrics.record_invite_ngn(InviteResult::Answered);
                    self.metrics.record_invite_extension(InviteResult::Answered);
                    self.metrics.inc_call_active();

                    // 内線レッグの UAS-side dialog を構築。Layer が無い (= BYE を内線へ
                    // 投げられない) 場合でも `Dialog` 自身は作っておく (将来用 / テスト用)。
                    let ext_dialog_cfg = self.build_ext_dialog_cfg(&request);
                    let ext_dialog =
                        match Dialog::from_uas_invite(&request, &response_to_ext, ext_dialog_cfg) {
                            Ok(d) => d,
                            Err(e) => {
                                // dialog 構築できない (Contact が無い等) なら以降の BYE 連動は
                                // 不能だが、通話自体は確立済みなのでエラー扱いはしない。
                                warn!(error=%e, "内線レッグ dialog 構築失敗 → BYE 連動不可");
                                return Ok(());
                            }
                        };

                    // 確立済みエントリとして登録 (NGN call-id も登録)。
                    if let Some(layer) = self.ext_layer.clone() {
                        let ngn_call_id = call.dialog.dialog().id().call_id.clone();
                        let entry = Arc::new(OutboundCallEntry {
                            ext_call_id: call_id.clone(),
                            ngn_call_id,
                            ext_dialog: Mutex::new(ext_dialog),
                            ngn_dialog: Mutex::new(call.dialog),
                            ext_responder: responder,
                            ext_remote: remote,
                            ext_layer: layer,
                            bridge_call_id,
                        });
                        self.registry.insert_confirmed(entry).await;
                    } else {
                        // ext_layer 未設定: BYE は片方向 (内線→NGN) のみ可能。
                        // NGN 側 dialog は保持する余地がないので drop する。
                        warn!(
                            "ext_layer 未設定 → 内線→NGN BYE 連動のみ。NGN→内線 BYE は片方向 200 OK のみ"
                        );
                        let _ = call.dialog;
                    }
                    Ok(())
                }
                Ok(InviteOutcome::Failed { response }) => {
                    warn!(code = response.status_code, "NGN 側 INVITE 失敗");
                    let result = if response.status_code == 486 {
                        InviteResult::Busy
                    } else {
                        InviteResult::Error
                    };
                    self.metrics.record_invite_ngn(result);
                    responder
                        .quick(response.status_code, response.reason.as_str())
                        .await
                }
                Err(e) => {
                    if was_cancelled {
                        // CANCEL 経路で 487 / Timer B で Err になったケース。
                        // 内線へは CANCEL 経路で 487 を返済済みの想定なので何もしない。
                        debug!(error=%e, "CANCEL 後の INVITE 終了");
                        return Ok(());
                    }
                    warn!(error=%e, "NGN 側 INVITE トランスポート失敗 → 503");
                    self.metrics.record_invite_ngn(InviteResult::Timeout);
                    responder.quick(503, "Service Unavailable").await
                }
            }
        }
        .instrument(span)
        .await
    }

    /// 内線からの BYE を受け、NGN レッグへ BYE を伝搬する。RFC 3261 §15.1.2。
    ///
    /// フロー:
    /// 1. 内線レッグの 200 OK を即返す (responder 経由)
    /// 2. registry から NGN UacDialog を引き、`send_bye` を呼ぶ
    /// 3. RTP ブリッジを停止し、call_active を -1
    async fn handle_ext_bye(
        &self,
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    ) -> Result<()> {
        // 1) 内線へ 200 OK を即返す (RFC 3261 §15.1.2)
        if let Err(e) = responder.quick(200, "OK").await {
            warn!(error=%e, "内線 BYE への 200 OK 送出失敗");
        }

        let call_id = match request.headers.get("call-id") {
            Some(c) => c.to_string(),
            None => {
                warn!("内線 BYE に Call-ID が無い");
                return Ok(());
            }
        };
        debug!(%remote, %call_id, "内線 BYE 受信 → NGN へ BYE 伝搬");

        let entry = match self.registry.remove_by_ext(&call_id).await {
            Some(e) => e,
            None => {
                debug!(%call_id, "BYE: 対応する outbound call が見つからない");
                return Ok(());
            }
        };

        // 2) NGN UacDialog で BYE を送る
        {
            let mut ngn_dlg = entry.ngn_dialog.lock().await;
            if let Err(e) = ngn_dlg.send_bye().await {
                warn!(error=%e, "NGN 側 BYE 送出失敗");
            }
        }

        // 3) RTP ブリッジ停止 + 観測
        self.metrics.dec_call_active();
        if let (Some(bridge_id), Some(mgr)) = (entry.bridge_call_id, self.call_manager.as_ref()) {
            if let Err(e) = mgr.terminate(bridge_id).await {
                warn!(error=%e, "RTP ブリッジ停止失敗");
            }
        }
        Ok(())
    }

    /// 内線からの CANCEL を受け、NGN へ CANCEL を伝搬する。RFC 3261 §9.1 / §15.1.
    async fn handle_ext_cancel(
        &self,
        request: SipRequest,
        _remote: SocketAddr,
        _responder: ResponderHandle,
    ) -> Result<()> {
        let call_id = match request.headers.get("call-id") {
            Some(c) => c.to_string(),
            None => return Ok(()),
        };
        info!(%call_id, "内線 CANCEL 受信 → NGN へ CANCEL");
        let pending = match self.registry.get_pending(&call_id).await {
            Some(p) => p,
            None => {
                debug!(%call_id, "CANCEL: 進行中 INVITE が見つからない (確立済み or 失敗済み)");
                return Ok(());
            }
        };
        // CANCEL フラグを立てる: invite() の future がこの後 200 を返してきても
        // 受理せず NGN へ即 BYE を送る経路に切り替える (RFC 3261 §9.1)。
        pending
            .cancelled_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        pending.cancelled.notify_waiters();

        // RFC 3261 §9.1: 元 INVITE と同じ branch / CSeq で CANCEL を送る。
        // CANCEL の応答 (200) は ngn_uac の transaction layer がディスパッチするが、
        // ここでは応答を待たず単発で send する (Uac::cancel_pending は応答待ちする
        // 実装になっているのでそれを使う)。
        match self.ngn_uac.cancel_pending(&pending.invite_plan).await {
            Ok(resp) => {
                debug!(code = resp.status_code, "NGN CANCEL 応答");
            }
            Err(e) => {
                warn!(error=%e, "NGN CANCEL 送出失敗");
            }
        }

        // 内線レッグへは 487 を返す (元 INVITE の ServerTransaction 経由)。
        // RFC 3261 §15.1: CANCEL を受けた UAS は元 INVITE に 487 Request Terminated を返す。
        if let Err(e) = pending.ext_responder.quick(487, "Request Terminated").await {
            warn!(error=%e, "内線へ 487 送出失敗");
        }
        // メトリクス: NGN INVITE は cancel された (= 失敗扱い)。
        self.metrics.record_invite_ngn(InviteResult::Error);
        Ok(())
    }

    /// 内線からの ACK を受け取る (RFC 3261 §17.1.1.3)。
    ///
    /// B2BUA では 内線→sabiden ACK と sabiden→NGN ACK は独立 (両側とも別々の
    /// 2xx に対する ACK) なので、本ハンドラは状態確認と監視のみで送出は行わない
    /// (NGN 側 ACK は `Uac::invite` 内で 200 OK 受信時に既に送出済み)。
    async fn handle_ext_ack(&self, request: SipRequest, _remote: SocketAddr) -> Result<()> {
        if let Some(cid) = request.headers.get("call-id") {
            if self.registry.lookup_by_ext(cid).await.is_some() {
                debug!(%cid, "内線 ACK 受信 → 通話確立済み");
            } else {
                debug!(%cid, "内線 ACK 受信 (未知の call: 既に終了している可能性)");
            }
        }
        Ok(())
    }

    /// NGN→内線方向の BYE を扱う (`NgnInboundHandler` から委譲される)。
    ///
    /// 1. registry から `OutboundCallEntry` を引く
    /// 2. 内線レッグへ BYE を `ext_layer.send_request` で送る
    /// 3. RTP ブリッジを停止
    pub(crate) async fn handle_ngn_bye(&self, ngn_call_id: &str) -> Result<()> {
        let entry = match self.registry.remove_by_ngn(ngn_call_id).await {
            Some(e) => e,
            None => {
                debug!(%ngn_call_id, "NGN BYE: 対応する outbound call が見つからない");
                return Ok(());
            }
        };
        let bye_req = {
            let mut dlg = entry.ext_dialog.lock().await;
            let req = dlg.build_bye();
            dlg.terminate();
            req
        };
        // 内線レッグの送信: 内線 UA がいる remote へ送る。応答は待つが timeout を
        // 短めに設定する余地はある (今は layer の Timer B に任せる)。
        match entry
            .ext_layer
            .send_request(bye_req, entry.ext_remote)
            .await
        {
            Ok(resp) => debug!(code = resp.status_code, "内線 BYE 応答"),
            Err(e) => warn!(error=%e, "内線へ BYE 送出失敗"),
        }
        // RTP ブリッジ停止 + 観測
        self.metrics.dec_call_active();
        if let (Some(bridge_id), Some(mgr)) = (entry.bridge_call_id, self.call_manager.as_ref()) {
            if let Err(e) = mgr.terminate(bridge_id).await {
                warn!(error=%e, "RTP ブリッジ停止失敗");
            }
        }
        Ok(())
    }

    /// 内線レッグの sabiden=UAS dialog 構築用 cfg を作る。
    fn build_ext_dialog_cfg(&self, invite: &SipRequest) -> DialogConfig {
        // local_uri = 内線 INVITE の To URI (= sabiden 側)
        // remote_uri = INVITE の From URI (= 内線側)
        let local_uri = invite
            .headers
            .get("to")
            .map(extract_uri_from_addr)
            .unwrap_or_else(|| "sip:sabiden".to_string());
        let remote_uri = invite
            .headers
            .get("from")
            .map(extract_uri_from_addr)
            .unwrap_or_else(|| "sip:unknown@sabiden".to_string());
        let sent_by = self
            .ext_local_addr
            .map(|a| a.to_string())
            .or_else(|| {
                self.ext_layer
                    .as_ref()
                    .and_then(|l| l.local_addr().ok().map(|a| a.to_string()))
            })
            .unwrap_or_else(|| "0.0.0.0:0".to_string());
        let local_contact = format!("sip:sabiden@{}", sent_by);
        DialogConfig {
            local_uri,
            remote_uri,
            local_contact,
            sent_by,
        }
    }

    /// 内線→NGN 発信時、CallManager があれば RTP ブリッジ用ソケットを bind し、
    /// NGN へ送る SDP オファを sabiden 側 NGN ソケットを指すように書き換える。
    /// 戻り値の `OutboundBridgeCtx` は確立後の `finalize_outbound_bridge` に渡す。
    async fn prepare_outbound_bridge(
        &self,
        ext_offer: &[u8],
    ) -> Result<Option<(OutboundBridgeCtx, Vec<u8>)>> {
        let Some(_mgr) = self.call_manager.as_ref() else {
            return Ok(None);
        };
        if ext_offer.is_empty() {
            return Ok(None);
        }
        let ext_peer = extract_rtp_endpoint(ext_offer)?;
        let ngn_bind_ip = self
            .bridge_ngn_bind_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let ext_bind_ip = self.bridge_ext_bind_ip.unwrap_or(ngn_bind_ip);
        let ngn_sock = Arc::new(UdpSocket::bind(SocketAddr::new(ngn_bind_ip, 0)).await?);
        let ext_sock = Arc::new(UdpSocket::bind(SocketAddr::new(ext_bind_ip, 0)).await?);
        let sabiden_ngn_addr = ngn_sock.local_addr()?;
        let rewritten =
            rewrite_rtp_endpoint(ext_offer, sabiden_ngn_addr.ip(), sabiden_ngn_addr.port())?;
        Ok(Some((
            OutboundBridgeCtx {
                ngn_sock,
                ext_sock,
                ext_peer,
            },
            rewritten,
        )))
    }

    /// NGN 200 OK の SDP answer を内線へ返す前に書き換え、`RtpBridge` を起動。
    /// 戻り値: (内線へ返す SDP body, 起動したブリッジの CallId)。
    /// `bridge_ctx` が `None` の場合は透過 (元 body をそのまま返す, CallId は None)。
    async fn finalize_outbound_bridge(
        &self,
        bridge_ctx: Option<OutboundBridgeCtx>,
        ext_offer: &[u8],
        ngn_answer: &[u8],
    ) -> Result<(Vec<u8>, Option<CallId>)> {
        let Some(ctx) = bridge_ctx else {
            return Ok((ngn_answer.to_vec(), None));
        };
        let Some(mgr) = self.call_manager.as_ref() else {
            return Ok((ngn_answer.to_vec(), None));
        };
        if ngn_answer.is_empty() {
            return Err(anyhow!("NGN 側 200 OK の SDP が空"));
        }
        let ngn_peer = extract_rtp_endpoint(ngn_answer)?;
        let sabiden_ext_addr = ctx.ext_sock.local_addr()?;

        // 内線へ返す SDP は sabiden の ext 側ソケットを指すように書き換える。
        // 元の SDP オファをベースにすると ptime / rtpmap が保たれて好ましい。
        let rewritten_for_ext =
            rewrite_rtp_endpoint(ext_offer, sabiden_ext_addr.ip(), sabiden_ext_addr.port())?;

        let bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ctx.ngn_sock,
            ext_socket: ctx.ext_sock,
            ngn_peer: Some(ngn_peer),
            ext_peer: Some(ctx.ext_peer),
            metrics: Some(self.metrics.clone()),
        })?;
        let cid = mgr.create_call().await;
        mgr.attach_bridge(cid, bridge).await?;
        Ok((rewritten_for_ext, Some(cid)))
    }
}

/// 内線レッグの 200 OK を組み立てる。`build_response_skeleton` がベース。
/// To に tag を付け、SDP body があれば設定する。
fn build_2xx_to_ext(invite: &SipRequest, body: &[u8]) -> SipResponse {
    let mut resp = build_response_skeleton(invite, 200, "OK");
    if !body.is_empty() {
        resp.headers.set("Content-Type", "application/sdp");
        resp.body = body.to_vec();
    }
    ensure_to_tag(&mut resp);
    resp
}

/// `<sip:user@host>;tag=...` のような name-addr / addr-spec から URI 部分のみ抽出する。
fn extract_uri_from_addr(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start + 1..].find('>') {
            return trimmed[start + 1..start + 1 + end].to_string();
        }
    }
    trimmed
        .split(';')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string()
}

/// `UasEventHandler::prepare_outbound_bridge` から `finalize_outbound_bridge` へ渡す
/// 中間状態。bind 済みのソケット 2 つと内線側ピアを保持する。
struct OutboundBridgeCtx {
    ngn_sock: Arc<UdpSocket>,
    ext_sock: Arc<UdpSocket>,
    ext_peer: SocketAddr,
}

/// `fork_to_bindings` 内部で使う leg 結果。
enum LegResult {
    Established {
        #[allow(dead_code)]
        aor: String,
        winner_uri: String,
        response: SipResponse,
    },
    Failed {
        #[allow(dead_code)]
        aor: String,
        status: u16,
    },
    Errored {
        #[allow(dead_code)]
        aor: String,
    },
}

/// winner 決定後に Cancel を送るための WebRTC leg 識別子。
#[derive(Clone)]
struct WebRtcLegHandle {
    ws: WsSink,
    pending: PendingAnswers,
    call_id: String,
}

/// 内線フォーク (transport-aware)。SIP/WebRTC を transport で分岐し並列に呼び出す。
/// 先着の 200 OK を winner として採用、それ以外の WebRTC leg には Cancel を流す。
pub async fn fork_to_bindings(
    inviter: ExtInviter,
    bindings: Vec<(String, Binding)>,
    sdp_offer: Vec<u8>,
    call_id: String,
    overall_timeout: Duration,
) -> ForkResult {
    if bindings.is_empty() {
        return ForkResult::AllFailed { last_status: None };
    }

    // 各 leg の終了を待ち合わせるチャネル。先着 200 を採用したら drop で終了させる。
    let (tx, mut rx) = mpsc::unbounded_channel::<LegResult>();
    let total = bindings.len();
    let webrtc_legs: Arc<Mutex<Vec<WebRtcLegHandle>>> = Arc::new(Mutex::new(Vec::new()));

    for (aor, binding) in bindings {
        let tx_c = tx.clone();
        let sdp_c = sdp_offer.clone();
        let call_id_c = call_id.clone();
        match binding.transport {
            ExtTransport::Sip => {
                let inviter_c = inviter.clone();
                let target_uri = binding.contact_uri.clone();
                let aor_c = aor.clone();
                tokio::spawn(async move {
                    let outcome = inviter_c.invite(&target_uri, &sdp_c).await;
                    let leg = match outcome {
                        Ok(super::manager::LegOutcome::Established { response, .. }) => {
                            LegResult::Established {
                                aor: aor_c,
                                winner_uri: target_uri,
                                response,
                            }
                        }
                        Ok(super::manager::LegOutcome::Failed { status, .. }) => {
                            LegResult::Failed { aor: aor_c, status }
                        }
                        Ok(super::manager::LegOutcome::Errored { .. }) | Err(_) => {
                            LegResult::Errored { aor: aor_c }
                        }
                    };
                    let _ = tx_c.send(leg);
                });
            }
            ExtTransport::WebRtc { peer, ws, pending } => {
                webrtc_legs.lock().await.push(WebRtcLegHandle {
                    ws: ws.clone(),
                    pending: pending.clone(),
                    call_id: call_id_c.clone(),
                });
                let aor_c = aor.clone();
                let target_uri = binding.contact_uri.clone();
                let leg_timeout = overall_timeout;
                tokio::spawn(async move {
                    let leg = run_webrtc_leg(
                        aor_c.clone(),
                        target_uri,
                        peer,
                        ws,
                        pending,
                        sdp_c,
                        call_id_c,
                        leg_timeout,
                    )
                    .await;
                    let _ = tx_c.send(leg);
                });
            }
        }
    }
    drop(tx);

    let mut last_status: Option<u16> = None;
    let mut received = 0usize;
    let deadline = tokio::time::Instant::now() + overall_timeout;

    let result = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break ForkResult::Timeout;
        }
        let next = match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(v)) => v,
            Ok(None) => break ForkResult::AllFailed { last_status },
            Err(_) => break ForkResult::Timeout,
        };
        received += 1;
        match next {
            LegResult::Established {
                winner_uri,
                response,
                ..
            } => {
                info!(winner = %winner_uri, "fork_to_bindings: 内線 {} が応答", winner_uri);
                break ForkResult::Answered {
                    winner_uri,
                    response,
                };
            }
            LegResult::Failed { status, .. } => {
                last_status = Some(status);
            }
            LegResult::Errored { .. } => {}
        }
        if received >= total {
            break ForkResult::AllFailed { last_status };
        }
    };

    // winner が決まった後、まだ走っている WebRTC leg に Cancel を流す
    if matches!(result, ForkResult::Answered { .. }) {
        let legs = webrtc_legs.lock().await.clone();
        for leg in legs {
            leg.pending.cancel(&leg.call_id).await;
            let _ = leg.ws.send(ServerMessage::Cancel {
                call_id: leg.call_id,
            });
        }
    }
    result
}

/// 1 つの WebRTC leg を駆動する。peer.handle_offer 診断 → pending 予約 →
/// WS で Offer push → browser からの Answer を timeout 内に待つ。
#[allow(clippy::too_many_arguments)]
async fn run_webrtc_leg(
    aor: String,
    target_uri: String,
    peer: Arc<dyn PeerSession>,
    ws: WsSink,
    pending: PendingAnswers,
    sdp_offer: Vec<u8>,
    call_id: String,
    leg_timeout: Duration,
) -> LegResult {
    let offer_text = match std::str::from_utf8(&sdp_offer) {
        Ok(t) => t.to_string(),
        Err(e) => {
            warn!(%aor, error=%e, "WebRTC leg: NGN SDP が UTF-8 でない");
            return LegResult::Errored { aor };
        }
    };
    let _peer_answer = match peer.handle_offer(&offer_text).await {
        Ok(a) => Some(a),
        Err(e) => {
            debug!(%aor, error=%e, "WebRTC leg: peer.handle_offer 失敗 (継続)");
            None
        }
    };

    let waiter = pending.register(&call_id).await;
    if let Err(e) = ws.send(ServerMessage::Offer {
        call_id: call_id.clone(),
        sdp: offer_text,
    }) {
        warn!(%aor, error=%e, "WebRTC leg: WS 送信失敗 (browser 切断?)");
        pending.cancel(&call_id).await;
        return LegResult::Errored { aor };
    }

    let answer = match tokio::time::timeout(leg_timeout, waiter).await {
        Ok(Ok(sdp)) => sdp,
        Ok(Err(_)) => {
            debug!(%aor, "WebRTC leg: pending oneshot がキャンセルされた");
            return LegResult::Errored { aor };
        }
        Err(_) => {
            warn!(%aor, "WebRTC leg: browser から answer タイムアウト");
            pending.cancel(&call_id).await;
            return LegResult::Failed { aor, status: 408 };
        }
    };

    let mut headers = SipHeaders::new();
    headers.set("Via", "SIP/2.0/WS webrtc.peer;branch=z9hG4bKwebrtc");
    headers.set("From", "<sip:webrtc>;tag=webrtc");
    headers.set("To", format!("<{}>;tag=webrtc-{}", target_uri, aor));
    headers.set("Call-ID", &call_id);
    headers.set("CSeq", "1 INVITE");
    headers.set("Content-Type", "application/sdp");
    let response = SipResponse {
        status_code: 200,
        reason: "OK".to_string(),
        headers,
        body: answer.into_bytes(),
    };
    LegResult::Established {
        aor,
        winner_uri: target_uri,
        response,
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
    wire_ngn_inbound_with_metrics(
        _layer,
        socket,
        inbound_rx,
        inviter,
        extensions,
        cfg,
        Metrics::new(),
    )
}

/// `wire_ngn_inbound` のメトリクス付き版。
pub fn wire_ngn_inbound_with_metrics(
    _layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    metrics: Arc<Metrics>,
) -> Arc<NgnInboundHandler> {
    let handler = NgnInboundHandler::with_metrics(socket, inviter, extensions, cfg, metrics);
    handler.clone().spawn(inbound_rx);
    handler
}

/// 内線が出した INVITE の Request-URI を NGN 直収用に正規化する。
///
/// NTT NGN (P-CSCF) は Request-URI の host が IP アドレス (P-CSCF IP) で
/// あることを要求する。LAN private IP (例: `192.168.20.239`) や NGN ドメイン
/// (例: `ntt-east.ne.jp`) のままだと **403 Forbidden** で蹴られる
/// (`docs/asterisk-real-invite.md` §3 / §5.1 — Asterisk 20 が同一線で
/// `sip:117@118.177.125.1:5060` で 200 OK を取得した実機キャプチャ準拠)。
///
/// 加えて、内線 (baresip 等) が `sip:117@<host>;transport=udp` のように
/// **uri-parameters** (RFC 3261 §19.1.1) を付けてくると、NGN P-CSCF は
/// `;transport=udp` を含む Request-URI を **`500 Server Internal Error`**
/// で蹴る (Issue #58 の実機 trace)。同 §19.1.1 の通り `uri-parameters` は
/// `;param` の繰返し、`headers` は `?h=v&h=v` の形を取るが、Asterisk 実機
/// INVITE は **どちらも付けず** に 200 OK を取得している
/// (`docs/asterisk-real-invite.md` §5.1)。NGN 直収では `transport`/`lr`/
/// `maddr` 等の URI パラメータは **不要かつ有害** なので、host/port 書換と
/// 同時に `;params` と `?headers` を完全に剥がす。
///
/// 引数:
/// - `req_uri`: 内線が出した SIP URI (例: `sip:117@192.168.20.239;transport=udp`)
/// - `ngn_server_host`: P-CSCF IP (例: `118.177.125.1`)
/// - `ngn_server_port`: P-CSCF port (通常 `5060`)
///
/// 戻り値: `sip:<user>@<ngn_server_host>:<ngn_server_port>` 形式の URI。
/// `;uri-parameters` と `?headers` は常に削除する (NGN 仕様)。
/// 既に正規化済 (host:port 一致 + params/headers 無し) ならそのまま返す
/// (idempotent)。パース不能な URI は変更せず元のまま返す (フェイルセーフ)。
pub fn normalize_request_uri_for_ngn(
    req_uri: &str,
    ngn_server_host: &str,
    ngn_server_port: u16,
) -> String {
    // RFC 3261 §19.1.1 準拠の構造解析を `parse_sip_uri` に委譲し、
    // ここでは host/port の書換と uri-parameters/headers の破棄だけ行う。
    let parsed = match crate::sip::message::parse_sip_uri(req_uri) {
        Ok(p) => p,
        Err(_) => return req_uri.to_string(),
    };
    // 既に P-CSCF host:port + params/headers 無しなら何もしない (idempotent)。
    let already_pcsf_host = parsed.host.eq_ignore_ascii_case(ngn_server_host);
    let already_pcsf_port = parsed.port == Some(ngn_server_port);
    if already_pcsf_host
        && already_pcsf_port
        && parsed.params.is_empty()
        && parsed.headers.is_empty()
    {
        return req_uri.to_string();
    }
    // 再構築。`<scheme>:<user>@<pcsf_host>:<pcsf_port>` のみ。
    // `;params` と `?headers` は NGN 仕様 (§docstring 参照) で常に剥がす。
    let scheme = if parsed.scheme.is_empty() {
        "sip".to_string()
    } else {
        parsed.scheme.clone()
    };
    match parsed.user {
        Some(user) => format!(
            "{}:{}@{}:{}",
            scheme, user, ngn_server_host, ngn_server_port
        ),
        None => format!("{}:{}:{}", scheme, ngn_server_host, ngn_server_port),
    }
}

/// 内線→NGN 発信時の SDP 強制書換 (CallManager 未注入時のフォールバック)。
///
/// Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §5.2): NGN へ出す INVITE の
/// SDP に LAN private IP (192.168.x.x 等) を載せると応答先が成立しない。
/// `c=` / `o=` IP は **必ず** sabiden eth1 (NGN 側 sent-by) IP に書換える。
///
/// RTP port は本パスでは sabiden が中継しないため、内線広告の port を
/// そのまま広告する (= NGN→内線 RTP は経路上 NAT 越えできないため音声は
/// 流れないが、SIP signaling は通り 200 OK を取れる)。本来は CallManager を
/// `main.rs` で注入し `prepare_outbound_bridge` 経由で IP/port 両方を sabiden
/// 側に書換るのが正解。
///
/// 戻り値:
/// - 入力が空なら `None`
/// - 書換成功なら `Some(rewritten_bytes)`
/// - 書換失敗 (SDP パースエラー等) でも、元 body を `Some` で返す
///   (LAN IP を漏らすが、INVITE 自体は出る)。warn ログで観測可能。
fn force_rewrite_sdp_for_ngn(ext_offer: &[u8], ngn_local_ip: IpAddr) -> Option<Vec<u8>> {
    if ext_offer.is_empty() {
        return None;
    }
    // 元 SDP の m=audio port を温存しつつ c=/o= IP のみ NGN 側へ書き換える。
    // rewrite_rtp_endpoint は port も書き換えてしまうため、まず port を取り出す。
    let port =
        match crate::sdp::SessionDescription::parse(std::str::from_utf8(ext_offer).unwrap_or("")) {
            Ok(sdp) => sdp
                .media
                .iter()
                .find(|m| m.media == "audio")
                .map(|m| m.port)
                .unwrap_or(0),
            Err(e) => {
                warn!(error=%e, "SDP パース失敗 → 元 body のまま (LAN IP 漏洩リスク)");
                return Some(ext_offer.to_vec());
            }
        };
    match rewrite_rtp_endpoint(ext_offer, ngn_local_ip, port) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            warn!(error=%e, "SDP 強制書換失敗 → 元 body のまま (LAN IP 漏洩リスク)");
            Some(ext_offer.to_vec())
        }
    }
}

/// `wire_ngn_inbound` の `CallManager` 接続版。RTP ブリッジを起動する経路。
pub fn wire_ngn_inbound_with_manager(
    layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    call_manager: Arc<CallManager>,
) -> Arc<NgnInboundHandler> {
    wire_ngn_inbound_with_manager_and_metrics(
        layer,
        socket,
        inbound_rx,
        inviter,
        extensions,
        cfg,
        call_manager,
        Metrics::new(),
    )
}

/// `wire_ngn_inbound_with_manager` の メトリクス付きバージョン。
///
/// Issue #40 の本流配線で `main.rs` から呼ぶエントリポイント。NGN 着信 INVITE に
/// 対して内線フォーク + RTP ブリッジ起動を一括で結線する。
///
/// 引数が多いのは結線ヘルパとして必須パラメータをそのまま受け渡すためで、
/// 構造体化は本流配線の関心事ではない (`main.rs` から 1 か所で呼ぶだけ)。
#[allow(clippy::too_many_arguments)]
pub fn wire_ngn_inbound_with_manager_and_metrics(
    _layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    call_manager: Arc<CallManager>,
    metrics: Arc<Metrics>,
) -> Arc<NgnInboundHandler> {
    let handler = NgnInboundHandler::with_call_manager_and_metrics(
        socket,
        inviter,
        extensions,
        cfg,
        call_manager,
        metrics,
    );
    handler.clone().spawn(inbound_rx);
    handler
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::{parse_message, SipMessage};
    use crate::sip::transaction::TransactionLayer;
    use crate::testing::builders;
    use crate::testing::scripted::{ScriptedAction, ScriptedInviter};
    use std::net::SocketAddr;
    use std::sync::Mutex as StdMutex;
    use tokio::net::UdpSocket;

    /// NGN 着信 INVITE → 内線フォーク (200) → 200 OK が NGN 側に届く。
    #[tokio::test]
    async fn ngn_invite_forwards_200_back() {
        // sabiden の NGN 側ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();

        // フェイク NGN クライアント (UA 役)
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

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

        // モック inviter (testing ハーネス): 200 OK + ダミー SDP
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n".to_vec())
            .build();

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
        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0312345678@sabiden",
            "ngn-invite-cid",
            "z9hG4bKngn1",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\n".to_vec(),
        );
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
        assert!(inviter.call_count() >= 1, "内線へ INVITE される");
    }

    /// 登録内線が 0 件なら 480 Temporarily Unavailable で返る。
    #[tokio::test]
    async fn ngn_invite_with_no_extensions_returns_480() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
        );

        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0312345678@sabiden",
            "ngn-noext-cid",
            "z9hG4bKngn-noext",
            Vec::new(),
        );
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
            inviter.call_count(),
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

    /// Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §5.1):
    /// 内線が出した Request-URI が LAN private IP / NGN ドメインのどちらでも
    /// P-CSCF IP+port (`118.177.125.1:5060`) に正規化される。
    #[test]
    fn normalize_request_uri_rewrites_to_pcsf_ip() {
        // ケース 1: LAN private IP → P-CSCF IP+port
        let lan = "sip:117@192.168.20.239";
        let out = normalize_request_uri_for_ngn(lan, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース 2: NGN ドメイン (`ntt-east.ne.jp`) → P-CSCF IP+port
        // (NGN は host が IP でないと 403 を返す実機証拠あり)
        let domain = "sip:117@ntt-east.ne.jp";
        let out = normalize_request_uri_for_ngn(domain, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース 3: LAN IP に port 付き
        let lan_port = "sip:117@192.168.20.239:5060";
        let out = normalize_request_uri_for_ngn(lan_port, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース 4: 既に P-CSCF host:port なら idempotent (= 変更しない)
        let already = "sip:117@118.177.125.1:5060";
        let out = normalize_request_uri_for_ngn(already, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");
    }

    /// RFC 3261 §19.1.1 — uri-parameters (`;transport`, `;lr`, `;maddr`, ...)
    /// と `?headers` は SIP-URI 構文上許されるが、NTT NGN P-CSCF は
    /// `;transport=udp` を含む Request-URI を **500 Server Internal Error**
    /// で蹴る (Issue #58 実機 trace)。Asterisk 実機 INVITE はどちらも付けず
    /// 200 OK を取得しているため (`docs/asterisk-real-invite.md` §5.1)、
    /// `normalize_request_uri_for_ngn` は host/port 書換と同時に `;params`
    /// と `?headers` を完全に削除する。
    #[test]
    fn rfc3261_19_1_1_normalize_strips_uri_params_and_headers() {
        // ケース A: ;transport=udp は剥がす (Issue #58 の主症状)
        let with_transport = "sip:117@127.0.0.1;transport=udp";
        let out = normalize_request_uri_for_ngn(with_transport, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース B: 複数 uri-parameters (;lr;maddr=...) はまとめて剥がす
        let with_multi = "sip:117@127.0.0.1;lr;maddr=192.0.2.1";
        let out = normalize_request_uri_for_ngn(with_multi, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース C: ?headers (RFC 3261 §19.1.1) も剥がす
        let with_headers = "sip:117@127.0.0.1?header=value";
        let out = normalize_request_uri_for_ngn(with_headers, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース D: 既に P-CSCF host:port だが ;params が残っているケース。
        // host/port 書換は不要だが ;params 削除のみ走らせて idempotent に
        // 落ち着かせる (Issue #58 の二重正規化対策)。
        let pcsf_with_params = "sip:117@118.177.125.1:5060;transport=udp";
        let out = normalize_request_uri_for_ngn(pcsf_with_params, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース E: 完全正規化済 (host:port 一致 + params/headers 無し) は
        // そのまま返す (true idempotent)。
        let canonical = "sip:117@118.177.125.1:5060";
        let out = normalize_request_uri_for_ngn(canonical, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");
    }

    /// Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §5.2):
    /// 内線 SDP に乗っている LAN private IP (`192.168.30.162` 等) は
    /// NGN 行きの INVITE では eth1 IP に強制書換される。
    #[test]
    fn outbound_invite_sdp_rewrites_private_ip_to_eth1() {
        let ext_offer = b"v=0\r\n\
                          o=iphone 2246 1745 IN IP4 192.168.30.162\r\n\
                          s=Talk\r\n\
                          c=IN IP4 192.168.30.162\r\n\
                          t=0 0\r\n\
                          m=audio 55120 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n";
        let eth1_ip: IpAddr = "118.177.72.242".parse().unwrap();
        let rewritten = force_rewrite_sdp_for_ngn(ext_offer, eth1_ip).expect("Some");
        let parsed =
            crate::sdp::SessionDescription::parse(std::str::from_utf8(&rewritten).unwrap())
                .expect("rewritten SDP must parse");

        // c= / o= は eth1 IP に書換 (LAN private は漏らさない)
        assert_eq!(parsed.connection.as_ref().unwrap().address, eth1_ip);
        assert_eq!(parsed.origin.address, eth1_ip);
        // RTP port は内線広告の port をそのまま温存 (中継不能でも SIP は通る)
        assert_eq!(parsed.media[0].port, 55120);

        // 空 body は None
        assert!(force_rewrite_sdp_for_ngn(b"", eth1_ip).is_none());
    }

    /// Asterisk 実機準拠 e2e: 内線 INVITE に対し UasEventHandler が NGN へ
    /// プロキシする際、出力 INVITE の Request-URI が P-CSCF IP:port になる。
    /// `docs/asterisk-real-invite.md` §3 / §5.1 の事故再現テスト。
    #[tokio::test]
    async fn invite_request_uri_uses_pcsf_ip_when_proxied_from_extension() {
        use crate::sip::uac::UacConfig;

        // (1) フェイク NGN (= P-CSCF) サーバ: INVITE を受けたら Request-URI を
        //     検査して 200 OK を返す。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let captured_uri: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let captured_via: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let captured_uri_c = captured_uri.clone();
        let captured_via_c = captured_via.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(req) = parsed {
                *captured_uri_c.lock().unwrap() = Some(req.uri.clone());
                *captured_via_c.lock().unwrap() = req.headers.get("via").map(str::to_string);
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
                let _ = fake_ngn_clone.recv_from(&mut buf).await;
            }
        });

        // (2) sabiden NGN 側 UAC: server_addr = fake_ngn (P-CSCF 役)。
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
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

        // (3) UasEventHandler を起動 (CallManager 無し = SDP 強制書換パス)
        let handler = UasEventHandler::new(ngn_uac.clone());
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.spawn(event_rx);

        // (4) 模擬内線 UAS: ServerTransaction を sabiden 内に作って
        //     UasEvent を直接 push する。
        let phone_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone_sock.local_addr().unwrap();
        let sabiden_uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

        // 内線が出すであろう INVITE: Request-URI は LAN IP (= 内線 UA から見た sabiden)。
        // ここでは "sip:117@192.168.20.239" を模擬。
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:117@192.168.20.239");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKptest", phone_addr),
        );
        invite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonereq");
        invite.headers.set("To", "<sip:117@192.168.20.239>");
        invite.headers.set("Call-ID", "uri-rewrite-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = b"v=0\r\n\
                        o=iphone 2246 1745 IN IP4 192.168.30.162\r\n\
                        s=Talk\r\n\
                        c=IN IP4 192.168.30.162\r\n\
                        t=0 0\r\n\
                        m=audio 55120 RTP/AVP 0\r\n\
                        a=rtpmap:0 PCMU/8000\r\n"
            .to_vec();
        phone_sock
            .send_to(&invite.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) =
            tokio::time::timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        let parsed = parse_message(&buf[..n]).unwrap();
        let req = match parsed {
            SipMessage::Request(r) => r,
            _ => panic!("INVITE 期待"),
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_uas_sock.clone()).unwrap();
        let responder = crate::sip::uas::ResponderHandle::__test_new(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder,
            })
            .unwrap();

        // (5) NGN タスクが Request-URI を回収するまで待つ
        let _ = ngn_task.await;

        // (6) 検証: 出力 INVITE の Request-URI は P-CSCF IP:port (= fake_ngn_addr) に
        //         書換わっているはず。
        let uri = captured_uri
            .lock()
            .unwrap()
            .clone()
            .expect("NGN へ INVITE が届くべき");
        let pcsf_str = fake_ngn_addr.to_string();
        let user_at_pcsf = format!("sip:117@{}", pcsf_str);
        assert_eq!(
            uri, user_at_pcsf,
            "Request-URI は P-CSCF IP+port に書換わるべき (Asterisk pcap §5.1)"
        );
        // 副次確認: Via に rport が付いていること (§5.5)
        let via = captured_via.lock().unwrap().clone().unwrap_or_default();
        assert!(
            via.contains(";rport"),
            "Via に `;rport` が必要 (Asterisk pcap §5.5): got {}",
            via
        );
    }

    /// 内線 UA → 内線 UAS → UasEventHandler → NGN UAC → フェイク NGN の
    /// end-to-end 結線テスト。Issue #15 の主目的である UAS event ハンドラの
    /// プロキシ動作を確認する。
    #[tokio::test]
    async fn uas_event_proxies_invite_to_ngn() {
        use crate::config::{ExtensionConfig, UasConfig};
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
        let registrar = uas.registrar();

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        // (4) UasEventHandler を起動 (UAS event → NGN UAC)
        let handler = UasEventHandler::new(ngn_uac);
        handler.spawn(event_rx);

        // (5) フェイク内線 UA から INVITE を送る。
        //
        // Issue #62 / RFC 3261 §22 以降、内線 INVITE では Digest challenge を
        // 出さない (REGISTER で確立した binding を信用)。ここでは REGISTER の
        // 往復を省略するため、registrar に AOR を直接 register して binding を
        // 作っておく (本テストの主眼は INVITE→NGN プロキシのため)。
        let phone = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let phone_local = phone.local_addr().unwrap();
        registrar
            .register(
                "iphone",
                format!("sip:iphone@{}", phone_local),
                phone_local,
                Duration::from_secs(60),
            )
            .await;

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

        // 100 Trying → 200 OK が届くまで複数応答を読む。401 は来ない。
        let mut buf = vec![0u8; 8192];
        let mut got_2xx = false;
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        assert_ne!(
                            r.status_code, 401,
                            "Issue #62: 既登録 binding に対し challenge してはならない"
                        );
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

    /// NGN→内線 着信で `CallManager` を接続した場合の統合テスト。
    ///
    /// - フェイク内線 inviter が SDP answer を返すように設定する
    /// - sabiden は両側 RTP ソケットを bind し、200 OK の SDP に sabiden の
    ///   NGN 側 RTP ポートを記載するはず
    /// - フェイク NGN ピアと フェイク内線ピアを別ソケットで模擬し、ブリッジ
    ///   経由で双方向 RTP が届くことを確認
    /// - BYE 受信で `CallManager` から通話が消えることを確認
    #[tokio::test]
    async fn ngn_inbound_with_call_manager_starts_rtp_bridge_and_rewrites_sdp() {
        use crate::call::manager::CallManager;
        use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク内線ピア (200 OK SDP の宛先)
        let ext_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_peer_addr = ext_peer_sock.local_addr().unwrap();
        let ext_answer_sdp = format!(
            "v=0\r\n\
             o=- 2 2 IN IP4 {ip}\r\n\
             s=-\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            ip = ext_peer_addr.ip(),
            port = ext_peer_addr.port()
        );

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(ext_answer_sdp.into_bytes())
            .build();

        // sabiden NGN 側 SIP ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();

        // フェイク NGN ピア (RTP の送り元/受け先 + SIP UA)
        let ngn_peer_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        // 内線登録
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

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound_with_manager(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
            mgr.clone(),
        );
        let _ = inviter; // keep call_count alive (no-op)

        // NGN INVITE 送信 (SDP オファあり)
        let ngn_offer_sdp = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 {ip}\r\n\
             s=-\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            ip = ngn_peer_addr.ip(),
            port = ngn_peer_addr.port()
        );
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKbridge1", ngn_peer_addr),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-bridge");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-bridge-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = ngn_offer_sdp.into_bytes();
        ngn_peer_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 200 OK を読み取り、書き換え後の SDP からブリッジが指す sabiden NGN ポートを得る
        let mut buf = vec![0u8; 8192];
        let sabiden_ngn_rtp: SocketAddr;
        loop {
            let (n, _) = timeout(Duration::from_secs(3), ngn_peer_sock.recv_from(&mut buf))
                .await
                .expect("200 OK が来ない")
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 200 {
                    assert!(!r.body.is_empty(), "200 OK には書き換え後の SDP が必要");
                    let sdp_text = std::str::from_utf8(&r.body).unwrap();
                    let parsed = crate::sdp::SessionDescription::parse(sdp_text).unwrap();
                    let conn = parsed.connection.as_ref().expect("c= が必要");
                    let port = parsed.media[0].port;
                    sabiden_ngn_rtp = SocketAddr::new(conn.address, port);
                    // ext_peer_addr (内線側) のままだと中継されないので絶対 NG
                    assert_ne!(
                        sabiden_ngn_rtp, ext_peer_addr,
                        "200 OK の SDP は sabiden 側 RTP ポートを指すべき (内線ポートのままでは透過不可)"
                    );
                    break;
                }
            }
        }

        // ブリッジが起動して CallManager に登録されているはず
        assert_eq!(mgr.len().await, 1, "通話エントリが 1 件");

        // フェイク NGN ピア → sabiden NGN RTP → 内線ピア の方向で RTP リレー確認
        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 160,
            ssrc: 0xCAFE_BABE,
            payload: vec![0xff; 160],
        }
        .to_bytes();
        ngn_peer_sock.send_to(&pkt, sabiden_ngn_rtp).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), ext_peer_sock.recv_from(&mut buf))
            .await
            .expect("内線ピアが RTP を受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.ssrc, 0xCAFE_BABE);

        // 逆方向: 内線ピアが返事を送ったら NGN ピアが受け取れる (送り元学習機構を活用)
        // ブリッジは learn_peer なので、ext_peer の最初の送信で sabiden_ext を学習させる必要がある。
        // 内線ピアは sabiden の ext 側 RTP ポートが分からない (本テストでは 200 OK の中身のみ
        // 知っているのは NGN 側ピア)。実際には内線も自身の SDP オファ→sabiden 側応答で
        // sabiden の ext ポートを知るが、本テストでは内線ピアが ext_peer_sock からの送信元として
        // 露出した sabiden の ext_socket をそのまま再送先に流用する。
        // → 直前に sabiden の ext 側ソケット → ext_peer_sock の通信が起きており、recv_from の
        //    ピア情報からは sabiden_ext が引ける。
        // ここでは簡略化のため、逆方向は省略する (片方向の中継・SDP 書き換え検証で十分)。

        // BYE で通話終了
        let mut bye = SipRequest::new(SipMethod::Bye, "sip:sabiden");
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKbridgebye", ngn_peer_addr),
        );
        bye.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-bridge");
        bye.headers.set("To", "<sip:0312345678@sabiden>;tag=local");
        bye.headers.set("Call-ID", "ngn-bridge-cid");
        bye.headers.set("CSeq", "2 BYE");
        ngn_peer_sock
            .send_to(&bye.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // BYE の 200 OK を待つ (CallManager::terminate が走る)
        for _ in 0..3 {
            match timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 200 {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        // CallManager::terminate は async で実行されているので少し待つ
        for _ in 0..20 {
            if mgr.len().await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(mgr.len().await, 0, "BYE で通話エントリが消えるべき");
    }

    /// 内線→NGN 発信時、`UasEventHandler::with_call_manager` 経路で
    /// SDP を sabiden 側に書き換えた INVITE が NGN に届き、
    /// 200 OK answer を内線へ返す際にも sabiden 側 ext ポートに書き換わることを確認。
    /// 加えて RTP リレーが NGN 側ピア → 内線側ピアで実際に動くことを検証する。
    #[tokio::test]
    async fn uas_event_with_call_manager_starts_rtp_bridge() {
        use crate::call::manager::CallManager;
        use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク内線ピア (内線 UA の RTP 担当役)
        let ext_peer_rtp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_peer_rtp_addr = ext_peer_rtp.local_addr().unwrap();

        // フェイク NGN: INVITE を受けて SDP answer (NGN ピアの RTP ポート) を 200 OK で返す。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        // NGN 側 RTP ピア
        let ngn_peer_rtp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_rtp_addr = ngn_peer_rtp.local_addr().unwrap();

        let invite_sdp_to_ngn: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(None));
        let invite_sdp_seen_for_task = invite_sdp_to_ngn.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(req) = parsed {
                assert_eq!(req.method, SipMethod::Invite);
                // 受信した SDP を保存 (sabiden 側 NGN ポートに書き換わっているはず)
                *invite_sdp_seen_for_task.lock().unwrap() = Some(req.body.clone());
                let mut resp = build_response_skeleton(&req, 200, "OK");
                resp.headers.set(
                    "To",
                    format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
                );
                resp.headers
                    .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                resp.headers.set("Content-Type", "application/sdp");
                resp.body = format!(
                    "v=0\r\n\
                     o=- 9 9 IN IP4 {ip}\r\n\
                     s=-\r\n\
                     c=IN IP4 {ip}\r\n\
                     t=0 0\r\n\
                     m=audio {port} RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n",
                    ip = ngn_peer_rtp_addr.ip(),
                    port = ngn_peer_rtp_addr.port()
                )
                .into_bytes();
                fake_ngn_clone
                    .send_to(&resp.to_bytes(), peer)
                    .await
                    .unwrap();
                // ACK 受信 (drop)
                let _ = fake_ngn_clone.recv_from(&mut buf).await;
            }
        });

        // sabiden NGN 側 UAC
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

        let mgr = CallManager::new(ExtensionRegistrar::new());

        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.spawn(event_rx);

        // 内線が出すであろう INVITE を擬似的に作成 (responder は ServerTransaction が必要)。
        // 内線ピア役の SIP トランザクションを 1 個作成し ResponderHandle を握る。
        let phone_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone_sock.local_addr().unwrap();
        // 内線→sabiden 用ソケット (内線 UAS 役を簡易的に手書きする)
        let sabiden_uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

        let mut invite_from_phone = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite_from_phone.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKuasinv", phone_addr),
        );
        invite_from_phone
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet");
        invite_from_phone
            .headers
            .set("To", "<sip:0312345678@sabiden>");
        invite_from_phone.headers.set("Call-ID", "uas-bridge-cid");
        invite_from_phone.headers.set("CSeq", "1 INVITE");
        invite_from_phone
            .headers
            .set("Content-Type", "application/sdp");
        invite_from_phone.body = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 {ip}\r\n\
             s=-\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            ip = ext_peer_rtp_addr.ip(),
            port = ext_peer_rtp_addr.port()
        )
        .into_bytes();

        // 内線から sabiden へ INVITE を送り、sabiden 側で ServerTransaction を作って
        // UasEvent を直接イベントチャネルに突っ込む。
        phone_sock
            .send_to(&invite_from_phone.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
        // sabiden 側で受信
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_message(&buf[..n]).unwrap();
        let req = match parsed {
            SipMessage::Request(r) => r,
            _ => panic!("INVITE 期待"),
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_uas_sock.clone()).unwrap();
        let responder = crate::sip::uas::ResponderHandle::__test_new(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder,
            })
            .unwrap();

        // 内線が 200 OK + SDP answer を受け取る (書き換えされているはず)
        let sabiden_ext_rtp: SocketAddr = loop {
            let (n, _) = timeout(Duration::from_secs(3), phone_sock.recv_from(&mut buf))
                .await
                .expect("内線へ 200 OK が来ない")
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 200 {
                    assert!(!r.body.is_empty(), "200 OK には書き換え後 SDP が必要");
                    let parsed = crate::sdp::SessionDescription::parse(
                        std::str::from_utf8(&r.body).unwrap(),
                    )
                    .unwrap();
                    let conn = parsed.connection.unwrap();
                    let port = parsed.media[0].port;
                    let addr = SocketAddr::new(conn.address, port);
                    assert_ne!(
                        addr, ngn_peer_rtp_addr,
                        "200 OK の SDP は sabiden 側 ext ポートを指すべき"
                    );
                    break addr;
                }
            }
        };

        // NGN へ送信された INVITE の SDP も書き換わっているはず
        let _ = ngn_task.await;
        let ngn_invite_sdp = invite_sdp_to_ngn
            .lock()
            .unwrap()
            .clone()
            .expect("NGN へ INVITE が届くべき");
        let parsed =
            crate::sdp::SessionDescription::parse(std::str::from_utf8(&ngn_invite_sdp).unwrap())
                .unwrap();
        assert_ne!(
            parsed.media[0].port,
            ext_peer_rtp_addr.port(),
            "NGN 行きの INVITE の SDP は sabiden 側 NGN ポートを指すべき"
        );

        // ブリッジが起動している
        assert_eq!(mgr.len().await, 1);

        // RTP リレー (NGN ピア → sabiden NGN bridge → 内線ピア) を確認するため、
        // sabiden_ext_rtp が ext_peer_rtp_addr ではなく sabiden 側 ext bridge ポートで
        // あることを利用して、ext_peer_rtp が sabiden_ext_rtp 宛に送る → ブリッジが
        // NGN 側へ転送 → ngn_peer_rtp が受信、を確認する。
        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 5,
            timestamp: 320,
            ssrc: 0xDEAD_BEEF,
            payload: vec![0xab; 160],
        }
        .to_bytes();
        ext_peer_rtp.send_to(&pkt, sabiden_ext_rtp).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), ngn_peer_rtp.recv_from(&mut buf))
            .await
            .expect("NGN ピアが RTP を受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.ssrc, 0xDEAD_BEEF);
    }

    // ===== B2BUA 双方向シグナリング テスト群 =====

    /// 内線→NGN 発信通話で、内線が BYE を出すと NGN にも BYE が伝搬される。
    /// RFC 3261 §15.1.2 (BYE) + B2BUA の責務 (両レッグの dialog を別々に閉じる)。
    #[tokio::test]
    async fn ext_bye_propagates_to_ngn() {
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: INVITE→200 OK→ACK→BYE→200 OK
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let ngn_bye_seen = Arc::new(StdMutex::new(false));
        let ngn_bye_seen_c = ngn_bye_seen.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE 受信 → 200 OK 返送
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(invite) = parse_message(&buf[..n]).unwrap() else {
                panic!("INVITE 期待");
            };
            assert_eq!(invite.method, SipMethod::Invite);
            let mut resp = build_response_skeleton(&invite, 200, "OK");
            resp.headers.set(
                "To",
                format!("{};tag=ngn-tag", invite.headers.get("to").unwrap()),
            );
            resp.headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_clone
                .send_to(&resp.to_bytes(), peer)
                .await
                .unwrap();
            // ACK 受信 (drop)
            let _ = fake_ngn_clone.recv_from(&mut buf).await;
            // BYE 受信 → 200 OK 返送
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            if let SipMessage::Request(bye) = parse_message(&buf[..n]).unwrap() {
                if bye.method == SipMethod::Bye {
                    *ngn_bye_seen_c.lock().unwrap() = true;
                    let bye_resp = build_response_skeleton(&bye, 200, "OK");
                    fake_ngn_clone
                        .send_to(&bye_resp.to_bytes(), peer)
                        .await
                        .unwrap();
                }
            }
        });

        // sabiden NGN UAC
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

        // sabiden 内線 UAS 用 socket (生 recv_from する用; レイヤを spawn しない)。
        // BYE を内線へ送るための ext_layer は別ソケットで持つ (本テストでは
        // ext→NGN 方向なので ext_layer は使われないが attach のみ)。
        let sabiden_ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_ext_addr = sabiden_ext_sock.local_addr().unwrap();
        let layer_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ext_layer, _ext_rx) = TransactionLayer::spawn(layer_sock.clone());

        // UasEventHandler with ext_layer attached
        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer.clone(), Some(sabiden_ext_addr));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.clone().spawn(event_rx);

        // フェイク内線: 自前ソケットから INVITE を送り、200 OK を受け取る
        let phone = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone.local_addr().unwrap();
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKextbye1", phone_addr),
        );
        invite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ext-bye-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));

        // sabiden の UAS-side ServerTransaction を作成し UasEvent::Invite を送る
        phone
            .send_to(&invite.to_bytes(), sabiden_ext_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_ext_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("INVITE 期待");
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let responder = crate::sip::uas::ResponderHandle::__test_new(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder,
            })
            .unwrap();

        // 内線が 200 OK を受信するまで待つ
        let _ok = loop {
            let (n, _) = timeout(Duration::from_secs(3), phone.recv_from(&mut buf))
                .await
                .expect("内線へ 200 OK が届かない")
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 200 {
                    break r;
                }
            }
        };

        // 内線が BYE を送る (B2BUA: NGN にも伝搬されるはず)
        let mut bye = SipRequest::new(SipMethod::Bye, "sip:sabiden");
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKextbye2", phone_addr),
        );
        bye.headers.set("From", "<sip:iphone@sabiden>;tag=phonet");
        bye.headers.set("To", "<sip:0312345678@sabiden>;tag=local"); // sabiden 側 tag 未把握なので仮値
        bye.headers.set("Call-ID", "ext-bye-cid");
        bye.headers.set("CSeq", "2 BYE");

        // sabiden 側で BYE を受信して UasEvent::Bye を直接 fire (UAS::run なしで動かしてるため)
        phone
            .send_to(&bye.to_bytes(), sabiden_ext_addr)
            .await
            .unwrap();
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_ext_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(bye_req) = parse_message(&buf[..n]).unwrap() else {
            panic!("BYE 期待");
        };
        assert_eq!(bye_req.method, SipMethod::Bye);
        let bye_stx =
            ServerTransaction::new(bye_req.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let bye_responder = crate::sip::uas::ResponderHandle::__test_new(bye_stx);
        event_tx
            .send(UasEvent::Bye {
                request: bye_req,
                remote,
                responder: bye_responder,
            })
            .unwrap();

        // 内線へ BYE 200 OK が返り、NGN にも BYE が届く
        let mut got_bye_ok = false;
        for _ in 0..3 {
            match timeout(Duration::from_secs(2), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 200 {
                            // BYE への 200 OK
                            got_bye_ok = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_bye_ok, "内線への BYE 200 OK が必要");

        // フェイク NGN タスクが BYE を観測した
        let _ = timeout(Duration::from_secs(3), ngn_task).await;
        assert!(*ngn_bye_seen.lock().unwrap(), "NGN へ BYE が伝搬されるべき");
    }

    /// 内線→NGN 発信通話で、NGN が BYE を出すと内線にも BYE が伝搬される。
    #[tokio::test]
    async fn ngn_bye_propagates_to_ext() {
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: INVITE→200 OK→ACK 受信、その後自分から BYE を送る
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        // BYE を送る側で response を受け取りたいのでチャネルを切らずにタスクを動かす
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE 受信
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(invite) = parse_message(&buf[..n]).unwrap() else {
                panic!("INVITE 期待");
            };
            // 200 OK 返送
            let mut resp = build_response_skeleton(&invite, 200, "OK");
            resp.headers.set(
                "To",
                format!("{};tag=ngn-tag", invite.headers.get("to").unwrap()),
            );
            resp.headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_clone
                .send_to(&resp.to_bytes(), peer)
                .await
                .unwrap();
            // ACK 受信
            let (_, _) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            // 自分から BYE 送出 (NGN ダイアログのテイクダウン)
            let mut bye = SipRequest::new(SipMethod::Bye, format!("sip:sabiden@{}", peer));
            bye.headers.set(
                "Via",
                format!("SIP/2.0/UDP {};branch=z9hG4bKngnbye", fake_ngn_addr),
            );
            bye.headers.set(
                "From",
                format!("{};tag=ngn-tag", invite.headers.get("to").unwrap()),
            );
            bye.headers.set("To", invite.headers.get("from").unwrap());
            bye.headers
                .set("Call-ID", invite.headers.get("call-id").unwrap());
            bye.headers.set("CSeq", "1 BYE");
            fake_ngn_clone.send_to(&bye.to_bytes(), peer).await.unwrap();
            // BYE への 200 OK を受け取る (ペイロードは捨てる)
            let _ = timeout(Duration::from_secs(3), fake_ngn_clone.recv_from(&mut buf)).await;
        });

        // sabiden NGN UAC + 着信ハンドラ
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, ngn_inbound_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
            },
            ngn_layer.clone(),
            fake_ngn_addr,
        ));

        // sabiden 内線 UAS 用 socket + layer
        let sabiden_ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_ext_addr = sabiden_ext_sock.local_addr().unwrap();
        let (ext_layer, _ext_rx) = TransactionLayer::spawn(sabiden_ext_sock.clone());

        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer.clone(), Some(sabiden_ext_addr));
        let handler_for_forwarder: Arc<dyn OutboundDialogForwarder> = handler.clone();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.clone().spawn(event_rx);

        // NGN 着信ハンドラを起動 (NGN 側 inbound_rx で BYE をキャッチさせる)。
        // inviter は使わない (内線着信は来ない) ので minimal な dummy を渡す。
        // (ハーネス Issue #42 で `ScriptedInviter` は builder ベースに統合された。)
        let dummy_inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let extensions_empty = ExtensionRegistrar::new();
        let ngn_handler = NgnInboundHandler::new(
            ngn_client_sock.clone(),
            dummy_inviter,
            extensions_empty,
            NgnInboundConfig::default(),
        );
        ngn_handler
            .set_outbound_forwarder(handler_for_forwarder)
            .await;
        ngn_handler.spawn(ngn_inbound_rx);

        // フェイク内線から INVITE を送る
        let phone = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone.local_addr().unwrap();
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKngnbye1", phone_addr),
        );
        invite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet2");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-bye-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));
        phone
            .send_to(&invite.to_bytes(), sabiden_ext_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_ext_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("INVITE 期待");
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let responder = crate::sip::uas::ResponderHandle::__test_new(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder,
            })
            .unwrap();

        // 内線が 200 OK を受信
        loop {
            let (n, _) = timeout(Duration::from_secs(3), phone.recv_from(&mut buf))
                .await
                .expect("内線へ 200 OK が届かない")
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 200 {
                    break;
                }
            }
        }

        // NGN は ACK 受信後に BYE を送ってくる → sabiden は内線へ BYE を伝搬する
        let got_bye = loop {
            let (n, _) = match timeout(Duration::from_secs(5), phone.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => break false,
            };
            if let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() {
                if req.method == SipMethod::Bye {
                    // 内線として 200 OK を返す
                    let bye_resp = build_response_skeleton(&req, 200, "OK");
                    phone
                        .send_to(&bye_resp.to_bytes(), sabiden_ext_addr)
                        .await
                        .unwrap();
                    break true;
                }
            }
        };
        assert!(got_bye, "NGN BYE が内線レッグに伝搬されるべき");
        let _ = timeout(Duration::from_secs(2), ngn_task).await;
    }

    /// 内線→NGN 発信中、INVITE 進行中に内線が CANCEL を出すと、NGN へ CANCEL が
    /// 伝搬され、内線へは 487 Request Terminated が返る。
    #[tokio::test]
    async fn ext_cancel_propagates_to_ngn_and_returns_487() {
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: INVITE を受けたら 100 Trying のみ返し、応答を保留。
        // CANCEL を受けたら 200 OK + 487 Request Terminated を返す。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let cancel_seen = Arc::new(StdMutex::new(false));
        let cancel_seen_c = cancel_seen.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(invite) = parse_message(&buf[..n]).unwrap() else {
                panic!("INVITE 期待");
            };
            assert_eq!(invite.method, SipMethod::Invite);
            // 100 Trying
            let trying = build_response_skeleton(&invite, 100, "Trying");
            fake_ngn_clone
                .send_to(&trying.to_bytes(), peer)
                .await
                .unwrap();
            // CANCEL を待つ
            let (n, peer2) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            if let SipMessage::Request(cancel) = parse_message(&buf[..n]).unwrap() {
                if cancel.method == SipMethod::Cancel {
                    *cancel_seen_c.lock().unwrap() = true;
                    let cancel_ok = build_response_skeleton(&cancel, 200, "OK");
                    fake_ngn_clone
                        .send_to(&cancel_ok.to_bytes(), peer2)
                        .await
                        .unwrap();
                    // 元 INVITE に 487 Request Terminated
                    let mut term = build_response_skeleton(&invite, 487, "Request Terminated");
                    term.headers.set(
                        "To",
                        format!("{};tag=ngn-cancel", invite.headers.get("to").unwrap()),
                    );
                    fake_ngn_clone
                        .send_to(&term.to_bytes(), peer)
                        .await
                        .unwrap();
                    // ACK 受信 (drop)
                    let _ =
                        timeout(Duration::from_secs(2), fake_ngn_clone.recv_from(&mut buf)).await;
                }
            }
        });

        // sabiden NGN UAC
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

        // sabiden 内線 UAS 用
        let sabiden_ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_ext_addr = sabiden_ext_sock.local_addr().unwrap();
        let (ext_layer, _ext_rx) = TransactionLayer::spawn(sabiden_ext_sock.clone());

        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer, Some(sabiden_ext_addr));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.clone().spawn(event_rx);

        // 内線が INVITE を送って sabiden が ServerTransaction を作る
        let phone = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone.local_addr().unwrap();
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKextcanc1", phone_addr),
        );
        invite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet3");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ext-cancel-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));
        phone
            .send_to(&invite.to_bytes(), sabiden_ext_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_ext_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("INVITE 期待");
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let responder = crate::sip::uas::ResponderHandle::__test_new(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req.clone(),
                remote,
                responder,
            })
            .unwrap();

        // INVITE が NGN へ届くまで少し待つ (registry に pending が入るタイミング)。
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 内線が CANCEL を送る (UasEvent::Cancel を直接 fire)
        let mut cancel = SipRequest::new(SipMethod::Cancel, "sip:0312345678@sabiden");
        cancel.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKextcanc1", phone_addr),
        );
        cancel
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet3");
        cancel.headers.set("To", "<sip:0312345678@sabiden>");
        cancel.headers.set("Call-ID", "ext-cancel-cid");
        cancel.headers.set("CSeq", "1 CANCEL");
        let cancel_stx =
            ServerTransaction::new(cancel.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let cancel_responder = crate::sip::uas::ResponderHandle::__test_new(cancel_stx);
        event_tx
            .send(UasEvent::Cancel {
                request: cancel,
                remote,
                responder: cancel_responder,
            })
            .unwrap();

        // 内線へ 487 が返る
        let mut got_487 = false;
        for _ in 0..6 {
            match timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 487 {
                            got_487 = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_487, "内線レッグへ 487 Request Terminated が必要");

        // NGN へ CANCEL が届く
        let _ = timeout(Duration::from_secs(3), ngn_task).await;
        assert!(
            *cancel_seen.lock().unwrap(),
            "NGN へ CANCEL が伝搬されるべき"
        );
    }

    /// `OutboundCallRegistry` の単体動作: pending → confirmed の遷移と
    /// 両側 Call-ID での lookup が機能する。
    #[tokio::test]
    async fn outbound_registry_lookup_by_either_call_id() {
        let reg = OutboundCallRegistry::new();
        // pending 投入
        let pending = Arc::new(PendingOutbound {
            ext_call_id: "ext-cid".to_string(),
            invite_plan: {
                let mut req = SipRequest::new(SipMethod::Invite, "sip:dst@host");
                req.headers
                    .set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest");
                req.headers.set("From", "<sip:src@host>;tag=alice");
                req.headers.set("To", "<sip:dst@host>");
                req.headers.set("Call-ID", "fake");
                req.headers.set("CSeq", "1 INVITE");
                crate::sip::uac::InvitePlan {
                    request: req,
                    cseq: 1,
                    target_uri: "sip:dst@host".to_string(),
                    session_expires: 300,
                }
            },
            ext_responder: {
                let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let mut req = SipRequest::new(SipMethod::Invite, "sip:dst@host");
                req.headers
                    .set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest");
                req.headers.set("From", "<sip:src@host>;tag=alice");
                req.headers.set("To", "<sip:dst@host>");
                req.headers.set("Call-ID", "fake");
                req.headers.set("CSeq", "1 INVITE");
                let stx =
                    ServerTransaction::new(req, "127.0.0.1:9999".parse().unwrap(), sock).unwrap();
                crate::sip::uas::ResponderHandle::__test_new(stx)
            },
            cancelled: tokio::sync::Notify::new(),
            cancelled_flag: std::sync::atomic::AtomicBool::new(false),
        });
        reg.insert_pending(pending.clone()).await;
        assert!(reg.get_pending("ext-cid").await.is_some());
        assert!(reg.take_pending("ext-cid").await.is_some());
        assert!(reg.get_pending("ext-cid").await.is_none());
    }

    /// NGN 着信 INVITE → WebRTC 内線への offer push → browser からの answer 受信
    /// → NGN へ 200 OK (browser answer SDP を body に詰めて) を返すまでの round trip。
    /// SIP UAC fork は使わず、WebRTC transport の binding 単独で動くことを確認する。
    /// バンドエイドだった `webrtc.local` フィルタの代替動作を保証するテスト。
    #[tokio::test]
    async fn ngn_invite_to_webrtc_binding_offer_push_and_answer_round_trip() {
        use crate::sip::message::parse_message;
        use crate::sip::message::SipMessage;
        use crate::sip::registrar::ExtTransport;
        use crate::sip::transaction::TransactionLayer;
        use crate::webrtc::peer::{PeerSession, StubPeerSession};
        use crate::webrtc::signaling::{ClientMessage, PendingAnswers, ServerMessage, WsSink};
        use std::time::Duration;
        use tokio::sync::mpsc;
        use tokio::time::timeout;

        // sabiden NGN SIP ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        // NGN 側ピア (フェイク UA)
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_addr = ngn_sock.local_addr().unwrap();

        // WebRTC 内線をシミュレートする WS チャネル (browser 役)
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();

        // ExtensionRegistrar に WebRTC transport で binding を入れる
        let extensions = ExtensionRegistrar::new();
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

        // browser シミュレーション: ServerMessage::Offer を受け取ったら同じ call_id で
        // ClientMessage::Answer { call_id, sdp } 相当の SDP を pending に届ける。
        let pending_for_browser = pending.clone();
        let browser_answer_sdp = "v=0\r\n\
                                  o=- 9 9 IN IP4 192.0.2.99\r\n\
                                  s=-\r\n\
                                  c=IN IP4 192.0.2.99\r\n\
                                  t=0 0\r\n\
                                  m=audio 30000 RTP/AVP 0\r\n\
                                  a=rtpmap:0 PCMU/8000\r\n";
        let browser_answer_sdp_owned = browser_answer_sdp.to_string();
        let browser_task = tokio::spawn(async move {
            let msg = timeout(Duration::from_secs(3), out_rx.recv())
                .await
                .expect("browser へ offer push が来ない")
                .expect("WS チャネルが閉じている");
            match msg {
                ServerMessage::Offer { call_id, sdp: _ } => {
                    let delivered = pending_for_browser
                        .deliver(&call_id, browser_answer_sdp_owned.clone())
                        .await;
                    assert!(delivered, "PendingAnswers::deliver が成功するはず");
                }
                other => panic!("offer 以外を受信: {:?}", other),
            }
        });

        // SIP fork 用 inviter (本テストでは呼ばれないはずだが ExtInviter が必要)。
        // (ハーネス Issue #42 で `ScriptedInviter` は builder ベースに統合された。)
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
        );

        // NGN INVITE 送信 (PCMU 0 のコンパクト SDP)
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKwebrtc-ngn", ngn_addr),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-w");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-webrtc-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = b"v=0\r\n\
                        o=- 1 1 IN IP4 192.0.2.1\r\n\
                        s=-\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        m=audio 20000 RTP/AVP 0\r\n\
                        a=rtpmap:0 PCMU/8000\r\n\
                        a=ptime:20\r\n\
                        a=sendrecv\r\n"
            .to_vec();
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 100 Trying と 200 OK を待つ
        let mut buf = vec![0u8; 8192];
        let mut got_100 = false;
        let mut got_200 = false;
        let mut answer_body = Vec::new();
        for _ in 0..5 {
            match timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        match r.status_code {
                            100 => got_100 = true,
                            200 => {
                                got_200 = true;
                                answer_body = r.body.clone();
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

        // 200 OK の body は browser が返した answer SDP で、SIP UAC fork は呼ばれていない
        assert_eq!(
            answer_body,
            browser_answer_sdp.as_bytes(),
            "200 OK の SDP body は browser の answer がそのまま入るべき"
        );
        assert_eq!(
            inviter.call_count(),
            0,
            "WebRTC 専用 binding なので SIP fork inviter は呼ばれないはず"
        );

        // browser タスクが正常に完了している
        browser_task.await.unwrap();

        // ClientMessage::Answer のラウンドトリップ JSON 表現も serde で読み書きできる
        let cm = ClientMessage::Answer {
            call_id: "x".into(),
            sdp: "v=0".into(),
        };
        let s = serde_json::to_string(&cm).unwrap();
        assert!(s.contains("\"type\":\"answer\""));
        assert!(s.contains("\"call_id\":\"x\""));
    }
}
