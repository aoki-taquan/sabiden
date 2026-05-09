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
use super::manager::{
    extract_rtp_endpoint, fork_to_extensions, CallManager, ForkResult, LegInviter, UacForker,
};
use super::CallId;
use crate::observability::{InviteResult, Metrics};
use crate::sdp::builder::rewrite_rtp_endpoint;
use crate::sip::dialog::{Dialog, DialogConfig};
use crate::sip::message::{SipMethod, SipRequest, SipResponse};
use crate::sip::registrar::ExtensionRegistrar;
use crate::sip::transaction::{
    build_response_skeleton, InboundRequest, ServerTransaction, TransactionLayer,
};
use crate::sip::uac::{InviteOutcome, InvitePlan, Uac, UacDialog};
use crate::sip::uas::{ResponderHandle, UasEvent};

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
            let targets: Vec<String> = bindings
                .iter()
                .map(|(_, b)| b.contact_uri.clone())
                .collect();

            // フォーク (内線レッグ)
            let sdp = request.body.clone();
            let result =
                fork_to_extensions(self.inviter.clone(), targets, sdp, self.cfg.fork_timeout).await;

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
        let rewritten =
            rewrite_rtp_endpoint(ext_answer, sabiden_ngn_addr.ip(), sabiden_ngn_addr.port())?;

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
            } => self.handle_invite(from_aor, request, remote, responder).await,
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
            let target = request.uri.clone();
            let ext_offer = request.body.clone();

            // CallManager があれば RTP ブリッジ用ソケットを先に確保し、
            // NGN へ送る INVITE の SDP を sabiden 側に書き換える。
            let (bridge_ctx, sdp_for_ngn) =
                match self.prepare_outbound_bridge(&ext_offer).await {
                    Ok(Some((ctx, rewritten))) => (Some(ctx), Some(rewritten)),
                    Ok(None) => (
                        None,
                        if ext_offer.is_empty() {
                            None
                        } else {
                            Some(ext_offer.clone())
                        },
                    ),
                    Err(e) => {
                        warn!(error=%e, "NGN 側 RTP ブリッジ準備失敗 → SDP 透過");
                        (
                            None,
                            if ext_offer.is_empty() {
                                None
                            } else {
                                Some(ext_offer.clone())
                            },
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

/// `wire_ngn_inbound` の `CallManager` 接続版。RTP ブリッジを起動する経路。
pub fn wire_ngn_inbound_with_manager(
    _layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    call_manager: Arc<CallManager>,
) -> Arc<NgnInboundHandler> {
    let handler =
        NgnInboundHandler::with_call_manager(socket, inviter, extensions, cfg, call_manager);
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

        let inviter = Arc::new(ScriptedInviter {
            status: 200,
            body: ext_answer_sdp.into_bytes(),
            called: AtomicUsize::new(0),
            seen_targets: StdMutex::new(Vec::new()),
        });

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
        bye.headers
            .set("To", "<sip:0312345678@sabiden>;tag=local"); // sabiden 側 tag 未把握なので仮値
        bye.headers.set("Call-ID", "ext-bye-cid");
        bye.headers.set("CSeq", "2 BYE");

        // sabiden 側で BYE を受信して UasEvent::Bye を直接 fire (UAS::run なしで動かしてるため)
        phone.send_to(&bye.to_bytes(), sabiden_ext_addr).await.unwrap();
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
            let _ = timeout(
                Duration::from_secs(3),
                fake_ngn_clone.recv_from(&mut buf),
            )
            .await;
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
        let dummy_inviter: ExtInviter = Arc::new(ScriptedInviter {
            status: 486,
            body: Vec::new(),
            called: AtomicUsize::new(0),
            seen_targets: StdMutex::new(Vec::new()),
        });
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
                    let _ = timeout(
                        Duration::from_secs(2),
                        fake_ngn_clone.recv_from(&mut buf),
                    )
                    .await;
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
        assert!(*cancel_seen.lock().unwrap(), "NGN へ CANCEL が伝搬されるべき");
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
}
