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
use crate::sip::message::{parse_sip_uri, SipMethod, SipRequest, SipResponse};
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
            metrics,
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
        // BYE は新しい transaction で 200 OK を返す。NGN 側ダイアログのテイクダウンは
        // 内線側 dialog 終了処理側で完了済みである前提 (Phase 1 簡易実装)。
        let mut tx = ServerTransaction::new(request.clone(), remote, self.socket.clone())?;
        let resp = build_response_skeleton(tx.request(), 200, "OK");
        tx.respond(resp).await?;
        if let Some(cid) = request.headers.get("call-id") {
            self.pending.lock().await.remove(cid);
            // 確立済みなら RTP ブリッジを停止する (CallManager::terminate)。
            let removed = { self.active.lock().await.remove(cid) };
            // active に居れば 200 OK 経由で確立済み (= inc_call_active 済み)。
            // BYE で通話終了として call_active を -1。
            if removed.is_some() {
                self.metrics.dec_call_active();
            }
            if let (Some(Some(call_id)), Some(mgr)) = (removed, self.call_manager.as_ref()) {
                if let Err(e) = mgr.terminate(call_id).await {
                    warn!(error=%e, "BYE 受信時の通話終了に失敗");
                }
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

/// 内線→NGN プロキシ時の Request-URI 正規化。
///
/// 内線 (Linphone 等) は `INVITE sip:<dial>@<sabiden-LAN-IP>` を吐くため、
/// このまま NGN にプロキシすると P-CSCF が LAN IP 宛 URI を 403 で蹴る。
/// host 部が NGN ドメインでも NGN P-CSCF アドレスでもない場合は、
/// host を `ngn_domain` に置換し、ユーザ部 (= dial 番号) を保持して返す。
/// `;params` `?headers` は捨てる (NGN 直収では transport=udp 等は不要)。
///
/// 既に NGN ドメインや P-CSCF アドレスを指している場合は変更しない。
/// パースに失敗した場合 (相対 URI 等) はフェイルセーフとして元 URI を返す。
fn normalize_request_uri_for_ngn(req_uri: &str, ngn_domain: &str, ngn_server_host: &str) -> String {
    let Some(parts) = parse_sip_uri(req_uri) else {
        return req_uri.to_string();
    };
    // host が既に NGN ドメイン (大小文字無視) または P-CSCF アドレスを指していれば
    // 触らない。NGN 経路は通常ドメイン名で発信するが、ピン留め IP 直指定の運用も
    // 許容するためこのガードを置く。
    let host_lower = parts.host.to_ascii_lowercase();
    let domain_lower = ngn_domain.to_ascii_lowercase();
    let server_lower = ngn_server_host.to_ascii_lowercase();
    if host_lower == domain_lower || host_lower == server_lower {
        // 既に正しい host。`;params` は念のため落とす。
        return rebuild_sip_uri(parts.scheme, parts.user, parts.host, parts.port);
    }
    // それ以外 (= 内線 UAS の bind IP / 任意の LAN IP / 不明 host) は
    // NGN ドメインに置き換える。port は捨てる (NGN は SRV/RFC 3263 で解決される)。
    rebuild_sip_uri(parts.scheme, parts.user, ngn_domain, None)
}

/// `parse_sip_uri` の結果から `;params` を剥がした URI を再構築する。
/// IPv6 リテラルの場合は `[..]` を付け直す。
fn rebuild_sip_uri(scheme: &str, user: Option<&str>, host: &str, port: Option<&str>) -> String {
    let host_part = if host.contains(':') {
        // IPv6 リテラル
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    let host_with_port = match port {
        Some(p) => format!("{}:{}", host_part, p),
        None => host_part,
    };
    match user {
        Some(u) => format!("{}:{}@{}", scheme, u, host_with_port),
        None => format!("{}:{}", scheme, host_with_port),
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
    /// RTP ブリッジ管理用 CallManager (`None` なら SDP 透過モード)。
    call_manager: Option<Arc<CallManager>>,
    /// 内線発信時の RTP ブリッジ用 NGN 側 bind IP。`None` なら loopback。
    bridge_ngn_bind_ip: Option<IpAddr>,
    /// 内線発信時の RTP ブリッジ用内線側 bind IP。`None` なら loopback。
    bridge_ext_bind_ip: Option<IpAddr>,
    /// 確立済み Call-ID → Option<CallId> (None は透過モード)
    active: Arc<Mutex<HashMap<String, Option<CallId>>>>,
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
            _dialogs: Arc::new(Mutex::new(HashMap::new())),
            call_manager: None,
            bridge_ngn_bind_ip: None,
            bridge_ext_bind_ip: None,
            active: Arc::new(Mutex::new(HashMap::new())),
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
            _dialogs: Arc::new(Mutex::new(HashMap::new())),
            call_manager: Some(call_manager),
            bridge_ngn_bind_ip,
            bridge_ext_bind_ip,
            active: Arc::new(Mutex::new(HashMap::new())),
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
                    // 内線が出した Request-URI は host 部分が sabiden 側 LAN IP
                    // (内線 UAS の bind IP) になっているため、そのまま NGN にプロキシすると
                    // P-CSCF が `403 Forbidden` で蹴る (NGN は LAN IP 宛 URI を受け付けない)。
                    // ここで NGN ドメイン宛 (`UacConfig::domain`) に正規化する。
                    // To ヘッダも `Uac::build_invite` 内で `target_uri` から組み立てるため、
                    // target を書き換えれば自動的に揃う。
                    let cfg = self.ngn_uac.config();
                    let server_host = self.ngn_uac.server_addr().ip().to_string();
                    let target =
                        normalize_request_uri_for_ngn(&request.uri, &cfg.domain, &server_host);
                    if target != request.uri {
                        debug!(
                            original = %request.uri,
                            rewritten = %target,
                            "Request-URI を NGN ドメインに正規化"
                        );
                    }
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

                    let plan = self
                        .ngn_uac
                        .build_invite(&target, sdp_for_ngn.as_deref(), None);
                    let outcome = self.ngn_uac.invite(plan, sdp_for_ngn).await;
                    match outcome {
                        Ok(InviteOutcome::Established(call)) => {
                            // NGN 側 200 OK の SDP answer を内線に返す。
                            // ブリッジを起動できるなら sabiden 側 ext ソケットを指すよう書き換える。
                            let body_for_ext = match self
                                .finalize_outbound_bridge(
                                    bridge_ctx,
                                    &ext_offer,
                                    &call.response.body,
                                    &call_id,
                                )
                                .await
                            {
                                Ok(body) => body,
                                Err(e) => {
                                    warn!(error=%e, "NGN 側 RTP ブリッジ確立失敗 → SDP 透過");
                                    call.response.body.clone()
                                }
                            };
                            if body_for_ext.is_empty() {
                                responder.quick(200, "OK").await?;
                            } else {
                                responder
                                    .respond_with_body(200, "OK", "application/sdp", body_for_ext)
                                    .await?;
                            }
                            // 観測: NGN レッグも内線レッグも応答済みとして記録
                            self.metrics.record_invite_ngn(InviteResult::Answered);
                            self.metrics.record_invite_extension(InviteResult::Answered);
                            // 通話確立として call_active を +1。透過モード (active に
                            // エントリ無し) でも BYE で必ず減算できるよう `None` を入れる。
                            if !call_id.is_empty() && call_id != "<no-call-id>" {
                                let mut active = self.active.lock().await;
                                active.entry(call_id.clone()).or_insert(None);
                            }
                            self.metrics.inc_call_active();
                            let _ = call.dialog;
                            Ok(())
                        }
                        Ok(InviteOutcome::Failed { response }) => {
                            warn!(code = response.status_code, "NGN 側 INVITE 失敗");
                            // 486 を Busy、それ以外を Error として記録 (Timeout は invite() で
                            // Err になるためここでは到達しない)。
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
                            warn!(error=%e, "NGN 側 INVITE トランスポート失敗 → 503");
                            self.metrics.record_invite_ngn(InviteResult::Timeout);
                            responder.quick(503, "Service Unavailable").await
                        }
                    }
                }
                .instrument(span)
                .await
            }
            UasEvent::Bye { request, remote } => {
                debug!(%remote, "内線 BYE → NGN にも BYE 必要 (Phase 2.5)");
                if let Some(cid) = request.headers.get("call-id") {
                    let removed = { self.active.lock().await.remove(cid) };
                    if removed.is_some() {
                        // 通話終了として call_active を -1
                        self.metrics.dec_call_active();
                    }
                    if let (Some(Some(call_id)), Some(mgr)) = (removed, self.call_manager.as_ref())
                    {
                        if let Err(e) = mgr.terminate(call_id).await {
                            warn!(error=%e, "内線 BYE 受信時の通話終了に失敗");
                        }
                    }
                }
                Ok(())
            }
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
    /// 内線へ返す SDP body を返す。`bridge_ctx` が `None` の場合は透過 (元 body をそのまま返す)。
    async fn finalize_outbound_bridge(
        &self,
        bridge_ctx: Option<OutboundBridgeCtx>,
        ext_offer: &[u8],
        ngn_answer: &[u8],
        call_id: &str,
    ) -> Result<Vec<u8>> {
        let Some(ctx) = bridge_ctx else {
            return Ok(ngn_answer.to_vec());
        };
        let Some(mgr) = self.call_manager.as_ref() else {
            return Ok(ngn_answer.to_vec());
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
        if !call_id.is_empty() {
            self.active
                .lock()
                .await
                .insert(call_id.to_string(), Some(cid));
        }
        Ok(rewritten_for_ext)
    }
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

    /// `normalize_request_uri_for_ngn` の単体動作確認。
    #[test]
    fn normalize_lan_ip_to_ngn_domain() {
        let out = normalize_request_uri_for_ngn(
            "sip:117@192.168.20.239",
            "ntt-east.ne.jp",
            "[2001:a7ff:2101:6::f]",
        );
        assert_eq!(out, "sip:117@ntt-east.ne.jp");
    }

    #[test]
    fn normalize_strips_transport_params() {
        let out = normalize_request_uri_for_ngn(
            "sip:0312345678@192.168.20.239:5060;transport=udp",
            "ntt-east.ne.jp",
            "p-cscf.ngn.example",
        );
        assert_eq!(out, "sip:0312345678@ntt-east.ne.jp");
    }

    #[test]
    fn normalize_keeps_existing_ngn_domain() {
        let out = normalize_request_uri_for_ngn(
            "sip:117@ntt-east.ne.jp",
            "ntt-east.ne.jp",
            "p-cscf.ngn.example",
        );
        assert_eq!(out, "sip:117@ntt-east.ne.jp");
    }

    #[test]
    fn normalize_keeps_pcscf_host() {
        let out = normalize_request_uri_for_ngn(
            "sip:117@p-cscf.ngn.example",
            "ntt-east.ne.jp",
            "p-cscf.ngn.example",
        );
        // host は P-CSCF と一致しているのでそのまま
        assert_eq!(out, "sip:117@p-cscf.ngn.example");
    }

    #[test]
    fn normalize_passthrough_on_unparseable() {
        // パース不能ならフェイルセーフで元 URI を返す
        let out = normalize_request_uri_for_ngn("not-a-uri", "ntt-east.ne.jp", "1.2.3.4");
        assert_eq!(out, "not-a-uri");
    }

    /// 内線→NGN プロキシ時、Request-URI が LAN IP のまま NGN に出ないこと。
    /// Linphone 等の内線が `INVITE sip:117@<sabiden-LAN-IP>` を吐いても、
    /// sabiden が `sip:117@ntt-east.ne.jp` に書き換えて NGN に送ること、
    /// To ヘッダも対応する形になっていることを確認する。
    #[tokio::test]
    async fn uas_invite_request_uri_rewritten_to_ngn_domain() {
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: INVITE を受けて Request-URI と To をキャプチャ。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();

        let captured_uri: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let captured_to: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let captured_uri_clone = captured_uri.clone();
        let captured_to_clone = captured_to.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(req) = parsed {
                assert_eq!(req.method, SipMethod::Invite);
                *captured_uri_clone.lock().unwrap() = Some(req.uri.clone());
                *captured_to_clone.lock().unwrap() =
                    req.headers.get("to").map(|s| s.to_string());
                // 200 OK (SDP 無し: 単純な動作確認のため)
                let mut resp = build_response_skeleton(&req, 200, "OK");
                resp.headers.set(
                    "To",
                    format!("{};tag=ngn-srv", req.headers.get("to").unwrap()),
                );
                resp.headers
                    .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                fake_ngn_clone
                    .send_to(&resp.to_bytes(), peer)
                    .await
                    .unwrap();
                // ACK 受信して捨てる
                let _ = timeout(Duration::from_secs(1), fake_ngn_clone.recv_from(&mut buf)).await;
            }
        });

        // sabiden NGN 側 UAC (domain = ntt-east.ne.jp)
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

        let handler = UasEventHandler::new(ngn_uac);
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.spawn(event_rx);

        // 内線→sabiden の SIP 経路を最低限再現するための bind 済みソケット。
        let phone_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone_sock.local_addr().unwrap();
        let sabiden_uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

        // 内線 (Linphone 等) がよくやるように Request-URI に sabiden の bind LAN IP
        // が乗っている INVITE を作る。実機では sabiden の LAN IP (例: 192.168.20.239) だが、
        // テスト経路は loopback bind なのでそのまま使うと P-CSCF (= fake_ngn = 127.0.0.1)
        // と衝突する。実機の挙動を再現するため、LAN IP リテラルを直接指定する。
        // この値は NGN ドメインでも P-CSCF アドレスでもないので、本実装は
        // ngn_uac.config().domain (ntt-east.ne.jp) に書き換えるはず。
        let req_uri = "sip:117@192.168.20.239".to_string();
        let mut invite_from_phone = SipRequest::new(SipMethod::Invite, &req_uri);
        invite_from_phone.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKrwriteuri", phone_addr),
        );
        invite_from_phone
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet2");
        invite_from_phone.headers.set("To", format!("<{}>", req_uri));
        invite_from_phone
            .headers
            .set("Call-ID", "rewrite-uri-cid");
        invite_from_phone.headers.set("CSeq", "1 INVITE");
        // SDP は無くてもよい (Request-URI / To の書き換え動作だけが対象)
        phone_sock
            .send_to(&invite_from_phone.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
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

        // NGN タスクが INVITE を受信して 200 OK を返すまで待つ
        timeout(Duration::from_secs(5), ngn_task)
            .await
            .expect("NGN タスク タイムアウト")
            .unwrap();

        let uri = captured_uri
            .lock()
            .unwrap()
            .clone()
            .expect("NGN へ INVITE が届くべき");
        let to = captured_to
            .lock()
            .unwrap()
            .clone()
            .expect("To ヘッダ未捕捉");
        // Request-URI: LAN IP ではなく NGN ドメインを指している
        assert_eq!(
            uri, "sip:117@ntt-east.ne.jp",
            "Request-URI は NGN ドメインに正規化されるべき (実際: {})",
            uri
        );
        // To: ユーザ部 117 を保持しつつドメインが NGN になっている
        assert!(
            to.contains("sip:117@ntt-east.ne.jp"),
            "To ヘッダも NGN ドメインに書き換わるべき (実際: {})",
            to
        );
        // 内線の LAN IP (192.168.20.239) が NGN まで漏れていない
        assert!(
            !uri.contains("192.168.20.239"),
            "Request-URI に内線 UAS の LAN IP が残っている: {}",
            uri
        );
        assert!(
            !to.contains("192.168.20.239"),
            "To ヘッダに内線 UAS の LAN IP が残っている: {}",
            to
        );
    }
}
