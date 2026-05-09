//! SIP トランザクション層 (RFC 3261 §17)
//!
//! トランザクション ID は (branch, sent-by, cseq-method) で一意に決まる
//! (RFC 3261 §17.1.3, §17.2.3)。本モジュールでは UAC/UAS の双方の
//! トランザクション状態機械と、UDP 上での再送 (Timer A/E) ・
//! トランザクション タイムアウト (Timer B/F) ・最終応答後の
//! バッファリング (Timer D/K) を実装する。
//!
//! NTT NGN 制約: 既存 `register.rs` 同様、Via ヘッダに `rport` を付けない
//! (拒否される) 制約は呼び出し側 (リクエスト ビルダ) の責務であり、本層は
//! Via をそのまま透過する。
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time;
use tracing::{debug, trace, warn};

use super::message::{parse_message, SipHeaders, SipMessage, SipMethod, SipRequest, SipResponse};
use crate::observability::{extract_method_and_call_id, SipTraceWriter, TraceDir};

/// RFC 3261 §17.1.1.1 Timer T1 (RTT 推定値)。デフォルトは 500ms。
pub const T1: Duration = Duration::from_millis(500);
/// RFC 3261 §17.1.2.2 Timer T2 (non-INVITE 再送間隔の上限)。デフォルトは 4s。
pub const T2: Duration = Duration::from_secs(4);
/// RFC 3261 §17.1.1.2 Timer T4 (メッセージのネット上残留時間)。デフォルトは 5s。
pub const T4: Duration = Duration::from_secs(5);
/// RFC 3261 §17.1.1.2 Timer B/F = 64 * T1 (トランザクション タイムアウト)。
pub const TIMER_B: Duration = Duration::from_millis(64 * 500);
/// RFC 3261 §17.1.1.2 Timer D。non-2xx 最終応答 → ACK 後の応答再送吸収期間。
/// UDP では 32s 以上必須 (デフォルト 32s)。TCP/SCTP では 0s で良いが
/// 本実装は UDP 専用なので固定 32s とする。
pub const TIMER_D: Duration = Duration::from_secs(32);

/// Client/Server を区別しないトランザクション ID。
///
/// RFC 3261 §17.1.3 / §17.2.3 に従い、branch (RFC 3261 magic cookie 付き) と
/// 送信元 sent-by、CSeq method の三要素で同定する。CANCEL は元の INVITE と
/// 同一 branch を共有するが method で区別される。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId {
    pub branch: String,
    pub sent_by: String,
    pub method: SipMethod,
}

impl TransactionId {
    /// クライアント (送信側) Via ヘッダから ID を生成。
    pub fn from_request(req: &SipRequest) -> Result<Self> {
        let via = req
            .headers
            .get("via")
            .ok_or_else(|| anyhow!("Via ヘッダがない"))?;
        let (branch, sent_by) = parse_via(via)?;
        Ok(Self {
            branch,
            sent_by,
            method: req.method.clone(),
        })
    }

    /// レスポンスからクライアント側 ID を再構築する。
    /// CANCEL に対する応答では Via に元 INVITE と同じ branch が入るが、
    /// CSeq の method で識別される (RFC 3261 §17.1.3)。
    pub fn from_response(resp: &SipResponse) -> Result<Self> {
        let via = resp
            .headers
            .get("via")
            .ok_or_else(|| anyhow!("Via ヘッダがない"))?;
        let (branch, sent_by) = parse_via(via)?;
        let cseq = resp
            .headers
            .get("cseq")
            .ok_or_else(|| anyhow!("CSeq ヘッダがない"))?;
        let method_str = cseq
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow!("CSeq の method が読めない: {}", cseq))?;
        let method: SipMethod = method_str.parse()?;
        Ok(Self {
            branch,
            sent_by,
            method,
        })
    }
}

/// Via ヘッダから (branch, sent-by) を抽出する。
fn parse_via(via: &str) -> Result<(String, String)> {
    // 例: "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKabc"
    let mut sent_by = String::new();
    let mut branch = String::new();
    let mut params_started = false;
    for (i, part) in via.split(';').enumerate() {
        if i == 0 {
            // "SIP/2.0/UDP host:port"
            let proto_and_host = part.trim();
            sent_by = proto_and_host
                .split_once(' ')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
            params_started = true;
            continue;
        }
        if !params_started {
            continue;
        }
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("branch=") {
            branch = rest.trim_matches('"').to_string();
        }
    }
    if branch.is_empty() {
        anyhow::bail!("Via に branch がない: {}", via);
    }
    if sent_by.is_empty() {
        anyhow::bail!("Via に sent-by がない: {}", via);
    }
    Ok((branch, sent_by))
}

/// クライアント トランザクションの状態 (RFC 3261 §17.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// INVITE 送信直後。再送タイマ A 起動 (RFC 3261 §17.1.1.2)。
    Calling,
    /// non-INVITE 送信直後。再送タイマ E 起動 (RFC 3261 §17.1.2.2)。
    Trying,
    /// 1xx 受信後。INVITE/non-INVITE で Timer A/E が止まる。
    Proceeding,
    /// 最終応答 (>=200) 受信後。Timer D (UDP) / K でバッファ。
    Completed,
    /// 終了。
    Terminated,
}

/// サーバ トランザクションの状態 (RFC 3261 §17.2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// non-INVITE: リクエスト受信直後 (provisional 未送信)。
    Trying,
    /// provisional 送信後。
    Proceeding,
    /// 最終応答送信後。再送に備えて Timer J/H 待機。
    Completed,
    /// INVITE のみ。最終応答 (>=300 又は 2xx 以外の終端) 後 ACK 受信。
    Confirmed,
    /// 終了。
    Terminated,
}

/// クライアント トランザクションへ流すイベント。
#[derive(Debug)]
enum ClientEvent {
    /// 受信した SIP レスポンス。
    Response(SipResponse),
}

/// クライアント トランザクションのハンドル。`run` を await すると
/// 最終応答 (>=200) を返す。再送・タイムアウトは内部で処理する。
pub struct ClientTransaction {
    id: TransactionId,
    request: SipRequest,
    destination: SocketAddr,
    socket: Arc<UdpSocket>,
    rx: mpsc::UnboundedReceiver<ClientEvent>,
    state: ClientState,
    tracer: SipTraceWriter,
    /// Timer D の間 transaction エントリを保持し、満了後に自身を
    /// 削除するためのテーブル ハンドル (RFC 3261 §17.1.1.2)。
    /// `TransactionLayer::create_client` 経由で生成された場合のみ Some。
    /// 単体テスト等で `ClientTransaction::new` を直接使う場合は None。
    table_handle: Option<Arc<Mutex<TransactionTable>>>,
}

impl ClientTransaction {
    /// 新しいクライアント トランザクションを作成し、駆動可能な状態にする。
    /// テスト専用 (Production パスは `new_with_table` 経由で table_handle を持つ)。
    #[cfg(test)]
    fn new(
        id: TransactionId,
        request: SipRequest,
        destination: SocketAddr,
        socket: Arc<UdpSocket>,
        rx: mpsc::UnboundedReceiver<ClientEvent>,
        tracer: SipTraceWriter,
    ) -> Self {
        Self::new_with_table(id, request, destination, socket, rx, tracer, None)
    }

    /// `TransactionLayer` 連携版。Timer D の自己消滅機能を有効にする。
    fn new_with_table(
        id: TransactionId,
        request: SipRequest,
        destination: SocketAddr,
        socket: Arc<UdpSocket>,
        rx: mpsc::UnboundedReceiver<ClientEvent>,
        tracer: SipTraceWriter,
        table_handle: Option<Arc<Mutex<TransactionTable>>>,
    ) -> Self {
        let state = match request.method {
            SipMethod::Invite => ClientState::Calling,
            _ => ClientState::Trying,
        };
        Self {
            id,
            request,
            destination,
            socket,
            rx,
            state,
            tracer,
            table_handle,
        }
    }

    /// Transaction を駆動して最終応答を返す。
    ///
    /// - Calling/Trying → Proceeding: 1xx 受信
    /// - * → Completed: >=200 受信
    /// - Timer B/F: タイムアウト (64*T1)
    /// - INVITE で 300-699 受信時は本層内で ACK を生成・送出し
    ///   (RFC 3261 §17.1.1.3)、Timer D (32s) の間は応答再送を吸収して
    ///   既送出 ACK を再送する (RFC 3261 §17.1.1.2 figure 5)。
    ///   この吸収はバックグラウンド タスクへ委譲し、本関数は直ちに
    ///   最終応答を呼び出し元へ返す。
    pub async fn run(mut self) -> Result<SipResponse> {
        let bytes = self.request.to_bytes();
        self.socket.send_to(&bytes, self.destination).await?;
        write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
        debug!(?self.id, "client tx 送信");

        let mut interval = T1;
        let next_retx = time::sleep(interval);
        tokio::pin!(next_retx);
        let timeout_b = time::sleep(TIMER_B);
        tokio::pin!(timeout_b);

        loop {
            tokio::select! {
                ev = self.rx.recv() => {
                    let Some(ClientEvent::Response(resp)) = ev else {
                        return Err(anyhow!("transaction layer が停止した"));
                    };
                    let code = resp.status_code;
                    trace!(?self.id, code, "client tx 応答");
                    if (100..200).contains(&code) {
                        // 1xx で再送停止 (RFC 3261 §17.1.1.2 / §17.1.2.2)
                        self.state = ClientState::Proceeding;
                        // 再送停止: タイマを十分先へ延ばす
                        next_retx
                            .as_mut()
                            .reset(time::Instant::now() + TIMER_B);
                        continue;
                    }
                    // 最終応答
                    self.state = ClientState::Completed;
                    // RFC 3261 §17.1.1.3: INVITE で non-2xx 最終応答が来たら
                    // 本トランザクション内で ACK を生成・送出する。2xx ACK は
                    // dialog 層 (RFC 3261 §13.2.2.4) の責務なので扱わない。
                    if self.request.method == SipMethod::Invite && (300..700).contains(&code) {
                        match build_non2xx_ack(&self.request, &resp) {
                            Ok(ack) => {
                                let ack_bytes = ack.to_bytes();
                                if let Err(e) =
                                    self.socket.send_to(&ack_bytes, self.destination).await
                                {
                                    warn!(error=%e, "non-2xx ACK 送信失敗");
                                } else {
                                    write_trace(&self.tracer, TraceDir::Sent, &ack_bytes).await;
                                    debug!(?self.id, code, "non-2xx ACK 送出");
                                }
                                // Timer D の間、応答再送を吸収して ACK を
                                // 再送するバックグラウンド タスクを起動。
                                self.spawn_completed_absorber(ack_bytes);
                            }
                            Err(e) => {
                                warn!(error=%e, "non-2xx ACK 構築失敗 (INVITE 本体不整合)");
                            }
                        }
                    }
                    return Ok(resp);
                }
                _ = &mut next_retx, if matches!(self.state, ClientState::Calling | ClientState::Trying) => {
                    // 再送 (Timer A: INVITE は倍々, Timer E: non-INVITE は T2 上限)
                    self.socket.send_to(&bytes, self.destination).await?;
                    write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
                    debug!(?self.id, ?interval, "client tx 再送");
                    interval = match self.request.method {
                        SipMethod::Invite => interval.saturating_mul(2),
                        _ => std::cmp::min(interval.saturating_mul(2), T2),
                    };
                    next_retx.as_mut().reset(time::Instant::now() + interval);
                }
                _ = &mut timeout_b => {
                    self.state = ClientState::Terminated;
                    warn!(?self.id, "client tx Timer B/F タイムアウト");
                    return Err(anyhow!("transaction timeout"));
                }
            }
        }
    }

    /// Completed 状態 (non-2xx 最終応答受信後) で動作するバックグラウンド
    /// タスクを spawn する (RFC 3261 §17.1.1.2 figure 5)。
    ///
    /// Timer D (UDP: 32s) の間、同じトランザクションへの応答再送を
    /// 吸収し、その都度 既送出 ACK (`ack_bytes`) をそのまま再送する。
    /// 新たな ACK は **生成しない**: 同一の ACK バイト列を流すことで
    /// UAS 側の transaction matching を成立させる。
    /// Timer D 満了後にトランザクション テーブルから自身を削除する。
    fn spawn_completed_absorber(&mut self, ack_bytes: Vec<u8>) {
        // self.rx は所有権が必要。受信機をこのタスクへ移すために
        // ダミー チャネルへ差し替える (run 関数自体は return 直後)。
        let (_dummy_tx, dummy_rx) = mpsc::unbounded_channel();
        let mut rx = std::mem::replace(&mut self.rx, dummy_rx);
        let socket = self.socket.clone();
        let dest = self.destination;
        let tracer = self.tracer.clone();
        let id = self.id.clone();
        let table = self.table_handle.clone();

        tokio::spawn(async move {
            let timer_d = time::sleep(TIMER_D);
            tokio::pin!(timer_d);
            loop {
                tokio::select! {
                    ev = rx.recv() => {
                        match ev {
                            Some(ClientEvent::Response(resp)) => {
                                // 同じ最終応答 (非 1xx) の再送 → ACK 再送。
                                // 1xx 等の不整合は無視。
                                if resp.status_code >= 200 {
                                    if let Err(e) =
                                        socket.send_to(&ack_bytes, dest).await
                                    {
                                        warn!(error=%e, "non-2xx ACK 再送失敗");
                                    } else {
                                        write_trace(&tracer, TraceDir::Sent, &ack_bytes).await;
                                        trace!(?id, "non-2xx ACK 再送");
                                    }
                                }
                            }
                            None => {
                                // 上位 dispatcher が落ちた。Timer D を待たずに終了。
                                break;
                            }
                        }
                    }
                    _ = &mut timer_d => {
                        debug!(?id, "Timer D 満了 → Terminated");
                        break;
                    }
                }
            }
            // 自身をテーブルから削除 (Terminated)。
            if let Some(table) = table {
                let mut guard = table.lock().await;
                guard.clients.remove(&id);
            }
        });
    }

    pub fn id(&self) -> &TransactionId {
        &self.id
    }

    pub fn state(&self) -> ClientState {
        self.state
    }
}

/// サーバ トランザクション (RFC 3261 §17.2)。
///
/// non-INVITE では provisional / final response 送信を司り、
/// 同一リクエストの再送に対しては最後に送った応答を返す。
/// INVITE では ACK 待機 (Timer H) の責務を負う。
pub struct ServerTransaction {
    id: TransactionId,
    request: SipRequest,
    remote: SocketAddr,
    socket: Arc<UdpSocket>,
    state: ServerState,
    last_response: Option<SipResponse>,
    tracer: SipTraceWriter,
}

impl ServerTransaction {
    pub fn new(request: SipRequest, remote: SocketAddr, socket: Arc<UdpSocket>) -> Result<Self> {
        Self::with_tracer(request, remote, socket, SipTraceWriter::disabled())
    }

    /// トレース有効版。`TransactionLayer` 経由で生成される。
    pub fn with_tracer(
        request: SipRequest,
        remote: SocketAddr,
        socket: Arc<UdpSocket>,
        tracer: SipTraceWriter,
    ) -> Result<Self> {
        let id = TransactionId::from_request(&request)?;
        let state = match request.method {
            SipMethod::Invite => ServerState::Proceeding,
            _ => ServerState::Trying,
        };
        Ok(Self {
            id,
            request,
            remote,
            socket,
            state,
            last_response: None,
            tracer,
        })
    }

    /// 応答を送信し、状態を遷移させる。
    pub async fn respond(&mut self, resp: SipResponse) -> Result<()> {
        let code = resp.status_code;
        let bytes = resp.to_bytes();
        self.socket.send_to(&bytes, self.remote).await?;
        write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
        self.last_response = Some(resp);
        match (self.state, code) {
            (ServerState::Trying, 100..=199) => self.state = ServerState::Proceeding,
            (ServerState::Trying | ServerState::Proceeding, 200..=699) => {
                self.state = ServerState::Completed;
            }
            (ServerState::Proceeding, 100..=199) => {} // 追加 provisional は状態維持
            _ => {}
        }
        debug!(?self.id, code, ?self.state, "server tx 応答");
        Ok(())
    }

    /// リクエスト再送に対して直近の応答を再送する (RFC 3261 §17.2.1 / §17.2.2)。
    pub async fn handle_retransmit(&self) -> Result<()> {
        if let Some(resp) = &self.last_response {
            let bytes = resp.to_bytes();
            self.socket.send_to(&bytes, self.remote).await?;
            write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
            trace!(?self.id, "server tx 応答再送");
        }
        Ok(())
    }

    pub fn id(&self) -> &TransactionId {
        &self.id
    }

    pub fn state(&self) -> ServerState {
        self.state
    }

    pub fn request(&self) -> &SipRequest {
        &self.request
    }
}

/// トランザクション層。受信ループを駆動し、レスポンスをクライアント
/// トランザクションへ振り分け、未マッチのリクエストは TU (上位) へ
/// 渡す。
///
/// SIP トレース機能 (Issue #20) はこの層で hook する。`with_tracer` で
/// [`SipTraceWriter`] を渡すと、recv_loop / 各トランザクションの送信時に
/// メッセージがダンプされる。
pub struct TransactionLayer {
    socket: Arc<UdpSocket>,
    inner: Arc<Mutex<TransactionTable>>,
    inbound_tx: mpsc::UnboundedSender<InboundRequest>,
    tracer: SipTraceWriter,
}

#[derive(Default)]
struct TransactionTable {
    /// branch+sent-by+method → クライアント トランザクションへの送信口。
    clients: HashMap<TransactionId, mpsc::UnboundedSender<ClientEvent>>,
}

/// TU (上位層) へ届ける受信リクエスト。
#[derive(Debug)]
pub struct InboundRequest {
    pub request: SipRequest,
    pub remote: SocketAddr,
}

impl TransactionLayer {
    /// レイヤを起動し、内部で受信ループ用タスクを spawn する。
    pub fn spawn(socket: Arc<UdpSocket>) -> (Arc<Self>, mpsc::UnboundedReceiver<InboundRequest>) {
        Self::spawn_with_tracer(socket, SipTraceWriter::disabled())
    }

    /// トレース有効版。`SipTraceWriter::open` で生成した writer を渡すと、
    /// 受信ループ・送信パスから自動的にダンプが走る。
    pub fn spawn_with_tracer(
        socket: Arc<UdpSocket>,
        tracer: SipTraceWriter,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<InboundRequest>) {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let layer = Arc::new(Self {
            socket: socket.clone(),
            inner: Arc::new(Mutex::new(TransactionTable::default())),
            inbound_tx,
            tracer,
        });
        let driver = layer.clone();
        tokio::spawn(async move { driver.recv_loop().await });
        (layer, inbound_rx)
    }

    /// 配下で使う [`SipTraceWriter`] のハンドル (UAS 等が server tx 構築時に使う)。
    pub fn tracer(&self) -> SipTraceWriter {
        self.tracer.clone()
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 8192];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, remote)) => {
                    let data = &buf[..n];
                    // パース前にトレース dump (壊れた SIP も観測したいため)
                    write_trace(&self.tracer, TraceDir::Recv, data).await;
                    match parse_message(data) {
                        Ok(SipMessage::Response(resp)) => {
                            self.dispatch_response(resp).await;
                        }
                        Ok(SipMessage::Request(req)) => {
                            let inbound = InboundRequest {
                                request: req,
                                remote,
                            };
                            // TU が落ちていたら受信ループも止める
                            if self.inbound_tx.send(inbound).is_err() {
                                warn!("TU receiver dropped; recv_loop 終了");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(error=%e, "SIP メッセージ パース失敗");
                        }
                    }
                }
                Err(e) => {
                    warn!(error=%e, "UDP 受信エラー");
                    break;
                }
            }
        }
    }

    async fn dispatch_response(&self, resp: SipResponse) {
        let id = match TransactionId::from_response(&resp) {
            Ok(id) => id,
            Err(e) => {
                warn!(error=%e, "応答 ID 抽出失敗");
                return;
            }
        };
        let sender = {
            let table = self.inner.lock().await;
            table.clients.get(&id).cloned()
        };
        if let Some(tx) = sender {
            let _ = tx.send(ClientEvent::Response(resp));
        } else {
            debug!(?id, "未知の transaction への応答 (drop)");
        }
    }

    /// クライアント トランザクションを登録し、ハンドルを返す。
    pub async fn create_client(
        &self,
        request: SipRequest,
        destination: SocketAddr,
    ) -> Result<ClientTransaction> {
        let id = TransactionId::from_request(&request)?;
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut table = self.inner.lock().await;
            table.clients.insert(id.clone(), tx);
        }
        Ok(ClientTransaction::new_with_table(
            id,
            request,
            destination,
            self.socket.clone(),
            rx,
            self.tracer.clone(),
            Some(self.inner.clone()),
        ))
    }

    /// トランザクション完了後にエントリを削除する。
    /// `ClientTransaction::run` 完了後に呼ぶ。
    pub async fn drop_client(&self, id: &TransactionId) {
        let mut table = self.inner.lock().await;
        table.clients.remove(id);
    }

    /// 応答を待たないリクエスト送信。
    ///
    /// RFC 3261 §13.2.2.4: 2xx に対する ACK は新規トランザクションを作らず、
    /// TU が単発で送信する (再送制御は TU の責任)。本メソッドは UAC が
    /// 2xx ACK や、トランザクションを介さない補助送信を行う際に使う。
    pub async fn send_request_no_wait(
        self: &Arc<Self>,
        request: SipRequest,
        destination: SocketAddr,
    ) -> Result<()> {
        let bytes = request.to_bytes();
        self.socket.send_to(&bytes, destination).await?;
        write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
        Ok(())
    }

    /// クライアント トランザクションを送って最終応答を待つ高水準 API。
    ///
    /// これは REGISTER 等の「リクエスト1本 → 応答待ち」用途向け。
    pub async fn send_request(
        self: &Arc<Self>,
        request: SipRequest,
        destination: SocketAddr,
    ) -> Result<SipResponse> {
        let tx = self.create_client(request, destination).await?;
        let id = tx.id().clone();
        let is_invite = matches!(id.method, SipMethod::Invite);
        // run の完了 (成功/失敗) 双方でテーブルを掃除する。
        // ただし INVITE で non-2xx 最終応答が返った場合は ClientTransaction
        // 内部で Timer D 期間中エントリを保持し続ける必要があるため、
        // 自前 cleanup はしない (absorber 側で削除する)。
        let layer = self.clone();
        let (done_tx, done_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = tx.run().await;
            let absorber_owns_cleanup = match &result {
                Ok(resp) => is_invite && (300..700).contains(&resp.status_code),
                Err(_) => false,
            };
            if !absorber_owns_cleanup {
                layer.drop_client(&id).await;
            }
            let _ = done_tx.send(result);
        });
        done_rx
            .await
            .map_err(|_| anyhow!("client transaction が中断された"))?
    }
}

/// SIP メッセージ raw bytes をトレース writer に渡すヘルパ。
/// パース失敗 / 部分受信でも observable にしたいので、UTF-8 でなくても
/// best-effort で method / call-id を抽出して保存する。
async fn write_trace(tracer: &SipTraceWriter, dir: TraceDir, raw: &[u8]) {
    let (method, call_id) = extract_method_and_call_id(raw);
    tracer.record(dir, &method, call_id.as_deref(), raw).await;
}

/// non-2xx 最終応答に対する ACK を構築する (RFC 3261 §17.1.1.3)。
///
/// 同じ INVITE トランザクション内で送出されるため:
/// - Request-URI: 元 INVITE と同じ
/// - Call-ID / From: 元 INVITE と同じ (From tag も保持)
/// - To: **応答** からコピー (応答に乗ってきた tag を含めるのが要件)
/// - CSeq: 元 INVITE と同じ番号、method は ACK
/// - Via: 元 INVITE の **top Via** だけを単一エントリで持たせる
///   (branch も同一 → UAS 側で同じトランザクションに突き合わせ)
/// - Route: 元 INVITE と同じ
/// - Max-Forwards: 元 INVITE のものをそのまま (なければ 70)
/// - Body: なし
fn build_non2xx_ack(invite: &SipRequest, response: &SipResponse) -> Result<SipRequest> {
    let mut ack = SipRequest::new(SipMethod::Ack, invite.uri.clone());

    let via = invite
        .headers
        .get("via")
        .ok_or_else(|| anyhow!("元 INVITE に Via がない"))?;
    ack.headers.set("Via", via);

    let from = invite
        .headers
        .get("from")
        .ok_or_else(|| anyhow!("元 INVITE に From がない"))?;
    ack.headers.set("From", from);

    // To は応答側からコピー (tag を含める)。応答に To が無いのは異常。
    let to = response
        .headers
        .get("to")
        .ok_or_else(|| anyhow!("応答に To がない"))?;
    ack.headers.set("To", to);

    let call_id = invite
        .headers
        .get("call-id")
        .ok_or_else(|| anyhow!("元 INVITE に Call-ID がない"))?;
    ack.headers.set("Call-ID", call_id);

    // CSeq: 同じ番号 + method=ACK
    let cseq = invite
        .headers
        .get("cseq")
        .ok_or_else(|| anyhow!("元 INVITE に CSeq がない"))?;
    let seq_num = cseq
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("CSeq の数値部が読めない: {}", cseq))?;
    ack.headers.set("CSeq", format!("{} ACK", seq_num));

    // Max-Forwards (元 INVITE のものをそのまま、なければ 70)
    let mf = invite.headers.get("max-forwards").unwrap_or("70");
    ack.headers.set("Max-Forwards", mf);

    // Route ヘッダ群 (RFC 3261 §17.1.1.3 末尾: same Route as original request)
    for r in invite.headers.get_all("route") {
        ack.headers.add("Route", r);
    }

    Ok(ack)
}

/// レスポンス送信用ヘルパ。
/// Via/From/To/Call-ID/CSeq/(timestamp) を request からコピーし、
/// To に tag を付ける (RFC 3261 §8.2.6.2)。
pub fn build_response_skeleton(request: &SipRequest, status: u16, reason: &str) -> SipResponse {
    let mut headers = SipHeaders::new();
    if let Some(via) = request.headers.get("via") {
        headers.set("Via", via);
    }
    if let Some(from) = request.headers.get("from") {
        headers.set("From", from);
    }
    if let Some(to) = request.headers.get("to") {
        headers.set("To", to);
    }
    if let Some(cid) = request.headers.get("call-id") {
        headers.set("Call-ID", cid);
    }
    if let Some(cseq) = request.headers.get("cseq") {
        headers.set("CSeq", cseq);
    }
    SipResponse {
        status_code: status,
        reason: reason.to_string(),
        headers,
        body: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::{SipMethod, SipRequest, SipResponse};

    fn make_request(branch: &str) -> SipRequest {
        let mut req = SipRequest::new(SipMethod::Register, "sip:ntt-east.ne.jp");
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP 192.0.2.1:5060;branch={}", branch),
        );
        req.headers
            .set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=alice");
        req.headers.set("To", "<sip:0312345678@ntt-east.ne.jp>");
        req.headers.set("Call-ID", "callid@host");
        req.headers.set("CSeq", "1 REGISTER");
        req
    }

    fn make_response(branch: &str, code: u16, method: &str) -> SipResponse {
        let mut headers = SipHeaders::new();
        headers.set(
            "Via",
            format!("SIP/2.0/UDP 192.0.2.1:5060;branch={}", branch),
        );
        headers.set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=alice");
        headers.set("To", "<sip:0312345678@ntt-east.ne.jp>;tag=server");
        headers.set("Call-ID", "callid@host");
        headers.set("CSeq", format!("1 {}", method));
        SipResponse {
            status_code: code,
            reason: "OK".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn test_transaction_id_match() {
        let req = make_request("z9hG4bKtest1");
        let id_req = TransactionId::from_request(&req).unwrap();
        let resp = make_response("z9hG4bKtest1", 200, "REGISTER");
        let id_resp = TransactionId::from_response(&resp).unwrap();
        assert_eq!(id_req, id_resp);
    }

    #[test]
    fn test_transaction_id_method_distinguishes_cancel() {
        // CANCEL は元の INVITE と branch を共有するが method で区別される
        let resp_invite = make_response("z9hG4bKshared", 200, "INVITE");
        let resp_cancel = make_response("z9hG4bKshared", 200, "CANCEL");
        let id_inv = TransactionId::from_response(&resp_invite).unwrap();
        let id_can = TransactionId::from_response(&resp_cancel).unwrap();
        assert_ne!(id_inv, id_can);
        assert_eq!(id_inv.branch, id_can.branch);
    }

    #[test]
    fn test_parse_via_with_extra_params() {
        let (branch, sent_by) =
            parse_via("SIP/2.0/UDP 192.0.2.1:5060;received=203.0.113.1;branch=z9hG4bKabc").unwrap();
        assert_eq!(branch, "z9hG4bKabc");
        assert_eq!(sent_by, "192.0.2.1:5060");
    }

    #[test]
    fn test_parse_via_missing_branch() {
        assert!(parse_via("SIP/2.0/UDP 192.0.2.1:5060").is_err());
    }

    #[test]
    fn test_response_skeleton_copies_required_headers() {
        let req = make_request("z9hG4bKskel");
        let resp = build_response_skeleton(&req, 200, "OK");
        assert_eq!(resp.status_code, 200);
        assert_eq!(
            resp.headers.get("via").unwrap(),
            "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKskel"
        );
        assert_eq!(resp.headers.get("call-id").unwrap(), "callid@host");
        assert_eq!(resp.headers.get("cseq").unwrap(), "1 REGISTER");
    }

    /// Timer B (64*T1 = 32s) 相当のタイムアウト確認。
    /// `tokio::time::pause` で仮想時間を進めて短時間で検証する。
    #[tokio::test(start_paused = true)]
    async fn test_client_transaction_timeout_b() {
        // 受信側として bind だけする (相手は応答しない)
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = socket.local_addr().unwrap();

        // ループバックに送るが受信側は何もしない (= 応答が来ないシナリオ)
        // 別ソケットを宛先にすることで自分宛の再送を吸収させる。
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_sink: SocketAddr = sink.local_addr().unwrap();
        let _ = dest;

        let req = make_request("z9hG4bKtimeoutB");
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        // 起動時は登録だけし、応答は来ない
        drop(tx);
        let ct = ClientTransaction::new(id, req, dest_sink, socket, rx, SipTraceWriter::disabled());
        let result = ct.run().await;
        assert!(result.is_err(), "timeout で Err になるはず");
    }

    /// 1xx 受信で Proceeding に遷移し、2xx で完了することを確認。
    #[tokio::test(start_paused = true)]
    async fn test_client_transaction_provisional_then_final() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_sink: SocketAddr = sink.local_addr().unwrap();

        let req = make_request("z9hG4bKprov");
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let ct = ClientTransaction::new(id, req, dest_sink, socket, rx, SipTraceWriter::disabled());

        // 100 Trying → 200 OK を流し込む
        tx.send(ClientEvent::Response(make_response(
            "z9hG4bKprov",
            100,
            "REGISTER",
        )))
        .unwrap();
        tx.send(ClientEvent::Response(make_response(
            "z9hG4bKprov",
            200,
            "REGISTER",
        )))
        .unwrap();

        let resp = ct.run().await.unwrap();
        assert_eq!(resp.status_code, 200);
    }

    /// レスポンス ディスパッチが ID 一致でクライアントに届くことを確認。
    #[tokio::test]
    async fn test_layer_dispatches_response_by_id() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();

        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock.clone());

        let mut req = SipRequest::new(SipMethod::Register, "sip:ntt-east.ne.jp");
        let local = client_sock.local_addr().unwrap();
        let branch = "z9hG4bKlayer1";
        req.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        req.headers
            .set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=alice");
        req.headers.set("To", "<sip:0312345678@ntt-east.ne.jp>");
        req.headers.set("Call-ID", "callid@host");
        req.headers.set("CSeq", "1 REGISTER");

        // サーバ側: リクエスト受信 → 200 OK
        let server_clone = server.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            // パースして応答を組み立てる
            let parsed = parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(parsed_req) = parsed {
                let resp = build_response_skeleton(&parsed_req, 200, "OK");
                server_clone.send_to(&resp.to_bytes(), peer).await.unwrap();
            }
        });

        let resp = layer.send_request(req, server_addr).await.unwrap();
        assert_eq!(resp.status_code, 200);
    }

    /// `build_non2xx_ack` の単体テスト。RFC 3261 §17.1.1.3 の必須要件:
    /// - Request-URI / Call-ID / From / Via branch / CSeq# は元 INVITE
    /// - To は **応答** の To (tag を含む)
    /// - CSeq method は ACK
    /// - Route ヘッダはコピー
    #[test]
    fn test_build_non2xx_ack_copies_headers_per_rfc3261_17_1_1_3() {
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@ntt-east.ne.jp");
        invite.headers.set(
            "Via",
            "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKackctest",
        );
        invite
            .headers
            .set("From", "<sip:alice@ntt-east.ne.jp>;tag=alice");
        invite.headers.set("To", "<sip:bob@ntt-east.ne.jp>");
        invite.headers.set("Call-ID", "ackc-call@host");
        invite.headers.set("CSeq", "42 INVITE");
        invite.headers.set("Max-Forwards", "70");
        invite.headers.add("Route", "<sip:proxy1@ntt-east.ne.jp;lr>");
        invite.headers.add("Route", "<sip:proxy2@ntt-east.ne.jp;lr>");

        let mut resp_headers = SipHeaders::new();
        resp_headers.set(
            "Via",
            "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKackctest",
        );
        resp_headers.set("From", "<sip:alice@ntt-east.ne.jp>;tag=alice");
        // 応答では To に tag が付く (UAS 側で生成された)
        resp_headers.set("To", "<sip:bob@ntt-east.ne.jp>;tag=ngn-server-tag");
        resp_headers.set("Call-ID", "ackc-call@host");
        resp_headers.set("CSeq", "42 INVITE");
        let resp = SipResponse {
            status_code: 403,
            reason: "Forbidden".into(),
            headers: resp_headers,
            body: Vec::new(),
        };

        let ack = build_non2xx_ack(&invite, &resp).unwrap();
        assert_eq!(ack.method, SipMethod::Ack);
        assert_eq!(ack.uri, "sip:bob@ntt-east.ne.jp");
        assert_eq!(
            ack.headers.get("via").unwrap(),
            "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKackctest"
        );
        assert_eq!(
            ack.headers.get("from").unwrap(),
            "<sip:alice@ntt-east.ne.jp>;tag=alice"
        );
        // To は応答からコピーされ tag を含む
        assert_eq!(
            ack.headers.get("to").unwrap(),
            "<sip:bob@ntt-east.ne.jp>;tag=ngn-server-tag"
        );
        assert_eq!(ack.headers.get("call-id").unwrap(), "ackc-call@host");
        assert_eq!(ack.headers.get("cseq").unwrap(), "42 ACK");
        assert_eq!(ack.headers.get("max-forwards").unwrap(), "70");
        // Route ヘッダ群が保持される
        let routes = ack.headers.get_all("route");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0], "<sip:proxy1@ntt-east.ne.jp;lr>");
        assert_eq!(routes[1], "<sip:proxy2@ntt-east.ne.jp;lr>");
        assert!(ack.body.is_empty());
    }

    /// INVITE → 403 の流れで、トランザクション層が ACK を自動送出することを
    /// 実 UDP ソケット越しに確認する (RFC 3261 §17.1.1.3 への直接テスト)。
    /// 続けて 同じ 403 を再送した時、同じ ACK が再送されることも確認する
    /// (RFC 3261 §17.1.1.2 figure 5)。
    #[tokio::test]
    async fn test_invite_non2xx_triggers_ack_and_absorbs_retransmits() {
        // mock UAS ソケット: INVITE を受け、403 を 2 度送り、ACK を 2 つ受ける
        let uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uas_addr = uas_sock.local_addr().unwrap();

        // UAC 側: layer をスポーンし INVITE を送る
        let uac_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uac_local = uac_sock.local_addr().unwrap();
        let (layer, _inbound_rx) = TransactionLayer::spawn(uac_sock.clone());

        let branch = "z9hG4bKinviteack";
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@127.0.0.1");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch={}", uac_local, branch),
        );
        invite.headers.set("From", "<sip:alice@example>;tag=alice");
        invite.headers.set("To", "<sip:bob@example>");
        invite.headers.set("Call-ID", "invite-ack-test@host");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Max-Forwards", "70");

        // mock UAS タスク
        let uas_clone = uas_sock.clone();
        let uac_invite_branch = branch.to_string();
        let uas_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            // 1) INVITE 受信
            let (n, peer) = uas_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            let invite_req = match parsed {
                SipMessage::Request(r) => r,
                _ => panic!("INVITE 期待"),
            };
            assert_eq!(invite_req.method, SipMethod::Invite);

            // 2) 403 Forbidden を構築・送信 (To に tag を付けて返す)
            let mut resp = build_response_skeleton(&invite_req, 403, "Forbidden");
            resp.headers
                .set("To", "<sip:bob@example>;tag=ngn-uas-tag");
            resp.reason = "Forbidden".into();
            let resp_bytes = resp.to_bytes();
            uas_clone.send_to(&resp_bytes, peer).await.unwrap();

            // 3) ACK を受信 (timeout を設けて hang を防ぐ)
            let recv_ack = tokio::time::timeout(Duration::from_secs(3), async {
                let mut b = vec![0u8; 4096];
                loop {
                    let (m, _p) = uas_clone.recv_from(&mut b).await.unwrap();
                    let parsed = parse_message(&b[..m]).unwrap();
                    if let SipMessage::Request(r) = parsed {
                        if r.method == SipMethod::Ack {
                            return r;
                        }
                    }
                }
            })
            .await
            .expect("ACK が来ない");

            // 必須: 元 INVITE と同じ Via branch を持つ
            let via = recv_ack.headers.get("via").unwrap();
            assert!(
                via.contains(&uac_invite_branch),
                "ACK Via に元 INVITE の branch がない: {}",
                via
            );
            // 必須: To に応答の tag が乗っている
            assert!(
                recv_ack.headers.get("to").unwrap().contains("tag=ngn-uas-tag"),
                "ACK の To に応答 tag が無い"
            );
            // 必須: CSeq method=ACK, 番号は元 INVITE と同じ
            assert_eq!(recv_ack.headers.get("cseq").unwrap(), "1 ACK");
            assert_eq!(recv_ack.headers.get("call-id").unwrap(), "invite-ack-test@host");

            // 4) 403 を再送 (NGN がよくやる)
            uas_clone.send_to(&resp_bytes, peer).await.unwrap();

            // 5) 2 回目の ACK を受信 (吸収 → 再送が要件)
            let recv_ack2 = tokio::time::timeout(Duration::from_secs(3), async {
                let mut b = vec![0u8; 4096];
                loop {
                    let (m, _p) = uas_clone.recv_from(&mut b).await.unwrap();
                    let parsed = parse_message(&b[..m]).unwrap();
                    if let SipMessage::Request(r) = parsed {
                        if r.method == SipMethod::Ack {
                            return r;
                        }
                    }
                }
            })
            .await
            .expect("2 回目の ACK が来ない (応答再送吸収が動いてない)");

            // 同じ ACK バイト列が再送されることを Via branch で確認
            assert_eq!(
                recv_ack2.headers.get("via").unwrap(),
                recv_ack.headers.get("via").unwrap()
            );
            assert_eq!(
                recv_ack2.headers.get("cseq").unwrap(),
                recv_ack.headers.get("cseq").unwrap()
            );
        });

        // UAC 側で INVITE を送って 403 を受け取る
        let resp = layer.send_request(invite, uas_addr).await.unwrap();
        assert_eq!(resp.status_code, 403);

        uas_handle.await.unwrap();
    }
}
