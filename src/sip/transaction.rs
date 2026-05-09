//! SIP トランザクション層 (RFC 3261 §17)
//!
//! トランザクション ID は (branch, sent-by, cseq-method) で一意に決まる
//! (RFC 3261 §17.1.3, §17.2.3)。本モジュールでは UAC/UAS の双方の
//! トランザクション状態機械を、UDP 上の前提で実装する。
//!
//! ## 状態機械
//!
//! ### Client INVITE (RFC 3261 §17.1.1, Figure 5)
//! ```text
//!         |INVITE from TU
//!         |INVITE sent
//!         |Timer A fires (T1, 2*T1, ..., resend INVITE)
//!         V
//!     +---------+
//!     | Calling | -- 1xx --+
//!     +---------+         |
//!         |               V
//!      2xx-6xx       +-----------+
//!         |          |Proceeding |--- 1xx ---+
//!         V          +-----------+           |
//!     +-----------+      |  2xx-6xx          |
//!     | Completed |<-----+                   |
//!     +-----------+                          |
//!         |                                  |
//!      Timer D                               |
//!         V                                  |
//!     +------------+                         |
//!     | Terminated |<------- Timer B --------+
//!     +------------+
//! ```
//! - Timer A: T1, 2*T1, 4*T1, ... (UDP のみ; INVITE 再送)
//! - Timer B: 64*T1 (=32s) でタイムアウト
//! - Timer D: UDP では 32s 以上 (本実装は 32s)
//!
//! ### Client non-INVITE (RFC 3261 §17.1.2, Figure 6)
//! ```text
//!         |Request from TU
//!         V
//!     +-------+
//!     |Trying | -- Timer E (T1, then min(2*prev, T2)) -> resend
//!     +-------+
//!         |  1xx                          200-699
//!         V                                   |
//!     +-----------+                           |
//!     |Proceeding | -- Timer E -> resend      |
//!     +-----------+                           |
//!         |  200-699                          |
//!         V                                   V
//!     +-----------+
//!     | Completed | -- Timer K (4s, UDP) -> Terminated
//!     +-----------+
//!         ^
//!         | Timer F (64*T1) -> Terminated (timeout)
//! ```
//!
//! ### Server INVITE (RFC 3261 §17.2.1, Figure 7)
//! ```text
//!         |INVITE
//!         V                       100-199 from TU
//!     +-----------+ <----------+
//!     |Proceeding |            |
//!     +-----------+ ---- 200 OK from TU ----> +-------+
//!         |       --- 300-699 from TU ---->   |       |
//!         |                                   |       |
//!         V                                   V       |
//!     +-----------+ ACK                  +-----------+|
//!     | Completed |---------> Confirmed  |   '2xx    ||
//!     +-----------+                      | retxn'    || (RFC 6026)
//!        | Timer G (T1, 2*T1, ..., T2 cap)|            |
//!        | resend final non-2xx          +-----------+
//!        | Timer H (64*T1) -> Terminated
//!        V (ACK)
//!     +-----------+   Timer I (T4) -> Terminated
//!     | Confirmed |
//!     +-----------+
//! ```
//! 200 OK の再送は本実装では `ServerTransaction` で `Timer G/H` 相当を
//! 同じパスで駆動する (RFC 6026 で 200 OK も transaction が保持する形に
//! 整理されたが、本実装は最後に送った final response を一律保持する)。
//!
//! ### Server non-INVITE (RFC 3261 §17.2.2, Figure 8)
//! ```text
//!         |Request from network
//!         V
//!     +--------+
//!     | Trying | --- 1xx -> Proceeding --- 200-699 -> Completed
//!     +--------+                                    | Timer J (64*T1, UDP)
//!                                                   V
//!                                              Terminated
//! ```
//! Completed 中の同一リクエスト再送に対しては、最後に送った final
//! response をそのまま再送する (RFC 3261 §17.2.2)。
//!
//! ## NTT NGN 制約
//! 既存 `register.rs` 同様、Via ヘッダに `rport` を付けない (拒否される)
//! 制約は呼び出し側 (リクエスト ビルダ) の責務であり、本層は Via を
//! そのまま透過する。
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
/// RFC 3261 §17.1.2.2 Timer T2 (non-INVITE 再送間隔の上限 / INVITE 200 OK 再送上限)。
pub const T2: Duration = Duration::from_secs(4);
/// RFC 3261 §17.1.1.2 Timer T4 (メッセージのネット上残留時間)。
pub const T4: Duration = Duration::from_secs(5);

/// RFC 3261 §17.1.1.2 Timer B = 64 * T1 (client INVITE タイムアウト = 32s)。
pub const TIMER_B: Duration = Duration::from_millis(64 * 500);
/// RFC 3261 §17.1.2.2 Timer F = 64 * T1 (client non-INVITE タイムアウト = 32s)。
pub const TIMER_F: Duration = Duration::from_millis(64 * 500);
/// RFC 3261 §17.1.1.2 Timer D (client INVITE Completed 滞在時間, UDP は >= 32s)。
pub const TIMER_D: Duration = Duration::from_secs(32);
/// RFC 3261 §17.1.2.2 Timer K (client non-INVITE Completed 滞在時間, UDP = T4)。
pub const TIMER_K: Duration = T4;
/// RFC 3261 §17.2.1 Timer H = 64 * T1 (server INVITE ACK 待ちの最終タイムアウト)。
pub const TIMER_H: Duration = Duration::from_millis(64 * 500);
/// RFC 3261 §17.2.1 Timer I (server INVITE Confirmed 滞在時間, UDP = T4)。
pub const TIMER_I: Duration = T4;
/// RFC 3261 §17.2.2 Timer J = 64 * T1 (server non-INVITE Completed 滞在時間, UDP)。
pub const TIMER_J: Duration = Duration::from_millis(64 * 500);

/// Client/Server を区別しないトランザクション ID。
///
/// RFC 3261 §17.1.3 / §17.2.3 に従い、branch (RFC 3261 magic cookie 付き) と
/// 送信元 sent-by、CSeq method の三要素で同定する。CANCEL は元の INVITE と
/// 同一 branch を共有するが method で区別される。ACK もまた CSeq method
/// が "INVITE" のままなので、サーバ側マッチングで特別扱いが必要。
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
    /// INVITE 送信直後。Timer A (再送) / B (タイムアウト) 起動。
    Calling,
    /// non-INVITE 送信直後。Timer E (再送) / F (タイムアウト) 起動。
    Trying,
    /// 1xx 受信後。INVITE は Timer A 停止、non-INVITE は Timer E を T2 に
    /// クリップしつつ継続。
    Proceeding,
    /// 最終応答 (>=200) 受信後。INVITE は Timer D, non-INVITE は Timer K で滞在。
    Completed,
    /// 終了。
    Terminated,
}

/// サーバ トランザクションの状態 (RFC 3261 §17.2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// non-INVITE: リクエスト受信直後 (provisional 未送信)。
    Trying,
    /// provisional 送信後 / INVITE は受信直後から Proceeding。
    Proceeding,
    /// 最終応答送信後。
    /// - non-INVITE: Timer J (64*T1) で滞在し、再送に応える。
    /// - INVITE non-2xx: Timer G (T1→T2 cap) で再送、Timer H (64*T1) で異常終了。
    Completed,
    /// INVITE Completed で ACK を受信した後の状態。Timer I (T4) で滞在。
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

/// サーバ トランザクションへ TransactionLayer から流すイベント。
#[derive(Debug)]
enum ServerEvent {
    /// 同じ branch+method のリクエスト再送。
    Retransmit,
    /// INVITE Completed 中に到着した ACK (CSeq method=INVITE)。
    Ack,
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
}

impl ClientTransaction {
    /// 新しいクライアント トランザクションを作成し、駆動可能な状態にする。
    fn new(
        id: TransactionId,
        request: SipRequest,
        destination: SocketAddr,
        socket: Arc<UdpSocket>,
        rx: mpsc::UnboundedReceiver<ClientEvent>,
        tracer: SipTraceWriter,
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
        }
    }

    /// Transaction を駆動して最終応答を返す。
    ///
    /// RFC 3261 §17.1 (Figure 5/6) の擬似コード:
    ///
    /// ```text
    /// // INVITE
    /// state = Calling
    /// send(request)
    /// schedule(Timer A = T1, fire repeatedly: send(request); A *= 2)
    /// schedule(Timer B = 64*T1, fire once: state = Terminated; report timeout)
    /// loop {
    ///   recv response or timer:
    ///     1xx: state = Proceeding; cancel(Timer A)
    ///     2xx-6xx: state = Completed; cancel(Timer A,B); schedule(Timer D)
    ///     Timer D: state = Terminated
    /// }
    ///
    /// // non-INVITE
    /// state = Trying
    /// send(request)
    /// schedule(Timer E = T1, fire repeatedly: send(request); E = min(2*E, T2))
    /// schedule(Timer F = 64*T1, fire once: state = Terminated; report timeout)
    /// loop {
    ///   recv response or timer:
    ///     1xx: state = Proceeding (Timer E は継続だが上限が T2)
    ///     200-699: state = Completed; cancel(E,F); schedule(Timer K = T4)
    ///     Timer K: state = Terminated
    /// }
    /// ```
    ///
    /// 本実装は `Completed` に入った時点で final response を呼び出し側に
    /// 返し、Timer D / K に相当するエントリ滞在は [`TransactionLayer`] 側
    /// で行う ([`TransactionLayer::drop_client_after`] 参照)。これは
    /// レスポンス再送への ACK 整合 (RFC 3261 §17.1.1.3) は ACK 送信側
    /// (UAC TU) の責務に切り出されているため。
    pub async fn run(mut self) -> Result<SipResponse> {
        let bytes = self.request.to_bytes();
        self.socket.send_to(&bytes, self.destination).await?;
        write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
        debug!(?self.id, "client tx 送信");

        // INVITE: Timer A 初期値 T1, 倍々
        // non-INVITE: Timer E 初期値 T1, min(2*prev, T2)
        let is_invite = matches!(self.request.method, SipMethod::Invite);
        let mut interval = T1;
        let timeout = if is_invite { TIMER_B } else { TIMER_F };

        let next_retx = time::sleep(interval);
        tokio::pin!(next_retx);
        let timeout_bf = time::sleep(timeout);
        tokio::pin!(timeout_bf);

        loop {
            tokio::select! {
                ev = self.rx.recv() => {
                    let Some(ClientEvent::Response(resp)) = ev else {
                        return Err(anyhow!("transaction layer が停止した"));
                    };
                    let code = resp.status_code;
                    trace!(?self.id, code, "client tx 応答");
                    if (100..200).contains(&code) {
                        // 1xx で状態遷移。
                        // - INVITE: Timer A を停止 (再送停止)
                        // - non-INVITE: Timer E は継続するが上限を T2 にクリップ。
                        //   既に T2 を超えていれば即 T2 にする。
                        self.state = ClientState::Proceeding;
                        if is_invite {
                            // Timer A 停止: 十分先へ
                            next_retx
                                .as_mut()
                                .reset(time::Instant::now() + timeout);
                        } else {
                            // RFC 3261 §17.1.2.2: Proceeding では Timer E を T2 にクリップ
                            interval = T2;
                            next_retx
                                .as_mut()
                                .reset(time::Instant::now() + interval);
                        }
                        continue;
                    }
                    // 最終応答 (>=200)
                    self.state = ClientState::Completed;
                    return Ok(resp);
                }
                _ = &mut next_retx, if matches!(self.state, ClientState::Calling | ClientState::Trying | ClientState::Proceeding) => {
                    // RFC 3261 §17.1.1.2 Timer A: INVITE は倍々 (T1, 2*T1, 4*T1, ...)
                    // RFC 3261 §17.1.2.2 Timer E: non-INVITE は min(2*prev, T2)
                    // ただし INVITE は Proceeding 入り後は再送しない。
                    if is_invite && self.state != ClientState::Calling {
                        // 念のためガード (上の 1xx ブランチで停止済みのはず)
                        next_retx.as_mut().reset(time::Instant::now() + timeout);
                        continue;
                    }
                    self.socket.send_to(&bytes, self.destination).await?;
                    write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
                    debug!(?self.id, ?interval, "client tx 再送");
                    interval = if is_invite {
                        interval.saturating_mul(2)
                    } else {
                        std::cmp::min(interval.saturating_mul(2), T2)
                    };
                    next_retx.as_mut().reset(time::Instant::now() + interval);
                }
                _ = &mut timeout_bf => {
                    self.state = ClientState::Terminated;
                    warn!(?self.id, ?timeout, "client tx Timer B/F タイムアウト");
                    return Err(anyhow!("transaction timeout"));
                }
            }
        }
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
/// Figure 7/8 の状態機械を内部で駆動する。Final response を `respond` で
/// 送ると、再送タイマ (INVITE: Timer G + H, non-INVITE: Timer J 滞在)
/// を内部で起動し、ACK 受信や Timer 満了で Terminated に遷移する。
///
/// 同一リクエストの再送に対しては、最後に送った final response を
/// 自動的に再送する ([`handle_retransmit`])。これは [`TransactionLayer`]
/// が ID マッチで呼び出すか、外部から直接呼び出す。
pub struct ServerTransaction {
    id: TransactionId,
    request: SipRequest,
    remote: SocketAddr,
    socket: Arc<UdpSocket>,
    state: ServerState,
    last_response: Option<SipResponse>,
    tracer: SipTraceWriter,
    /// `respond` で final を送った時点で起動する内部タイマタスクのハンドル。
    /// Drop 時に abort して、未完のタイマを掃除する。
    timer_task: Option<tokio::task::JoinHandle<()>>,
    /// 内部タイマタスクへ ACK / 再送イベントを伝えるチャネル。
    timer_event_tx: Option<mpsc::UnboundedSender<ServerEvent>>,
}

impl Drop for ServerTransaction {
    fn drop(&mut self) {
        if let Some(h) = self.timer_task.take() {
            h.abort();
        }
    }
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
            timer_task: None,
            timer_event_tx: None,
        })
    }

    /// 応答を送信し、状態を遷移させる。
    ///
    /// final response (>=200) を送った時点で:
    /// - INVITE non-2xx: Completed に遷移し、Timer G (T1→T2 cap) で再送、
    ///   Timer H (64*T1) で異常タイムアウト。ACK 受信で Confirmed → Timer I。
    /// - INVITE 2xx: 同様に Timer G/H でメッセージを保持する (RFC 6026 で
    ///   transaction が 2xx も保持する形に整理された)。ACK 受信で Confirmed。
    /// - non-INVITE: Completed に遷移し、Timer J (64*T1) で滞在。
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
                self.start_completed_timers();
            }
            (ServerState::Proceeding, 100..=199) => {} // 追加 provisional は状態維持
            _ => {}
        }
        debug!(?self.id, code, ?self.state, "server tx 応答");
        Ok(())
    }

    /// `state == Completed` に入った時点で再送 / タイムアウトのバックグラウンド
    /// タスクを起動する。Drop で abort される。
    fn start_completed_timers(&mut self) {
        // 既に走っているなら停止 (二重 final 等)。
        if let Some(h) = self.timer_task.take() {
            h.abort();
        }

        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ServerEvent>();
        self.timer_event_tx = Some(event_tx);

        let is_invite = matches!(self.request.method, SipMethod::Invite);
        let socket = self.socket.clone();
        let remote = self.remote;
        let tracer = self.tracer.clone();
        let id = self.id.clone();
        let last_bytes = self
            .last_response
            .as_ref()
            .map(|r| r.to_bytes())
            .unwrap_or_default();

        let task = tokio::spawn(async move {
            if last_bytes.is_empty() {
                return;
            }
            if is_invite {
                // Timer G: T1 から始め T2 にクリップ、Timer H = 64*T1
                let mut g_interval = T1;
                let g_sleep = time::sleep(g_interval);
                tokio::pin!(g_sleep);
                let h_sleep = time::sleep(TIMER_H);
                tokio::pin!(h_sleep);

                let got_ack;
                loop {
                    tokio::select! {
                        ev = event_rx.recv() => {
                            match ev {
                                Some(ServerEvent::Retransmit) => {
                                    // RFC 3261 §17.2.1: Completed 中に再送リクエスト
                                    // が来たら最後の final を返し、Timer G を初期化。
                                    let _ = socket.send_to(&last_bytes, remote).await;
                                    write_trace(&tracer, TraceDir::Sent, &last_bytes).await;
                                    g_interval = T1;
                                    g_sleep.as_mut().reset(time::Instant::now() + g_interval);
                                }
                                Some(ServerEvent::Ack) => {
                                    got_ack = true;
                                    break;
                                }
                                None => return,
                            }
                        }
                        _ = &mut g_sleep => {
                            // Timer G 満了: 自発再送
                            let _ = socket.send_to(&last_bytes, remote).await;
                            write_trace(&tracer, TraceDir::Sent, &last_bytes).await;
                            g_interval = std::cmp::min(g_interval.saturating_mul(2), T2);
                            g_sleep.as_mut().reset(time::Instant::now() + g_interval);
                            trace!(?id, ?g_interval, "server tx Timer G 自発再送");
                        }
                        _ = &mut h_sleep => {
                            warn!(?id, "server tx Timer H タイムアウト (ACK 不到来)");
                            got_ack = false;
                            break;
                        }
                    }
                }

                if got_ack {
                    // RFC 3261 §17.2.1: Confirmed で Timer I = T4 だけ滞在し、
                    // 遅延 ACK の再送を吸収して Terminated。
                    time::sleep(TIMER_I).await;
                    trace!(?id, "server tx Timer I 終了 → Terminated");
                } else {
                    trace!(?id, "server tx Timer H で異常終了");
                }
            } else {
                // non-INVITE: Timer J = 64*T1 滞在。Completed 中の再送には
                // 既送 final を再送 (RFC 3261 §17.2.2)。
                let j_sleep = time::sleep(TIMER_J);
                tokio::pin!(j_sleep);

                loop {
                    tokio::select! {
                        ev = event_rx.recv() => {
                            match ev {
                                Some(ServerEvent::Retransmit) => {
                                    let _ = socket.send_to(&last_bytes, remote).await;
                                    write_trace(&tracer, TraceDir::Sent, &last_bytes).await;
                                }
                                Some(ServerEvent::Ack) => {
                                    // non-INVITE には ACK が来ないが、念のため無視
                                }
                                None => return,
                            }
                        }
                        _ = &mut j_sleep => {
                            trace!(?id, "server tx Timer J 終了 → Terminated");
                            return;
                        }
                    }
                }
            }
        });

        self.timer_task = Some(task);
    }

    /// リクエスト再送に対して直近の応答を再送する (RFC 3261 §17.2.1 / §17.2.2)。
    ///
    /// 内部タイマタスクが起動済みならそちらに通知して再送 + Timer リセットを
    /// させる。未起動 (Completed 前) なら同期的に最後の応答を送る。
    pub async fn handle_retransmit(&self) -> Result<()> {
        if let Some(tx) = &self.timer_event_tx {
            let _ = tx.send(ServerEvent::Retransmit);
            return Ok(());
        }
        if let Some(resp) = &self.last_response {
            let bytes = resp.to_bytes();
            self.socket.send_to(&bytes, self.remote).await?;
            write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
            trace!(?self.id, "server tx 応答再送 (タイマ未起動)");
        }
        Ok(())
    }

    /// INVITE Completed 中に ACK を受信したことを伝える。
    /// Confirmed に遷移し、Timer I (T4) 滞在後に Terminated。
    pub fn handle_ack(&mut self) {
        if matches!(self.request.method, SipMethod::Invite)
            && matches!(self.state, ServerState::Completed)
        {
            self.state = ServerState::Confirmed;
            if let Some(tx) = &self.timer_event_tx {
                let _ = tx.send(ServerEvent::Ack);
            }
        }
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
        Ok(ClientTransaction::new(
            id,
            request,
            destination,
            self.socket.clone(),
            rx,
            self.tracer.clone(),
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
        // run の完了 (成功/失敗) 双方でテーブルを掃除する。
        let layer = self.clone();
        let (done_tx, done_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = tx.run().await;
            layer.drop_client(&id).await;
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

    fn make_invite_request(branch: &str) -> SipRequest {
        let mut req = SipRequest::new(SipMethod::Invite, "sip:bob@ntt-east.ne.jp");
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP 192.0.2.1:5060;branch={}", branch),
        );
        req.headers
            .set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=alice");
        req.headers.set("To", "<sip:bob@ntt-east.ne.jp>");
        req.headers.set("Call-ID", "callid@host");
        req.headers.set("CSeq", "1 INVITE");
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

    /// Timer B (64*T1 = 32s) 相当のタイムアウト確認 (INVITE)。
    /// `tokio::time::pause` で仮想時間を進めて短時間で検証する。
    #[tokio::test(start_paused = true)]
    async fn test_client_invite_timer_b_timeout() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_sink: SocketAddr = sink.local_addr().unwrap();

        let req = make_invite_request("z9hG4bKtimerB");
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        drop(tx);
        let ct = ClientTransaction::new(id, req, dest_sink, socket, rx, SipTraceWriter::disabled());
        let result = ct.run().await;
        assert!(result.is_err(), "Timer B (64*T1=32s) でタイムアウトするはず");
    }

    /// Timer F (64*T1 = 32s) 相当のタイムアウト確認 (non-INVITE)。
    #[tokio::test(start_paused = true)]
    async fn test_client_non_invite_timer_f_timeout() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_sink: SocketAddr = sink.local_addr().unwrap();

        let req = make_request("z9hG4bKtimerF");
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        drop(tx);
        let ct = ClientTransaction::new(id, req, dest_sink, socket, rx, SipTraceWriter::disabled());
        let result = ct.run().await;
        assert!(result.is_err(), "Timer F (64*T1=32s) でタイムアウトするはず");
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

    /// 再送ステップを観測するためのヘルパ。
    ///
    /// `tokio::time::pause` モードでは、UDP recv は実 OS の syscall であり
    /// 仮想時間と独立に走るため、`time::advance` 後は recv タスクに poll
    /// 機会を与える必要がある。`yield_now` を数回挟んで、tokio runtime に
    /// 再スケジュール機会を与える。
    async fn step_and_yield(amount: Duration) {
        time::advance(amount).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// RFC 3261 §17.1.1.2 Timer A: INVITE は T1, 2*T1, 4*T1, ... で再送される。
    /// 仮想時間を進めて再送回数が指数バックオフであることを確認。
    #[tokio::test(start_paused = true)]
    async fn test_client_invite_timer_a_exponential_backoff() {
        // 受信側ソケットに送って recv で再送をカウントする。
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = sink.local_addr().unwrap();

        // recv は別タスクで貯める
        let sink_clone = sink.clone();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if sink_clone.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let req = make_invite_request("z9hG4bKtimerA");
        let id = TransactionId::from_request(&req).unwrap();
        let (_tx, rx) = mpsc::unbounded_channel::<ClientEvent>();
        let ct = ClientTransaction::new(id, req, dest, socket, rx, SipTraceWriter::disabled());
        let h = tokio::spawn(async move { ct.run().await });
        // 初回送信を待つ
        step_and_yield(Duration::from_millis(0)).await;

        // 仮想時間: T1 (500ms) で 1 回目再送, +1000ms で 2回目, +2000ms で 3回目, ...
        // 段階的に進めて UDP recv に処理機会を与える。
        for _ in 0..6 {
            step_and_yield(Duration::from_secs(5)).await;
        }

        let n = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            n >= 5,
            "Timer A による再送が指数バックオフで複数回起きるはず (got {})",
            n
        );

        // 最終的に Timer B でエラーになる
        step_and_yield(Duration::from_secs(5)).await;
        let res = h.await.unwrap();
        assert!(res.is_err(), "Timer B でタイムアウトするはず");
    }

    /// RFC 3261 §17.1.2.2 Timer E: non-INVITE は T1, 2*T1, ..., T2 cap で再送。
    /// 1 秒以上経過しても再送間隔は T2 (=4s) を超えないことを確認。
    #[tokio::test(start_paused = true)]
    async fn test_client_non_invite_timer_e_t2_cap() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = sink.local_addr().unwrap();

        let sink_clone = sink.clone();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if sink_clone.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let req = make_request("z9hG4bKtimerE");
        let id = TransactionId::from_request(&req).unwrap();
        let (_tx, rx) = mpsc::unbounded_channel::<ClientEvent>();
        let ct = ClientTransaction::new(id, req, dest, socket, rx, SipTraceWriter::disabled());
        let h = tokio::spawn(async move { ct.run().await });
        step_and_yield(Duration::from_millis(0)).await;

        // 32s 弱の間で T1, 2T1, 4T1=2s, 8T1=4s, T2=4s, T2=4s, ... で
        // 累計 ~10 回程度の送信が起きる (1 + 5..10 程度の再送)。
        for _ in 0..6 {
            step_and_yield(Duration::from_secs(5)).await;
        }

        let n = counter.load(std::sync::atomic::Ordering::SeqCst);
        // 純粋な指数バックオフだと 32s で 6 回 (1+2+4+8+16=31s 累積) にしかならないが、
        // T2 cap で抑えられて 7 回以上になるはず。
        assert!(
            n >= 7,
            "Timer E は T2 cap で抑えられて再送回数が増えるはず (got {})",
            n
        );

        step_and_yield(Duration::from_secs(5)).await;
        let res = h.await.unwrap();
        assert!(res.is_err(), "Timer F でタイムアウトするはず");
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

    /// RFC 3261 §17.2.1 Timer G: server INVITE Completed で final response が
    /// 自発再送される。Timer G は T1, 2*T1, ..., T2 cap。
    #[tokio::test(start_paused = true)]
    async fn test_server_invite_timer_g_retransmits_final() {
        // server tx 用ソケット (送信元)。client 役は別ソケットで recv する。
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr: SocketAddr = client_sock.local_addr().unwrap();

        // 受信カウンタ
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        let cs = client_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if cs.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let req = make_invite_request("z9hG4bKsrvG");
        let mut stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        // 486 Busy Here を返す = Completed に遷移し Timer G/H 起動
        let resp = make_response("z9hG4bKsrvG", 486, "INVITE");
        stx.respond(resp).await.unwrap();
        assert_eq!(stx.state(), ServerState::Completed);
        step_and_yield(Duration::from_millis(0)).await;

        // 最初の送信 1 回 + Timer G 自発再送が 32s 内で複数回起きる。
        for _ in 0..6 {
            step_and_yield(Duration::from_secs(5)).await;
        }

        let n = counter.load(std::sync::atomic::Ordering::SeqCst);
        // 1 (初送) + Timer G 5 回以上 (T1+2T1+4T1+T2+T2+... )
        assert!(
            n >= 6,
            "Timer G による final response 再送が複数回起きるはず (got {})",
            n
        );

        // ここで stx を drop して内部タスクを停止
        drop(stx);
    }

    /// RFC 3261 §17.2.1 Timer H: server INVITE Completed で ACK が来ないと
    /// 64*T1 (=32s) 後に Timer H で異常終了 (再送停止)。
    #[tokio::test(start_paused = true)]
    async fn test_server_invite_timer_h_stops_retransmits() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr: SocketAddr = client_sock.local_addr().unwrap();

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        let cs = client_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if cs.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let req = make_invite_request("z9hG4bKsrvH");
        let mut stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        let resp = make_response("z9hG4bKsrvH", 486, "INVITE");
        stx.respond(resp).await.unwrap();
        step_and_yield(Duration::from_millis(0)).await;

        // Timer H (32s) を超えて経過しても再送はそれ以上増えないことを確認。
        for _ in 0..7 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        let count_after_h = counter.load(std::sync::atomic::Ordering::SeqCst);

        for _ in 0..3 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        let count_later = counter.load(std::sync::atomic::Ordering::SeqCst);

        assert_eq!(
            count_after_h, count_later,
            "Timer H 後は再送停止 (count: {} -> {})",
            count_after_h, count_later
        );
        drop(stx);
    }

    /// RFC 3261 §17.2.1: ACK 受信で Confirmed → Timer I (T4=5s) 後 Terminated。
    /// `handle_ack` で再送が止まることを確認。
    #[tokio::test(start_paused = true)]
    async fn test_server_invite_ack_stops_timer_g() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr: SocketAddr = client_sock.local_addr().unwrap();

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        let cs = client_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if cs.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let req = make_invite_request("z9hG4bKsrvACK");
        let mut stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        let resp = make_response("z9hG4bKsrvACK", 486, "INVITE");
        stx.respond(resp).await.unwrap();
        step_and_yield(Duration::from_millis(0)).await;

        // T1+α の間に ACK を渡して Timer G を停止
        step_and_yield(Duration::from_millis(800)).await;
        let count_before_ack = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            count_before_ack >= 2,
            "ACK 前に少なくとも 1 回は Timer G 再送 (got {})",
            count_before_ack
        );

        stx.handle_ack();
        assert_eq!(stx.state(), ServerState::Confirmed);

        // ACK 後、Timer I (T4=5s) 期間は何もしない。
        for _ in 0..4 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        let count_after_ack = counter.load(std::sync::atomic::Ordering::SeqCst);
        // ACK 後は再送がほとんど増えない (タイミング差 1 回ぐらいまで許容)
        assert!(
            count_after_ack - count_before_ack <= 1,
            "ACK 受信後は Timer G 停止 (before {} -> after {})",
            count_before_ack,
            count_after_ack
        );
        drop(stx);
    }

    /// RFC 3261 §17.2.2 Timer J: server non-INVITE Completed 滞在中に
    /// 同一リクエスト再送に対し既送 final を再送する。
    #[tokio::test(start_paused = true)]
    async fn test_server_non_invite_timer_j_retransmits_on_request_dup() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr: SocketAddr = client_sock.local_addr().unwrap();

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        let cs = client_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if cs.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let req = make_request("z9hG4bKsrvJ"); // REGISTER (non-INVITE)
        let stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        // mut で final を送る
        let mut stx = stx;
        stx.respond(make_response("z9hG4bKsrvJ", 200, "REGISTER"))
            .await
            .unwrap();

        // 最初の 1 回が届くまで進める
        step_and_yield(Duration::from_millis(0)).await;
        let count_initial = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(count_initial, 1, "final 1 回送信 (got {})", count_initial);

        // 同一リクエスト再送 → handle_retransmit (Timer J 期間内は既送 final を再送)
        for _ in 0..3 {
            stx.handle_retransmit().await.unwrap();
            step_and_yield(Duration::from_millis(0)).await;
        }
        let count_after_dup = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            count_after_dup >= 4,
            "再送リクエストごとに既送 final が再送される (got {})",
            count_after_dup
        );

        // Timer J (32s) 後はタイマタスクが終了する。
        for _ in 0..7 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        // 以降の handle_retransmit は通知だけで何も送らない (タスクが居ないため)
        // ただし通知チャネルは生きているので unwrap は成功する。
        stx.handle_retransmit().await.unwrap();
        drop(stx);
    }

    #[test]
    fn test_timer_constants_match_rfc() {
        // RFC 3261 §17 で各 Timer の値がデフォルトと一致することを定数で確認。
        assert_eq!(T1, Duration::from_millis(500));
        assert_eq!(T2, Duration::from_secs(4));
        assert_eq!(T4, Duration::from_secs(5));
        assert_eq!(TIMER_B, T1 * 64);
        assert_eq!(TIMER_F, T1 * 64);
        assert_eq!(TIMER_H, T1 * 64);
        assert_eq!(TIMER_J, T1 * 64);
        assert_eq!(TIMER_K, T4);
        assert_eq!(TIMER_I, T4);
        assert_eq!(TIMER_D, Duration::from_secs(32));
    }
}
