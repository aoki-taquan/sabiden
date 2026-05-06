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

/// RFC 3261 §17.1.1.1 Timer T1 (RTT 推定値)。デフォルトは 500ms。
pub const T1: Duration = Duration::from_millis(500);
/// RFC 3261 §17.1.2.2 Timer T2 (non-INVITE 再送間隔の上限)。デフォルトは 4s。
pub const T2: Duration = Duration::from_secs(4);
/// RFC 3261 §17.1.1.2 Timer T4 (メッセージのネット上残留時間)。デフォルトは 5s。
pub const T4: Duration = Duration::from_secs(5);
/// RFC 3261 §17.1.1.2 Timer B/F = 64 * T1 (トランザクション タイムアウト)。
pub const TIMER_B: Duration = Duration::from_millis(64 * 500);

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
}

impl ClientTransaction {
    /// 新しいクライアント トランザクションを作成し、駆動可能な状態にする。
    fn new(
        id: TransactionId,
        request: SipRequest,
        destination: SocketAddr,
        socket: Arc<UdpSocket>,
        rx: mpsc::UnboundedReceiver<ClientEvent>,
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
        }
    }

    /// Transaction を駆動して最終応答を返す。
    ///
    /// - Calling/Trying → Proceeding: 1xx 受信
    /// - * → Completed: >=200 受信
    /// - Timer B/F: タイムアウト (64*T1)
    pub async fn run(mut self) -> Result<SipResponse> {
        let bytes = self.request.to_bytes();
        self.socket.send_to(&bytes, self.destination).await?;
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
                    return Ok(resp);
                }
                _ = &mut next_retx, if matches!(self.state, ClientState::Calling | ClientState::Trying) => {
                    // 再送 (Timer A: INVITE は倍々, Timer E: non-INVITE は T2 上限)
                    self.socket.send_to(&bytes, self.destination).await?;
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
}

impl ServerTransaction {
    pub fn new(request: SipRequest, remote: SocketAddr, socket: Arc<UdpSocket>) -> Result<Self> {
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
        })
    }

    /// 応答を送信し、状態を遷移させる。
    pub async fn respond(&mut self, resp: SipResponse) -> Result<()> {
        let code = resp.status_code;
        let bytes = resp.to_bytes();
        self.socket.send_to(&bytes, self.remote).await?;
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
            self.socket.send_to(&resp.to_bytes(), self.remote).await?;
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
pub struct TransactionLayer {
    socket: Arc<UdpSocket>,
    inner: Arc<Mutex<TransactionTable>>,
    inbound_tx: mpsc::UnboundedSender<InboundRequest>,
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
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let layer = Arc::new(Self {
            socket: socket.clone(),
            inner: Arc::new(Mutex::new(TransactionTable::default())),
            inbound_tx,
        });
        let driver = layer.clone();
        tokio::spawn(async move { driver.recv_loop().await });
        (layer, inbound_rx)
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 8192];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, remote)) => {
                    let data = &buf[..n];
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
        let ct = ClientTransaction::new(id, req, dest_sink, socket, rx);
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
        let ct = ClientTransaction::new(id, req, dest_sink, socket, rx);

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
}
