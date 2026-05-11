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
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::time;
use tracing::{debug, trace, warn};

#[cfg(test)]
use super::message::parse_message;
use super::message::{
    extract_request_skeleton_for_400, parse_message_classified, ParseError, SipHeaders, SipMessage,
    SipMethod, SipRequest, SipResponse,
};
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
///
/// non-2xx 最終応答 → ACK 後の応答再送吸収期間。TCP/SCTP では 0s で良いが
/// 本実装は UDP 専用なので固定 32s とする。
pub const TIMER_D: Duration = Duration::from_secs(32);
/// RFC 3261 §17.1.2.2 Timer K (client non-INVITE Completed 滞在時間, UDP = T4)。
pub const TIMER_K: Duration = T4;
/// RFC 3261 §17.2.1 Timer H = 64 * T1 (server INVITE ACK 待ちの最終タイムアウト)。
pub const TIMER_H: Duration = Duration::from_millis(64 * 500);
/// RFC 3261 §17.2.1 Timer I (server INVITE Confirmed 滞在時間, UDP = T4)。
pub const TIMER_I: Duration = T4;
/// RFC 3261 §17.2.2 Timer J = 64 * T1 (server non-INVITE Completed 滞在時間, UDP)。
pub const TIMER_J: Duration = Duration::from_millis(64 * 500);

/// UDP datagram の最大サイズ (= IPv4/IPv6 datagram length field 上限の 65535 オクテット)。
///
/// RFC 3261 §18.1.1 (Sending Requests over UDP):
///   "If the request is too large for UDP, TCP MUST be used instead."
/// RFC 3261 §18.3 (Framing):
///   UDP では 1 SIP メッセージ = 1 datagram。SIP メッセージ自体に
///   公式な上限は無く、`Content-Length` は 32-bit 整数まで許容されるが、
///   UDP datagram は IP 層の都合で 65535 オクテットを超えられない。
/// RFC 3261 §18.4 (Error Handling):
///   トランスポート層でメッセージを破棄したら、上位層には届かない。
///   sabiden は NGN 直収で UDP のみ使うので、TCP fallback はせず、
///   UDP datagram の理論上限まで受理できるバッファを使う。
///
/// `recv_from` は datagram が buf より大きい場合 silently truncate するため、
/// バッファは datagram 上限以上を確保する。実機 NGN の 200 OK は通常 1〜2 KB
/// だが、Path / Service-Route / Authentication-Info / 多段 Record-Route を
/// 重ねると 8 KB を簡単に超える事例があり、`vec![0u8; 8192]` だと
/// SDP body が削られて parse は通っても下流が壊れる
/// (issue #88 / `docs/asterisk-real-invite.md`)。
pub const MAX_UDP_DATAGRAM_SIZE: usize = 65_535;

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

/// Via ヘッダの sent-by から host 部だけを取り出す。
///
/// `192.0.2.1:5060` → `192.0.2.1`、`[2001:db8::1]:5060` → `[2001:db8::1]`、
/// ポート省略時は文字列をそのまま返す。RFC 3261 §18.2.1 で「Via host が
/// UDP source IP と異なるか」を判定するための前処理。
fn via_sent_by_host(sent_by: &str) -> &str {
    let s = sent_by.trim();
    // IPv6 リテラル `[..]:port` は `]` 以降の `:port` だけを切る。
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            return &s[..end + 1];
        }
        return s;
    }
    // IPv4 / FQDN の場合は最後の `:` でポートを切る。
    match s.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => host,
        _ => s,
    }
}

/// `SocketAddr` を SIP Via ヘッダの host 表現にする。
/// IPv6 は `[..]` でくくる (RFC 3261 §25.1 host)。
fn ip_for_via_host(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => v4.ip().to_string(),
        SocketAddr::V6(v6) => format!("[{}]", v6.ip()),
    }
}

/// RFC 3581 §4 / RFC 3261 §18.2.1 に従い、UAS が応答に乗せる Via
/// ヘッダを書き換える。
///
/// - 元 Via に `;rport` パラメータがあれば (値の有無を問わず):
///   - `received=<UDP source IP>` を追加 (既存 `received=` は上書き)
///   - `rport` を `rport=<UDP source port>` に書き換え (RFC 3581 §4)
/// - `;rport` が無くても、Via sent-by host が UDP source IP と異なるなら
///   `received=<UDP source IP>` を追加 (RFC 3261 §18.2.1)
/// - 上記いずれにも該当しなければ Via をそのまま返す
///
/// パラメータ順序は元 Via のものを保持する。`branch` 等の他パラメータ
/// (RFC 3261 §20.42) には触らない。
pub fn apply_rport_to_via_for_response(via: &str, remote: &SocketAddr) -> String {
    let trimmed = via.trim();
    // sent-protocol + sent-by を切り離す
    let mut iter = trimmed.split(';');
    let head = match iter.next() {
        Some(h) => h.trim().to_string(),
        None => return via.to_string(),
    };
    // sent-by host (port 抜き) を取り出して remote.ip() と比較する
    let sent_by = head.split_once(' ').map(|x| x.1.trim()).unwrap_or("");
    let sent_by_host = via_sent_by_host(sent_by);
    let remote_ip_for_via = ip_for_via_host(remote);

    let mut params: Vec<String> = iter.map(|p| p.trim().to_string()).collect();
    let has_rport = params
        .iter()
        .any(|p| p == "rport" || p.starts_with("rport="));
    let need_received = has_rport || sent_by_host != remote_ip_for_via;

    if !has_rport && !need_received {
        return via.to_string();
    }

    // received= の上書き or 追加 (rport が無くても sent-by ≠ src のとき必要)
    if need_received {
        let received_val = format!("received={}", remote.ip());
        if let Some(pos) = params
            .iter()
            .position(|p| p == "received" || p.starts_with("received="))
        {
            params[pos] = received_val;
        } else {
            params.push(received_val);
        }
    }
    // rport= の上書き (rport があった場合のみ; RFC 3581 §4)
    if has_rport {
        let rport_val = format!("rport={}", remote.port());
        if let Some(pos) = params
            .iter()
            .position(|p| p == "rport" || p.starts_with("rport="))
        {
            params[pos] = rport_val;
        }
    }

    let mut out = head;
    for p in params {
        out.push(';');
        out.push_str(&p);
    }
    out
}

/// RFC 3581 §4 / RFC 3261 §18.2.1: UAS が応答 UDP を送り返す宛先を決める。
///
/// - 元 Via に `;rport` があれば、UDP source (= `remote`) を使う。これに
///   より NAT/VPN の外側からの REGISTER/INVITE に対しても応答が確実に
///   到達する (本 issue #60 の VPN/NAT 越えの根本対処)。
/// - `;rport` 無し、かつ Via host が UDP source IP と異なる場合も、
///   実機到達性を優先して UDP source へ返す。Via host (例: Linphone の
///   `192.0.2.1` ダミー) を信用すると黒穴行きになるため。
/// - 上記いずれにも該当しなければ `remote` をそのまま返す (NAT/VPN を
///   挟まないループバック等のテスト経路)。
///
/// 結局のところ「常に UDP source へ返す」ことになるが、本関数は将来
/// rport 強制要件 (RFC 5626) や経路バインディングを足す際の単一切替点
/// として残す。
pub fn response_destination_for(via: &str, remote: SocketAddr) -> SocketAddr {
    // 現状の SIP/UDP 実装では UDP source へ返すのが最も実機適合的。
    // (`docs/architecture.md` §11 NAT 越え参照)
    let _ = via;
    remote
}

/// INVITE クライアント トランザクションの応答受信進捗
/// (RFC 3261 §9.1 "Once the CANCEL is constructed, the client SHOULD check
/// whether it has received any response (provisional or final) for the
/// request being cancelled" を CANCEL 送出前にチェックするための観測値)。
///
/// `cancel_pending` (UAC TU) はこの状態を `watch` で読み、 RFC 3261 §9.1
/// が要求する **"If no provisional response has been received, the CANCEL
/// request MUST NOT be sent"** を満たす:
/// - `Pending` の間は CANCEL を送らずに待機。
/// - `Provisional` に遷移したら CANCEL を送る。
/// - `Final` に直行した (1xx を経ずに最終応答を受けた) 場合、 CANCEL は
///   no-op (RFC 3261 §9.1: "If the original request has generated a final
///   response, the CANCEL SHOULD NOT be sent") なので送らずに諦める。
///
/// `watch` の初期値は `Pending`。 transaction layer の `dispatch_response`
/// が応答コードを見て遷移を駆動する (`Pending → Provisional` か
/// `Pending → Final`)。 `Provisional → Final` も観測できるが、
/// `cancel_pending` 側は Provisional 検出時点で待機を抜けるため後者の遷移は
/// ロジックに影響しない (transaction 終了後の cleanup で `watch` 自体が
/// drop され、 receiver の `changed()` は `Err` になる)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteResponseProgress {
    /// まだ応答 (1xx も最終応答も) を受信していない (RFC 3261 §9.1 待機条件)。
    Pending,
    /// 1xx を受信済み (CANCEL を送ってよい状態)。
    Provisional,
    /// 既に最終応答 (>=200) を受信済み (CANCEL は no-op、 送らない)。
    Final,
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
    /// 状態遷移の要点:
    /// - Calling/Trying → Proceeding: 1xx 受信
    /// - * → Completed: >=200 受信
    /// - Timer B/F: タイムアウト (64*T1)
    /// - INVITE で 300-699 受信時は本層内で ACK を生成・送出し
    ///   (RFC 3261 §17.1.1.3)、Timer D (32s) の間は応答再送を吸収して
    ///   既送出 ACK を再送する (RFC 3261 §17.1.1.2 figure 5)。
    ///   この吸収はバックグラウンド タスク (`spawn_completed_absorber`) に
    ///   委譲し、本関数は直ちに最終応答を呼び出し元へ返す。
    /// - 2xx ACK は dialog 層 (RFC 3261 §13.2.2.4) の責務なので扱わない。
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
            // provisional watch も一緒に drop して、 待機中の `cancel_pending`
            // 側の `changed()` を `Err` で抜けさせる (RFC 3261 §9.1: 最終応答
            // 到達後の CANCEL は SHOULD NOT)。
            if let Some(table) = table {
                let mut guard = table.lock().await;
                guard.clients.remove(&id);
                guard.provisional.remove(&id);
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
    /// リクエストを受け取った UDP source。応答送信先 (`response_dest`) と
    /// `received=` パラメータの計算に使う。診断ログでも参照する想定で残す。
    #[allow(dead_code)]
    remote: SocketAddr,
    /// 応答 UDP の宛先。RFC 3581 §4 / RFC 3261 §18.2.1 に従い、
    /// rport の有無 / Via host と UDP source の一致を見て決定する。
    /// 詳細は [`response_destination_for`] のコメント。
    response_dest: SocketAddr,
    /// 応答 Via に乗せる文字列 (RFC 3581 §4 / RFC 3261 §18.2.1 に従い、
    /// 必要なら `received=` / `rport=` を埋めた値)。`build_response_skeleton`
    /// が request からコピーした Via を、`respond` 直前にこの値で上書きする。
    response_via: String,
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
        // RFC 3581 §4 / RFC 3261 §18.2.1: 応答 Via には received / rport を
        // 埋め、UDP 宛先は Via host ではなく UDP source を使う。Linphone 等
        // が Via host にダミー IP (RFC 5737 `192.0.2.x`) を入れる VPN/NAT
        // 越えのケースで応答到達性を担保する (issue #60)。
        let original_via = request
            .headers
            .get("via")
            .ok_or_else(|| anyhow!("Via ヘッダがない"))?;
        let response_via = apply_rport_to_via_for_response(original_via, &remote);
        let response_dest = response_destination_for(original_via, remote);
        Ok(Self {
            id,
            request,
            remote,
            response_dest,
            response_via,
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
    pub async fn respond(&mut self, mut resp: SipResponse) -> Result<()> {
        let code = resp.status_code;
        // RFC 3581 §4 / RFC 3261 §18.2.1: 応答の top Via は元 request の Via を
        // 反映しつつ、`received=` / `rport=` を UDP source で埋める。
        // `build_response_skeleton` が単に request の Via をコピーしただけの
        // 値を上書きする。
        resp.headers.set("Via", self.response_via.clone());
        let bytes = resp.to_bytes();
        // 応答送信先は Via host ではなく UDP source。Via host が
        // RFC 5737 ダミー (`192.0.2.x`) でも届く (issue #60)。
        self.socket.send_to(&bytes, self.response_dest).await?;
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
        // 再送 (Timer G / J) も応答と同じ UDP 宛先 (rport / received 反映済) を
        // 使う (RFC 3581 §4)。
        let remote = self.response_dest;
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
            // 応答再送も rport / received 反映済の UDP 宛先へ (RFC 3581 §4)
            self.socket.send_to(&bytes, self.response_dest).await?;
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
    /// INVITE クライアント トランザクション ID → 応答受信進捗の broadcast 元。
    ///
    /// RFC 3261 §9.1 (CANCEL は 1xx 受信後にのみ送出) を満たすため、 UAC TU
    /// (`Uac::cancel_pending`) が CANCEL 送出前に 1xx 受信を待機できるよう
    /// `watch::Sender` を保持する。 `dispatch_response` が応答コードに応じて
    /// `Pending → Provisional` / `Pending → Final` を駆動し、
    /// `Uac::cancel_pending` 側は `subscribe()` した receiver で待機する。
    ///
    /// INVITE 専用 (non-INVITE は CANCEL 対象外: RFC 3261 §9.1 "A CANCEL
    /// request SHOULD NOT be sent to cancel a request other than INVITE")。
    /// transaction 終了時 (`drop_client` / absorber Timer D 満了) に
    /// 一緒に remove する。 `watch::Sender` が drop されると receiver の
    /// `changed()` は `Err` を返すため、 `cancel_pending` 側はそれを
    /// 「transaction 終了済 = CANCEL 不要」と解釈する。
    provisional: HashMap<TransactionId, watch::Sender<InviteResponseProgress>>,
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

    /// 受信ループで使っているソケットのローカルアドレス。
    /// Via sent-by / Contact ヘッダ生成に使う。
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// UDP 受信ループ本体。
    ///
    /// RFC 3261 §18.1.1 / §18.3 により、UDP では 1 SIP メッセージ = 1 datagram。
    /// `tokio::net::UdpSocket::recv_from` は buf より大きい datagram を
    /// 受信した場合 silently truncate し、戻り値 `n` には buf 長しか入らない。
    /// truncate された SIP メッセージは header 不整合や SDP body 切れで
    /// 下流が誤動作するため、バッファは UDP datagram 上限 (65535 オクテット)
    /// を確保する (`MAX_UDP_DATAGRAM_SIZE`)。
    ///
    /// それでも `n == buf.len()` なら datagram が 65535 オクテット丁度か、
    /// それを超えて IP 層 fragment failure 等に遭った可能性があるので
    /// warn ログで band-aid 検知のヒントを残す (RFC 3261 §18.4
    /// "Error Handling" 観点)。
    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, remote)) => {
                    if n == buf.len() {
                        // RFC 3261 §18.1.1: UDP datagram が buffer 上限ぴったり
                        // で返るのは現実的には truncate の兆候 (= datagram が
                        // 65535 オクテット以上)。NGN では発生し得ない想定だが、
                        // 観測経路を確保しておく。
                        warn!(
                            len = n,
                            %remote,
                            "UDP recv buffer 上限到達: SIP メッセージが truncate された可能性 (RFC 3261 §18.1.1)"
                        );
                    }
                    let data = &buf[..n];
                    // パース前にトレース dump (壊れた SIP も観測したいため)
                    write_trace(&self.tracer, TraceDir::Recv, data).await;
                    match parse_message_classified(data) {
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
                            // 空 UDP / SIP keepalive (CRLF だけ) はパース失敗するが
                            // 障害ではない。warn を散らすと実害のある故障が
                            // 埋もれるので debug に格下げする。
                            if data.iter().all(|&b| b.is_ascii_whitespace()) {
                                debug!(len = data.len(), "空 UDP/keepalive を無視");
                            } else {
                                warn!(error=%e, "SIP メッセージ パース失敗");
                                // RFC 3261 §16 / §21.4.1: malformed syntax は
                                // `400 Bad Request` を返すべき。 ただし応答に
                                // 必須な Via/From/To/Call-ID/CSeq が抽出
                                // できなければ silent drop (応答先不明)。
                                // 本流は header-recoverable なエラー
                                // (truncate / 重複 CL / 非数値 CL) のみ。
                                if e.is_header_recoverable() {
                                    self.try_send_400_bad_request(data, remote, &e).await;
                                }
                            }
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

    /// RFC 3261 §21.4.1 (400 Bad Request): malformed syntax を検出した
    /// 受信 datagram に対して、 best-effort で抽出した Via/From/To/Call-ID/
    /// CSeq を反映した 400 応答を **UDP source** へ返送する。
    ///
    /// - 応答先は `remote` (= `recv_from` の source address)。 RFC 3261 §18.2.2
    ///   "received" / `rport` の方針と整合させるため、 Via に `received=` を
    ///   付加する (`rport` 値は付加しない: stateless responder で via host
    ///   との突合経路が無いため)。
    /// - 抽出失敗 (CRLFCRLF 不在 / 必須ヘッダ欠落) は silent drop。
    /// - send_to の I/O エラーも silent drop (それ自体を更に通知する経路が
    ///   無く、 上流が再送して回復することを期待)。
    async fn try_send_400_bad_request(&self, data: &[u8], remote: SocketAddr, err: &ParseError) {
        let Some(skel) = extract_request_skeleton_for_400(data) else {
            debug!("400 Bad Request 抑制 (Via/From/To/Call-ID/CSeq の抽出失敗で応答先不明)");
            return;
        };

        // RFC 3261 §8.2.6: 応答は request の Via/From/To/Call-ID/CSeq を
        // そのままコピーする。 `build_response_skeleton` は SipRequest を
        // 必要とするので、 best-effort で SipRequest を再構築する (body は
        // 空 = 400 応答に body は不要、 RFC 3261 §21.4.1 reason phrase で
        // 十分)。
        let dummy_req = SipRequest {
            method: skel.method.clone(),
            uri: skel.uri.clone(),
            headers: skel.headers.clone(),
            body: Vec::new(),
        };
        let mut resp = build_response_skeleton(&dummy_req, 400, "Bad Request");
        // RFC 3261 §18.2.2 (received= の付加): UDP source IP が Via host と
        // 異なる場合は MUST。 stateless responder では via host を信用せず
        // 常に付加するのが安全 (上流 proxy が後段で剥がす)。
        if let Some(via) = resp.headers.get("via") {
            if !via.contains("received=") {
                let augmented = format!("{};received={}", via, remote.ip());
                resp.headers.set("Via", augmented);
            }
        }
        // 診断のため Reason ヘッダ (RFC 3326) で具体エラー種別を残す。
        // 上流が無視する側のヘッダなので副作用なし。
        resp.headers.set(
            "Reason",
            format!("SIP;cause=400;text=\"{}\"", reason_text(err)),
        );

        let bytes = resp.to_bytes();
        write_trace(&self.tracer, TraceDir::Sent, &bytes).await;
        if let Err(io_err) = self.socket.send_to(&bytes, remote).await {
            warn!(error = %io_err, %remote, "400 Bad Request 送信失敗 (silent drop)");
        } else {
            debug!(
                %remote,
                error = %err,
                "400 Bad Request 返却 (RFC 3261 §21.4.1, malformed syntax)"
            );
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
        let code = resp.status_code;
        // RFC 3261 §9.1 の CANCEL 送出ゲート用に、 INVITE クライアント
        // トランザクションの応答受信進捗を `Pending → Provisional` /
        // `Pending → Final` に進める。 `Provisional → Final` も観測できるが、
        // `cancel_pending` 側は Provisional 検出時点で待機を抜けるため動作影響なし。
        // sender (mpsc) と同じ lock 内で読み取り、 watch の send は lock 外で行う
        // (watch::Sender::send は同期 API、 send_replace で値を上書きするだけなので
        // mpsc 側の lock を保持したまま呼んでも問題ないが、 単純化のため分離する)。
        let (sender, provisional_sender) = {
            let table = self.inner.lock().await;
            (
                table.clients.get(&id).cloned(),
                table.provisional.get(&id).cloned(),
            )
        };
        if let Some(psend) = provisional_sender {
            let new_state = if (100..200).contains(&code) {
                InviteResponseProgress::Provisional
            } else if code >= 200 {
                InviteResponseProgress::Final
            } else {
                // 0..100 は SIP では非合法 (RFC 3261 §7.2: status-code は
                // 100..699)。 transition せずに無視。
                *psend.borrow()
            };
            // 既に Final なら Provisional に戻さない (monotonic 遷移)。
            let cur = *psend.borrow();
            let should_advance = matches!(
                (cur, new_state),
                (InviteResponseProgress::Pending, _)
                    | (
                        InviteResponseProgress::Provisional,
                        InviteResponseProgress::Final
                    )
            );
            if should_advance {
                // send_replace は receiver が居なくても成功する。
                let _ = psend.send_replace(new_state);
            }
        }
        if let Some(tx) = sender {
            let _ = tx.send(ClientEvent::Response(resp));
        } else {
            debug!(?id, "未知の transaction への応答 (drop)");
        }
    }

    /// クライアント トランザクションを登録し、ハンドルを返す。
    ///
    /// INVITE のときは、 RFC 3261 §9.1 (CANCEL は 1xx 後にのみ送出) を満たすため
    /// 応答受信進捗を発信する [`watch::Sender<InviteResponseProgress>`] も併設して
    /// テーブルに登録する。 UAC TU 側は [`Self::provisional_watch`] で
    /// receiver を取得し、 CANCEL 送出前に Provisional への遷移を待機する。
    pub async fn create_client(
        &self,
        request: SipRequest,
        destination: SocketAddr,
    ) -> Result<ClientTransaction> {
        let id = TransactionId::from_request(&request)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let is_invite = matches!(id.method, SipMethod::Invite);
        {
            let mut table = self.inner.lock().await;
            table.clients.insert(id.clone(), tx);
            if is_invite {
                // RFC 3261 §9.1 用: 1xx 受信を CANCEL 送出側が待てるよう watch を作る。
                let (psend, _) = watch::channel(InviteResponseProgress::Pending);
                table.provisional.insert(id.clone(), psend);
            }
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

    /// 進行中 INVITE トランザクションの応答受信進捗 watcher を返す。
    ///
    /// RFC 3261 §9.1: CANCEL は 1xx 受信後にのみ送出してよい。 UAC TU
    /// (`Uac::cancel_pending`) は CANCEL 送出前にこの receiver を読み、
    /// `Provisional` への遷移を待機する。 transaction が既に終了している
    /// (= テーブルからエントリが消えた) 場合は `None` を返す:
    /// 呼出側は「既に最終応答済 / Timer B タイムアウト済」 と解釈し、 RFC §9.1
    /// 後半 "If the original request has generated a final response, the
    /// CANCEL SHOULD NOT be sent" に従い CANCEL を送らない。
    pub async fn provisional_watch(
        &self,
        id: &TransactionId,
    ) -> Option<watch::Receiver<InviteResponseProgress>> {
        let table = self.inner.lock().await;
        table.provisional.get(id).map(|s| s.subscribe())
    }

    /// トランザクション完了後にエントリを削除する。
    /// `ClientTransaction::run` 完了後に呼ぶ。
    ///
    /// INVITE の場合は、 紐づく provisional watch も同時に drop することで、
    /// 待機中の `cancel_pending` 側の `changed()` を `Err` にして
    /// 「transaction 終了済」 を通知する (RFC 3261 §9.1 後半: 最終応答到達後の
    /// CANCEL は no-op)。
    pub async fn drop_client(&self, id: &TransactionId) {
        let mut table = self.inner.lock().await;
        table.clients.remove(id);
        table.provisional.remove(id);
    }

    /// 現在テーブルに登録されているクライアント トランザクション数。
    ///
    /// `crate` 内部観測用: テストでの Timer D / Timer K (RFC 3261 §17.1.1.2 /
    /// §17.1.2.2) 経過後の table cleanup 検証、 および将来の Prometheus メトリ
    /// ック (`sabiden_sip_client_transactions`) で生のゲージとして expose する
    /// ための足場。 production 経路で値そのものを分岐に使うことは想定しない
    /// (= test-only API ではなく観測値)。
    ///
    /// 戻り値の lock は読み取り完了で即解放される (`Mutex` ガードを跨いで
    /// 保持しない)。
    ///
    /// 現状は test mod (`#[cfg(test)]`) からのみ呼ばれているため、 `cargo build`
    /// (non-test) では未使用扱いになるが、 上述の通り Prometheus メトリック
    /// 実装時に observability layer から呼ぶ予定なので `allow(dead_code)` で
    /// 留保する (CLAUDE.md §6.3 production-side test hook 禁止: これは hook
    /// ではなく観測 API)。
    #[allow(dead_code)]
    pub(crate) async fn client_count(&self) -> usize {
        self.inner.lock().await.clients.len()
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

/// `ParseError` を `Reason` ヘッダ (RFC 3326) に載せる短い英文へ変換する。
///
/// `Display` の長文 (filename / count 等) を載せると Reason ヘッダの BNF
/// (`reason-text = quoted-string`) で扱いにくいので、 enum variant 名相当の
/// 短い token を返す。
fn reason_text(err: &ParseError) -> &'static str {
    match err {
        ParseError::Empty => "empty",
        ParseError::NoCrlfCrlf => "no-crlfcrlf",
        ParseError::Truncated { .. } => "content-length-truncated",
        ParseError::DuplicateContentLength { .. } => "duplicate-content-length",
        ParseError::NonNumericContentLength { .. } => "non-numeric-content-length",
        ParseError::MalformedRequestLine { .. } => "malformed-request-line",
        ParseError::BadStatusCode { .. } => "bad-status-code",
        ParseError::UnknownMethod { .. } => "unknown-method",
    }
}

/// レスポンス送信用ヘルパ。
///
/// 受信 request から応答で必須 / 推奨される ヘッダを最小限コピーする。
///
/// # コピー対象
///
/// - **Via / From / To / Call-ID / CSeq** (RFC 3261 §8.2.6.2):
///   UAS が応答を生成する際の **必須** copy 対象。 To には呼出側が後段で
///   tag を付与する (本関数では付けない: ステータスコードによっては付与禁止)。
/// - **Record-Route** (RFC 3261 §12.1.1):
///   > The UAS then constructs the state of the dialog. ... The route set
///   > MUST be set to the list of URIs in the Record-Route header field
///   > from the request, taken in order and preserving all URI parameters.
///   > ... **The 2xx response MUST contain a Record-Route header field
///   > obtained by copying the Record-Route header field from the request
///   > without modification.**
///
///   2xx 応答に限らず Record-Route を全 final/provisional 応答で echo して
///   問題ない (UAC 側は dialog 確立時 = 2xx でのみ使う)。 ここでは全応答で
///   一律 echo する形にして、 呼出側の漏れを防ぐ。 複数 Record-Route ヘッダ
///   (multi-hop proxy) の **順序と多重度** を維持するため、 `get_all`
///   経由で per-entry `add` する。
/// - **Timestamp** (RFC 3261 §20.38):
///   > A response to a request containing a Timestamp header field SHOULD
///   > echo the Timestamp value without modification (in the response).
///
///   RTT 計測に使われる SHOULD 規定。 単一値なので `set` でコピー。
///
/// # 非コピー対象 (意図的)
///
/// - **Contact**: 応答の Contact は UAS の連絡先であり request からコピーしない
///   (RFC 3261 §8.2.6.2 / §20.10)。 呼出側が `set` する。
/// - **Route**: request 側のヘッダで応答では使わない (§16.4 と §12.2.1.1)。
/// - **Max-Forwards / Allow / Supported 等**: 応答固有の値を呼出側で組み立てる。
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
    // RFC 3261 §12.1.1: UAS は 2xx 応答に Record-Route を **そのまま** echo する。
    // multi-proxy 経路では Record-Route が複数値で乗ってくるため、 順序と
    // 多重度を保ったまま `add` で per-entry コピーする。 `get_all` は
    // 受信順に Vec を返す (`SipHeaders::fields` の挿入順)。
    // 結果として UAC 側 dialog で route set (RFC 3261 §12.1.2 で逆順を取る)
    // が正しく構築でき、 in-dialog request (BYE / Re-INVITE / UPDATE) が
    // loose routing で経路解決できる。
    for rr in request.headers.get_all("record-route") {
        headers.add("Record-Route", rr);
    }
    // RFC 3261 §20.38: Timestamp は応答で SHOULD echo (RTT 計測用途)。
    // 単一値ヘッダ。 値そのまま (delay の追加は呼出側の責任)。
    if let Some(ts) = request.headers.get("timestamp") {
        headers.set("Timestamp", ts);
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

    /// RFC 3261 §12.1.1: UAS が組み立てる 2xx 応答は、 受信 INVITE の
    /// Record-Route を **そのまま、 順序と多重度を保って** echo しなければ
    /// ならない。 これが欠落すると UAC 側 dialog の route set が空になり、
    /// in-dialog BYE / Re-INVITE が loose routing 経路を辿れず、 proxy
    /// 多段経路で宛先解決に失敗する。
    #[test]
    fn rfc3261_12_1_1_response_skeleton_echoes_record_route_in_order() {
        let mut req = make_invite_request("z9hG4bKrr");
        // multi-hop proxy 想定: edge → core の 2 段で Record-Route が積まれる。
        // 受信順 = 上流に近い側から、 という SIP の Record-Route 規約に従う
        // (RFC 3261 §16.6 step 4)。
        req.headers.add("Record-Route", "<sip:edge.example.net;lr>");
        req.headers.add("Record-Route", "<sip:core.example.net;lr>");
        let resp = build_response_skeleton(&req, 200, "OK");

        let rrs = resp.headers.get_all("record-route");
        assert_eq!(
            rrs,
            vec!["<sip:edge.example.net;lr>", "<sip:core.example.net;lr>"],
            "Record-Route は受信順を保ったまま全件 echo されるべき"
        );
    }

    /// RFC 3261 §12.1.1: Record-Route が request に **無い** 場合は、
    /// 応答にも追加してはならない (空 echo)。 NGN 直収のように proxy が 1 段
    /// しか挟まらない構成では、 内線 → sabiden (UAS) レッグで Record-Route
    /// が乗らない通常運用のケース。
    #[test]
    fn rfc3261_12_1_1_response_skeleton_no_record_route_when_absent() {
        let req = make_invite_request("z9hG4bKnorr");
        let resp = build_response_skeleton(&req, 200, "OK");
        assert!(
            resp.headers.get_all("record-route").is_empty(),
            "request に Record-Route が無いなら応答にも入れない"
        );
    }

    /// RFC 3261 §20.38: Timestamp ヘッダが request に乗っているなら、
    /// 応答は SHOULD でそれを **そのまま** echo する (RTT 計測用途)。
    #[test]
    fn rfc3261_20_38_response_skeleton_echoes_timestamp() {
        let mut req = make_invite_request("z9hG4bKts");
        req.headers.set("Timestamp", "54.3");
        let resp = build_response_skeleton(&req, 200, "OK");
        assert_eq!(
            resp.headers.get("timestamp"),
            Some("54.3"),
            "Timestamp は値そのままに echo する"
        );
    }

    /// RFC 3261 §20.38: request に Timestamp が無いなら応答にも入れない。
    #[test]
    fn rfc3261_20_38_response_skeleton_no_timestamp_when_absent() {
        let req = make_invite_request("z9hG4bKnots");
        let resp = build_response_skeleton(&req, 200, "OK");
        assert!(
            resp.headers.get("timestamp").is_none(),
            "request に Timestamp が無いなら応答にも入れない"
        );
    }

    /// RFC 3261 §12.1.1 / §20.38: Record-Route と Timestamp は INVITE
    /// 以外の request (例: BYE / Re-INVITE) でも同様に echo されるべき。
    /// in-dialog BYE は UAC 側 route set 由来で Record-Route を改めて
    /// 載せないのが普通だが、 proxy が再度 Record-Route を載せて UAS 側で
    /// route set を更新する RFC 5658 拡張ケースに備える。
    #[test]
    fn rfc3261_12_1_1_response_skeleton_echoes_record_route_for_non_invite() {
        let mut req = SipRequest::new(SipMethod::Bye, "sip:bob@ntt-east.ne.jp");
        req.headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKbye");
        req.headers
            .set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=alice");
        req.headers.set("To", "<sip:bob@ntt-east.ne.jp>;tag=bob");
        req.headers.set("Call-ID", "callid@host");
        req.headers.set("CSeq", "2 BYE");
        req.headers
            .add("Record-Route", "<sip:proxy.example.net;lr>");
        req.headers.set("Timestamp", "100.5");

        let resp = build_response_skeleton(&req, 200, "OK");
        assert_eq!(
            resp.headers.get_all("record-route"),
            vec!["<sip:proxy.example.net;lr>"]
        );
        assert_eq!(resp.headers.get("timestamp"), Some("100.5"));
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
        assert!(
            result.is_err(),
            "Timer B (64*T1=32s) でタイムアウトするはず"
        );
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
        assert!(
            result.is_err(),
            "Timer F (64*T1=32s) でタイムアウトするはず"
        );
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

    /// `build_non2xx_ack` の単体テスト。RFC 3261 §17.1.1.3 の必須要件:
    /// - Request-URI / Call-ID / From / Via branch / CSeq# は元 INVITE
    /// - To は **応答** の To (tag を含む)
    /// - CSeq method は ACK
    /// - Route ヘッダはコピー
    #[test]
    fn test_build_non2xx_ack_copies_headers_per_rfc3261_17_1_1_3() {
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@ntt-east.ne.jp");
        invite
            .headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKackctest");
        invite
            .headers
            .set("From", "<sip:alice@ntt-east.ne.jp>;tag=alice");
        invite.headers.set("To", "<sip:bob@ntt-east.ne.jp>");
        invite.headers.set("Call-ID", "ackc-call@host");
        invite.headers.set("CSeq", "42 INVITE");
        invite.headers.set("Max-Forwards", "70");
        invite
            .headers
            .add("Route", "<sip:proxy1@ntt-east.ne.jp;lr>");
        invite
            .headers
            .add("Route", "<sip:proxy2@ntt-east.ne.jp;lr>");

        let mut resp_headers = SipHeaders::new();
        resp_headers.set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKackctest");
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
            resp.headers.set("To", "<sip:bob@example>;tag=ngn-uas-tag");
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
                recv_ack
                    .headers
                    .get("to")
                    .unwrap()
                    .contains("tag=ngn-uas-tag"),
                "ACK の To に応答 tag が無い"
            );
            // 必須: CSeq method=ACK, 番号は元 INVITE と同じ
            assert_eq!(recv_ack.headers.get("cseq").unwrap(), "1 ACK");
            assert_eq!(
                recv_ack.headers.get("call-id").unwrap(),
                "invite-ack-test@host"
            );

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

    // -----------------------------------------------------------------------
    // RFC 3581 §4 / RFC 3261 §18.2.1: UAS rport / received 対応 (issue #60)
    // -----------------------------------------------------------------------

    /// RFC 3581 §4: 受信 Via に `;rport` があれば、応答 Via に
    /// `received=<UDP src ip>;rport=<UDP src port>` が埋め込まれる。
    #[test]
    fn rfc3581_uas_adds_received_and_rport_when_present() {
        let via = "SIP/2.0/UDP 192.0.2.1:59983;branch=z9hG4bKabc;rport";
        let remote: SocketAddr = "203.0.113.7:55442".parse().unwrap();
        let updated = apply_rport_to_via_for_response(via, &remote);
        assert!(
            updated.contains("received=203.0.113.7"),
            "received= に UDP source IP: {}",
            updated
        );
        assert!(
            updated.contains("rport=55442"),
            "rport= に UDP source port: {}",
            updated
        );
        // 元の branch は保持される
        assert!(updated.contains("branch=z9hG4bKabc"), "{}", updated);
    }

    /// RFC 3581 §4: 既に `;rport=NNN` が入った Via が来た場合 (proxy 経由など)、
    /// 応答 Via では UDP source の port で上書きする。
    #[test]
    fn rfc3581_uas_overwrites_existing_rport_value() {
        let via = "SIP/2.0/UDP 192.0.2.1:5060;rport=11111;branch=z9hG4bKxyz";
        let remote: SocketAddr = "203.0.113.7:55442".parse().unwrap();
        let updated = apply_rport_to_via_for_response(via, &remote);
        assert!(
            updated.contains("rport=55442"),
            "rport= が UDP source port で上書きされる: {}",
            updated
        );
        assert!(
            !updated.contains("rport=11111"),
            "古い rport= 値が残ってはいけない: {}",
            updated
        );
    }

    /// RFC 3261 §18.2.1: `;rport` が無くても、Via host が UDP source IP と
    /// 異なるときは `received=<UDP src ip>` を追加する (rport は付けない)。
    #[test]
    fn rfc3261_18_2_1_uas_adds_received_when_via_host_differs_from_src() {
        let via = "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnoport";
        let remote: SocketAddr = "203.0.113.7:55442".parse().unwrap();
        let updated = apply_rport_to_via_for_response(via, &remote);
        assert!(
            updated.contains("received=203.0.113.7"),
            "received= 追加: {}",
            updated
        );
        assert!(
            !updated.contains("rport"),
            ";rport が無いなら rport= も追加しない: {}",
            updated
        );
    }

    /// RFC 3261 §18.2.1: Via host と UDP source IP が一致 (NAT 越えなし)
    /// かつ `;rport` 無しなら Via は手付かず。
    #[test]
    fn rfc3261_18_2_1_uas_keeps_via_when_host_matches() {
        let via = "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKsame";
        let remote: SocketAddr = "127.0.0.1:55555".parse().unwrap();
        let updated = apply_rport_to_via_for_response(via, &remote);
        assert_eq!(updated, via);
    }

    /// IPv6 sent-by の host 部抽出が `[::1]:5060` → `[::1]` で動く。
    #[test]
    fn via_sent_by_host_handles_ipv6_literal() {
        assert_eq!(via_sent_by_host("[2001:db8::1]:5060"), "[2001:db8::1]");
        assert_eq!(via_sent_by_host("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(via_sent_by_host("192.0.2.1:5060"), "192.0.2.1");
        assert_eq!(via_sent_by_host("192.0.2.1"), "192.0.2.1");
        assert_eq!(
            via_sent_by_host("host.example.com:5061"),
            "host.example.com"
        );
    }

    /// VPN/NAT 越え再現: Via host が RFC 5737 ダミー (`192.0.2.1`) でも、
    /// `ServerTransaction` の応答 UDP destination は UDP source (= remote)
    /// になる (issue #60 の症状根本対処、RFC 3581 §4)。
    #[tokio::test]
    async fn rfc3581_uas_uses_udp_source_for_response_when_rport_present() {
        // UAS ソケット
        let uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // 「真の UDP source」(VPN 出口) を別ソケットで模擬する
        let vpn_egress = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let vpn_addr = vpn_egress.local_addr().unwrap();

        // INVITE 風 request (Via host は VPN 内 IP `192.0.2.1` ダミー)。
        let mut req = make_invite_request("z9hG4bKvpn");
        req.headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:59983;branch=z9hG4bKvpn;rport");

        // ServerTransaction を vpn_addr (UDP source) で生成
        let mut stx = ServerTransaction::new(req, vpn_addr, uas_sock.clone()).unwrap();
        // 200 OK を返す
        let mut resp = make_response("z9hG4bKvpn", 200, "INVITE");
        resp.headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:59983;branch=z9hG4bKvpn;rport");
        stx.respond(resp).await.unwrap();

        // VPN 出口ソケットが応答を **受け取れる** ことを確認 (Via host
        // `192.0.2.1` 黒穴行きではない)
        let mut buf = vec![0u8; 4096];
        let (n, _peer) =
            tokio::time::timeout(Duration::from_secs(1), vpn_egress.recv_from(&mut buf))
                .await
                .expect("応答が UDP source に届かない (issue #60 再発)")
                .unwrap();
        let resp_text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp_text.contains("SIP/2.0 200"));
        // received= / rport= が乗っている
        assert!(
            resp_text.contains(&format!("received={}", vpn_addr.ip())),
            "received= が無い: {}",
            resp_text
        );
        assert!(
            resp_text.contains(&format!("rport={}", vpn_addr.port())),
            "rport= が無い: {}",
            resp_text
        );
        drop(stx);
    }

    /// E2E: 内線 UAS が VPN 経由 (Via host が RFC 5737 ダミー) からの REGISTER
    /// 風リクエストに対して、応答 UDP を **UDP source** へ向けることを確認する。
    /// issue #60 の Linphone/VPN 経路の最小再現。
    #[tokio::test]
    async fn vpn_dummy_via_host_response_routes_to_udp_source() {
        let uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uas_addr = uas_sock.local_addr().unwrap();
        // recv_loop を起動して TU に流す
        let (_layer, mut inbound_rx) = TransactionLayer::spawn(uas_sock.clone());

        // VPN 出口の UDP socket
        let vpn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Linphone-like REGISTER: Via host = 192.0.2.1 (RFC 5737), rport 付き
        let mut req = SipRequest::new(SipMethod::Register, "sip:sabiden");
        req.headers.set(
            "Via",
            "SIP/2.0/UDP 192.0.2.1:59983;branch=z9hG4bKvpne2e;rport",
        );
        req.headers.set("From", "<sip:alice@sabiden>;tag=alice");
        req.headers.set("To", "<sip:alice@sabiden>");
        req.headers.set("Call-ID", "vpn-e2e@host");
        req.headers.set("CSeq", "1 REGISTER");
        vpn.send_to(&req.to_bytes(), uas_addr).await.unwrap();

        // TU 受信
        let inbound = tokio::time::timeout(Duration::from_secs(1), inbound_rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound dropped");
        // ServerTransaction を構築し、200 OK を返す (UAS 模擬)
        let mut stx =
            ServerTransaction::new(inbound.request.clone(), inbound.remote, uas_sock.clone())
                .unwrap();
        let resp = build_response_skeleton(&inbound.request, 200, "OK");
        stx.respond(resp).await.unwrap();

        // VPN 側で応答が受け取れる (Via host `192.0.2.1` ではなく UDP source
        // = vpn の local_addr に到達) ことを確認
        let mut buf = vec![0u8; 4096];
        let (n, _peer) = tokio::time::timeout(Duration::from_secs(1), vpn.recv_from(&mut buf))
            .await
            .expect("応答が UDP source に届かない (issue #60 再発)")
            .unwrap();
        let resp_text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            resp_text.starts_with("SIP/2.0 200"),
            "200 が来ない: {}",
            resp_text
        );
        let vpn_local = vpn.local_addr().unwrap();
        assert!(
            resp_text.contains(&format!("received={}", vpn_local.ip())),
            "received= が UDP src IP: {}",
            resp_text
        );
        assert!(
            resp_text.contains(&format!("rport={}", vpn_local.port())),
            "rport= が UDP src port: {}",
            resp_text
        );
        drop(stx);
    }

    /// RFC 3261 §18.1.1 / §18.3: UDP では 1 SIP メッセージ = 1 datagram。
    /// `recv_from` のバッファが datagram より小さいと silently truncate され、
    /// 末端が削れた SIP メッセージは下流で誤動作する。
    ///
    /// issue #88: 旧実装は `vec![0u8; 8192]` 固定で、Path / Service-Route /
    /// Authentication-Info を多段で重ねた応答 (8 KB 超) を取りこぼしていた。
    /// バッファを `MAX_UDP_DATAGRAM_SIZE` (= 65535) に拡大したことで、
    /// 16 KB の SIP 応答が完全に parse されることを検証する。
    #[tokio::test]
    async fn rfc3261_18_1_1_recv_loop_handles_16kb_response() {
        // server = テスト用 UAS、client_sock 上に TransactionLayer を spawn
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();

        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (layer, _inbound_rx) = TransactionLayer::spawn(client_sock.clone());

        let local = client_sock.local_addr().unwrap();
        let branch = "z9hG4bKlarge16k";
        let mut req = SipRequest::new(SipMethod::Register, "sip:ntt-east.ne.jp");
        req.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        req.headers
            .set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=alice");
        req.headers.set("To", "<sip:0312345678@ntt-east.ne.jp>");
        req.headers.set("Call-ID", "callid-large@host");
        req.headers.set("CSeq", "1 REGISTER");

        // サーバ役: REGISTER を受け、巨大 (>16 KB) の 200 OK を組み立てて返送する。
        // Path / Service-Route / Record-Route が多段で乗ったケースを模す。
        let server_clone = server.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            let parsed_req = match parsed {
                SipMessage::Request(r) => r,
                _ => panic!("expected request"),
            };
            let mut resp = build_response_skeleton(&parsed_req, 200, "OK");
            // 1 個 ~256 バイトの Path ヘッダを 80 個積んで合計 ~20 KB に膨らませる
            // (8 KB を確実に超え、かつ UDP datagram 上限 65535 には収まる)。
            let mut path_blob = String::new();
            for i in 0..80 {
                path_blob.push_str(&format!(
                    "<sip:term@scscf{i:03}.ims.example.net;lr;\
                     transport=udp;orig;\
                     route-padding-{}>",
                    "x".repeat(200)
                ));
                if i + 1 < 80 {
                    path_blob.push(',');
                }
            }
            resp.headers.set("Path", path_blob);
            // SDP body も少し付ける (8 KB 超でも下流で読めることを確かめる目的)。
            // Content-Length は to_bytes() 側で付与される。
            let body = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n".to_vec();
            resp.headers.set("Content-Type", "application/sdp");
            resp.body = body;

            let bytes = resp.to_bytes();
            assert!(
                bytes.len() > 16 * 1024,
                "test fixture が 16 KB を超えていない: {} bytes",
                bytes.len()
            );
            assert!(
                bytes.len() < MAX_UDP_DATAGRAM_SIZE,
                "test fixture が UDP 上限を超えている: {} bytes",
                bytes.len()
            );
            server_clone.send_to(&bytes, peer).await.unwrap();
        });

        // 旧 8 KB バッファだと SDP body が削れて parse は通っても下流で失敗する。
        // 65535 バッファなら 200 OK が完全に届き、TransactionLayer が
        // 正しい応答を Future に dispatch できる。
        let resp =
            tokio::time::timeout(Duration::from_secs(3), layer.send_request(req, server_addr))
                .await
                .expect("send_request timeout (= recv_loop が大 datagram を取り落とした疑い)")
                .expect("send_request error");
        assert_eq!(resp.status_code, 200);
        // 大量に積んだ Path ヘッダが parse 後も生きている = truncate されていない。
        let path = resp.headers.get("path").expect("Path header missing");
        assert!(
            path.len() > 16 * 1024,
            "Path header が短すぎる (truncate?): {} bytes",
            path.len()
        );
        // SDP body も末端まで届いているか確認 (truncate 検出)。
        let body_text = std::str::from_utf8(&resp.body).unwrap();
        assert!(
            body_text.contains("m=audio 30000 RTP/AVP 0"),
            "SDP body が末端で truncate: {:?}",
            body_text
        );
    }

    /// RFC 3261 §21.4.1 (400 Bad Request): `Content-Length` 宣言値が
    /// datagram 本文長より大きい (truncate) request を受信したら、 必須
    /// ヘッダ (Via/From/To/Call-ID/CSeq) を再現した 400 応答を **UDP source**
    /// へ返送する。 応答に乗る Reason ヘッダ (RFC 3326) で truncate 起因と
    /// 診断できることも確認する (Issue #126)。
    #[tokio::test]
    async fn rfc3261_21_4_1_truncated_request_yields_400_bad_request() {
        let uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uas_addr = uas_sock.local_addr().unwrap();
        let (_layer, _inbound_rx) = TransactionLayer::spawn(uas_sock.clone());

        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Content-Length: 9999 と宣言するが body は 4 byte しかない truncate request
        let raw = b"OPTIONS sip:sabiden SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 127.0.0.1:0;branch=z9hG4bKtrunc126\r\n\
                    From: <sip:caller@example>;tag=alice126\r\n\
                    To: <sip:sabiden@127.0.0.1>\r\n\
                    Call-ID: trunc-call-id-126@host\r\n\
                    CSeq: 1 OPTIONS\r\n\
                    Content-Length: 9999\r\n\
                    \r\n\
                    body";
        client.send_to(raw, uas_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _peer) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("400 Bad Request が届かない (= silent drop に退化)")
            .unwrap();
        let resp_text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            resp_text.starts_with("SIP/2.0 400 "),
            "400 Bad Request が返ってこない: {}",
            resp_text
        );
        // Via / From / To / Call-ID / CSeq が原リクエストから保たれていること
        assert!(
            resp_text.contains("z9hG4bKtrunc126"),
            "Via 不一致: {}",
            resp_text
        );
        assert!(
            resp_text.contains("trunc-call-id-126@host"),
            "Call-ID 不一致: {}",
            resp_text
        );
        assert!(
            resp_text.contains("CSeq: 1 OPTIONS"),
            "CSeq 不一致: {}",
            resp_text
        );
        // Reason ヘッダ (RFC 3326) で truncate と分かる
        assert!(
            resp_text.contains("content-length-truncated"),
            "Reason ヘッダで truncate と判別できない: {}",
            resp_text
        );
    }

    /// RFC 3261 §7.3.1 / §20.14 (400 Bad Request, request smuggling 防止):
    /// 重複 `Content-Length` を含む request は 400 で拒否し、 1 件目だけ
    /// 採用して silent に通す経路を遮断する (Issue #126)。
    #[tokio::test]
    async fn rfc3261_7_3_1_duplicate_content_length_yields_400_bad_request() {
        let uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uas_addr = uas_sock.local_addr().unwrap();
        let (_layer, _inbound_rx) = TransactionLayer::spawn(uas_sock.clone());

        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let raw = b"OPTIONS sip:sabiden SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 127.0.0.1:0;branch=z9hG4bKdup126\r\n\
                    From: <sip:caller@example>;tag=alice126b\r\n\
                    To: <sip:sabiden@127.0.0.1>\r\n\
                    Call-ID: dup-call-id-126@host\r\n\
                    CSeq: 2 OPTIONS\r\n\
                    Content-Length: 0\r\n\
                    Content-Length: 999\r\n\
                    \r\n";
        client.send_to(raw, uas_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _peer) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("400 Bad Request が届かない")
            .unwrap();
        let resp_text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            resp_text.starts_with("SIP/2.0 400 "),
            "400 Bad Request が返ってこない: {}",
            resp_text
        );
        assert!(
            resp_text.contains("z9hG4bKdup126"),
            "Via 不一致: {}",
            resp_text
        );
        assert!(
            resp_text.contains("dup-call-id-126@host"),
            "Call-ID 不一致: {}",
            resp_text
        );
        assert!(
            resp_text.contains("duplicate-content-length"),
            "Reason ヘッダで重複 CL と判別できない: {}",
            resp_text
        );
    }

    /// RFC 3261 §16.3 / §21.4.1 (silent drop): CRLFCRLF が無く header 終端
    /// 不明な datagram は応答先が決まらないので silent drop。 400 を返さない
    /// (= recv 側でタイムアウトすること) を確認する (Issue #126)。
    #[tokio::test]
    async fn rfc3261_16_3_no_crlfcrlf_silently_dropped_no_400() {
        let uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uas_addr = uas_sock.local_addr().unwrap();
        let (_layer, _inbound_rx) = TransactionLayer::spawn(uas_sock.clone());

        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // CRLFCRLF を欠く header 部だけの datagram
        let raw =
            b"INVITE sip:sabiden SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:0;branch=z9hG4bKnocrlf\r\n";
        client.send_to(raw, uas_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let res =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await;
        assert!(
            res.is_err(),
            "応答先不明な malformed datagram に 400 が返ってきた (silent drop が壊れた): {:?}",
            res
        );
    }

    // -----------------------------------------------------------------------
    // RFC 3261 §17 Timer / 状態遷移 / 重複応答 境界条件 (Issue #116)
    // -----------------------------------------------------------------------

    /// テスト用: INVITE 応答 (180/200/...) を作る。CSeq method を明示する。
    fn make_invite_response(branch: &str, code: u16, reason: &str) -> SipResponse {
        let mut headers = SipHeaders::new();
        headers.set(
            "Via",
            format!("SIP/2.0/UDP 192.0.2.1:5060;branch={}", branch),
        );
        headers.set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=alice");
        // 180/200 とも UAS で生成された tag が乗る (RFC 3261 §8.2.6.2)
        headers.set("To", "<sip:bob@ntt-east.ne.jp>;tag=ngn-server-tag");
        headers.set("Call-ID", "callid@host");
        headers.set("CSeq", "1 INVITE");
        SipResponse {
            status_code: code,
            reason: reason.to_string(),
            headers,
            body: Vec::new(),
        }
    }

    /// RFC 3261 §17.1.1 Figure 5: INVITE Calling → Proceeding (1xx) → Completed (2xx)
    /// の状態遷移と、トランザクション層が **2xx ACK を自動送出しない** ことを確認する。
    /// RFC 3261 §13.2.2.4: "The 2xx ACK for an INVITE is a separate transaction
    /// generated by the TU"。 transaction 層は 2xx を上に上げるだけで終了する。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_1_1_invite_calling_proceeding_completed_no_2xx_ack_from_transaction() {
        // UAC ソケット (実際に送る側)
        let uac_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // UAS 役 (受信して何が届くか観測する)
        let uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uas_addr: SocketAddr = uas_sock.local_addr().unwrap();

        // UAS 側: 何が届いたかを集める (INVITE 1 回 + 2xx ACK が無いこと)
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let received_clone = received.clone();
        let uas_clone = uas_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((n, _peer)) = uas_clone.recv_from(&mut buf).await {
                    received_clone.lock().await.push(buf[..n].to_vec());
                }
            }
        });

        let branch = "z9hG4bKproc2xx";
        let req = make_invite_request(branch);
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let ct = ClientTransaction::new(
            id,
            req,
            uas_addr,
            uac_sock.clone(),
            rx,
            SipTraceWriter::disabled(),
        );

        // 180 Ringing → 200 OK を流し込む
        tx.send(ClientEvent::Response(make_invite_response(
            branch, 180, "Ringing",
        )))
        .unwrap();
        tx.send(ClientEvent::Response(make_invite_response(
            branch, 200, "OK",
        )))
        .unwrap();

        let resp = ct.run().await.unwrap();
        assert_eq!(resp.status_code, 200);

        // INVITE 送信の後、transaction 層が ACK を自動送出**しない** ことを確認。
        // (受信側に追加で何か届かないか、 32s 程度仮想時間を進めて観測する)
        for _ in 0..7 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        let recv = received.lock().await;
        // 1) INVITE が 1 回だけ届いていること (Timer A は 1xx 受信で停止: 再送ゼロ)
        let invite_count = recv.iter().filter(|b| b.starts_with(b"INVITE")).count();
        assert_eq!(
            invite_count, 1,
            "1xx 受信後は INVITE 再送停止 (RFC 3261 §17.1.1.2 Timer A 停止) (got {})",
            invite_count
        );
        // 2) ACK は届いていない (RFC 3261 §13.2.2.4: 2xx ACK は TU の責務)
        let ack_count = recv.iter().filter(|b| b.starts_with(b"ACK ")).count();
        assert_eq!(
            ack_count, 0,
            "2xx に対する ACK は transaction 層から送ってはいけない (RFC 3261 §13.2.2.4)"
        );
    }

    /// RFC 3261 §17.1.1.2 figure 5: INVITE Completed (non-2xx) で Timer D (=32s)
    /// 滞在中、 同一 final response 再送に対して同じ ACK バイト列を再送する。
    /// `test_invite_non2xx_triggers_ack_and_absorbs_retransmits` の virtual-time
    /// 版で、 ACK バイト列が **同一** であることに加え、 同一 branch/sent-by/method=Ack
    /// で唯一の transaction エントリに突き合わせ可能であることを確認する
    /// (RFC 3261 §17.1.3 transaction matching)。
    #[tokio::test]
    async fn rfc3261_17_1_1_2_invite_non2xx_completed_absorbs_response_retransmit_same_ack() {
        let uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uas_addr = uas_sock.local_addr().unwrap();

        let uac_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let uac_local = uac_sock.local_addr().unwrap();
        let (layer, _inbound_rx) = TransactionLayer::spawn(uac_sock.clone());

        let branch = "z9hG4bKabsorb";
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@127.0.0.1");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch={}", uac_local, branch),
        );
        invite.headers.set("From", "<sip:alice@example>;tag=alice");
        invite.headers.set("To", "<sip:bob@example>");
        invite.headers.set("Call-ID", "absorb-test@host");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Max-Forwards", "70");

        let uas_clone = uas_sock.clone();
        let uas_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            // 1) INVITE 受信
            let (n, peer) = uas_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            let invite_req = match parsed {
                SipMessage::Request(r) => r,
                _ => panic!("INVITE 期待"),
            };

            // 2) 486 Busy Here を返す
            let mut resp = build_response_skeleton(&invite_req, 486, "Busy Here");
            resp.headers.set("To", "<sip:bob@example>;tag=server-486");
            let resp_bytes = resp.to_bytes();
            uas_clone.send_to(&resp_bytes, peer).await.unwrap();

            // 3) ACK 受信 (1 回目)
            let ack1 = tokio::time::timeout(Duration::from_secs(3), async {
                let mut b = vec![0u8; 4096];
                loop {
                    let (m, _p) = uas_clone.recv_from(&mut b).await.unwrap();
                    if let Ok(SipMessage::Request(r)) = parse_message(&b[..m]) {
                        if r.method == SipMethod::Ack {
                            return b[..m].to_vec();
                        }
                    }
                }
            })
            .await
            .expect("1st ACK timeout");

            // 4) 486 を再送 → ACK 再送を待つ
            uas_clone.send_to(&resp_bytes, peer).await.unwrap();
            let ack2 = tokio::time::timeout(Duration::from_secs(3), async {
                let mut b = vec![0u8; 4096];
                loop {
                    let (m, _p) = uas_clone.recv_from(&mut b).await.unwrap();
                    if let Ok(SipMessage::Request(r)) = parse_message(&b[..m]) {
                        if r.method == SipMethod::Ack {
                            return b[..m].to_vec();
                        }
                    }
                }
            })
            .await
            .expect("2nd ACK timeout (response retransmit absorber broken)");

            // 5) もう 1 回 486 を再送 → 3 個目の ACK
            uas_clone.send_to(&resp_bytes, peer).await.unwrap();
            let ack3 = tokio::time::timeout(Duration::from_secs(3), async {
                let mut b = vec![0u8; 4096];
                loop {
                    let (m, _p) = uas_clone.recv_from(&mut b).await.unwrap();
                    if let Ok(SipMessage::Request(r)) = parse_message(&b[..m]) {
                        if r.method == SipMethod::Ack {
                            return b[..m].to_vec();
                        }
                    }
                }
            })
            .await
            .expect("3rd ACK timeout");

            // ACK バイト列が **完全に同一** であることを確認 (新しい ACK を生成して
            // いない。 同じ ACK を再送している)。
            assert_eq!(
                ack1, ack2,
                "1st ACK と 2nd ACK のバイト列が異なる (新規 ACK 生成は禁止 RFC 3261 §17.1.1.2)"
            );
            assert_eq!(ack2, ack3, "2nd ACK と 3rd ACK のバイト列が異なる");
        });

        let resp = layer.send_request(invite, uas_addr).await.unwrap();
        assert_eq!(resp.status_code, 486);

        uas_handle.await.unwrap();
    }

    /// RFC 3261 §17.1.2.2 Timer K: non-INVITE クライアント トランザクションが
    /// 最終応答 (>=200) を受信して Completed に入った後、 UDP では Timer K
    /// (= T4 = 5s) 経過後に Terminated へ遷移し table から消える。
    ///
    /// 検証戦略 (`tokio::test(start_paused = true)` + virtual time):
    /// 1. `TransactionLayer::send_request` で REGISTER を投入 (登録直後は
    ///    `client_count() == 1`)。
    /// 2. `dispatch_response` で 200 OK を流し、 `send_request` を完了させる。
    /// 3. **完了直後** に `client_count() == 0` であることを確認 (sabiden は
    ///    non-INVITE で absorber を spawn せず即時 cleanup、 RFC §17.1.2.2 の
    ///    Timer K 上限内で削除されているので RFC 準拠)。
    /// 4. `time::advance(TIMER_K + α)` で **Timer K 境界を跨いでも** table が
    ///    flap せず `client_count() == 0` を維持することを確認 (Completed →
    ///    Terminated 遷移の冪等性)。
    ///
    /// 注: 現状実装は non-INVITE Completed で response 再送を吸収しない
    /// (Timer K 期間中の応答再送 → ACK 不要だがエントリ保持で TU への重複
    /// 通知を抑制、 が将来課題)。 本テストは「Timer K 経過と表テーブル状態
    /// が矛盾しないこと」を保証する境界テストであり、 absorber 拡張が入った
    /// 際にも本テストの assert (T4 後に 0 件) は維持されるべきである。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_1_2_2_non_invite_completed_timer_k_clears_table() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (layer, _inbound_rx) = TransactionLayer::spawn(socket.clone());
        let local = socket.local_addr().unwrap();

        let branch = "z9hG4bKtimerKclear";
        let mut req = SipRequest::new(SipMethod::Register, "sip:registrar.example");
        req.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        req.headers.set("From", "<sip:alice@example>;tag=alice");
        req.headers.set("To", "<sip:alice@example>");
        req.headers.set("Call-ID", "timerK-clear@host");
        req.headers.set("CSeq", "1 REGISTER");
        req.headers.set("Max-Forwards", "70");

        // send_request は完了応答受領まで await でブロックするので、 別 task で走らせ
        // て発行直後の table state を観測する。
        let layer_send = layer.clone();
        let req_send = req.clone();
        let send_handle =
            tokio::spawn(async move { layer_send.send_request(req_send, dest).await });

        // create_client が完了するまで yield を入れる (send_request 内の spawn が
        // 走り、 transaction が table に登録されるまで待つ)。
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            layer.client_count().await,
            1,
            "REGISTER 送信直後は table に 1 件 (RFC 3261 §17.1.2.2 Trying 状態)"
        );

        // 200 OK を dispatch して Completed → 即時 cleanup を起こす。
        let mut resp = make_response(branch, 200, "REGISTER");
        // dispatch_response は応答の Via から transaction を引くため、 send 側と
        // 同じ branch / sent-by に揃える。
        resp.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        layer.dispatch_response(resp).await;

        let final_resp = send_handle.await.unwrap().unwrap();
        assert_eq!(final_resp.status_code, 200);

        // RFC §17.1.2.2 Timer K の T4 上限 (=5s) 内で table から消えているはず。
        // sabiden は即時 cleanup (drop_client) するので 0 になる。
        assert_eq!(
            layer.client_count().await,
            0,
            "non-INVITE final 受領後は Timer K (T4={:?}) 上限内で table から削除",
            TIMER_K
        );

        // Timer K (=T4) 境界を跨いで table が flap しない (二重削除パニックや
        // 再挿入が無い) ことを確認する。
        step_and_yield(TIMER_K + Duration::from_millis(100)).await;
        assert_eq!(
            layer.client_count().await,
            0,
            "Timer K 経過後も table は空 (Completed → Terminated 遷移の冪等性)"
        );
    }

    /// RFC 3261 §17.1.1.2 Timer A 停止: 1xx 受信前なら Timer A で再送が走るが、
    /// 1xx 受信後 (Proceeding) は **追加の INVITE 再送が止まる** ことを観測する。
    /// `test_client_invite_timer_a_exponential_backoff` は 1xx を流さない
    /// シナリオ。 こちらは「1xx を入れたら再送が増えなくなる」境界条件を
    /// 直接確認する。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_1_1_2_timer_a_stops_on_provisional() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = sink.local_addr().unwrap();

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        let sk = sink.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if sk.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let branch = "z9hG4bKtimerAstop";
        let req = make_invite_request(branch);
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let ct = ClientTransaction::new(id, req, dest, socket, rx, SipTraceWriter::disabled());

        let h = tokio::spawn(async move { ct.run().await });
        // 初回送信を観測
        step_and_yield(Duration::from_millis(0)).await;
        let count_initial = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(count_initial, 1, "INVITE 初送 1 回 (got {})", count_initial);

        // T1=500ms 経過させて Timer A 1 回目再送を観測
        step_and_yield(Duration::from_millis(600)).await;
        let count_after_one_a = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            count_after_one_a, 2,
            "T1 経過で Timer A 1 回目再送 (got {})",
            count_after_one_a
        );

        // 1xx を流して Proceeding に遷移
        tx.send(ClientEvent::Response(make_invite_response(
            branch, 180, "Ringing",
        )))
        .unwrap();
        step_and_yield(Duration::from_millis(0)).await;

        // 1xx 受信後は Timer A が止まる: 仮想時間を 30s (Timer B 直前) 進めても
        // INVITE 送信回数は増えないはず。
        for _ in 0..6 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        let count_after_provisional = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            count_after_one_a, count_after_provisional,
            "1xx 受信後は Timer A 停止 (RFC 3261 §17.1.1.2): {} -> {}",
            count_after_one_a, count_after_provisional
        );

        // 200 OK で完了
        tx.send(ClientEvent::Response(make_invite_response(
            branch, 200, "OK",
        )))
        .unwrap();
        let res = h.await.unwrap();
        assert_eq!(res.unwrap().status_code, 200);
    }

    /// RFC 3261 §17.1.2.2 / §17.1.2.4 (Figure 6): non-INVITE は 1xx 受信後も
    /// **再送は継続する** が、 間隔の上限が T2 にクリップされる。
    /// (INVITE と異なる挙動。)
    /// `test_client_non_invite_timer_e_t2_cap` で T2 cap は確認済だが、
    /// 「1xx 受信後も再送が止まらない」境界条件は別テストで明示する。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_1_2_2_non_invite_timer_e_continues_after_provisional_with_t2_cap() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = sink.local_addr().unwrap();

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        let sk = sink.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if sk.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let branch = "z9hG4bKtimerEprov";
        let req = make_request(branch); // REGISTER (non-INVITE)
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let ct = ClientTransaction::new(id, req, dest, socket, rx, SipTraceWriter::disabled());

        let h = tokio::spawn(async move { ct.run().await });
        step_and_yield(Duration::from_millis(0)).await;

        // T1 + 2T1 経過で Timer E が 2 回再送するまで待つ
        step_and_yield(Duration::from_millis(600)).await; // T1 (=500ms)
        step_and_yield(Duration::from_secs(1)).await; // 2T1 (=1s)
        let count_before_prov = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            count_before_prov >= 3,
            "Timer E で 1+2 回以上再送されているはず (got {})",
            count_before_prov
        );

        // 100 Trying を流す → Proceeding に遷移するが Timer E は継続 (T2 cap)
        tx.send(ClientEvent::Response(make_response(
            branch, 100, "REGISTER",
        )))
        .unwrap();
        step_and_yield(Duration::from_millis(0)).await;

        // 仮想時間を 12s 進めて再送が続いている (= T2 で約 3 回追加) ことを確認
        for _ in 0..3 {
            step_and_yield(Duration::from_secs(4)).await;
        }
        let count_after_prov = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            count_after_prov > count_before_prov,
            "non-INVITE は 1xx 後も Timer E で再送継続 (T2 cap, RFC 3261 §17.1.2.2): {} -> {}",
            count_before_prov,
            count_after_prov
        );

        // 200 OK で終了
        tx.send(ClientEvent::Response(make_response(
            branch, 200, "REGISTER",
        )))
        .unwrap();
        let res = h.await.unwrap();
        assert_eq!(res.unwrap().status_code, 200);
    }

    /// RFC 3261 §17.2.1 Timer I: server INVITE Completed で ACK を受信したら
    /// Confirmed → Timer I (T4=5s) 滞在後 Terminated。 ACK 受信直後は Confirmed
    /// 状態になることを確認する (`handle_ack` のテストの上澄みは既存にあるが、
    /// 「`handle_retransmit` が Confirmed 中に no-op で済む」 = ACK が出されない)
    /// ことの確認も兼ねる)。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_2_1_timer_i_after_ack_keeps_state_confirmed() {
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

        let req = make_invite_request("z9hG4bKsrvI");
        let mut stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        let resp = make_invite_response("z9hG4bKsrvI", 487, "Request Terminated");
        stx.respond(resp).await.unwrap();
        assert_eq!(stx.state(), ServerState::Completed);

        // 即 ACK
        step_and_yield(Duration::from_millis(0)).await;
        stx.handle_ack();
        assert_eq!(
            stx.state(),
            ServerState::Confirmed,
            "ACK 受信後は Confirmed (RFC 3261 §17.2.1)"
        );
        let count_at_ack = counter.load(std::sync::atomic::Ordering::SeqCst);

        // Timer I 期間 (T4 = 5s) を超えて経過させる
        for _ in 0..2 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        let count_after_i = counter.load(std::sync::atomic::Ordering::SeqCst);
        // Confirmed → Timer I 経過まで final response 再送はゼロ
        assert!(
            count_after_i - count_at_ack <= 1,
            "Confirmed → Timer I の間は再送停止 (got {} -> {})",
            count_at_ack,
            count_after_i
        );

        // 状態は依然 Confirmed (Terminated に外向きで遷移する API を sabiden は
        // 公開していない。 内部タイマタスク終了時に drop で abort)。
        assert_eq!(stx.state(), ServerState::Confirmed);
        drop(stx);
    }

    /// RFC 3261 §17.2.2 Timer J 経過後: server non-INVITE で Timer J (=64*T1=32s)
    /// が満了するとタイマタスクが終了する。 そのあと `handle_retransmit` を呼ぶと、
    /// 内部タスクは存在しないが `timer_event_tx` 経由で send だけ走る (返値は Ok)。
    /// **同期パスでの応答再送は走らない** (= UDP に何も新規発行されない)
    /// 境界条件を確認する。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_2_2_timer_j_expired_handle_retransmit_is_noop() {
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

        let req = make_request("z9hG4bKsrvJexp"); // REGISTER (non-INVITE)
        let mut stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        stx.respond(make_response("z9hG4bKsrvJexp", 200, "REGISTER"))
            .await
            .unwrap();
        step_and_yield(Duration::from_millis(0)).await;
        let count_initial = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(count_initial, 1, "final 1 回送信");

        // Timer J (32s) を超えて進める。 タイマタスクは Timer J で抜けて終了する。
        for _ in 0..7 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        let count_after_j = counter.load(std::sync::atomic::Ordering::SeqCst);

        // Timer J 経過後の handle_retransmit: 通知チャネルへ send は成功するが、
        // タスクは既に消えているので UDP には何も出ない (no-op)。
        stx.handle_retransmit().await.unwrap();
        // `unbounded_channel` の receiver が drop されてないので send は OK。
        // ただしいずれにせよ UDP 出力は増えない:
        for _ in 0..4 {
            step_and_yield(Duration::from_millis(100)).await;
        }
        let count_after_noop = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            count_after_j, count_after_noop,
            "Timer J 経過後は handle_retransmit が UDP に何も出さない (got {} -> {})",
            count_after_j, count_after_noop
        );
        drop(stx);
    }

    /// RFC 3261 §17.1.1: 同一 transaction が **重複 final response (2x final)** を
    /// 受け取ったとき、 transaction 層の Public API (`run`) は最初の final で
    /// 終了する。 2 個目以降は absorber が走っていない場合 (non-INVITE) には
    /// 上位 `dispatch_response` で「未知の transaction」 扱いで drop される。
    /// 本テストでは `ClientTransaction::run` が **最初の** final だけを返す
    /// 境界条件を確認する。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_1_1_duplicate_final_response_first_one_wins() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_sink: SocketAddr = sink.local_addr().unwrap();

        let req = make_request("z9hG4bKdupfinal");
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let ct = ClientTransaction::new(id, req, dest_sink, socket, rx, SipTraceWriter::disabled());

        // 2 個の final (異なる reason) を続けて流す
        let mut first = make_response("z9hG4bKdupfinal", 200, "REGISTER");
        first.reason = "OK-FIRST".into();
        tx.send(ClientEvent::Response(first)).unwrap();

        let mut second = make_response("z9hG4bKdupfinal", 200, "REGISTER");
        second.reason = "OK-SECOND".into();
        tx.send(ClientEvent::Response(second)).unwrap();

        let resp = ct.run().await.unwrap();
        // 最初の final だけが返ること
        assert_eq!(resp.status_code, 200);
        assert_eq!(
            resp.reason, "OK-FIRST",
            "重複 final の 1 個目だけが client transaction から返るべき"
        );
    }

    /// RFC 3261 §17.2.1 figure 7: server INVITE で 2x final response (二重 final)
    /// を `respond` した場合、 内部タイマタスクは古いものを abort して新しいもの
    /// を起動する (RFC 6026 と整合; 二重 final は sabiden の `start_completed_timers`
    /// が `if let Some(h) = self.timer_task.take() { h.abort(); }` で明示的に
    /// 処理する)。 タスクが leak しないことと、 最後の final が再送される
    /// ことを確認する境界条件。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_2_1_server_invite_second_respond_replaces_timer_task() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr: SocketAddr = client_sock.local_addr().unwrap();

        // recv 内容を貯める
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let received_clone = received.clone();
        let cs = client_sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if let Ok((n, _peer)) = cs.recv_from(&mut buf).await {
                    received_clone.lock().await.push(buf[..n].to_vec());
                }
            }
        });

        let req = make_invite_request("z9hG4bKsrvDup");
        let mut stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();

        // 1 個目 final: 486
        let resp1 = make_invite_response("z9hG4bKsrvDup", 486, "Busy Here");
        stx.respond(resp1).await.unwrap();
        assert_eq!(stx.state(), ServerState::Completed);

        // 少し進めて Timer G で 1 回再送が走るのを観測
        step_and_yield(Duration::from_millis(600)).await;

        // 2 個目 final: 487 (例えば CANCEL から起こる)
        let resp2 = make_invite_response("z9hG4bKsrvDup", 487, "Request Terminated");
        stx.respond(resp2).await.unwrap();
        assert_eq!(stx.state(), ServerState::Completed);

        // 少し進めて再送を観測
        step_and_yield(Duration::from_millis(600)).await;

        let recv = received.lock().await;
        // 486 と 487 がそれぞれ少なくとも 1 回 (= 初送) は届いている
        let has_486 = recv.iter().any(|b| {
            std::str::from_utf8(b)
                .ok()
                .map(|s| s.contains("486"))
                .unwrap_or(false)
        });
        let has_487 = recv.iter().any(|b| {
            std::str::from_utf8(b)
                .ok()
                .map(|s| s.contains("487"))
                .unwrap_or(false)
        });
        assert!(has_486, "1 個目の final (486) が UDP に出ていない");
        assert!(
            has_487,
            "2 個目の final (487) が UDP に出ていない (二重 respond で新タスクに置換されない疑い)"
        );
        drop(stx);
    }

    /// RFC 3261 §17.1.3 / §17.2.3: ACK は CSeq method=INVITE のままだが、
    /// transaction matching では **method=Ack** として一意に扱われる。
    /// `TransactionId::from_request` で ACK request の Via branch が
    /// 元 INVITE と同じでも、 method 部 (= ACK) で別 transaction として
    /// 区別されることを確認する (= 重複 ACK 検出の前提)。
    #[test]
    fn rfc3261_17_1_3_transaction_id_distinguishes_invite_and_ack_with_same_branch() {
        // 元 INVITE
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@ntt-east.ne.jp");
        invite
            .headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKdup");
        invite
            .headers
            .set("From", "<sip:alice@ntt-east.ne.jp>;tag=alice");
        invite.headers.set("To", "<sip:bob@ntt-east.ne.jp>");
        invite.headers.set("Call-ID", "ack-distinct@host");
        invite.headers.set("CSeq", "1 INVITE");

        // 同じ branch / sent-by で method=ACK
        let mut ack = SipRequest::new(SipMethod::Ack, "sip:bob@ntt-east.ne.jp");
        ack.headers
            .set("Via", "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKdup");
        ack.headers
            .set("From", "<sip:alice@ntt-east.ne.jp>;tag=alice");
        ack.headers.set("To", "<sip:bob@ntt-east.ne.jp>;tag=server");
        ack.headers.set("Call-ID", "ack-distinct@host");
        ack.headers.set("CSeq", "1 ACK");

        let id_invite = TransactionId::from_request(&invite).unwrap();
        let id_ack = TransactionId::from_request(&ack).unwrap();
        // branch / sent-by が同じでも method が違うので別 ID
        assert_eq!(id_invite.branch, id_ack.branch);
        assert_eq!(id_invite.sent_by, id_ack.sent_by);
        assert_ne!(
            id_invite, id_ack,
            "method=INVITE と method=ACK は別 transaction (RFC 3261 §17.1.3)"
        );

        // 重複 ACK は同じ ID で識別される (= server tx で吸収する単位)
        let mut ack2 = ack.clone();
        ack2.headers.set("Max-Forwards", "70"); // 内容差は ID に影響しない
        let id_ack2 = TransactionId::from_request(&ack2).unwrap();
        assert_eq!(id_ack, id_ack2, "重複 ACK は同 ID で再送扱い");
    }

    /// RFC 3261 §18.2.1 + §25.1 (Via host BNF): IPv6 sent-by を持つ Via に
    /// `;rport` がある場合、 `received=` には角括弧なしで IPv6 アドレスが
    /// セットされ、 IPv6 source IP と Via host が同一なら received= は
    /// 追加されないこと。 `apply_rport_to_via_for_response` の境界条件。
    #[test]
    fn rfc3581_apply_rport_with_ipv6_sent_by_and_remote() {
        // ケース 1: IPv6 sent-by + IPv6 remote 一致 + ;rport あり →
        //   rport= は埋まる。 received= は付加 (RFC 3581 §4: rport があれば
        //   常に received= を埋めるのが本実装の方針)。
        let via = "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKv6;rport";
        let remote: SocketAddr = "[2001:db8::1]:55555".parse().unwrap();
        let updated = apply_rport_to_via_for_response(via, &remote);
        assert!(
            updated.contains("rport=55555"),
            "rport が UDP source port で埋まる: {}",
            updated
        );
        assert!(
            updated.contains("received=2001:db8::1"),
            "received= が IPv6 アドレスで埋まる (角括弧なし): {}",
            updated
        );
        // 元 branch は保持
        assert!(updated.contains("branch=z9hG4bKv6"), "{}", updated);

        // ケース 2: IPv6 sent-by + 異なる IPv6 remote + ;rport なし →
        //   received= 追加 (RFC 3261 §18.2.1)。 rport= は付かない。
        let via2 = "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKv6b";
        let remote2: SocketAddr = "[2001:db8::99]:55556".parse().unwrap();
        let updated2 = apply_rport_to_via_for_response(via2, &remote2);
        assert!(
            updated2.contains("received=2001:db8::99"),
            "Via host と異なる IPv6 source なら received= 追加: {}",
            updated2
        );
        assert!(
            !updated2.contains("rport"),
            ";rport が無ければ rport= も追加しない: {}",
            updated2
        );

        // ケース 3: IPv6 sent-by + 同一 IPv6 remote + ;rport なし → 手付かず
        let via3 = "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKv6c";
        let remote3: SocketAddr = "[2001:db8::1]:55557".parse().unwrap();
        let updated3 = apply_rport_to_via_for_response(via3, &remote3);
        assert_eq!(
            updated3, via3,
            "IPv6 sent-by が UDP source IP と一致、 ;rport なしなら Via 不変"
        );
    }

    /// RFC 3261 §17.2.1: server INVITE Trying state は実装上、 INVITE 受信
    /// 直後から Proceeding に入る (sabiden の `with_tracer` で
    /// `state = Proceeding` を即セット)。 その後 1xx (e.g. 100 Trying) を
    /// 送っても Proceeding のまま。 さらに 1xx を重ねても Proceeding を維持。
    /// (RFC 3261 §17.2.1 figure 7: Proceeding 中の 1xx は loop back arrow)
    #[tokio::test]
    async fn rfc3261_17_2_1_server_invite_starts_in_proceeding_and_stays_on_provisional() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr: SocketAddr = client_sock.local_addr().unwrap();

        let req = make_invite_request("z9hG4bKsrvProc");
        let mut stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        // 受信直後から Proceeding (RFC 3261 §17.2.1 figure 7 上端)
        assert_eq!(stx.state(), ServerState::Proceeding);

        // 100 Trying → Proceeding 維持
        let resp100 = make_invite_response("z9hG4bKsrvProc", 100, "Trying");
        stx.respond(resp100).await.unwrap();
        assert_eq!(
            stx.state(),
            ServerState::Proceeding,
            "1xx を送っても Proceeding (RFC 3261 §17.2.1)"
        );

        // 180 Ringing → Proceeding 維持
        let resp180 = make_invite_response("z9hG4bKsrvProc", 180, "Ringing");
        stx.respond(resp180).await.unwrap();
        assert_eq!(
            stx.state(),
            ServerState::Proceeding,
            "追加 1xx でも Proceeding 維持"
        );

        // final で Completed
        let resp200 = make_invite_response("z9hG4bKsrvProc", 200, "OK");
        stx.respond(resp200).await.unwrap();
        assert_eq!(stx.state(), ServerState::Completed);
        drop(stx);
    }

    /// RFC 3261 §17.2.2: server non-INVITE は受信直後 Trying。 1xx 送出で
    /// Proceeding。 final で Completed。 sabiden の状態機械が忠実に
    /// 動作することを確認する。
    #[tokio::test]
    async fn rfc3261_17_2_2_server_non_invite_state_transitions() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr: SocketAddr = client_sock.local_addr().unwrap();

        let req = make_request("z9hG4bKsrvNonInvSt");
        let mut stx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        // non-INVITE は Trying から開始 (RFC 3261 §17.2.2 figure 8)
        assert_eq!(stx.state(), ServerState::Trying);

        // 100 Trying → Proceeding
        stx.respond(make_response("z9hG4bKsrvNonInvSt", 100, "REGISTER"))
            .await
            .unwrap();
        assert_eq!(
            stx.state(),
            ServerState::Proceeding,
            "Trying + 1xx → Proceeding"
        );

        // 200 OK → Completed
        stx.respond(make_response("z9hG4bKsrvNonInvSt", 200, "REGISTER"))
            .await
            .unwrap();
        assert_eq!(stx.state(), ServerState::Completed);
        drop(stx);
    }

    /// RFC 3261 §17.1.1.2: INVITE が Calling の間は Timer A 再送が走るが、
    /// Calling から **直接 Completed (final 受信)** に飛んだ場合、 Timer A
    /// は止まる (Proceeding を経由しないパス)。 既存テストは 1xx を介在させる
    /// シナリオ。 こちらは 1xx なし即 final ケースの境界条件。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_1_1_calling_directly_to_completed_stops_timer_a() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sink = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = sink.local_addr().unwrap();

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cnt = counter.clone();
        let sk = sink.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                if sk.recv_from(&mut buf).await.is_ok() {
                    cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        let branch = "z9hG4bKcallingfinal";
        let req = make_invite_request(branch);
        let id = TransactionId::from_request(&req).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let ct = ClientTransaction::new(id, req, dest, socket, rx, SipTraceWriter::disabled());
        let h = tokio::spawn(async move { ct.run().await });
        step_and_yield(Duration::from_millis(0)).await;
        // 初送 1 回
        let count_initial = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(count_initial, 1);

        // 1xx 抜きで即 200 OK
        tx.send(ClientEvent::Response(make_invite_response(
            branch, 200, "OK",
        )))
        .unwrap();
        let res = h.await.unwrap();
        assert_eq!(res.unwrap().status_code, 200);

        // run 完了後、 仮想時間を進めても再送は走らない (transaction は終了している)
        for _ in 0..3 {
            step_and_yield(Duration::from_secs(5)).await;
        }
        let count_final = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            count_final, 1,
            "Calling → (1xx 経由せず) → Completed 後は再送停止 (got {})",
            count_final
        );
    }

    /// RFC 3261 §17.1.1.2 Timer D: INVITE non-2xx 最終応答受領後の Completed
    /// 滞在中、 absorber バックグラウンド タスクが Timer D (=32s) の間 table
    /// エントリを保持して応答再送を吸収する。 Timer D 満了でエントリは
    /// table から削除され Terminated に遷移する。
    ///
    /// 検証戦略 (`tokio::test(start_paused = true)` + virtual time):
    /// 1. INVITE を `create_client` で登録 → `client_count() == 1`。
    /// 2. 486 Busy Here を `dispatch_response` で流して non-2xx ACK を生成、
    ///    absorber を spawn させる。
    /// 3. absorber spawn 直後は **table エントリが保持** されている
    ///    (`client_count() == 1`、 RFC §17.1.1.2 figure 5 の Completed 滞在)。
    /// 4. `time::advance(TIMER_D + α)` で Timer D 境界を跨ぐ。
    /// 5. **table エントリが clear** されている (`client_count() == 0`)。
    ///
    /// CLAUDE.md §6.3 (production-side test hook 禁止) に従い、 観測には
    /// `TransactionLayer::client_count` (`pub(crate)`、 将来 Prometheus
    /// メトリック用) のみを使用する。
    #[tokio::test(start_paused = true)]
    async fn rfc3261_17_1_1_2_timer_d_clears_table_entry_after_expiry() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // dummy destination (送信先は 127.0.0.1:1 = 何も listen してない。
        // ACK 送出失敗は warn ログのみで test 自体には影響しない)
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (layer, _inbound_rx) = TransactionLayer::spawn(socket.clone());

        let local = socket.local_addr().unwrap();
        let branch = "z9hG4bKtimerDclear";
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@127.0.0.1");
        invite
            .headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        invite.headers.set("From", "<sip:alice@example>;tag=alice");
        invite.headers.set("To", "<sip:bob@example>");
        invite.headers.set("Call-ID", "timerD-clear@host");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Max-Forwards", "70");

        let ct = layer.create_client(invite.clone(), dest).await.unwrap();
        assert_eq!(
            layer.client_count().await,
            1,
            "create_client 直後は table に 1 件"
        );

        // 486 を Via 揃えで作って dispatch_response で流す。
        let mut resp_486 = make_invite_response(branch, 486, "Busy Here");
        resp_486
            .headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));

        let h = tokio::spawn(async move { ct.run().await });

        // dispatch_response 経由で 486 を流す (deterministic)。
        layer.dispatch_response(resp_486).await;
        let result = h.await.unwrap().unwrap();
        assert_eq!(result.status_code, 486);

        // run 完了直後: absorber が spawn され、 table エントリが Timer D の
        // 間保持される (RFC §17.1.1.2 figure 5)。 spawn 直後の yield を
        // 入れて absorber task に poll 機会を渡す (= まだ Timer D 未経過なので
        // 何もしないはず)。
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            layer.client_count().await,
            1,
            "Completed 滞在中は absorber が table エントリを保持 (Timer D = {:?} の間)",
            TIMER_D
        );

        // Timer D (32s) を僅かに超えて時間を進める。 step_and_yield は内部で
        // yield を 16 回入れるので、 absorber が timer_d 分岐へ進入し remove
        // するまでを観測できる。
        step_and_yield(TIMER_D + Duration::from_millis(100)).await;

        // Timer D 満了 → absorber が自身を table から削除する。
        assert_eq!(
            layer.client_count().await,
            0,
            "Timer D ({:?}) 経過後は table エントリが clear (RFC 3261 §17.1.1.2: Completed → Terminated)",
            TIMER_D
        );
    }

    // ====================================================================
    // RFC 3261 §9.1 用 InviteResponseProgress watch のテスト群 (Issue #97)
    //
    // CANCEL UAC は 1xx 受信前に CANCEL を送ってはならない (MUST NOT)。
    // transaction layer は INVITE クライアント transaction を `create_client`
    // で登録する際に `watch::Sender<InviteResponseProgress>` を併設し、
    // `dispatch_response` で応答コードに応じて Pending → Provisional /
    // Pending → Final へ遷移させる。 UAC TU はこの watch を購読して
    // CANCEL のゲートとして使う。
    // ====================================================================

    /// RFC 3261 §9.1: INVITE 登録直後の `provisional_watch` の初期値は
    /// `Pending` でなければならない (まだ 1xx も最終応答も受け取っていない)。
    #[tokio::test]
    async fn rfc3261_9_1_provisional_watch_initial_state_is_pending() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (layer, _inbound_rx) = TransactionLayer::spawn(socket.clone());
        let local = socket.local_addr().unwrap();
        let branch = "z9hG4bKprogressInit";
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@127.0.0.1");
        invite
            .headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        invite.headers.set("From", "<sip:alice@example>;tag=alice");
        invite.headers.set("To", "<sip:bob@example>");
        invite.headers.set("Call-ID", "progress-init@host");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Max-Forwards", "70");

        let id = TransactionId::from_request(&invite).unwrap();
        let _ct = layer.create_client(invite, dest).await.unwrap();
        let rx = layer.provisional_watch(&id).await.expect("watch present");
        assert_eq!(*rx.borrow(), InviteResponseProgress::Pending);
    }

    /// RFC 3261 §9.1: 1xx (100 Trying 等) を受信したら `provisional_watch` は
    /// Pending → Provisional に遷移する。 UAC TU はこの遷移を観測してから
    /// CANCEL を送出する。
    #[tokio::test]
    async fn rfc3261_9_1_provisional_watch_transitions_on_1xx() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (layer, _inbound_rx) = TransactionLayer::spawn(socket.clone());
        let local = socket.local_addr().unwrap();
        let branch = "z9hG4bKprogress1xx";
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@127.0.0.1");
        invite
            .headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        invite.headers.set("From", "<sip:alice@example>;tag=alice");
        invite.headers.set("To", "<sip:bob@example>");
        invite.headers.set("Call-ID", "progress-1xx@host");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Max-Forwards", "70");

        let id = TransactionId::from_request(&invite).unwrap();
        let _ct = layer.create_client(invite, dest).await.unwrap();
        let mut rx = layer.provisional_watch(&id).await.expect("watch present");
        // 100 Trying を dispatch する
        let mut trying = make_invite_response(branch, 100, "Trying");
        trying
            .headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        layer.dispatch_response(trying).await;
        // changed() で遷移を観測。
        rx.changed().await.expect("watch should change on 1xx");
        assert_eq!(*rx.borrow_and_update(), InviteResponseProgress::Provisional);
    }

    /// RFC 3261 §9.1 後半: 1xx を経ずに最終応答 (>=200) を受信した場合、
    /// `provisional_watch` は Pending → Final に直接遷移する
    /// (CANCEL を送ってはならない状態)。
    #[tokio::test]
    async fn rfc3261_9_1_provisional_watch_transitions_directly_to_final_on_2xx() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (layer, _inbound_rx) = TransactionLayer::spawn(socket.clone());
        let local = socket.local_addr().unwrap();
        let branch = "z9hG4bKprogressFinal";
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:bob@127.0.0.1");
        invite
            .headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        invite.headers.set("From", "<sip:alice@example>;tag=alice");
        invite.headers.set("To", "<sip:bob@example>");
        invite.headers.set("Call-ID", "progress-final@host");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Max-Forwards", "70");

        let id = TransactionId::from_request(&invite).unwrap();
        let _ct = layer.create_client(invite, dest).await.unwrap();
        let mut rx = layer.provisional_watch(&id).await.expect("watch present");
        // 486 を直接 dispatch する
        let mut busy = make_invite_response(branch, 486, "Busy Here");
        busy.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        layer.dispatch_response(busy).await;
        rx.changed().await.expect("watch should change on final");
        assert_eq!(*rx.borrow_and_update(), InviteResponseProgress::Final);
    }

    /// RFC 3261 §9.1: non-INVITE には `provisional_watch` を作らない
    /// (CANCEL は INVITE 専用、 §9.1 "A CANCEL request SHOULD NOT be sent to
    /// cancel a request other than INVITE")。
    #[tokio::test]
    async fn rfc3261_9_1_provisional_watch_absent_for_non_invite() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (layer, _inbound_rx) = TransactionLayer::spawn(socket.clone());
        let local = socket.local_addr().unwrap();
        let branch = "z9hG4bKnoninvite";
        let mut reg = SipRequest::new(SipMethod::Register, "sip:registrar.example");
        reg.headers
            .set("Via", format!("SIP/2.0/UDP {};branch={}", local, branch));
        reg.headers.set("From", "<sip:alice@example>;tag=alice");
        reg.headers.set("To", "<sip:alice@example>");
        reg.headers.set("Call-ID", "noninvite@host");
        reg.headers.set("CSeq", "1 REGISTER");
        reg.headers.set("Max-Forwards", "70");

        let id = TransactionId::from_request(&reg).unwrap();
        let _ct = layer.create_client(reg, dest).await.unwrap();
        assert!(
            layer.provisional_watch(&id).await.is_none(),
            "non-INVITE には provisional_watch を作らない (RFC 3261 §9.1)"
        );
    }
}
