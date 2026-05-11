//! テスト用 [`sabiden::call::manager::LegInviter`] 実装。
//!
//! 本番経路の `UacForker` (`src/call/manager.rs`) は [`sabiden::sip::uac::Uac`]
//! を使って UDP で INVITE を送るが、 テストでは sabiden の Uac/Transaction 層
//! をフルに走らせると ack/bye 周りの状態管理が肥大化するため、 内線レッグの
//! mock UA UDP socket に直接 INVITE を撃ち、 100 を読み飛ばして 200 OK を
//! [`sabiden::call::manager::LegOutcome::Established`] として返す最小実装で
//! 駆動する。
//!
//! これは CLAUDE.md §6.3 「mock UA / mock NGN は production 型を mock しない」
//! 制約に従う: `LegInviter` trait は production の public API であり、 trait
//! 実装をテスト側で追加するだけなので production 型を改変したり test hook を
//! 生やしたりはしない。
//!
//! RFC 3261 §13.2.1 (UAC: INVITE 発行) / §13.2.2.4 (2xx ACK は別 transaction)。
//! ACK は 200 OK 後に独立に送る (本実装でも `acks_sent` カウンタで観測可能)。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use sabiden::call::manager::{LegInviter, LegOutcome};
use sabiden::sip::message::{
    parse_message, SipHeaders, SipMessage, SipMethod, SipRequest, SipResponse,
};
use sabiden::sip::uac::InvitePlan;

/// テスト用 LegInviter。 target_uri → 物理 UDP addr の解決テーブルを持つ。
///
/// sabiden の `fork_to_bindings` は `binding.contact_uri` (= URI 文字列) を
/// target に渡してくる。 本実装はそれを `targets` で `SocketAddr` に解決し、
/// 自前 UdpSocket から INVITE を送る。
pub struct TestLegInviter {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    /// `contact_uri` → 実物理 SocketAddr の解決テーブル。
    targets: HashMap<String, SocketAddr>,
    cseq_counter: AtomicU32,
    /// 観測用: invite() が呼ばれた回数。
    pub call_count: Arc<AtomicU32>,
    /// 観測用: 200 OK 受領後に送出した ACK の件数 (RFC 3261 §13.2.2.4 検証)。
    pub acks_sent: Arc<AtomicU32>,
    /// 戻り値 `LegOutcome` を組むため、 各 target の最新 INVITE を保存しておく
    /// (plan は `InvitePlan` で sabiden が CANCEL を撃つ場合の参照用)。
    last_invites: Arc<Mutex<HashMap<String, SipRequest>>>,
}

impl TestLegInviter {
    /// `127.0.0.1:0` で送信側 UDP socket を bind してハンドルを返す。
    pub async fn start(targets: HashMap<String, SocketAddr>) -> Arc<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind leg inviter");
        let local_addr = socket.local_addr().expect("local addr");
        Arc::new(Self {
            socket: Arc::new(socket),
            local_addr,
            targets,
            cseq_counter: AtomicU32::new(0),
            call_count: Arc::new(AtomicU32::new(0)),
            acks_sent: Arc::new(AtomicU32::new(0)),
            last_invites: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[async_trait]
impl LegInviter for TestLegInviter {
    async fn invite(&self, target_uri: &str, sdp_offer: &[u8]) -> Result<LegOutcome> {
        self.call_count.fetch_add(1, Ordering::SeqCst);

        let target_addr = match self.targets.get(target_uri) {
            Some(a) => *a,
            None => {
                // 解決不能はテスト構成ミス。 fail-fast で原因を可視化する。
                anyhow::bail!(
                    "TestLegInviter: target_uri {:?} の SocketAddr 解決失敗",
                    target_uri
                );
            }
        };

        let cseq = self.cseq_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let call_id = format!("ext-leg-{}", rand_hex(8));
        let from_tag = format!("ext-leg-{}", rand_hex(6));
        let branch = format!("z9hG4bK-ext-{}", rand_hex(8));

        // INVITE を組み立て (RFC 3261 §8.1.1)。
        let mut req = SipRequest::new(SipMethod::Invite, target_uri.to_string());
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};rport;branch={}", self.local_addr, branch),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", format!("<sip:sabiden@127.0.0.1>;tag={}", from_tag));
        req.headers.set("To", format!("<{}>", target_uri));
        req.headers.set("Call-ID", &call_id);
        req.headers.set("CSeq", format!("{} INVITE", cseq));
        req.headers
            .set("Contact", format!("<sip:sabiden@{}>", self.local_addr));
        req.headers
            .set("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS");
        if !sdp_offer.is_empty() {
            req.headers.set("Content-Type", "application/sdp");
            req.body = sdp_offer.to_vec();
        }

        let plan = InvitePlan {
            request: req.clone(),
            cseq,
            target_uri: target_uri.to_string(),
            session_expires: 300,
        };

        self.last_invites
            .lock()
            .await
            .insert(target_uri.to_string(), req.clone());

        // INVITE 送信。
        self.socket
            .send_to(&req.to_bytes(), target_addr)
            .await
            .map_err(|e| anyhow::anyhow!("send INVITE: {e}"))?;

        // RFC 3261 §17.1.1: 最大 5 秒で最終応答を待つ。 mock UA は即時応答する
        // 想定なので余裕を持って 3 秒に絞る。
        let mut buf = vec![0u8; 16 * 1024];
        let deadline = Duration::from_secs(3);
        let mut final_resp: Option<SipResponse> = None;
        for _ in 0..6 {
            let (n, _) = match timeout(deadline, self.socket.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => break,
            };
            match parse_message(&buf[..n]) {
                Ok(SipMessage::Response(r)) => {
                    if r.status_code < 200 {
                        // provisional は読み飛ばし (RFC 3261 §17.1.1.2)。
                        continue;
                    }
                    final_resp = Some(r);
                    break;
                }
                Ok(SipMessage::Request(_)) => continue,
                Err(_) => continue,
            }
        }

        let response = match final_resp {
            Some(r) => r,
            None => {
                return Ok(LegOutcome::Errored {
                    plan: Some(plan.clone()),
                });
            }
        };

        if (200..300).contains(&response.status_code) {
            // RFC 3261 §13.2.2.4: 2xx INVITE は ACK を新規 transaction で送る。
            // dialog ID = (Call-ID, From-tag, To-tag) なので応答の To-tag を使う。
            let to_tag = extract_to_tag_from_response(&response);
            let ack = build_ack_for_2xx(target_uri, &call_id, cseq, &from_tag, to_tag.as_deref());
            if let Err(e) = self.socket.send_to(&ack.to_bytes(), target_addr).await {
                tracing::warn!(error=%e, "TestLegInviter: 2xx ACK 送信失敗");
            } else {
                self.acks_sent.fetch_add(1, Ordering::SeqCst);
            }
            Ok(LegOutcome::Established { plan, response })
        } else {
            Ok(LegOutcome::Failed {
                plan,
                status: response.status_code,
            })
        }
    }
}

/// RFC 3261 §13.2.2.4: 2xx に対する ACK は **新規 branch / Via** を持ち、
/// CSeq method は ACK、 CSeq 番号は INVITE と同じ。 To に応答の To-tag を入れる。
fn build_ack_for_2xx(
    request_uri: &str,
    call_id: &str,
    cseq: u32,
    from_tag: &str,
    to_tag: Option<&str>,
) -> SipRequest {
    let mut headers = SipHeaders::new();
    headers.set(
        "Via",
        format!(
            "SIP/2.0/UDP 127.0.0.1:0;rport;branch=z9hG4bK-ack-{}",
            rand_hex(6)
        ),
    );
    headers.set("Max-Forwards", "70");
    headers.set("From", format!("<sip:sabiden@127.0.0.1>;tag={}", from_tag));
    let to = match to_tag {
        Some(t) => format!("<{}>;tag={}", request_uri, t),
        None => format!("<{}>", request_uri),
    };
    headers.set("To", to);
    headers.set("Call-ID", call_id);
    headers.set("CSeq", format!("{} ACK", cseq));
    SipRequest {
        method: SipMethod::Ack,
        uri: request_uri.to_string(),
        headers,
        body: Vec::new(),
    }
}

fn extract_to_tag_from_response(resp: &SipResponse) -> Option<String> {
    let to = resp.headers.get("to")?;
    to.split(';').find_map(|seg| {
        let seg = seg.trim();
        seg.strip_prefix("tag=").map(|v| v.to_string())
    })
}

fn rand_hex(n_bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}
