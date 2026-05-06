/// RFC 3261 REGISTER + RFC 4028 Session Timer 対応
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, info, warn};

use super::auth::{DigestChallenge, DigestCredentials};
use super::message::{parse_message, SipMessage, SipMethod, SipRequest};
use super::utils::{new_branch, new_call_id, new_tag};
use crate::config::SipConfig;

static CSEQ: AtomicU32 = AtomicU32::new(1);

pub struct Registrar {
    config: Arc<SipConfig>,
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    call_id: String,
    tag: String,
}

impl Registrar {
    pub fn new(config: Arc<SipConfig>, socket: Arc<UdpSocket>, server_addr: SocketAddr) -> Self {
        Self {
            config,
            socket,
            server_addr,
            call_id: new_call_id(),
            tag: new_tag(),
        }
    }

    pub async fn run(&self) -> Result<()> {
        loop {
            match self.register_with_retry().await {
                Ok(expires) => {
                    let refresh = Duration::from_secs((expires as f64 * 0.9) as u64);
                    info!("REGISTER 成功 次回更新まで {}秒", refresh.as_secs());
                    time::sleep(refresh).await;
                }
                Err(e) => {
                    warn!("REGISTER 失敗: {} 30秒後に再試行", e);
                    time::sleep(Duration::from_secs(30)).await;
                }
            }
        }
    }

    /// 認証チャレンジを処理して REGISTER を完了させる
    async fn register_with_retry(&self) -> Result<u32> {
        // Step 1: 認証なしで送信
        let cseq = CSEQ.fetch_add(1, Ordering::SeqCst);
        let req = self.build_register(cseq, None);
        self.send(&req).await?;

        let resp = self.recv_response().await?;
        match resp.status_code {
            200 => Ok(parse_expires(&resp.headers)),
            401 => {
                let www_auth = resp
                    .headers
                    .get("www-authenticate")
                    .ok_or_else(|| anyhow::anyhow!("401 without WWW-Authenticate"))?
                    .to_string();
                let challenge = DigestChallenge::parse(&www_auth)?;
                let creds =
                    DigestCredentials::new(&self.config.phone_number, &self.config.password);
                let uri = format!("sip:{}", self.config.domain);
                let digest = creds.compute(&challenge, "REGISTER", &uri, 1);

                let cseq2 = CSEQ.fetch_add(1, Ordering::SeqCst);
                let req2 = self.build_register(cseq2, Some(&digest.header_value));
                self.send(&req2).await?;

                let resp2 = self.recv_response().await?;
                if resp2.status_code == 200 {
                    Ok(parse_expires(&resp2.headers))
                } else {
                    anyhow::bail!("REGISTER 失敗: {} {}", resp2.status_code, resp2.reason)
                }
            }
            code => anyhow::bail!("予期しない応答: {} {}", code, resp.reason),
        }
    }

    fn build_register(&self, cseq: u32, authorization: Option<&str>) -> SipRequest {
        let domain = &self.config.domain;
        let number = &self.config.phone_number;
        let local_addr = self.config.local_addr;

        let mut req = SipRequest::new(SipMethod::Register, format!("sip:{}", domain));

        // Via ヘッダ: rport を付けない (NTT NGN 必須)
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch={}", local_addr, new_branch()),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers.set(
            "From",
            format!("<sip:{}@{}>;tag={}", number, domain, self.tag),
        );
        req.headers
            .set("To", format!("<sip:{}@{}>", number, domain));
        req.headers.set("Call-ID", &self.call_id);
        req.headers.set("CSeq", format!("{} REGISTER", cseq));
        req.headers
            .set("Contact", format!("<sip:{}@{}>", number, local_addr));
        req.headers
            .set("Expires", self.config.register_expires.to_string());
        req.headers
            .set("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY");
        req.headers.set("User-Agent", "hikari-sip/0.1");

        if let Some(auth) = authorization {
            req.headers.set("Authorization", auth);
        }

        req
    }

    async fn send(&self, req: &SipRequest) -> Result<()> {
        let bytes = req.to_bytes();
        debug!("送信:\n{}", String::from_utf8_lossy(&bytes));
        self.socket.send_to(&bytes, self.server_addr).await?;
        Ok(())
    }

    async fn recv_response(&self) -> Result<super::message::SipResponse> {
        let mut buf = vec![0u8; 4096];
        let deadline = time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    let (n, _) = result?;
                    debug!("受信:\n{}", String::from_utf8_lossy(&buf[..n]));
                    match parse_message(&buf[..n])? {
                        SipMessage::Response(r) => return Ok(r),
                        SipMessage::Request(_) => {
                            // REGISTER 中に届いたリクエストは無視
                            continue;
                        }
                    }
                }
                _ = &mut deadline => {
                    anyhow::bail!("REGISTER タイムアウト");
                }
            }
        }
    }
}

fn parse_expires(headers: &super::message::SipHeaders) -> u32 {
    headers
        .get("expires")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600)
}
