/// RFC 3261 REGISTER + RFC 4028 Session Timer 対応
///
/// 本実装は SIP トランザクション層 (`super::transaction`) を経由して
/// REGISTER を送信する (RFC 3261 §17.1.2)。これにより再送 (Timer E)
/// とトランザクション タイムアウト (Timer F) は transaction 層で
/// ハンドルされ、本モジュールは認証チャレンジ→再送信のロジックに集中する。
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::time;
use tracing::{info, warn};

use super::auth::{DigestChallenge, DigestCredentials};
use super::message::{SipMethod, SipRequest};
use super::transaction::TransactionLayer;
use super::utils::{new_branch, new_call_id, new_tag};
use crate::config::SipConfig;

static CSEQ: AtomicU32 = AtomicU32::new(1);

pub struct Registrar {
    config: Arc<SipConfig>,
    layer: Arc<TransactionLayer>,
    server_addr: SocketAddr,
    call_id: String,
    tag: String,
    /// REGISTER 成功状態を外部 (health server 等) と共有するためのフラグ
    registered: Arc<AtomicBool>,
}

impl Registrar {
    pub fn new(
        config: Arc<SipConfig>,
        layer: Arc<TransactionLayer>,
        server_addr: SocketAddr,
    ) -> Self {
        Self {
            config,
            layer,
            server_addr,
            call_id: new_call_id(),
            tag: new_tag(),
            registered: Arc::new(AtomicBool::new(false)),
        }
    }

    /// REGISTER 成功状態を購読するための共有ハンドル
    pub fn registered_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.registered)
    }

    pub async fn run(&self) -> Result<()> {
        loop {
            match self.register_with_retry().await {
                Ok(expires) => {
                    self.registered.store(true, Ordering::SeqCst);
                    let refresh = Duration::from_secs((expires as f64 * 0.9) as u64);
                    info!("REGISTER 成功 次回更新まで {}秒", refresh.as_secs());
                    time::sleep(refresh).await;
                }
                Err(e) => {
                    self.registered.store(false, Ordering::SeqCst);
                    warn!("REGISTER 失敗: {} 30秒後に再試行", e);
                    time::sleep(Duration::from_secs(30)).await;
                }
            }
        }
    }

    /// 認証チャレンジを処理して REGISTER を完了させる
    async fn register_with_retry(&self) -> Result<u32> {
        // Step 1: 認証なしで送信 (transaction 経由)
        let cseq = CSEQ.fetch_add(1, Ordering::SeqCst);
        let req = self.build_register(cseq, None);
        let resp = self.layer.send_request(req, self.server_addr).await?;
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
                let resp2 = self.layer.send_request(req2, self.server_addr).await?;
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
}

fn parse_expires(headers: &super::message::SipHeaders) -> u32 {
    headers
        .get("expires")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600)
}
