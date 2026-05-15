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
use tracing::{info, info_span, warn, Instrument};

use super::auth::{DigestChallenge, DigestCredentials};
use super::message::{SipMethod, SipRequest};
use super::transaction::TransactionLayer;
use super::utils::{new_branch, new_call_id, new_tag};
use crate::config::SipConfig;
use crate::observability::Metrics;

static CSEQ: AtomicU32 = AtomicU32::new(1);

pub struct Registrar {
    config: Arc<SipConfig>,
    layer: Arc<TransactionLayer>,
    server_addr: SocketAddr,
    call_id: String,
    tag: String,
    /// REGISTER 成功状態を外部 (health server 等) と共有するためのフラグ
    registered: Arc<AtomicBool>,
    /// 観測カウンタ (Issue #20)。`Default` 化で metrics 無し動作も許容する。
    metrics: Arc<Metrics>,
}

impl Registrar {
    pub fn new(
        config: Arc<SipConfig>,
        layer: Arc<TransactionLayer>,
        server_addr: SocketAddr,
    ) -> Self {
        Self::with_metrics(config, layer, server_addr, Metrics::new())
    }

    /// メトリクス付き版コンストラクタ。`main.rs` から共有 [`Metrics`] を渡す。
    pub fn with_metrics(
        config: Arc<SipConfig>,
        layer: Arc<TransactionLayer>,
        server_addr: SocketAddr,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            config,
            layer,
            server_addr,
            call_id: new_call_id(),
            tag: new_tag(),
            registered: Arc::new(AtomicBool::new(false)),
            metrics,
        }
    }

    /// REGISTER 成功状態を購読するための共有ハンドル
    pub fn registered_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.registered)
    }

    pub async fn run(&self) -> Result<()> {
        // Call-ID と AOR を span に持たせて、再送・チャレンジまで一貫追跡できるようにする。
        let span = info_span!(
            "register",
            aor = %format!("{}@{}", self.config.phone_number, self.config.domain),
            call_id = %self.call_id,
        );
        async move {
            loop {
                match self.register_with_retry().await {
                    Ok(expires) => {
                        self.registered.store(true, Ordering::SeqCst);
                        self.metrics.record_register(true);
                        let refresh = Duration::from_secs((expires as f64 * 0.9) as u64);
                        info!("REGISTER 成功 次回更新まで {}秒", refresh.as_secs());
                        time::sleep(refresh).await;
                    }
                    Err(e) => {
                        self.registered.store(false, Ordering::SeqCst);
                        self.metrics.record_register(false);
                        warn!("REGISTER 失敗: {} 30秒後に再試行", e);
                        time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
            // unreachable; ループ内で必ず continue する。型推論のため明示。
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
        .instrument(span)
        .await
    }

    /// 認証チャレンジを処理して REGISTER を完了させる
    ///
    /// password が `None` の場合は NGN 直収モード (Issue #37) として動作する:
    /// - 最初から Authorization ヘッダ無しで送る
    /// - 200 ならそのまま成功 (回線認証で通った)
    /// - 401 が返ってきても再送はしない (DHCP/MAC 経路の問題なので
    ///   レイヤを越えて修正する必要があり、ここで再試行しても無意味)
    async fn register_with_retry(&self) -> Result<u32> {
        // Step 1: 認証なしで送信 (transaction 経由)
        let cseq = CSEQ.fetch_add(1, Ordering::SeqCst);
        let req = self.build_register(cseq, None);
        let resp = self.layer.send_request(req, self.server_addr).await?;
        match resp.status_code {
            200 => {
                // RFC 3608 §3.2: REGISTER 200 OK の Service-Route を保存し
                // 以降の dialog-creating request (INVITE 等) の Route ヘッダに echo する。
                // IMS では MUST。 NGN は `Service-Route: <sip:ntt-east.ne.jp;lr>` を返す。
                let sr = resp.headers.get("service-route").map(|s| s.to_string());
                tracing::debug!(service_route=?sr, "REGISTER 200 OK: Service-Route 保存 (RFC 3608)");
                crate::sip::store_service_route(sr);
                // outbound_proxy style: NGN P-CSCF IP を Route として固定使用
                // (Asterisk pcap 互換、 NTT 直収で実機適合確認 2026-05-12)。
                let op = format!("<sip:{};lr>", self.server_addr);
                tracing::debug!(outbound_proxy_route=%op, "outbound_proxy Route 保存");
                crate::sip::store_outbound_proxy_route(Some(op));
                Ok(parse_expires(&resp.headers))
            }
            401 => {
                // password が無い (NGN 直収モード) で 401 が返るのは、
                // 回線認証側 (HGW WAN MAC spoof / DHCPv4 vendor class) の問題。
                // SIP 層で再送しても通らないので即 bail させ、上位 (register loop)
                // の 30 秒バックオフ + ログで運用者に気付かせる。
                let Some(password) = self.config.password.as_deref() else {
                    anyhow::bail!(
                        "REGISTER 401 in auth=none mode: NGN 回線認証 (HGW MAC / \
                         DHCPv4 vendor class) を確認してください (Issue #37)"
                    );
                };
                let www_auth = resp
                    .headers
                    .get("www-authenticate")
                    .ok_or_else(|| anyhow::anyhow!("401 without WWW-Authenticate"))?
                    .to_string();
                let challenge = DigestChallenge::parse(&www_auth)?;
                let creds = DigestCredentials::new(&self.config.phone_number, password);
                let uri = format!("sip:{}", self.config.domain);
                let digest = creds.compute(&challenge, "REGISTER", &uri, 1);

                let cseq2 = CSEQ.fetch_add(1, Ordering::SeqCst);
                let req2 = self.build_register(cseq2, Some(&digest.header_value));
                let resp2 = self.layer.send_request(req2, self.server_addr).await?;
                if resp2.status_code == 200 {
                    // RFC 3608 §3.2: 同上、 challenge 後の REGISTER 200 OK でも保存
                    let sr = resp2.headers.get("service-route").map(|s| s.to_string());
                    tracing::debug!(service_route=?sr, "REGISTER (auth) 200 OK: Service-Route 保存 (RFC 3608)");
                    crate::sip::store_service_route(sr);
                    // auth path も outbound_proxy_route を保存 (200-direct path との
                    // consistency、 将来 HGW emulation で password 設定時に Route が
                    // 空にならないようにする)。
                    let op = format!("<sip:{};lr>", self.server_addr);
                    tracing::debug!(outbound_proxy_route=%op, "outbound_proxy Route 保存 (auth path)");
                    crate::sip::store_outbound_proxy_route(Some(op));
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
        let local_addr = self.config.expect_local_addr();

        let mut req = SipRequest::new(SipMethod::Register, format!("sip:{}", domain));

        // RFC 3581 §4 (Symmetric Response Routing): UAC が Via に `;rport` を
        // 付与すると、 UAS は応答時に UDP source port を `rport=<n>` で埋めて
        // 応答する (NAT/PAT で port 変換されていても応答が届く)。
        //
        // NGN 直収では rport 有無いずれでも 200 OK が返る (両対応、
        // `docs/asterisk-real-invite.md` §3 / §5.5、 CLAUDE.md §5)。 ここで
        // rport を付ける理由は (a) sabiden 内 UAC (`uac.rs` の INVITE) が
        // 既に rport 付きで送っており、 同一線で REGISTER だけ非対称になる
        // 状態を解消するため (Issue #120)、 (b) Asterisk 実機 pcap も
        // rport 付きで成立しているため (`docs/asterisk-real-invite.md`
        // §5.5 INVITE 例 L158)。
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};rport;branch={}", local_addr, new_branch()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::{parse_message, SipMessage};
    use crate::sip::transaction::{build_response_skeleton, TransactionLayer};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    /// RFC 3581 §4 (Symmetric Response Routing): UAC は Via に `;rport`
    /// パラメータを付与してよく、 UAS はそれを見て応答先 port を
    /// `received`/`rport` で学習する。 sabiden 内 UAC (`uac.rs` の INVITE) と
    /// REGISTER 間の非対称を防ぐため、 REGISTER も `;rport` を出力する
    /// (Issue #120、 `docs/asterisk-real-invite.md` §3 / §5.5)。
    #[tokio::test]
    async fn rfc3581_4_register_via_includes_rport() {
        let cfg = SipConfig {
            server_addr: "127.0.0.1:5060".parse().unwrap(),
            bind_addr: None,
            local_addr: Some("127.0.0.1:5060".parse().unwrap()),
            phone_number: "0312345678".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            password: None,
            register_expires: 3600,
        };
        let dummy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (layer, _rx) = TransactionLayer::spawn(dummy_sock);
        let registrar = Registrar::new(Arc::new(cfg), layer, "127.0.0.1:5060".parse().unwrap());
        let req = registrar.build_register(1, None);
        let via = req
            .headers
            .get("via")
            .expect("Via must be present on REGISTER");
        assert!(
            via.contains(";rport"),
            "RFC 3581 §4: REGISTER Via must include `;rport` (got: {via})"
        );
        // branch も同時に存在すること (RFC 3261 §8.1.1.7、 magic cookie 必須)。
        assert!(
            via.contains(";branch=z9hG4bK"),
            "RFC 3261 §8.1.1.7: Via branch must use magic cookie z9hG4bK (got: {via})"
        );
    }

    /// Issue #37: NGN 直収モード (password=None) では Authorization ヘッダ
    /// が一切付かないこと。`build_register` の単体検証。
    #[tokio::test]
    async fn build_register_omits_authorization_when_no_password() {
        let cfg = SipConfig {
            server_addr: "127.0.0.1:5060".parse().unwrap(),
            bind_addr: None,
            local_addr: Some("127.0.0.1:5060".parse().unwrap()),
            phone_number: "0312345678".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            password: None,
            register_expires: 3600,
        };
        let dummy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (layer, _rx) = TransactionLayer::spawn(dummy_sock);
        let registrar = Registrar::new(Arc::new(cfg), layer, "127.0.0.1:5060".parse().unwrap());
        let req = registrar.build_register(1, None);
        assert!(
            req.headers.get("authorization").is_none(),
            "auth=none mode must not send Authorization header"
        );
    }

    /// Issue #37: 直収モード REGISTER で 200 OK が返れば成功扱いになり、
    /// Authorization ヘッダはネットワーク上にも一切現れないこと。
    #[tokio::test]
    async fn register_succeeds_without_password_when_200() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();

        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = client_sock.local_addr().unwrap();
        let (layer, _rx) = TransactionLayer::spawn(client_sock);

        // mock NGN サーバ: REGISTER を 1 回受信し 200 OK を返す。
        // 受信した REGISTER の生バイトを共有スロットに置き、Authorization が
        // 含まれていないことをアサートする。
        let captured: Arc<tokio::sync::Mutex<Option<Vec<u8>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let captured_clone = Arc::clone(&captured);
        let server_clone = Arc::clone(&server_sock);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            *captured_clone.lock().await = Some(buf[..n].to_vec());
            if let Ok(SipMessage::Request(req)) = parse_message(&buf[..n]) {
                let mut resp = build_response_skeleton(&req, 200, "OK");
                resp.headers.set("Expires", "3600");
                server_clone.send_to(&resp.to_bytes(), peer).await.unwrap();
            }
        });

        let cfg = Arc::new(SipConfig {
            server_addr,
            bind_addr: None,
            local_addr: Some(local),
            phone_number: "0312345678".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            password: None,
            register_expires: 3600,
        });
        let registrar = Registrar::new(cfg, layer, server_addr);
        let expires = registrar.register_with_retry().await.expect("200 OK");
        assert_eq!(expires, 3600);

        let raw = captured.lock().await.clone().expect("server received");
        let raw_str = String::from_utf8_lossy(&raw).to_lowercase();
        assert!(
            !raw_str.contains("authorization:"),
            "wire bytes must not contain Authorization header in auth=none mode"
        );
        // Issue #120 / RFC 3581 §4: REGISTER も Via に `;rport` を載せて送る。
        // 文字列マッチは Via ヘッダ表記 (full / compact) と大文字小文字に関わらず
        // `;rport` トークンが現れることだけ確認する。
        assert!(
            raw_str.contains(";rport"),
            "RFC 3581 §4: wire bytes must contain `;rport` on Via (got: {raw_str})"
        );
    }

    /// Issue #37: 直収モードで 401 が返ってきたら、SIP 層では再送せず即 bail
    /// する (DHCP/MAC 経路を疑うため)。
    #[tokio::test]
    async fn register_bails_on_401_without_password() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();

        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = client_sock.local_addr().unwrap();
        let (layer, _rx) = TransactionLayer::spawn(client_sock);

        // mock サーバ: 401 + WWW-Authenticate を返す。再送が来てしまうと
        // recv_from が再びブロックして時間切れになる構造で、二重送信ガード
        // を兼ねる。
        let server_clone = Arc::clone(&server_sock);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = server_clone.recv_from(&mut buf).await.unwrap();
            if let Ok(SipMessage::Request(req)) = parse_message(&buf[..n]) {
                let mut resp = build_response_skeleton(&req, 401, "Unauthorized");
                resp.headers.set(
                    "WWW-Authenticate",
                    "Digest realm=\"ntt-east.ne.jp\",nonce=\"abc\",algorithm=MD5",
                );
                server_clone.send_to(&resp.to_bytes(), peer).await.unwrap();
            }
        });

        let cfg = Arc::new(SipConfig {
            server_addr,
            bind_addr: None,
            local_addr: Some(local),
            phone_number: "0312345678".to_string(),
            domain: "ntt-east.ne.jp".to_string(),
            password: None,
            register_expires: 3600,
        });
        let registrar = Registrar::new(cfg, layer, server_addr);
        let err = registrar
            .register_with_retry()
            .await
            .expect_err("401 in auth=none mode should bail");
        let msg = format!("{}", err);
        assert!(
            msg.contains("auth=none") || msg.contains("回線認証"),
            "error must explain MAC/DHCP origin (got: {msg})"
        );
    }
}
