//! 内線 UAS (User Agent Server)
//!
//! Linphone / Zoiper 等の SIP UA を内線として受け付けるサーバ。
//! NGN 側の `Registrar` (UAC) とは別ポート・別 [`TransactionLayer`]
//! インスタンスで動かすことで、内線網と NGN 網を L4 で分離する
//! (`ARCHITECTURE.md` 参照)。
//!
//! 本モジュールは以下を担う:
//! - REGISTER の Digest 認証 (`super::auth`) と
//!   [`ExtensionRegistrar`] への登録 (RFC 3261 §10)
//! - INVITE / BYE / CANCEL / ACK / OPTIONS の最低限の応答
//! - 上位層 (Call Manager, Issue #5) への INVITE/BYE 通知 (mpsc チャネル)
//!
//! Call Manager (`UasEvent` の受信側) が未接続なら INVITE/BYE は
//! それぞれ 503 / 481 で応答する。これにより UAS 単体でも CI 上で
//! 動作確認できる。
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tracing::{debug, info, info_span, warn, Instrument};

use super::auth::{build_www_authenticate, DigestAuthorization};
use super::message::{SipMethod, SipRequest, SipResponse};
use super::registrar::ExtensionRegistrar;
use super::transaction::{
    build_response_skeleton, InboundRequest, ServerTransaction, TransactionLayer,
};
use super::utils::{new_call_id, new_tag};
use crate::config::{ExtensionConfig, UasConfig};
use crate::observability::Metrics;

/// 上位層 (Call Manager) に流すイベント。
///
/// UAS 自身は通話状態を持たない。INVITE を受け取ったら認証だけ済ませて
/// そのまま上位に流し、上位が応答とブリッジを組み立てる。
#[derive(Debug)]
pub enum UasEvent {
    /// 認証済みの内線からの INVITE。`responder` 経由で 1xx/2xx/4xx 等を返す。
    Invite {
        /// 認証された AOR (内線ユーザ名)。
        from_aor: String,
        /// SIP リクエスト本体 (SDP オファ含む)。
        request: SipRequest,
        /// 送信元 (応答送信先)。
        remote: SocketAddr,
        /// レスポンスを送るためのハンドル。
        responder: ResponderHandle,
    },
    /// 既存ダイアログに対する BYE。`responder` で 200 OK を返す。
    Bye {
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    },
    /// 進行中 INVITE への CANCEL (RFC 3261 §9). `responder` は CANCEL 自身の
    /// 200 OK を返すために使う (元 INVITE は別途 487 で閉じる必要がある)。
    Cancel {
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    },
    /// 内線からの ACK (2xx 確定後)。RFC 3261 §17.1.1.3 に従い応答は不要なので
    /// `responder` は持たず、上位層が必要なら通話状態を Connected に遷移させる
    /// マーカとして使う。
    Ack {
        request: SipRequest,
        remote: SocketAddr,
    },
}

/// 1 リクエストに対応するサーバ トランザクションの操作ハンドル。
///
/// 内部で [`ServerTransaction`] を `Arc<Mutex>` 共有することで、
/// 上位層が複数回 (1xx → 2xx 等) 応答できるようにする。
#[derive(Clone)]
pub struct ResponderHandle {
    inner: Arc<Mutex<ServerTransaction>>,
}

impl std::fmt::Debug for ResponderHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderHandle").finish_non_exhaustive()
    }
}

impl ResponderHandle {
    fn new(tx: ServerTransaction) -> Self {
        Self {
            inner: Arc::new(Mutex::new(tx)),
        }
    }

    /// テスト用に `ServerTransaction` から直接構築するヘルパ。
    /// 通常経路では `ExtensionUas` 内部でしか作られない。
    #[doc(hidden)]
    pub fn __test_new(tx: ServerTransaction) -> Self {
        Self::new(tx)
    }

    /// 任意の応答を送信する。
    pub async fn respond(&self, response: SipResponse) -> Result<()> {
        let mut tx = self.inner.lock().await;
        tx.respond(response).await
    }

    /// 元リクエストから組み立てた簡易応答を送る。
    pub async fn quick(&self, status: u16, reason: &str) -> Result<()> {
        let resp = {
            let tx = self.inner.lock().await;
            build_response_skeleton(tx.request(), status, reason)
        };
        self.respond(resp).await
    }

    /// ボディ付き応答を送る。
    ///
    /// 200 OK + `application/sdp` で SDP answer を内線に返したい等、
    /// `quick` ではボディを乗せられない用途のためのヘルパ。
    /// To タグが未付与なら付与する (RFC 3261 §8.2.6.2)。
    pub async fn respond_with_body(
        &self,
        status: u16,
        reason: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<()> {
        let mut resp = {
            let tx = self.inner.lock().await;
            build_response_skeleton(tx.request(), status, reason)
        };
        if !body.is_empty() {
            resp.headers.set("Content-Type", content_type);
            resp.body = body;
        }
        ensure_to_tag(&mut resp);
        self.respond(resp).await
    }
}

/// 設定済みの内線アカウント表 (username → password)。
type AuthDb = HashMap<String, String>;

/// 内線 UAS。`bind` でソケットを開き、`with_handler` で上位イベント送信先を
/// 渡してから `run` で受信ループに入る。
pub struct ExtensionUas {
    config: UasConfig,
    auth_db: AuthDb,
    socket: Arc<UdpSocket>,
    /// `TransactionLayer` の所有権を保持する。Drop されると内部 spawn の
    /// 受信ループが停止するため、UAS の生存期間中は手放さない。
    /// (将来 ServerTransaction の登録/再送制御で使う場合は public API を生やす。)
    _layer: Arc<TransactionLayer>,
    registrar: Arc<ExtensionRegistrar>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    event_tx: Option<mpsc::UnboundedSender<UasEvent>>,
    /// 観測カウンタ。internal `extension_registered` gauge を更新する。
    metrics: Arc<Metrics>,
}

impl ExtensionUas {
    /// UDP ソケットを bind して UAS を初期化する。
    pub async fn bind(config: UasConfig, extensions: &[ExtensionConfig]) -> Result<Self> {
        Self::bind_with_metrics(config, extensions, Metrics::new()).await
    }

    /// メトリクス付き bind。
    pub async fn bind_with_metrics(
        config: UasConfig,
        extensions: &[ExtensionConfig],
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind(config.bind_addr).await?);
        info!("内線 UAS bind: {}", config.bind_addr);
        let (layer, inbound_rx) = TransactionLayer::spawn(socket.clone());
        let auth_db = extensions
            .iter()
            .map(|e| (e.username.clone(), e.password.clone()))
            .collect();
        Ok(Self {
            config,
            auth_db,
            socket,
            _layer: layer,
            registrar: ExtensionRegistrar::new(),
            inbound_rx,
            event_tx: None,
            metrics,
        })
    }

    /// Call Manager (#5) との接続用 mpsc チャネルを設定する。
    /// 呼ばなければ INVITE は 503、BYE は 481 で応答する。
    pub fn with_handler(mut self, event_tx: mpsc::UnboundedSender<UasEvent>) -> Self {
        self.event_tx = Some(event_tx);
        self
    }

    /// 内線登録テーブルへの参照。Call Manager がフォーク先を引くのに使う。
    pub fn registrar(&self) -> Arc<ExtensionRegistrar> {
        self.registrar.clone()
    }

    /// 受信ソケットへの参照。テストや、内線網用 UAC の構築時に
    /// 同じ bind addr を使い回したいケースで利用する。
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// 受信ループを駆動している `TransactionLayer` への参照。
    /// 上位層 (B2BUA) が内線レッグへ in-dialog リクエスト (BYE 等) を
    /// `send_request` で送るために必要。
    pub fn layer(&self) -> Arc<TransactionLayer> {
        self._layer.clone()
    }

    /// 受信ループ。`Ctrl-C` などで中断されるまで終了しない。
    pub async fn run(mut self) -> Result<()> {
        // 期限切れエントリを掃除するタスクを並走させる。同時に
        // `extension_registered` gauge をスナップショット長で更新する。
        let registrar = self.registrar.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                let removed = registrar.purge_expired().await;
                if removed > 0 {
                    debug!("内線登録 {} 件を期限切れ削除", removed);
                }
                let n = registrar.snapshot().await.len() as u64;
                metrics.set_extension_registered(n);
            }
        });

        while let Some(inbound) = self.inbound_rx.recv().await {
            self.handle_request(inbound).await;
        }
        Ok(())
    }

    async fn handle_request(&self, inbound: InboundRequest) {
        let InboundRequest { request, remote } = inbound;
        let method = request.method.clone();
        let call_id = request
            .headers
            .get("call-id")
            .map(str::to_string)
            .unwrap_or_else(|| "<no-call-id>".to_string());
        let span = info_span!(
            "uas_request",
            call_id = %call_id,
            method = %method,
            direction = "extension",
        );
        async move {
            debug!(?method, %remote, "内線リクエスト受信");

            // ServerTransaction を作成 (Via/branch から ID 生成失敗 = 不正パケット)
            let server_tx =
                match ServerTransaction::new(request.clone(), remote, self.socket.clone()) {
                    Ok(tx) => tx,
                    Err(e) => {
                        warn!(error=%e, "ServerTransaction 生成失敗");
                        return;
                    }
                };
            let responder = ResponderHandle::new(server_tx);

            match method {
                SipMethod::Register => {
                    if let Err(e) = self.handle_register(&request, remote, &responder).await {
                        warn!(error=%e, "REGISTER 処理エラー");
                    }
                }
                SipMethod::Invite => {
                    if let Err(e) = self.handle_invite(&request, remote, responder).await {
                        warn!(error=%e, "INVITE 処理エラー");
                    }
                }
                SipMethod::Bye => {
                    self.handle_bye(request.clone(), remote, responder).await;
                }
                SipMethod::Cancel => {
                    // CANCEL は元 INVITE と同じ branch を共有する。
                    // RFC 3261 §9.2: CANCEL 自体には 200 OK を返し、元 INVITE は
                    // 上位層 (B2BUA) が 487 Request Terminated で閉じる責務を負う。
                    let _ = responder.quick(200, "OK").await;
                    if let Some(tx) = &self.event_tx {
                        let _ = tx.send(UasEvent::Cancel {
                            request,
                            remote,
                            responder,
                        });
                    }
                }
                SipMethod::Ack => {
                    // ACK 自体には応答しない (RFC 3261 §17.2.7)。
                    // 上位 (B2BUA) には通話状態の Confirmed 遷移マーカとして渡す。
                    debug!("ACK 受信 → 上位層へ転送");
                    if let Some(tx) = &self.event_tx {
                        let _ = tx.send(UasEvent::Ack { request, remote });
                    }
                }
                SipMethod::Options => {
                    // 単純な keep-alive 応答 (Linphone 等が定期送信する)
                    let _ = responder.quick(200, "OK").await;
                }
                other => {
                    warn!(?other, "未対応メソッド → 405");
                    let _ = responder.quick(405, "Method Not Allowed").await;
                }
            }
        }
        .instrument(span)
        .await
    }

    /// REGISTER の Digest 認証と登録。
    ///
    /// フロー (RFC 3261 §10):
    /// 1. `Authorization` ヘッダなし → 401 + WWW-Authenticate (nonce 発行)
    /// 2. `Authorization` あり → 検証成功なら登録 + 200 OK / 失敗なら 401 (stale)
    async fn handle_register(
        &self,
        request: &SipRequest,
        remote: SocketAddr,
        responder: &ResponderHandle,
    ) -> Result<()> {
        // username は Authorization ヘッダ優先、なければ To から推測
        let auth_header = request.headers.get("authorization").map(str::to_string);

        let auth = match auth_header.as_deref() {
            Some(h) => match DigestAuthorization::parse(h) {
                Ok(a) => a,
                Err(e) => {
                    warn!(error=%e, "Authorization パース失敗");
                    return self.send_challenge(responder, "Bad Authorization").await;
                }
            },
            None => {
                return self.send_challenge(responder, "Unauthorized").await;
            }
        };

        let Some(password) = self.auth_db.get(&auth.username) else {
            warn!(user=%auth.username, "未登録ユーザの REGISTER → 403");
            return responder.quick(403, "Forbidden").await;
        };

        if !auth.verify("REGISTER", password) {
            warn!(user=%auth.username, "Digest 検証失敗 → 401");
            return self.send_challenge(responder, "Unauthorized").await;
        }

        // 認証成功 → 登録
        let aor = auth.username.clone();
        let contact_uri = request
            .headers
            .get("contact")
            .map(extract_uri_from_contact)
            .unwrap_or_else(|| format!("sip:{}@{}", aor, remote));
        let expires = parse_register_expires(request).min(self.config.max_expires);

        self.registrar
            .register(
                &aor,
                contact_uri.clone(),
                remote,
                Duration::from_secs(expires.into()),
            )
            .await;
        // 観測: 登録直後に gauge を更新する (purge ループの 30 秒待たずに反映する)。
        let n = self.registrar.snapshot().await.len() as u64;
        self.metrics.set_extension_registered(n);
        info!(
            "内線 REGISTER 成功: {} → {} (expires={}s)",
            aor, contact_uri, expires
        );

        // 200 OK + Contact + Expires
        let mut resp = build_response_skeleton(request, 200, "OK");
        ensure_to_tag(&mut resp);
        if let Some(c) = request.headers.get("contact") {
            // RFC 3261 §10.3: REGISTER の応答は登録された Contact 一覧を返す。
            // 内線用途では送ってきた値をそのまま expires 付きで返す。
            resp.headers
                .set("Contact", format!("{};expires={}", c, expires));
        }
        resp.headers.set("Expires", expires.to_string());
        responder.respond(resp).await
    }

    async fn send_challenge(&self, responder: &ResponderHandle, reason: &str) -> Result<()> {
        let nonce = new_call_id(); // 実用上十分にランダム
        let header = build_www_authenticate(&self.config.realm, &nonce);
        let mut resp = {
            let tx = responder.inner.lock().await;
            build_response_skeleton(tx.request(), 401, reason)
        };
        ensure_to_tag(&mut resp);
        resp.headers.set("WWW-Authenticate", header);
        responder.respond(resp).await
    }

    async fn handle_invite(
        &self,
        request: &SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    ) -> Result<()> {
        // 認証
        let auth = match request.headers.get("authorization") {
            Some(h) => match DigestAuthorization::parse(h) {
                Ok(a) => a,
                Err(_) => return self.send_challenge(&responder, "Bad Authorization").await,
            },
            None => return self.send_challenge(&responder, "Unauthorized").await,
        };
        let Some(password) = self.auth_db.get(&auth.username) else {
            return responder.quick(403, "Forbidden").await;
        };
        if !auth.verify("INVITE", password) {
            return self.send_challenge(&responder, "Unauthorized").await;
        }

        // 100 Trying を即返す (RFC 3261 §17.2.1)
        responder.quick(100, "Trying").await?;

        // 上位 (Call Manager) があれば渡す。なければ 503。
        if let Some(tx) = &self.event_tx {
            let event = UasEvent::Invite {
                from_aor: auth.username,
                request: request.clone(),
                remote,
                responder,
            };
            if tx.send(event).is_err() {
                warn!("Call Manager 受信側が閉じている → 503");
                // ここでは responder は move 済みなので応答できない。
                // (Issue #5 が落ちた場合の縮退は将来課題)
            }
            Ok(())
        } else {
            warn!("Call Manager 未接続 → 503");
            responder.quick(503, "Service Unavailable").await
        }
    }

    async fn handle_bye(
        &self,
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    ) {
        // BYE は既存ダイアログ前提。UAS 自身は dialog テーブルを持たないので
        // 上位層 (B2BUA) に渡し、200 OK の送出は上位層に任せる。上位層が
        // 未接続のときは無害な 200 OK で閉じる (RFC 3261 §15.1.2 では
        // 「既知でなければ 481」だが、内線側 dialog 状態は B2BUA 側にしか
        // 無く、ここで 481 を返すと UA がリソース解放を後回しにする)。
        if let Some(tx) = &self.event_tx {
            if tx
                .send(UasEvent::Bye {
                    request,
                    remote,
                    responder,
                })
                .is_err()
            {
                warn!("Call Manager 受信側が閉じている → BYE は dropped");
            }
        } else {
            let _ = responder.quick(200, "OK").await;
        }
    }
}

/// REGISTER の expires を取り出す。Contact ヘッダ パラメータが優先で、
/// なければ Expires ヘッダを見る (RFC 3261 §10.2.1.1)。デフォルトは 3600。
fn parse_register_expires(request: &SipRequest) -> u32 {
    if let Some(contact) = request.headers.get("contact") {
        for part in contact.split(';') {
            if let Some(v) = part.trim().strip_prefix("expires=") {
                if let Ok(n) = v.trim_matches('"').parse::<u32>() {
                    return n;
                }
            }
        }
    }
    request
        .headers
        .get("expires")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(3600)
}

/// `Contact: <sip:user@host:port>;expires=...` から URI 部分を抽出。
fn extract_uri_from_contact(contact: &str) -> String {
    let s = contact.trim();
    if let Some(start) = s.find('<') {
        if let Some(end) = s[start + 1..].find('>') {
            return s[start + 1..start + 1 + end].to_string();
        }
    }
    // `<>` 無しの場合: 先頭のセミコロンより前を URI とみなす
    s.split(';').next().unwrap_or(s).trim().to_string()
}

/// レスポンスの To に tag が無ければ付与する (RFC 3261 §8.2.6.2)。
fn ensure_to_tag(resp: &mut SipResponse) {
    if let Some(to) = resp.headers.get("to") {
        if !to.contains("tag=") {
            let new = format!("{};tag={}", to, new_tag());
            resp.headers.set("To", new);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::auth::{DigestChallenge, DigestCredentials};
    use crate::sip::message::{parse_message, SipMessage};
    use crate::testing::builders;
    use crate::testing::fixtures;

    /// 認証付き REGISTER の往復: クライアント側ソケットから REGISTER を送り、
    /// 401 → Authorization 付きで再送 → 200 OK を確認する。
    /// (RFC 3261 §10.2 / §22.4)
    #[tokio::test]
    async fn register_with_digest_succeeds() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        let registrar = uas.registrar();

        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        // テスト用クライアント
        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // 1) 認証なし REGISTER
        let req1 = builders::register_from_phone(&local, "iphone", "z9hG4bKreg1", None);
        client.send_to(&req1.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("401 timeout")
            .unwrap();
        let resp1 = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!("response expected"),
        };
        assert_eq!(resp1.status_code, 401);
        let www = resp1.headers.get("www-authenticate").unwrap().to_string();
        let challenge = DigestChallenge::parse(&www).unwrap();

        // 2) Authorization 付きで再送
        let creds = DigestCredentials::new("iphone", "secret");
        let auth = creds.compute(&challenge, "REGISTER", "sip:sabiden", 1);
        let req2 = builders::register_from_phone(
            &local,
            "iphone",
            "z9hG4bKreg2",
            Some(&auth.header_value),
        );
        client.send_to(&req2.to_bytes(), server_addr).await.unwrap();

        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("200 timeout")
            .unwrap();
        let resp2 = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!("response expected"),
        };
        assert_eq!(resp2.status_code, 200);

        let bindings = registrar.snapshot().await;
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].0, "iphone");
    }

    /// 不正パスワードでは 401 が再度返り、登録されない。
    #[tokio::test]
    async fn register_with_wrong_password_rejected() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        let registrar = uas.registrar();

        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        let req1 = builders::register_from_phone(&local, "iphone", "z9hG4bKbad1", None);
        client.send_to(&req1.to_bytes(), server_addr).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!(),
        };
        let challenge =
            DigestChallenge::parse(resp.headers.get("www-authenticate").unwrap()).unwrap();

        let creds = DigestCredentials::new("iphone", "WRONG");
        let auth = creds.compute(&challenge, "REGISTER", "sip:sabiden", 1);
        let req2 = builders::register_from_phone(
            &local,
            "iphone",
            "z9hG4bKbad2",
            Some(&auth.header_value),
        );
        client.send_to(&req2.to_bytes(), server_addr).await.unwrap();

        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp2 = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!(),
        };
        assert_eq!(resp2.status_code, 401);
        assert!(registrar.snapshot().await.is_empty());
    }

    /// 未登録ユーザは 403。
    #[tokio::test]
    async fn unknown_user_gets_403() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // 未登録ユーザで認証情報をでっち上げる
        let challenge = DigestChallenge {
            realm: "sabiden-test".into(),
            nonce: "fakenonce".into(),
            algorithm: "MD5".into(),
            qop: Some("auth".into()),
            opaque: None,
        };
        let creds = DigestCredentials::new("ghost", "anything");
        let auth = creds.compute(&challenge, "REGISTER", "sip:sabiden", 1);
        let req = builders::register_from_phone(
            &local,
            "ghost",
            "z9hG4bKghost",
            Some(&auth.header_value),
        );
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!(),
        };
        assert_eq!(resp.status_code, 403);
    }

    /// Call Manager 未接続なら認証済み INVITE は 503 で返る。
    #[tokio::test]
    async fn invite_without_handler_returns_503() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // チャレンジを取得するため認証なし INVITE を送る
        let mut req =
            builders::invite_from_phone(&local, "iphone", "sip:dest@sabiden", "z9hG4bKinv1", None);
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!(),
        };
        assert_eq!(resp.status_code, 401);
        let challenge =
            DigestChallenge::parse(resp.headers.get("www-authenticate").unwrap()).unwrap();

        // Authorization 付きで再送
        let creds = DigestCredentials::new("iphone", "secret");
        let auth = creds.compute(&challenge, "INVITE", "sip:dest@sabiden", 1);
        req = builders::invite_from_phone(
            &local,
            "iphone",
            "sip:dest@sabiden",
            "z9hG4bKinv2",
            Some(&auth.header_value),
        );
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        // 100 Trying と 503 が来るはず (順不同に近いがどちらも届くまで読む)
        let mut got_100 = false;
        let mut got_503 = false;
        for _ in 0..2 {
            let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                match r.status_code {
                    100 => got_100 = true,
                    503 => got_503 = true,
                    _ => {}
                }
            }
        }
        assert!(got_100 && got_503, "100 と 503 が届くべき");
    }

    /// `with_handler` で接続したチャネルに INVITE が転送される。
    #[tokio::test]
    async fn invite_with_handler_forwards_event() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // チャレンジ往復 (省略のため直接 challenge 値を作る代わりに UAS から取得)
        let mut req = builders::invite_from_phone(
            &local,
            "iphone",
            "sip:dest@sabiden",
            "z9hG4bKinvfwd1",
            None,
        );
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!(),
        };
        let challenge =
            DigestChallenge::parse(resp.headers.get("www-authenticate").unwrap()).unwrap();
        let creds = DigestCredentials::new("iphone", "secret");
        let auth = creds.compute(&challenge, "INVITE", "sip:dest@sabiden", 1);
        req = builders::invite_from_phone(
            &local,
            "iphone",
            "sip:dest@sabiden",
            "z9hG4bKinvfwd2",
            Some(&auth.header_value),
        );
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        // 上位層がイベントを受け取る
        let event = time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("event timeout")
            .expect("event present");
        match event {
            UasEvent::Invite {
                from_aor,
                responder,
                ..
            } => {
                assert_eq!(from_aor, "iphone");
                // 上位層相当: 200 OK を返してみる
                responder.quick(200, "OK").await.unwrap();
            }
            other => panic!("unexpected event: {:?}", other),
        }

        // 100 Trying / 200 OK 等、何らかの 2xx が届く
        let mut saw_2xx = false;
        for _ in 0..3 {
            match time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if (200..300).contains(&r.status_code) {
                            saw_2xx = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(saw_2xx, "200 OK が届くべき");
    }

    #[test]
    fn parse_expires_from_contact_param() {
        let mut req = SipRequest::new(SipMethod::Register, "sip:sabiden");
        req.headers.set("Contact", "<sip:iphone@host>;expires=120");
        assert_eq!(parse_register_expires(&req), 120);
    }

    #[test]
    fn parse_expires_from_header_when_no_contact_param() {
        let mut req = SipRequest::new(SipMethod::Register, "sip:sabiden");
        req.headers.set("Contact", "<sip:iphone@host>");
        req.headers.set("Expires", "240");
        assert_eq!(parse_register_expires(&req), 240);
    }

    #[test]
    fn extract_uri_brackets() {
        assert_eq!(
            extract_uri_from_contact("<sip:iphone@host>;expires=300"),
            "sip:iphone@host"
        );
    }

    #[test]
    fn extract_uri_no_brackets() {
        assert_eq!(
            extract_uri_from_contact("sip:iphone@host"),
            "sip:iphone@host"
        );
    }
}
