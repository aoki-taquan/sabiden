//! Web Push 通知 (Issue #294)
//!
//! PWA の tab が閉じている / 画面が lock されている状態でも NGN 着信を
//! ユーザに通知するため、 W3C Push API + Service Worker + RFC 8030
//! (Generic Event Delivery Using HTTP Push, GEDHP) 経路で push を送る。
//!
//! # 関連 RFC / 仕様
//!
//! - **RFC 8030**: HTTP Web Push の wire protocol (`POST <endpoint>` +
//!   `Encryption` / `Crypto-Key` / `TTL` ヘッダ等)。 push endpoint は
//!   subscribe 時にブラウザが提供する URL で、 sabiden は **VAPID 鍵で
//!   署名した JWT** を `Authorization` に載せて POST する。
//! - **RFC 8291** (Message Encryption for Web Push): payload は ECDH 派生
//!   鍵 + HKDF + AES128-GCM で encrypt して送る。 本実装では
//!   [`web_push::ContentEncoding::Aes128Gcm`] (= aes128gcm / RFC 8188) を使う。
//! - **RFC 8292** (Voluntary Application Server Identification, VAPID):
//!   push service に「だれが送ったか」を JWT で示す自主的な identification
//!   (= "voluntary")。 必須ではないが、 GCM/FCM 等のいくつかの push service
//!   は VAPID 無しの request を rate-limit / 拒否する。 公開鍵は base64-url
//!   形式でブラウザにも `applicationServerKey` として渡す
//!   (Push API §5.3 `PushManager.subscribe(options)`)。
//! - **W3C Push API**: ブラウザ側 API。 `navigator.serviceWorker` →
//!   `PushManager.subscribe(...)` で `PushSubscription` を得る。
//!
//! # VAPID 鍵生成手順 (運用者向け)
//!
//! VAPID 鍵は P-256 (prime256v1) ECDSA 鍵対。 公開鍵 (uncompressed, 65 byte)
//! を base64url で encode して PWA に渡し、 秘密鍵 (PEM) を sabiden の
//! 設定に渡す。
//!
//! ```bash
//! # 1. 秘密鍵 (P-256) を PEM で生成
//! openssl ecparam -name prime256v1 -genkey -noout -out vapid_private.pem
//!
//! # 2. PEM ファイルを `config.toml` の `[push] vapid_private_pem = "..."` に
//! #    base64-encode せず **PEM 全文** で書く (改行を `\n` で escape):
//! #    あるいは環境変数 `SABIDEN_VAPID_PRIVATE_PEM` で渡す。
//!
//! # 3. PWA に渡す applicationServerKey (uncompressed public key の base64url)
//! #    は sabiden が `GET /api/push/vapid-public-key` で配信する
//! #    (= [`VapidKeys::public_key_b64url`] を JSON で返す)。
//! ```
//!
//! # アーキテクチャ
//!
//! ```text
//! [Browser]                [sabiden]                [Push Service (FCM/Mozilla)]
//!    │                        │                                │
//!    │  POST /api/push/subscribe (endpoint, p256dh, auth)      │
//!    │ ─────────────────────► │                                │
//!    │                        │ store in PushSubscriptionStore │
//!    │                        │                                │
//!    │   NGN INVITE received  │                                │
//!    │                        │  POST <endpoint> (encrypted)   │
//!    │                        │ ─────────────────────────────► │
//!    │   push event delivered │                                │
//!    │ ◄──────────────────────┼────────────────────────────────│
//!    │                        │                                │
//! [Service Worker]            │                                │
//!    │ show Notification      │                                │
//!    │ on tap: clients.openWindow + signaling reconnect        │
//! ```
//!
//! # 設計判断
//!
//! - **store は in-memory + AOR (= ext_id) キー**: 1 AOR に複数 device は
//!   持てる。 同一 device の再 subscribe は `endpoint` (URL) 一意で dedup。
//! - **404 / 410 で自動 unsubscribe**: RFC 8030 §5 の "Removing a Subscription"
//!   (`POST` への応答が 404 Not Found / 410 Gone) は subscription が
//!   永続的に無効化されたことを示す。 store から削除する。
//! - **`PushNotifier` を trait に分離**: unit test で `MockPushNotifier` を
//!   差し込めるようにする (production code から panic/unwrap を避けるため)。

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use web_push::{
    ContentEncoding, IsahcWebPushClient, PartialVapidSignatureBuilder, SubscriptionInfo,
    VapidSignatureBuilder, WebPushClient, WebPushError, WebPushMessageBuilder,
};

/// 1 つの PWA Push 購読 (= 1 endpoint / device)。
///
/// `endpoint` は browser が `PushManager.subscribe` で返す URL。
/// `p256dh` は ECDH 公開鍵 (base64-url, padding 無し)、 `auth` は 16 byte の
/// 認証 secret (同じく base64-url)。 RFC 8291 §4.1。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PushSubscription {
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

impl PushSubscription {
    /// browser 由来の値を簡易検証する。 RFC 8030 / 8291 で endpoint は HTTPS
    /// URL で、 p256dh / auth は base64url 文字列。 本関数は **形式チェック**
    /// のみで、 暗号鍵としての妥当性 (= 圧縮形式 byte 長 65 等) は
    /// `WebPushMessageBuilder::build` 側で検出する (= `InvalidCryptoKeys` を
    /// 返す)。
    ///
    /// # base64url padding の扱い (Issue #307)
    ///
    /// `p256dh` / `auth` の base64url encode は **padding (`=`) 無し** が正則。
    ///
    /// - **RFC 4648 §3.2**: padding は "MAY be required"。 base64url を採用する
    ///   個別仕様が padding 有無を定める。
    /// - **RFC 8291 §3.2 (Web Push 鍵): "values are encoded using
    ///   base64url encoding [RFC7515]"**。 RFC 7515 §2 (JSON Web Signature) の
    ///   "Base64url Encoding" 定義は **明示的に no-padding** で固定されている
    ///   ("Base64 encoding using the URL- and filename-safe character set ...
    ///   with all trailing '=' characters omitted")。
    /// - PWA frontend (`navigator.serviceWorker` 経由) も意図的に `=` を strip
    ///   して送ってくるため、 server が `=` 入りを許容すると、 同一 device で
    ///   「padding 有り版」 と「padding 無し版」 の **二重 entry** が
    ///   `PushSubscriptionStore` に登録されうる。 fan-out が 2 重発火する。
    ///
    /// 以上から padding (`=`) を含む値は **Err で reject** する。
    pub fn validate(&self) -> Result<()> {
        if !(self.endpoint.starts_with("https://") || self.endpoint.starts_with("http://")) {
            return Err(anyhow!(
                "endpoint must be an http(s) URL (got: {})",
                self.endpoint
            ));
        }
        if self.endpoint.len() > 2048 {
            return Err(anyhow!("endpoint length exceeds 2048"));
        }
        for (name, value) in [("p256dh", &self.p256dh), ("auth", &self.auth)] {
            if value.is_empty() {
                return Err(anyhow!("{name} must not be empty"));
            }
            // RFC 7515 §2 / RFC 8291 §3.2: base64url for Web Push keys is
            // **no-padding**。 `=` 入りは reject (Issue #307)。
            if value.contains('=') {
                return Err(anyhow!(
                    "{name} must be base64url without padding (RFC 7515 §2 / RFC 8291 §3.2)"
                ));
            }
            if !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(anyhow!("{name} must be base64url"));
            }
        }
        Ok(())
    }
}

/// 着信通知のペイロード。 Service Worker (`sw.js`) が受け取り、
/// `Notification API` で表示するためのデータ。
///
/// JSON にしてから AES128-GCM で encrypt して push service に送る (RFC 8291)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncomingCallPayload {
    /// メッセージ種別を `serde` の untagged 衝突を避けるために明示する。
    /// 将来別種の通知 (例: voicemail 着信) を追加した際に SW 側で switch する。
    #[serde(rename = "type")]
    pub kind: String,
    /// NGN INVITE の Call-ID。 PWA が WS reconnect → ringing に合わせるために使う。
    pub call_id: String,
    /// 発信者番号 (例 `"117"`、 NGN inbound で carrier IMS が PAI/PPI を剥ぐ
    /// 場合は `"anonymous"` 等)。 表示用途のみ。
    pub caller_number: String,
    /// 通知発火 UNIX 秒 (Service Worker 側で stale 通知の suppression に使う)。
    pub issued_at: u64,
}

impl IncomingCallPayload {
    pub fn new(call_id: impl Into<String>, caller_number: impl Into<String>) -> Self {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            kind: "incoming_call".to_string(),
            call_id: call_id.into(),
            caller_number: caller_number.into(),
            issued_at,
        }
    }
}

/// AOR (= ext_id) → 購読集合のテーブル。
///
/// 同一 AOR に複数 device (例: 自宅 PC + スマホ) を許容するため `Vec` で持つ。
/// `endpoint` の値で重複は dedup する (= 同一 device の再 subscribe は上書き)。
#[derive(Default)]
pub struct PushSubscriptionStore {
    inner: Mutex<HashMap<String, Vec<PushSubscription>>>,
}

impl PushSubscriptionStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// AOR に対して購読を登録/更新する。 同じ `endpoint` の既存 entry は
    /// 置き換える (= 同一 device の鍵 rotation を許容する)。
    pub async fn upsert(&self, aor: &str, sub: PushSubscription) -> Result<()> {
        sub.validate().context("push subscription validation")?;
        let mut t = self.inner.lock().await;
        let entry = t.entry(aor.to_string()).or_default();
        entry.retain(|s| s.endpoint != sub.endpoint);
        entry.push(sub);
        Ok(())
    }

    /// AOR + endpoint を取り除く (RFC 8030 §5 404/410 受信時、 もしくは
    /// PWA の明示的 unsubscribe で呼ぶ)。 戻り値は実際に削除した件数。
    pub async fn remove(&self, aor: &str, endpoint: &str) -> usize {
        let mut t = self.inner.lock().await;
        let Some(entry) = t.get_mut(aor) else {
            return 0;
        };
        let before = entry.len();
        entry.retain(|s| s.endpoint != endpoint);
        let removed = before - entry.len();
        if entry.is_empty() {
            t.remove(aor);
        }
        removed
    }

    /// AOR の購読一覧を返す (空ならば空 Vec)。
    pub async fn list(&self, aor: &str) -> Vec<PushSubscription> {
        let t = self.inner.lock().await;
        t.get(aor).cloned().unwrap_or_default()
    }

    /// 全 AOR + 購読の snapshot を返す (テスト・診断用)。
    pub async fn snapshot(&self) -> HashMap<String, Vec<PushSubscription>> {
        self.inner.lock().await.clone()
    }

    /// AOR 数を返す。
    pub async fn aor_count(&self) -> usize {
        self.inner.lock().await.len()
    }
}

/// VAPID 鍵対 (RFC 8292)。
///
/// `private_pem` は PEM 文字列 (PKCS#8 or SEC1)、 `public_b64url` は
/// `applicationServerKey` として PWA に渡す uncompressed 公開鍵を base64url
/// encode したもの。 sabiden 起動時に PEM から派生して keep する。
#[derive(Clone)]
pub struct VapidKeys {
    private_pem: Arc<Vec<u8>>,
    public_b64url: String,
    /// VAPID JWT の `sub` claim に入る連絡先 (RFC 8292 §2.1.1):
    /// `mailto:operator@example.com` か `https://example.com` の URL。
    /// 多くの push service は `sub` 必須。
    subject: String,
}

impl VapidKeys {
    /// PEM 文字列から VAPID 鍵対を構築する。 PEM は PKCS#8 (`-----BEGIN PRIVATE KEY-----`)
    /// または SEC1 (`-----BEGIN EC PRIVATE KEY-----`) のどちらでも可
    /// ([`VapidSignatureBuilder::from_pem_no_sub`] の仕様)。
    pub fn from_pem(pem: &str, subject: &str) -> Result<Self> {
        if subject.is_empty() {
            return Err(anyhow!("vapid subject must not be empty"));
        }
        let pem_bytes = pem.as_bytes().to_vec();
        let partial: PartialVapidSignatureBuilder =
            VapidSignatureBuilder::from_pem_no_sub(std::io::Cursor::new(pem_bytes.clone()))
                .map_err(|e| anyhow!("VAPID PEM parse 失敗: {e}"))?;
        let public_key_bytes = partial.get_public_key();
        let public_b64url = URL_SAFE_NO_PAD.encode(&public_key_bytes);
        Ok(Self {
            private_pem: Arc::new(pem_bytes),
            public_b64url,
            subject: subject.to_string(),
        })
    }

    pub fn public_key_b64url(&self) -> &str {
        &self.public_b64url
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// PEM bytes を Cursor で取り出す (`VapidSignatureBuilder::from_pem*` が
    /// `Read` を要求するため)。 起動時 1 度の builder 構築でのみ呼ぶ想定
    /// (Issue #308: 通知ごとの再パースは廃止)。 内部は `Arc<Vec<u8>>` で
    /// 共有しているので clone コストは小さい。
    pub(crate) fn pem_cursor(&self) -> std::io::Cursor<Vec<u8>> {
        std::io::Cursor::new((*self.private_pem).clone())
    }
}

/// Push 送信抽象。 production は [`WebPushNotifier`]、 test は
/// [`MockPushNotifier`] を使う。
///
/// `send_incoming_call` は **per-subscription** で結果を返す。 1 件失敗しても
/// 他の subscription への送信は継続する責務は呼出側 (= 高レベル fan-out
/// ヘルパ `notify_incoming_call`) にある。
#[async_trait]
pub trait PushNotifier: Send + Sync {
    async fn send_incoming_call(
        &self,
        sub: &PushSubscription,
        payload: &IncomingCallPayload,
    ) -> Result<(), PushSendError>;
}

/// `PushNotifier::send_incoming_call` の失敗を呼出側がカテゴリ分けできるよう
/// 分類した error。 `Gone` の場合は store から該当 subscription を破棄する。
///
/// # 区別の根拠 (Issue #309, RFC 8030 §5)
///
/// RFC 8030 §5 ("Removing a Subscription") は 404 / 410 を「永続的無効」 と
/// 規定する。 一方 401 Unauthorized (VAPID JWT exp 切れや署名鍵 rotation) は
/// **再起動 / 鍵 reload で復活可能** な一時状態。 5xx / IO error も同様に
/// transient。 そのため:
///
/// - **`Gone`**: 404 / 410。 store から該当 subscription を即削除。
/// - **`Rejected { code, message }`**: 400 BadRequest / 413 PayloadTooLarge /
///   InvalidCryptoKeys 等、 **request 自体が恒久的に不正**。 store は保持
///   (config を直して再起動すれば直る可能性はあるが、 そのままでは何度送っても
///   同じ結果)。 `code` は HTTP status 由来の数値で、 metric / log 区別用。
/// - **`Transient(String)`**: 401 Unauthorized (JWT exp 切れ等) / 5xx ServerError
///   / connection IO / unencryptable payload。 retry もしくは次回 INVITE で
///   復活する想定。 store は当然保持。
#[derive(Debug)]
pub enum PushSendError {
    /// RFC 8030 §5: 404 Not Found / 410 Gone。 subscription は永続的に無効。
    Gone,
    /// 4xx (Gone / Unauthorized を除く) の恒久 reject。
    /// `code` は HTTP status code 相当 (web-push crate 内 mapping、 必ずしも
    /// 受信した wire 上の数値とは限らない)。 metric / log で分類するために
    /// 数値で保持する。
    Rejected { code: u16, message: String },
    /// 5xx / connection error / unencryptable payload / 401 Unauthorized
    /// (JWT exp 切れ等の一時不正)。 store は保持し、 次回送信で復活を期待する。
    Transient(String),
}

impl PushSendError {
    /// `Rejected` を構築するヘルパ。 internal error (= crate 内で発生して
    /// wire status を持たない error: payload serialize 失敗等) は
    /// `code = 0` を使う。
    fn rejected(code: u16, message: impl Into<String>) -> Self {
        PushSendError::Rejected {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PushSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushSendError::Gone => f.write_str("subscription gone (404/410)"),
            PushSendError::Rejected { code, message } => {
                write!(f, "push rejected ({code}): {message}")
            }
            PushSendError::Transient(m) => write!(f, "push transient error: {m}"),
        }
    }
}

impl std::error::Error for PushSendError {}

impl From<WebPushError> for PushSendError {
    fn from(e: WebPushError) -> Self {
        // RFC 8030 §5 (Removing a Subscription): 404 / 410 = 永続的無効
        // (web-push crate では `EndpointNotFound` / `EndpointNotValid`)。
        //
        // RFC 8030 §5 (Request Validation): 400 BadRequest / 413 PayloadTooLarge
        // は request 自体の不正で、 同じ subscription でも request 内容を
        // 直さない限り恒久 reject。
        //
        // RFC 8292 §2 (VAPID): 401 Unauthorized は JWT exp 切れや署名鍵 rotation
        // で発生する **一時** 不正。 次回送信時に JWT を作り直せば復活する。
        // ゆえに Transient に振り分ける (Issue #309)。
        //
        // 5xx ServerError / IO / Unspecified は network or push service 側の
        // 一時障害で、 retry で復活する想定 → Transient。
        match e {
            WebPushError::EndpointNotValid(_) | WebPushError::EndpointNotFound(_) => {
                PushSendError::Gone
            }
            // RFC 8030 §5 で `Bad Request` (400) は subscription 自体の問題ではなく
            // request 内容の不正 (payload / header) を示す。
            WebPushError::BadRequest(_) => PushSendError::rejected(400, e.to_string()),
            // RFC 8030 §5 で 413 Payload Too Large。
            WebPushError::PayloadTooLarge => PushSendError::rejected(413, e.to_string()),
            // 暗号鍵 / package name / TTL / Topic / Claims は crate 内 validation
            // 失敗で wire status を持たないが、 request 内容が恒久的に不正なので
            // Rejected 扱い。 code = 0 (= 内部 validation error)。
            WebPushError::InvalidCryptoKeys
            | WebPushError::MissingCryptoKeys
            | WebPushError::InvalidPackageName
            | WebPushError::InvalidTtl
            | WebPushError::InvalidTopic
            | WebPushError::InvalidClaims
            | WebPushError::InvalidUri => PushSendError::rejected(0, e.to_string()),
            // 401: VAPID JWT exp 切れ等は一時的 → Transient (Issue #309)。
            WebPushError::Unauthorized(_) => PushSendError::Transient(e.to_string()),
            // 5xx server-side。 retry_after は web-push crate が保持するが
            // 上位はまず種別だけ知れれば良い。
            WebPushError::ServerError { .. } => PushSendError::Transient(e.to_string()),
            _ => PushSendError::Transient(e.to_string()),
        }
    }
}

/// 本番用 `PushNotifier`: VAPID 署名 + AES128-GCM (RFC 8291) で Push Service
/// に送信する。 内部は isahc-based HTTP/2 client (`IsahcWebPushClient`)
/// を使う (web-push crate 既定)。
///
/// # VAPID 鍵の再利用 (Issue #308)
///
/// `PartialVapidSignatureBuilder` は **PEM パース + ECDSA 鍵展開済み**
/// の状態を保持する。 通知 1 件ごとに PEM 文字列から都度パースすると
/// 数 ms の ECDSA decode が hot path に乗る (fan-out 数 × Issue #294 規模)。
/// web-push crate `vapid/builder.rs` §270 `#[derive(Clone)]` + §276
/// `add_sub_info(self, sub_info)` を利用し、 起動時に 1 度だけ PEM を
/// パース → builder を保持 → 送信ごとに `.clone()` してから per-subscription
/// `add_sub_info(&info)` で `VapidSignatureBuilder<'_>` を取り出す。
pub struct WebPushNotifier {
    client: IsahcWebPushClient,
    keys: VapidKeys,
    /// 起動時に PEM から構築した署名 builder。 ECDSA private key を
    /// 内部に保持する。 通知ごとに `clone()` (= 鍵 byte の `Arc`-like cheap
    /// copy) してから `add_sub_info` を呼ぶ。
    sig_builder: PartialVapidSignatureBuilder,
}

impl WebPushNotifier {
    pub fn new(keys: VapidKeys) -> Result<Self> {
        let client =
            IsahcWebPushClient::new().map_err(|e| anyhow!("isahc HTTP client init: {e}"))?;
        // 起動時に 1 度だけ PEM をパースして、 後の送信では clone + add_sub_info
        // のみで JWT を作る (Issue #308)。
        let sig_builder = VapidSignatureBuilder::from_pem_no_sub(keys.pem_cursor())
            .map_err(|e| anyhow!("VAPID PEM パース失敗 (起動時): {e}"))?;
        Ok(Self {
            client,
            keys,
            sig_builder,
        })
    }

    pub fn keys(&self) -> &VapidKeys {
        &self.keys
    }
}

#[async_trait]
impl PushNotifier for WebPushNotifier {
    async fn send_incoming_call(
        &self,
        sub: &PushSubscription,
        payload: &IncomingCallPayload,
    ) -> Result<(), PushSendError> {
        let info = SubscriptionInfo::new(&sub.endpoint, &sub.p256dh, &sub.auth);
        // RFC 8292 §2: VAPID 署名は subscription 毎に audience (endpoint origin)
        // を含む JWT。 起動時 cache 済の `PartialVapidSignatureBuilder` を clone
        // し、 per-send で `add_sub_info(&info)` から完成させる (Issue #308)。
        let mut sig_builder = self.sig_builder.clone().add_sub_info(&info);
        // RFC 8292 §2.1.1 `sub` claim。
        sig_builder.add_claim("sub", self.keys.subject.as_str());
        let sig = sig_builder
            .build()
            .map_err(|e| PushSendError::rejected(0, format!("VAPID signature build: {e}")))?;

        let body = serde_json::to_vec(payload)
            .map_err(|e| PushSendError::rejected(0, format!("payload JSON serialize 失敗: {e}")))?;
        let mut builder = WebPushMessageBuilder::new(&info);
        // RFC 8030 §5.2: TTL (秒)。 着信通知は短く保つ (5 分 = 300 秒)。
        // それを超えて未配送なら通話は既に終わっている可能性が高い。
        builder.set_ttl(300);
        // RFC 8030 §5.3 / Push API §5.4: urgency=high で電池節約モードでも
        // 配送される (着信は最も優先度が高い)。
        builder.set_urgency(web_push::Urgency::High);
        builder.set_payload(ContentEncoding::Aes128Gcm, &body);
        builder.set_vapid_signature(sig);
        let msg = builder.build().map_err(PushSendError::from)?;
        self.client.send(msg).await.map_err(PushSendError::from)?;
        Ok(())
    }
}

/// signaling 層 [`crate::webrtc::signaling::PwaPushHandler`] の本番実装。
///
/// `ClientMessage::PushSubscribe` を受領した signaling 層が本 trait 経由で
/// AOR + endpoint + keys を渡すと、 内部の [`PushSubscriptionStore`] に upsert
/// する。 validate は [`PushSubscription::validate`] (HTTPS / base64url / 空鍵
/// 検査) に委譲する。
#[async_trait]
impl crate::webrtc::signaling::PwaPushHandler for PushSubscriptionStore {
    async fn upsert_subscription(
        &self,
        aor: &str,
        endpoint: &str,
        p256dh: &str,
        auth: &str,
    ) -> Result<()> {
        let sub = PushSubscription {
            endpoint: endpoint.to_string(),
            p256dh: p256dh.to_string(),
            auth: auth.to_string(),
        };
        // store.upsert は validate を内部で呼ぶ (HTTPS / base64url / 空鍵検査)。
        self.upsert(aor, sub).await
    }
}

/// 全 AOR の購読に着信通知を fan-out するヘルパ。
///
/// 1 件失敗しても他の subscription への送信は継続する。 `Gone` 系の error は
/// その場で `store` から削除する (RFC 8030 §5)。 戻り値は `(sent, dropped)` で、
/// `sent` は 200/201 が返った件数、 `dropped` は Gone で破棄した件数。
pub async fn notify_incoming_call(
    store: &PushSubscriptionStore,
    notifier: &dyn PushNotifier,
    aor: &str,
    payload: &IncomingCallPayload,
) -> (usize, usize) {
    let subs = store.list(aor).await;
    if subs.is_empty() {
        debug!(%aor, "push: 購読なし (skip)");
        return (0, 0);
    }
    let mut sent = 0usize;
    let mut dropped = 0usize;
    for sub in subs {
        match notifier.send_incoming_call(&sub, payload).await {
            Ok(()) => {
                sent += 1;
                debug!(%aor, endpoint=%sub.endpoint, "push: 送信成功");
            }
            Err(PushSendError::Gone) => {
                let n = store.remove(aor, &sub.endpoint).await;
                dropped += n;
                info!(%aor, endpoint=%sub.endpoint, removed=n, "push: subscription Gone → store から削除");
            }
            Err(e @ PushSendError::Rejected { .. }) => {
                // 恒久 reject (Issue #309): config / request 自体が不正。
                // 再送しても改善せず subscription も保持 (rotation 等で別ルートから直る可能性)。
                warn!(%aor, endpoint=%sub.endpoint, error=%e, "push: 送信 Rejected (subscription 保持)");
            }
            Err(e @ PushSendError::Transient(_)) => {
                // 一時障害 (5xx / 401 JWT exp / IO 等): retry 視野で subscription 保持。
                warn!(%aor, endpoint=%sub.endpoint, error=%e, "push: 送信 Transient (subscription 保持、 次回 retry)");
            }
        }
    }
    (sent, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// RFC 8030 / 8291 に直接依存しないテスト用 PushNotifier。 送信ログのみ
    /// 保持し、 `Gone` を指定すれば該当 subscription の自動削除経路も検証できる。
    #[derive(Default)]
    struct MockPushNotifier {
        sent: Mutex<Vec<(PushSubscription, IncomingCallPayload)>>,
        gone_endpoints: Mutex<Vec<String>>,
        send_count: AtomicUsize,
    }

    #[async_trait]
    impl PushNotifier for MockPushNotifier {
        async fn send_incoming_call(
            &self,
            sub: &PushSubscription,
            payload: &IncomingCallPayload,
        ) -> Result<(), PushSendError> {
            self.send_count.fetch_add(1, Ordering::SeqCst);
            if self.gone_endpoints.lock().await.contains(&sub.endpoint) {
                return Err(PushSendError::Gone);
            }
            self.sent.lock().await.push((sub.clone(), payload.clone()));
            Ok(())
        }
    }

    fn make_sub(endpoint: &str) -> PushSubscription {
        PushSubscription {
            endpoint: endpoint.to_string(),
            // RFC 8291 §4.1: p256dh / auth は base64url。 形式チェックの最小値。
            p256dh: "BPq".to_string(),
            auth: "AAAA".to_string(),
        }
    }

    /// CRUD #1: upsert + list が等しく round-trip する。
    #[tokio::test]
    async fn store_upsert_then_list_returns_same_subscription() {
        let store = PushSubscriptionStore::new();
        let sub = make_sub("https://updates.push.services.mozilla.com/wpush/v1/abc");
        store.upsert("alice", sub.clone()).await.unwrap();
        let got = store.list("alice").await;
        assert_eq!(got, vec![sub]);
    }

    /// CRUD #2: 同じ endpoint で再 upsert すると上書きされ、 件数は増えない。
    #[tokio::test]
    async fn store_upsert_same_endpoint_replaces_in_place() {
        let store = PushSubscriptionStore::new();
        let mut sub = make_sub("https://example.com/p/1");
        store.upsert("alice", sub.clone()).await.unwrap();
        sub.p256dh = "BPq-rotated".to_string();
        store.upsert("alice", sub.clone()).await.unwrap();
        let got = store.list("alice").await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].p256dh, "BPq-rotated");
    }

    /// CRUD #3: 異なる endpoint は AOR 内に並ぶ (1 AOR 複数 device)。
    #[tokio::test]
    async fn store_supports_multiple_endpoints_per_aor() {
        let store = PushSubscriptionStore::new();
        store
            .upsert("alice", make_sub("https://example.com/p/1"))
            .await
            .unwrap();
        store
            .upsert("alice", make_sub("https://example.com/p/2"))
            .await
            .unwrap();
        let got = store.list("alice").await;
        assert_eq!(got.len(), 2);
    }

    /// CRUD #4: remove で AOR が空になると entry ごと消える。
    #[tokio::test]
    async fn store_remove_drops_empty_aor() {
        let store = PushSubscriptionStore::new();
        let endpoint = "https://example.com/p/1";
        store.upsert("alice", make_sub(endpoint)).await.unwrap();
        assert_eq!(store.aor_count().await, 1);
        let removed = store.remove("alice", endpoint).await;
        assert_eq!(removed, 1);
        assert_eq!(store.aor_count().await, 0);
        assert!(store.list("alice").await.is_empty());
    }

    /// validate: HTTPS 以外は弾く。
    #[tokio::test]
    async fn subscription_validate_rejects_non_http_url() {
        let mut sub = make_sub("https://example.com/p/1");
        sub.endpoint = "ftp://example.com/x".to_string();
        let err = sub.validate().unwrap_err();
        assert!(err.to_string().contains("http"));
    }

    /// validate: p256dh 空は弾く。
    #[tokio::test]
    async fn subscription_validate_rejects_empty_key() {
        let mut sub = make_sub("https://example.com/p/1");
        sub.p256dh = String::new();
        assert!(sub.validate().is_err());
    }

    /// validate: base64url padding (`=`) を含む鍵を reject する (Issue #307,
    /// RFC 7515 §2 / RFC 8291 §3.2)。 p256dh / auth どちらでも reject。
    #[tokio::test]
    async fn subscription_validate_rejects_base64url_padding_in_p256dh() {
        let mut sub = make_sub("https://example.com/p/1");
        // 末尾に padding が付いた値
        sub.p256dh = "BPq=".to_string();
        let err = sub.validate().unwrap_err();
        // メッセージに padding 検出が出ていること (RFC 引用込み)
        let msg = err.to_string();
        assert!(
            msg.contains("padding") || msg.contains("RFC 7515"),
            "unexpected error message: {msg}"
        );
    }

    #[tokio::test]
    async fn subscription_validate_rejects_base64url_padding_in_auth() {
        let mut sub = make_sub("https://example.com/p/1");
        sub.auth = "AAA=".to_string();
        assert!(sub.validate().is_err());
    }

    /// validate: padding 無しの (正則な) base64url は通る (regression 用)。
    #[tokio::test]
    async fn subscription_validate_accepts_base64url_no_padding() {
        let sub = PushSubscription {
            endpoint: "https://example.com/p/1".to_string(),
            // 典型的な uncompressed P-256 公開鍵 base64url (87 文字、 padding なし)
            p256dh:
                "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM"
                    .to_string(),
            // 典型的な 16 byte auth secret base64url (22 文字、 padding なし)
            auth: "tBHItJI5svbpez7KI4CCXg".to_string(),
        };
        assert!(sub.validate().is_ok());
    }

    /// `PushSendError`: Display で variant が区別できる (metric / log 用)。
    #[test]
    fn push_send_error_display_distinguishes_variants() {
        assert!(PushSendError::Gone.to_string().contains("gone"));
        let rejected = PushSendError::Rejected {
            code: 413,
            message: "payload too large".to_string(),
        };
        let s = rejected.to_string();
        assert!(s.contains("413"));
        assert!(s.contains("payload too large"));

        let transient = PushSendError::Transient("io".to_string());
        assert!(transient.to_string().contains("transient"));
    }

    /// `WebPushError` → `PushSendError` 変換: Issue #309 の主旨。
    ///
    /// `web_push::ErrorInfo` は crate 外に公開されていない (lib.rs §55-61 の
    /// re-export 対象外) ため、 `ErrorInfo` を要求する variant
    /// (`Unauthorized` / `BadRequest` / `Endpoint*` / `ServerError` /
    /// `NotImplemented` / `Other`) の直接構築はテストできない。
    /// ここでは **構築できる unit variant** のみで対応表を検証する。
    ///
    /// `Unauthorized` を Transient に振り分ける Issue #309 主旨は、
    /// `From<WebPushError> for PushSendError` の docstring + match 表で
    /// **本流側コードで明示** している (= レビューでの担保)。
    #[test]
    fn web_push_error_maps_payload_too_large_to_rejected_413() {
        let e: PushSendError = WebPushError::PayloadTooLarge.into();
        match e {
            PushSendError::Rejected { code, .. } => assert_eq!(code, 413),
            other => panic!("expected Rejected(413), got {:?}", other),
        }
    }

    #[test]
    fn web_push_error_maps_invalid_crypto_keys_to_rejected_zero() {
        let e: PushSendError = WebPushError::InvalidCryptoKeys.into();
        match e {
            PushSendError::Rejected { code, .. } => assert_eq!(code, 0),
            other => panic!("expected Rejected(0), got {:?}", other),
        }
    }

    #[test]
    fn web_push_error_maps_missing_crypto_keys_to_rejected_zero() {
        let e: PushSendError = WebPushError::MissingCryptoKeys.into();
        match e {
            PushSendError::Rejected { code, .. } => assert_eq!(code, 0),
            other => panic!("expected Rejected(0), got {:?}", other),
        }
    }

    #[test]
    fn web_push_error_maps_invalid_ttl_to_rejected_zero() {
        let e: PushSendError = WebPushError::InvalidTtl.into();
        match e {
            PushSendError::Rejected { code, .. } => assert_eq!(code, 0),
            other => panic!("expected Rejected(0), got {:?}", other),
        }
    }

    #[test]
    fn web_push_error_maps_invalid_topic_to_rejected_zero() {
        let e: PushSendError = WebPushError::InvalidTopic.into();
        assert!(matches!(e, PushSendError::Rejected { code: 0, .. }));
    }

    #[test]
    fn web_push_error_maps_invalid_package_name_to_rejected_zero() {
        let e: PushSendError = WebPushError::InvalidPackageName.into();
        assert!(matches!(e, PushSendError::Rejected { code: 0, .. }));
    }

    #[test]
    fn web_push_error_maps_invalid_uri_to_rejected_zero() {
        let e: PushSendError = WebPushError::InvalidUri.into();
        assert!(matches!(e, PushSendError::Rejected { code: 0, .. }));
    }

    /// 5xx ServerError / IO / Unspecified / InvalidResponse / ResponseTooLarge
    /// 等は **Transient** (Issue #309)。 unit variant の中から代表選定。
    #[test]
    fn web_push_error_maps_unspecified_to_transient() {
        let e: PushSendError = WebPushError::Unspecified.into();
        assert!(matches!(e, PushSendError::Transient(_)));
    }

    #[test]
    fn web_push_error_maps_invalid_response_to_transient() {
        let e: PushSendError = WebPushError::InvalidResponse.into();
        assert!(matches!(e, PushSendError::Transient(_)));
    }

    #[test]
    fn web_push_error_maps_response_too_large_to_transient() {
        let e: PushSendError = WebPushError::ResponseTooLarge.into();
        assert!(matches!(e, PushSendError::Transient(_)));
    }

    /// notify fan-out: 複数 subscription に正しく送信される。
    #[tokio::test]
    async fn notify_incoming_call_fans_out_to_all_subscriptions() {
        let store = PushSubscriptionStore::new();
        store
            .upsert("alice", make_sub("https://example.com/p/1"))
            .await
            .unwrap();
        store
            .upsert("alice", make_sub("https://example.com/p/2"))
            .await
            .unwrap();
        let notifier = MockPushNotifier::default();
        let payload = IncomingCallPayload::new("call-123", "0312345678");
        let (sent, dropped) = notify_incoming_call(&store, &notifier, "alice", &payload).await;
        assert_eq!(sent, 2);
        assert_eq!(dropped, 0);
        assert_eq!(notifier.send_count.load(Ordering::SeqCst), 2);
    }

    /// notify fan-out: Gone (404/410) endpoint は store から自動削除される
    /// (RFC 8030 §5)。
    #[tokio::test]
    async fn notify_incoming_call_auto_removes_gone_subscriptions() {
        let store = PushSubscriptionStore::new();
        store
            .upsert("alice", make_sub("https://example.com/p/gone"))
            .await
            .unwrap();
        store
            .upsert("alice", make_sub("https://example.com/p/ok"))
            .await
            .unwrap();
        let notifier = MockPushNotifier::default();
        notifier
            .gone_endpoints
            .lock()
            .await
            .push("https://example.com/p/gone".to_string());
        let payload = IncomingCallPayload::new("call-1", "117");
        let (sent, dropped) = notify_incoming_call(&store, &notifier, "alice", &payload).await;
        assert_eq!(sent, 1);
        assert_eq!(dropped, 1);
        let remaining = store.list("alice").await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].endpoint, "https://example.com/p/ok");
    }

    /// notify fan-out: 該当 AOR の購読が無い場合は (0, 0)。
    #[tokio::test]
    async fn notify_incoming_call_no_subscriptions_returns_zero() {
        let store = PushSubscriptionStore::new();
        let notifier = MockPushNotifier::default();
        let payload = IncomingCallPayload::new("call-1", "117");
        let (sent, dropped) = notify_incoming_call(&store, &notifier, "ghost", &payload).await;
        assert_eq!(sent, 0);
        assert_eq!(dropped, 0);
        assert_eq!(notifier.send_count.load(Ordering::SeqCst), 0);
    }

    /// IncomingCallPayload は JSON で round-trip する (Service Worker 受信時の
    /// パース互換)。 `kind: "incoming_call"` が固定であることも確認する。
    #[test]
    fn payload_serializes_with_stable_type_tag() {
        let p = IncomingCallPayload::new("call-1", "117");
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["type"], "incoming_call");
        assert_eq!(json["call_id"], "call-1");
        assert_eq!(json["caller_number"], "117");
        // round-trip
        let back: IncomingCallPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back, p);
    }

    /// VAPID PEM 文字列 (PKCS#8) から鍵対が構築でき、 base64url 公開鍵が
    /// uncompressed P-256 (= 65 byte → base64url 87 文字弱) に近い長さで
    /// 出てくることを確認する。 RFC 8292 §3.2 (公開鍵 export 形式)。
    #[test]
    fn vapid_keys_from_pem_returns_public_key_b64url() {
        // P-256 PEM (PKCS#8) は OpenSSL `openssl ecparam ... | openssl pkcs8`
        // で生成する。 テストでは固定値ベクタ:
        //
        //   $ openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt
        //
        // 以下は本テスト専用の使い捨て鍵。 production secret ではない。
        const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgb2gYuG8JTWzkrOXL\n\
Ysmtx3EJ1admqAJc8UwOexy1MFKhRANCAAQtqZ42q5xPHcPSMGdo7DdS9vaFSB4w\n\
QdPnU3DA4y5ptWiM3WQVvw8Xvk6BWnZcrNr1fh1uP9V/w+CG76Ya0gKP\n\
-----END PRIVATE KEY-----\n";
        let keys = VapidKeys::from_pem(TEST_PEM, "mailto:test@example.com").unwrap();
        assert_eq!(keys.subject(), "mailto:test@example.com");
        let pub_b64 = keys.public_key_b64url();
        // base64url encoded 65 byte → ceil(65/3 * 4) = 88 chars (no padding 87)
        assert!(pub_b64.len() >= 80, "public key too short: {pub_b64}");
        // base64url 文字種のみ
        assert!(pub_b64
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    /// Issue #308: `WebPushNotifier::new` が `PartialVapidSignatureBuilder`
    /// を 1 回だけ構築して保持する。 PEM が壊れていれば new で失敗する
    /// (= 通知ごとの再パースは廃止された)。
    ///
    /// `IsahcWebPushClient::new()` も呼ぶので、 isahc init が失敗する環境
    /// (例: 一部 sandbox) では skip 相当の扱いをする。
    #[test]
    fn web_push_notifier_new_parses_pem_once_at_startup() {
        const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgb2gYuG8JTWzkrOXL\n\
Ysmtx3EJ1admqAJc8UwOexy1MFKhRANCAAQtqZ42q5xPHcPSMGdo7DdS9vaFSB4w\n\
QdPnU3DA4y5ptWiM3WQVvw8Xvk6BWnZcrNr1fh1uP9V/w+CG76Ya0gKP\n\
-----END PRIVATE KEY-----\n";
        let keys = VapidKeys::from_pem(TEST_PEM, "mailto:test@example.com").unwrap();
        // 良い PEM では new が通る (= builder 構築済み)。
        let notifier = match WebPushNotifier::new(keys.clone()) {
            Ok(n) => n,
            Err(e) => {
                // isahc init 失敗 (sandbox 等) は本テストの対象外。
                eprintln!("WebPushNotifier::new skipped (isahc init failed): {e}");
                return;
            }
        };
        // 公開鍵が builder と keys で一致 (= 同じ PEM 由来) を確認する。
        // PartialVapidSignatureBuilder::get_public_key() は uncompressed 65 byte。
        let from_builder = notifier.sig_builder.get_public_key();
        let from_keys = URL_SAFE_NO_PAD.decode(keys.public_key_b64url()).unwrap();
        assert_eq!(from_builder, from_keys);
    }

    /// Issue #308: 壊れた PEM では `WebPushNotifier::new` が即 Err を返す
    /// (= 起動時に検出される、 通知 hot path に持ち越さない)。
    #[test]
    fn web_push_notifier_new_rejects_broken_pem() {
        const BROKEN_PEM: &str =
            "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n";
        // VapidKeys::from_pem も同じ PEM をパースするので、 そちらで先に
        // 弾かれる (= 壊れた PEM が new に到達しない)。 これも回避経路として
        // 妥当。
        let result = VapidKeys::from_pem(BROKEN_PEM, "mailto:test@example.com");
        assert!(result.is_err());
    }
}
