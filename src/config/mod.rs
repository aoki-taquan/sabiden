use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub sip: SipConfig,
    #[serde(default)]
    pub health: HealthConfig,
    /// 内線 UAS 設定 (省略可: NGN 側登録のみで内線受付しない構成も許容する)。
    #[serde(default)]
    pub uas: Option<UasConfig>,
    /// 内線一覧 (UAS が REGISTER を受け付ける際の Digest 認証情報)。
    #[serde(default)]
    pub extensions: Vec<ExtensionConfig>,
    /// SIP メッセージファイルダンプ (Issue #20)。`dir` 未設定なら無効。
    #[serde(default)]
    pub trace: TraceConfig,
    /// WebRTC ゲートウェイ (Issue #23)。`secret_hex` 未設定なら無効。
    #[serde(default)]
    pub webrtc: WebRtcConfig,
    /// NGN 直収モード設定 (Issue #37)。`direct_mode = true` で auth=none REGISTER。
    #[serde(default)]
    pub ngn: NgnConfig,
    /// RTP ブリッジ用 bind IP (Issue #66)。NGN レッグと内線レッグで bind IP を
    /// 個別に指定できる。未設定時は SIP local_addr (eth1 NGN 側) にフォールバック。
    #[serde(default)]
    pub bridge: BridgeConfig,
    /// 留守録 (Issue #288)。 NGN inbound で fork 全失敗時に sabiden が代理で
    /// 200 OK を返し RTP 音声を WAV で保存する。 既定 disabled。
    #[serde(default)]
    pub voicemail: crate::call::voicemail::VoicemailConfig,
    /// 着信ルーティングルール (Issue #295)。 NGN inbound INVITE のフォーク先を
    /// 時間帯 / 曜日 / 発信者番号で絞り込む。 ルール無し or 全 rule no-match の
    /// 場合は registrar 全 binding に fork する従来挙動を維持する (後方互換)。
    #[serde(default)]
    pub routing: RoutingConfig,
    /// active call recording (Issue #296)。 通話確立中に PWA からのトリガで
    /// RTP 音声を WAV に保存する。 voicemail とは別ディレクトリで運用。
    /// 既定 disabled (= 完全に既存挙動)。
    #[serde(default)]
    pub recording: crate::call::recording::RecordingConfig,
    /// AI 文字起こし (Issue #300)。 Voicemail / Recording WAV から sidecar
    /// `.txt` を生成する。 既定 disabled (= transcript 生成しない、 既存
    /// 挙動と完全互換)。 backend は `"stub"` (本 PR で wire 済) のみで、
    /// `"whisper-api"` / `"faster-whisper"` は別 Issue で wire-up 予定。
    #[serde(default)]
    pub transcription: crate::observability::transcription::TranscriptionConfig,
    /// PWA Web Push 通知 (Issue #294)。 NGN inbound INVITE 受領時に
    /// 該当 PWA 内線 ID への購読があれば Web Push (RFC 8030 / RFC 8291
    /// / RFC 8292 VAPID) を送り、 tab 閉じ / 画面 lock 中でも着信を
    /// 通知できるようにする。 既定 disabled (= 既存挙動完全互換)。
    #[serde(default)]
    pub push: PushConfig,
    /// SMS (RFC 3428 MESSAGE) ring buffer / 送信 API (Issue #299)。 既定 disabled
    /// (= 旧挙動: NGN 着 MESSAGE は 200 OK 受け流し、 PWA SMS 送信 API は 503)。
    #[serde(default)]
    pub sms: SmsConfig,
}

/// PWA Web Push 通知設定 (Issue #294)。
///
/// # RFC 引用
/// - **RFC 8030**: Generic Event Delivery Using HTTP Push (Web Push wire protocol)
/// - **RFC 8291**: Message Encryption for Web Push (AES128-GCM)
/// - **RFC 8292**: VAPID (Voluntary Application Server Identification)
///
/// # VAPID 鍵生成手順 (運用者向け)
///
/// VAPID 鍵は P-256 (prime256v1) ECDSA 鍵対。 PEM 秘密鍵を sabiden に渡し、
/// 派生した公開鍵 (uncompressed, base64url) は `GET /api/push/vapid-public-key`
/// から PWA が取得する。
///
/// ```bash
/// # 1. P-256 秘密鍵 (PKCS#8) を生成
/// openssl ecparam -name prime256v1 -genkey -noout |
///   openssl pkcs8 -topk8 -nocrypt -out vapid_private.pem
///
/// # 2. config.toml に PEM 全文を埋め込む (改行を \n で escape)、
/// #    または環境変数 SABIDEN_PUSH_VAPID_PRIVATE_PEM で渡す。
/// ```
///
/// # TOML 例
///
/// ```toml
/// [push]
/// enabled = true
/// subject = "mailto:operator@example.com"
/// vapid_private_pem = """-----BEGIN PRIVATE KEY-----
/// MIGH...
/// -----END PRIVATE KEY-----
/// """
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PushConfig {
    /// 機能 ON/OFF。 false (既定) のとき push サブシステムは完全未起動。
    #[serde(default)]
    pub enabled: bool,
    /// VAPID 秘密鍵の PEM 文字列 (PKCS#8 / SEC1 どちらも可)。
    /// 機密情報なので環境変数 `SABIDEN_PUSH_VAPID_PRIVATE_PEM` で渡すのが推奨。
    #[serde(default)]
    pub vapid_private_pem: Option<String>,
    /// VAPID JWT の `sub` claim (RFC 8292 §2.1.1)。 多くの push service
    /// (FCM 等) で必須。 `mailto:operator@example.com` または `https://example.com`。
    #[serde(default)]
    pub subject: Option<String>,
}

/// SMS (RFC 3428) 設定 (Issue #299)。
///
/// TOML 表記:
/// ```toml
/// [sms]
/// enabled = true
/// max_history = 200
/// ```
///
/// `enabled = false` (既定) のときは:
/// - NGN / 内線 から受信した MESSAGE は body 破棄して 200 OK で受け流す (従来挙動)
/// - `POST /api/sms` / `GET /api/sms/recent` / `ClientMessage::SendSms` は
///   `sms_unavailable` / 503 で拒否される
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmsConfig {
    /// 有効化フラグ。 既定 `false`。
    #[serde(default)]
    pub enabled: bool,
    /// ring buffer 保持上限 (件)。 既定 200 件 (RFC 3428 は配送保証無し pager-mode
    /// なので、 中規模 SOHO 想定で 200 = およそ 1 日分)。 過大値は RAM を圧迫する
    /// ので運用上は 1000 程度を上限の目安にする (各 message 数 KB)。
    #[serde(default = "default_sms_max_history")]
    pub max_history: usize,
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_history: default_sms_max_history(),
        }
    }
}

fn default_sms_max_history() -> usize {
    200
}

/// 着信ルーティング設定 (Issue #295)。
///
/// TOML 表記:
/// ```toml
/// [[routing.rule]]
/// name = "office_hours"
/// priority = 100
/// match.weekday = ["mon", "tue", "wed", "thu", "fri"]
/// match.time_range = "09:00-18:00"
/// fork = ["iphone", "office-phone"]
/// ```
///
/// `rule = []` (省略) で従来挙動 (全内線 fork) を維持。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RoutingConfig {
    /// 個別ルール。 評価順は `priority` 降順 (同値は宣言順)。
    #[serde(default)]
    pub rule: Vec<crate::call::routing::RoutingRule>,
}

impl RoutingConfig {
    /// `crate::call::routing::RoutingRules` への変換 (ownership 移転)。
    pub fn into_rules(self) -> crate::call::routing::RoutingRules {
        crate::call::routing::RoutingRules { rules: self.rule }
    }

    /// 借用 ref で `RoutingRules` の clone を取り出す (起動時 validate 用)。
    pub fn to_rules(&self) -> crate::call::routing::RoutingRules {
        crate::call::routing::RoutingRules {
            rules: self.rule.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SipConfig {
    /// SIP サーバ IP (DHCP Option 120 で取得した値)
    pub server_addr: SocketAddr,
    /// NGN UDP ソケットの bind アドレス (Issue #35)。
    ///
    /// 省略時は `[::]:5060` (IPv4/IPv6 デュアルスタック listen)。
    /// K8s 等で pod IP が起動毎に変わる環境では `0.0.0.0:5060` でも可。
    /// `bind_addr` のポートは Via/Contact の sent-by ポートとしても使われる。
    #[serde(default)]
    pub bind_addr: Option<SocketAddr>,
    /// Via/Contact ヘッダ用のローカルアドレス (NGN 側に見える source IP:port)。
    ///
    /// 省略時は起動時に `server_addr` 宛のダミー UDP socket で
    /// カーネルが選ぶ source IP を取得し、ポートは `bind_addr` のポートを使う
    /// (Issue #35)。明示指定したい場合 (NAT 越しで外部 IP を載せたい等) は
    /// 設定 or 環境変数 `SABIDEN_SIP_LOCAL_ADDR` で上書きできる。
    #[serde(default)]
    pub local_addr: Option<SocketAddr>,
    /// 電話番号 (例: 0312345678)
    pub phone_number: String,
    /// SIP ドメイン (例: ntt-east.ne.jp)
    pub domain: String,
    /// SIP パスワード。
    ///
    /// HGW 経由の Digest 認証では必須だが、NGN 直収モード (Issue #37) では
    /// 回線認証 (HGW WAN MAC + DHCPv4 vendor class "RX-600KI") に基づくため
    /// 不要となる。`None` の場合 `register_with_retry` は Authorization
    /// ヘッダ無しで送信し、401 が返ってきたら諦める (DHCP/MAC 経路に問題がある
    /// と判断する)。
    #[serde(default)]
    pub password: Option<String>,
    /// REGISTER の Expires 値 (秒)
    #[serde(default = "default_expires")]
    pub register_expires: u32,
}

impl SipConfig {
    /// `bind_addr` の解決済み値。未設定時は `[::]:5060` を返す。
    pub fn resolved_bind_addr(&self) -> SocketAddr {
        self.bind_addr.unwrap_or_else(default_sip_bind_addr)
    }

    /// `local_addr` の解決済み値を返す (Option::expect)。
    ///
    /// `Config::load` / `Config::resolve_local_addr` を経由していれば必ず
    /// `Some` になっている前提。直接 `SipConfig` を構築したテストコード等で
    /// `None` のまま参照すると panic する。
    pub fn expect_local_addr(&self) -> SocketAddr {
        self.local_addr.expect(
            "SipConfig::local_addr unresolved (call Config::load() or resolve_local_addr first)",
        )
    }
}

fn default_sip_bind_addr() -> SocketAddr {
    "[::]:5060".parse().expect("default sip bind addr")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthConfig {
    /// ヘルスチェック HTTP サーバの bind アドレス
    #[serde(default = "default_health_addr")]
    pub bind_addr: SocketAddr,
}

/// SIP メッセージダンプ設定 (Issue #20)。
///
/// `dir` を指定すると `<dir>/<unix_ms>_<dir>_<method>_<call_id>.txt` 形式で
/// 全 SIP メッセージ (送受信) を記録する。1000 ファイル超 / 100MB 超で
/// 自動ローテーション。CLI `--trace-dir` で上書き可能。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TraceConfig {
    /// 出力先ディレクトリ。未設定 (`None`) なら無効。
    #[serde(default)]
    pub dir: Option<String>,
}

/// 内線 UAS (スマホ受付) の設定。
///
/// NGN 側 (`SipConfig`) とは別ポートで待ち受ける必要があるため
/// (内線網と NGN 網は L4 で分離する)、独立した bind アドレスを持つ。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UasConfig {
    /// 内線受付の bind アドレス。デフォルトは `0.0.0.0:5061`。
    #[serde(default = "default_uas_bind")]
    pub bind_addr: SocketAddr,
    /// 401 で返す `realm` (Digest)。デフォルトは `sabiden`。
    #[serde(default = "default_uas_realm")]
    pub realm: String,
    /// REGISTER 受付時の expires のクランプ上限 (秒)。
    /// UA が極端に長い expires を要求しても、これを超えない。
    #[serde(default = "default_uas_max_expires")]
    pub max_expires: u32,
}

impl Default for UasConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_uas_bind(),
            realm: default_uas_realm(),
            max_expires: default_uas_max_expires(),
        }
    }
}

/// WebRTC ゲートウェイ (Issue #23 / Issue #28)。
///
/// 有効化するには `secret_hex` (HMAC-SHA256 共有秘密) を設定する。
/// 既存 health server (axum) に `/signal` ルートを相乗りさせるため、
/// 独立した bind アドレスは持たず `[health] bind_addr` を共有する。
///
/// Issue #28 で実 ICE/DTLS-SRTP (str0m) を有効化する場合は `public_ip` を
/// 設定し、UDP ポート範囲を `udp_port_range` で固定する (Cloudflare Tunnel /
/// 静的ファイアウォール構成での予測可能性のため)。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebRtcConfig {
    /// HMAC-SHA256 トークン検証用の共有秘密 (16 進文字列)。
    /// 未設定の場合 WebRTC ゲートウェイは無効。
    /// 機密情報なので環境変数 `SABIDEN_WEBRTC_SECRET_HEX` で渡すのが推奨。
    #[serde(default)]
    pub secret_hex: Option<String>,
    /// `register` メッセージで Registrar に書き込むときの expires 秒。
    #[serde(default = "default_webrtc_register_ttl")]
    pub register_ttl_secs: u64,
    /// メディア層に使うバックエンド種別。
    /// - `"stub"` (デフォルト): SDP オファ/アンサのみ生成 (テスト/開発用)
    /// - `"str0m"`: 実 ICE/DTLS-SRTP/RTP 終端 (Issue #28)
    #[serde(default = "default_webrtc_backend")]
    pub backend: String,
    /// ICE host candidate (RFC 8839 §5.1 / RFC 5245 §4.1.1.2) に載せる
    /// 「外部から到達可能な IP アドレス」。 IPv4 / IPv6 どちらも受理する
    /// (Issue #103)。 Cloudflare Tunnel 経由なら LAN 側 IP でも可。
    /// 未設定なら全インタフェースで listen するが ICE candidate は配信
    /// できない (str0m バックエンドでは必須)。
    ///
    /// IPv6 を指定した場合、 UDP socket は `::` (IPv6 UNSPECIFIED) に bind
    /// される (Linux 既定の `IPV6_V6ONLY=1` により IPv6 only listen)。
    /// IPv4 / IPv6 同時 advertisement (dual-stack host candidate) は将来課題
    /// (ソケットがファミリ別に必要で str0m 側設計が変わるため、 本 PR では
    /// 単一ファミリのみ対応)。
    #[serde(default)]
    pub public_ip: Option<String>,
    /// UDP メディアポートの範囲 ("40000-40999" 形式)。
    /// str0m はソケット上限を 1 つ用意するため、本範囲から空きポートを 1 つ
    /// 選ぶ (将来 multi-session で使い分ける可能性に備えて範囲指定)。
    #[serde(default)]
    pub udp_port_range: Option<String>,
    /// 外部 STUN/TURN サーバ URL (例 `"turn:turn.example.com:3478"`)。
    /// str0m ICE-Lite 構成では我々が NAT 越えする必要は無いが、ブラウザ側が
    /// strict NAT 配下にいる場合に備えて relay candidate を SDP に載せる選択肢。
    /// 本 PR では設定値の取り込みのみ行い、実際の TURN allocate は TODO。
    #[serde(default)]
    pub ice_servers: Vec<String>,
    /// WebSocket keepalive Ping 送出周期 (秒)。
    ///
    /// Cloudflare Tunnel は idle 100 秒で WS を切断する (`docs/CLOUDFLARE.md`
    /// §6 トラブルシュート、 Issue #98)。 既定 30 秒は経路上の idle timer を
    /// 確実にリセットする値 (RFC 6455 §5.5.2 Ping は keepalive 用途として MAY、
    /// `docs/refactor-plan.md` 経由で根拠付け)。
    ///
    /// 通常は既定で十分。 経路に他の idle timeout (LB / SBC / NAT) が挟まる
    /// 場合のみ短縮する (Issue #131)。
    #[serde(default = "default_webrtc_keepalive_interval")]
    pub keepalive_interval_secs: u64,
    /// 受信フレーム不在で WS 接続をアイドル切断する閾値 (秒)。
    ///
    /// 既定 60 秒 = `keepalive_interval_secs` の 2 倍 (RFC 6455 §5.5.3 の
    /// Pong 即応 SHOULD を踏まえ、 1 周期分のトレラントを許容)。
    /// Cloudflare の 100 秒 timeout より十分小さい (Issue #98 / #131)。
    #[serde(default = "default_webrtc_idle_timeout")]
    pub idle_timeout_secs: u64,
}

/// `#[derive(Default)]` だと `u64` の既定値が 0 になり、
/// `WebRtcConfig::default()` 経由で構築したシグナリングが
/// `tokio::time::interval(Duration::from_secs(0))` で panic する
/// (`Duration::ZERO` は `interval` の事前条件違反)。
/// また `idle_timeout_secs = 0` は受信フレーム不在で即座に WS 切断と
/// 解釈されてしまうため、 keepalive 機構自体が成立しなくなる。
///
/// Issue #166 (PR #165 review follow-up) / CLAUDE.md §6.5 panic 禁止。
/// 既定値は `default_webrtc_*` ヘルパと同一: keepalive 30s / idle 60s
/// (Issue #98 / #131、 Cloudflare Tunnel 100 秒 idle 切断対策、
/// RFC 6455 §5.5.2 Ping)。
impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            secret_hex: None,
            register_ttl_secs: default_webrtc_register_ttl(),
            backend: default_webrtc_backend(),
            public_ip: None,
            udp_port_range: None,
            ice_servers: Vec::new(),
            keepalive_interval_secs: default_webrtc_keepalive_interval(),
            idle_timeout_secs: default_webrtc_idle_timeout(),
        }
    }
}

/// NGN 直収モード関連の設定 (Issue #37)。
///
/// home-ops PR #214 の検証で確定した「HGW WAN MAC spoof + DHCPv4 vendor class
/// `RX-600KI` で /30 IPv4 lease を貰い、回線認証ベースで SIP REGISTER する」
/// レシピに sabiden を追従させるためのスイッチ群。
///
/// sabiden 自身は DHCPv4 や MAC spoof は行わない (init container と K8s NIC
/// 設定で実施)。本構造体の `vendor_class` は init container から参照される
/// 設定値として保持し、運用ドキュメントとの整合を取るためのもの。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NgnConfig {
    /// NGN 直収モード。`true` の場合:
    /// - SIP `password` は不要 (Authorization ヘッダなしで REGISTER 送信)
    /// - 401 が返ってきたら回線認証 (MAC/DHCP) 側の問題なので bail
    #[serde(default)]
    pub direct_mode: bool,
    /// DHCPv4 で送出する Vendor Class (RFC 2132 option 60)。
    /// NGN 側は `RX-600KI` 等 NTT 純正 HGW の値を期待する。sabiden 自身は
    /// DHCP しないため本値は init container 側から参照する想定。
    #[serde(default = "default_vendor_class")]
    pub vendor_class: String,
}

impl Default for NgnConfig {
    fn default() -> Self {
        Self {
            direct_mode: false,
            vendor_class: default_vendor_class(),
        }
    }
}

fn default_vendor_class() -> String {
    "RX-600KI".to_string()
}

/// RTP ブリッジ用 bind IP の設定 (Issue #66)。
///
/// sabiden は B2BUA として NGN レッグ ⇔ 内線レッグの 2 つの UDP socket を
/// bind し、間で RTP/RTCP を中継する。各 socket をどの IP で bind するかは
/// NIC レイアウトに依存するため、以下の 2 つを個別指定できる:
///
/// - `ngn_bind_ip`: NGN 側 RTP socket の bind IP。`docs/asterisk-real-invite.md`
///   §5.2 準拠で **NGN 側 NIC (eth1) の IPv4** を指定するのが正解。SDP の
///   `c=` / `o=` で NGN へ広告する IP もこれと一致する。
/// - `ext_bind_ip`: 内線側 RTP socket の bind IP。**内線 UA (Linphone 等) から
///   到達可能な IP** を指定する必要がある。LAN 上の内線端末が 192.168.x.x の
///   私設 IP 空間にいる場合、sabiden の eth0 LAN IP (例 `192.168.20.239`) を
///   指定しないと、内線 UA からの RTP が sabiden に届かず無音になる
///   (Issue #66 で発覚)。
///
/// 両方未設定時は SIP の `local_addr` (= eth1 NGN 側 IP) を両側で使う。
/// これは 1 NIC 構成 (= NGN 直収だが LAN 経由内線が無いテスト構成) では
/// 動くが、内線が別 NIC にいる本番構成では `ext_bind_ip` を明示する必要が
/// ある。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BridgeConfig {
    /// NGN 側 RTP socket の bind IP。`None` なら SIP local_addr に従う。
    #[serde(default)]
    pub ngn_bind_ip: Option<IpAddr>,
    /// 内線側 RTP socket の bind IP。`None` なら `ngn_bind_ip` (or SIP local_addr) に従う。
    /// 内線 UA から到達可能な IP を設定すること (LAN 経由内線なら eth0 LAN IP)。
    #[serde(default)]
    pub ext_bind_ip: Option<IpAddr>,
}

fn default_webrtc_register_ttl() -> u64 {
    300
}

fn default_webrtc_backend() -> String {
    "stub".to_string()
}

/// Issue #98 / #131: Cloudflare Tunnel 100 秒 idle 切断より十分短い既定。
/// 経路上の idle timer を確実にリセットする (RFC 6455 §5.5.2)。
fn default_webrtc_keepalive_interval() -> u64 {
    30
}

/// Issue #98 / #131: keepalive_interval の 2 倍 = Pong 不在 1 周期分許容。
/// Cloudflare の 100 秒 timeout より十分小さい。
fn default_webrtc_idle_timeout() -> u64 {
    60
}

/// 1 つの内線アカウント。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtensionConfig {
    /// 内線ユーザ名 (REGISTER の To/From で来る AOR の username 部分)。
    pub username: String,
    /// 内線パスワード (Digest 認証用、平文)。
    pub password: String,
}

fn default_uas_bind() -> SocketAddr {
    "0.0.0.0:5061".parse().expect("default uas bind")
}

fn default_uas_realm() -> String {
    "sabiden".to_string()
}

fn default_uas_max_expires() -> u32 {
    3600
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_health_addr(),
        }
    }
}

fn default_expires() -> u32 {
    3600
}

fn default_health_addr() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("default health addr")
}

impl Config {
    /// TOML ファイル読み込み + 環境変数で上書き (K8s 互換)
    ///
    /// 環境変数命名規則: `SABIDEN_<SECTION>_<KEY>`
    /// 例: `SABIDEN_SIP_PASSWORD`, `SABIDEN_SIP_PHONE_NUMBER`
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut config = if path.exists() {
            let content =
                std::fs::read_to_string(path).with_context(|| format!("read {:?}", path))?;
            toml::from_str::<Config>(&content).context("parse config TOML")?
        } else {
            Config::from_env_only()?
        };
        config.apply_env_overrides();
        config.resolve_local_addr()?;
        // Issue #295: 着信ルーティングルールの構文を起動時に validate。
        // 不正な time_range / weekday を抱えたまま起動すると評価時に「無条件
        // unmatch」 で sticky に bypass され、 営業時間外でも全 fork する事故に
        // つながる。 fail-fast で防ぐ。
        crate::call::routing::validate_rules(&config.routing.to_rules())
            .map_err(|e| anyhow::anyhow!("invalid [[routing.rule]]: {}", e))?;
        Ok(config)
    }

    /// `sip.local_addr` が未設定 (Option::None) なら `server_addr` を基に
    /// 自動検出する (Issue #35)。明示指定が既にある場合は何もしない。
    ///
    /// テストや差し替え用に分離した public API。`Config::load` から自動で
    /// 呼ばれる。
    pub fn resolve_local_addr(&mut self) -> Result<()> {
        if self.sip.local_addr.is_some() {
            return Ok(());
        }
        let bind_port = self.sip.resolved_bind_addr().port();
        let detected = crate::sip::addr::detect_local_addr(self.sip.server_addr, bind_port)
            .context("auto-detect local_addr (Issue #35)")?;
        self.sip.local_addr = Some(detected);
        Ok(())
    }

    fn from_env_only() -> Result<Self> {
        Ok(Config {
            sip: SipConfig {
                server_addr: env_required("SABIDEN_SIP_SERVER_ADDR")?
                    .parse()
                    .context("parse SABIDEN_SIP_SERVER_ADDR")?,
                bind_addr: std::env::var("SABIDEN_SIP_BIND_ADDR")
                    .ok()
                    .and_then(|s| s.parse().ok()),
                // local_addr は省略可: 後段の `resolve_local_addr` で
                // 自動検出する (Issue #35)。明示指定がある場合のみ採用。
                local_addr: std::env::var("SABIDEN_SIP_LOCAL_ADDR")
                    .ok()
                    .and_then(|s| s.parse().ok()),
                phone_number: env_required("SABIDEN_SIP_PHONE_NUMBER")?,
                domain: env_required("SABIDEN_SIP_DOMAIN")?,
                // password は NGN 直収モード (Issue #37) では不要なので
                // 環境変数のみの起動でもオプショナル扱いする。
                password: std::env::var("SABIDEN_SIP_PASSWORD")
                    .ok()
                    .filter(|s| !s.is_empty()),
                register_expires: std::env::var("SABIDEN_SIP_REGISTER_EXPIRES")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(default_expires),
            },
            health: HealthConfig::default(),
            uas: None,
            extensions: Vec::new(),
            trace: TraceConfig::default(),
            // Issue #166: `WebRtcConfig::default()` が手書き Default で
            // keepalive 30s / idle 60s を初期化するため、 env-only 起動
            // (TOML 不在) でも既定値が確実に反映される。
            webrtc: WebRtcConfig::default(),
            ngn: NgnConfig::default(),
            bridge: BridgeConfig::default(),
            voicemail: crate::call::voicemail::VoicemailConfig::default(),
            routing: RoutingConfig::default(),
            recording: crate::call::recording::RecordingConfig::default(),
            transcription: crate::observability::transcription::TranscriptionConfig::default(),
            push: PushConfig::default(),
            sms: SmsConfig::default(),
        })
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SABIDEN_SIP_SERVER_ADDR") {
            if let Ok(addr) = v.parse() {
                self.sip.server_addr = addr;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_SIP_BIND_ADDR") {
            if let Ok(addr) = v.parse() {
                self.sip.bind_addr = Some(addr);
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_SIP_LOCAL_ADDR") {
            if let Ok(addr) = v.parse() {
                self.sip.local_addr = Some(addr);
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_SIP_PHONE_NUMBER") {
            self.sip.phone_number = v;
        }
        if let Ok(v) = std::env::var("SABIDEN_SIP_DOMAIN") {
            self.sip.domain = v;
        }
        if let Ok(v) = std::env::var("SABIDEN_SIP_PASSWORD") {
            // 空文字列はパスワード未設定として扱う (NGN 直収モードで k8s から
            // 値だけ消したい場合の対応)。
            self.sip.password = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("SABIDEN_SIP_REGISTER_EXPIRES") {
            if let Ok(n) = v.parse() {
                self.sip.register_expires = n;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_HEALTH_BIND_ADDR") {
            if let Ok(addr) = v.parse() {
                self.health.bind_addr = addr;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_UAS_BIND_ADDR") {
            if let Ok(addr) = v.parse() {
                self.uas.get_or_insert_with(UasConfig::default).bind_addr = addr;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_UAS_REALM") {
            self.uas.get_or_insert_with(UasConfig::default).realm = v;
        }
        if let Ok(v) = std::env::var("SABIDEN_TRACE_DIR") {
            // 空文字列はトレース無効化として扱う (k8s で値だけ消したいケース対応)。
            self.trace.dir = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("SABIDEN_WEBRTC_SECRET_HEX") {
            // 空文字列は WebRTC ゲートウェイ無効化として扱う。
            self.webrtc.secret_hex = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("SABIDEN_WEBRTC_REGISTER_TTL_SECS") {
            if let Ok(n) = v.parse() {
                self.webrtc.register_ttl_secs = n;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_WEBRTC_BACKEND") {
            if !v.is_empty() {
                self.webrtc.backend = v;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_WEBRTC_PUBLIC_IP") {
            self.webrtc.public_ip = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("SABIDEN_WEBRTC_UDP_PORT_RANGE") {
            self.webrtc.udp_port_range = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("SABIDEN_WEBRTC_ICE_SERVERS") {
            // カンマ区切り
            self.webrtc.ice_servers = if v.is_empty() {
                Vec::new()
            } else {
                v.split(',').map(|s| s.trim().to_string()).collect()
            };
        }
        // Issue #131: WebRTC シグナリング keepalive の運用調整窓口
        // (RFC 6455 §5.5.2 Ping、 Cloudflare Tunnel 100 秒 idle 切断対策)。
        if let Ok(v) = std::env::var("SABIDEN_WEBRTC_KEEPALIVE_INTERVAL_SECS") {
            if let Ok(n) = v.parse() {
                self.webrtc.keepalive_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_WEBRTC_IDLE_TIMEOUT_SECS") {
            if let Ok(n) = v.parse() {
                self.webrtc.idle_timeout_secs = n;
            }
        }
        // [ngn] セクション (Issue #37)
        if let Ok(v) = std::env::var("SABIDEN_NGN_DIRECT_MODE") {
            // "true"/"1"/"yes" を真として受ける (k8s 環境変数の自然な使い方)。
            let lower = v.to_ascii_lowercase();
            self.ngn.direct_mode = matches!(lower.as_str(), "true" | "1" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("SABIDEN_NGN_VENDOR_CLASS") {
            if !v.is_empty() {
                self.ngn.vendor_class = v;
            }
        }
        // [bridge] セクション (Issue #66): RTP ブリッジ bind IP の上書き。
        // 空文字列は明示的なリセット (= None フォールバック) として扱う。
        if let Ok(v) = std::env::var("SABIDEN_BRIDGE_NGN_BIND_IP") {
            self.bridge.ngn_bind_ip = if v.is_empty() { None } else { v.parse().ok() };
        }
        if let Ok(v) = std::env::var("SABIDEN_BRIDGE_EXT_BIND_IP") {
            self.bridge.ext_bind_ip = if v.is_empty() { None } else { v.parse().ok() };
        }
        // [voicemail] セクション (Issue #288): 留守録 ON/OFF + storage 上書き。
        if let Ok(v) = std::env::var("SABIDEN_VOICEMAIL_ENABLED") {
            let lower = v.to_ascii_lowercase();
            self.voicemail.enabled = matches!(lower.as_str(), "true" | "1" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("SABIDEN_VOICEMAIL_STORAGE_DIR") {
            if !v.is_empty() {
                self.voicemail.storage_dir = std::path::PathBuf::from(v);
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_VOICEMAIL_MAX_DURATION_SECS") {
            if let Ok(n) = v.parse() {
                self.voicemail.max_duration_secs = n;
            }
        }
        // [transcription] セクション (Issue #300): AI 文字起こし。 既定 disabled
        // で完全な後方互換。 backend は "stub" のみ wire 済、 将来 Whisper API /
        // faster-whisper を追加した時に api_key_env / model_path も env で
        // 上書きできるよう経路だけ用意しておく。
        if let Ok(v) = std::env::var("SABIDEN_TRANSCRIPTION_ENABLED") {
            let lower = v.to_ascii_lowercase();
            self.transcription.enabled = matches!(lower.as_str(), "true" | "1" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("SABIDEN_TRANSCRIPTION_BACKEND") {
            if !v.is_empty() {
                self.transcription.backend = v;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_TRANSCRIPTION_API_KEY_ENV") {
            self.transcription.api_key_env = if v.is_empty() { None } else { Some(v) };
        }
        if let Ok(v) = std::env::var("SABIDEN_TRANSCRIPTION_MODEL_PATH") {
            self.transcription.model_path = if v.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(v))
            };
        }
        // [push] セクション (Issue #294): PWA Web Push 通知。
        // RFC 8030 / RFC 8291 / RFC 8292 VAPID。 機密情報なので環境変数経由を推奨。
        if let Ok(v) = std::env::var("SABIDEN_PUSH_ENABLED") {
            let lower = v.to_ascii_lowercase();
            self.push.enabled = matches!(lower.as_str(), "true" | "1" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("SABIDEN_PUSH_VAPID_PRIVATE_PEM") {
            if !v.is_empty() {
                self.push.vapid_private_pem = Some(v);
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_PUSH_SUBJECT") {
            if !v.is_empty() {
                self.push.subject = Some(v);
            }
        }
        // [sms] セクション (Issue #299): SMS ring buffer / 送信 API ON/OFF。
        if let Ok(v) = std::env::var("SABIDEN_SMS_ENABLED") {
            let lower = v.to_ascii_lowercase();
            self.sms.enabled = matches!(lower.as_str(), "true" | "1" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("SABIDEN_SMS_MAX_HISTORY") {
            if let Ok(n) = v.parse() {
                self.sms.max_history = n;
            }
        }
    }

    pub fn example() -> String {
        r#"[sip]
# DHCP Option 120 で取得した SIP サーバアドレス
server_addr = "[2001:A7FF:2101:6::F]:5060"
# NGN UDP ソケットの bind アドレス (省略時 [::]:5060)
# bind_addr = "[::]:5060"
# この機器の NGN 側 IPv6 アドレス。省略すると起動時に server_addr 宛の
# ダミー UDP socket でカーネルが選ぶ source IP を自動検出する (Issue #35)。
# K8s 等で pod IP が動的な環境では未指定推奨。
# local_addr = "[2001:xxxx:xxxx::1]:5060"
# ひかり電話の電話番号
phone_number = "0312345678"
# NTT ドメイン
domain = "ntt-east.ne.jp"
# SIP 認証パスワード (HGW 設定画面から確認)。
# NGN 直収モード ([ngn] direct_mode = true) では不要なのでコメントアウト可。
password = "your_sip_password"
# REGISTER 有効期限 (秒)
register_expires = 3600

# NGN 直収モード設定 (任意)
# home-ops PR #214 検証で確定したレシピ:
#   1. HGW を一度起動し OSS-DB に WAN MAC を登録
#   2. K8s NIC で HGW WAN MAC を spoof + DHCPv4 vendor class を送出
#   3. /30 IPv4 lease + DHCP option 120 で SIP server IP を取得
#   4. SIP REGISTER (Authorization なし、回線認証ベース) → 200 OK
# sabiden は (4) のみ担当。(1)-(3) は init container と K8s NIC 設定で実施。
# [ngn]
# direct_mode = true
# vendor_class = "RX-600KI"

[health]
# ヘルスチェック HTTP サーバ
bind_addr = "0.0.0.0:8080"

# 内線 UAS (スマホ受付) 設定 (省略可)
[uas]
bind_addr = "0.0.0.0:5061"
realm = "sabiden"
max_expires = 3600

# 内線アカウント (任意)
# [[extensions]]
# username = "iphone"
# password = "iphone_password"
#
# [[extensions]]
# username = "android"
# password = "android_password"

# SIP メッセージファイルダンプ (任意)
# [trace]
# dir = "/var/log/sabiden/sip"

# WebRTC ゲートウェイ (任意)
# secret_hex は HMAC-SHA256 トークン検証用 (32 バイト = 64 hex 推奨)
# 機密情報のため環境変数 SABIDEN_WEBRTC_SECRET_HEX 経由を推奨
# [webrtc]
# secret_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# register_ttl_secs = 300
# # メディア層: "stub" (デフォルト) または "str0m" (実 ICE/DTLS-SRTP)
# backend = "str0m"
# # 外部到達可能 IPv4。Cloudflare Tunnel 経由なら LAN 側でも可
# public_ip = "203.0.113.1"
# # メディア用 UDP ポート範囲 (ファイアウォール/Tunnel 設定での予測可能性のため固定)
# udp_port_range = "40000-40999"
# # STUN/TURN URL (現状は SDP に乗せるのみ、relay allocate は将来実装)
# ice_servers = ["turn:turn.example.com:3478"]
# # WS keepalive (Issue #98 / #131)。 既定 30s / 60s は Cloudflare Tunnel 100s
# # idle 切断対策の安全側 (RFC 6455 §5.5.2 Ping は keepalive として MAY)。
# # 通常は変更不要。 経路上に他の idle timer (LB / SBC / NAT) がある場合のみ短縮。
# keepalive_interval_secs = 30
# idle_timeout_secs = 60

# RTP ブリッジ用 bind IP (任意, Issue #66)
# 内線 UA (Linphone 等) が NGN 側 NIC とは別 NIC (eth0 LAN 等) にいる場合、
# 内線レッグ RTP socket を LAN 側 IP で bind する必要がある (内線 UA から
# 到達可能な IP でないと SDP 広告先に RTP が届かない)。
# - ngn_bind_ip: NGN 側 RTP socket bind IP (省略時は sip.local_addr に従う)
# - ext_bind_ip: 内線側 RTP socket bind IP (省略時は ngn_bind_ip にフォールバック)
# [bridge]
# ngn_bind_ip = "118.177.72.242"
# ext_bind_ip = "192.168.20.239"

# 留守録 (Issue #288)。 fork all-fail (内線も PWA も応答せず) の inbound 通話で
# sabiden が代理で 200 OK を返し、 NGN からの RTP 音声を WAV に保存する。
# PWA からは `/api/voicemail/list` / `/api/voicemail/{id}/audio` / DELETE で操作。
# [voicemail]
# enabled = false
# storage_dir = "/var/lib/sabiden/voicemail"
# max_duration_secs = 60

# AI 文字起こし stub (Issue #300)。 Voicemail / Recording の WAV から sidecar
# `.txt` を生成する。 既定 disabled (= `.txt` 不生成、 完全な後方互換)。
# 現状は backend = "stub" のみ wire 済 (placeholder text)。 実 Whisper API /
# faster-whisper backend は別 Issue で実装予定。
# [transcription]
# enabled = false
# backend = "stub"

# PWA Web Push 通知 (Issue #294、 RFC 8030 / RFC 8291 / RFC 8292 VAPID)。
# PWA tab が閉じている / 画面 lock 中でも NGN 着信を通知するため、 Service
# Worker + Notification API + Web Push (Mozilla / FCM 等) 経由で push する。
#
# VAPID 鍵生成 (運用者):
#   openssl ecparam -name prime256v1 -genkey -noout |
#     openssl pkcs8 -topk8 -nocrypt -out vapid_private.pem
# 機密情報なので環境変数 `SABIDEN_PUSH_VAPID_PRIVATE_PEM` で渡すのが推奨。
#
# [push]
# enabled = false
# subject = "mailto:operator@example.com"
# vapid_private_pem = """-----BEGIN PRIVATE KEY-----
# MIGH...
# -----END PRIVATE KEY-----
# """

# SMS (RFC 3428 MESSAGE、 Issue #299)。 NGN / 内線 から受信した MESSAGE 本文を
# ring buffer に store し、 PWA から送信もできる (`GET /api/sms/recent`
# / `POST /api/sms`)。 既定 disabled (= 旧挙動: 200 OK 受け流しのみ)。
# [sms]
# enabled = false
# max_history = 200
"#
        .to_string()
    }
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("environment variable {} not set", key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_sip(local: Option<&str>, bind: Option<&str>) -> SipConfig {
        SipConfig {
            server_addr: "127.0.0.1:5060".parse().unwrap(),
            bind_addr: bind.map(|s| s.parse().unwrap()),
            local_addr: local.map(|s| s.parse().unwrap()),
            phone_number: "0312345678".to_string(),
            domain: "example.test".to_string(),
            password: Some("p".to_string()),
            register_expires: 3600,
        }
    }

    /// Issue #35: `local_addr` が明示指定されている場合は変更しない (互換性)。
    #[test]
    fn resolve_keeps_explicit_local_addr() {
        let mut cfg = Config {
            sip: base_sip(Some("[2001:db8::1]:5060"), None),
            health: HealthConfig::default(),
            uas: None,
            extensions: Vec::new(),
            trace: TraceConfig::default(),
            webrtc: WebRtcConfig::default(),
            ngn: NgnConfig::default(),
            bridge: BridgeConfig::default(),
            voicemail: crate::call::voicemail::VoicemailConfig::default(),
            routing: RoutingConfig::default(),
            recording: crate::call::recording::RecordingConfig::default(),
            transcription: crate::observability::transcription::TranscriptionConfig::default(),
            push: PushConfig::default(),
            sms: SmsConfig::default(),
        };
        cfg.resolve_local_addr().expect("resolve");
        assert_eq!(
            cfg.sip.local_addr.unwrap(),
            "[2001:db8::1]:5060".parse().unwrap()
        );
    }

    /// Issue #35: `local_addr` 省略時は server_addr 宛のルーティングから自動検出する。
    #[test]
    fn resolve_auto_detects_when_missing() {
        let mut cfg = Config {
            sip: base_sip(None, None),
            health: HealthConfig::default(),
            uas: None,
            extensions: Vec::new(),
            trace: TraceConfig::default(),
            webrtc: WebRtcConfig::default(),
            ngn: NgnConfig::default(),
            bridge: BridgeConfig::default(),
            voicemail: crate::call::voicemail::VoicemailConfig::default(),
            routing: RoutingConfig::default(),
            recording: crate::call::recording::RecordingConfig::default(),
            transcription: crate::observability::transcription::TranscriptionConfig::default(),
            push: PushConfig::default(),
            sms: SmsConfig::default(),
        };
        cfg.resolve_local_addr().expect("resolve");
        let local = cfg.sip.local_addr.expect("auto-detected");
        // 127.0.0.1:5060 サーバ宛なので IPv4 source / port は bind_addr (default :5060) のポート。
        assert!(local.is_ipv4(), "expected v4 source for v4 server");
        assert_eq!(local.port(), 5060);
    }

    /// `bind_addr` のポートが反映されること (Via sent-by ポート決定)。
    #[test]
    fn resolve_uses_bind_addr_port_for_via() {
        let mut cfg = Config {
            sip: base_sip(None, Some("0.0.0.0:15060")),
            health: HealthConfig::default(),
            uas: None,
            extensions: Vec::new(),
            trace: TraceConfig::default(),
            webrtc: WebRtcConfig::default(),
            ngn: NgnConfig::default(),
            bridge: BridgeConfig::default(),
            voicemail: crate::call::voicemail::VoicemailConfig::default(),
            routing: RoutingConfig::default(),
            recording: crate::call::recording::RecordingConfig::default(),
            transcription: crate::observability::transcription::TranscriptionConfig::default(),
            push: PushConfig::default(),
            sms: SmsConfig::default(),
        };
        cfg.resolve_local_addr().expect("resolve");
        assert_eq!(cfg.sip.local_addr.unwrap().port(), 15060);
    }

    /// `bind_addr` 省略時のデフォルトは `[::]:5060`。
    #[test]
    fn default_bind_addr_is_dual_stack_ipv6() {
        let cfg = base_sip(None, None);
        let bind = cfg.resolved_bind_addr();
        assert_eq!(bind.port(), 5060);
        assert!(bind.is_ipv6());
    }

    /// TOML から `local_addr` を完全に省略してもパースできること (Issue #35)。
    #[test]
    fn toml_parses_without_local_addr() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "example.test"
password = "p"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.sip.local_addr.is_none());
        assert!(cfg.sip.bind_addr.is_none());
    }

    /// Issue #37: NGN 直収モードでは password を完全に省略しても
    /// TOML パースが通り、`SipConfig.password` が `None` であること。
    #[test]
    fn toml_parses_without_password_for_ngn_direct() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[ngn]
direct_mode = true
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.sip.password.is_none());
        assert!(cfg.ngn.direct_mode);
        assert_eq!(cfg.ngn.vendor_class, "RX-600KI");
    }

    /// Issue #37: `[ngn]` セクション全省略でも `direct_mode = false` で
    /// vendor_class はデフォルト "RX-600KI" が入る (旧 HGW Digest モード互換)。
    #[test]
    fn toml_default_ngn_section_is_legacy_compatible() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"
password = "secret"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.ngn.direct_mode);
        assert_eq!(cfg.ngn.vendor_class, "RX-600KI");
        assert_eq!(cfg.sip.password.as_deref(), Some("secret"));
    }

    /// Issue #66: `[bridge]` セクションで RTP ブリッジ bind IP を NGN 側と
    /// 内線側で個別指定できる。省略時は両方 `None` (= SIP local_addr に
    /// フォールバック) のまま。
    #[test]
    fn toml_parses_bridge_section_with_per_leg_bind_ip() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[bridge]
ngn_bind_ip = "118.177.72.242"
ext_bind_ip = "192.168.20.239"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert_eq!(
            cfg.bridge.ngn_bind_ip,
            Some("118.177.72.242".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            cfg.bridge.ext_bind_ip,
            Some("192.168.20.239".parse::<IpAddr>().unwrap())
        );
    }

    /// Issue #66: `[bridge]` セクション省略時は両 IP とも `None`。
    #[test]
    fn toml_default_bridge_section_is_unset() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.bridge.ngn_bind_ip.is_none());
        assert!(cfg.bridge.ext_bind_ip.is_none());
    }

    /// Issue #37: vendor_class は将来の機種変更に備えて上書き可能。
    #[test]
    fn toml_ngn_vendor_class_can_be_overridden() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[ngn]
direct_mode = true
vendor_class = "PR-500KI"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.ngn.vendor_class, "PR-500KI");
    }

    /// Issue #131: WebRTC keepalive の既定値 (Cloudflare Tunnel 100 秒 idle
    /// 切断対策、 RFC 6455 §5.5.2 Ping)。 TOML 省略時に 30s / 60s が反映される。
    #[test]
    fn toml_default_webrtc_keepalive_is_30s_idle_60s() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[webrtc]
secret_hex = "00"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.webrtc.keepalive_interval_secs, 30);
        assert_eq!(cfg.webrtc.idle_timeout_secs, 60);
    }

    /// Issue #166 (PR #165 follow-up): `WebRtcConfig::default()` を直接呼んだ
    /// 場合に keepalive_interval / idle_timeout が 0 ではなく既定値で初期化
    /// されること。`#[derive(Default)]` のままだと `u64` が 0 になり、
    /// `tokio::time::interval(Duration::ZERO)` で panic / idle 即切断に
    /// なるため、 手書き `Default` で 30s / 60s を保証する。
    /// CLAUDE.md §6.5 (production code で panic 禁止) / RFC 6455 §5.5.2 Ping。
    #[test]
    fn webrtc_config_default_initializes_keepalive_non_zero() {
        let webrtc = WebRtcConfig::default();
        assert_ne!(
            webrtc.keepalive_interval_secs, 0,
            "keepalive_interval_secs must be non-zero to avoid \
             tokio::time::interval(Duration::ZERO) panic"
        );
        assert_ne!(
            webrtc.idle_timeout_secs, 0,
            "idle_timeout_secs must be non-zero to avoid \
             immediate WS disconnect on absence of inbound frames"
        );
        assert_eq!(webrtc.keepalive_interval_secs, 30);
        assert_eq!(webrtc.idle_timeout_secs, 60);
        // 連動する他の既定値も併せて確認 (`backend`/`register_ttl_secs`
        // が手書き Default で抜けないこと回帰防止)。
        assert_eq!(webrtc.backend, "stub");
        assert_eq!(webrtc.register_ttl_secs, 300);
        assert!(webrtc.secret_hex.is_none());
        assert!(webrtc.public_ip.is_none());
        assert!(webrtc.udp_port_range.is_none());
        assert!(webrtc.ice_servers.is_empty());
    }

    /// Issue #166: `Duration::from_secs(0)` を `tokio::time::interval` に渡すと
    /// panic することの再現テスト (semantics 文書化)。 本 PR の Default
    /// 修正が無いと WebRtcConfig::default() からこの panic 経路に入る。
    #[tokio::test]
    #[should_panic]
    async fn tokio_interval_panics_on_zero_duration() {
        let _ = tokio::time::interval(std::time::Duration::from_secs(0));
    }

    /// Issue #288: `[voicemail]` セクション省略時の既定値は `enabled=false` /
    /// `storage_dir=/tmp/sabiden-voicemail` / `max_duration_secs=60`。
    #[test]
    fn toml_default_voicemail_section_is_disabled_with_safe_defaults() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.voicemail.enabled);
        assert_eq!(
            cfg.voicemail.storage_dir,
            std::path::PathBuf::from("/tmp/sabiden-voicemail")
        );
        assert_eq!(cfg.voicemail.max_duration_secs, 60);
    }

    /// Issue #288: TOML から `enabled` / `storage_dir` / `max_duration_secs` を上書き。
    #[test]
    fn toml_voicemail_section_can_be_overridden() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[voicemail]
enabled = true
storage_dir = "/var/lib/sabiden/voicemail"
max_duration_secs = 120
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.voicemail.enabled);
        assert_eq!(
            cfg.voicemail.storage_dir,
            std::path::PathBuf::from("/var/lib/sabiden/voicemail")
        );
        assert_eq!(cfg.voicemail.max_duration_secs, 120);
    }

    /// Issue #131: TOML で keepalive を上書きできる (経路追加 idle timer 対策)。
    #[test]
    fn toml_webrtc_keepalive_can_be_overridden() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[webrtc]
secret_hex = "00"
keepalive_interval_secs = 5
idle_timeout_secs = 12
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.webrtc.keepalive_interval_secs, 5);
        assert_eq!(cfg.webrtc.idle_timeout_secs, 12);
    }

    /// Issue #295: `[[routing.rule]]` セクションを TOML から複数 rule で
    /// パースし、 `RoutingRules::evaluate` がそのまま使える形にする。
    /// priority / match.weekday / match.time_range / match.from_number / fork
    /// の 5 フィールドを 1 件で確認 + 複数 rule の宣言順保持を確認する
    /// (integration: TOML → struct → RoutingRules round-trip)。
    #[test]
    fn toml_parses_routing_rules_with_all_match_fields() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[[routing.rule]]
name = "vip_customer"
priority = 200
match.from_number = ["0312345678"]
fork = ["boss-mobile"]

[[routing.rule]]
name = "office_hours"
priority = 100
match.weekday = ["mon", "tue", "wed", "thu", "fri"]
match.time_range = "09:00-18:00"
fork = ["iphone", "office-phone"]

[[routing.rule]]
name = "after_hours"
priority = 0
fork = []
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.routing.rule.len(), 3);

        // 宣言順を維持していること
        assert_eq!(cfg.routing.rule[0].name, "vip_customer");
        assert_eq!(cfg.routing.rule[0].priority, 200);
        assert_eq!(
            cfg.routing.rule[0].match_.from_number.as_deref(),
            Some(&["0312345678".to_string()][..])
        );
        assert!(cfg.routing.rule[0].match_.weekday.is_none());
        assert!(cfg.routing.rule[0].match_.time_range.is_none());
        assert_eq!(cfg.routing.rule[0].fork, vec!["boss-mobile".to_string()]);

        assert_eq!(cfg.routing.rule[1].name, "office_hours");
        assert_eq!(cfg.routing.rule[1].priority, 100);
        assert_eq!(
            cfg.routing.rule[1].match_.time_range.as_deref(),
            Some("09:00-18:00")
        );
        assert_eq!(
            cfg.routing.rule[1].match_.weekday.as_ref().map(|v| v.len()),
            Some(5)
        );
        assert_eq!(
            cfg.routing.rule[1].fork,
            vec!["iphone".to_string(), "office-phone".to_string()]
        );

        assert_eq!(cfg.routing.rule[2].name, "after_hours");
        assert_eq!(cfg.routing.rule[2].priority, 0);
        assert!(cfg.routing.rule[2].fork.is_empty());

        // 起動時 validate (構文 OK)
        crate::call::routing::validate_rules(&cfg.routing.to_rules()).expect("validate");
    }

    /// Issue #295: `[[routing.rule]]` セクション省略時は `rule` 配列が空 (=
    /// `evaluate` は常に `NoRule` を返す)、 旧挙動 (全 fork) と完全互換。
    #[test]
    fn toml_default_routing_section_is_empty_for_backward_compat() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.routing.rule.is_empty());
        let rules = cfg.routing.to_rules();
        assert!(rules.is_empty());
    }

    /// Issue #295: TOML から `priority` 省略時は serde default = 0 が入る。
    /// `match` も省略可能で、 省略時は MatchSpec::default() (全 None)。
    #[test]
    fn toml_routing_rule_omitted_priority_and_match_use_defaults() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[[routing.rule]]
name = "catchall"
fork = ["iphone"]
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.routing.rule.len(), 1);
        assert_eq!(cfg.routing.rule[0].priority, 0);
        assert!(cfg.routing.rule[0].match_.weekday.is_none());
        assert!(cfg.routing.rule[0].match_.time_range.is_none());
        assert!(cfg.routing.rule[0].match_.from_number.is_none());
    }

    /// Issue #300: `[transcription]` セクション省略時は disabled + backend="stub"。
    /// `[transcription]` セクション全省略でも TOML パースが通り、
    /// `Config.transcription.enabled = false` で完全な後方互換。
    #[test]
    fn toml_default_transcription_section_is_disabled_with_stub_backend() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.transcription.enabled);
        assert_eq!(cfg.transcription.backend, "stub");
        assert!(cfg.transcription.api_key_env.is_none());
        assert!(cfg.transcription.model_path.is_none());
    }

    /// Issue #300: `[transcription]` セクション override → TOML パース確認。
    #[test]
    fn toml_transcription_section_can_be_overridden() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[transcription]
enabled = true
backend = "stub"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.transcription.enabled);
        assert_eq!(cfg.transcription.backend, "stub");
    }

    /// Issue #295: 不正な time_range は `Config::load` 経路の validate で
    /// エラー化する。 ここでは validate を直接呼んで構文エラー検出を確認。
    #[test]
    fn toml_routing_validate_rejects_bad_time_range() {
        let toml_str = r#"
[sip]
server_addr = "127.0.0.1:5060"
phone_number = "0312345678"
domain = "ntt-east.ne.jp"

[[routing.rule]]
name = "bad"
match.time_range = "25:99-zz:00"
fork = []
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        let result = crate::call::routing::validate_rules(&cfg.routing.to_rules());
        assert!(result.is_err());
    }
}
