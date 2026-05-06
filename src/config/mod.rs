use std::net::SocketAddr;
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
    /// SIP パスワード
    pub password: String,
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
    /// ICE host candidate に載せる「外部から到達可能な IPv4」。
    /// Cloudflare Tunnel 経由なら LAN 側でも可。未設定なら全インタフェースで
    /// listen するが ICE candidate は配信できない (str0m バックエンドでは必須)。
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
}

fn default_webrtc_register_ttl() -> u64 {
    300
}

fn default_webrtc_backend() -> String {
    "stub".to_string()
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
                password: env_required("SABIDEN_SIP_PASSWORD")?,
                register_expires: std::env::var("SABIDEN_SIP_REGISTER_EXPIRES")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(default_expires),
            },
            health: HealthConfig::default(),
            uas: None,
            extensions: Vec::new(),
            trace: TraceConfig::default(),
            webrtc: WebRtcConfig {
                backend: default_webrtc_backend(),
                ..WebRtcConfig::default()
            },
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
            self.sip.password = v;
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
# SIP 認証パスワード (HGW 設定画面から確認)
password = "your_sip_password"
# REGISTER 有効期限 (秒)
register_expires = 3600

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
            password: "p".to_string(),
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
}
