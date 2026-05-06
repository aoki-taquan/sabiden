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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SipConfig {
    /// SIP サーバ IP (DHCP Option 120 で取得した値)
    pub server_addr: SocketAddr,
    /// ローカルアドレス (NGN IPv6 インタフェースのアドレス)
    pub local_addr: SocketAddr,
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
        Ok(config)
    }

    fn from_env_only() -> Result<Self> {
        Ok(Config {
            sip: SipConfig {
                server_addr: env_required("SABIDEN_SIP_SERVER_ADDR")?
                    .parse()
                    .context("parse SABIDEN_SIP_SERVER_ADDR")?,
                local_addr: env_required("SABIDEN_SIP_LOCAL_ADDR")?
                    .parse()
                    .context("parse SABIDEN_SIP_LOCAL_ADDR")?,
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
        })
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SABIDEN_SIP_SERVER_ADDR") {
            if let Ok(addr) = v.parse() {
                self.sip.server_addr = addr;
            }
        }
        if let Ok(v) = std::env::var("SABIDEN_SIP_LOCAL_ADDR") {
            if let Ok(addr) = v.parse() {
                self.sip.local_addr = addr;
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
    }

    pub fn example() -> String {
        r#"[sip]
# DHCP Option 120 で取得した SIP サーバアドレス
server_addr = "[2001:A7FF:2101:6::F]:5060"
# この機器の NGN 側 IPv6 アドレス
local_addr = "[2001:xxxx:xxxx::1]:5060"
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
"#
        .to_string()
    }
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("environment variable {} not set", key))
}
