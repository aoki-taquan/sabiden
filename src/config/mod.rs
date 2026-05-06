use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub sip: SipConfig,
    #[serde(default)]
    pub health: HealthConfig,
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
"#
        .to_string()
    }
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("environment variable {} not set", key))
}
