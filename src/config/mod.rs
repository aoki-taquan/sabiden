use std::net::SocketAddr;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub sip: SipConfig,
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

fn default_expires() -> u32 {
    3600
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
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
"#
        .to_string()
    }
}
