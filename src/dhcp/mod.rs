use anyhow::Result;
/// DHCP Option 120 (RFC 3361) から SIP サーバアドレスを取得するヘルパー
///
/// 実際の取得は dhclient / dhcpcd の hook スクリプト経由で環境変数に入れて
/// このモジュールで読み取るのが現実的。
use std::net::IpAddr;

/// dhclient が Option 120 を取得した際の環境変数から SIP サーバを読む
/// dhclient.conf に以下を追加することで $new_ip_sip_servers が設定される:
///   option ip-sip-servers code 120 = { boolean, array of ip-address };
pub fn sip_servers_from_env() -> Vec<IpAddr> {
    let raw = std::env::var("new_ip_sip_servers").unwrap_or_default();
    raw.split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// /var/lib/dhcp/dhclient.leases から Option 120 を直接パース
pub fn sip_servers_from_lease_file(path: &str) -> Result<Vec<IpAddr>> {
    let content = std::fs::read_to_string(path)?;
    let mut servers = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // option ip-sip-servers 124.245.0.1;
        if line.starts_with("option ip-sip-servers") {
            let rest = line
                .trim_start_matches("option ip-sip-servers")
                .trim()
                .trim_end_matches(';');
            for addr_str in rest.split(',').map(|s| s.trim()) {
                if let Ok(ip) = addr_str.parse() {
                    servers.push(ip);
                }
            }
        }
    }

    Ok(servers)
}

/// NTT 東日本 NGN の既知 SIP サーバ (Option 120 が取得できない場合のフォールバック)
/// これらは変更される可能性があるため DHCP 取得を優先すること
pub fn known_ntt_east_servers() -> Vec<IpAddr> {
    vec![
        "2001:A7FF:2101:6::F".parse().unwrap(),
        "2001:A7FF:2101:1::C".parse().unwrap(),
        "2001:A7FF:2101::2".parse().unwrap(),
        "2001:A7FF:2101:3::F".parse().unwrap(),
    ]
}
