//! SDP パーサ (RFC 4566)。
//!
//! SDP は行単位 (CRLF または LF) で `<type>=<value>` 形式。
//! 各 type は 1 文字。本実装では SIP ユースケース (audio セッション) で
//! 必要となる v / o / s / c / t / m / a を扱う。
//! 想定外の type 行 (i, u, e, p, b, k, r, z) は、互換性のため無視する。

use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};

use super::{Attribute, Connection, MediaDescription, Origin, SessionDescription, Timing};

/// SDP テキストをパースする。
pub fn parse(input: &str) -> Result<SessionDescription> {
    // RFC 4566 Section 5: lines are CRLF terminated, but parsers SHOULD also accept LF.
    let lines: Vec<&str> = input
        .split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .collect();

    let mut idx = 0usize;
    let mut version: Option<u32> = None;
    let mut origin: Option<Origin> = None;
    let mut session_name: Option<String> = None;
    let mut connection: Option<Connection> = None;
    let mut timing: Option<Timing> = None;
    let mut session_attrs: Vec<Attribute> = Vec::new();
    let mut media: Vec<MediaDescription> = Vec::new();

    // セッションレベルの行を処理
    while idx < lines.len() {
        let line = lines[idx];
        let (ty, val) = split_type_value(line)?;
        match ty {
            'v' => {
                version = Some(
                    val.parse()
                        .with_context(|| format!("v= の数値変換失敗: {val}"))?,
                );
                idx += 1;
            }
            'o' => {
                origin = Some(parse_origin(val)?);
                idx += 1;
            }
            's' => {
                session_name = Some(val.to_string());
                idx += 1;
            }
            'c' => {
                connection = Some(parse_connection(val)?);
                idx += 1;
            }
            't' => {
                timing = Some(parse_timing(val)?);
                idx += 1;
            }
            'a' => {
                session_attrs.push(parse_attribute(val));
                idx += 1;
            }
            'm' => {
                // メディアセクションに突入。以降は media ループに任せる。
                break;
            }
            // 互換性のため無視
            'i' | 'u' | 'e' | 'p' | 'b' | 'k' | 'r' | 'z' => {
                idx += 1;
            }
            _ => {
                idx += 1;
            }
        }
    }

    // メディアセクション
    while idx < lines.len() {
        let line = lines[idx];
        let (ty, val) = split_type_value(line)?;
        if ty != 'm' {
            // 仕様上 m= の前にメディアレベル行は来ない
            idx += 1;
            continue;
        }
        let mut m = parse_media(val)?;
        idx += 1;

        // 次の m= までが本メディアの属性
        while idx < lines.len() {
            let l = lines[idx];
            let (t, v) = split_type_value(l)?;
            match t {
                'm' => break,
                'c' => {
                    m.connection = Some(parse_connection(v)?);
                    idx += 1;
                }
                'a' => {
                    m.attributes.push(parse_attribute(v));
                    idx += 1;
                }
                'i' | 'b' | 'k' => {
                    idx += 1;
                }
                _ => {
                    idx += 1;
                }
            }
        }
        media.push(m);
    }

    Ok(SessionDescription {
        version: version.ok_or_else(|| anyhow!("v= 行が必須"))?,
        origin: origin.ok_or_else(|| anyhow!("o= 行が必須"))?,
        session_name: session_name.ok_or_else(|| anyhow!("s= 行が必須"))?,
        connection,
        timing: timing.ok_or_else(|| anyhow!("t= 行が必須"))?,
        attributes: session_attrs,
        media,
    })
}

fn split_type_value(line: &str) -> Result<(char, &str)> {
    let mut chars = line.chars();
    let ty = chars
        .next()
        .ok_or_else(|| anyhow!("空行は事前にフィルタされているはず"))?;
    let eq = chars
        .next()
        .ok_or_else(|| anyhow!("type の後に = が必要: {line}"))?;
    if eq != '=' {
        bail!("SDP 行は `<type>=<value>` 形式: {line}");
    }
    Ok((ty, &line[2..]))
}

fn parse_origin(val: &str) -> Result<Origin> {
    // <username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
    let parts: Vec<&str> = val.split_whitespace().collect();
    if parts.len() != 6 {
        bail!("o= 行のフィールド数が不正: {val}");
    }
    if parts[3] != "IN" {
        bail!("o= の nettype は IN のみサポート: {}", parts[3]);
    }
    check_addrtype(parts[4])?;
    let address = parse_ip(parts[5], parts[4])?;
    Ok(Origin {
        username: parts[0].to_string(),
        session_id: parts[1]
            .parse()
            .with_context(|| format!("o= sess-id 不正: {}", parts[1]))?,
        session_version: parts[2]
            .parse()
            .with_context(|| format!("o= sess-version 不正: {}", parts[2]))?,
        address,
    })
}

fn parse_connection(val: &str) -> Result<Connection> {
    // <nettype> <addrtype> <connection-address>
    let parts: Vec<&str> = val.split_whitespace().collect();
    if parts.len() != 3 {
        bail!("c= 行のフィールド数が不正: {val}");
    }
    if parts[0] != "IN" {
        bail!("c= の nettype は IN のみサポート: {}", parts[0]);
    }
    check_addrtype(parts[1])?;
    // RFC 4566 では IPv4 multicast で `<addr>/<ttl>` 形式があり得るが本実装は未対応。
    let addr_part = parts[2].split('/').next().unwrap_or(parts[2]);
    let address = parse_ip(addr_part, parts[1])?;
    Ok(Connection { address })
}

fn parse_timing(val: &str) -> Result<Timing> {
    let parts: Vec<&str> = val.split_whitespace().collect();
    if parts.len() != 2 {
        bail!("t= 行のフィールド数が不正: {val}");
    }
    Ok(Timing {
        start: parts[0]
            .parse()
            .with_context(|| format!("t= start 不正: {}", parts[0]))?,
        stop: parts[1]
            .parse()
            .with_context(|| format!("t= stop 不正: {}", parts[1]))?,
    })
}

fn parse_media(val: &str) -> Result<MediaDescription> {
    // <media> <port> <proto> <fmt> ...
    let parts: Vec<&str> = val.split_whitespace().collect();
    if parts.len() < 4 {
        bail!("m= 行のフィールド数が不足: {val}");
    }
    // <port> 部分は "<port>/<num-ports>" 形式もあり得る (RFC 4566)。
    // 本実装ではポート部分のみ採用し、num-ports は無視する。
    let port_part = parts[1].split('/').next().unwrap_or(parts[1]);
    let port: u16 = port_part
        .parse()
        .with_context(|| format!("m= ポート不正: {}", parts[1]))?;
    Ok(MediaDescription {
        media: parts[0].to_string(),
        port,
        protocol: parts[2].to_string(),
        formats: parts[3..].iter().map(|s| s.to_string()).collect(),
        connection: None,
        attributes: Vec::new(),
    })
}

fn parse_attribute(val: &str) -> Attribute {
    // a=<flag> または a=<key>:<value>
    if let Some((key, value)) = val.split_once(':') {
        Attribute::Value {
            key: key.to_string(),
            value: value.to_string(),
        }
    } else {
        Attribute::Property(val.to_string())
    }
}

fn check_addrtype(at: &str) -> Result<()> {
    match at {
        "IP4" | "IP6" => Ok(()),
        other => bail!("未知の addrtype: {other}"),
    }
}

fn parse_ip(s: &str, addrtype: &str) -> Result<IpAddr> {
    let ip = IpAddr::from_str(s).with_context(|| format!("IP アドレス不正: {s}"))?;
    match (addrtype, &ip) {
        ("IP4", IpAddr::V4(_)) | ("IP6", IpAddr::V6(_)) => Ok(ip),
        _ => bail!("addrtype {addrtype} と IP {s} が一致しない"),
    }
}
