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
    // RFC 4566 §5.14 (m=):
    //   m=<media> <port> <proto> <fmt> ...
    //   proto = token *("/" token)
    // <media>, <port>, <proto> はそれぞれ token (BNF: token-char の連続) で、
    // 空白 / 制御文字 / 特殊文字 (CTL, SP, HTAB, '"', '(', ')', ',', ':' 等) を
    // 含むことは許されない。 本実装は port が u16 数値であることまで検証し、
    // proto は `validate_proto` で BNF (token *("/" token)) を強制する。
    let parts: Vec<&str> = val.split_whitespace().collect();
    if parts.len() < 4 {
        bail!("m= 行のフィールド数が不足: {val}");
    }
    // <port> 部分は "<port>/<num-ports>" 形式もあり得る (RFC 4566 §5.14)。
    // 本実装ではポート部分のみ採用し、num-ports は無視する。
    let port_part = parts[1].split('/').next().unwrap_or(parts[1]);
    let port: u16 = port_part
        .parse()
        .with_context(|| format!("m= ポート不正: {}", parts[1]))?;
    let protocol = validate_proto(parts[2])?;
    Ok(MediaDescription {
        media: parts[0].to_string(),
        port,
        protocol,
        formats: parts[3..].iter().map(|s| s.to_string()).collect(),
        connection: None,
        attributes: Vec::new(),
    })
}

/// RFC 4566 §5.14 (m=) の `<proto>` BNF を検証する。
///
/// ```text
///   proto      = token *("/" token)
///   token      = 1*(token-char)
///   token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 /
///                %x41-5A / %x5E-7E
/// ```
///
/// 主な valid 値: `udp`, `RTP/AVP`, `RTP/SAVP` (RFC 3711), `RTP/AVPF`
/// (RFC 4585), `UDP/TLS/RTP/SAVPF` (RFC 5764), `TCP/MSRP`, etc.
///
/// 違反例:
/// - 空文字
/// - 先頭 / 末尾 / 内部に `/` の連続 (空 token を含む)
/// - 空白 / タブ / 制御文字 / `:` / `(` / `)` / `,` / `;` / `<` / `>` /
///   `@` / `[` / `\` / `]` / `"` / `?` / `=` 等 (BNF 範囲外)
///
/// なお `{` (0x7B) / `|` (0x7C) / `}` (0x7D) / `~` (0x7E) は BNF 範囲
/// (0x5E-0x7E) 内なので token として **許容** される (例: 妙な独自 proto)。
///
/// なお、 RFC 4566 token は **case-sensitive** で `RTP/AVP` と `rtp/avp` は
/// 別物。 本関数は case を変えずに、 与えられた string を BNF に通すだけ
/// (case 正規化は `convert_avp_to_savpf` 等の比較側責務)。
fn validate_proto(s: &str) -> Result<String> {
    if s.is_empty() {
        bail!("m= proto が空 (RFC 4566 §5.14)");
    }
    for tok in s.split('/') {
        if tok.is_empty() {
            bail!("m= proto に空の token (RFC 4566 §5.14): {s}");
        }
        for ch in tok.chars() {
            if !is_rfc4566_token_char(ch) {
                bail!(
                    "m= proto に RFC 4566 §5.14 token 外の文字 (U+{:04X}): {s}",
                    ch as u32
                );
            }
        }
    }
    Ok(s.to_string())
}

/// RFC 4566 §9 (BNF) の `token-char` 定義に従う。
///
/// ```text
///   token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 /
///                %x41-5A / %x5E-7E
/// ```
///
/// 除外される代表的 ASCII: `SP` (0x20) / `"` (0x22) / `(` (0x28) /
/// `)` (0x29) / `,` (0x2C) / `/` (0x2F) / `:` (0x3A) / `;` (0x3B) /
/// `<` (0x3C) / `=` (0x3D) / `>` (0x3E) / `?` (0x3F) / `@` (0x40) /
/// `[` (0x5B) / `\` (0x5C) / `]` (0x5D)、 および 0x00-0x1F の CTL と
/// 0x7F (DEL)、 ASCII 範囲外 (0x80-)。
///
/// `proto = token *("/" token)` の token 単位で呼び出すため、 `/` 自体は
/// ここでは true を返さない (呼出し側で `split('/')` 済)。
fn is_rfc4566_token_char(ch: char) -> bool {
    let c = ch as u32;
    matches!(
        c,
        0x21
            | 0x23..=0x27
            | 0x2A..=0x2B
            | 0x2D..=0x2E
            | 0x30..=0x39
            | 0x41..=0x5A
            | 0x5E..=0x7E
    )
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

#[cfg(test)]
mod proto_validation_tests {
    //! RFC 4566 §5.14 `m=<media> <port> <proto> <fmt>` の `<proto>` BNF
    //! 検証テスト。 IANA 登録の主要値 (RFC 3551 / RFC 3711 / RFC 4585 /
    //! RFC 5764) を accept し、 BNF 違反値を reject することを確かめる。

    use super::*;

    fn parse_m(line_val: &str) -> Result<MediaDescription> {
        parse_media(line_val)
    }

    /// RFC 4566 §5.14 + RFC 3551: 最も基本の `RTP/AVP` は accept。
    #[test]
    fn rfc4566_5_14_accepts_rtp_avp() {
        let m = parse_m("audio 30000 RTP/AVP 0").expect("RTP/AVP は valid");
        assert_eq!(m.protocol, "RTP/AVP");
        assert_eq!(m.media, "audio");
        assert_eq!(m.port, 30000);
        assert_eq!(m.formats, vec!["0".to_string()]);
    }

    /// RFC 3711: `RTP/SAVP` は accept。
    #[test]
    fn rfc3711_accepts_rtp_savp() {
        let m = parse_m("audio 5004 RTP/SAVP 0").expect("RTP/SAVP は valid");
        assert_eq!(m.protocol, "RTP/SAVP");
    }

    /// RFC 4585: `RTP/AVPF` (feedback) は accept。
    #[test]
    fn rfc4585_accepts_rtp_avpf() {
        let m = parse_m("audio 5004 RTP/AVPF 0").expect("RTP/AVPF は valid");
        assert_eq!(m.protocol, "RTP/AVPF");
    }

    /// RFC 5764: WebRTC で必須の `UDP/TLS/RTP/SAVPF` は accept。
    #[test]
    fn rfc5764_accepts_udp_tls_rtp_savpf() {
        let m = parse_m("audio 9 UDP/TLS/RTP/SAVPF 0").expect("UDP/TLS/RTP/SAVPF は valid");
        assert_eq!(m.protocol, "UDP/TLS/RTP/SAVPF");
    }

    /// RFC 4566 §5.14: `udp` 単独 (RTP 以外のメディア用) も BNF 上 valid。
    #[test]
    fn rfc4566_5_14_accepts_lowercase_udp_token() {
        let m = parse_m("audio 49170 udp 0").expect("udp は token 1 個で valid");
        assert_eq!(m.protocol, "udp");
    }

    /// RFC 4566 §5.14: proto に `:` (token-char 外) を含むと reject。
    /// 例: 誤って `RTP:AVP` と書いた SDP。
    #[test]
    fn rfc4566_5_14_rejects_colon_in_proto() {
        let err = parse_m("audio 5004 RTP:AVP 0").expect_err("`:` は token-char 外");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("token") || msg.contains("proto"),
            "エラーメッセージに proto/token への言及が無い: {msg}"
        );
    }

    /// RFC 4566 §5.14: proto に `@` (token-char 外) を含むと reject。
    #[test]
    fn rfc4566_5_14_rejects_at_sign_in_proto() {
        assert!(parse_m("audio 5004 RTP@AVP 0").is_err());
    }

    /// RFC 4566 §9 BNF (`token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E /
    /// %x30-39 / %x41-5A / %x5E-7E`): 範囲外の代表的 ASCII セパレータを reject。
    ///
    /// 具体的に reject されるべき文字 (BNF 範囲外):
    /// - 0x22 `"`, 0x28 `(`, 0x29 `)`, 0x2C `,`, 0x2F `/` (token 内には不可、
    ///   ただし proto 内で区切りとしては別途許容)
    /// - 0x3A `:`, 0x3B `;`, 0x3C `<`, 0x3D `=`, 0x3E `>`, 0x3F `?`, 0x40 `@`
    /// - 0x5B `[`, 0x5C `\`, 0x5D `]`
    ///
    /// `{` (0x7B) / `|` (0x7C) / `}` (0x7D) / `~` (0x7E) は BNF 範囲内なので
    /// 本テストでは reject 対象に含めない (RFC 4566 §9 BNF 確認済)。
    #[test]
    fn rfc4566_5_14_rejects_misc_separators_in_proto() {
        for bad in [
            "audio 5004 RTP<AVP 0",
            "audio 5004 RTP>AVP 0",
            "audio 5004 RTP=AVP 0",
            "audio 5004 RTP?AVP 0",
            "audio 5004 RTP[AVP 0",
            "audio 5004 RTP]AVP 0",
            "audio 5004 RTP\\AVP 0",
            "audio 5004 RTP(AVP 0",
            "audio 5004 RTP)AVP 0",
            "audio 5004 RTP,AVP 0",
            "audio 5004 RTP;AVP 0",
            "audio 5004 RTP\"AVP 0",
            "audio 5004 RTP@AVP 0",
        ] {
            assert!(parse_m(bad).is_err(), "BNF 外を accept してしまった: {bad}");
        }
    }

    /// RFC 4566 §5.14: `proto = token *("/" token)` で空 token は不可。
    /// `RTP//AVP` (連続スラッシュ) や `/RTP/AVP` (先頭スラッシュ) は reject。
    #[test]
    fn rfc4566_5_14_rejects_empty_token_segments() {
        for bad in [
            "audio 5004 RTP//AVP 0",
            "audio 5004 /RTP/AVP 0",
            "audio 5004 RTP/AVP/ 0",
            "audio 5004 / 0",
        ] {
            assert!(parse_m(bad).is_err(), "空 token を accept した: {bad}");
        }
    }

    /// RFC 4566 §5.14: 制御文字 (0x00-0x1F, 0x7F) は token-char 外。
    /// `split_whitespace` で TAB / LF / CR は除去されるが、 それ以外の
    /// CTL (例 0x01 SOH, 0x7F DEL) が紛れ込んだケースを検証する。
    #[test]
    fn rfc4566_5_14_rejects_control_chars_in_proto() {
        let bad = format!("audio 5004 RTP{}AVP 0", '\u{01}');
        assert!(parse_m(&bad).is_err(), "SOH (0x01) を accept した: {bad:?}");
        let bad_del = format!("audio 5004 RTP{}AVP 0", '\u{7F}');
        assert!(
            parse_m(&bad_del).is_err(),
            "DEL (0x7F) を accept した: {bad_del:?}"
        );
    }

    /// RFC 4566 §9 BNF: ASCII 範囲外 (例: 日本語) は token-char 外。
    #[test]
    fn rfc4566_9_rejects_non_ascii_in_proto() {
        assert!(parse_m("audio 5004 RTP/АVP 0").is_err()); // А=Cyrillic
        assert!(parse_m("audio 5004 RTP/プロト 0").is_err());
    }

    /// 互換性: 既知の SDP (NGN PCMU offer / WebRTC SAVPF) が SessionDescription
    /// レベルで引き続きパース可能であること (regression guard)。
    #[test]
    fn rfc4566_5_14_does_not_break_known_offers() {
        let ngn = "v=0\r\n\
                   o=- 0 0 IN IP6 2001:db8::1\r\n\
                   s=-\r\n\
                   c=IN IP6 2001:db8::1\r\n\
                   t=0 0\r\n\
                   m=audio 30000 RTP/AVP 0\r\n\
                   a=rtpmap:0 PCMU/8000\r\n";
        assert!(parse(ngn).is_ok());

        let webrtc = "v=0\r\n\
                      o=mozilla 1 0 IN IP4 0.0.0.0\r\n\
                      s=-\r\n\
                      t=0 0\r\n\
                      m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
                      c=IN IP4 0.0.0.0\r\n\
                      a=rtpmap:0 PCMU/8000\r\n";
        assert!(parse(webrtc).is_ok());
    }

    /// 不正 proto が含まれる SDP は SessionDescription レベルでも reject される。
    /// 攻撃面: SDP fuzz で proto に巨大 / 異常文字列が来た場合の早期 reject。
    #[test]
    fn rfc4566_5_14_session_parse_rejects_invalid_proto() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 192.0.2.1\r\n\
                   s=-\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 5004 RTP:AVP 0\r\n";
        assert!(parse(sdp).is_err(), "BNF 違反 proto の SDP が parse 通った");
    }
}
