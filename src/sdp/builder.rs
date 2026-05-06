//! SDP シリアライザ (RFC 4566)。
//!
//! `SessionDescription` を SDP テキストに変換する。RFC 4566 では
//! 行終端は CRLF。SIP 経由で送信されるため UTF-8 ではなく US-ASCII を想定。
//!
//! また、NTT ひかり電話 (NGN) で頻出する G.711 μ-law のオファーを
//! 簡単に作れるヘルパ [`Sdpoffer`] 系コンストラクタを提供する。

use std::fmt::Write as _;
use std::net::IpAddr;

use super::{
    addrtype_of, Attribute, Connection, MediaDescription, Origin, SessionDescription, Timing,
};

/// SDP 全体をシリアライズする。
pub fn serialize(sdp: &SessionDescription) -> String {
    // RFC 4566 Section 5: 行順序は v, o, s, i?, u?, e*, p*, c?, b*, t, ..., a*, m*
    // 必須行 + よく使う行のみ書く。
    let mut out = String::with_capacity(256);
    let _ = writeln_crlf(&mut out, &format!("v={}", sdp.version));
    let _ = writeln_crlf(&mut out, &format!("o={}", format_origin(&sdp.origin)));
    let _ = writeln_crlf(&mut out, &format!("s={}", sdp.session_name));
    if let Some(c) = &sdp.connection {
        let _ = writeln_crlf(&mut out, &format!("c={}", format_connection(c)));
    }
    let _ = writeln_crlf(&mut out, &format!("t={}", format_timing(&sdp.timing)));
    for a in &sdp.attributes {
        let _ = writeln_crlf(&mut out, &format!("a={}", format_attr(a)));
    }
    for m in &sdp.media {
        let _ = writeln_crlf(&mut out, &format!("m={}", format_media(m)));
        if let Some(c) = &m.connection {
            let _ = writeln_crlf(&mut out, &format!("c={}", format_connection(c)));
        }
        for a in &m.attributes {
            let _ = writeln_crlf(&mut out, &format!("a={}", format_attr(a)));
        }
    }
    out
}

fn writeln_crlf(s: &mut String, line: &str) -> std::fmt::Result {
    write!(s, "{line}\r\n")
}

fn format_origin(o: &Origin) -> String {
    format!(
        "{} {} {} IN {} {}",
        o.username,
        o.session_id,
        o.session_version,
        addrtype_of(&o.address),
        o.address
    )
}

fn format_connection(c: &Connection) -> String {
    format!("IN {} {}", addrtype_of(&c.address), c.address)
}

fn format_timing(t: &Timing) -> String {
    format!("{} {}", t.start, t.stop)
}

fn format_media(m: &MediaDescription) -> String {
    let mut s = format!("{} {} {}", m.media, m.port, m.protocol);
    for f in &m.formats {
        s.push(' ');
        s.push_str(f);
    }
    s
}

fn format_attr(a: &Attribute) -> String {
    match a {
        Attribute::Property(k) => k.clone(),
        Attribute::Value { key, value } => format!("{key}:{value}"),
    }
}

impl SessionDescription {
    /// NGN / SIP UAC で典型的に使う G.711 μ-law (PCMU) オファーを作る。
    ///
    /// - `addr`: ローカル IP (c= と o= に使う)
    /// - `port`: RTP ポート
    /// - `ptime_ms`: パケット間隔 (ミリ秒)。NGN では 20 が一般的。
    pub fn pcmu_offer(addr: IpAddr, port: u16, ptime_ms: u32) -> Self {
        // RFC 4566 Section 5.2: o= の sess-id は NTP 形式の数値推奨。
        // RFC 3264 では同一セッションで同じ sess-id を維持し、変更ごとに
        // sess-version をインクリメントする。ここでは暫定値を入れる。
        let session_id = 0u64;
        SessionDescription {
            version: 0,
            origin: Origin {
                username: "-".to_string(),
                session_id,
                session_version: session_id,
                address: addr,
            },
            session_name: "-".to_string(),
            connection: Some(Connection { address: addr }),
            timing: Timing { start: 0, stop: 0 },
            attributes: Vec::new(),
            media: vec![MediaDescription {
                media: "audio".to_string(),
                port,
                protocol: "RTP/AVP".to_string(),
                formats: vec!["0".to_string()],
                connection: None,
                attributes: vec![
                    // PT=0 は RFC 3551 で PCMU/8000 が静的に予約されているが、
                    // SIP 相互運用のため明示的に rtpmap を書くのが慣習。
                    Attribute::Value {
                        key: "rtpmap".to_string(),
                        value: "0 PCMU/8000".to_string(),
                    },
                    Attribute::Value {
                        key: "ptime".to_string(),
                        value: ptime_ms.to_string(),
                    },
                ],
            }],
        }
    }
}
