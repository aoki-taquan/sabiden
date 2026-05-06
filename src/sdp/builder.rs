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

/// SDP の RTP エンドポイント (c= IP / m= port) を sabiden 側に書き換える。
///
/// B2BUA で受け取った SDP オファ/アンサをそのまま反対側に流すと、ピアは
/// 互いに直接 RTP を送ろうとして sabiden を経由しなくなってしまう。
/// そこで sabiden が中継用に bind した IP と port で
/// セッションレベル `c=` と最初の `m=audio` の port を書き換える。
///
/// 書き換え対象:
/// - `o=` の origin address (`addr` に置換)
/// - セッションレベル `c=` (`addr` に置換、なければ生成)
/// - 最初の `m=audio` の port (`port` に置換)
/// - その `m=audio` のメディアレベル `c=` があれば (`addr` に置換)
///
/// 元 SDP のパースに失敗したらそのまま返す。
pub fn rewrite_rtp_endpoint(sdp_bytes: &[u8], addr: IpAddr, port: u16) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(sdp_bytes)?;
    let mut sdp = SessionDescription::parse(text)?;

    sdp.origin.address = addr;
    // セッションレベル c= は必ず sabiden を指すようにする
    sdp.connection = Some(Connection { address: addr });

    // 最初の audio media を sabiden 側に書き換える
    if let Some(audio) = sdp.media.iter_mut().find(|m| m.media == "audio") {
        audio.port = port;
        // メディアレベル c= が立っていればそちらも整合させる
        if audio.connection.is_some() {
            audio.connection = Some(Connection { address: addr });
        }
    }

    Ok(sdp.to_string_crlf().into_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// セッションレベル c= しかない SDP は c= とポートが書き換わる。
    #[test]
    fn rewrite_rewrites_session_level_connection() {
        let original = b"v=0\r\n\
                         o=- 1 1 IN IP4 192.0.2.1\r\n\
                         s=-\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 30000 RTP/AVP 0\r\n\
                         a=rtpmap:0 PCMU/8000\r\n";
        let new_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let rewritten = rewrite_rtp_endpoint(original, new_addr, 40000).unwrap();
        let parsed = SessionDescription::parse(std::str::from_utf8(&rewritten).unwrap()).unwrap();
        assert_eq!(parsed.connection.as_ref().unwrap().address, new_addr);
        assert_eq!(parsed.origin.address, new_addr);
        assert_eq!(parsed.media[0].port, 40000);
        // PT/rtpmap は保持される
        assert_eq!(parsed.media[0].formats, vec!["0"]);
        assert!(parsed.find_rtpmap(0).is_some());
    }

    /// メディアレベル c= がある SDP も書き換わる。
    #[test]
    fn rewrite_rewrites_media_level_connection() {
        let original = b"v=0\r\n\
                         o=- 1 1 IN IP4 192.0.2.1\r\n\
                         s=-\r\n\
                         t=0 0\r\n\
                         m=audio 30000 RTP/AVP 0\r\n\
                         c=IN IP4 198.51.100.5\r\n\
                         a=rtpmap:0 PCMU/8000\r\n";
        let new_addr: IpAddr = "2001:db8::1".parse().unwrap();
        let rewritten = rewrite_rtp_endpoint(original, new_addr, 5004).unwrap();
        let parsed = SessionDescription::parse(std::str::from_utf8(&rewritten).unwrap()).unwrap();
        assert_eq!(parsed.connection.as_ref().unwrap().address, new_addr);
        assert_eq!(parsed.media[0].port, 5004);
        assert_eq!(
            parsed.media[0].connection.as_ref().unwrap().address,
            new_addr
        );
    }

    /// 不正な SDP はエラーで返る (元バイト列のまま流用するとピアが読めない)。
    #[test]
    fn rewrite_invalid_sdp_errors() {
        let original = b"not an sdp at all";
        let new_addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(rewrite_rtp_endpoint(original, new_addr, 1234).is_err());
    }
}
