//! SDP (Session Description Protocol) パーサ・シリアライザ
//!
//! RFC 4566 に基づく SDP 実装。SIP INVITE で送受信される SDP の
//! Offer/Answer モデル (RFC 3264) を意識した設計。
//!
//! NTT ひかり電話 (NGN) の場合 IPv6 + G.711 μ-law (PT=0) が中心。

pub mod builder;
pub mod parser;

use std::fmt;
use std::net::IpAddr;

/// SDP セッション記述全体 (RFC 4566 Section 5)。
///
/// 必須フィールド (v=, o=, s=, t=) は構造体フィールドとして保持し、
/// オプションのセッション属性 (a=) と c= 行はそれぞれ Vec / Option で持つ。
#[derive(Debug, Clone, PartialEq)]
pub struct SessionDescription {
    /// v= プロトコルバージョン (常に 0)
    pub version: u32,
    /// o= 起点 (origin)
    pub origin: Origin,
    /// s= セッション名 (空のときは "-" を入れる)
    pub session_name: String,
    /// c= 接続情報 (セッションレベル、メディアレベルにも書ける)
    pub connection: Option<Connection>,
    /// t= タイミング (start, stop)。0 0 が一般的。
    pub timing: Timing,
    /// セッションレベル属性 a= (rtpmap など)
    pub attributes: Vec<Attribute>,
    /// メディア記述 m=
    pub media: Vec<MediaDescription>,
}

/// o= 行 (RFC 4566 Section 5.2)。
///
/// 形式: `o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>`
#[derive(Debug, Clone, PartialEq)]
pub struct Origin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub address: IpAddr,
}

/// c= 行 (RFC 4566 Section 5.7)。
///
/// 形式: `c=<nettype> <addrtype> <connection-address>`
/// IPv4 multicast の TTL 表記 (例: `224.2.36.42/127`) は本実装では未対応。
#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub address: IpAddr,
}

/// t= 行 (RFC 4566 Section 5.9)。
///
/// 形式: `t=<start-time> <stop-time>`。SIP セッションでは通常 `0 0`。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Timing {
    pub start: u64,
    pub stop: u64,
}

/// m= 行で始まるメディア記述 (RFC 4566 Section 5.14)。
#[derive(Debug, Clone, PartialEq)]
pub struct MediaDescription {
    /// audio / video / etc.
    pub media: String,
    /// RTP ポート
    pub port: u16,
    /// プロトコル (例: "RTP/AVP")
    pub protocol: String,
    /// フォーマット (RTP の payload type 番号など)
    pub formats: Vec<String>,
    /// メディアレベルの c= 行 (オプション)
    pub connection: Option<Connection>,
    /// メディア属性 a=
    pub attributes: Vec<Attribute>,
}

/// SDP 属性 (a=) (RFC 4566 Section 5.13)。
///
/// "property" (`a=sendrecv`) と "value" (`a=rtpmap:0 PCMU/8000`) の 2 形態がある。
#[derive(Debug, Clone, PartialEq)]
pub enum Attribute {
    /// `a=<flag>` 形式
    Property(String),
    /// `a=<key>:<value>` 形式
    Value { key: String, value: String },
}

impl Attribute {
    /// 属性キーを返す (Property/Value どちらでも統一して取得)。
    pub fn key(&self) -> &str {
        match self {
            Attribute::Property(k) => k,
            Attribute::Value { key, .. } => key,
        }
    }

    /// `a=rtpmap:<pt> <encoding>/<clockrate>[/<params>]` をパースする。
    /// 自身が rtpmap 属性でなければ None。
    pub fn as_rtpmap(&self) -> Option<RtpMap> {
        let Attribute::Value { key, value } = self else {
            return None;
        };
        if key != "rtpmap" {
            return None;
        }
        RtpMap::parse(value).ok()
    }
}

/// rtpmap 属性のパース結果 (RFC 4566 Section 6)。
#[derive(Debug, Clone, PartialEq)]
pub struct RtpMap {
    /// payload type (0..=127)
    pub payload_type: u8,
    /// エンコーディング名 (例: "PCMU")
    pub encoding: String,
    /// クロックレート (Hz)
    pub clock_rate: u32,
    /// チャンネル等のオプションパラメータ
    pub parameters: Option<String>,
}

impl RtpMap {
    /// `<pt> <encoding>/<clockrate>[/<params>]` の値部分をパースする。
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let mut iter = value.splitn(2, char::is_whitespace);
        let pt_str = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("rtpmap: payload type が見つからない"))?;
        let rest = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("rtpmap: encoding が見つからない"))?
            .trim();
        let payload_type: u8 = pt_str
            .parse()
            .map_err(|_| anyhow::anyhow!("rtpmap: payload type が数値でない: {}", pt_str))?;
        let mut parts = rest.split('/');
        let encoding = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("rtpmap: encoding 名なし"))?
            .to_string();
        let clock_rate: u32 = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("rtpmap: clock rate なし"))?
            .parse()
            .map_err(|_| anyhow::anyhow!("rtpmap: clock rate が数値でない"))?;
        let parameters = parts.next().map(|s| s.to_string());
        Ok(RtpMap {
            payload_type,
            encoding,
            clock_rate,
            parameters,
        })
    }
}

impl SessionDescription {
    /// 文字列から SDP をパースする。RFC 4566。
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        parser::parse(input)
    }

    /// SDP を文字列にシリアライズする (CRLF 区切り)。
    pub fn to_string_crlf(&self) -> String {
        builder::serialize(self)
    }

    /// 指定された payload type の rtpmap 属性を最初のメディアから探す。
    pub fn find_rtpmap(&self, payload_type: u8) -> Option<RtpMap> {
        for m in &self.media {
            for a in &m.attributes {
                if let Some(rm) = a.as_rtpmap() {
                    if rm.payload_type == payload_type {
                        return Some(rm);
                    }
                }
            }
        }
        None
    }
}

impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_crlf())
    }
}

/// IP アドレスから SDP の addrtype 文字列 ("IP4" / "IP6") を返す。
pub(crate) fn addrtype_of(addr: &IpAddr) -> &'static str {
    match addr {
        IpAddr::V4(_) => "IP4",
        IpAddr::V6(_) => "IP6",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// 実機キャプチャを意識した NGN 風 SDP のラウンドトリップ。
    #[test]
    fn round_trip_ngn_ipv6_pcmu() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP6 2001:db8::1\r\n\
                   s=-\r\n\
                   c=IN IP6 2001:db8::1\r\n\
                   t=0 0\r\n\
                   m=audio 30000 RTP/AVP 0\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=ptime:20\r\n";
        let parsed = SessionDescription::parse(sdp).expect("parse");
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.origin.username, "-");
        assert_eq!(
            parsed.origin.address,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(parsed.session_name, "-");
        let conn = parsed.connection.as_ref().unwrap();
        assert!(matches!(conn.address, IpAddr::V6(_)));
        assert_eq!(parsed.timing, Timing { start: 0, stop: 0 });

        let m = &parsed.media[0];
        assert_eq!(m.media, "audio");
        assert_eq!(m.port, 30000);
        assert_eq!(m.protocol, "RTP/AVP");
        assert_eq!(m.formats, vec!["0".to_string()]);

        // rtpmap が引ける
        let rm = parsed.find_rtpmap(0).expect("PCMU rtpmap");
        assert_eq!(rm.encoding, "PCMU");
        assert_eq!(rm.clock_rate, 8000);
        assert_eq!(rm.payload_type, 0);
        assert!(rm.parameters.is_none());

        // シリアライズ→再パースで等価
        let serialized = parsed.to_string_crlf();
        let reparsed = SessionDescription::parse(&serialized).expect("reparse");
        assert_eq!(parsed, reparsed);
    }

    /// IPv4 SDP の基本パース。
    #[test]
    fn parse_ipv4_sdp() {
        let sdp = "v=0\r\n\
                   o=alice 2890844526 2890844527 IN IP4 192.0.2.10\r\n\
                   s=Session\r\n\
                   c=IN IP4 192.0.2.10\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 8 101\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n\
                   a=rtpmap:101 telephone-event/8000\r\n\
                   a=fmtp:101 0-15\r\n\
                   a=sendrecv\r\n";
        let parsed = SessionDescription::parse(sdp).expect("parse");
        assert_eq!(parsed.origin.username, "alice");
        assert_eq!(parsed.origin.session_id, 2890844526);
        assert_eq!(parsed.origin.session_version, 2890844527);
        assert_eq!(
            parsed.origin.address,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
        );
        let m = &parsed.media[0];
        assert_eq!(m.formats, vec!["0", "8", "101"]);
        assert_eq!(m.attributes.len(), 5);
        assert!(m
            .attributes
            .iter()
            .any(|a| matches!(a, Attribute::Property(p) if p == "sendrecv")));
        let pcma = parsed.find_rtpmap(8).expect("PCMA rtpmap");
        assert_eq!(pcma.encoding, "PCMA");
    }

    /// LF のみの行終端も受け付ける (SHOULD: RFC 4566)。
    #[test]
    fn parse_accepts_lf_only() {
        let sdp = "v=0\no=- 1 1 IN IP4 192.0.2.1\ns=-\nc=IN IP4 192.0.2.1\nt=0 0\nm=audio 5004 RTP/AVP 0\n";
        let parsed = SessionDescription::parse(sdp).expect("parse");
        assert_eq!(parsed.media[0].port, 5004);
    }

    /// addrtype と IP の不一致はエラー。
    #[test]
    fn mismatched_addrtype_rejected() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 ::1\r\ns=-\r\nt=0 0\r\nm=audio 1000 RTP/AVP 0\r\n";
        assert!(SessionDescription::parse(sdp).is_err());
    }

    /// 必須フィールド欠落はエラー。
    #[test]
    fn missing_required_fields_rejected() {
        let sdp = "v=0\r\ns=-\r\nt=0 0\r\n"; // o= 欠落
        assert!(SessionDescription::parse(sdp).is_err());
    }

    /// `pcmu_offer` ヘルパが期待通りの SDP を生成する。
    #[test]
    fn pcmu_offer_helper_ipv6() {
        let addr: IpAddr = "2001:db8::abcd".parse().unwrap();
        let offer = SessionDescription::pcmu_offer(addr, 30000, 20);
        let s = offer.to_string_crlf();
        assert!(s.contains("v=0\r\n"));
        assert!(s.contains("c=IN IP6 2001:db8::abcd\r\n"));
        assert!(s.contains("m=audio 30000 RTP/AVP 0\r\n"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=ptime:20\r\n"));
        // 自身がパースできる
        let reparsed = SessionDescription::parse(&s).expect("reparse offer");
        assert_eq!(reparsed.find_rtpmap(0).unwrap().encoding, "PCMU");
    }

    /// RFC 4566 §5.2 (Origin): "<sess-id> is a numeric string such that the
    /// tuple of <username>, <sess-id>, <nettype>, <addrtype>, and
    /// <unicast-address> forms a globally unique identifier for the session."
    ///
    /// `pcmu_offer` が sess-id=0 固定だと、 同一 sabiden プロセスから複数の
    /// INVITE を出した際に GU 性を失う。 Issue #78 で UNIX epoch 秒ベースに
    /// 変更したので、 (1) sess-id が 0 でないこと、 (2) sess-id == sess-version
    /// (RFC 3264 §8: 初回オファーは同値、 後続変更で sess-version を回す) を
    /// 検証する。
    #[test]
    fn rfc4566_5_2_pcmu_offer_session_id_nonzero_and_matches_version() {
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        let offer = SessionDescription::pcmu_offer(addr, 30000, 20);
        assert_ne!(
            offer.origin.session_id, 0,
            "sess-id must be a unique numeric value, not the fixed 0 (RFC 4566 §5.2)"
        );
        assert_eq!(
            offer.origin.session_id, offer.origin.session_version,
            "initial offer should have sess-id == sess-version (RFC 3264 §8)"
        );
    }

    /// rtpmap でチャンネル付き (例: opus/48000/2) のパース。
    #[test]
    fn rtpmap_with_channels() {
        let a = Attribute::Value {
            key: "rtpmap".to_string(),
            value: "111 opus/48000/2".to_string(),
        };
        let rm = a.as_rtpmap().expect("rtpmap");
        assert_eq!(rm.payload_type, 111);
        assert_eq!(rm.encoding, "opus");
        assert_eq!(rm.clock_rate, 48000);
        assert_eq!(rm.parameters.as_deref(), Some("2"));
    }

    /// メディアレベルの c= がパースされる。
    #[test]
    fn media_level_connection() {
        let sdp = "v=0\r\n\
                   o=- 1 1 IN IP4 192.0.2.1\r\n\
                   s=-\r\n\
                   t=0 0\r\n\
                   m=audio 5004 RTP/AVP 0\r\n\
                   c=IN IP4 198.51.100.5\r\n\
                   a=rtpmap:0 PCMU/8000\r\n";
        let parsed = SessionDescription::parse(sdp).expect("parse");
        assert!(parsed.connection.is_none());
        let mc = parsed.media[0].connection.as_ref().unwrap();
        assert_eq!(mc.address, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)));
    }

    /// 不明な行 (i=, u= 等) は無視される。
    #[test]
    fn unknown_lines_ignored() {
        let sdp = "v=0\r\n\
                   o=- 1 1 IN IP4 192.0.2.1\r\n\
                   s=-\r\n\
                   i=Some Info\r\n\
                   u=https://example.com/\r\n\
                   c=IN IP4 192.0.2.1\r\n\
                   t=0 0\r\n\
                   m=audio 5004 RTP/AVP 0\r\n\
                   a=rtpmap:0 PCMU/8000\r\n";
        let parsed = SessionDescription::parse(sdp).expect("parse");
        assert_eq!(parsed.media.len(), 1);
    }
}
