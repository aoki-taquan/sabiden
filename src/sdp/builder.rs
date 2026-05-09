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
    // Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §3 / §4):
    // `o=` の username は `-` に正規化する (Asterisk は `-`、sabiden は内線
    // 由来で `iphone` 等が乗る → NGN は 500 Server Internal Error を返す)。
    // RFC 4566 §5.2 でも username が `-` (anonymous origin) は推奨形。
    sdp.origin.username = "-".to_string();
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

/// audio メディアを **G.711 μ-law (payload type 0) のみ** に絞った SDP を返す。
///
/// NTT ひかり電話 (NGN) は PCMU(0) しか受け入れず、Linphone/Zoiper 等が送ってくる
/// multi-codec オファ (Opus, Speex, G.729, telephone-event 等) を素通しすると
/// `488 Not Acceptable Here` で拒否される。本関数は内線→NGN プロキシ時の
/// SDP を NGN 仕様に正規化する用途。
///
/// 動作:
/// - audio media の `formats` を `["0"]` に置換
/// - rtpmap / fmtp 系のうち payload_type=0 以外を削除
/// - WebRTC/DTLS-SRTP/ICE 由来属性 (rtcp-fb / rtcp-xr / fingerprint / setup /
///   ice-* / candidate / msid / mid / ssrc* / extmap / rtcp-mux 等) を削除
/// - PCMU の `a=rtpmap:0 PCMU/8000` が無ければ補う
///
/// パース不能ならそのまま返す (ベストエフォート)。
pub fn restrict_audio_to_pcmu(sdp_bytes: &[u8]) -> Vec<u8> {
    let text = match std::str::from_utf8(sdp_bytes) {
        Ok(s) => s,
        Err(_) => return sdp_bytes.to_vec(),
    };
    let mut sdp = match SessionDescription::parse(text) {
        Ok(s) => s,
        Err(_) => return sdp_bytes.to_vec(),
    };

    // WebRTC / DTLS-SRTP / ICE / multiplex 系・rtcp-xr 等は NGN が解釈しない
    // ので、セッションレベル / メディアレベル双方で削除する。
    fn is_unsupported_by_ngn(a: &Attribute) -> bool {
        match a {
            Attribute::Value { key, .. } => matches!(
                key.as_str(),
                "rtcp-fb"
                    | "rtcp-xr"
                    | "fingerprint"
                    | "setup"
                    | "ice-ufrag"
                    | "ice-pwd"
                    | "ice-options"
                    | "ice-mismatch"
                    | "candidate"
                    | "msid"
                    | "mid"
                    | "ssrc"
                    | "ssrc-group"
                    | "extmap"
                    | "rtcp-mux"
                    | "record"
            ),
            Attribute::Property(p) => {
                matches!(p.as_str(), "rtcp-mux" | "ice-lite" | "rtcp-rsize")
            }
        }
    }

    sdp.attributes.retain(|a| !is_unsupported_by_ngn(a));

    if let Some(audio) = sdp.media.iter_mut().find(|m| m.media == "audio") {
        audio.formats = vec!["0".to_string()];
        let mut have_pcmu_rtpmap = false;
        audio.attributes.retain(|a| {
            if is_unsupported_by_ngn(a) {
                return false;
            }
            match a {
                Attribute::Value { key, value } => {
                    let is_pt_zero = || {
                        value
                            .split_whitespace()
                            .next()
                            .and_then(|p| p.parse::<u8>().ok())
                            .map(|pt| pt == 0)
                            .unwrap_or(true)
                    };
                    match key.as_str() {
                        "rtpmap" => {
                            let keep = is_pt_zero();
                            if keep {
                                have_pcmu_rtpmap = true;
                            }
                            keep
                        }
                        "fmtp" => is_pt_zero(),
                        _ => true,
                    }
                }
                Attribute::Property(_) => true,
            }
        });
        if !have_pcmu_rtpmap {
            audio.attributes.insert(
                0,
                Attribute::Value {
                    key: "rtpmap".to_string(),
                    value: "0 PCMU/8000".to_string(),
                },
            );
        }
    }
    sdp.to_string_crlf().into_bytes()
}

#[cfg(test)]
mod restrict_pcmu_tests {
    use super::*;

    #[test]
    fn restrict_audio_to_pcmu_drops_opus_and_keeps_pcmu() {
        // Linphone (実機 trace) が NGN に送ってきた multi-codec オファ。
        // 96=opus, 97=speex/16k, 98=speex/8k, 0=PCMU, 8=PCMA, 18=G.729,
        // 101=telephone-event/48k, 99/100=telephone-event/16k/8k。
        let linphone_sdp = b"v=0\r\n\
o=iphone 2043 3470 IN IP4 192.168.30.162\r\n\
s=Talk\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
a=rtcp-xr:rcvr-rtt=all:10000 stat-summary=loss,dup,jitt,TTL voip-metrics\r\n\
a=record:off\r\n\
m=audio 54205 RTP/AVP 96 97 98 0 8 18 101 99 100\r\n\
a=rtpmap:96 opus/48000/2\r\n\
a=fmtp:96 useinbandfec=1\r\n\
a=rtpmap:97 speex/16000\r\n\
a=fmtp:97 vbr=on\r\n\
a=rtpmap:98 speex/8000\r\n\
a=fmtp:98 vbr=on\r\n\
a=fmtp:18 annexb=yes\r\n\
a=rtpmap:101 telephone-event/48000\r\n\
a=rtpmap:99 telephone-event/16000\r\n\
a=rtpmap:100 telephone-event/8000\r\n\
a=rtcp:62018\r\n\
a=rtcp-fb:* trr-int 1000\r\n\
a=rtcp-fb:* ccm tmmbr\r\n";

        let restricted = restrict_audio_to_pcmu(linphone_sdp);
        let s = std::str::from_utf8(&restricted).expect("utf8");

        // 必ず残るべきもの
        assert!(s.contains("m=audio 54205 RTP/AVP 0\r\n"), "m= が PCMU only に絞られてない: {s}");
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"), "PCMU rtpmap が無い: {s}");

        // 必ず消えるべきもの
        assert!(!s.to_lowercase().contains("opus"), "opus が残ってる: {s}");
        assert!(!s.to_lowercase().contains("speex"), "speex が残ってる: {s}");
        assert!(!s.to_lowercase().contains("telephone-event"), "telephone-event が残ってる");
        assert!(!s.contains("rtcp-fb"), "rtcp-fb が残ってる");
        assert!(!s.contains("rtcp-xr"), "rtcp-xr が残ってる (セッションレベルのみ削除対象外なら見直し)");
    }

    #[test]
    fn restrict_audio_to_pcmu_passes_through_already_pcmu_only() {
        let pcmu_only = b"v=0\r\n\
o=- 0 0 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=ptime:20\r\n\
a=sendrecv\r\n";
        let restricted = restrict_audio_to_pcmu(pcmu_only);
        let s = std::str::from_utf8(&restricted).expect("utf8");
        assert!(s.contains("m=audio 30000 RTP/AVP 0\r\n"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=ptime:20\r\n"));
        assert!(s.contains("a=sendrecv\r\n"));
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
