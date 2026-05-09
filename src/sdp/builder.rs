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

/// `convert_avp_to_savpf` で必要となる ICE / DTLS パラメータ。
///
/// sabiden は ICE-Lite controlled モードで動作する想定なので、ufrag / pwd /
/// fingerprint は sabiden 側 (str0m) が生成し、ブラウザに渡す。
///
/// 各値は SDP 行末に直接埋め込まれるため、改行や `:` 等のエスケープは行わない。
/// 呼び出し側で str0m が生成した文字列をそのまま渡すこと。
#[derive(Debug, Clone)]
pub struct DtlsIceParams {
    /// `a=ice-ufrag:<v>` の値
    pub ice_ufrag: String,
    /// `a=ice-pwd:<v>` の値
    pub ice_pwd: String,
    /// `a=fingerprint:<algo> <hex-colon>` の値部分。
    /// 例: `"sha-256 5C:F8:64:..."`
    pub fingerprint: String,
    /// `a=setup:<role>` の役割。サーバ側受信時 (NGN→ブラウザ) は `passive`、
    /// 発信側として offer を出すなら `actpass` を渡すと良い。
    pub setup: String,
}

impl DtlsIceParams {
    /// 既定値 (`setup=actpass`)。
    pub fn new(
        ice_ufrag: impl Into<String>,
        ice_pwd: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            ice_ufrag: ice_ufrag.into(),
            ice_pwd: ice_pwd.into(),
            fingerprint: fingerprint.into(),
            setup: "actpass".to_string(),
        }
    }
}

/// NGN の `RTP/AVP` (DTLS なし) SDP を、ブラウザ向け `UDP/TLS/RTP/SAVPF` に
/// 変換する。
///
/// # 用途
///
/// NGN → ブラウザ着信フローで sabiden が SDP 変換器として両側を仲介する際に
/// 使う。NGN から受け取った INVITE の SDP body を本関数でブラウザ用 offer に
/// 加工し、WS シグナリング経由で push する。
///
/// # 行う加工
///
/// - 最初の `m=audio` の `proto` を `UDP/TLS/RTP/SAVPF` に書き換え
/// - 既存の rtpmap / ptime / fmtp / sendrecv 系は保持 (PCMU PT=0 など)
/// - メディアレベル属性の先頭付近に以下を追加 (重複は事前に除去)
///   - `a=rtcp-mux`
///   - `a=ice-ufrag:<ufrag>` / `a=ice-pwd:<pwd>`
///   - `a=fingerprint:<fp>` / `a=setup:<role>`
///   - `a=mid:0`
/// - セッションレベルにブラウザが期待する属性を補う
///   - `a=group:BUNDLE 0`
///   - `a=msid-semantic:WMS *`
///   - `a=ice-options:trickle`
///   - `a=fingerprint:<fp>` (セッションレベルにも複製)
///
/// 元 SDP のパースに失敗したら `Err` を返す。
pub fn convert_avp_to_savpf(sdp_bytes: &[u8], params: &DtlsIceParams) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(sdp_bytes)?;
    let mut sdp = SessionDescription::parse(text)?;

    // ---- セッションレベル属性 ----
    // 既存の同名属性を除去してから追加する。
    sdp.attributes.retain(|a| {
        !matches!(
            a.key(),
            "group" | "msid-semantic" | "ice-options" | "fingerprint"
        )
    });
    sdp.attributes.push(Attribute::Value {
        key: "group".to_string(),
        value: "BUNDLE 0".to_string(),
    });
    sdp.attributes.push(Attribute::Value {
        key: "msid-semantic".to_string(),
        value: "WMS *".to_string(),
    });
    sdp.attributes.push(Attribute::Value {
        key: "ice-options".to_string(),
        value: "trickle".to_string(),
    });
    sdp.attributes.push(Attribute::Value {
        key: "fingerprint".to_string(),
        value: params.fingerprint.clone(),
    });

    // ---- 最初の m=audio をブラウザ向けに加工 ----
    let audio = sdp
        .media
        .iter_mut()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow::anyhow!("m=audio が見つからない"))?;

    audio.protocol = "UDP/TLS/RTP/SAVPF".to_string();

    // 既存の同名属性を除去してから上書きで追加する。
    audio.attributes.retain(|a| {
        !matches!(
            a.key(),
            "rtcp-mux"
                | "ice-ufrag"
                | "ice-pwd"
                | "fingerprint"
                | "setup"
                | "mid"
                | "candidate"
                | "end-of-candidates"
        )
    });
    audio
        .attributes
        .push(Attribute::Property("rtcp-mux".to_string()));
    audio.attributes.push(Attribute::Value {
        key: "ice-ufrag".to_string(),
        value: params.ice_ufrag.clone(),
    });
    audio.attributes.push(Attribute::Value {
        key: "ice-pwd".to_string(),
        value: params.ice_pwd.clone(),
    });
    audio.attributes.push(Attribute::Value {
        key: "fingerprint".to_string(),
        value: params.fingerprint.clone(),
    });
    audio.attributes.push(Attribute::Value {
        key: "setup".to_string(),
        value: params.setup.clone(),
    });
    audio.attributes.push(Attribute::Value {
        key: "mid".to_string(),
        value: "0".to_string(),
    });

    Ok(sdp.to_string_crlf().into_bytes())
}

/// ブラウザ answer (`UDP/TLS/RTP/SAVPF`) を、NGN 向け `RTP/AVP` に変換する。
///
/// # 用途
///
/// ブラウザから受け取った answer を NGN に 200 OK で返す前段で本関数を通す。
/// DTLS-SRTP / ICE 系属性は NGN にとって意味がないので除去し、純粋な
/// G.711 RTP (PT=0 PCMU/8000) として再構成する。
///
/// # 行う加工
///
/// - 最初の `m=audio` の `proto` を `RTP/AVP` に書き換え
/// - メディアレベル属性から以下を除去:
///   `ice-ufrag` / `ice-pwd` / `ice-options` / `fingerprint` / `setup`
///   / `rtcp-mux` / `mid` / `msid` / `ssrc` / `extmap` / `rtcp-fb`
///   / `candidate` / `end-of-candidates` / `bundle-only` / `rtcp`
/// - セッションレベル属性から以下を除去:
///   `group` / `msid-semantic` / `ice-options` / `ice-ufrag` / `ice-pwd`
///   / `fingerprint` / `setup`
/// - rtpmap / ptime / fmtp / sendrecv 等のメディア属性は保持
///
/// 元 SDP のパースに失敗したら `Err` を返す。
pub fn convert_savpf_to_avp(sdp_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(sdp_bytes)?;
    let mut sdp = SessionDescription::parse(text)?;

    // ---- セッションレベル属性のうち WebRTC 専用を除去 ----
    sdp.attributes.retain(|a| {
        !matches!(
            a.key(),
            "group"
                | "msid-semantic"
                | "ice-options"
                | "ice-ufrag"
                | "ice-pwd"
                | "fingerprint"
                | "setup"
        )
    });

    // ---- 最初の m=audio を NGN 向けに加工 ----
    let audio = sdp
        .media
        .iter_mut()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow::anyhow!("m=audio が見つからない"))?;

    audio.protocol = "RTP/AVP".to_string();
    audio.attributes.retain(|a| {
        !matches!(
            a.key(),
            "ice-ufrag"
                | "ice-pwd"
                | "ice-options"
                | "fingerprint"
                | "setup"
                | "rtcp-mux"
                | "rtcp"
                | "mid"
                | "msid"
                | "ssrc"
                | "ssrc-group"
                | "extmap"
                | "rtcp-fb"
                | "candidate"
                | "end-of-candidates"
                | "bundle-only"
                | "rtcp-rsize"
        )
    });

    Ok(sdp.to_string_crlf().into_bytes())
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
        assert!(
            s.contains("m=audio 54205 RTP/AVP 0\r\n"),
            "m= が PCMU only に絞られてない: {s}"
        );
        assert!(
            s.contains("a=rtpmap:0 PCMU/8000\r\n"),
            "PCMU rtpmap が無い: {s}"
        );

        // 必ず消えるべきもの
        assert!(!s.to_lowercase().contains("opus"), "opus が残ってる: {s}");
        assert!(!s.to_lowercase().contains("speex"), "speex が残ってる: {s}");
        assert!(
            !s.to_lowercase().contains("telephone-event"),
            "telephone-event が残ってる"
        );
        assert!(!s.contains("rtcp-fb"), "rtcp-fb が残ってる");
        assert!(
            !s.contains("rtcp-xr"),
            "rtcp-xr が残ってる (セッションレベルのみ削除対象外なら見直し)"
        );
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

    fn make_dtls_params() -> DtlsIceParams {
        let mut p = DtlsIceParams::new(
            "abcd1234",
            "0123456789abcdef0123456789abcdef",
            "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        );
        p.setup = "passive".to_string();
        p
    }

    /// AVP → SAVPF 変換: protocol が書き換わり、必要属性が追加される。
    #[test]
    fn convert_avp_to_savpf_basic() {
        let ngn = b"v=0\r\n\
                    o=- 0 0 IN IP6 2001:db8::1\r\n\
                    s=-\r\n\
                    c=IN IP6 2001:db8::1\r\n\
                    t=0 0\r\n\
                    m=audio 30000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=ptime:20\r\n";
        let params = make_dtls_params();
        let out = convert_avp_to_savpf(ngn, &params).expect("convert");
        let s = std::str::from_utf8(&out).unwrap();

        // m= の proto が書き換わる
        assert!(
            s.contains("m=audio 30000 UDP/TLS/RTP/SAVPF 0\r\n"),
            "proto 書き換え漏れ:\n{}",
            s
        );

        // PCMU rtpmap / ptime は保持
        assert!(s.contains("a=rtpmap:0 PCMU/8000"));
        assert!(s.contains("a=ptime:20"));

        // セッションレベル必須属性
        assert!(s.contains("a=group:BUNDLE 0"));
        assert!(s.contains("a=msid-semantic:WMS *"));
        assert!(s.contains("a=ice-options:trickle"));

        // メディアレベル必須属性
        assert!(s.contains("a=rtcp-mux"));
        assert!(s.contains("a=ice-ufrag:abcd1234"));
        assert!(s.contains("a=ice-pwd:0123456789abcdef0123456789abcdef"));
        assert!(s.contains("a=fingerprint:sha-256 AA:BB:CC"));
        assert!(s.contains("a=setup:passive"));
        assert!(s.contains("a=mid:0"));

        // 結果が再パース可能であること
        let _ = SessionDescription::parse(s).expect("再パース");
    }

    /// AVP→SAVPF 変換は冪等 (二度かけても同名属性が重複しない)。
    #[test]
    fn convert_avp_to_savpf_is_idempotent() {
        let ngn = b"v=0\r\n\
                    o=- 0 0 IN IP4 192.0.2.1\r\n\
                    s=-\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    m=audio 30000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        let params = make_dtls_params();
        let once = convert_avp_to_savpf(ngn, &params).unwrap();
        let twice = convert_avp_to_savpf(&once, &params).unwrap();
        let s = std::str::from_utf8(&twice).unwrap();

        // 同名属性は 1 回ずつのみ出現する
        let count = |k: &str| s.matches(k).count();
        assert_eq!(count("a=ice-ufrag:"), 1);
        assert_eq!(count("a=ice-pwd:"), 1);
        assert_eq!(count("a=setup:"), 1);
        assert_eq!(count("a=rtcp-mux"), 1);
        assert_eq!(count("a=mid:"), 1);
        assert_eq!(count("a=group:"), 1);
        assert_eq!(count("a=msid-semantic:"), 1);
        assert_eq!(count("a=ice-options:"), 1);
    }

    /// SAVPF → AVP 変換: protocol が戻り、WebRTC 専用属性が消える。
    #[test]
    fn convert_savpf_to_avp_strips_webrtc_attrs() {
        let browser = b"v=0\r\n\
                        o=mozilla 1 0 IN IP4 0.0.0.0\r\n\
                        s=-\r\n\
                        t=0 0\r\n\
                        a=group:BUNDLE 0\r\n\
                        a=msid-semantic:WMS *\r\n\
                        a=ice-options:trickle\r\n\
                        a=fingerprint:sha-256 AA:BB:CC:DD\r\n\
                        m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
                        c=IN IP4 0.0.0.0\r\n\
                        a=rtpmap:0 PCMU/8000\r\n\
                        a=ptime:20\r\n\
                        a=sendrecv\r\n\
                        a=ice-ufrag:wxyz\r\n\
                        a=ice-pwd:browserpwd1234567890browserpwd12\r\n\
                        a=fingerprint:sha-256 11:22:33:44\r\n\
                        a=setup:active\r\n\
                        a=mid:0\r\n\
                        a=rtcp-mux\r\n\
                        a=rtcp:9 IN IP4 0.0.0.0\r\n\
                        a=ssrc:12345 cname:foo\r\n\
                        a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n";
        let out = convert_savpf_to_avp(browser).expect("convert");
        let s = std::str::from_utf8(&out).unwrap();

        // proto が AVP に戻る
        assert!(
            s.contains("m=audio 9 RTP/AVP 0\r\n"),
            "proto 書き換え漏れ:\n{}",
            s
        );

        // WebRTC 専用属性は除去される
        for forbidden in [
            "a=ice-ufrag",
            "a=ice-pwd",
            "a=ice-options",
            "a=fingerprint",
            "a=setup",
            "a=rtcp-mux",
            "a=mid",
            "a=ssrc",
            "a=extmap",
            "a=group",
            "a=msid-semantic",
            "a=rtcp:",
        ] {
            assert!(!s.contains(forbidden), "{} が残っている:\n{}", forbidden, s);
        }

        // 一方で rtpmap / ptime / sendrecv は保持される
        assert!(s.contains("a=rtpmap:0 PCMU/8000"));
        assert!(s.contains("a=ptime:20"));
        assert!(s.contains("a=sendrecv"));

        // 再パース可能
        let _ = SessionDescription::parse(s).expect("再パース");
    }

    /// AVP → SAVPF → AVP のラウンドトリップで PCMU 構造が保たれる。
    #[test]
    fn convert_round_trip_preserves_pcmu() {
        let ngn = b"v=0\r\n\
                    o=- 0 0 IN IP4 192.0.2.1\r\n\
                    s=-\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    m=audio 30000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=ptime:20\r\n\
                    a=sendrecv\r\n";
        let params = make_dtls_params();
        let mid = convert_avp_to_savpf(ngn, &params).unwrap();
        let back = convert_savpf_to_avp(&mid).unwrap();
        let s = std::str::from_utf8(&back).unwrap();
        let parsed = SessionDescription::parse(s).expect("parse");
        assert_eq!(parsed.media[0].protocol, "RTP/AVP");
        assert_eq!(parsed.media[0].formats, vec!["0"]);
        assert!(parsed.find_rtpmap(0).is_some());
        assert!(s.contains("a=ptime:20"));
        assert!(s.contains("a=sendrecv"));
    }

    /// m=audio が無い SDP は両関数とも Err になる。
    #[test]
    fn convert_no_audio_errors() {
        let bad = b"v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\nm=video 30000 RTP/AVP 96\r\n";
        let params = make_dtls_params();
        assert!(convert_avp_to_savpf(bad, &params).is_err());
        assert!(convert_savpf_to_avp(bad).is_err());
    }
}
