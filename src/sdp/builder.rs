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
///
/// `ssrc` / `cname` / `msid_*` は WebRTC ブラウザが
/// [RFC 5576 §4.1](https://www.rfc-editor.org/rfc/rfc5576#section-4.1) /
/// [RFC 8830 §2](https://www.rfc-editor.org/rfc/rfc8830#section-2) /
/// [W3C webrtc-pc §5.7] に基づき RTP 受信側 track binding を行うため必要。
/// 未指定 (`None`) なら [`DtlsIceParams::ssrc_or_default`] / [`Self::cname_or_default`]
/// 等が `o=` の session-id 由来の安定値を返す。
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
    /// 任意の SSRC (RFC 5576 §4.1 `a=ssrc:<ssrc-id>`)。 未指定なら
    /// session-id 由来のデフォルトを使う。
    pub ssrc: Option<u32>,
    /// 任意の CNAME (RFC 5576 §6.1 `a=ssrc:<id> cname:<cname>`)。
    /// 未指定なら `"sabiden"` 固定文字列。
    pub cname: Option<String>,
    /// 任意の MediaStream ID (RFC 8830 §2 `a=msid:<stream-id> <track-id>`)。
    /// 未指定なら `"sabiden"`。
    pub msid_stream_id: Option<String>,
    /// 任意の MediaStreamTrack ID (RFC 8830 §2)。
    /// 未指定なら `"audio0"` (`a=mid:0` と整合)。
    pub msid_track_id: Option<String>,
}

impl DtlsIceParams {
    /// 既定値 (`setup=actpass`、 ssrc / cname / msid 未指定)。
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
            ssrc: None,
            cname: None,
            msid_stream_id: None,
            msid_track_id: None,
        }
    }

    /// SSRC を上書きするビルダ (RFC 5576 §4.1)。
    pub fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = Some(ssrc);
        self
    }

    /// CNAME を上書きするビルダ (RFC 5576 §6.1 / RFC 7022)。
    pub fn with_cname(mut self, cname: impl Into<String>) -> Self {
        self.cname = Some(cname.into());
        self
    }

    /// MediaStream / MediaStreamTrack ID (RFC 8830 §2) を上書きするビルダ。
    pub fn with_msid(mut self, stream_id: impl Into<String>, track_id: impl Into<String>) -> Self {
        self.msid_stream_id = Some(stream_id.into());
        self.msid_track_id = Some(track_id.into());
        self
    }

    /// SSRC が指定されていればそれを、無ければ `fallback_seed` 由来の安定値を返す。
    /// RFC 5576 §4.1: SSRC は 32-bit unsigned。 0 は予約値なので避ける。
    fn ssrc_or_default(&self, fallback_seed: u64) -> u32 {
        if let Some(s) = self.ssrc {
            return s;
        }
        // RFC 3550 §8.1: SSRC は衝突回避のため擬似乱数推奨だが、
        // sabiden では呼の単位で十分に分散すれば良いので session-id seed から導出。
        // 0 は予約値なので 1..=u32::MAX に丸める。
        let s = (fallback_seed ^ (fallback_seed >> 32)) as u32;
        if s == 0 {
            1
        } else {
            s
        }
    }

    fn cname_or_default(&self) -> &str {
        // RFC 7022 §3.1: CNAME はセッション内で安定で、ホスト識別ではなく
        // 短期セッション識別で良い。 sabiden は固定文字列で十分。
        self.cname.as_deref().unwrap_or("sabiden")
    }

    fn msid_stream_id_or_default(&self) -> &str {
        self.msid_stream_id.as_deref().unwrap_or("sabiden")
    }

    fn msid_track_id_or_default(&self) -> &str {
        // `a=mid:0` と紐づけて `audio0` 既定 (RFC 8830 §2 例示風)。
        self.msid_track_id.as_deref().unwrap_or("audio0")
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
/// - 既存の rtpmap / ptime / fmtp 系は保持 (PCMU PT=0 など)
/// - メディアレベル属性の先頭付近に以下を追加 (重複は事前に除去)
///   - `a=rtcp-mux`
///   - `a=rtcp:<port>` ([RFC 3605 §2.1](https://www.rfc-editor.org/rfc/rfc3605#section-2.1):
///     RTCP port を明示。 rtcp-mux 併用でも RFC 3605 §2.1 は冪等で問題なし)
///   - `a=ice-ufrag:<ufrag>` / `a=ice-pwd:<pwd>`
///   - `a=fingerprint:<fp>` / `a=setup:<role>`
///   - `a=mid:0`
///   - `a=sendrecv` ([RFC 4566 §6](https://www.rfc-editor.org/rfc/rfc4566#section-6):
///     direction が無いと sendrecv 既定だがブラウザは明示を期待する)
///   - `a=msid:<stream-id> <track-id>` ([RFC 8830 §2](https://www.rfc-editor.org/rfc/rfc8830#section-2),
///     [W3C webrtc-pc §5.8.2](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver):
///     ブラウザ側 `RTCRtpReceiver` の track binding に必須)
///   - `a=ssrc:<ssrc> cname:<cname>` /
///     `a=ssrc:<ssrc> msid:<stream-id> <track-id>`
///     ([RFC 5576 §4.1 / §6.1](https://www.rfc-editor.org/rfc/rfc5576):
///     SSRC ⇔ Stream の binding)
/// - セッションレベルにブラウザが期待する属性を補う
///   - `a=group:BUNDLE 0` ([RFC 8843 §7.2](https://www.rfc-editor.org/rfc/rfc8843#section-7.2))
///   - `a=msid-semantic:WMS *` ([RFC 8830 §2](https://www.rfc-editor.org/rfc/rfc8830#section-2))
///   - `a=ice-options:trickle` ([RFC 8838 §11](https://www.rfc-editor.org/rfc/rfc8838#section-11):
///     trickle ICE option registration。 RFC 8840 は SIP usage 専用)
///   - `a=fingerprint:<fp>` (セッションレベルにも複製)
///
/// JSEP ([RFC 8829 §5.2.1](https://www.rfc-editor.org/rfc/rfc8829#section-5.2.1)) に
/// 従い、 ブラウザの `setRemoteDescription()` が破棄なく受理できる SDP を構築する。
///
/// # SSRC / CNAME / MSID
///
/// `params.ssrc` / `cname` / `msid_stream_id` / `msid_track_id` が `None` の
/// 場合は `o=` の session-id 由来の安定値 (CNAME は `"sabiden"` 固定) を補う。
/// 既存の `a=ssrc:` 行が SDP に含まれていれば一旦削除して上書きする (冪等性)。
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

    // SSRC / msid 既定値の解決。 session-id を seed にして SSRC を導出するので
    // 同一セッション内で再変換しても同値になる (冪等性確保、 RFC 5576 §4.1)。
    let ssrc = params.ssrc_or_default(sdp.origin.session_id);
    let cname = params.cname_or_default().to_string();
    let msid_stream = params.msid_stream_id_or_default().to_string();
    let msid_track = params.msid_track_id_or_default().to_string();

    // ---- 最初の m=audio をブラウザ向けに加工 ----
    let audio = sdp
        .media
        .iter_mut()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow::anyhow!("m=audio が見つからない"))?;

    let audio_port = audio.port;
    audio.protocol = "UDP/TLS/RTP/SAVPF".to_string();

    // 既存の同名属性を除去してから上書きで追加する。
    // direction (sendrecv/sendonly/recvonly/inactive) は元 SDP の意図を壊さない
    // ため retain では消さず、 後段で「無ければ補う」方針にする (RFC 4566 §6)。
    audio.attributes.retain(|a| {
        !matches!(
            a.key(),
            "rtcp-mux"
                | "rtcp"
                | "ice-ufrag"
                | "ice-pwd"
                | "fingerprint"
                | "setup"
                | "mid"
                | "msid"
                | "ssrc"
                | "ssrc-group"
                | "candidate"
                | "end-of-candidates"
        )
    });
    audio
        .attributes
        .push(Attribute::Property("rtcp-mux".to_string()));
    // RFC 3605 §2.1: `a=rtcp:<port> [<nettype> <addrtype> <addr>]`。
    // rtcp-mux 環境でも値は audio の port と同一を提示する (互換性のため)。
    audio.attributes.push(Attribute::Value {
        key: "rtcp".to_string(),
        value: audio_port.to_string(),
    });
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

    // RFC 4566 §6: direction 属性 (sendrecv/sendonly/recvonly/inactive) が
    // 既に存在すればそれを尊重 (NGN 由来 SDP に sendrecv が乗っているケース)。
    // 無ければブラウザ向け既定として `sendrecv` を補う (W3C webrtc-pc §5.7
    // のデフォルト)。
    let has_direction = audio
        .attributes
        .iter()
        .any(|a| matches!(a.key(), "sendrecv" | "sendonly" | "recvonly" | "inactive"));
    if !has_direction {
        audio
            .attributes
            .push(Attribute::Property("sendrecv".to_string()));
    }

    // RFC 8830 §2 / W3C webrtc-pc §5.7:
    // `a=msid:<MediaStream-id> <MediaStreamTrack-id>` を 1 行追加する。
    audio.attributes.push(Attribute::Value {
        key: "msid".to_string(),
        value: format!("{} {}", msid_stream, msid_track),
    });

    // RFC 5576 §6.1: `a=ssrc:<ssrc-id> cname:<cname>` (CNAME は必須)。
    // §4.1: `a=ssrc:<ssrc-id> <attribute>:<value>` 形式で複数 attribute を出す。
    // ブラウザは msid を ssrc-level にも要求するので両方出す (互換性のため
    // session-level msid と二重化、 W3C unified-plan)。
    audio.attributes.push(Attribute::Value {
        key: "ssrc".to_string(),
        value: format!("{} cname:{}", ssrc, cname),
    });
    audio.attributes.push(Attribute::Value {
        key: "ssrc".to_string(),
        value: format!("{} msid:{} {}", ssrc, msid_stream, msid_track),
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
    // ブラウザ生成 SDP は `o=- <huge-i64> 2 ...` のように 64-bit session-id を
    // 出すが、NGN P-CSCF はおそらく 32-bit 値を期待しており overflow / 内部
    // collision で 486 Busy Here を返す。 RFC 4566 §5.2 は uint64 を許すが、
    // Asterisk 実機は小さい NTP 風数値 (例 397958033) を使っており確認済。
    // 安全側で UNIX epoch 秒を採用 (32-bit に収まる、 単調増加、 衝突可能性低)。
    //
    // RFC 4566 §5.2: session-id は「session のグローバル一意 ID」であり、
    // 同一セッション内 (= 同一 Call-ID 内の re-INVITE 連) では **不変** で
    // あるべき。 入力 SDP の session-id が 32-bit に収まるなら踏襲し、 64-bit
    // (= ブラウザ生成等) なら NGN 互換のため UNIX epoch 秒に置換する。
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if sdp.origin.session_id > u32::MAX as u64 {
        sdp.origin.session_id = now_secs;
    }
    // RFC 3264 §8 (Modifying the Session):
    //   "For each offer or answer, the session version in the origin field
    //    MUST increment by one if the session description changes."
    // 本関数は c= / m= port / o= IP / o= username を必ず書換える (= session
    // description が変わる) ので、 sess-version は入力値 + 1 する義務がある。
    // `wrapping_add` で u64 上限 (RFC 4566 §5.2 は uint64) の循環を安全に扱う。
    sdp.origin.session_version = sdp.origin.session_version.wrapping_add(1);
    // セッションレベル c= は必ず sabiden を指すようにする
    sdp.connection = Some(Connection { address: addr });

    // 最初の audio media を sabiden 側に書き換える。
    // メディアレベル `c=` は **削除** する。 session-level `c=` を上で `addr` に
    // 強制セット済なので、 media-level に同値の `c=` を残すと NGN P-CSCF が
    // 重複セット連結した形で session を判定して 500 Server Internal Error を
    // 返す事例を実機で確認済 (2026-05-10、 Firefox 由来 SDP)。 RFC 4566 §5.7
    // 上は許容だが、 NGN 実機が許容しないので `audio.connection = None` で
    // 揃える (Asterisk pcap も session-level のみで media-level c= は出さない)。
    if let Some(audio) = sdp.media.iter_mut().find(|m| m.media == "audio") {
        audio.port = port;
        audio.connection = None;
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
                matches!(
                    p.as_str(),
                    "rtcp-mux"
                        | "ice-lite"
                        | "rtcp-rsize"
                        | "extmap-allow-mixed"
                        | "end-of-candidates"
                        | "bundle-only"
                )
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

    /// Issue #69 / RFC 4733 §3.2: PCMU + telephone-event を残す変種では
    /// PT=0 と PT=101 だけが残り、`a=fmtp:101 0-15` が補完される。
    #[test]
    fn rfc4733_3_2_restrict_audio_to_pcmu_with_dtmf_keeps_pt_0_and_101() {
        // Linphone から来る multi-codec オファに PT=101 telephone-event/8000 が
        // 既に乗っているケース。`fmtp:101 0-16` のように DTMF 範囲外まで含む
        // 値が来ても、フィルタ後の fmtp はそのまま (RFC 4733 §3.2 の `0-15` を
        // 越える dynamic 範囲を許容する UA はそのまま素通しでよい)。
        let linphone_sdp = b"v=0\r\n\
o=iphone 1 1 IN IP4 192.168.30.162\r\n\
s=Talk\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 54205 RTP/AVP 96 0 8 101\r\n\
a=rtpmap:96 opus/48000/2\r\n\
a=fmtp:96 useinbandfec=1\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-15\r\n";

        let restricted = restrict_audio_to_pcmu_with_dtmf(linphone_sdp);
        let s = std::str::from_utf8(&restricted).expect("utf8");

        // m= 行に PT=0 と PT=101 が両方残る
        assert!(
            s.contains("m=audio 54205 RTP/AVP 0 101\r\n"),
            "PT 0 + 101 のみであるべき: {s}"
        );
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=rtpmap:101 telephone-event/8000\r\n"));
        assert!(s.contains("a=fmtp:101 0-15\r\n"));

        // Opus / PCMA は消える
        assert!(!s.to_lowercase().contains("opus"), "opus が残ってる: {s}");
        assert!(!s.contains("PCMA"), "PCMA が残ってる: {s}");
    }

    /// Issue #69: PT=101 が **48000Hz** で来た場合 (Linphone デフォ) は破棄し、
    /// 8000Hz 用 rtpmap を補う。NGN audio は 8kHz 固定のため 48k だと整合しない。
    #[test]
    fn rfc4733_3_2_restrict_audio_drops_48khz_telephone_event_and_inserts_8khz() {
        let sdp = b"v=0\r\n\
o=- 1 1 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 54205 RTP/AVP 0 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:101 telephone-event/48000\r\n";

        let restricted = restrict_audio_to_pcmu_with_dtmf(sdp);
        let s = std::str::from_utf8(&restricted).expect("utf8");
        assert!(
            !s.contains("telephone-event/48000"),
            "48k は捨てるべき: {s}"
        );
        assert!(s.contains("a=rtpmap:101 telephone-event/8000\r\n"));
        assert!(s.contains("a=fmtp:101 0-15\r\n"));
    }

    /// Issue #69: PT=101 が SDP に無くても (PCMU only オファ) 補完される。
    #[test]
    fn rfc4733_3_2_restrict_audio_inserts_dtmf_into_pcmu_only_offer() {
        let pcmu_only = b"v=0\r\n\
o=- 0 0 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=ptime:20\r\n";
        let restricted = restrict_audio_to_pcmu_with_dtmf(pcmu_only);
        let s = std::str::from_utf8(&restricted).expect("utf8");
        assert!(s.contains("m=audio 30000 RTP/AVP 0 101\r\n"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=rtpmap:101 telephone-event/8000\r\n"));
        assert!(s.contains("a=fmtp:101 0-15\r\n"));
        assert!(s.contains("a=ptime:20\r\n"));
    }

    /// `pcmu_offer_with_dtmf` ヘルパが PT=0 + PT=101 を提示する SDP を生成する。
    #[test]
    fn rfc4733_3_2_pcmu_offer_with_dtmf_emits_telephone_event() {
        let addr: IpAddr = "192.168.1.10".parse().unwrap();
        let offer = SessionDescription::pcmu_offer_with_dtmf(addr, 30000, 20);
        let s = offer.to_string_crlf();
        assert!(s.contains("m=audio 30000 RTP/AVP 0 101\r\n"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=rtpmap:101 telephone-event/8000\r\n"));
        assert!(s.contains("a=fmtp:101 0-15\r\n"));
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

/// DTMF 用 telephone-event の RTP payload type 番号 (動的だが de-facto 101)。
///
/// SDP の `a=rtpmap:101 telephone-event/8000` で合意される (RFC 4733 §3.2)。
/// sabiden は B2BUA として両レッグに同一値を提示する。
pub const DTMF_PAYLOAD_TYPE: u8 = 101;

impl SessionDescription {
    /// NGN / SIP UAC で典型的に使う G.711 μ-law (PCMU) オファーを作る。
    ///
    /// - `addr`: ローカル IP (c= と o= に使う)
    /// - `port`: RTP ポート
    /// - `ptime_ms`: パケット間隔 (ミリ秒)。NGN では 20 が一般的。
    pub fn pcmu_offer(addr: IpAddr, port: u16, ptime_ms: u32) -> Self {
        // RFC 4566 §5.2 (Origin): "<sess-id> is a numeric string such that the
        // tuple of <username>, <sess-id>, <nettype>, <addrtype>, and
        // <unicast-address> forms a globally unique identifier for the
        // session." 即ち、 同一 sabiden プロセスが複数 INVITE を出すケースで
        // sess-id が全通話で同一になるとセッション識別性を喪う。 RFC 同節
        // recommends NTP timestamp。 ここでは UNIX epoch 秒を使う
        // (Asterisk 実機の `o=- 397958033 ...` 風: `docs/asterisk-real-invite.md`
        // §2、 `rewrite_rtp_endpoint` (本ファイル) と同パターン)。
        //
        // RFC 3264 §8 (Modifying the Session): "the version number is
        // incremented each time the session description is changed." 初回
        // オファーでは sess-id == sess-version で始め、 後続の SDP rewrite
        // (e.g. Re-INVITE) で +1 する運用 (Issue #77)。
        let session_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
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

    /// `pcmu_offer` に **RFC 4733 telephone-event (DTMF)** PT=101 を追加した
    /// オファー。NGN レッグでも内線レッグでも DTMF in-band 中継するための
    /// SDP を発行する用途。
    ///
    /// - `m=audio <port> RTP/AVP 0 101`
    /// - `a=rtpmap:0 PCMU/8000`
    /// - `a=rtpmap:101 telephone-event/8000`
    /// - `a=fmtp:101 0-15` (RFC 4733 §3.2: 0-9, *, #, A-D の全 DTMF event)
    /// - `a=ptime:<ptime_ms>`
    pub fn pcmu_offer_with_dtmf(addr: IpAddr, port: u16, ptime_ms: u32) -> Self {
        let mut sdp = Self::pcmu_offer(addr, port, ptime_ms);
        let media = &mut sdp.media[0];
        media.formats.push(DTMF_PAYLOAD_TYPE.to_string());
        media.attributes.push(Attribute::Value {
            key: "rtpmap".to_string(),
            value: format!("{} telephone-event/8000", DTMF_PAYLOAD_TYPE),
        });
        media.attributes.push(Attribute::Value {
            key: "fmtp".to_string(),
            // RFC 4733 §3.2: 0-15 を全許容するのが最も互換性が高い。
            value: format!("{} 0-15", DTMF_PAYLOAD_TYPE),
        });
        sdp
    }
}

/// audio メディアを **G.711 μ-law (PT 0) + telephone-event (PT 101)** に絞った
/// SDP を返す。`restrict_audio_to_pcmu` の DTMF 対応版。
///
/// NGN は PCMU (PT 0) しか音声として受け入れないが、telephone-event (RFC 4733)
/// は in-band DTMF 中継のため一緒に提示してよい (NGN 側の Asterisk 等の
/// SIP プロキシは telephone-event を素通しする)。Linphone / Zoiper 等が
/// 送ってくる multi-codec オファ (Opus / Speex / G.729 等) を素通しすると
/// 488 で蹴られるが、PCMU + telephone-event だけ残せば 200 OK が返る。
///
/// 動作:
/// - audio media の `formats` を `["0", "101"]` に置換
/// - rtpmap / fmtp 系のうち payload_type=0 / 101 以外を削除
/// - WebRTC/DTLS-SRTP/ICE 由来属性 (`restrict_audio_to_pcmu` と同じセット) を削除
/// - PCMU の `a=rtpmap:0 PCMU/8000` が無ければ補う
/// - telephone-event の `a=rtpmap:101 telephone-event/8000` と
///   `a=fmtp:101 0-15` が無ければ補う (RFC 4733 §3.2)
///
/// パース不能ならそのまま返す (ベストエフォート)。
pub fn restrict_audio_to_pcmu_with_dtmf(sdp_bytes: &[u8]) -> Vec<u8> {
    let text = match std::str::from_utf8(sdp_bytes) {
        Ok(s) => s,
        Err(_) => return sdp_bytes.to_vec(),
    };
    let mut sdp = match SessionDescription::parse(text) {
        Ok(s) => s,
        Err(_) => return sdp_bytes.to_vec(),
    };

    // 削除対象: NGN が解釈しない WebRTC / DTLS-SRTP / ICE / multiplex 系。
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
                matches!(
                    p.as_str(),
                    "rtcp-mux"
                        | "ice-lite"
                        | "rtcp-rsize"
                        | "extmap-allow-mixed"
                        | "end-of-candidates"
                        | "bundle-only"
                )
            }
        }
    }
    sdp.attributes.retain(|a| !is_unsupported_by_ngn(a));

    if let Some(audio) = sdp.media.iter_mut().find(|m| m.media == "audio") {
        let dtmf_pt_str = DTMF_PAYLOAD_TYPE.to_string();
        audio.formats = vec!["0".to_string(), dtmf_pt_str.clone()];

        let mut have_pcmu_rtpmap = false;
        let mut have_dtmf_rtpmap = false;
        let mut have_dtmf_fmtp = false;
        audio.attributes.retain(|a| {
            if is_unsupported_by_ngn(a) {
                return false;
            }
            match a {
                Attribute::Value { key, value } => {
                    let pt_of_value = || {
                        value
                            .split_whitespace()
                            .next()
                            .and_then(|p| p.parse::<u8>().ok())
                    };
                    match key.as_str() {
                        "rtpmap" => match pt_of_value() {
                            Some(0) => {
                                have_pcmu_rtpmap = true;
                                true
                            }
                            Some(pt) if pt == DTMF_PAYLOAD_TYPE => {
                                // 既存の telephone-event/8000 のみ採用 (48000 等は破棄)
                                let is_8khz = value.contains("/8000");
                                if is_8khz {
                                    have_dtmf_rtpmap = true;
                                    true
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        },
                        "fmtp" => match pt_of_value() {
                            Some(0) => true,
                            Some(pt) if pt == DTMF_PAYLOAD_TYPE => {
                                have_dtmf_fmtp = true;
                                true
                            }
                            _ => false,
                        },
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
        if !have_dtmf_rtpmap {
            audio.attributes.push(Attribute::Value {
                key: "rtpmap".to_string(),
                value: format!("{} telephone-event/8000", DTMF_PAYLOAD_TYPE),
            });
        }
        if !have_dtmf_fmtp {
            audio.attributes.push(Attribute::Value {
                key: "fmtp".to_string(),
                value: format!("{} 0-15", DTMF_PAYLOAD_TYPE),
            });
        }
    }
    sdp.to_string_crlf().into_bytes()
}

/// Issue #108 / RFC 3264 §6.1: NGN へ返す **answer の payload type を NGN offer の
/// subset に強制制限** する。
///
/// `restrict_audio_to_pcmu` / `restrict_audio_to_pcmu_with_dtmf` は ext_answer 由来の
/// PT を `[0]` / `[0, 101]` に絞り込むが、 NGN offer 側がそれらの PT を提示して
/// いない場合 (例: NGN offer が `m=audio ... RTP/AVP 8` で PCMU 非提示)、
/// 結果は RFC 3264 §6.1 の subset 規則に違反する:
///
/// > RFC 3264 §6.1: "For each "m=" line in the offer, the answerer MUST be prepared
/// > to receive media that is described by the media format codes listed in the
/// > offer.  A reasonable answer is to accept a subset of the formats."
///
/// `m=` 行の formats は **offer の formats の真部分集合 (= subset)** でなければ
/// ならない (RFC 3264 §6.1 / §6).
///
/// 本関数は **NGN offer (incoming INVITE の body) を一次情報** として PT 集合を
/// 決定する:
///
/// - PCMU (PT 0): NGN offer の `m=audio` formats に **0 が含まれる場合のみ**
///   answer に乗せる。 含まれない場合は `Err` を返す。 呼出側は bridge 起動
///   失敗扱いで処理する (現状の `start_bridge_for_inbound` 呼出側は 502 Bad
///   Gateway で呼を放棄する。 RFC 3261 §13.3.1.2 / RFC 3264 §6 "no common codec"
///   としては 488 Not Acceptable Here がより semantic に近いが、 呼出側
///   fallback 経路は別 issue で扱う)。
/// - telephone-event (PT 101): NGN offer 側が `a=rtpmap:101 telephone-event/...`
///   と `m=` formats に 101 を **両方** 提示している場合のみ answer に乗せる。
///   どちらか欠ければ PT 0 のみ。
///
/// PT 集合を決めたら、 ext_answer をベースに既存の `restrict_audio_to_pcmu` /
/// `restrict_audio_to_pcmu_with_dtmf` を適切に呼んで answer を整形する
/// (ptime / `a=` 属性は ext_answer 由来を活かす、 RFC 3264 §6 の素直な答え方)。
///
/// # 引数
///
/// - `ngn_offer`: NGN P-CSCF から到着した INVITE の SDP body。 UTF-8 でない場合は
///   `Err` (RFC 3261 §7.1: SIP body は ASCII / UTF-8 想定)。
/// - `ext_answer`: 内線 (SIP / WebRTC) が返した 200 OK 由来の SDP body。
///
/// # 戻り値
///
/// 整形済 answer SDP の byte 列。 PT 0 が NGN offer に無い等で交渉不能なら `Err`。
pub fn restrict_answer_to_ngn_offer_subset(
    ngn_offer: &[u8],
    ext_answer: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let offer_audio = parse_audio_formats_and_rtpmap(ngn_offer)?;

    // RFC 3264 §6.1: answer formats は offer formats の subset。 PCMU (PT 0) が
    // NGN offer の m=audio formats に無ければ「共通 codec 無し」状態であり、
    // 呼出側で 488 Not Acceptable Here を返す。 sabiden は NGN 直収で PCMU のみ
    // サポートする (`docs/asterisk-real-invite.md` §2)。
    if !offer_audio.formats.contains(&PCMU_PAYLOAD_TYPE.to_string()) {
        return Err(anyhow::anyhow!(
            "RFC 3264 §6.1: NGN offer に PCMU (PT {}) が含まれないため answer subset 不能 (formats={:?})",
            PCMU_PAYLOAD_TYPE,
            offer_audio.formats
        ));
    }

    // telephone-event (PT 101) は NGN offer が m= formats と a=rtpmap:101 の両方で
    // 提示している場合のみ answer に乗せる (RFC 4733 §2.4.1: rtpmap が dynamic PT の
    // 意味付け、 RFC 3264 §6.1: subset 規則)。 NGN 実機の Asterisk pcap
    // (`docs/asterisk-real-invite.md` §3) では `m=audio ... RTP/AVP 0 101` +
    // `a=rtpmap:101 telephone-event/8000` の両方が乗るので、 通常パスでは PT 101
    // 維持。
    let offer_has_dtmf_in_formats = offer_audio.formats.contains(&DTMF_PAYLOAD_TYPE.to_string());
    let allow_dtmf = offer_has_dtmf_in_formats && offer_audio.has_telephone_event_rtpmap;

    if allow_dtmf {
        Ok(restrict_audio_to_pcmu_with_dtmf(ext_answer))
    } else {
        Ok(restrict_audio_to_pcmu(ext_answer))
    }
}

/// G.711 μ-law の静的 RTP payload type 番号 (RFC 3551 §6, AVP profile)。
const PCMU_PAYLOAD_TYPE: u8 = 0;

/// `parse_audio_formats_and_rtpmap` の戻り値: NGN offer の `m=audio` formats 一覧
/// と、 `a=rtpmap` 行に `telephone-event` が宣言されているか。
#[derive(Debug)]
struct AudioOfferSummary {
    formats: Vec<String>,
    has_telephone_event_rtpmap: bool,
}

/// 受信 SDP の最初の `m=audio` から formats 一覧 + telephone-event rtpmap 有無を
/// 抽出する。 RFC 3264 §6.1 subset 判定の一次情報源。
///
/// パース不能 (UTF-8 / SDP 文法エラー / m=audio 不在) は `Err` を返す。
fn parse_audio_formats_and_rtpmap(sdp_bytes: &[u8]) -> anyhow::Result<AudioOfferSummary> {
    let text = std::str::from_utf8(sdp_bytes)
        .map_err(|e| anyhow::anyhow!("SDP が UTF-8 でない: {}", e))?;
    let sdp = SessionDescription::parse(text)?;
    let audio = sdp
        .media
        .iter()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow::anyhow!("SDP に m=audio 行が無い"))?;
    let has_telephone_event_rtpmap = audio.attributes.iter().any(|a| match a {
        Attribute::Value { key, value } => {
            key == "rtpmap" && value.to_ascii_lowercase().contains("telephone-event")
        }
        Attribute::Property(_) => false,
    });
    Ok(AudioOfferSummary {
        formats: audio.formats.clone(),
        has_telephone_event_rtpmap,
    })
}

#[cfg(test)]
mod restrict_answer_subset_tests {
    use super::*;

    /// RFC 3264 §6.1: NGN offer = `[0, 101]` + `a=rtpmap:101 telephone-event/8000`、
    /// ext_answer = `[0, 8, 101]` (PCMA 混在) のとき、 answer は **NGN offer の
    /// subset** に絞られ `[0, 101]` で出力される (PCMA は破棄、 DTMF は維持)。
    /// 実機 Asterisk pcap (`docs/asterisk-real-invite.md` §3) と整合する典型形。
    #[test]
    fn rfc3264_6_1_offer_pcmu_dtmf_answer_keeps_pcmu_dtmf_subset() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0 101\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=rtpmap:101 telephone-event/8000\r\n\
                          a=fmtp:101 0-15\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0 8 101\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=rtpmap:8 PCMA/8000\r\n\
                           a=rtpmap:101 telephone-event/8000\r\n\
                           a=fmtp:101 0-15\r\n";

        let restricted =
            restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer).expect("subset 計算成功");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(
            s.contains("m=audio 40000 RTP/AVP 0 101\r\n"),
            "answer は NGN offer subset (= [0, 101]) に絞り込まれる: {s}"
        );
        assert!(!s.contains("PCMA"), "PCMA は NGN offer に無いので破棄: {s}");
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=rtpmap:101 telephone-event/8000\r\n"));
    }

    /// RFC 3264 §6.1: NGN offer = `[0]` のみ (telephone-event 非提示)、
    /// ext_answer = `[0, 101]` (内線が DTMF 付き) のとき、 answer は **PT 0 のみ**
    /// に絞られる (PT 101 を offer subset 外として除外する)。
    /// PR #149 / Issue #149 と同じ挙動を新 helper でも保証する回帰防止。
    #[test]
    fn rfc3264_6_1_offer_pcmu_only_answer_drops_dtmf() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0 101\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=rtpmap:101 telephone-event/8000\r\n\
                           a=fmtp:101 0-15\r\n";

        let restricted = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect("subset 計算成功 (PCMU 共通)");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(
            s.contains("m=audio 40000 RTP/AVP 0\r\n"),
            "answer は NGN offer subset (= [0]) に絞り込まれる: {s}"
        );
        assert!(
            !s.to_lowercase().contains("telephone-event"),
            "PT 101 は NGN offer に無いので破棄 (RFC 3264 §6.1 違反防止): {s}"
        );
    }

    /// RFC 3264 §6.1: NGN offer に PCMU (PT 0) が無ければ「共通 codec 無し」状態。
    /// `Err` を返し、 呼出側で 488 Not Acceptable Here (RFC 3261 §13.3.1.2) を
    /// 発行する責務とする。 sabiden は NGN 直収で PCMU only を前提
    /// (`docs/asterisk-real-invite.md` §2)。
    #[test]
    fn rfc3264_6_1_offer_without_pcmu_errors() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0\r\n\
                           a=rtpmap:0 PCMU/8000\r\n";

        let err = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect_err("PCMU 非提示は err");
        let msg = format!("{}", err);
        assert!(
            msg.contains("PCMU") && msg.contains("§6.1"),
            "エラーは subset 規則違反を示す: {msg}"
        );
    }

    /// RFC 3264 §6.1: NGN offer の `m=` formats に PT 101 が並んでいても、
    /// `a=rtpmap:101 telephone-event/...` が無い (= encoding 不明) なら、
    /// answer に PT 101 を乗せるのは subset 規則に反する (PT が同じでも
    /// encoding が違えば別 codec)。 安全側で PT 0 のみに絞る。
    #[test]
    fn rfc3264_6_1_offer_pt101_without_telephone_event_rtpmap_drops_dtmf() {
        // m= には 101 が並ぶが、 rtpmap は別エンコーディング (例: 何かの dynamic)。
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0 101\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=rtpmap:101 opus/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0 101\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=rtpmap:101 telephone-event/8000\r\n";

        let restricted =
            restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer).expect("PCMU は共通");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(
            s.contains("m=audio 40000 RTP/AVP 0\r\n"),
            "rtpmap が telephone-event でなければ PT 101 を answer に乗せない: {s}"
        );
        assert!(
            !s.to_lowercase().contains("telephone-event"),
            "answer に telephone-event を残さない: {s}"
        );
    }

    /// 不正 UTF-8 NGN offer は `Err`。 呼出側で `restrict_audio_to_pcmu` への
    /// フォールバック (= 既存挙動) を選ぶか、 488 で蹴るかを判断する。
    /// 安全側で `Err` を返し、 呼出側が判定する責務にする。
    #[test]
    fn ngn_offer_invalid_utf8_returns_err() {
        let bad_offer: &[u8] = &[0xff, 0xfe, b'b', b'a', b'd'];
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0\r\n\
                           a=rtpmap:0 PCMU/8000\r\n";
        assert!(restrict_answer_to_ngn_offer_subset(bad_offer, ext_answer).is_err());
    }

    /// NGN offer に m=audio が無い (RFC 4566 §5.14 違反) → `Err`。
    /// 通常 NGN INVITE では起こり得ないが防御的に検証する。
    #[test]
    fn ngn_offer_without_audio_media_returns_err() {
        let no_audio = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                         c=IN IP4 118.177.125.1\r\nt=0 0\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0\r\n\
                           a=rtpmap:0 PCMU/8000\r\n";
        assert!(restrict_answer_to_ngn_offer_subset(no_audio, ext_answer).is_err());
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

    /// メディアレベル c= がある SDP は **削除** される (session-level c= に統一)。
    /// 実機検証 2026-05-10: NGN P-CSCF は session+media level で同値の c= が
    /// 重複していると 500 Server Internal Error を返す (Firefox 由来 SDP)。
    #[test]
    fn rewrite_strips_media_level_connection_for_ngn_compatibility() {
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
        // メディアレベル c= は削除されているはず
        assert!(parsed.media[0].connection.is_none());
    }

    /// 不正な SDP はエラーで返る (元バイト列のまま流用するとピアが読めない)。
    #[test]
    fn rewrite_invalid_sdp_errors() {
        let original = b"not an sdp at all";
        let new_addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(rewrite_rtp_endpoint(original, new_addr, 1234).is_err());
    }

    /// RFC 3264 §8 (Modifying the Session):
    ///   "For each offer or answer, the session version in the origin field
    ///    MUST increment by one if the session description changes."
    ///
    /// `rewrite_rtp_endpoint` は c= / m= port / o= IP / o= username を必ず
    /// 書換えるので sess-version は **入力値 + 1** にならなければならない。
    /// re-INVITE で同 Call-ID に同 sess-version を載せると、 ピア (NGN P-CSCF /
    /// 内線 UA) は「内容変わってない」と判定し RTP socket を再 bind しない
    /// (Issue #77 / `docs/asterisk-real-invite.md` §2 で実機証拠)。
    #[test]
    fn rfc3264_section8_rewrite_increments_session_version() {
        let original = b"v=0\r\n\
                         o=- 1 42 IN IP4 192.0.2.1\r\n\
                         s=-\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 30000 RTP/AVP 0\r\n\
                         a=rtpmap:0 PCMU/8000\r\n";
        let new_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let rewritten = rewrite_rtp_endpoint(original, new_addr, 40000).unwrap();
        let parsed = SessionDescription::parse(std::str::from_utf8(&rewritten).unwrap()).unwrap();
        // 入力 sess-version=42 → 出力 sess-version=43 (RFC 3264 §8: +1)
        assert_eq!(
            parsed.origin.session_version, 43,
            "RFC 3264 §8 violation: sess-version は入力値 +1 でなければならない (got {})",
            parsed.origin.session_version
        );
    }

    /// RFC 4566 §5.2: session-id は session のグローバル一意 ID であり、
    /// 同一 session (= 同一 Call-ID の re-INVITE 連) では **不変** であるべき。
    /// 32-bit に収まる小さい値 (Asterisk pcap 由来の現実値) は踏襲する。
    #[test]
    fn rfc4566_section5_2_rewrite_preserves_small_session_id() {
        let original = b"v=0\r\n\
                         o=- 397958033 1 IN IP4 192.0.2.1\r\n\
                         s=-\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 30000 RTP/AVP 0\r\n\
                         a=rtpmap:0 PCMU/8000\r\n";
        let new_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let rewritten = rewrite_rtp_endpoint(original, new_addr, 40000).unwrap();
        let parsed = SessionDescription::parse(std::str::from_utf8(&rewritten).unwrap()).unwrap();
        // 入力 sess-id=397958033 (32-bit OK) → そのまま踏襲
        assert_eq!(parsed.origin.session_id, 397_958_033);
        // sess-version は +1
        assert_eq!(parsed.origin.session_version, 2);
    }

    /// 64-bit (= ブラウザ生成、 RFC 4566 §5.2 は uint64 を許すが NGN P-CSCF は
    /// 32-bit 期待で 486 を返す事例あり、 `src/sdp/builder.rs::rewrite_rtp_endpoint`
    /// docstring 参照) は UNIX epoch 秒に置換する。 sess-version は **入力値 +1**。
    #[test]
    fn rfc3264_section8_rewrite_increments_even_when_session_id_normalized() {
        // ブラウザ風: session-id = 64-bit、 session-version = 2 (Firefox 既定)
        let original = b"v=0\r\n\
                         o=mozilla 12345678901234567890 2 IN IP4 192.0.2.1\r\n\
                         s=-\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 30000 RTP/AVP 0\r\n\
                         a=rtpmap:0 PCMU/8000\r\n";
        // SessionDescription::parse が u64 を解釈できることを確認するため別途解析
        // (ここでは parse 結果から入力 sess-version を取り出して期待値を作る)
        let parsed_in = SessionDescription::parse(std::str::from_utf8(original).unwrap()).unwrap();
        let expected_version = parsed_in.origin.session_version.wrapping_add(1);

        let new_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let rewritten = rewrite_rtp_endpoint(original, new_addr, 40000).unwrap();
        let parsed = SessionDescription::parse(std::str::from_utf8(&rewritten).unwrap()).unwrap();

        // sess-version は +1 されている (RFC 3264 §8)
        assert_eq!(parsed.origin.session_version, expected_version);
        // sess-id は 32-bit 超過のため NGN 互換に正規化 (元の 64-bit 値ではない)
        assert_ne!(parsed.origin.session_id, parsed_in.origin.session_id);
        assert!(parsed.origin.session_id <= u32::MAX as u64);
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

    /// RFC 5576 §6.1: `a=ssrc:<id> cname:<value>` が出力に含まれる。
    /// RFC 5576 §4.1: ssrc-level 属性で SSRC ⇔ Stream binding を行う。
    #[test]
    fn rfc5576_4_1_convert_avp_to_savpf_emits_ssrc_cname() {
        let ngn = b"v=0\r\n\
                    o=- 100 100 IN IP4 192.0.2.1\r\n\
                    s=-\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    m=audio 30000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        let params = make_dtls_params()
            .with_ssrc(0xDEAD_BEEF)
            .with_cname("test-cname");
        let out = convert_avp_to_savpf(ngn, &params).expect("convert");
        let s = std::str::from_utf8(&out).unwrap();

        assert!(
            s.contains("a=ssrc:3735928559 cname:test-cname\r\n"),
            "ssrc cname 行欠落 (RFC 5576 §6.1):\n{}",
            s
        );
        // 再パース可能
        let _ = SessionDescription::parse(s).expect("re-parse");
    }

    /// RFC 8830 §2: `a=msid:<stream-id> <track-id>` の媒体レベル行と
    /// `a=ssrc:<id> msid:<stream-id> <track-id>` の二重化 (W3C unified-plan)。
    #[test]
    fn rfc8830_2_convert_avp_to_savpf_emits_msid() {
        let ngn = b"v=0\r\n\
                    o=- 100 100 IN IP4 192.0.2.1\r\n\
                    s=-\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    m=audio 30000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        let params = make_dtls_params()
            .with_ssrc(42)
            .with_cname("c")
            .with_msid("stream-7", "track-9");
        let out = convert_avp_to_savpf(ngn, &params).expect("convert");
        let s = std::str::from_utf8(&out).unwrap();

        // メディアレベル msid (RFC 8830 §2)
        assert!(
            s.contains("a=msid:stream-7 track-9\r\n"),
            "msid 行欠落:\n{}",
            s
        );
        // ssrc-level msid (W3C webrtc-pc / unified-plan、 ssrc と紐付け)
        assert!(
            s.contains("a=ssrc:42 msid:stream-7 track-9\r\n"),
            "ssrc msid 行欠落:\n{}",
            s
        );
    }

    /// RFC 3605 §2.1: `a=rtcp:<port>` を媒体レベルで出力する (rtcp-mux 併用でも
    /// audio.port と同一値を出して互換性を保つ)。
    #[test]
    fn rfc3605_2_1_convert_avp_to_savpf_emits_rtcp_port() {
        let ngn = b"v=0\r\n\
                    o=- 100 100 IN IP4 192.0.2.1\r\n\
                    s=-\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    m=audio 31234 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        let params = make_dtls_params();
        let out = convert_avp_to_savpf(ngn, &params).expect("convert");
        let s = std::str::from_utf8(&out).unwrap();

        assert!(
            s.contains("a=rtcp:31234\r\n"),
            "a=rtcp:<port> が m=audio port と一致していない:\n{}",
            s
        );
    }

    /// RFC 4566 §6: direction 属性 (sendrecv 等) が SDP に無ければ補う。
    #[test]
    fn rfc4566_6_convert_avp_to_savpf_supplies_default_direction() {
        let ngn_no_direction = b"v=0\r\n\
                                 o=- 1 1 IN IP4 192.0.2.1\r\n\
                                 s=-\r\n\
                                 c=IN IP4 192.0.2.1\r\n\
                                 t=0 0\r\n\
                                 m=audio 30000 RTP/AVP 0\r\n\
                                 a=rtpmap:0 PCMU/8000\r\n";
        let params = make_dtls_params();
        let out = convert_avp_to_savpf(ngn_no_direction, &params).expect("convert");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            s.contains("a=sendrecv\r\n"),
            "direction 既定 sendrecv 補完漏れ:\n{}",
            s
        );
    }

    /// RFC 4566 §6: 元 SDP に `a=recvonly` 等が乗っていればその direction を
    /// 尊重し、 `sendrecv` で上書きしない。
    #[test]
    fn rfc4566_6_convert_avp_to_savpf_preserves_existing_direction() {
        let ngn_recvonly = b"v=0\r\n\
                             o=- 1 1 IN IP4 192.0.2.1\r\n\
                             s=-\r\n\
                             c=IN IP4 192.0.2.1\r\n\
                             t=0 0\r\n\
                             m=audio 30000 RTP/AVP 0\r\n\
                             a=rtpmap:0 PCMU/8000\r\n\
                             a=recvonly\r\n";
        let params = make_dtls_params();
        let out = convert_avp_to_savpf(ngn_recvonly, &params).expect("convert");
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("a=recvonly\r\n"), "recvonly 保持失敗:\n{}", s);
        assert!(
            !s.contains("a=sendrecv\r\n"),
            "direction 二重化 (recvonly + sendrecv 両方) :\n{}",
            s
        );
    }

    /// RFC 8829 §5.2.1 (JSEP): 出力 SDP がブラウザ `setRemoteDescription()` で
    /// 必要な ssrc / msid / rtcp / direction / mid / ice / dtls 属性を全て
    /// 含むこと。 W3C webrtc-pc § 5.7 / 5.8 の RTCRtpReceiver 必須属性網羅。
    #[test]
    fn rfc8829_5_2_1_convert_avp_to_savpf_includes_all_browser_required_attrs() {
        let ngn = b"v=0\r\n\
                    o=- 12345 12345 IN IP4 192.0.2.1\r\n\
                    s=-\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    m=audio 40000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        let params = make_dtls_params();
        let out = convert_avp_to_savpf(ngn, &params).expect("convert");
        let s = std::str::from_utf8(&out).unwrap();

        // ICE / DTLS 必須 (RFC 8839 / 8842)
        assert!(s.contains("a=ice-ufrag:"), "ice-ufrag 欠落");
        assert!(s.contains("a=ice-pwd:"), "ice-pwd 欠落");
        assert!(s.contains("a=fingerprint:"), "fingerprint 欠落");
        assert!(s.contains("a=setup:"), "setup 欠落");

        // bundling / multiplex (RFC 8843 / 8829)
        assert!(s.contains("a=group:BUNDLE"), "BUNDLE 欠落");
        assert!(s.contains("a=mid:0"), "mid 欠落");
        assert!(s.contains("a=rtcp-mux"), "rtcp-mux 欠落");

        // direction (RFC 4566 §6)
        assert!(s.contains("a=sendrecv"), "direction 欠落");

        // SSRC / CNAME / MSID (RFC 5576 / RFC 8830)
        assert!(
            s.contains("a=ssrc:") && s.contains("cname:"),
            "ssrc cname 欠落"
        );
        assert!(s.contains("a=msid:"), "msid 欠落");
        assert!(s.contains("a=msid-semantic:WMS"), "msid-semantic 欠落");

        // RTCP port 明示 (RFC 3605 §2.1)
        assert!(s.contains("a=rtcp:40000"), "a=rtcp:<port> 欠落");

        // 再パース可能
        let _ = SessionDescription::parse(s).expect("re-parse");
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
        // RFC 3605 §2.1: a=rtcp は 1 行
        assert_eq!(count("a=rtcp:"), 1);
        // RFC 8830 §2: メディアレベル msid は 1 行
        // (ssrc-level の `a=ssrc:<id> msid:...` 行も msid を含むので、
        //  ここでは a=msid: 行だけを数える)
        assert_eq!(s.lines().filter(|l| l.starts_with("a=msid:")).count(), 1);
        // RFC 5576 §4.1: ssrc-level 属性は 2 行 (cname + msid) でちょうど。
        // 二度かけても増えない (旧 ssrc が retain で除去されるので冪等)。
        assert_eq!(count("a=ssrc:"), 2);
        // direction は 1 行のみ (sendrecv 既定)。
        let direction_count = s
            .lines()
            .filter(|l| {
                matches!(
                    l.trim_end(),
                    "a=sendrecv" | "a=sendonly" | "a=recvonly" | "a=inactive"
                )
            })
            .count();
        assert_eq!(direction_count, 1, "direction が 0 か 2 以上:\n{}", s);
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
