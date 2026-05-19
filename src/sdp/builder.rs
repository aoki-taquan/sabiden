//! SDP シリアライザ (RFC 4566)。
//!
//! `SessionDescription` を SDP テキストに変換する。RFC 4566 では
//! 行終端は CRLF。SIP 経由で送信されるため UTF-8 ではなく US-ASCII を想定。
//!
//! また、NTT ひかり電話 (NGN) で頻出する G.711 μ-law のオファーを
//! 簡単に作れるヘルパ ([`SessionDescription::pcmu_offer`] 系コンストラクタ) を提供する。

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
/// 未指定 (`None`) なら `DtlsIceParams::ssrc_or_default` / `Self::cname_or_default`
/// 等が `o=` の session-id 由来の安定値を返す (private helper、 internal use only)。
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
        // Issue #325: `a=rtcp:<port>` は m=audio の RTP port に対応する RTCP port を
        // 厳密に広告する属性 (RFC 3605 §2、 RFC 5761 §5.1.3)。 上で m=audio port を
        // 書換えた以上、 既存 `a=rtcp` は **旧 port + 1** を指したままになる。
        // 厳格準拠 UA はこの値で RTCP を旧 port に送りつけ、 sabiden 側の RTCP
        // ソケット (`port + 1` 想定) に届かない。 ここで現在の audio.port に
        // 整合するよう RTCP port を再計算する。 オプションの `<nettype>
        // <addrtype> <connection-address>` は session-level `c=` (上で `addr` に
        // 設定済) と整合するため drop する (RFC 3605 §2.1: address parts are
        // optional; omitting them defers to the session-level connection).
        let new_rtcp_port = port.saturating_add(1).to_string();
        for attr in audio.attributes.iter_mut() {
            if let Attribute::Value { key, value } = attr {
                if key == "rtcp" {
                    *value = new_rtcp_port.clone();
                }
            }
        }
    }

    Ok(sdp.to_string_crlf().into_bytes())
}

/// RFC 3264 §6.1 / RFC 4566 §6: offer SDP の最初の `m=audio` から
/// `a=ptime:<n>` 値を抽出する。
///
/// `a=ptime` は packetization period (ms) を表すメディアレベル属性で、
/// answerer は offer の値を **echo するのが推奨** (RFC 3264 §6.1: answer の
/// attribute は offer の subset)。 NGN は実機キャプチャ (Issue #249,
/// `/tmp/sabiden-080-inbound.pcap`) で常に `a=ptime:20` を offer に乗せて
/// 来るが、 PWA/WebRTC 由来 SDP やテスト SDP では別値 (例 30, 60) も
/// あり得るため、 ハードコードせず offer から拾う。
///
/// 戻り値:
/// - `Some(n)`: `m=audio` 直下のメディア属性に `a=ptime:n` がある
/// - `None`: 不在 / パース不能 / `n` が u32 範囲外 / `m=audio` 不在
///
/// パース不能 SDP は呼出側で 200 OK を素通しさせる経路に従うため `None` で
/// 良い (= 「ptime echo は best-effort」)。
pub fn extract_ptime_from_offer(offer_bytes: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(offer_bytes).ok()?;
    let sdp = SessionDescription::parse(text).ok()?;
    let audio = sdp.media.iter().find(|m| m.media == "audio")?;
    for a in &audio.attributes {
        if let Attribute::Value { key, value } = a {
            if key == "ptime" {
                return value.trim().parse::<u32>().ok();
            }
        }
    }
    None
}

/// RFC 3264 §6.1 / RFC 4566 §6: answer SDP の最初の `m=audio` に
/// `a=ptime:<n>` を **無ければ** 追加する。
///
/// answer SDP に既に ptime があれば変更しない (内線側が異なる値を主張する
/// 余地を残す)。 不在の場合のみ、 offer 由来の値を補う。 RFC 3264 §6.1 は
/// answer の attribute を offer の subset とする推奨であり、 answerer が
/// 別 ptime を望むなら answerer 値を尊重する (offer 側が次回 re-INVITE で
/// 調整可能)。
///
/// パース不能ならそのまま返す (ベストエフォート、 NGN への 200 OK 全体の
/// 整合性は呼出側で別途検証する)。
pub fn ensure_ptime_in_answer(answer_bytes: &[u8], ptime_ms: u32) -> Vec<u8> {
    let text = match std::str::from_utf8(answer_bytes) {
        Ok(s) => s,
        Err(_) => return answer_bytes.to_vec(),
    };
    let mut sdp = match SessionDescription::parse(text) {
        Ok(s) => s,
        Err(_) => return answer_bytes.to_vec(),
    };
    let audio = match sdp.media.iter_mut().find(|m| m.media == "audio") {
        Some(m) => m,
        None => return answer_bytes.to_vec(),
    };
    let has_ptime = audio
        .attributes
        .iter()
        .any(|a| matches!(a, Attribute::Value { key, .. } if key == "ptime"));
    if !has_ptime {
        audio.attributes.push(Attribute::Value {
            key: "ptime".to_string(),
            value: ptime_ms.to_string(),
        });
    }
    sdp.to_string_crlf().into_bytes()
}

/// audio メディアを **G.711 μ-law (payload type 0) のみ** に絞った SDP を返す。
///
/// 本関数は Phase R3 (`docs/refactor-plan.md` §1.4 / §4.2、 Issue #272) で
/// `crate::sdp::negotiation::Negotiator::for_ngn()` への薄い wrapper に再構成
/// された。 旧来の `PCMU only 化 + WebRTC attr 剥離 + ptime/rtcp/s= 補完` の
/// 4 責務は `Negotiator` 内部で分離されており、 本関数は backwards compat 用の
/// alias である (新規 callsite は `Negotiator::for_ngn().rewrite_offer(...)` を
/// 使うこと)。
///
/// NTT ひかり電話 (NGN) は PCMU(0) しか受け入れず、Linphone/Zoiper 等が送ってくる
/// multi-codec オファ (Opus, Speex, G.729, telephone-event 等) を素通しすると
/// `488 Not Acceptable Here` で拒否される。本関数は内線→NGN プロキシ時の
/// SDP を NGN 仕様に正規化する用途。
///
/// パース不能ならそのまま返す (ベストエフォート)。
pub fn restrict_audio_to_pcmu(sdp_bytes: &[u8]) -> Vec<u8> {
    crate::sdp::negotiation::Negotiator::for_ngn().rewrite_offer(sdp_bytes)
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

    /// RFC 3605 §2.1: `restrict_audio_to_pcmu_with_dtmf` は `a=rtcp:<port+1>` を
    /// m=audio port に基づいて inject する (RTCP port を explicit signal、 modern
    /// peer 互換)。 Issue #260 / PR #264 真因 (NGN parity reject) の
    /// falsification test で NGN は honor しないと確認済だが、 SHOULD-level
    /// compliance + WebRTC 等 modern peer interop に有効。
    #[test]
    fn rfc3605_restrict_audio_to_pcmu_with_dtmf_injects_a_rtcp() {
        let sdp_with_port = b"v=0\r\n\
o=- 0 0 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";
        let restricted = restrict_audio_to_pcmu_with_dtmf(sdp_with_port);
        let s = std::str::from_utf8(&restricted).expect("utf8");
        assert!(
            s.contains("a=rtcp:30001\r\n"),
            "a=rtcp:<port+1> が m=audio 30000 から派生して inject されるべき:\n{}",
            s
        );
    }

    /// `a=rtcp:` が既に SDP に含まれていれば idempotent (二重 inject しない)。
    #[test]
    fn rfc3605_restrict_audio_idempotent_with_existing_a_rtcp() {
        let sdp = b"v=0\r\n\
o=- 0 0 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtcp:40000\r\n\
a=sendrecv\r\n";
        let restricted = restrict_audio_to_pcmu_with_dtmf(sdp);
        let s = std::str::from_utf8(&restricted).expect("utf8");
        assert!(s.contains("a=rtcp:40000\r\n"));
        assert!(
            !s.contains("a=rtcp:30001\r\n"),
            "既存 a=rtcp:40000 がある時に a=rtcp:30001 を二重に inject すべきでない:\n{}",
            s
        );
    }

    /// RFC 4566 §5.3: `restrict_audio_to_pcmu_with_dtmf` は空 / `-` の `s=` を
    /// 非空に置換する (厳格な registrar が `s=-` を reject する事例対応、
    /// Asterisk 互換 `docs/asterisk-real-invite.md` §2)。
    #[test]
    fn rfc4566_session_name_replaced_when_empty_or_dash() {
        let sdp = b"v=0\r\n\
o=- 0 0 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";
        let restricted = restrict_audio_to_pcmu_with_dtmf(sdp);
        let s = std::str::from_utf8(&restricted).expect("utf8");
        assert!(
            s.contains("s=sabiden\r\n"),
            "s=- は s=sabiden に置換されるべき:\n{}",
            s
        );
        assert!(!s.contains("s=-\r\n"));
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
    crate::sdp::negotiation::Negotiator::for_ngn_with_dtmf().rewrite_offer(sdp_bytes)
}

/// Issue #108 / Issue #212 / RFC 3264 §6.1: NGN へ返す **answer の payload type を
/// `NGN offer ∩ ext_answer` の真 intersection** に絞り込む。
///
/// # RFC 引用
///
/// RFC 3264 §6.1 (Generating the Answer / Unicast Streams):
///
/// > "For each "m=" line in the offer, the answerer MUST generate a corresponding
/// > "m=" line in the answer. ... For streams marked as sendrecv in the answer,
/// > the "m=" line ... MUST include at least one media format that the offerer
/// > and answerer can use. The answerer MAY include any media formats that it
/// > supports, **but it MUST list them in priority order ... and the formats
/// > listed MUST be a subset of those listed in the offer**."
///
/// → answer の `m=` formats は **「offer に列挙された PT」かつ「answerer が
/// 実際にサポートする PT」の交わり (intersection)** でなければならない。
/// 旧実装 (PR #209 まで) は ext_answer の formats を見ず、 NGN offer 由来の PT を
/// `[0]` / `[0, 101]` に上書き合成していた。 これは ext_answer が PCMU を含まない
/// (= 内線が PCMA / Opus only) ケースで RFC 3264 §6.1 違反 + 無音通話の原因。
///
/// # アルゴリズム
///
/// 1. NGN offer の `m=audio` formats (= NGN が **送信し得る** PT 集合) を抽出
/// 2. ext_answer の `m=audio` formats (= 内線 / WebRTC / SIP が **受信できる** PT
///    集合) を抽出
/// 3. **両者の intersection** を NGN offer の出現順 (RFC 3264 §6.1 "priority
///    order" は offer の preference 順を answerer がそのまま尊重するのが慣習) で
///    出力 formats とする
/// 4. intersection が空なら `Err` (RFC 3264 §6.1: "no common media format" →
///    呼出側で 488 Not Acceptable Here / 502 Bad Gateway 相当)
/// 5. `rtpmap` / `fmtp` 属性 (RFC 4566 §6) は **intersection PT に対応する行のみ**
///    残す。 ext_answer 由来の encoding 情報を優先 (内線が実際に offer した形)。
/// 6. WebRTC / DTLS-SRTP / ICE 由来の attribute (ice-*, candidate, fingerprint,
///    setup, rtcp-mux 等) は NGN が解釈しないので削除 (`docs/asterisk-real-invite.md`
///    §2)。
///
/// # NGN PCMU-only 制約との関係
///
/// CLAUDE.md §5 (NGN は PCMU only) は **callsite (orchestrator)** が
/// 「NGN offer は PCMU only / DTMF 付」で来ることに依存する: intersection が
/// 自然に PCMU only / PCMU+DTMF になる。 本関数は汎用的に intersection を計算し、
/// NGN 制約は offer 側の formats が体現する。
///
/// # 引数
///
/// - `ngn_offer`: NGN P-CSCF から到着した INVITE の SDP body。 UTF-8 / SDP 文法
///   不正は `Err` (RFC 3261 §7.1: SIP body は ASCII / UTF-8 想定)。
/// - `ext_answer`: 内線 (SIP 200 OK / WebRTC answer) 由来の SDP body。
///
/// # 戻り値
///
/// 整形済 answer SDP の byte 列。 intersection が空、 SDP 不正、 m=audio 不在は
/// `Err`。 呼出側は 502 Bad Gateway / 488 Not Acceptable Here で対応する。
pub fn restrict_answer_to_ngn_offer_subset(
    ngn_offer: &[u8],
    ext_answer: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let offer_audio = parse_audio_formats_and_rtpmap(ngn_offer)?;
    let answer_audio = parse_audio_formats_and_rtpmap(ext_answer)?;

    // RFC 3264 §6.1: answer formats = offer ∩ answerer-supported。 NGN offer の
    // 出現順を維持 (offerer の preference order 尊重)。
    let intersection: Vec<String> = offer_audio
        .formats
        .iter()
        .filter(|pt| answer_audio.formats.contains(pt))
        .cloned()
        .collect();

    if intersection.is_empty() {
        return Err(anyhow::anyhow!(
            "RFC 3264 §6.1: NGN offer formats ({:?}) と ext answer formats ({:?}) の \
             intersection が空。 共通 codec 無し → 呼出側で 488 Not Acceptable Here 相当",
            offer_audio.formats,
            answer_audio.formats
        ));
    }

    build_answer_with_format_subset(ext_answer, &intersection)
}

/// NGN が解釈しない WebRTC / DTLS-SRTP / ICE / multiplex 系 attribute を判定する
/// (RFC 5245 / RFC 5763 / RFC 8829 / RFC 5888 / RFC 5576 / RFC 5285 等)。
///
/// `restrict_audio_to_pcmu` と同じセット。 NGN 直収で実機検証済
/// (`docs/asterisk-real-invite.md` §2)。
fn is_unsupported_by_ngn_answer(a: &Attribute) -> bool {
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
        Attribute::Property(p) => matches!(
            p.as_str(),
            "rtcp-mux"
                | "ice-lite"
                | "rtcp-rsize"
                | "extmap-allow-mixed"
                | "end-of-candidates"
                | "bundle-only"
        ),
    }
}

/// `rtpmap` / `fmtp` 属性の値先頭 (= "<pt> ...") を payload type に解釈する。
/// パース失敗時は `None` (= 属性として PT に紐付かない、 保守的に保持する判断は
/// 呼出側へ委譲)。
fn pt_of_rtpmap_or_fmtp_value(value: &str) -> Option<u8> {
    value.split_whitespace().next().and_then(|p| p.parse().ok())
}

/// ext_answer をベースに、 `m=audio` formats を `keep_pts` (= NGN offer 順の
/// intersection) に絞り、 対応しない rtpmap / fmtp を除去し、 NGN が解釈しない
/// WebRTC / ICE 由来 attribute を剥がした answer SDP を返す。
///
/// RFC 4566 §6 (rtpmap): "Up to one rtpmap attribute SHOULD be defined for each
/// media format specified in the corresponding "m=" line." → keep_pts に対応
/// する rtpmap だけを残し、 静的 PT (PCMU=0 等) で rtpmap が無いものは
/// ext_answer に元々無いならそのままで OK (RFC 3551 で静的予約)。
///
/// RFC 3264 §6.1: answer の `m=` formats は **offer の subset**。 本関数の
/// 呼出側 (`restrict_answer_to_ngn_offer_subset`) で intersection 計算済の
/// 前提なので、 ここでは「絞り込みの実行」だけを行う。
fn build_answer_with_format_subset(
    ext_answer: &[u8],
    keep_pts: &[String],
) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(ext_answer)
        .map_err(|e| anyhow::anyhow!("ext answer SDP が UTF-8 でない: {}", e))?;
    let mut sdp = SessionDescription::parse(text)?;

    // セッションレベル attribute から WebRTC/ICE 由来を剥がす。
    sdp.attributes.retain(|a| !is_unsupported_by_ngn_answer(a));

    let audio = sdp
        .media
        .iter_mut()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow::anyhow!("ext answer SDP に m=audio 行が無い"))?;

    // RFC 3264 §6.1: m= formats を NGN offer 順の intersection に置換。
    audio.formats = keep_pts.to_vec();

    // RFC 4566 §6: rtpmap / fmtp は m= formats に対応する PT だけ残す。
    // PT が parse 不能な rtpmap/fmtp は安全側で破棄する (NGN は不明 PT の
    // rtpmap を不正 SDP として 500 で蹴る実績あり: project memory
    // `project_ngn_media_c_duplicate` 系)。
    audio.attributes.retain(|a| {
        if is_unsupported_by_ngn_answer(a) {
            return false;
        }
        match a {
            Attribute::Value { key, value } => match key.as_str() {
                "rtpmap" | "fmtp" => match pt_of_rtpmap_or_fmtp_value(value) {
                    Some(pt) => keep_pts.contains(&pt.to_string()),
                    None => false,
                },
                _ => true,
            },
            Attribute::Property(_) => true,
        }
    });

    Ok(sdp.to_string_crlf().into_bytes())
}

/// `parse_audio_formats_and_rtpmap` の戻り値: 最初の `m=audio` の formats 一覧。
///
/// RFC 3264 §6.1 の intersection (offer formats ∩ answer formats) を計算する
/// ための一次情報。 PT を `String` のままにすることで、 静的 PT (0, 8 等) /
/// 動的 PT (96-127) を同じ比較で扱える (RFC 3551 §6 / RFC 3264 §6.1)。
#[derive(Debug)]
struct AudioOfferSummary {
    formats: Vec<String>,
}

/// 受信 SDP の最初の `m=audio` 行から formats 一覧を抽出する。 RFC 3264 §6.1
/// intersection 判定の一次情報源。
///
/// パース不能 (UTF-8 / SDP 文法エラー / m=audio 不在) は `Err`。 呼出側で
/// 488 Not Acceptable Here / 502 Bad Gateway 相当で fallback。
fn parse_audio_formats_and_rtpmap(sdp_bytes: &[u8]) -> anyhow::Result<AudioOfferSummary> {
    let text = std::str::from_utf8(sdp_bytes)
        .map_err(|e| anyhow::anyhow!("SDP が UTF-8 でない: {}", e))?;
    let sdp = SessionDescription::parse(text)?;
    let audio = sdp
        .media
        .iter()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow::anyhow!("SDP に m=audio 行が無い"))?;
    Ok(AudioOfferSummary {
        formats: audio.formats.clone(),
    })
}

#[cfg(test)]
mod restrict_answer_subset_tests {
    use super::*;

    /// Issue #212 (a) / RFC 3264 §6.1: NGN offer = `[0, 8, 101]`、
    /// ext_answer = `[0, 101]` のとき、 真 intersection で answer は `[0, 101]`。
    /// 旧実装 (PR #209) は ext_answer を見ずに `[0, 101]` を **forcibly synthesize**
    /// していたため、 ext_answer に 101 が無くても 101 を載せる band-aid だった。
    /// 新実装は両側に 101 がある場合のみ 101 を載せる。
    #[test]
    fn rfc3264_6_1_issue212_a_offer_pcmu_pcma_dtmf_answer_pcmu_dtmf() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0 8 101\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=rtpmap:101 telephone-event/8000\r\n\
                          a=fmtp:101 0-15\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0 101\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=rtpmap:101 telephone-event/8000\r\n\
                           a=fmtp:101 0-15\r\n";

        let restricted = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect("intersection 計算成功");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(
            s.contains("m=audio 40000 RTP/AVP 0 101\r\n"),
            "intersection = [0, 101] (NGN offer 順): {s}"
        );
        assert!(
            !s.contains("PCMA") && !s.contains("rtpmap:8"),
            "PT 8 (PCMA) は ext_answer に無いので intersection に入らず、 rtpmap も破棄: {s}"
        );
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=rtpmap:101 telephone-event/8000\r\n"));
    }

    /// Issue #212 (b) / RFC 3264 §6.1: NGN offer = `[8]` (PCMA only)、
    /// ext_answer = `[111]` (Opus only) のとき、 intersection は空集合 → `Err`。
    /// 呼出側は 488 Not Acceptable Here (RFC 3261 §21.4.26) / 502 Bad Gateway 相当
    /// で fallback する。
    #[test]
    fn rfc3264_6_1_issue212_b_no_common_pt_errors() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 111\r\n\
                           a=rtpmap:111 opus/48000/2\r\n";

        let err = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect_err("intersection 空は Err");
        let msg = format!("{}", err);
        assert!(
            msg.contains("§6.1") && msg.contains("intersection"),
            "Err は subset 規則 + intersection 空を示す: {msg}"
        );
    }

    /// Issue #212 (c) / RFC 3264 §6.1: NGN offer = `[0, 8, 9]` (PCMU/PCMA/G.722)、
    /// ext_answer = `[0, 9]` (PCMU/G.722) のとき、 intersection は `[0, 9]`。
    /// NGN offer 順 (0, 8, 9) を尊重し answer は `[0, 9]` (PCMA は ext_answer に
    /// 無いので除外、 PT 8 を skip して PT 9 を続ける)。
    #[test]
    fn rfc3264_6_1_issue212_c_partial_overlap_keeps_intersection_in_offer_order() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0 8 9\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=rtpmap:9 G722/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0 9\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=rtpmap:9 G722/8000\r\n";

        let restricted = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect("intersection 計算成功");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(
            s.contains("m=audio 40000 RTP/AVP 0 9\r\n"),
            "intersection [0, 9] (PT 8 は ext_answer に無く除外): {s}"
        );
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=rtpmap:9 G722/8000\r\n"));
        assert!(!s.contains("rtpmap:8"), "PT 8 rtpmap は破棄: {s}");
    }

    /// Issue #212 (d) / RFC 4566 §6 (rtpmap): answer の rtpmap / fmtp 行は
    /// intersection PT に対応する行のみ残る。 ext_answer に余分な rtpmap (PT 8 等)
    /// があっても剥がす。
    #[test]
    fn rfc4566_6_issue212_d_attribute_filter_strips_non_intersection_rtpmap() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0 101\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=rtpmap:101 telephone-event/8000\r\n\
                          a=fmtp:101 0-15\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0 8 9 101\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=rtpmap:8 PCMA/8000\r\n\
                           a=rtpmap:9 G722/8000\r\n\
                           a=rtpmap:101 telephone-event/8000\r\n\
                           a=fmtp:101 0-15\r\n\
                           a=ptime:20\r\n";

        let restricted = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect("intersection 計算成功");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(
            s.contains("a=rtpmap:0 PCMU/8000\r\n"),
            "PT 0 rtpmap 保持: {s}"
        );
        assert!(
            s.contains("a=rtpmap:101 telephone-event/8000\r\n"),
            "PT 101 rtpmap 保持: {s}"
        );
        assert!(
            s.contains("a=fmtp:101 0-15\r\n"),
            "PT 101 fmtp 保持 (RFC 4733 §3.2): {s}"
        );
        assert!(
            !s.contains("PCMA") && !s.contains("rtpmap:8"),
            "PT 8 rtpmap 破棄: {s}"
        );
        assert!(!s.contains("rtpmap:9"), "PT 9 rtpmap 破棄: {s}");
        assert!(
            s.contains("a=ptime:20\r\n"),
            "ptime は PT 非依存で保持: {s}"
        );
    }

    /// Issue #212 (e) / RFC 3264 §6.1 ("priority order"): answer の `m=` formats
    /// は NGN offer の出現順を維持する。 ext_answer 側の順序は無視 (offer 側の
    /// preference を尊重するのが慣習)。
    #[test]
    fn rfc3264_6_1_issue212_e_preserves_offer_order_not_answer_order() {
        // NGN offer: [101, 0] (DTMF を先に提示する架空の順序)
        // ext_answer: [0, 101] (PCMU を先に並べる)
        // 期待: intersection を NGN offer 順 = [101, 0] で返す。
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 101 0\r\n\
                          a=rtpmap:101 telephone-event/8000\r\n\
                          a=fmtp:101 0-15\r\n\
                          a=rtpmap:0 PCMU/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0 101\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=rtpmap:101 telephone-event/8000\r\n\
                           a=fmtp:101 0-15\r\n";

        let restricted = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect("intersection 計算成功");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(
            s.contains("m=audio 40000 RTP/AVP 101 0\r\n"),
            "answer formats は NGN offer 順 [101, 0] を維持 (RFC 3264 §6.1): {s}"
        );
    }

    /// 既存 NGN inbound 通話パス (Issue #145) の回帰防止: NGN offer = `[0, 101]`、
    /// PWA (str0m) ext_answer = `[0, 101]` の典型形で intersection が PCMU+DTMF。
    #[test]
    fn rfc3264_6_1_ngn_inbound_typical_pcmu_dtmf_passes_through() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0 101\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=rtpmap:101 telephone-event/8000\r\n\
                          a=fmtp:101 0-15\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0 101\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=rtpmap:101 telephone-event/8000\r\n\
                           a=fmtp:101 0-15\r\n\
                           a=ptime:20\r\n";

        let restricted = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect("intersection 計算成功");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(s.contains("m=audio 40000 RTP/AVP 0 101\r\n"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=rtpmap:101 telephone-event/8000\r\n"));
        assert!(s.contains("a=ptime:20\r\n"));
    }

    /// 既存 117 通話 (PCMU SIP-only) の回帰防止: 両側 PT 0 only で intersection
    /// は `[0]` のみ。
    #[test]
    fn rfc3264_6_1_117_call_pcmu_only_both_sides() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0\r\n\
                           a=rtpmap:0 PCMU/8000\r\n";

        let restricted = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect("intersection 計算成功");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(s.contains("m=audio 40000 RTP/AVP 0\r\n"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
    }

    /// 不正 UTF-8 NGN offer は `Err`。 呼出側は 488 / 502 で fallback する。
    #[test]
    fn ngn_offer_invalid_utf8_returns_err() {
        let bad_offer: &[u8] = &[0xff, 0xfe, b'b', b'a', b'd'];
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0\r\n\
                           a=rtpmap:0 PCMU/8000\r\n";
        assert!(restrict_answer_to_ngn_offer_subset(bad_offer, ext_answer).is_err());
    }

    /// 不正 UTF-8 ext_answer も `Err`。 内線 200 OK 由来 SDP の妥当性は事前
    /// 保証されないので両側を防御する。
    #[test]
    fn ext_answer_invalid_utf8_returns_err() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n";
        let bad_answer: &[u8] = &[0xff, 0xfe, b'b', b'a', b'd'];
        assert!(restrict_answer_to_ngn_offer_subset(ngn_offer, bad_answer).is_err());
    }

    /// NGN offer に m=audio が無い (RFC 4566 §5.14 違反) → `Err`。
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

    /// ext_answer に m=audio が無い → `Err`。
    #[test]
    fn ext_answer_without_audio_media_returns_err() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n";
        let no_audio = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                         c=IN IP4 192.168.30.10\r\nt=0 0\r\n";
        assert!(restrict_answer_to_ngn_offer_subset(ngn_offer, no_audio).is_err());
    }

    /// Issue #212 / 旧 band-aid 撤去: ext_answer が PCMU を含まない
    /// (= 内線が PCMA / Opus only) ケースで、 旧実装は `[0]` を forcibly
    /// synthesize していた (PR #209 review 🟡 #1 #2)。 新実装は intersection が
    /// 空になり Err を返す → 呼出側で fallback (= bridge 起動失敗 / 488 / 502)。
    #[test]
    fn rfc3264_6_1_old_band_aid_pcmu_synthesize_removed() {
        // NGN offer は PCMU + DTMF (実機 NGN の典型)、 ext_answer は PCMA only。
        // 旧実装: PCMU が offer にあるので `restrict_audio_to_pcmu` で `[0]` を
        // synthesize し、 ext_answer の PCMA を無視して [0] を返していた。
        // 新実装: intersection = {} → Err。
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0 101\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=rtpmap:101 telephone-event/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 8\r\n\
                           a=rtpmap:8 PCMA/8000\r\n";

        let err = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect_err("intersection 空 (ext が PCMA only) → Err");
        let msg = format!("{}", err);
        assert!(
            msg.contains("intersection"),
            "Err は intersection 空示唆: {msg}"
        );
    }

    /// WebRTC 由来 ext_answer に含まれる ICE / DTLS-SRTP / RTCP-mux 属性は NGN
    /// が解釈しないので answer から剥がす (`docs/asterisk-real-invite.md` §2、
    /// `restrict_audio_to_pcmu` と同じ判定セット)。
    #[test]
    fn webrtc_attributes_stripped_for_ngn() {
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                          c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                          m=audio 24252 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n";
        let ext_answer = b"v=0\r\no=- 2 2 IN IP4 192.168.30.10\r\ns=-\r\n\
                           c=IN IP4 192.168.30.10\r\nt=0 0\r\n\
                           m=audio 40000 RTP/AVP 0\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=ice-ufrag:abcd\r\n\
                           a=ice-pwd:0123456789abcdef0123456789abcd\r\n\
                           a=fingerprint:sha-256 AA:BB:CC:DD\r\n\
                           a=setup:active\r\n\
                           a=rtcp-mux\r\n\
                           a=mid:0\r\n";

        let restricted = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
            .expect("intersection 計算成功");
        let s = std::str::from_utf8(&restricted).expect("utf8");

        assert!(!s.contains("ice-ufrag"));
        assert!(!s.contains("ice-pwd"));
        assert!(!s.contains("fingerprint"));
        assert!(!s.contains("setup"));
        assert!(!s.contains("rtcp-mux"));
        assert!(!s.contains("mid:"));
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

    /// RFC 3605 §2 (Real Time Control Protocol (RTCP) attribute in SDP):
    ///
    /// > "The general form of this attribute is:
    /// >     a=rtcp:<port> [<nettype> <addrtype> <connection-address>]"
    ///
    /// `a=rtcp` は **対応する m=audio の RTP port に対する RTCP port** を厳密に
    /// 広告する属性であり、 strict-compliance peer はこの値で RTCP を送出する。
    /// `rewrite_rtp_endpoint` で m=audio port を sabiden 側 socket port に書換える
    /// 際に、 既存 `a=rtcp` を **新 port + 1** に更新しないと、 peer は旧 port + 1
    /// に RTCP を送出してしまい sabiden に届かない (Issue #325)。
    ///
    /// 本テストは Negotiator が PCMU only 化と同時に `a=rtcp:<orig_port+1>` を
    /// inject した SDP に対し、 続けて `rewrite_rtp_endpoint` を適用したときに
    /// `a=rtcp` が新 port+1 を指すことを確認する (intercom 全経路で再現する
    /// pre-existing pattern、 PR #320 / PR #323 / Issue #325)。
    #[test]
    fn rfc3605_section2_rewrite_updates_a_rtcp_to_new_port_plus_one() {
        // Negotiator が a=rtcp:30001 を inject 済み (m=audio 30000 の +1)。
        let pre_rewrite = b"v=0\r\n\
                            o=- 1 1 IN IP4 192.0.2.1\r\n\
                            s=sabiden\r\n\
                            c=IN IP4 192.0.2.1\r\n\
                            t=0 0\r\n\
                            m=audio 30000 RTP/AVP 0\r\n\
                            a=rtpmap:0 PCMU/8000\r\n\
                            a=ptime:20\r\n\
                            a=rtcp:30001\r\n";
        let new_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let rewritten = rewrite_rtp_endpoint(pre_rewrite, new_addr, 40000).unwrap();
        let s = std::str::from_utf8(&rewritten).expect("utf8");

        // RTP port は書換わっている
        assert!(
            s.contains("m=audio 40000 RTP/AVP 0\r\n"),
            "m=audio が 40000 に書換わっていない:\n{s}"
        );
        // RFC 3605 §2: a=rtcp は新 port + 1 を指すべき (= 40001)
        assert!(
            s.contains("a=rtcp:40001\r\n"),
            "a=rtcp が新 port+1 (40001) を指していない (旧 30001 のまま):\n{s}"
        );
        // 旧値 30001 が残っていないこと (stale advertisement の検出)
        assert!(
            !s.contains("a=rtcp:30001\r\n"),
            "旧 a=rtcp:30001 が残存している (RFC 3605 §2 違反):\n{s}"
        );
        // a=rtcp 行は 1 つだけ (重複 inject 防止)
        let rtcp_count = s.lines().filter(|l| l.starts_with("a=rtcp:")).count();
        assert_eq!(rtcp_count, 1, "a=rtcp 行が複数:\n{s}");
    }

    /// RFC 3605 §2: 入力 SDP が `a=rtcp:<port> <nettype> <addrtype> <addr>`
    /// 形式 (optional address part 付き) を持つ場合も、 port rewrite 時に
    /// 新 port+1 だけが残り、 旧 address parts は drop される
    /// (session-level c= が新 addr を指しているため不要、 RFC 3605 §2.1)。
    #[test]
    fn rfc3605_section2_rewrite_updates_a_rtcp_with_address_parts() {
        let pre_rewrite = b"v=0\r\n\
                            o=- 1 1 IN IP4 192.0.2.1\r\n\
                            s=-\r\n\
                            c=IN IP4 192.0.2.1\r\n\
                            t=0 0\r\n\
                            m=audio 62018 RTP/AVP 0\r\n\
                            a=rtpmap:0 PCMU/8000\r\n\
                            a=rtcp:62019 IN IP4 192.0.2.1\r\n";
        let new_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let rewritten = rewrite_rtp_endpoint(pre_rewrite, new_addr, 54200).unwrap();
        let s = std::str::from_utf8(&rewritten).expect("utf8");

        assert!(s.contains("m=audio 54200 RTP/AVP 0\r\n"), "{s}");
        assert!(
            s.contains("a=rtcp:54201\r\n"),
            "a=rtcp が新 port+1 (54201) に更新されていない:\n{s}"
        );
        // 旧アドレス part は drop されている (session-level c= が新 addr を指す)
        assert!(
            !s.contains("a=rtcp:62019"),
            "旧 a=rtcp:62019 ... が残存:\n{s}"
        );
        assert!(
            !s.contains("192.0.2.1"),
            "旧 c=/o=/a=rtcp の旧 IP が残存:\n{s}"
        );
    }

    /// `a=rtcp` が無い SDP では `rewrite_rtp_endpoint` は a=rtcp を inject しない
    /// (それは `Negotiator::ensure_a_rtcp` の責務、 順序として両者が組み合わさる
    /// callsite で結果的に正しい port+1 が現れる)。
    #[test]
    fn rewrite_does_not_inject_a_rtcp_when_absent() {
        let pre_rewrite = b"v=0\r\n\
                            o=- 1 1 IN IP4 192.0.2.1\r\n\
                            s=-\r\n\
                            c=IN IP4 192.0.2.1\r\n\
                            t=0 0\r\n\
                            m=audio 30000 RTP/AVP 0\r\n\
                            a=rtpmap:0 PCMU/8000\r\n";
        let new_addr: IpAddr = "10.0.0.1".parse().unwrap();
        let rewritten = rewrite_rtp_endpoint(pre_rewrite, new_addr, 40000).unwrap();
        let s = std::str::from_utf8(&rewritten).expect("utf8");
        assert!(
            !s.contains("a=rtcp:"),
            "a=rtcp を勝手に inject すべきでない:\n{s}"
        );
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

    /// RFC 3264 §6.1 / RFC 4566 §6 (Issue #249): offer SDP に `a=ptime:20` が
    /// あれば `extract_ptime_from_offer` は `Some(20)` を返す。 これは NGN
    /// 着信時に 200 OK SDP へ ptime を echo するための一次情報源。
    #[test]
    fn rfc3264_6_1_extract_ptime_from_ngn_offer() {
        let offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                      c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                      m=audio 13300 RTP/AVP 0\r\n\
                      a=ptime:20\r\n\
                      a=rtpmap:0 PCMU/8000\r\n\
                      a=sendrecv\r\n";
        assert_eq!(extract_ptime_from_offer(offer), Some(20));
    }

    /// RFC 3264 §6.1: offer に ptime が無いケース。 `None` で返す
    /// (= 呼出側で 「ptime は echo しない」 と判断する根拠)。
    #[test]
    fn rfc3264_6_1_extract_ptime_absent() {
        let offer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                      c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                      m=audio 13300 RTP/AVP 0\r\n\
                      a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(extract_ptime_from_offer(offer), None);
    }

    /// RFC 3264 §6.1 (Issue #249): answer SDP に `a=ptime` が無く offer に
    /// 20 ms があるなら、 `ensure_ptime_in_answer(answer, 20)` で
    /// `a=ptime:20` を追加する。
    #[test]
    fn rfc3264_6_1_inbound_answer_echoes_ptime() {
        let answer = b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\n\
                       c=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                       m=audio 40000 RTP/AVP 0\r\n\
                       a=rtpmap:0 PCMU/8000\r\n\
                       a=sendrecv\r\n";
        let out = ensure_ptime_in_answer(answer, 20);
        let s = std::str::from_utf8(&out).expect("utf8");
        assert!(
            s.contains("a=ptime:20\r\n"),
            "answer に ptime:20 が echo されているべき (RFC 3264 §6.1): {s}"
        );
        // 既存 attribute は保持
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=sendrecv\r\n"));
    }

    /// RFC 3264 §6.1: answer に既に ptime があれば上書きせず保持する
    /// (= answerer の主張を尊重)。
    #[test]
    fn rfc3264_6_1_existing_ptime_in_answer_preserved() {
        let answer = b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\n\
                       c=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                       m=audio 40000 RTP/AVP 0\r\n\
                       a=rtpmap:0 PCMU/8000\r\n\
                       a=ptime:30\r\n";
        let out = ensure_ptime_in_answer(answer, 20);
        let s = std::str::from_utf8(&out).expect("utf8");
        assert!(
            s.contains("a=ptime:30\r\n"),
            "answer が ptime:30 を主張 → 上書きしない (offer 由来 20 は無視): {s}"
        );
        assert!(
            !s.contains("a=ptime:20\r\n"),
            "20 は付与してはいけない: {s}"
        );
    }
}
