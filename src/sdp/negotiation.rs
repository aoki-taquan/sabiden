//! SDP Negotiator: codec subset + WebRTC attribute strip + NGN normalization.
//!
//! 本モジュールは Phase R3 (`docs/refactor-plan.md` §1.4 / §4.2) で導入された
//! **責務分離レイヤ**。 旧来 `crate::sdp::builder::restrict_audio_to_pcmu` /
//! `restrict_audio_to_pcmu_with_dtmf` の 1 関数に同居していた以下 4 つの責務を
//! 分割し、 設定可能な `Negotiator` 型に集約する:
//!
//! 1. **Codec subset (RFC 3264 §6.1)**: 許可 payload type を残し、 それ以外の
//!    `m=` formats / `a=rtpmap` / `a=fmtp` を除去する。 NGN 直収では PCMU(0) と
//!    任意で telephone-event(101) のみ許可される (CLAUDE.md §5、
//!    `docs/asterisk-real-invite.md` §2)。
//! 2. **WebRTC attribute strip (RFC 5763 / RFC 8839 / RFC 8843)**: NGN P-CSCF が
//!    解釈しない DTLS-SRTP / ICE / multiplex 系属性 (`fingerprint` / `setup` /
//!    `ice-*` / `candidate` / `rtcp-mux` / `mid` / `msid` / `ssrc` / `extmap` /
//!    `rtcp-fb` / `rtcp-xr` 等) を session level / media level の両方から剥がす。
//! 3. **NGN media-level 正規化 (RFC 4566 §5.3 / §6, RFC 3605 §2.1)**:
//!    `s=` が空 / `-` なら `sabiden` に置換、 `a=ptime:20` が無ければ補完、
//!    `a=rtcp:<port+1>` が無ければ m=audio port + 1 で補完する。
//! 4. **PCMU rtpmap / telephone-event rtpmap+fmtp 補完 (RFC 3551 §6 / RFC 4733 §3.2)**:
//!    PT 0 の rtpmap が無ければ `0 PCMU/8000` を head に挿入、 with_dtmf の場合
//!    PT 101 が無ければ `101 telephone-event/8000` と `fmtp:101 0-15` を補完。
//!
//! # 既存 `restrict_audio_to_pcmu*` との関係
//!
//! `crate::sdp::builder::restrict_audio_to_pcmu` / `_with_dtmf` は本モジュールへの
//! 薄い wrapper として残置されており、 production callsite は段階的に
//! `Negotiator::for_ngn()` / `Negotiator::for_ngn_with_dtmf()` 経由に置換する。
//!
//! # NGN 実機制約 (CLAUDE.md §5)
//!
//! - 音声コーデックは **PCMU (PT 0) only**。 PCMA / G.722 / Opus は NGN レッグへ
//!   流すと 488 Not Acceptable Here / 500 Internal Server Error を返される。
//! - telephone-event (RFC 4733) は **8kHz のみ許容**。 Linphone デフォルトの
//!   48000Hz は破棄して 8000Hz に補完する。
//! - WebRTC SAVPF 由来属性 (DTLS-SRTP / ICE / BUNDLE / msid / ssrc) は NGN が
//!   解釈せず、 残すと 500 で蹴られる実績がある (`docs/asterisk-real-invite.md` §2)。

use crate::sdp::{Attribute, SessionDescription};

/// `a=fmtp:101 0-15` で signal される telephone-event の RTP payload type
/// (de-facto 101、 RFC 4733 §3.2)。
///
/// `crate::sdp::builder::DTMF_PAYLOAD_TYPE` と同一値。 本モジュールでは
/// `Negotiator::for_ngn_with_dtmf` 構築時の codec subset に乗せる。
pub const DTMF_PAYLOAD_TYPE: u8 = 101;

/// SDP コーデック許可リスト entry。
///
/// 現状は PCMU(0) と telephone-event(101) を想定するが、 将来 PCMA(8) /
/// G.722(9) など追加が必要になった場合は `AllowedCodec` を増やすだけで
/// `Negotiator` の API を変えずに済む。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedCodec {
    /// RTP payload type (RFC 3551 §6 静的 PT、 または RFC 3264 §6.1 動的 PT)。
    pub payload_type: u8,
    /// `a=rtpmap` 値の右辺 (`<encoding>/<rate>[/<params>]`)。 PT が静的 PT で
    /// 既に rtpmap が無い場合に補完するために保持。
    pub rtpmap_value: &'static str,
    /// `a=fmtp` 値の右辺 (telephone-event の `0-15` 等)。 None なら fmtp は補完しない。
    pub fmtp_value: Option<&'static str>,
    /// rtpmap 値の `/<rate>` を整合チェックする (RFC 3551 §6 / RFC 4733 §3.2)。
    /// `Some("/8000")` のように先頭 `/` 込みの subslice を指定する。 既存 SDP に
    /// 別 rate の rtpmap (例: telephone-event/48000) があれば破棄する。 None なら
    /// rate 不問。
    pub required_rate_marker: Option<&'static str>,
}

impl AllowedCodec {
    /// G.711 μ-law (RFC 3551 §4.5.14): PT 0 / 8 kHz mono。 NGN 必須 codec。
    pub const PCMU: AllowedCodec = AllowedCodec {
        payload_type: 0,
        rtpmap_value: "0 PCMU/8000",
        fmtp_value: None,
        required_rate_marker: Some("/8000"),
    };

    /// telephone-event (RFC 4733 §3.2): PT 101 / 8 kHz / events 0-15。 NGN は
    /// `audio` payload としては解釈しないが、 in-band DTMF 中継のため許可する。
    pub const TELEPHONE_EVENT: AllowedCodec = AllowedCodec {
        payload_type: DTMF_PAYLOAD_TYPE,
        rtpmap_value: "101 telephone-event/8000",
        fmtp_value: Some("101 0-15"),
        required_rate_marker: Some("/8000"),
    };
}

/// SDP の **codec subset + 属性正規化**を一括で行う型。
///
/// インスタンスは `for_ngn()` / `for_ngn_with_dtmf()` で生成する。 設定済
/// `Negotiator` は再利用可能 (immutable) で、 `rewrite_offer` /
/// `rewrite_answer` の呼出に副作用を持たない。
///
/// # 設計
///
/// 旧 `restrict_audio_to_pcmu*` は引数なしの単一関数で「PCMU only」「WebRTC strip」
/// 「ptime 補完」「rtcp 補完」「s= 補完」を全部やっていた。 `Negotiator` は
/// codec 集合と attribute filter ポリシーを内部状態として持ち、 副作用を
/// transformation 関数群に分割する。 これにより `docs/refactor-plan.md` §Phase R3
/// で挙げた以下のテスト可能性を確保する:
///
/// - 「PCMU only 化」を単独で検証 (NGN 非依存テスト)
/// - 「WebRTC attr 剥離」を単独で検証 (codec ロジックと独立)
/// - 「ptime / rtcp 補完」を単独で検証
/// - 「s= 正規化」を単独で検証 (RFC 4566 §5.3 strict registrar 対策)
#[derive(Debug, Clone)]
pub struct Negotiator {
    /// audio media に許可する payload type のリスト。 順序は `m=audio` 行で
    /// 出力する PT の順序になる。
    allowed_audio: Vec<AllowedCodec>,
    /// `true` なら NGN が解釈しない WebRTC / DTLS-SRTP / ICE / multiplex 系属性を
    /// session level / media level から剥がす (CLAUDE.md §5)。
    strip_webrtc_attrs: bool,
    /// `true` なら NGN 媒体に必要な以下を補完する:
    /// - `s=` が空 / `-` なら `sabiden`
    /// - `a=ptime:20` が無ければ補完 (RFC 4566 §6 / NGN QoS path)
    /// - `a=rtcp:<port+1>` が無ければ補完 (RFC 3605 §2.1、 modern peer 互換)
    normalize_for_ngn: bool,
}

impl Negotiator {
    /// NGN 直収用 (PCMU only)。 `restrict_audio_to_pcmu` 相当。
    ///
    /// 設定:
    /// - allowed_audio: `[PCMU(0)]`
    /// - strip_webrtc_attrs: true
    /// - normalize_for_ngn: true
    pub fn for_ngn() -> Self {
        Self {
            allowed_audio: vec![AllowedCodec::PCMU],
            strip_webrtc_attrs: true,
            normalize_for_ngn: true,
        }
    }

    /// NGN 直収 + DTMF 用 (PCMU + telephone-event)。
    /// `restrict_audio_to_pcmu_with_dtmf` 相当。
    ///
    /// 設定:
    /// - allowed_audio: `[PCMU(0), TELEPHONE_EVENT(101)]`
    /// - strip_webrtc_attrs: true
    /// - normalize_for_ngn: true
    pub fn for_ngn_with_dtmf() -> Self {
        Self {
            allowed_audio: vec![AllowedCodec::PCMU, AllowedCodec::TELEPHONE_EVENT],
            strip_webrtc_attrs: true,
            normalize_for_ngn: true,
        }
    }

    /// 内線 / WebRTC / SIP からの **offer** SDP を NGN レッグに送出する形に
    /// 書換える。 失敗時 (UTF-8 / SDP 文法エラー) は入力をそのまま返す
    /// ベストエフォート挙動 (旧 `restrict_audio_to_pcmu` と同じ)。
    ///
    /// # RFC 引用
    ///
    /// - RFC 3264 §6.1 (Generating the Offer / Unicast Streams): "the offer
    ///   MUST contain at least one media format that the offerer is willing to
    ///   accept" → allowed_audio が `[PCMU]` のみなら m= は `0` のみで送出される。
    /// - RFC 5763 §5 / RFC 8843 §7.2 / RFC 8839 §5.4: DTLS-SRTP / BUNDLE / ICE
    ///   属性は SAVPF profile 用。 NGN AVP profile では削除する。
    pub fn rewrite_offer(&self, sdp_bytes: &[u8]) -> Vec<u8> {
        self.apply(sdp_bytes)
    }

    /// NGN から受信した INVITE/200 OK の SDP (= **answer 候補** または NGN 由来
    /// offer) を内線レッグへ relay する形に書換える。 現状の NGN 経路では
    /// `rewrite_offer` と同じ正規化 (PCMU only / s= / ptime / rtcp) で十分。
    ///
    /// `ext_offer` 引数は将来 RFC 3264 §6.1 intersection 計算 (offer formats ∩
    /// answerer formats) を本関数に持ち込むための placeholder。 現状は
    /// `restrict_answer_to_ngn_offer_subset` (`crate::sdp::builder`) が
    /// orchestrator から直接呼ばれているため、 本関数は ngn_answer の
    /// PCMU-only 正規化だけを行う。
    ///
    /// # RFC 引用
    ///
    /// - RFC 3264 §6.1: answer formats は offer formats の subset。
    /// - RFC 4566 §6: rtpmap / fmtp は m= formats に対応する PT だけ残す。
    pub fn rewrite_answer(&self, _ext_offer: &[u8], ngn_answer: &[u8]) -> Vec<u8> {
        self.apply(ngn_answer)
    }

    /// 共通の SDP 変換ロジック (offer / answer 両方で同じ rewrite を実施)。
    fn apply(&self, sdp_bytes: &[u8]) -> Vec<u8> {
        let text = match std::str::from_utf8(sdp_bytes) {
            Ok(s) => s,
            Err(_) => return sdp_bytes.to_vec(),
        };
        let mut sdp = match SessionDescription::parse(text) {
            Ok(s) => s,
            Err(_) => return sdp_bytes.to_vec(),
        };

        if self.strip_webrtc_attrs {
            sdp.attributes.retain(|a| !is_unsupported_by_ngn(a));
        }

        if let Some(audio) = sdp.media.iter_mut().find(|m| m.media == "audio") {
            self.apply_codec_subset(audio);
            if self.normalize_for_ngn {
                ensure_ptime(audio);
                ensure_a_rtcp(audio);
            }
        }

        if self.normalize_for_ngn && (sdp.session_name.is_empty() || sdp.session_name == "-") {
            // RFC 4566 §5.3: `s=` MUST be non-empty。 厳格な registrar が `s=-` を
            // reject する事例対応 (`docs/asterisk-real-invite.md` §2、 Asterisk
            // 実機は `s=Asterisk` 使用)。
            sdp.session_name = "sabiden".to_string();
        }

        sdp.to_string_crlf().into_bytes()
    }

    /// audio media の formats と rtpmap / fmtp を allowed_audio に絞り込む。
    fn apply_codec_subset(&self, audio: &mut crate::sdp::MediaDescription) {
        // formats 列を allowed_audio の順で構築。
        audio.formats = self
            .allowed_audio
            .iter()
            .map(|c| c.payload_type.to_string())
            .collect();

        let allowed_pts: Vec<u8> = self.allowed_audio.iter().map(|c| c.payload_type).collect();

        // attribute フィルタ: WebRTC 属性除去 + rtpmap/fmtp の PT subset。
        audio.attributes.retain(|a| {
            if self.strip_webrtc_attrs && is_unsupported_by_ngn(a) {
                return false;
            }
            match a {
                Attribute::Value { key, value } => {
                    let pt = pt_of_rtpmap_or_fmtp(value);
                    match key.as_str() {
                        "rtpmap" => match pt {
                            Some(pt_val) => {
                                let Some(codec) =
                                    self.allowed_audio.iter().find(|c| c.payload_type == pt_val)
                                else {
                                    return false;
                                };
                                // rate 整合チェック (RFC 4733 §3.2: 48000Hz の
                                // telephone-event は audio 8kHz と不整合)。
                                if let Some(marker) = codec.required_rate_marker {
                                    if !value.contains(marker) {
                                        return false;
                                    }
                                }
                                true
                            }
                            None => false,
                        },
                        "fmtp" => match pt {
                            Some(pt_val) => allowed_pts.contains(&pt_val),
                            None => false,
                        },
                        _ => true,
                    }
                }
                Attribute::Property(_) => true,
            }
        });

        // 欠落した rtpmap / fmtp を補完。 RFC 3551 §6 (static PT 0 = PCMU/8000) /
        // RFC 4733 §3.2 (telephone-event)。
        for (idx, codec) in self.allowed_audio.iter().enumerate() {
            let has_rtpmap = audio.attributes.iter().any(|a| {
                matches!(a, Attribute::Value { key, value }
                    if key == "rtpmap"
                        && pt_of_rtpmap_or_fmtp(value) == Some(codec.payload_type))
            });
            if !has_rtpmap {
                let rtpmap_attr = Attribute::Value {
                    key: "rtpmap".to_string(),
                    value: codec.rtpmap_value.to_string(),
                };
                // PCMU(= 先頭 codec) は head に挿入、 後続 codec は末尾追加。
                // 旧実装互換: `restrict_audio_to_pcmu*` は PCMU rtpmap を index 0 に
                // 挿入し、 telephone-event rtpmap は末尾 push する。
                if idx == 0 {
                    audio.attributes.insert(0, rtpmap_attr);
                } else {
                    audio.attributes.push(rtpmap_attr);
                }
            }
            if let Some(fmtp_val) = codec.fmtp_value {
                let has_fmtp = audio.attributes.iter().any(|a| {
                    matches!(a, Attribute::Value { key, value }
                        if key == "fmtp"
                            && pt_of_rtpmap_or_fmtp(value) == Some(codec.payload_type))
                });
                if !has_fmtp {
                    audio.attributes.push(Attribute::Value {
                        key: "fmtp".to_string(),
                        value: fmtp_val.to_string(),
                    });
                }
            }
        }
    }
}

/// `a=ptime:20` を audio media に補完する (無ければ末尾追加)。
///
/// RFC 4566 §6 (ptime): "length of time in milliseconds represented by the
/// media in a packet". NGN PCMU は 20 ms 固定 (RFC 3551 §4.5.14)。
fn ensure_ptime(audio: &mut crate::sdp::MediaDescription) {
    let has_ptime = audio
        .attributes
        .iter()
        .any(|a| matches!(a, Attribute::Value { key, .. } if key == "ptime"));
    if !has_ptime {
        audio.attributes.push(Attribute::Value {
            key: "ptime".to_string(),
            value: "20".to_string(),
        });
    }
}

/// `a=rtcp:<port+1>` を audio media に補完する (RFC 3605 §2.1)。
///
/// NGN P-CSCF は本属性を honor しない (2026-05-15 falsification test、
/// `project_ngn_500_FINAL.md`) ものの、 WebRTC / modern peer interop に有効。
fn ensure_a_rtcp(audio: &mut crate::sdp::MediaDescription) {
    let has_a_rtcp = audio
        .attributes
        .iter()
        .any(|a| matches!(a, Attribute::Value { key, .. } if key == "rtcp"));
    if !has_a_rtcp {
        let rtcp_port = audio.port.saturating_add(1);
        audio.attributes.push(Attribute::Value {
            key: "rtcp".to_string(),
            value: rtcp_port.to_string(),
        });
    }
}

/// NGN が解釈しない WebRTC / DTLS-SRTP / ICE / multiplex 系属性を判定する。
///
/// 根拠 RFC:
/// - RFC 5763 §5 (DTLS-SRTP): `a=fingerprint` / `a=setup`
/// - RFC 8839 §5.4 (ICE): `a=ice-ufrag` / `a=ice-pwd` / `a=ice-options` /
///   `a=ice-mismatch` / `a=candidate` / `a=end-of-candidates` / `a=ice-lite`
/// - RFC 8843 §7.2 (BUNDLE): `a=mid` / `a=group:BUNDLE` / `a=bundle-only`
/// - RFC 8285 §6 (RTP header extensions): `a=extmap` / `a=extmap-allow-mixed`
/// - RFC 5576 §4 (SSRC attributes): `a=ssrc` / `a=ssrc-group`
/// - RFC 8830 §2 (msid): `a=msid` (media level) / `a=msid-semantic` (session
///   level — session level は本 filter で扱わず、 BUNDLE strip 経路で削除する)
/// - RFC 4585 / RFC 5104 / RFC 8108 (RTCP feedback): `a=rtcp-fb`
/// - RFC 3611 (RTCP-XR): `a=rtcp-xr`
/// - RFC 5761 §5 (rtcp-mux): `a=rtcp-mux` / `a=rtcp-rsize` (RFC 5506)
/// - RFC 6464 §5 (record): `a=record`
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

/// `rtpmap` / `fmtp` 属性値の先頭 token を payload type (u8) としてパースする。
///
/// RFC 4566 §6: `a=rtpmap:<pt> <encoding>/<rate>[/<params>]`。 PT が parse 不能な
/// rtpmap / fmtp は安全側で破棄する (NGN が不正 SDP として 500 で蹴る事例あり)。
fn pt_of_rtpmap_or_fmtp(value: &str) -> Option<u8> {
    value.split_whitespace().next().and_then(|p| p.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3264 §6.1 + CLAUDE.md §5: PCMU only 化で Opus / PCMA / G.729 等を破棄、
    /// PT 0 だけ残し、 PCMU rtpmap が無ければ補完する。 旧
    /// `restrict_audio_to_pcmu_drops_opus_and_keeps_pcmu` と同じ scenario。
    #[test]
    fn rfc3264_6_1_for_ngn_drops_opus_and_keeps_pcmu_only() {
        // Linphone multi-codec offer (実機 trace 由来)。
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

        let neg = Negotiator::for_ngn();
        let out = neg.rewrite_offer(linphone_sdp);
        let s = std::str::from_utf8(&out).expect("utf8");

        assert!(s.contains("m=audio 54205 RTP/AVP 0\r\n"), "{}", s);
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"), "{}", s);
        assert!(!s.to_lowercase().contains("opus"));
        assert!(!s.to_lowercase().contains("speex"));
        assert!(!s.to_lowercase().contains("telephone-event"));
        assert!(!s.contains("rtcp-fb"));
        assert!(!s.contains("rtcp-xr"));
    }

    /// RFC 5763 §5 / RFC 8839 §5.4 / RFC 8843 §7.2: WebRTC SAVPF 由来属性は
    /// NGN AVP では削除する。 ssrc / msid / mid / extmap / candidate / setup /
    /// fingerprint / ice-ufrag / ice-pwd / rtcp-mux 等を全部剥がす検証。
    #[test]
    fn rfc8843_for_ngn_strips_webrtc_attrs() {
        let webrtc_sdp = b"v=0\r\n\
o=- 1 1 IN IP4 192.168.1.10\r\n\
s=-\r\n\
c=IN IP4 192.168.1.10\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic:WMS *\r\n\
m=audio 30000 UDP/TLS/RTP/SAVPF 0\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD\r\n\
a=setup:actpass\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:0123456789abcdef0123456789ab\r\n\
a=candidate:1 1 udp 2113929471 192.168.1.10 30000 typ host\r\n\
a=end-of-candidates\r\n\
a=mid:0\r\n\
a=rtcp-mux\r\n\
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
a=msid:stream0 audio0\r\n\
a=ssrc:11111 cname:sabiden\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

        let neg = Negotiator::for_ngn();
        let out = neg.rewrite_offer(webrtc_sdp);
        let s = std::str::from_utf8(&out).expect("utf8");

        // 必ず消えるべき WebRTC 属性
        for needle in [
            "fingerprint",
            "setup:",
            "ice-ufrag",
            "ice-pwd",
            "candidate:",
            "end-of-candidates",
            "mid:",
            "rtcp-mux",
            "extmap",
            "msid:",
            "ssrc:",
        ] {
            assert!(
                !s.contains(needle),
                "WebRTC attr `{}` が残っている:\n{}",
                needle,
                s
            );
        }

        // 残るべきもの: PCMU rtpmap / sendrecv (RFC 4566 §6 direction は保持)
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=sendrecv\r\n"));
    }

    /// Phase R3 DoD: `Negotiator` の冪等性 (apply を 2 回かけても結果が変わらない)。
    /// `restrict_audio_to_pcmu_passes_through_already_pcmu_only` の拡張。
    #[test]
    fn negotiator_for_ngn_is_idempotent() {
        let already_normalized = b"v=0\r\n\
o=- 0 0 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=ptime:20\r\n\
a=sendrecv\r\n";
        let neg = Negotiator::for_ngn();
        let once = neg.rewrite_offer(already_normalized);
        let twice = neg.rewrite_offer(&once);
        assert_eq!(
            once, twice,
            "Negotiator::rewrite_offer は冪等であるべき (二重適用で差分なし)"
        );
        let s = std::str::from_utf8(&twice).expect("utf8");
        // 補完項目は元 SDP の値を尊重
        assert!(s.contains("a=ptime:20\r\n"));
        assert!(s.contains("a=sendrecv\r\n"));
        // s= は元が `-` だったので sabiden に置換
        assert!(s.contains("s=sabiden\r\n"));
    }

    /// RFC 4733 §3.2: `for_ngn_with_dtmf` は PT 0 + PT 101 を残し、
    /// telephone-event/48000 は破棄して /8000 に補完する (Issue #69 と同パターン)。
    #[test]
    fn rfc4733_3_2_for_ngn_with_dtmf_keeps_pcmu_and_dtmf_only() {
        let linphone_sdp = b"v=0\r\n\
o=- 1 1 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 54205 RTP/AVP 96 0 8 101\r\n\
a=rtpmap:96 opus/48000/2\r\n\
a=fmtp:96 useinbandfec=1\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:101 telephone-event/48000\r\n";

        let neg = Negotiator::for_ngn_with_dtmf();
        let out = neg.rewrite_offer(linphone_sdp);
        let s = std::str::from_utf8(&out).expect("utf8");

        assert!(s.contains("m=audio 54205 RTP/AVP 0 101\r\n"), "{}", s);
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        // 48000Hz telephone-event は破棄 → 8000Hz で補完
        assert!(!s.contains("telephone-event/48000"));
        assert!(s.contains("a=rtpmap:101 telephone-event/8000\r\n"));
        assert!(s.contains("a=fmtp:101 0-15\r\n"));
        assert!(!s.to_lowercase().contains("opus"));
        assert!(!s.contains("PCMA"));
    }

    /// RFC 3605 §2.1 + RFC 4566 §6 + RFC 4566 §5.3: NGN 媒体正規化補完
    /// (a=ptime / a=rtcp / s= 置換) を 1 ケースで通しチェック。
    #[test]
    fn rfc3605_for_ngn_with_dtmf_injects_normalizations() {
        // a=ptime / a=rtcp が無く、 s= が `-` の最小 PCMU offer
        let minimal = b"v=0\r\n\
o=- 0 0 IN IP4 192.168.30.162\r\n\
s=-\r\n\
c=IN IP4 192.168.30.162\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=sendrecv\r\n";

        let neg = Negotiator::for_ngn_with_dtmf();
        let out = neg.rewrite_offer(minimal);
        let s = std::str::from_utf8(&out).expect("utf8");

        assert!(s.contains("s=sabiden\r\n"), "RFC 4566 §5.3 s= 置換: {s}");
        assert!(s.contains("a=ptime:20\r\n"), "RFC 4566 §6 ptime 補完: {s}");
        assert!(
            s.contains("a=rtcp:30001\r\n"),
            "RFC 3605 §2.1 a=rtcp port+1 補完: {s}"
        );
        assert!(
            s.contains("m=audio 30000 RTP/AVP 0 101\r\n"),
            "DTMF PT 101 を formats に含める: {s}"
        );
    }

    /// RFC 3264 §6.1 + RFC 4566 §6: `rewrite_answer` で NGN 由来 200 OK の SDP を
    /// 内線 relay 用に PCMU only / sendrecv 保持で書換える (既存 NGN inbound 経路)。
    /// `_ext_offer` 引数は将来の intersection 計算用 placeholder で、 現状の
    /// rewrite_answer は ngn_answer のみを使う。
    #[test]
    fn rfc3264_6_1_for_ngn_rewrite_answer_relays_pcmu_only() {
        let ngn_offer_placeholder = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                                      c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                                      m=audio 24252 RTP/AVP 0\r\n\
                                      a=rtpmap:0 PCMU/8000\r\n";
        let ngn_answer = b"v=0\r\no=- 1 1 IN IP4 118.177.125.1\r\ns=-\r\n\
                           c=IN IP4 118.177.125.1\r\nt=0 0\r\n\
                           m=audio 24252 RTP/AVP 0\r\n\
                           a=rtpmap:0 PCMU/8000\r\n\
                           a=ptime:20\r\n\
                           a=sendrecv\r\n";

        let neg = Negotiator::for_ngn();
        let out = neg.rewrite_answer(ngn_offer_placeholder, ngn_answer);
        let s = std::str::from_utf8(&out).expect("utf8");

        assert!(s.contains("m=audio 24252 RTP/AVP 0\r\n"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(s.contains("a=ptime:20\r\n"));
        assert!(s.contains("a=sendrecv\r\n"));
    }

    /// 不正 UTF-8 / 不正 SDP はベストエフォートで入力をそのまま返す
    /// (旧 `restrict_audio_to_pcmu*` 互換)。 production 経路で SDP 不正があっても
    /// crash させない。
    #[test]
    fn invalid_input_returns_input_as_is() {
        let bad_utf8: &[u8] = &[0xff, 0xfe, b'b', b'a', b'd'];
        let neg = Negotiator::for_ngn();
        assert_eq!(neg.rewrite_offer(bad_utf8), bad_utf8.to_vec());

        let bad_sdp = b"not a valid sdp";
        assert_eq!(neg.rewrite_offer(bad_sdp), bad_sdp.to_vec());
    }
}
