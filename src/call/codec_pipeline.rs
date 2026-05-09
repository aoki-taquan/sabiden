//! コーデックパイプライン選択 (Issue #29)
//!
//! NGN レッグと内線レッグの SDP からそれぞれの音声コーデックを判定し、
//! 「素通し ([`RtpBridge`]) で済むのか」「Opus↔G.711 トランスコード
//! ([`TranscodingBridge`]) が要るのか」を選ぶための判断ロジックを集約する。
//!
//! ## 判定方針 (RFC 3264 §5.1 / RFC 4566 §6 / RFC 7587 §7)
//!
//! - SDP 中に `a=rtpmap:<pt> opus/48000[/<ch>]` (RFC 7587 §7.1) があれば
//!   そのレッグは Opus を要求していると判断する。
//! - それ以外で `a=rtpmap:<pt> PCMU/8000` (RFC 3551 §4.5.14) または
//!   `m=audio` の static format に `0` が含まれていれば PCMU と判断する。
//! - 両側 PCMU → [`MediaPlan::Relay`] (素通し)
//! - 一方が Opus、もう一方が PCMU → [`MediaPlan::Transcode`] (Opus↔PCMU)
//! - その他 (Opus×Opus / 不明) → [`MediaPlan::Relay`] にフォールバック
//!   (Opus 同士は本来素通せるが、本実装の WebRTC ↔ NGN 用途では起こらない
//!   想定のため、最も安全な「触らない」を選ぶ)
//!
//! ## 既存動作の保持
//!
//! Phase 1〜Phase 4 で実機検証済みの **PCMU↔PCMU 既存パス** (Linphone↔NGN /
//! 117 時報通話) を絶対に壊さないため、`select_media_plan` は両側 PCMU の
//! ときに必ず `MediaPlan::Relay` を返す (= 既存 [`RtpBridge`] にフォールバック)。
//!
//! ## NGN 制約 (CLAUDE.md §5)
//!
//! NGN レッグは **PCMU only** が絶対要件 (`docs/asterisk-real-invite.md` §2)。
//! NGN へ Opus を流す経路は本実装で組み立てない。`select_media_plan` の
//! 引数順序は `(ngn_sdp, ext_sdp)` と固定し、NGN レッグ側で Opus を検出
//! しても本来発生しないが、もし出てきた場合はトランスコードではなく
//! Relay にフォールバックする (NGN レッグ書換は呼び出し側 `restrict_audio_to_pcmu`
//! が責任を持つ)。

use crate::call::transcoder::find_opus_payload_type;

/// 1 レッグ (NGN 側 / 内線側) で判定したコーデック種別。
///
/// 本実装が現状サポートするのは PCMU と Opus の 2 つだけ。`Unknown` は
/// 「rtpmap が読めなかった / 別コーデックが宣言されている」場合の
/// セーフティ用バリアント。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegCodec {
    /// G.711 μ-law (RFC 3551 §4.5.14, PT=0 静的)。
    Pcmu,
    /// Opus 48 kHz (RFC 7587)。`pt` は SDP `a=rtpmap` で指定された動的 PT。
    Opus { pt: u8 },
    /// 検出不能 / 本実装未対応コーデック。
    Unknown,
}

impl LegCodec {
    /// SDP バイト列からこのレッグのコーデックを判定する。
    ///
    /// Opus (`a=rtpmap:<pt> opus/48000[/<ch>]`) を最優先で見る。
    /// なければ PCMU の有無を見る (rtpmap または m=audio formats に "0")。
    pub fn detect(sdp_bytes: &[u8]) -> Self {
        if let Some(pt) = find_opus_payload_type(sdp_bytes) {
            return LegCodec::Opus { pt };
        }
        if sdp_has_pcmu(sdp_bytes) {
            return LegCodec::Pcmu;
        }
        LegCodec::Unknown
    }
}

/// 両レッグの SDP から決定するブリッジング戦略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaPlan {
    /// 素通し: `RtpBridge` で十分。両側 PCMU など。
    Relay,
    /// Opus ⇔ PCMU トランスコード。`opus_pt` は WebRTC レッグで使う Opus 動的 PT。
    Transcode { opus_pt: u8 },
}

/// NGN レッグ SDP / 内線レッグ SDP から [`MediaPlan`] を決定する。
///
/// 引数順序は `(ngn_sdp, ext_sdp)` で固定する (NGN は PCMU only 制約)。
///
/// RFC 3264 §5.1: Offer/Answer モデルでは answer に乗るコーデックが実際の
/// 通話で流れる。したがって Plan 決定には NGN 側 / 内線側それぞれが
/// **最終的に合意したコーデック** (= 各 SDP の rtpmap) を見れば足りる。
pub fn select_media_plan(ngn_sdp: &[u8], ext_sdp: &[u8]) -> MediaPlan {
    let ngn = LegCodec::detect(ngn_sdp);
    let ext = LegCodec::detect(ext_sdp);
    match (ngn, ext) {
        // 既存の PCMU↔PCMU 経路を絶対に壊さない (CLAUDE.md §5 / Issue #29 DoD)。
        (LegCodec::Pcmu, LegCodec::Pcmu) => MediaPlan::Relay,
        // 内線が Opus の場合のみトランスコード。NGN は PCMU 固定。
        (LegCodec::Pcmu, LegCodec::Opus { pt }) => MediaPlan::Transcode { opus_pt: pt },
        // NGN レッグに Opus が混入するのは仕様逸脱 (NGN は PCMU only)。
        // restrict_audio_to_pcmu が呼び出し側で適用される前提のため、ここに
        // 来るのは異常系。安全側に倒して Relay (= 触らない) を返す。
        // TODO(本流対応): NGN へ Opus が漏れたら警告ログを出す経路を Issue #29
        //   後続でメトリクス化する。
        (LegCodec::Opus { .. }, _) => MediaPlan::Relay,
        // 内線が Unknown / 未対応コーデックの場合も Relay に倒す (素通しなら
        // 内線↔NGN を直接繋いだのと同じ。RTP は読めなくても素通せる)。
        (LegCodec::Pcmu, LegCodec::Unknown) => MediaPlan::Relay,
        (LegCodec::Unknown, _) => MediaPlan::Relay,
    }
}

/// SDP 中に PCMU が宣言されているか (rtpmap または静的 PT=0) を判定する。
///
/// RFC 3551 §6 (Static payload types): PT=0 は PCMU の静的割当てなので、
/// rtpmap 行が無くても `m=audio <port> RTP/AVP 0` だけで PCMU と解釈できる。
fn sdp_has_pcmu(sdp_bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(sdp_bytes) else {
        return false;
    };
    let mut in_audio_media = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("m=") {
            in_audio_media = rest.starts_with("audio ");
            if in_audio_media {
                // RTP/AVP の format 一覧に "0" (PCMU 静的 PT) があるか
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 4 && parts[3..].contains(&"0") {
                    return true;
                }
            }
        } else if in_audio_media {
            if let Some(rest) = line.strip_prefix("a=rtpmap:") {
                if let Some((_pt, codec_part)) = rest.split_once(' ') {
                    let codec = codec_part
                        .split('/')
                        .next()
                        .unwrap_or("")
                        .to_ascii_uppercase();
                    if codec == "PCMU" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3551 §6: PT=0 は PCMU の静的割当て。rtpmap が無くても識別できる。
    #[test]
    fn rfc3551_static_pt0_identifies_pcmu() {
        let sdp = b"v=0\r\n\
                    o=- 1 1 IN IP4 192.0.2.1\r\n\
                    s=-\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    m=audio 30000 RTP/AVP 0\r\n";
        assert_eq!(LegCodec::detect(sdp), LegCodec::Pcmu);
    }

    /// RFC 7587 §7.1: `a=rtpmap:<pt> opus/48000/<ch>` で Opus 動的 PT を識別。
    #[test]
    fn rfc7587_rtpmap_identifies_opus() {
        let sdp = b"v=0\r\n\
                    m=audio 40000 UDP/TLS/RTP/SAVPF 111 0\r\n\
                    a=rtpmap:111 opus/48000/2\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        // Opus を最優先で検出 (PCMU 0 も同居しているが Opus を返す)。
        assert_eq!(LegCodec::detect(sdp), LegCodec::Opus { pt: 111 });
    }

    /// rtpmap に PCMU だけがある SDP は PCMU と判定される。
    #[test]
    fn rfc3551_pcmu_rtpmap_identifies_pcmu() {
        let sdp = b"m=audio 5004 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(LegCodec::detect(sdp), LegCodec::Pcmu);
    }

    /// PCMU↔PCMU の plan は必ず Relay (既存パス保持)。
    #[test]
    fn pcmu_to_pcmu_plan_is_relay() {
        let pcmu = b"m=audio 5004 RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(select_media_plan(pcmu, pcmu), MediaPlan::Relay);
    }

    /// 内線 Opus + NGN PCMU はトランスコード (opus_pt は内線側の値)。
    #[test]
    fn opus_ext_pcmu_ngn_plan_is_transcode_with_ext_pt() {
        let ngn_pcmu = b"m=audio 5004 RTP/AVP 0\r\n\
                         a=rtpmap:0 PCMU/8000\r\n";
        let ext_opus = b"m=audio 40000 UDP/TLS/RTP/SAVPF 111\r\n\
                         a=rtpmap:111 opus/48000/2\r\n";
        assert_eq!(
            select_media_plan(ngn_pcmu, ext_opus),
            MediaPlan::Transcode { opus_pt: 111 }
        );
    }

    /// NGN 側に Opus が混入した場合は Relay にフォールバック (異常系)。
    /// 呼び出し側 `restrict_audio_to_pcmu` で防ぐべきだが、本関数は
    /// 安全側に倒す。
    #[test]
    fn opus_on_ngn_side_falls_back_to_relay() {
        let ngn_opus = b"m=audio 5004 RTP/AVP 96\r\n\
                         a=rtpmap:96 opus/48000/2\r\n";
        let ext_pcmu = b"m=audio 5004 RTP/AVP 0\r\n\
                         a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(select_media_plan(ngn_opus, ext_pcmu), MediaPlan::Relay);
    }

    /// 不明コーデック同士は Relay (素通し試行)。
    #[test]
    fn unknown_codec_falls_back_to_relay() {
        let unknown = b"m=audio 5004 RTP/AVP 9\r\n\
                        a=rtpmap:9 G722/8000\r\n";
        assert_eq!(LegCodec::detect(unknown), LegCodec::Unknown);
        assert_eq!(select_media_plan(unknown, unknown), MediaPlan::Relay);
    }

    /// 大文字 OPUS でもケース無視で検出される (RFC 4566 §6 case-insensitive)。
    #[test]
    fn opus_codec_name_is_case_insensitive() {
        let sdp = b"m=audio 40000 RTP/AVP 96\r\n\
                    a=rtpmap:96 OPUS/48000/2\r\n";
        assert_eq!(LegCodec::detect(sdp), LegCodec::Opus { pt: 96 });
    }
}
