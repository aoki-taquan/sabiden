//! RTP/RTCP (RFC 3550) + G.711 μ-law (RFC 3551) 実装
//!
//! NGN 向けに RTP パケット送受信、ジッタバッファ、RTCP SR/RR を提供する。
//! DSCP 32 (TOS 0x80) を RTP/RTCP 送信ソケットにも適用する。

pub mod codec;
pub mod jitter;
pub mod packet;
pub mod rtcp;
pub mod session;

#[allow(unused_imports)]
pub use packet::{RtpPacket, PAYLOAD_TYPE_ULAW, SAMPLES_PER_FRAME, SAMPLE_RATE};
#[allow(unused_imports)]
pub use session::{RtpSession, RtpSessionStats};

/// G.711 1 フレームのミリ秒長 (RFC 3551)
pub const FRAME_MS: u32 = 20;

/// G.711 μ-law エンコード (linear16 PCM → ulaw)
pub fn encode_ulaw(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32635;

    let mut s = sample as i32;
    let sign = if s < 0 {
        s = -s;
        0x80u8
    } else {
        0u8
    };
    if s > CLIP {
        s = CLIP;
    }
    s += BIAS;

    // セグメント境界テーブルで exp (0-7) を決定
    let exp: u8 = if s < 256 {
        0
    } else if s < 512 {
        1
    } else if s < 1024 {
        2
    } else if s < 2048 {
        3
    } else if s < 4096 {
        4
    } else if s < 8192 {
        5
    } else if s < 16384 {
        6
    } else {
        7
    };

    let mantissa = ((s >> (exp as i32 + 3)) & 0x0f) as u8;
    !(sign | (exp << 4) | mantissa)
}

/// G.711 μ-law デコード (ulaw → linear16 PCM)
pub fn decode_ulaw(byte: u8) -> i16 {
    let byte = !byte;
    let sign = (byte & 0x80) != 0;
    let exp = ((byte >> 4) & 0x07) as i32;
    let mantissa = (byte & 0x0f) as i32;
    let magnitude = ((mantissa << 3) + 0x84) << exp.max(0);
    let val = magnitude - 0x84;
    if sign {
        -(val as i16)
    } else {
        val as i16
    }
}

/// RTP/RTCP 送信ソケットに DSCP 32 (TOS 0x80) を設定する。
///
/// NTT ひかり電話 (NGN) は RTP/RTCP に DSCP 32 を要求する。
/// IPv6 (NGN は IPv6 直結) では `IPV6_TCLASS`、IPv4 では `IP_TOS` を使う。
#[cfg(target_os = "linux")]
pub fn set_rtp_dscp(socket: &tokio::net::UdpSocket, dscp: u32) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;
    let tos = (dscp << 2) as libc::c_int;
    let fd = socket.as_raw_fd();
    unsafe {
        // IPv6 socket では IPV6_TCLASS が必要 (NGN 想定)
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        // IPv4 用 IP_TOS も保険でセット (失敗しても無視)
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TOS,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_rtp_dscp(_socket: &tokio::net::UdpSocket, _dscp: u32) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};

    #[test]
    fn test_ulaw_roundtrip() {
        // μ-law は非線形量子化なので完全一致しない
        // 低振幅ほど精度が高く、最大振幅付近では量子化ステップが大きい (最大~512)
        let cases: &[(i16, i32)] = &[
            (0, 4), // 無音: 誤差は BIAS 分のみ
            (100, 20),
            (1000, 50),
            (8000, 300),
            (32767, 700), // 最大振幅: セグメント7の量子化ステップ~512
        ];
        for &(sample, max_diff) in cases {
            for &s in &[sample, -sample] {
                let encoded = encode_ulaw(s);
                let decoded = decode_ulaw(encoded);
                let diff = (s as i32 - decoded as i32).abs();
                assert!(
                    diff <= max_diff,
                    "sample={} encoded={} decoded={} diff={} (max allowed={})",
                    s,
                    encoded,
                    decoded,
                    diff,
                    max_diff
                );
            }
        }
    }

    /// RFC 3551 §4.5.14 (PCMU encoding): silence (linear 0) は
    /// μ-law 0xFF (= ~0xFF after `! sign | exp | mantissa`) になる。
    /// "silence pattern" は VAD / DTX 連動で「無音検出時に 0xFF だけを流す」
    /// 上位層の前提となる。
    #[test]
    fn rfc3551_4_5_14_silence_encodes_to_0xff() {
        // BIAS 加算により sign=0, exp=0, mantissa=0 となり、 反転後 0xFF
        let silence = encode_ulaw(0);
        assert_eq!(
            silence, 0xFF,
            "linear 0 が μ-law 0xFF にエンコードされていない: 0x{silence:02X}"
        );
    }

    /// RFC 3551 §4.5.14 + ITU-T G.711: μ-law は対称量子化を仮定 (一部の
    /// 実装では sign 0/1 で 1 LSB ずれる)。 本実装は正/負で誤差量がほぼ
    /// 同じになることを検査し、 上位層 (echo cancel, AGC) で偏りを生まない
    /// ことを保証する。
    #[test]
    fn rfc3551_4_5_14_symmetric_quantization() {
        // 4 kHz ナイキスト直下のいくつかの代表点で正/負誤差の差が小さいこと
        for s in [100i16, 1000, 8000, 16000] {
            let pos = (s as i32 - decode_ulaw(encode_ulaw(s)) as i32).abs();
            let neg = (-s as i32 - decode_ulaw(encode_ulaw(-s)) as i32).abs();
            let diff = (pos - neg).abs();
            assert!(
                diff <= 4,
                "sample={s} で正負量子化誤差が偏っている: pos={pos} neg={neg}"
            );
        }
    }

    /// RFC 3551 §4.5.14 (静的 PT 0 = PCMU): PCMU は RTP 静的ペイロード
    /// タイプ 0 に固定。 `RtpPacket` を 160 bytes (= 20ms @ 8 kHz) で組んで
    /// PT=0 と一致することを確認する。 NGN 直収では 8 kHz/PCMU しか流せない
    /// (CLAUDE.md §5)。
    #[test]
    fn rfc3551_static_pt0_pcmu_packet_shape() {
        let payload: Vec<u8> = (0..160u32).map(|i| encode_ulaw(i as i16 * 100)).collect();
        assert_eq!(payload.len(), 160, "PCMU 1 フレームは 160 bytes (20ms)");
        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 0,
            ssrc: 0xDEAD_BEEF,
            payload: payload.clone(),
        };
        let bytes = pkt.to_bytes();
        let parsed = RtpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payload_type, 0, "PCMU 静的 PT は 0");
        assert_eq!(parsed.payload.len(), 160);
        assert_eq!(parsed.payload, payload);
    }

    /// RFC 3551 §4.5.14: μ-law の bias (`0x84`) と zero crossing 周辺の
    /// 量子化ステップが他のセグメントより細かいことを確認する。
    /// 「無音付近 ±100 では誤差が小さい」「最大振幅付近では誤差が大きい」
    /// という非線形 quantizer 特性が崩れていないかの回帰検査。
    #[test]
    fn rfc3551_4_5_14_zero_crossing_finer_than_full_scale() {
        let near_zero_err = (50_i16 as i32 - decode_ulaw(encode_ulaw(50_i16)) as i32).abs();
        let mid_err = (8000_i16 as i32 - decode_ulaw(encode_ulaw(8000_i16)) as i32).abs();
        let full_err = (32000_i16 as i32 - decode_ulaw(encode_ulaw(32000_i16)) as i32).abs();
        assert!(
            near_zero_err < mid_err,
            "zero-crossing 誤差 {} が 8000 誤差 {} 以上 (非線形特性異常)",
            near_zero_err,
            mid_err,
        );
        assert!(
            mid_err < full_err,
            "8000 誤差 {} が 32000 誤差 {} 以上 (非線形特性異常)",
            mid_err,
            full_err,
        );
    }

    /// PT 切り替え検査: RTP ヘッダの payload type は 7 bit。 PCMU (0) と
    /// 動的 PT (典型 96 / 111) を切り替えても残りのヘッダフィールドが
    /// 影響を受けないこと、 受信側で `pt == 0` の判別がきちんと機能する
    /// ことを確認する。 transcoder 層は受信 PT を見て PCMU と Opus を
    /// 分岐するため、 ここが揺らぐと音声が無音になる。
    #[test]
    fn rfc3550_5_1_pt_field_is_independent_of_other_header_fields() {
        let payload = vec![0xFFu8; 160];
        let make = |pt: u8| RtpPacket {
            payload_type: pt,
            marker: false,
            sequence: 1234,
            timestamp: 0x1000,
            ssrc: 0xAABB_CCDD,
            payload: payload.clone(),
        };

        // PCMU
        let p_pcmu = make(0);
        // Opus dynamic PT (96, 111)
        let p_opus_96 = make(96);
        let p_opus_111 = make(111);

        let b_pcmu = p_pcmu.to_bytes();
        let b_96 = p_opus_96.to_bytes();
        let b_111 = p_opus_111.to_bytes();

        // PT 以外 (2nd byte の bit 0-6 だけが変わる) は同一であること
        for (i, (a, b)) in b_pcmu.iter().zip(b_96.iter()).enumerate() {
            if i == 1 {
                continue;
            }
            assert_eq!(a, b, "byte {i} で PCMU と Opus PT=96 のヘッダが乖離");
        }
        for (i, (a, b)) in b_96.iter().zip(b_111.iter()).enumerate() {
            if i == 1 {
                continue;
            }
            assert_eq!(a, b, "byte {i} で Opus PT=96/111 のヘッダが乖離");
        }

        // パース時に PT 判別が機能すること
        assert_eq!(RtpPacket::from_bytes(&b_pcmu).unwrap().payload_type, 0);
        assert_eq!(RtpPacket::from_bytes(&b_96).unwrap().payload_type, 96);
        assert_eq!(RtpPacket::from_bytes(&b_111).unwrap().payload_type, 111);

        // PCMU 判別子 (静的 PT 0) が他と確実に違うこと
        assert_ne!(PAYLOAD_TYPE_ULAW, 96);
        assert_ne!(PAYLOAD_TYPE_ULAW, 111);
    }
}
