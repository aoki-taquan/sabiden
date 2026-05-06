//! RTP/RTCP (RFC 3550) + G.711 μ-law (RFC 3551) 実装
//!
//! NGN 向けに RTP パケット送受信、ジッタバッファ、RTCP SR/RR を提供する。
//! DSCP 32 (TOS 0x80) を RTP/RTCP 送信ソケットにも適用する。

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
}
