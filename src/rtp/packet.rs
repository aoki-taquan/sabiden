//! RTP パケット (RFC 3550 §5.1) 構造とシリアライズ/パース
//!
//! Phase 1 では V=2, P=0, X=0, CC=0, M=0 の最小ヘッダのみ生成し、
//! 受信時はマーカー・CSRC まで読み取れるよう柔軟にパースする。

use anyhow::Result;

/// G.711 μ-law (RFC 3551 §4.5.14)
pub const PAYLOAD_TYPE_ULAW: u8 = 0;
/// G.711 A-law (RFC 3551 §4.5.14)
pub const PAYLOAD_TYPE_ALAW: u8 = 8;
/// 8000 Hz サンプリング (G.711)
pub const SAMPLE_RATE: u32 = 8000;
/// 1 フレーム 20ms = 160 サンプル (G.711)
pub const SAMPLES_PER_FRAME: usize = (SAMPLE_RATE * 20 / 1000) as usize;

/// RTP パケット (RFC 3550 §5.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    pub payload_type: u8,
    pub marker: bool,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

impl RtpPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.payload.len());
        // V=2, P=0, X=0, CC=0
        buf.push(0b1000_0000);
        let m_bit = if self.marker { 0x80 } else { 0 };
        buf.push(m_bit | (self.payload_type & 0x7f));
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// RFC 3550 §5.1 に従いヘッダをパース。CSRC・拡張ヘッダはスキップする。
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            anyhow::bail!("RTP パケットが短すぎる: {} bytes", data.len());
        }
        let version = data[0] >> 6;
        if version != 2 {
            anyhow::bail!("RTP バージョン不正: {}", version);
        }
        let padding = (data[0] & 0x20) != 0;
        let extension = (data[0] & 0x10) != 0;
        let cc = (data[0] & 0x0f) as usize;
        let marker = (data[1] & 0x80) != 0;
        let payload_type = data[1] & 0x7f;
        let sequence = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let mut offset = 12 + cc * 4;
        if data.len() < offset {
            anyhow::bail!("CSRC 領域不足: csrc_count={} len={}", cc, data.len());
        }
        if extension {
            // RFC 3550 §5.3.1: profile(2) + length(2) + length*4
            if data.len() < offset + 4 {
                anyhow::bail!("拡張ヘッダ不足");
            }
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4 + ext_len * 4;
            if data.len() < offset {
                anyhow::bail!("拡張ヘッダ長不足");
            }
        }

        let mut end = data.len();
        if padding {
            // 末尾バイトがパディング長
            let pad_len = data[end - 1] as usize;
            if pad_len == 0 || pad_len > end - offset {
                anyhow::bail!("パディング長不正: {}", pad_len);
            }
            end -= pad_len;
        }

        let payload = data[offset..end].to_vec();
        Ok(RtpPacket {
            payload_type,
            marker,
            sequence,
            timestamp,
            ssrc,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_packet_roundtrip() {
        let pkt = RtpPacket {
            payload_type: 0,
            marker: false,
            sequence: 12345,
            timestamp: 0xDEAD_BEEF,
            ssrc: 0xCAFE_BABE,
            payload: vec![0x01, 0x02, 0x03],
        };
        let bytes = pkt.to_bytes();
        let parsed = RtpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn test_rtp_marker_bit() {
        let pkt = RtpPacket {
            payload_type: 0,
            marker: true,
            sequence: 1,
            timestamp: 0,
            ssrc: 0xAABB_CCDD,
            payload: vec![0xff],
        };
        let bytes = pkt.to_bytes();
        assert_eq!(bytes[1] & 0x80, 0x80, "marker ビットがセットされていない");
        let parsed = RtpPacket::from_bytes(&bytes).unwrap();
        assert!(parsed.marker);
    }

    #[test]
    fn test_rtp_short_packet_rejected() {
        assert!(RtpPacket::from_bytes(&[0u8; 11]).is_err());
    }

    #[test]
    fn test_rtp_bad_version_rejected() {
        let mut bytes = RtpPacket {
            payload_type: 0,
            marker: false,
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
            payload: vec![],
        }
        .to_bytes();
        bytes[0] = 0; // V=0
        assert!(RtpPacket::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_rtp_with_csrc() {
        // CC=2 のパケットを手動で組み立て、CSRC 領域がスキップされることを確認
        let mut bytes = vec![0b1000_0010u8, 0x00, 0x00, 0x01]; // V=2 CC=2 PT=0 seq=1
        bytes.extend_from_slice(&0u32.to_be_bytes()); // ts
        bytes.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // ssrc
        bytes.extend_from_slice(&0u32.to_be_bytes()); // csrc[0]
        bytes.extend_from_slice(&0u32.to_be_bytes()); // csrc[1]
        bytes.extend_from_slice(&[0xAA, 0xBB]); // payload
        let parsed = RtpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payload, vec![0xAA, 0xBB]);
        assert_eq!(parsed.ssrc, 0x1234_5678);
    }

    #[test]
    fn test_rtp_with_padding() {
        // P=1 のパケット。末尾バイトがパディング長
        let mut bytes = vec![0b1010_0000u8, 0x00]; // V=2 P=1
        bytes.extend_from_slice(&1u16.to_be_bytes()); // seq
        bytes.extend_from_slice(&0u32.to_be_bytes()); // ts
        bytes.extend_from_slice(&0u32.to_be_bytes()); // ssrc
        bytes.extend_from_slice(&[0xAA, 0xBB]); // payload
        bytes.extend_from_slice(&[0x00, 0x00, 0x03]); // padding 3 bytes
        let parsed = RtpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payload, vec![0xAA, 0xBB]);
    }
}
