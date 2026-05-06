/// RTP (RFC 3550) + G.711 μ-law (ulaw) の基本実装
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::debug;

static SEQ: AtomicU16 = AtomicU16::new(0);

pub const PAYLOAD_TYPE_ULAW: u8 = 0; // G.711 μ-law
pub const SAMPLE_RATE: u32 = 8000;
pub const FRAME_MS: u32 = 20;
pub const SAMPLES_PER_FRAME: usize = (SAMPLE_RATE * FRAME_MS / 1000) as usize; // 160

#[derive(Debug, Clone)]
pub struct RtpPacket {
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

impl RtpPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.payload.len());
        // V=2, P=0, X=0, CC=0, M=0
        buf.push(0b10000000);
        buf.push(self.payload_type & 0x7f);
        buf.push((self.sequence >> 8) as u8);
        buf.push(self.sequence as u8);
        buf.push((self.timestamp >> 24) as u8);
        buf.push((self.timestamp >> 16) as u8);
        buf.push((self.timestamp >> 8) as u8);
        buf.push(self.timestamp as u8);
        buf.push((self.ssrc >> 24) as u8);
        buf.push((self.ssrc >> 16) as u8);
        buf.push((self.ssrc >> 8) as u8);
        buf.push(self.ssrc as u8);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            anyhow::bail!("RTP パケットが短すぎる: {} bytes", data.len());
        }
        let payload_type = data[1] & 0x7f;
        let sequence = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let payload = data[12..].to_vec();
        Ok(RtpPacket { payload_type, sequence, timestamp, ssrc, payload })
    }
}

pub struct RtpSession {
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    ssrc: u32,
    timestamp: Arc<AtomicU32>,
}

impl RtpSession {
    pub fn new(socket: Arc<UdpSocket>, remote: SocketAddr) -> Self {
        let ssrc: u32 = rand::random();
        Self {
            socket,
            remote,
            ssrc,
            timestamp: Arc::new(AtomicU32::new(rand::random())),
        }
    }

    pub async fn send_ulaw(&self, pcm_ulaw: &[u8]) -> Result<()> {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let ts = self.timestamp.fetch_add(SAMPLES_PER_FRAME as u32, Ordering::SeqCst);

        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            sequence: seq,
            timestamp: ts,
            ssrc: self.ssrc,
            payload: pcm_ulaw.to_vec(),
        };

        let bytes = pkt.to_bytes();
        debug!("RTP 送信: seq={} ts={} len={}", seq, ts, bytes.len());
        self.socket.send_to(&bytes, self.remote).await?;
        Ok(())
    }

    pub async fn recv(&self) -> Result<RtpPacket> {
        let mut buf = vec![0u8; 1500];
        let (n, _) = self.socket.recv_from(&mut buf).await?;
        RtpPacket::from_bytes(&buf[..n])
    }
}

/// G.711 μ-law エンコード (linear16 PCM → ulaw)
pub fn encode_ulaw(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32635;

    let mut s = sample as i32;
    let sign = if s < 0 { s = -s; 0x80u8 } else { 0u8 };
    if s > CLIP { s = CLIP; }
    s += BIAS;

    // セグメント境界テーブルで exp (0-7) を決定
    let exp: u8 = if s < 256 { 0 }
                  else if s < 512 { 1 }
                  else if s < 1024 { 2 }
                  else if s < 2048 { 3 }
                  else if s < 4096 { 4 }
                  else if s < 8192 { 5 }
                  else if s < 16384 { 6 }
                  else { 7 };

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
    if sign { -(val as i16) } else { val as i16 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ulaw_roundtrip() {
        // μ-law は非線形量子化なので完全一致しない
        // 低振幅ほど精度が高く、最大振幅付近では量子化ステップが大きい (最大~512)
        let cases: &[(i16, i32)] = &[
            (0, 4),        // 無音: 誤差は BIAS 分のみ
            (100, 20),
            (1000, 50),
            (8000, 300),
            (32767, 700),  // 最大振幅: セグメント7の量子化ステップ~512
        ];
        for &(sample, max_diff) in cases {
            for &s in &[sample, -sample] {
                let encoded = encode_ulaw(s);
                let decoded = decode_ulaw(encoded);
                let diff = (s as i32 - decoded as i32).abs();
                assert!(
                    diff <= max_diff,
                    "sample={} encoded={} decoded={} diff={} (max allowed={})",
                    s, encoded, decoded, diff, max_diff
                );
            }
        }
    }

    #[test]
    fn test_rtp_packet_roundtrip() {
        let pkt = RtpPacket {
            payload_type: 0,
            sequence: 12345,
            timestamp: 0xDEADBEEF,
            ssrc: 0xCAFEBABE,
            payload: vec![0x01, 0x02, 0x03],
        };
        let bytes = pkt.to_bytes();
        let parsed = RtpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sequence, 12345);
        assert_eq!(parsed.timestamp, 0xDEADBEEF);
        assert_eq!(parsed.ssrc, 0xCAFEBABE);
        assert_eq!(parsed.payload, vec![0x01, 0x02, 0x03]);
    }
}
