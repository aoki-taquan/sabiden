//! RTCP SR / RR (RFC 3550 §6.4)
//!
//! Phase 1 で必要な最小機能:
//! - SR (Sender Report) 生成・パース
//! - RR (Receiver Report) 生成・パース
//! - SDES CNAME (RFC 3550 §6.5) を簡易的にサポート (任意)
//!
//! NTP タイムスタンプは UNIX エポック → NTP エポック (1900年) 補正を行う。

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};

/// RTCP packet type 値 (RFC 3550 §A.11.1)
pub const PT_SR: u8 = 200;
pub const PT_RR: u8 = 201;
pub const PT_SDES: u8 = 202;
pub const PT_BYE: u8 = 203;

/// 1900-01-01 から 1970-01-01 までの秒数
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// NTP 64-bit 時刻 (上位32: 秒, 下位32: 秒の小数部 fraction)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpTimestamp {
    pub seconds: u32,
    pub fraction: u32,
}

impl NtpTimestamp {
    pub fn now() -> Self {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = dur.as_secs() + NTP_UNIX_OFFSET;
        // nanos -> 32-bit fraction: nanos * 2^32 / 1e9
        let nanos = dur.subsec_nanos() as u64;
        let fraction = ((nanos << 32) / 1_000_000_000) as u32;
        Self {
            seconds: secs as u32,
            fraction,
        }
    }

    /// SR の "NTP timestamp middle 32 bits" (RFC 3550 §6.4.1)
    pub fn middle32(&self) -> u32 {
        // 上位 16 bits of seconds + 上位 16 bits of fraction
        ((self.seconds & 0xFFFF) << 16) | (self.fraction >> 16)
    }
}

/// 1 受信元あたりの Report Block (RFC 3550 §6.4.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    /// 24-bit 累積ロス
    pub cumulative_lost: u32,
    pub extended_highest_seq: u32,
    pub jitter: u32,
    pub last_sr: u32,
    pub delay_since_last_sr: u32,
}

impl ReportBlock {
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.push(self.fraction_lost);
        let cum = self.cumulative_lost & 0x00FF_FFFF;
        buf.push((cum >> 16) as u8);
        buf.push((cum >> 8) as u8);
        buf.push(cum as u8);
        buf.extend_from_slice(&self.extended_highest_seq.to_be_bytes());
        buf.extend_from_slice(&self.jitter.to_be_bytes());
        buf.extend_from_slice(&self.last_sr.to_be_bytes());
        buf.extend_from_slice(&self.delay_since_last_sr.to_be_bytes());
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 24 {
            bail!("Report Block 長不足: {} bytes", data.len());
        }
        let ssrc = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let fraction_lost = data[4];
        let cumulative_lost = ((data[5] as u32) << 16) | ((data[6] as u32) << 8) | data[7] as u32;
        let extended_highest_seq = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let jitter = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let last_sr = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let delay_since_last_sr = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        Ok(Self {
            ssrc,
            fraction_lost,
            cumulative_lost,
            extended_highest_seq,
            jitter,
            last_sr,
            delay_since_last_sr,
        })
    }
}

/// SR (Sender Report)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    pub ssrc: u32,
    pub ntp: NtpTimestamp,
    pub rtp_timestamp: u32,
    pub packet_count: u32,
    pub octet_count: u32,
    pub reports: Vec<ReportBlock>,
}

impl SenderReport {
    pub fn to_bytes(&self) -> Vec<u8> {
        let rc = self.reports.len().min(31) as u8;
        // length は 32-bit ワード単位の "本パケット長 - 1"
        let body_len_words = (28 / 4 - 1) + (rc as usize) * 6; // SR header(28B) + reports
        let mut buf = Vec::with_capacity((body_len_words + 1) * 4);
        buf.push(0b1000_0000 | rc); // V=2 P=0 RC
        buf.push(PT_SR);
        buf.extend_from_slice(&(body_len_words as u16).to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(&self.ntp.seconds.to_be_bytes());
        buf.extend_from_slice(&self.ntp.fraction.to_be_bytes());
        buf.extend_from_slice(&self.rtp_timestamp.to_be_bytes());
        buf.extend_from_slice(&self.packet_count.to_be_bytes());
        buf.extend_from_slice(&self.octet_count.to_be_bytes());
        for rb in self.reports.iter().take(31) {
            rb.write_to(&mut buf);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (header, body) = parse_rtcp_header(data, PT_SR)?;
        if body.len() < 24 {
            bail!("SR body 長不足: {}", body.len());
        }
        let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let ntp = NtpTimestamp {
            seconds: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            fraction: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        };
        let rtp_timestamp = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
        let packet_count = u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
        let octet_count = u32::from_be_bytes([body[20], body[21], body[22], body[23]]);
        let mut reports = Vec::with_capacity(header.rc as usize);
        let mut off = 24;
        for _ in 0..header.rc {
            if body.len() < off + 24 {
                bail!("SR Report Block 不足");
            }
            reports.push(ReportBlock::from_bytes(&body[off..off + 24])?);
            off += 24;
        }
        Ok(Self {
            ssrc,
            ntp,
            rtp_timestamp,
            packet_count,
            octet_count,
            reports,
        })
    }
}

/// RR (Receiver Report)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    pub ssrc: u32,
    pub reports: Vec<ReportBlock>,
}

impl ReceiverReport {
    pub fn to_bytes(&self) -> Vec<u8> {
        let rc = self.reports.len().min(31) as u8;
        let body_len_words = (8 / 4 - 1) + (rc as usize) * 6; // RR header(8B SSRC含まず) + reports
        let mut buf = Vec::with_capacity((body_len_words + 1) * 4);
        buf.push(0b1000_0000 | rc);
        buf.push(PT_RR);
        buf.extend_from_slice(&(body_len_words as u16).to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        for rb in self.reports.iter().take(31) {
            rb.write_to(&mut buf);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (header, body) = parse_rtcp_header(data, PT_RR)?;
        if body.len() < 4 {
            bail!("RR body 長不足");
        }
        let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let mut reports = Vec::with_capacity(header.rc as usize);
        let mut off = 4;
        for _ in 0..header.rc {
            if body.len() < off + 24 {
                bail!("RR Report Block 不足");
            }
            reports.push(ReportBlock::from_bytes(&body[off..off + 24])?);
            off += 24;
        }
        Ok(Self { ssrc, reports })
    }
}

struct RtcpHeader {
    rc: u8,
    #[allow(dead_code)]
    length_words: u16,
}

fn parse_rtcp_header(data: &[u8], expected_pt: u8) -> Result<(RtcpHeader, &[u8])> {
    if data.len() < 4 {
        bail!("RTCP header 不足: {} bytes", data.len());
    }
    let v = data[0] >> 6;
    if v != 2 {
        bail!("RTCP version 不正: {}", v);
    }
    let rc = data[0] & 0x1f;
    let pt = data[1];
    if pt != expected_pt {
        bail!("RTCP PT 不一致: expected={} got={}", expected_pt, pt);
    }
    let length_words = u16::from_be_bytes([data[2], data[3]]);
    let total_bytes = (length_words as usize + 1) * 4;
    if data.len() < total_bytes {
        bail!(
            "RTCP パケット切り詰め: declared={} got={}",
            total_bytes,
            data.len()
        );
    }
    Ok((RtcpHeader { rc, length_words }, &data[4..total_bytes]))
}

/// RTCP コンパウンドパケットの最初の 1 つの種別を覗き見る (ディスパッチ用)
pub fn peek_packet_type(data: &[u8]) -> Option<u8> {
    if data.len() < 2 {
        return None;
    }
    if data[0] >> 6 != 2 {
        return None;
    }
    Some(data[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_now_is_after_2020() {
        let n = NtpTimestamp::now();
        // 2020-01-01 in NTP seconds
        let cutoff = (1577836800u64 + NTP_UNIX_OFFSET) as u32;
        assert!(n.seconds > cutoff);
    }

    #[test]
    fn sr_roundtrip() {
        let sr = SenderReport {
            ssrc: 0x1111_2222,
            ntp: NtpTimestamp {
                seconds: 0xAABB_CCDD,
                fraction: 0x1234_5678,
            },
            rtp_timestamp: 0x1000_0000,
            packet_count: 100,
            octet_count: 16000,
            reports: vec![ReportBlock {
                ssrc: 0xDEAD_BEEF,
                fraction_lost: 5,
                cumulative_lost: 0x000F_FFFF,
                extended_highest_seq: 0x0001_0000,
                jitter: 42,
                last_sr: 0xCAFE_BABE,
                delay_since_last_sr: 65536,
            }],
        };
        let bytes = sr.to_bytes();
        assert_eq!(bytes.len() % 4, 0);
        let parsed = SenderReport::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, sr);
    }

    #[test]
    fn rr_roundtrip_no_reports() {
        let rr = ReceiverReport {
            ssrc: 0x1234_5678,
            reports: vec![],
        };
        let bytes = rr.to_bytes();
        assert_eq!(bytes.len(), 8);
        let parsed = ReceiverReport::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, rr);
    }

    #[test]
    fn rr_roundtrip_with_reports() {
        let rr = ReceiverReport {
            ssrc: 0xAAAA_BBBB,
            reports: vec![
                ReportBlock {
                    ssrc: 1,
                    fraction_lost: 10,
                    cumulative_lost: 100,
                    extended_highest_seq: 200,
                    jitter: 5,
                    last_sr: 0,
                    delay_since_last_sr: 0,
                },
                ReportBlock {
                    ssrc: 2,
                    fraction_lost: 0,
                    cumulative_lost: 0,
                    extended_highest_seq: 50,
                    jitter: 1,
                    last_sr: 0xDEAD_BEEF,
                    delay_since_last_sr: 1234,
                },
            ],
        };
        let bytes = rr.to_bytes();
        let parsed = ReceiverReport::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, rr);
    }

    #[test]
    fn peek_packet_type_works() {
        let rr = ReceiverReport {
            ssrc: 0,
            reports: vec![],
        };
        let bytes = rr.to_bytes();
        assert_eq!(peek_packet_type(&bytes), Some(PT_RR));
    }

    #[test]
    fn parse_rejects_wrong_pt() {
        let rr = ReceiverReport {
            ssrc: 0,
            reports: vec![],
        };
        let bytes = rr.to_bytes();
        assert!(SenderReport::from_bytes(&bytes).is_err());
    }

    /// RFC 3550 §6.4.1 (Sender Report) は SR の "NTP timestamp" を 64-bit
    /// として書き、 同時にメディア時刻 (RTP timestamp) と相関を取る。
    /// `to_bytes` / `from_bytes` の対称性は `sr_roundtrip` で見ているが、
    /// バイトレイアウト (固定ヘッダ 28 bytes) が RFC の絵と一致するかは
    /// 別個に押さえる。
    /// レイアウト: [V/P/RC | PT=200 | length] [SSRC] [NTP sec] [NTP frac]
    ///            [RTP ts] [packet count] [octet count]
    #[test]
    fn rfc3550_6_4_1_sr_wire_layout() {
        let sr = SenderReport {
            ssrc: 0x1122_3344,
            ntp: NtpTimestamp {
                seconds: 0xAABB_CCDD,
                fraction: 0x1234_5678,
            },
            rtp_timestamp: 0x0BAD_F00D,
            packet_count: 42,
            octet_count: 8400,
            reports: vec![],
        };
        let bytes = sr.to_bytes();
        // SR (RC=0) は 28 bytes
        assert_eq!(
            bytes.len(),
            28,
            "SR 全長が 28 bytes でない: {}",
            bytes.len()
        );
        assert_eq!(bytes[0] >> 6, 2, "RTCP V=2 でない");
        assert_eq!(bytes[0] & 0x1f, 0, "RC=0 でない (reports 空)");
        assert_eq!(bytes[1], PT_SR);
        // length は 32-bit ワード単位の "本パケット長 - 1" = 6
        let length_words = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(
            length_words, 6,
            "SR length words が 6 でない: {length_words}"
        );
        // SSRC
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            0x1122_3344,
        );
        // NTP sec / frac
        assert_eq!(
            u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            0xAABB_CCDD,
        );
        assert_eq!(
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            0x1234_5678,
        );
        // RTP timestamp
        assert_eq!(
            u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            0x0BAD_F00D,
        );
        // packet / octet count
        assert_eq!(
            u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            42,
        );
        assert_eq!(
            u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            8400,
        );
    }

    /// RFC 3550 §6.4.2 (Receiver Report): RR 固定ヘッダは 8 bytes (V/P/RC, PT,
    /// length, SSRC)、 その後に Report Block が RC 個ぶら下がる。 各 Report
    /// Block は 24 bytes。
    #[test]
    fn rfc3550_6_4_2_rr_wire_layout_with_one_report() {
        let rr = ReceiverReport {
            ssrc: 0xDEAD_BEEF,
            reports: vec![ReportBlock {
                ssrc: 0xCAFE_BABE,
                fraction_lost: 0x42,
                cumulative_lost: 0x00_0102,
                extended_highest_seq: 0x0001_2345,
                jitter: 0x0000_00FF,
                last_sr: 0x1234_5678,
                delay_since_last_sr: 0x0000_0042,
            }],
        };
        let bytes = rr.to_bytes();
        assert_eq!(
            bytes.len(),
            8 + 24,
            "RR + 1 report の長さが 32 bytes でない"
        );
        assert_eq!(bytes[0] & 0x1f, 1, "RC が 1 でない");
        assert_eq!(bytes[1], PT_RR);
        let length_words = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(length_words, 7, "RR(1 report) length words=7 のはず");
        // SSRC of sender
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            0xDEAD_BEEF,
        );
        // Report Block: SSRC_1
        assert_eq!(
            u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            0xCAFE_BABE,
        );
        // fraction_lost / cumulative_lost (24-bit)
        assert_eq!(bytes[12], 0x42);
        assert_eq!(bytes[13], 0x00);
        assert_eq!(bytes[14], 0x01);
        assert_eq!(bytes[15], 0x02);
        // round-trip
        let parsed = ReceiverReport::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, rr);
    }

    /// RFC 3550 §6.1: "Each RTCP packet MUST be transmitted as a compound
    /// packet that begins with an SR or RR ...".
    /// 実際の RTCP 送信は SR + SDES などを 1 UDP datagram にまとめて出すため、
    /// `peek_packet_type` で先頭種別が SR と判別できることを検査する。
    /// (`peek_packet_type` は最初の 1 つだけ覗き見る semantics)。
    #[test]
    fn rfc3550_6_1_peek_packet_type_finds_first_in_compound() {
        let sr = SenderReport {
            ssrc: 0x1111_1111,
            ntp: NtpTimestamp {
                seconds: 0,
                fraction: 0,
            },
            rtp_timestamp: 0,
            packet_count: 0,
            octet_count: 0,
            reports: vec![],
        };
        let rr = ReceiverReport {
            ssrc: 0x2222_2222,
            reports: vec![],
        };

        // SR + RR の compound packet を組む (簡易: 単純連結)。
        // 実用上 RFC では SR/RR の後に SDES が来るが、 peek_packet_type は
        // 先頭バイトしか見ないので任意の RTCP を後続にして検証可能。
        let mut compound = sr.to_bytes();
        compound.extend(rr.to_bytes());
        assert_eq!(
            peek_packet_type(&compound),
            Some(PT_SR),
            "compound 先頭種別が SR と判別されていない"
        );
        // 先頭 SR だけパースしても、 to_bytes 長で切れていれば OK
        let head_len = 28; // SR(RC=0) のサイズ
        let parsed = SenderReport::from_bytes(&compound[..head_len]).unwrap();
        assert_eq!(parsed.ssrc, sr.ssrc);
    }

    /// RFC 3550 §A.11.1 (PT 値テーブル): SR=200, RR=201, SDES=202, BYE=203.
    /// `peek_packet_type` で PT 切り替えを検出するディスパッチケースを
    /// それぞれ確認する。 ディスパッチ層が「先頭が BYE なら teardown を
    /// 発火」「先頭が SR なら統計更新」と分岐するための前提条件。
    #[test]
    fn rfc3550_a_11_1_peek_packet_type_distinguishes_sr_rr_bye() {
        // SR
        let sr_bytes = SenderReport {
            ssrc: 1,
            ntp: NtpTimestamp {
                seconds: 0,
                fraction: 0,
            },
            rtp_timestamp: 0,
            packet_count: 0,
            octet_count: 0,
            reports: vec![],
        }
        .to_bytes();
        assert_eq!(peek_packet_type(&sr_bytes), Some(PT_SR));

        // RR
        let rr_bytes = ReceiverReport {
            ssrc: 2,
            reports: vec![],
        }
        .to_bytes();
        assert_eq!(peek_packet_type(&rr_bytes), Some(PT_RR));

        // 手組みの BYE (RFC 3550 §6.6): V=2 P=0 SC=1, PT=203, length=1, SSRC
        let bye_bytes: [u8; 8] = [
            0b1000_0001, // V=2 P=0 SC=1
            PT_BYE,
            0x00,
            0x01, // length = 1 (= 8 bytes - 4)
            0x00,
            0x00,
            0x00,
            0x03, // SSRC
        ];
        assert_eq!(peek_packet_type(&bye_bytes), Some(PT_BYE));

        // 手組みの SDES (RFC 3550 §6.5): V=2 SC=1, PT=202, length=2,
        // SSRC + CNAME item + null terminator + padding
        let sdes_bytes: [u8; 12] = [
            0b1000_0001,
            PT_SDES,
            0x00,
            0x02, // length = 2 (= 12 bytes - 4 = 8 → words=2)
            0x00,
            0x00,
            0x00,
            0x04, // SSRC
            0x01, // CNAME (item type)
            0x02, // length 2
            b'X',
            b'Y',
        ];
        assert_eq!(peek_packet_type(&sdes_bytes), Some(PT_SDES));

        // 不正バージョン: None
        let mut bad = sr_bytes.clone();
        bad[0] = 0; // V=0
        assert_eq!(peek_packet_type(&bad), None);

        // 短すぎる入力
        assert_eq!(peek_packet_type(&[]), None);
        assert_eq!(peek_packet_type(&[0xff]), None);
    }

    /// RFC 3550 §6.4.1 で SR の length フィールドは「32-bit ワード単位の
    /// パケット長 - 1」と規定。 truncation (declared > actual) を
    /// パーサが検知して reject することを確認する。
    #[test]
    fn rfc3550_6_4_1_sr_rejects_truncated_packet() {
        let sr = SenderReport {
            ssrc: 1,
            ntp: NtpTimestamp {
                seconds: 0,
                fraction: 0,
            },
            rtp_timestamp: 0,
            packet_count: 0,
            octet_count: 0,
            reports: vec![],
        };
        let bytes = sr.to_bytes();
        // 1 byte 削れば declared length と合わない
        let truncated = &bytes[..bytes.len() - 1];
        assert!(
            SenderReport::from_bytes(truncated).is_err(),
            "truncated SR が reject されていない"
        );
    }
}
