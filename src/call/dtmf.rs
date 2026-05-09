//! DTMF 中継 (RFC 4733 telephone-event ⇔ SIP INFO 双方向)
//!
//! sabiden は B2BUA として 2 つのレッグ (NGN ⇔ 内線) の間で DTMF を
//! 透過する責務を負う。本モジュールは以下を提供する:
//!
//! 1. **RFC 4733 §2.3 telephone-event RTP payload のパース / 構築**
//!    - 4 バイト固定ヘッダ: `event(8) | E|R|volume(7) | duration(16)`
//!    - DTMF 0-15 (0..9, *, #, A..D, flash) を `event` 番号で表現
//! 2. **DTMF 文字 ⇔ event 番号** の変換 (RFC 4733 §3.2)
//! 3. **SIP INFO `application/dtmf-relay`** body のパース / 生成
//!    (Cisco/Avaya 由来の de-facto 仕様。RFC 6086 自体は body フォーマット
//!    を規定しないが、`Signal=<digit>\r\nDuration=<ms>\r\n` 形式が広く使われる)
//! 4. **INFO → RFC 4733 RTP packet 列の生成** (interop bridge)
//!    - 1 押下を `start (M=1) → 中間繰り返し → end (E=1) を 3 回` の packet
//!      列に展開する (RFC 4733 §2.5.1.2 Reliability of End packets)
//!
//! # 注意 (NGN 制約)
//!
//! - NGN レッグの SDP は `restrict_audio_to_pcmu_with_dtmf` で
//!   `0 PCMU/8000` + `101 telephone-event/8000` を提示する。fmtp は
//!   `0-15` (RFC 4733 §3.2 の DTMF event 全体) を許容。
//! - RTP timestamp は audio と共通クロック (8000 Hz)。本モジュールは
//!   timestamp / sequence の払い出しを呼び出し側に委ねるため、payload と
//!   marker bit のみ生成する。
//! - 本モジュールは IO を持たない。RTP socket への送信や INFO の TU
//!   ディスパッチは `orchestrator.rs` 側に閉じる。

use anyhow::{anyhow, Result};

use crate::rtp::packet::RtpPacket;

/// RFC 4733 §3.2 で規定された telephone-event の RTP payload type 番号は
/// セッションごとに動的に決まる (typical 101)。SDP の rtpmap で合意される。
///
/// sabiden は SDP オファ / アンサで PT=101 を使う前提で固定する
/// (`SessionDescription::pcmu_offer_with_dtmf` と整合)。
pub const PAYLOAD_TYPE_TELEPHONE_EVENT: u8 = 101;

/// RFC 4733 telephone-event の RTP payload (4 バイト)。
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E|R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - `event`: DTMF event 番号 (0..15 で 0-9 / `*` / `#` / A..D / flash)
/// - `E` (end): 押下終了パケットで 1
/// - `R` (reserved): 0
/// - `volume`: -dBm0 (0..63 のうち 0..36 が DTMF 用)
/// - `duration`: イベント継続時間 (RTP clock 単位、PCMU では 8000 Hz)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelephoneEvent {
    pub event: u8,
    pub end: bool,
    pub volume: u8,
    pub duration: u16,
}

impl TelephoneEvent {
    /// 4 バイトに encode する。`Self` は `Copy` なので `self` を値で取る
    /// (clippy `wrong_self_convention` 対応)。
    pub fn into_payload(self) -> [u8; 4] {
        // 上位 1 ビット = E、次 1 ビット = R(=0)、下位 6 ビット = volume
        let e_bit = if self.end { 0x80 } else { 0 };
        let volume = self.volume & 0x3f;
        [
            self.event,
            e_bit | volume,
            (self.duration >> 8) as u8,
            (self.duration & 0xff) as u8,
        ]
    }

    /// 4 バイト payload を decode する。
    pub fn from_payload(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(anyhow!(
                "telephone-event payload は 4 バイト必須: {} バイト",
                data.len()
            ));
        }
        let event = data[0];
        let flags = data[1];
        let end = (flags & 0x80) != 0;
        let volume = flags & 0x3f;
        let duration = u16::from_be_bytes([data[2], data[3]]);
        Ok(Self {
            event,
            end,
            volume,
            duration,
        })
    }
}

/// DTMF 文字 → RFC 4733 §3.2 event 番号。
///
/// `0`-`9` → 0..9、`*` → 10、`#` → 11、`A`-`D` → 12..15。
/// その他 (空白 / `,` / `w` 等の dial pause 系) は `None` を返す。
pub fn digit_to_event(digit: char) -> Option<u8> {
    match digit {
        '0'..='9' => Some((digit as u8) - b'0'),
        '*' => Some(10),
        '#' => Some(11),
        'A'..='D' => Some(12 + (digit as u8) - b'A'),
        'a'..='d' => Some(12 + (digit as u8) - b'a'),
        _ => None,
    }
}

/// RFC 4733 §3.2 event 番号 → DTMF 文字。範囲外なら `None`。
pub fn event_to_digit(event: u8) -> Option<char> {
    match event {
        0..=9 => Some((b'0' + event) as char),
        10 => Some('*'),
        11 => Some('#'),
        12..=15 => Some((b'A' + (event - 12)) as char),
        _ => None,
    }
}

/// SIP INFO `application/dtmf-relay` body をパースする。
///
/// Cisco / Avaya / Polycom 由来の de-facto 仕様で広く使われる形式:
///
/// ```text
/// Signal=1\r\n
/// Duration=200\r\n
/// ```
///
/// または `Signal=*` のように記号が直接入る。RFC 6086 自体は body 形式を
/// 規定しないが、`Content-Type: application/dtmf-relay` でこの形を使う UA
/// (Linphone, baresip 等) がある。
///
/// 戻り値: (digit char, duration_ms)。`Duration=` が無ければ既定 250ms。
pub fn parse_application_dtmf_relay(body: &[u8]) -> Result<(char, u32)> {
    let text = std::str::from_utf8(body)?;
    let mut signal: Option<char> = None;
    let mut duration_ms: u32 = 250;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Signal=") {
            let rest = rest.trim();
            // 数字 1 文字 (例: "1") か記号 (例: "*") を取り出す
            if let Some(c) = rest.chars().next() {
                signal = Some(c);
            }
        } else if let Some(rest) = line.strip_prefix("Duration=") {
            let rest = rest.trim();
            if let Ok(n) = rest.parse::<u32>() {
                duration_ms = n;
            }
        }
    }
    let signal = signal.ok_or_else(|| anyhow!("dtmf-relay body に Signal= が無い"))?;
    Ok((signal, duration_ms))
}

/// SIP INFO `application/dtmf` body (`<digit>` 1 文字) をパースする。
///
/// SIPp / Asterisk 由来の最小形式。Body は数字 1 文字または `*` `#` のみ。
pub fn parse_application_dtmf(body: &[u8]) -> Result<char> {
    let text = std::str::from_utf8(body)?.trim();
    text.chars().next().ok_or_else(|| anyhow!("dtmf body が空"))
}

/// 1 回の DTMF 押下を表現する RFC 4733 RTP packet 列。
///
/// RFC 4733 §2.5.1.2 (Reliability of End packets):
/// > The receiver of the events will not necessarily see them all because
/// > some may be lost in transit. The end of an event is therefore signaled
/// > by setting the end bit, with this last packet sent as a triplet to
/// > offer redundancy against packet loss.
///
/// よって列の最後 3 packet は `end=true` (E=1) で同一 timestamp / 同一
/// duration を持つ retransmission となる。
///
/// 本構造体は `Vec<RtpPacket>` を生成するヘルパであり、socket 送信は
/// 呼び出し側 (orchestrator) が行う。
#[derive(Debug, Clone)]
pub struct DtmfPacketSequence {
    pub packets: Vec<RtpPacket>,
}

/// DTMF を RFC 4733 §2.5 に従って RTP packet 列に展開する。
///
/// パラメータ:
/// - `event`: digit_to_event 済の event 番号
/// - `start_seq`: 最初の packet の sequence (以降 +1 ずつ)
/// - `start_timestamp`: 最初の packet の RTP timestamp (RFC 4733 §2.5.1.1)
///   PCMU 8kHz 想定で同じ session の audio timestamp と共通クロック。
/// - `ssrc`: 同 session の audio SSRC と独立して払い出して良い (RFC 4733 §2.4)
/// - `duration_ms`: 押下の総継続時間 (ミリ秒)。8000Hz 換算で `duration` フィールドに
///   入る。RFC 4733 例では 100ms 程度の `period_ms` 単位で繰り返し packet を送る。
/// - `period_ms`: packet 送信間隔 (ms)。RFC 4733 §2.5.1.1 では 50ms が典型。
///
/// # 構造
///
/// 1. 1 個目: `event=event, end=false, M=1 (start), duration=period_ms*8`
/// 2. 続き: `end=false, M=0, duration=2*period_ms*8, 3*period_ms*8, ...`
///    `duration_ms` を超えるまで生成
/// 3. 最後 3 個: `end=true, M=0, duration=duration_ms*8` (同値の triplet)
///
/// `period_ms = 0` または `duration_ms = 0` の場合は最小限 (start + end triplet)
/// で構成する。
pub fn build_dtmf_packet_sequence(
    event: u8,
    start_seq: u16,
    start_timestamp: u32,
    ssrc: u32,
    duration_ms: u32,
    period_ms: u32,
    volume: u8,
) -> DtmfPacketSequence {
    const CLOCK_HZ: u32 = 8000;
    let total_duration_units = ((duration_ms.max(1)) * CLOCK_HZ / 1000).min(u16::MAX as u32) as u16;
    let period_units = if period_ms == 0 {
        total_duration_units
    } else {
        ((period_ms * CLOCK_HZ / 1000).min(u16::MAX as u32) as u16).max(1)
    };

    let mut packets: Vec<RtpPacket> = Vec::new();
    let mut seq = start_seq;
    let mut accumulated: u16 = period_units;
    let mut first = true;

    // 中間 packet (E=0): duration が total に達するまで送り続ける。
    loop {
        let cur_duration = accumulated.min(total_duration_units);
        let evt = TelephoneEvent {
            event,
            end: false,
            volume,
            duration: cur_duration,
        };
        packets.push(RtpPacket {
            payload_type: PAYLOAD_TYPE_TELEPHONE_EVENT,
            // RFC 4733 §2.5.1.2: 押下開始の最初の packet で marker=1。
            marker: first,
            sequence: seq,
            timestamp: start_timestamp,
            ssrc,
            payload: evt.into_payload().to_vec(),
        });
        seq = seq.wrapping_add(1);
        first = false;
        if cur_duration >= total_duration_units {
            break;
        }
        accumulated = accumulated.saturating_add(period_units);
    }

    // 終端 packet を 3 連送 (RFC 4733 §2.5.1.2)。同 timestamp、同 duration。
    let final_evt = TelephoneEvent {
        event,
        end: true,
        volume,
        duration: total_duration_units,
    };
    let final_payload = final_evt.into_payload().to_vec();
    for _ in 0..3 {
        packets.push(RtpPacket {
            payload_type: PAYLOAD_TYPE_TELEPHONE_EVENT,
            marker: false,
            sequence: seq,
            timestamp: start_timestamp,
            ssrc,
            payload: final_payload.clone(),
        });
        seq = seq.wrapping_add(1);
    }

    DtmfPacketSequence { packets }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4733 §3.2: digit ⇔ event 番号 全マッピングをラウンドトリップで確認。
    #[test]
    fn rfc4733_3_2_digit_event_round_trip() {
        for (digit, expected) in [
            ('0', 0u8),
            ('1', 1),
            ('2', 2),
            ('3', 3),
            ('4', 4),
            ('5', 5),
            ('6', 6),
            ('7', 7),
            ('8', 8),
            ('9', 9),
            ('*', 10),
            ('#', 11),
            ('A', 12),
            ('B', 13),
            ('C', 14),
            ('D', 15),
        ] {
            assert_eq!(digit_to_event(digit), Some(expected), "digit={digit}");
            assert_eq!(event_to_digit(expected), Some(digit), "event={expected}");
        }
        // 範囲外の event は None
        assert_eq!(event_to_digit(16), None);
        // 大文字小文字両対応
        assert_eq!(digit_to_event('a'), Some(12));
        assert_eq!(digit_to_event('d'), Some(15));
        // ダイアル pause 系は None
        assert_eq!(digit_to_event(','), None);
        assert_eq!(digit_to_event(' '), None);
    }

    /// RFC 4733 §2.3: 4 バイト payload のラウンドトリップ。
    #[test]
    fn rfc4733_2_3_telephone_event_payload_round_trip() {
        let evt = TelephoneEvent {
            event: 1, // digit '1'
            end: false,
            volume: 10,
            duration: 800, // 100ms @ 8kHz
        };
        let bytes = evt.into_payload();
        assert_eq!(bytes, [0x01, 0x0a, 0x03, 0x20]);
        let parsed = TelephoneEvent::from_payload(&bytes).unwrap();
        assert_eq!(parsed, evt);
    }

    /// RFC 4733 §2.3: end bit が立った payload。
    #[test]
    fn rfc4733_2_3_end_bit_encoded_in_msb_of_byte_2() {
        let evt = TelephoneEvent {
            event: 11, // '#'
            end: true,
            volume: 5,
            duration: 1600, // 200ms @ 8kHz
        };
        let bytes = evt.into_payload();
        // byte0 = 11 = 0x0b, byte1 = 0x80 (E) | 0x05 (volume) = 0x85
        assert_eq!(bytes[0], 0x0b);
        assert_eq!(bytes[1], 0x85);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 1600);

        let parsed = TelephoneEvent::from_payload(&bytes).unwrap();
        assert!(parsed.end);
        assert_eq!(parsed.event, 11);
    }

    /// 短すぎる payload はエラー。
    #[test]
    fn telephone_event_short_payload_errors() {
        assert!(TelephoneEvent::from_payload(&[0u8; 3]).is_err());
    }

    /// `application/dtmf-relay` body パース (Cisco/Avaya 形式)。
    #[test]
    fn dtmf_relay_body_parse_signal_and_duration() {
        let body = b"Signal=1\r\nDuration=200\r\n";
        let (sig, dur) = parse_application_dtmf_relay(body).unwrap();
        assert_eq!(sig, '1');
        assert_eq!(dur, 200);
    }

    /// `application/dtmf-relay` body: 記号 (`*`)。
    #[test]
    fn dtmf_relay_body_parse_star() {
        let body = b"Signal=*\r\nDuration=160\r\n";
        let (sig, dur) = parse_application_dtmf_relay(body).unwrap();
        assert_eq!(sig, '*');
        assert_eq!(dur, 160);
    }

    /// `application/dtmf-relay` body: Duration が無いと既定 250ms。
    #[test]
    fn dtmf_relay_body_default_duration() {
        let body = b"Signal=#\r\n";
        let (sig, dur) = parse_application_dtmf_relay(body).unwrap();
        assert_eq!(sig, '#');
        assert_eq!(dur, 250);
    }

    /// `application/dtmf` body は 1 文字。
    #[test]
    fn dtmf_body_parse_single_char() {
        assert_eq!(parse_application_dtmf(b"5").unwrap(), '5');
        assert_eq!(parse_application_dtmf(b"#").unwrap(), '#');
        assert_eq!(parse_application_dtmf(b"  *\r\n").unwrap(), '*');
        assert!(parse_application_dtmf(b"").is_err());
    }

    /// RFC 4733 §2.5.1.2: 押下シーケンスは marker=1 (start) で始まり
    /// 末尾 3 packet が end=true triplet で終わる。
    #[test]
    fn rfc4733_2_5_1_packet_sequence_starts_with_marker_and_ends_with_end_triplet() {
        // duration=100ms, period=50ms → 中間 2 packet + 終端 3 packet = 5 packet
        let seq = build_dtmf_packet_sequence(1, /* '1' */ 100, 1000, 0xCAFE_BABE, 100, 50, 10);
        let packets = &seq.packets;
        assert_eq!(packets.len(), 5, "100ms / 50ms 区切り = 2 packets + end x3");

        // 1 個目は marker=1 (start)
        assert!(packets[0].marker, "start packet で marker=1 必須");
        let evt0 = TelephoneEvent::from_payload(&packets[0].payload).unwrap();
        assert!(!evt0.end);
        assert_eq!(evt0.event, 1);

        // 2 個目以降の中間は marker=0
        assert!(!packets[1].marker);

        // 末尾 3 packet は end=true、同 timestamp、同 duration
        for p in &packets[packets.len() - 3..] {
            let evt = TelephoneEvent::from_payload(&p.payload).unwrap();
            assert!(evt.end, "end triplet は E=1 必須");
            assert_eq!(p.timestamp, 1000);
        }
        // sequence 番号は連続
        let mut expected_seq = 100u16;
        for p in packets {
            assert_eq!(p.sequence, expected_seq);
            expected_seq = expected_seq.wrapping_add(1);
        }
    }

    /// 全 packet が PAYLOAD_TYPE_TELEPHONE_EVENT、SSRC / start timestamp が揃っている。
    #[test]
    fn rfc4733_2_5_packet_sequence_uses_consistent_pt_ssrc_and_timestamp() {
        let seq = build_dtmf_packet_sequence(11, /* '#' */ 0, 12345, 0x1234_5678, 200, 50, 0);
        assert!(!seq.packets.is_empty());
        for p in &seq.packets {
            assert_eq!(p.payload_type, PAYLOAD_TYPE_TELEPHONE_EVENT);
            assert_eq!(p.ssrc, 0x1234_5678);
            // RFC 4733 §2.5.1.1: 同 1 押下のすべての packet で timestamp は不変
            assert_eq!(p.timestamp, 12345);
        }
    }

    /// `period_ms = 0` でも最小限 (start + end x3) は生成される。
    #[test]
    fn dtmf_zero_period_produces_minimal_sequence() {
        let seq = build_dtmf_packet_sequence(2, 0, 0, 0xAABB_CCDD, 50, 0, 0);
        // 1 (start) + 3 (end triplet) = 4
        assert_eq!(seq.packets.len(), 4);
        assert!(seq.packets[0].marker);
        for p in &seq.packets[1..] {
            let evt = TelephoneEvent::from_payload(&p.payload).unwrap();
            assert!(evt.end);
        }
    }
}
