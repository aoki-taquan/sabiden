//! RTP セッション (RFC 3550)
//!
//! 1 通話分の片方向ストリーム送信状態 + 受信側 SSRC 別のジッタバッファを保持する。
//! 双方向通話は本構造体 1 つで完結する (上位レイヤから `send_ulaw` と `recv` を呼ぶ)。
//!
//! - 送信: 単調増加する seq, ts (8000Hz, G.711 1フレーム = 160 サンプル)
//! - 受信: SSRC 毎にジッタバッファを作り、並べ替え後のパケットを取り出す
//! - RTCP: 送受信パケット数・octet 数・ジッタを集計し SR / RR を生成する
//! - DSCP: `set_rtp_dscp(&socket, 32)` を `RtpSession::new` で適用する

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

use crate::rtp::jitter::{JitterBuffer, JitterStats, DEFAULT_DEPTH};
use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW, SAMPLES_PER_FRAME};
use crate::rtp::rtcp::{NtpTimestamp, ReceiverReport, ReportBlock, SenderReport};
use crate::rtp::set_rtp_dscp;

/// RTP セッションの統計値スナップショット
#[derive(Debug, Clone, Copy, Default)]
pub struct RtpSessionStats {
    pub sent_packets: u64,
    pub sent_octets: u64,
    pub recv_packets: u64,
    pub recv_octets: u64,
    pub jitter: f64,
    pub lost: i64,
    pub max_seq_ext: i64,
}

/// RTP セッション (1 通話 / 1 メディアフロー)
pub struct RtpSession {
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    /// 自送信側 SSRC
    ssrc: u32,
    /// 自送信 seq (16-bit 単調増加, ラップする)
    seq: AtomicU16,
    /// 自送信 RTP timestamp (8000Hz)
    timestamp: AtomicU32,
    /// 累積送信パケット数
    sent_packets: AtomicU64,
    /// 累積送信 payload octet 数 (ヘッダ含まず) -- RFC 3550 §6.4.1
    sent_octets: AtomicU64,
    /// 累積受信パケット数
    recv_packets: AtomicU64,
    /// 累積受信 octet 数
    recv_octets: AtomicU64,
    /// 受信 SSRC ごとのジッタバッファ
    inbound: Mutex<HashMap<u32, JitterBuffer>>,
    /// 直近送信した SR の (NTP middle32, 送信時刻)。RR の DLSR 計算に使う
    last_sr: Mutex<Option<(u32, Instant)>>,
    /// ジッタバッファの深度 (パケット数)
    depth: usize,
    /// 受信 SSRC を初めて見たときの最終直近 SR 時刻のメモ
    remote_last_sr_recv: Mutex<HashMap<u32, (u32, Instant)>>,
}

impl RtpSession {
    /// 新規セッションを作成。`socket` は事前に bind 済みであること。
    /// DSCP 32 を本ソケットに適用する。
    pub fn new(socket: Arc<UdpSocket>, remote: SocketAddr) -> Result<Self> {
        Self::with_depth(socket, remote, DEFAULT_DEPTH)
    }

    pub fn with_depth(socket: Arc<UdpSocket>, remote: SocketAddr, depth: usize) -> Result<Self> {
        // RTP/RTCP にも DSCP 32 (TOS 0x80) を適用する (NGN 要件)
        set_rtp_dscp(&socket, 32)?;
        let ssrc: u32 = rand::random();
        Ok(Self {
            socket,
            remote,
            ssrc,
            seq: AtomicU16::new(rand::random()),
            timestamp: AtomicU32::new(rand::random()),
            sent_packets: AtomicU64::new(0),
            sent_octets: AtomicU64::new(0),
            recv_packets: AtomicU64::new(0),
            recv_octets: AtomicU64::new(0),
            inbound: Mutex::new(HashMap::new()),
            last_sr: Mutex::new(None),
            depth,
            remote_last_sr_recv: Mutex::new(HashMap::new()),
        })
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// G.711 μ-law 1 フレームを送る。`pcm_ulaw` の長さは通常 160 バイト。
    pub async fn send_ulaw(&self, pcm_ulaw: &[u8]) -> Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let ts = self
            .timestamp
            .fetch_add(SAMPLES_PER_FRAME as u32, Ordering::SeqCst);

        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: seq,
            timestamp: ts,
            ssrc: self.ssrc,
            payload: pcm_ulaw.to_vec(),
        };

        let bytes = pkt.to_bytes();
        trace!("RTP 送信: seq={} ts={} len={}", seq, ts, bytes.len());
        self.socket.send_to(&bytes, self.remote).await?;
        self.sent_packets.fetch_add(1, Ordering::Relaxed);
        self.sent_octets
            .fetch_add(pcm_ulaw.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// 任意の payload を送る (将来の DTMF / Opus 用)。timestamp 増分は呼び出し側責任。
    pub async fn send_payload(
        &self,
        payload_type: u8,
        ts_increment: u32,
        marker: bool,
        payload: &[u8],
    ) -> Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let ts = self.timestamp.fetch_add(ts_increment, Ordering::SeqCst);
        let pkt = RtpPacket {
            payload_type: payload_type & 0x7f,
            marker,
            sequence: seq,
            timestamp: ts,
            ssrc: self.ssrc,
            payload: payload.to_vec(),
        };
        let bytes = pkt.to_bytes();
        self.socket.send_to(&bytes, self.remote).await?;
        self.sent_packets.fetch_add(1, Ordering::Relaxed);
        self.sent_octets
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// 受信した raw RTP バイトをジッタバッファに投入する。
    /// 上位ループで `socket.recv_from` -> `ingest_raw` -> `pull` の流れに使う。
    pub fn ingest_raw(&self, data: &[u8]) -> Result<()> {
        let pkt = RtpPacket::from_bytes(data)?;
        self.ingest_packet(pkt);
        Ok(())
    }

    /// パース済み RTP パケットをジッタバッファに投入。
    pub fn ingest_packet(&self, pkt: RtpPacket) {
        let len = pkt.payload.len() as u64;
        self.recv_packets.fetch_add(1, Ordering::Relaxed);
        self.recv_octets.fetch_add(len, Ordering::Relaxed);
        let now = Instant::now();
        let mut map = self.inbound.lock().expect("inbound mutex poisoned");
        let jb = map
            .entry(pkt.ssrc)
            .or_insert_with(|| JitterBuffer::new(self.depth));
        jb.push(pkt, now);
    }

    /// 指定 SSRC のジッタバッファから 1 パケット取り出す。
    pub fn pull(&self, ssrc: u32) -> Option<RtpPacket> {
        let mut map = self.inbound.lock().expect("inbound mutex poisoned");
        map.get_mut(&ssrc).and_then(|jb| jb.pull())
    }

    /// 任意の取り出し可能なパケットを 1 つ返す (SSRC 不問)。
    pub fn pull_any(&self) -> Option<RtpPacket> {
        let mut map = self.inbound.lock().expect("inbound mutex poisoned");
        for jb in map.values_mut() {
            if let Some(p) = jb.pull() {
                return Some(p);
            }
        }
        None
    }

    /// UDP ソケットから 1 パケット受信して、RTP としてジッタバッファに投入する。
    /// 上位ループ用ヘルパ。
    pub async fn recv_once(&self) -> Result<()> {
        let mut buf = vec![0u8; 1500];
        let (n, _src) = self.socket.recv_from(&mut buf).await?;
        if let Err(e) = self.ingest_raw(&buf[..n]) {
            warn!("RTP パース失敗 ({} bytes): {}", n, e);
        }
        Ok(())
    }

    pub fn stats(&self) -> RtpSessionStats {
        let mut combined = RtpSessionStats {
            sent_packets: self.sent_packets.load(Ordering::Relaxed),
            sent_octets: self.sent_octets.load(Ordering::Relaxed),
            recv_packets: self.recv_packets.load(Ordering::Relaxed),
            recv_octets: self.recv_octets.load(Ordering::Relaxed),
            jitter: 0.0,
            lost: 0,
            max_seq_ext: 0,
        };
        let map = self.inbound.lock().expect("inbound mutex poisoned");
        // 複数 SSRC がいれば最大ジッタを採用する
        for jb in map.values() {
            let s = jb.stats();
            if s.jitter > combined.jitter {
                combined.jitter = s.jitter;
            }
            // RFC 3550 §A.3: cumulative_lost = expected - received。
            // Issue #93 で旧 `s.lost` (バッファ overflow ベース) から差し替え。
            combined.lost += s.cumulative_lost();
            if s.max_seq_ext > combined.max_seq_ext {
                combined.max_seq_ext = s.max_seq_ext;
            }
        }
        combined
    }

    /// 受信 SSRC ごとのジッタ統計
    pub fn jitter_stats(&self) -> HashMap<u32, JitterStats> {
        let map = self.inbound.lock().expect("inbound mutex poisoned");
        map.iter().map(|(k, v)| (*k, v.stats())).collect()
    }

    /// SR (Sender Report) を生成する (RFC 3550 §6.4.1)
    pub fn build_sr(&self) -> SenderReport {
        let now_ntp = NtpTimestamp::now();
        let now_inst = Instant::now();
        let rtp_ts = self.timestamp.load(Ordering::Relaxed);
        let reports = self.build_report_blocks(now_inst);
        // SR 送信時刻を記録 (RFC 3550 §6.4.1 LSR/DLSR)
        let mut last_sr = self.last_sr.lock().expect("last_sr mutex poisoned");
        *last_sr = Some((now_ntp.middle32(), now_inst));
        SenderReport {
            ssrc: self.ssrc,
            ntp: now_ntp,
            rtp_timestamp: rtp_ts,
            packet_count: self.sent_packets.load(Ordering::Relaxed) as u32,
            octet_count: self.sent_octets.load(Ordering::Relaxed) as u32,
            reports,
        }
    }

    /// RR (Receiver Report) を生成する。送信していないセッション (受信専用) でも使える。
    pub fn build_rr(&self) -> ReceiverReport {
        let reports = self.build_report_blocks(Instant::now());
        ReceiverReport {
            ssrc: self.ssrc,
            reports,
        }
    }

    fn build_report_blocks(&self, now: Instant) -> Vec<ReportBlock> {
        let map = self.inbound.lock().expect("inbound mutex poisoned");
        let last_sr_recv = self
            .remote_last_sr_recv
            .lock()
            .expect("remote_last_sr_recv mutex poisoned");
        map.iter()
            .take(31)
            .map(|(ssrc, jb)| {
                let s = jb.stats();
                // RFC 3550 §6.4.1 / §A.3: cumulative_lost = expected - received
                // (24-bit signed, clamp to 0 for under-flow).
                // 旧実装は `s.lost` (バッファ overflow 検出ベースの近似値) を
                // 使っていたため真のロス数を反映しなかった (Issue #93)。
                let cum_signed = s.cumulative_lost();
                let cum = cum_signed.max(0) as u32 & 0x00FF_FFFF;
                let frac = if let Some(base) = s.base_seq_ext {
                    let expected = (s.max_seq_ext - base + 1).max(0) as u64;
                    let lost_total = cum_signed.max(0) as u64;
                    (lost_total * 256)
                        .checked_div(expected)
                        .map(|v| v.min(255) as u8)
                        .unwrap_or(0)
                } else {
                    0
                };
                let (last_sr, dlsr) = last_sr_recv
                    .get(ssrc)
                    .map(|(mid, inst)| {
                        let elapsed = now.saturating_duration_since(*inst);
                        // RFC 3550 §6.4.1: DLSR は 1/65536 秒単位
                        let dlsr = (elapsed.as_secs_f64() * 65_536.0) as u32;
                        (*mid, dlsr)
                    })
                    .unwrap_or((0, 0));
                ReportBlock {
                    ssrc: *ssrc,
                    fraction_lost: frac,
                    cumulative_lost: cum,
                    extended_highest_seq: s.max_seq_ext as u32,
                    jitter: s.jitter as u32,
                    last_sr,
                    delay_since_last_sr: dlsr,
                }
            })
            .collect()
    }

    /// 相手から受信した SR を記録する (RR 生成時の LSR/DLSR 計算用)。
    pub fn record_remote_sr(&self, sr: &SenderReport) {
        let mut map = self
            .remote_last_sr_recv
            .lock()
            .expect("remote_last_sr_recv mutex poisoned");
        map.insert(sr.ssrc, (sr.ntp.middle32(), Instant::now()));
        debug!(
            "相手 SR 記録: ssrc=0x{:08x} pkts={} octets={}",
            sr.ssrc, sr.packet_count, sr.octet_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::packet::SAMPLES_PER_FRAME;

    async fn make_session() -> Arc<RtpSession> {
        // Linux/IPv4 ループバックで bind。CI でも動くように IPv6 ではなく v4。
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // 適当な相手アドレスを向ける (実送信はしない)
        let remote = socket.local_addr().unwrap();
        Arc::new(RtpSession::new(Arc::new(socket), remote).unwrap())
    }

    #[tokio::test]
    async fn ingest_and_pull_in_order() {
        let s = make_session().await;
        for i in 1..=5u16 {
            let pkt = RtpPacket {
                payload_type: PAYLOAD_TYPE_ULAW,
                marker: false,
                sequence: i,
                timestamp: i as u32 * SAMPLES_PER_FRAME as u32,
                ssrc: 0xABCD_1234,
                payload: vec![0xff; 160],
            };
            s.ingest_packet(pkt);
        }
        // depth=4 を満たした上で投入数 5 個 → 順序通りに取り出せる
        let mut got = Vec::new();
        while let Some(p) = s.pull(0xABCD_1234) {
            got.push(p.sequence);
        }
        assert!(
            got.windows(2).all(|w| w[0] < w[1]),
            "降順 pull はあり得ない"
        );
        assert!(!got.is_empty());
        assert_eq!(got.first().copied(), Some(1));
        assert_eq!(s.stats().recv_packets, 5);
    }

    #[tokio::test]
    async fn build_sr_increments_counts() {
        let s = make_session().await;
        // 自分宛にループバック送信し、ingest 経由で受信側もカウント
        let payload = vec![0u8; 160];
        s.send_ulaw(&payload).await.unwrap();
        s.send_ulaw(&payload).await.unwrap();

        let sr = s.build_sr();
        assert_eq!(sr.ssrc, s.ssrc());
        assert_eq!(sr.packet_count, 2);
        assert_eq!(sr.octet_count, 320);
    }

    #[tokio::test]
    async fn rr_has_report_block_per_ssrc() {
        let s = make_session().await;
        for ssrc in [0x1111_1111u32, 0x2222_2222u32] {
            for i in 1..=4u16 {
                s.ingest_packet(RtpPacket {
                    payload_type: 0,
                    marker: false,
                    sequence: i,
                    timestamp: 0,
                    ssrc,
                    payload: vec![0; 160],
                });
            }
        }
        let rr = s.build_rr();
        assert_eq!(rr.reports.len(), 2);
    }

    #[tokio::test]
    async fn record_remote_sr_affects_dlsr() {
        let s = make_session().await;
        // ダミー SSRC のパケットを 1 つ ingest して inbound に登録
        s.ingest_packet(RtpPacket {
            payload_type: 0,
            marker: false,
            sequence: 1,
            timestamp: 0,
            ssrc: 0xFEED_FACE,
            payload: vec![0; 160],
        });
        let sr = SenderReport {
            ssrc: 0xFEED_FACE,
            ntp: NtpTimestamp {
                seconds: 0xAABB_CCDD,
                fraction: 0x1122_3344,
            },
            rtp_timestamp: 0,
            packet_count: 0,
            octet_count: 0,
            reports: vec![],
        };
        s.record_remote_sr(&sr);
        let rr = s.build_rr();
        let rb = rr
            .reports
            .iter()
            .find(|rb| rb.ssrc == 0xFEED_FACE)
            .expect("Report block 必要");
        assert_eq!(rb.last_sr, sr.ntp.middle32());
    }

    #[tokio::test]
    async fn send_ulaw_actually_emits_packet() {
        // 送信先ソケットを別途 bind して受け取る
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s = Arc::new(RtpSession::new(Arc::new(send_sock), recv_addr).unwrap());

        s.send_ulaw(&[0xff; 160]).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let (n, _) = recv_sock.recv_from(&mut buf).await.unwrap();
        let pkt = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(pkt.payload_type, PAYLOAD_TYPE_ULAW);
        assert_eq!(pkt.payload.len(), 160);
        assert_eq!(pkt.ssrc, s.ssrc());
    }
}
