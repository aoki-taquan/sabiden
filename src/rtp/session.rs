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
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

use crate::rtp::jitter::{JitterBuffer, JitterStats, DEFAULT_DEPTH};
use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW, SAMPLES_PER_FRAME};
use crate::rtp::rtcp::{NtpTimestamp, ReceiverReport, ReportBlock, SenderReport};
use crate::rtp::{set_rtp_dscp, RECV_BUF_SIZE};

/// Talkspurt 境界判定の閾値 (RFC 3551 §4.1 / RFC 7587 §4.4)。
///
/// PCMU 1 フレーム = 20 ms (RFC 3551 §4.5.14) なので、 直前送信から
/// 30 ms 以上経過 (= フレーム 1.5 本分) を「連続音声区間が途切れた」
/// と判定し、 次のパケットに M=1 を立てる。 これは Issue #84 で要請された
/// 「talkspurt 開始の M=1」の根本対処であり、 受信側 (NGN / WebRTC stack)
/// の adaptive jitter buffer が talkspurt 境界を認識できるようにする。
///
/// 30 ms という値は RFC で明示されていないが、 (a) 20 ms (= 1 frame 周期)
/// より長くないと jitter で false positive する、 (b) 40 ms (= silence
/// 検出器の最短窓) より短くないと talkspurt 開始を逃す、 という両端の制約
/// から PCMU の場合 30 ms を採用する。 Opus DTX 復帰 (RFC 7587 §3.7) も
/// silence packet 4 個 = 80 ms 以上の gap で発火するので 30 ms で十分に
/// 検出できる。
///
/// # 限界 (false positive の可能性)
///
/// 30 ms 閾値は近似値: PCMU 20 ms 周期で 1 frame loss (= 40 ms gap) を
/// talkspurt 境界と誤判定する可能性がある。 ただし旧実装 (常に M=0) からは
/// regression ではなく、 受信側 adaptive jitter buffer の微小な playout
/// 再計算で吸収される。 将来 false-positive 抑制が必要なら 50 ms+ への
/// 引き上げを別 Issue で検討する (PCMU 2 frame loss = 60 ms+ なら確実に
/// talkspurt 境界扱い)。
const TALKSPURT_GAP_THRESHOLD: Duration = Duration::from_millis(30);

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
    /// 直近 `send_ulaw` 送出時刻。 talkspurt 境界判定に使う (RFC 3551 §4.1)。
    /// 初回送信 (= `None`) もしくは [`TALKSPURT_GAP_THRESHOLD`] 以上空いたら
    /// 次パケットで M=1 を立てる (Issue #84)。
    last_send_time: Mutex<Option<Instant>>,
    /// RFC 3550 §6.4.1 / §A.3 fraction_lost interval 計算用の per-SSRC 前回値。
    /// `(last_reported_expected, last_reported_received)` を保持し、
    /// `build_report_blocks` 出力後に最新累積値で更新する。
    last_reported_per_ssrc: Mutex<HashMap<u32, (i64, u64)>>,
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
            last_send_time: Mutex::new(None),
            last_reported_per_ssrc: Mutex::new(HashMap::new()),
        })
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// G.711 μ-law 1 フレームを送る。`pcm_ulaw` の長さは通常 160 バイト。
    ///
    /// # Marker bit (RFC 3551 §4.1 / RFC 3550 §5.1)
    ///
    /// RFC 3551 §4.1: audio profile における marker bit semantics。 silence
    /// suppression / DTX 復帰後の最初の talkspurt packet で M=1 を立て、
    /// 受信側 jitter buffer に「ここから連続音声」と通知する。 marker bit の
    /// 解釈そのものは RFC 3550 §5.1 が profile に委譲しており、 audio profile
    /// (RFC 3551) では talkspurt の先頭マーキングが該当する。
    ///
    /// 本実装は `last_send_time` を保持し、 (a) 初回送信、 もしくは
    /// (b) 直前送信から [`TALKSPURT_GAP_THRESHOLD`] (= 30 ms) 以上経過した場合に
    /// M=1 を立てる。 30 ms は PCMU 1 frame 周期 (20 ms) と silence detector
    /// の最短窓 (40 ms) の中間値であり、 false positive と false negative の
    /// 両方を避ける (Issue #84)。
    pub async fn send_ulaw(&self, pcm_ulaw: &[u8]) -> Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let ts = self
            .timestamp
            .fetch_add(SAMPLES_PER_FRAME as u32, Ordering::SeqCst);

        // talkspurt 境界判定: 直前送信からの経過時間で決める。
        // mutex は本関数内のみで保持する短いスコープ。
        let now = Instant::now();
        let marker = {
            let mut last = self
                .last_send_time
                .lock()
                .expect("last_send_time mutex poisoned");
            let is_talkspurt_start = match *last {
                None => true,
                Some(prev) => now.saturating_duration_since(prev) >= TALKSPURT_GAP_THRESHOLD,
            };
            *last = Some(now);
            is_talkspurt_start
        };

        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker,
            sequence: seq,
            timestamp: ts,
            ssrc: self.ssrc,
            payload: pcm_ulaw.to_vec(),
        };

        let bytes = pkt.to_bytes();
        trace!(
            "RTP 送信: seq={} ts={} len={} M={}",
            seq,
            ts,
            bytes.len(),
            marker as u8
        );
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
    ///
    /// バッファサイズは [`RECV_BUF_SIZE`] (9000 byte, jumbo frame 上限) を用いる。
    /// RFC 3550 §5.1 RTP ヘッダ (12 byte + 任意 CSRC 60 byte + RFC 5285 拡張) と
    /// §6.4 compound RTCP (SR/SDES/BYE 連結) が 1500 byte を超える場合に備える。
    /// `n == RECV_BUF_SIZE` の場合は MSG_TRUNC 相当 (Linux 上の tokio は expose しない)
    /// と推定して警告ログを残す (Issue #96)。
    pub async fn recv_once(&self) -> Result<()> {
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        let (n, _src) = self.socket.recv_from(&mut buf).await?;
        if n == RECV_BUF_SIZE {
            warn!(
                bytes = n,
                "RTP/RTCP datagram が受信バッファ上限 ({} byte) に達しました — \
                 truncate の可能性 (RFC 3550 §5.1 / §6.4, Issue #96)",
                RECV_BUF_SIZE
            );
        }
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

    /// RFC 3550 §6.4.1 / Appendix A.3 に従い RR / SR の各 SSRC 向け
    /// report block を構築する。 `fraction_lost` は **直前の RR/SR 報告以降の
    /// interval 内で観測したロス比** として算出する (§6.4.1 原文:
    /// "expressed as a fixed point number with the binary point at the left
    /// edge of the field … the fraction of RTP data packets from source SSRC_n
    /// lost since the previous SR or RR packet was sent").
    ///
    /// 旧実装は累積 `cumulative_lost * 256 / expected` を返していたため、
    /// 通話初期に発生したロスが永続的に fraction として残り続け、 受信側 NW
    /// 品質の **直近** 状態を反映しなかった (Issue #199 / PR #196 follow-up)。
    /// 本実装は各 SSRC について `(last_reported_expected, last_reported_received)`
    /// を本セッションに保持し、 報告のたびに `JitterStats::fraction_lost` へ
    /// 渡すことで差分ベースの計算を行う。 出力後に最新累積値で更新する。
    ///
    /// `cumulative_lost` は §A.3 のとおり累積値 (24-bit signed, under-flow は 0
    /// にクランプ) を返す。 `extended_highest_seq` / `jitter` / `LSR` / `DLSR`
    /// も §6.4.1 各フィールド定義に準拠。
    fn build_report_blocks(&self, now: Instant) -> Vec<ReportBlock> {
        let map = self.inbound.lock().expect("inbound mutex poisoned");
        let last_sr_recv = self
            .remote_last_sr_recv
            .lock()
            .expect("remote_last_sr_recv mutex poisoned");
        let mut last_reported = self
            .last_reported_per_ssrc
            .lock()
            .expect("last_reported_per_ssrc mutex poisoned");
        map.iter()
            .take(31)
            .map(|(ssrc, jb)| {
                let s = jb.stats();
                // RFC 3550 §6.4.1 / §A.3: cumulative_lost = expected - received
                // (24-bit signed, clamp to 0 for under-flow)。
                let cum_signed = s.cumulative_lost();
                let cum = cum_signed.max(0) as u32 & 0x00FF_FFFF;

                // RFC 3550 §6.4.1 fraction_lost: 直前 RR/SR 報告以降の
                // interval (= 差分 expected / 差分 received) で算出。
                // 前回値が無ければ (last_exp, last_recv) = (0, 0) で評価され、
                // 累積全体を「最初の interval」として扱う初回 RR と整合する。
                let (last_exp, last_recv) = last_reported.get(ssrc).copied().unwrap_or((0, 0));
                let frac = s.fraction_lost(last_exp, last_recv);

                // 出力後、 次回 interval の起点として現在の累積値を保存。
                // expected = max_seq_ext - base_seq_ext + 1 (RFC §A.3)。
                if let Some(base) = s.base_seq_ext {
                    let expected_now = s.max_seq_ext - base + 1;
                    last_reported.insert(*ssrc, (expected_now, s.received));
                }

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

    /// RFC 3551 §4.1 (audio profile marker bit) — talkspurt 開始の最初の
    /// パケットに M=1 が立つ。
    ///
    /// 初回 `send_ulaw` 呼び出しは「無音 → 音声」の遷移とみなされるため
    /// (last_send_time が None)、 必ず M=1 となる。
    /// Issue #84: 旧実装は常に M=0 を送っていたため、 対向 jitter buffer は
    /// talkspurt 境界を検出できなかった。
    #[tokio::test]
    async fn rfc3551_4_1_send_ulaw_first_packet_has_marker() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s = Arc::new(RtpSession::new(Arc::new(send_sock), recv_addr).unwrap());

        s.send_ulaw(&[0xff; 160]).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let (n, _) = recv_sock.recv_from(&mut buf).await.unwrap();
        let pkt = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert!(
            pkt.marker,
            "RFC 3551 §4.1: 初回 send_ulaw の M ビットは 1 (talkspurt 開始)"
        );
    }

    /// RFC 3551 §4.1 — talkspurt 継続中 (frame 間隔 = 20 ms < 30 ms 閾値) では
    /// M=0 を維持する。
    ///
    /// 連続した `send_ulaw` 呼び出しが PCMU の 1 frame 周期 (20 ms, RFC 3551
    /// §4.5.14) 以内で行われる限り、 talkspurt 内の continuation packet として
    /// M=0 で送出される (Issue #84)。
    #[tokio::test]
    async fn rfc3551_4_1_send_ulaw_continuation_packet_has_no_marker() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s = Arc::new(RtpSession::new(Arc::new(send_sock), recv_addr).unwrap());

        // 1 個目 (M=1 を期待)
        s.send_ulaw(&[0xff; 160]).await.unwrap();
        // 即座に 2 個目 (gap = 数 µs ≪ 30 ms 閾値 → M=0 を期待)
        s.send_ulaw(&[0xff; 160]).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n1, _) = recv_sock.recv_from(&mut buf).await.unwrap();
        let pkt1 = RtpPacket::from_bytes(&buf[..n1]).unwrap();
        let (n2, _) = recv_sock.recv_from(&mut buf).await.unwrap();
        let pkt2 = RtpPacket::from_bytes(&buf[..n2]).unwrap();

        assert!(pkt1.marker, "1 個目は talkspurt 開始 (M=1) — RFC 3551 §4.1");
        assert!(
            !pkt2.marker,
            "2 個目は talkspurt 継続 (M=0) — RFC 3551 §4.1"
        );
    }

    /// RFC 3551 §4.1 / RFC 7587 §4.4 — silence / DTX 復帰後の最初のパケットに
    /// M=1 が立つ。
    ///
    /// `TALKSPURT_GAP_THRESHOLD` (= 30 ms) 以上の gap を空けて再送信した場合、
    /// 「無音区間が挟まった」とみなして M=1 を立てる。 これにより対向の
    /// adaptive jitter buffer は talkspurt 境界を検出できる (Issue #84)。
    #[tokio::test]
    async fn rfc3551_4_1_send_ulaw_after_silence_gap_has_marker() {
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s = Arc::new(RtpSession::new(Arc::new(send_sock), recv_addr).unwrap());

        // 第 1 talkspurt
        s.send_ulaw(&[0xff; 160]).await.unwrap();
        // silence gap (閾値 30 ms より大きく空ける)
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // 第 2 talkspurt 開始
        s.send_ulaw(&[0xff; 160]).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n1, _) = recv_sock.recv_from(&mut buf).await.unwrap();
        let pkt1 = RtpPacket::from_bytes(&buf[..n1]).unwrap();
        let (n2, _) = recv_sock.recv_from(&mut buf).await.unwrap();
        let pkt2 = RtpPacket::from_bytes(&buf[..n2]).unwrap();

        assert!(pkt1.marker, "第 1 talkspurt 開始の M=1");
        assert!(
            pkt2.marker,
            "silence 後の第 2 talkspurt 開始の M=1 (RFC 3551 §4.1 / RFC 7587 §4.4)"
        );
    }

    /// RFC 3550 §5.1 (extension 含む RTP packet) と §6.4 (compound RTCP) で
    /// 1500 byte を超える datagram が到来した場合に、 `recv_once` が
    /// **末尾を切り詰めない** ことを検証する。 旧 1500 byte 固定では
    /// 受信側 socket が `MSG_TRUNC` 相当で trailing byte を捨て、 上位の
    /// `RtpPacket::from_bytes` が「短いペイロード」を観測する不具合があった
    /// (Issue #96)。
    ///
    /// 本テストは PCMU PT=0 で 2000 byte の payload (合計 12 + 2000 = 2012
    /// byte) を loopback 送信し、 受信統計 `recv_octets` に **payload 全長
    /// 2000 byte が記録される** ことを確認する。 もし 1500 byte で truncate
    /// されていれば 2000 ではなく ~1488 (= 1500 - 12 byte header) になる。
    /// ローカル loopback は MTU 65535 (Linux `lo`) のため datagram は分割
    /// されず、 truncate は受信バッファ要因のみとなる。
    #[tokio::test]
    async fn rfc3550_5_1_large_rtp_packet_not_truncated_on_recv() {
        // 受信側 socket = RtpSession の入口
        let recv_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_sock.local_addr().unwrap();
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let send_addr = send_sock.local_addr().unwrap();
        let s = Arc::new(RtpSession::new(Arc::new(recv_sock), send_addr).unwrap());

        // 2000 byte payload (1500 byte IP MTU を超えるサイズ)
        let payload = vec![0xAAu8; 2000];
        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 42,
            timestamp: 12_345,
            ssrc: 0xDEAD_BEEF,
            payload: payload.clone(),
        };
        let bytes = pkt.to_bytes();
        assert!(
            bytes.len() > 1500,
            "事前条件: 検査対象 datagram は 1500 byte より大きいこと (got {})",
            bytes.len(),
        );

        // 送信 → recv_once でジッタバッファに入る
        send_sock.send_to(&bytes, recv_addr).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), s.recv_once())
            .await
            .expect("recv_once timeout")
            .expect("recv_once error");

        // 受信 payload 長が記録された octet 数と一致する (truncate 無し)
        // RFC 3550 §6.4.1: octet_count は payload のみカウント、 header 含まず。
        let stats = s.stats();
        assert_eq!(
            stats.recv_packets, 1,
            "1 datagram を受信したはず (recv_packets が増えていない)"
        );
        assert_eq!(
            stats.recv_octets, 2000,
            "受信 payload が truncate されている: 期待 2000 / 実 {} \
             (RFC 3550 §5.1 / §6.4.1 / Issue #96)",
            stats.recv_octets,
        );
    }

    /// 指定 SSRC / seq の PCMU 1 フレーム RTP パケットを `ingest_packet` 経由で
    /// 注入するヘルパ。 fraction_lost 系テストで利用。
    fn ingest_seq(s: &Arc<RtpSession>, ssrc: u32, seq: u16) {
        s.ingest_packet(RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: seq,
            timestamp: (seq as u32) * SAMPLES_PER_FRAME as u32,
            ssrc,
            payload: vec![0; 160],
        });
    }

    /// RFC 3550 §6.4.1 / Appendix A.3: 通常 loss が interval 内に分散している
    /// ケース。 seq=1..=10 のうち seq=4 がロス、 1 回目の RR で
    /// fraction_lost = 1 * 256 / 10 = 25 を観測する (初回 interval は累積全体)。
    #[tokio::test]
    async fn rfc3550_6_4_1_fraction_lost_normal_distribution() {
        let s = make_session().await;
        let ssrc = 0xCAFE_F00Du32;
        // seq=1..=10 のうち 4 を欠落させる (9 packet 受信、 expected = 10)
        for seq in [1u16, 2, 3, 5, 6, 7, 8, 9, 10] {
            ingest_seq(&s, ssrc, seq);
        }
        let rr = s.build_rr();
        let rb = rr
            .reports
            .iter()
            .find(|rb| rb.ssrc == ssrc)
            .expect("Report block 必要");
        // expected_interval = 10 (初回なので last_expected=0), received_interval = 9,
        // lost_interval = 1, frac = 1 * 256 / 10 = 25
        assert_eq!(
            rb.fraction_lost, 25,
            "初回 RR の fraction_lost = lost_interval * 256 / expected_interval"
        );
        // cumulative_lost (§A.3) = expected - received = 10 - 9 = 1
        assert_eq!(rb.cumulative_lost, 1);
    }

    /// RFC 3550 §6.4.1: fraction_lost は **直前 RR 以降** のみを反映する。
    /// 通話初期にロスが発生しても、 後続の RR では「その RR 以降の interval」
    /// だけを見て計算するので、 過去ロスは fraction として残らない。
    ///
    /// 旧実装は累積 lost を expected で割っていたため初期ロスが永続化したが、
    /// 本実装は interval 差分計算により 0 を返すべき (PR #196 follow-up)。
    #[tokio::test]
    async fn rfc3550_6_4_1_fraction_lost_only_reflects_since_last_rr() {
        let s = make_session().await;
        let ssrc = 0xBEEF_1234u32;
        // Interval 1: seq=1..=5 のうち seq=3 がロス → 4 packet 受信、 expected = 5
        for seq in [1u16, 2, 4, 5] {
            ingest_seq(&s, ssrc, seq);
        }
        let rr1 = s.build_rr();
        let rb1 = rr1
            .reports
            .iter()
            .find(|rb| rb.ssrc == ssrc)
            .expect("Report block 必要");
        // 初回 RR: expected_interval = 5, lost_interval = 1, frac = 1 * 256 / 5 = 51
        assert_eq!(rb1.fraction_lost, 51, "初回 interval の loss が反映される");
        assert_eq!(rb1.cumulative_lost, 1);

        // Interval 2: seq=6..=10 全部受信 (ロスなし)
        for seq in 6u16..=10u16 {
            ingest_seq(&s, ssrc, seq);
        }
        let rr2 = s.build_rr();
        let rb2 = rr2
            .reports
            .iter()
            .find(|rb| rb.ssrc == ssrc)
            .expect("Report block 必要");
        // 2 回目 RR: 直前 RR 以降の expected_interval = 5, received_interval = 5,
        // lost_interval = 0 → fraction = 0。 累積 cumulative_lost = 1 は維持。
        assert_eq!(
            rb2.fraction_lost, 0,
            "直前 RR 以降にロスが無ければ fraction_lost = 0 \
             (RFC 3550 §6.4.1)"
        );
        assert_eq!(
            rb2.cumulative_lost, 1,
            "cumulative_lost は累積 (RFC 3550 §A.3) なので維持"
        );
    }

    /// RFC 3550 §6.4.1: 初回 interval にロス無し → fraction_lost = 0。
    /// 続く interval にロスが発生 → fraction_lost が直近 interval だけを反映する。
    /// 本テストは「ロスなし interval は 0」「次 interval は分子差分」両方を確認。
    #[tokio::test]
    async fn rfc3550_6_4_1_fraction_lost_zero_then_nonzero() {
        let s = make_session().await;
        let ssrc = 0xDEAD_5678u32;
        // Interval 1: seq=1..=4 全部受信
        for seq in 1u16..=4u16 {
            ingest_seq(&s, ssrc, seq);
        }
        let rr1 = s.build_rr();
        let rb1 = rr1
            .reports
            .iter()
            .find(|rb| rb.ssrc == ssrc)
            .expect("Report block 必要");
        assert_eq!(
            rb1.fraction_lost, 0,
            "ロスなし interval の fraction_lost は 0"
        );
        assert_eq!(rb1.cumulative_lost, 0);

        // Interval 2: seq=5..=8 のうち seq=6 がロス
        for seq in [5u16, 7, 8] {
            ingest_seq(&s, ssrc, seq);
        }
        let rr2 = s.build_rr();
        let rb2 = rr2
            .reports
            .iter()
            .find(|rb| rb.ssrc == ssrc)
            .expect("Report block 必要");
        // expected_interval = (8 - 0 + 1) - (4 - 0 + 1) = 9 - 4 = 4,
        // (注: base_seq_ext は base、 max_seq_ext は最新値)
        // received_interval = 7 - 4 = 3, lost_interval = 1, frac = 1 * 256 / 4 = 64
        assert_eq!(
            rb2.fraction_lost, 64,
            "interval 内 1 loss / 4 expected → 256/4 = 64"
        );
        assert_eq!(rb2.cumulative_lost, 1);

        // Interval 3: seq=9..=12 全部受信 → 再度 fraction_lost = 0 に戻ること
        for seq in 9u16..=12u16 {
            ingest_seq(&s, ssrc, seq);
        }
        let rr3 = s.build_rr();
        let rb3 = rr3
            .reports
            .iter()
            .find(|rb| rb.ssrc == ssrc)
            .expect("Report block 必要");
        assert_eq!(
            rb3.fraction_lost, 0,
            "次の interval でロスが無くなれば fraction_lost は 0 に戻る"
        );
        assert_eq!(rb3.cumulative_lost, 1, "累積 loss は維持");
    }
}
