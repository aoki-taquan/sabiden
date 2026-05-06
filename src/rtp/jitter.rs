//! ジッタバッファ (RFC 3550 §6.4.1 のジッタ計算 + 並べ替え)
//!
//! 方針:
//! - 50-100ms のターゲット深度。G.711 20ms フレーム前提なら 3-5 パケット相当
//! - シーケンス番号でソートし、最古のパケットから取り出す
//! - 重複パケットは破棄、極端に古いパケット (深度を超えた遅延) も破棄
//! - シーケンス番号は 16-bit ラップアラウンドを考慮 (符号付き差分)
//! - パケットロス・受信パケット数・破棄数を統計として保持
//!
//! ジッタ推定 (RFC 3550 Appendix A.8):
//!   D(i,j) = (Rj - Ri) - (Sj - Si)
//!   J(i)   = J(i-1) + (|D(i-1,i)| - J(i-1)) / 16

use std::collections::BTreeMap;
use std::time::Instant;

use crate::rtp::packet::RtpPacket;

/// デフォルトのジッタバッファ深度 (パケット数)。
/// G.711 20ms フレームで 4 パケット = 80ms。
pub const DEFAULT_DEPTH: usize = 4;

/// 連続性判定の許容ギャップ (これを超えるとロスとみなす)
const SEQ_REORDER_WINDOW: i32 = 3000;

/// ジッタバッファ統計 (RFC 3550 RR で報告するために保持)
#[derive(Debug, Clone, Copy, Default)]
pub struct JitterStats {
    /// 受信した総パケット数 (重複・古すぎるものを含む)
    pub received: u64,
    /// 取り出し時に検出した期待 seq とのズレの累積 (= 推定ロス)
    pub lost: i64,
    /// 重複として破棄したパケット数
    pub duplicates: u64,
    /// バッファ容量超過で破棄したパケット数
    pub late_drops: u64,
    /// 推定ジッタ (RFC 3550 Appendix A.8 / 8000 Hz クロック単位)
    pub jitter: f64,
    /// 受信した最大シーケンス番号 (ラップ補正済みの拡張値)
    pub max_seq_ext: i64,
    /// 受信した最初の seq の拡張値
    pub base_seq_ext: Option<i64>,
}

impl JitterStats {
    /// RFC 3550 §6.4.1 fraction lost: 直前の SR からのロス比 (0..=255)
    /// 単純化のため累積値ベースで計算する。
    pub fn fraction_lost(&self, last_reported_lost: i64, last_reported_recv: u64) -> u8 {
        let recv_diff = self.received.saturating_sub(last_reported_recv);
        let lost_diff = (self.lost - last_reported_lost).max(0) as u64;
        let expected = recv_diff + lost_diff;
        if expected == 0 {
            return 0;
        }
        let frac = (lost_diff * 256) / expected;
        frac.min(255) as u8
    }
}

/// 入ってきた RTP パケットを並べ替えるジッタバッファ。
pub struct JitterBuffer {
    depth: usize,
    /// 拡張シーケンス番号 → パケット
    queue: BTreeMap<i64, RtpPacket>,
    /// 次に取り出すべき拡張 seq。None なら未初期化
    next_pull_seq: Option<i64>,
    /// ジッタ計算用: 直前パケットの (RTP ts, 受信時刻)
    last_arrival: Option<(u32, Instant)>,
    /// 16-bit seq の上位ラップカウンタを管理するための直近値
    last_seq_raw: Option<u16>,
    /// 拡張 seq のオフセット (ラップ毎に +65536)
    seq_cycles: i64,
    stats: JitterStats,
}

impl JitterBuffer {
    /// 指定された深度 (パケット数) のジッタバッファを作る。
    /// `depth` が 0 の場合は最小値 1 にクランプする。
    pub fn new(depth: usize) -> Self {
        Self {
            depth: depth.max(1),
            queue: BTreeMap::new(),
            next_pull_seq: None,
            last_arrival: None,
            last_seq_raw: None,
            seq_cycles: 0,
            stats: JitterStats::default(),
        }
    }

    /// 50-100ms 相当のデフォルト深度で生成。
    pub fn with_default_depth() -> Self {
        Self::new(DEFAULT_DEPTH)
    }

    pub fn stats(&self) -> JitterStats {
        self.stats
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// パケットを投入する。受信時刻 `now` はテスト用に注入可能。
    pub fn push(&mut self, pkt: RtpPacket, now: Instant) {
        self.stats.received += 1;
        let ext_seq = self.extend_seq(pkt.sequence);

        // 拡張 seq を更新
        if ext_seq > self.stats.max_seq_ext {
            self.stats.max_seq_ext = ext_seq;
        }
        if self.stats.base_seq_ext.is_none() {
            self.stats.base_seq_ext = Some(ext_seq);
        }

        // ジッタ更新 (RFC 3550 Appendix A.8)
        if let Some((prev_ts, prev_arrival)) = self.last_arrival {
            // 受信間隔を 8000 Hz クロック単位に変換
            let arrival_delta_secs = now.saturating_duration_since(prev_arrival).as_secs_f64();
            let arrival_ticks = arrival_delta_secs * 8000.0;
            let ts_delta = (pkt.timestamp.wrapping_sub(prev_ts)) as i32 as f64;
            let d = (arrival_ticks - ts_delta).abs();
            self.stats.jitter += (d - self.stats.jitter) / 16.0;
        }
        self.last_arrival = Some((pkt.timestamp, now));

        // 既に pull 済みの古い seq は捨てる
        if let Some(next) = self.next_pull_seq {
            if ext_seq < next {
                self.stats.late_drops += 1;
                return;
            }
        }

        // 重複は捨てる
        if self.queue.contains_key(&ext_seq) {
            self.stats.duplicates += 1;
            return;
        }

        self.queue.insert(ext_seq, pkt);

        // 容量を超えた場合は最古を強制的に取り出す代わりにフラグを立てる
        // 実際の取り出しは pull() の責務とし、ここでは超過分を late_drops しない
    }

    /// 次のパケットを取り出す。
    /// バッファが `depth` に満たない場合は None (まだ待つ)。
    /// ロスを検出した場合 (期待 seq が無いが後続が揃っている) は None を返さず先頭を出す。
    pub fn pull(&mut self) -> Option<RtpPacket> {
        // 初期化前: 一定数たまるまで待つ
        if self.next_pull_seq.is_none() {
            if self.queue.len() < self.depth {
                return None;
            }
            // 最古の seq を起点とする
            let &first = self.queue.keys().next()?;
            self.next_pull_seq = Some(first);
        }

        // 通常時はバッファが depth 未満なら待つ。ただし溢れている時は強制 pull。
        if self.queue.len() < self.depth && self.queue.len() < self.depth.saturating_mul(2) {
            // 期待 seq のパケットがあれば返す。無ければ None (ロス疑い -> 待つ)
            let next = self.next_pull_seq?;
            if let Some(pkt) = self.queue.remove(&next) {
                self.next_pull_seq = Some(next + 1);
                return Some(pkt);
            }
            return None;
        }

        // バッファが溢れている: 期待 seq を超えてでも先頭を出す (ロスを確定)
        let next = self.next_pull_seq?;
        if let Some(pkt) = self.queue.remove(&next) {
            self.next_pull_seq = Some(next + 1);
            return Some(pkt);
        }
        // 先頭 seq まで進める (ロス分を加算)
        let &first = self.queue.keys().next()?;
        let lost = first - next;
        if lost > 0 {
            self.stats.lost += lost;
        }
        let pkt = self.queue.remove(&first)?;
        self.next_pull_seq = Some(first + 1);
        Some(pkt)
    }

    /// バッファに残っているパケットを期待 seq 順に全て吐き出す。通話終了時用。
    pub fn drain(&mut self) -> Vec<RtpPacket> {
        let mut out = Vec::with_capacity(self.queue.len());
        let mut next = self
            .next_pull_seq
            .or_else(|| self.queue.keys().next().copied())
            .unwrap_or(0);
        while let Some((&seq, _)) = self.queue.iter().next() {
            if seq > next {
                self.stats.lost += seq - next;
            }
            let pkt = self.queue.remove(&seq).expect("seq just iterated");
            next = seq + 1;
            out.push(pkt);
        }
        self.next_pull_seq = Some(next);
        out
    }

    /// 16-bit RTP seq を 32-bit 拡張 seq へ補正する。
    fn extend_seq(&mut self, seq: u16) -> i64 {
        match self.last_seq_raw {
            None => {
                self.last_seq_raw = Some(seq);
                self.seq_cycles = 0;
                seq as i64
            }
            Some(last) => {
                let diff = (seq as i32) - (last as i32);
                if diff < -SEQ_REORDER_WINDOW {
                    // 大きく前進したと解釈 (ラップ)
                    self.seq_cycles += 1 << 16;
                    self.last_seq_raw = Some(seq);
                } else if diff > SEQ_REORDER_WINDOW {
                    // 大きく後退したと解釈 (前のラップ周回のパケット)
                    return self.seq_cycles - (1 << 16) + seq as i64;
                } else if diff > 0 {
                    self.last_seq_raw = Some(seq);
                }
                self.seq_cycles + seq as i64
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(seq: u16, ts: u32) -> RtpPacket {
        RtpPacket {
            payload_type: 0,
            marker: false,
            sequence: seq,
            timestamp: ts,
            ssrc: 0xDEAD_BEEF,
            payload: vec![seq as u8],
        }
    }

    #[test]
    fn ordered_pull_after_buffer_fill() {
        let mut jb = JitterBuffer::new(3);
        let now = Instant::now();
        // depth=3 を満たすまで pull は None
        jb.push(pkt(1, 0), now);
        assert!(jb.pull().is_none());
        jb.push(pkt(2, 160), now);
        assert!(jb.pull().is_none());
        jb.push(pkt(3, 320), now);
        assert_eq!(jb.pull().unwrap().sequence, 1);
    }

    #[test]
    fn reorder_then_pull_in_order() {
        let mut jb = JitterBuffer::new(3);
        let now = Instant::now();
        jb.push(pkt(2, 160), now);
        jb.push(pkt(1, 0), now);
        jb.push(pkt(3, 320), now);
        let seqs: Vec<u16> = (0..3)
            .filter_map(|_| jb.pull().map(|p| p.sequence))
            .collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn duplicate_dropped() {
        let mut jb = JitterBuffer::new(2);
        let now = Instant::now();
        jb.push(pkt(10, 0), now);
        jb.push(pkt(10, 0), now);
        assert_eq!(jb.stats().duplicates, 1);
    }

    #[test]
    fn loss_detected_when_buffer_overflows() {
        let mut jb = JitterBuffer::new(2);
        let now = Instant::now();
        // seq=1,2 を入れて pull で初期化
        jb.push(pkt(1, 0), now);
        jb.push(pkt(2, 160), now);
        assert_eq!(jb.pull().unwrap().sequence, 1);
        // seq=3 はロスし、seq=4,5,6 を投入。バッファが depth*2 で強制吐き出し
        jb.push(pkt(4, 480), now);
        jb.push(pkt(5, 640), now);
        jb.push(pkt(6, 800), now);
        // 期待 seq=2 -> 取り出せる
        assert_eq!(jb.pull().unwrap().sequence, 2);
        // 期待 seq=3 -> 無いがバッファ過多 -> 4 を返してロス +1
        let p = jb.pull().unwrap();
        assert_eq!(p.sequence, 4);
        assert_eq!(jb.stats().lost, 1);
    }

    #[test]
    fn seq_wraparound_handled() {
        let mut jb = JitterBuffer::new(2);
        let now = Instant::now();
        jb.push(pkt(65534, 0), now);
        jb.push(pkt(65535, 160), now);
        jb.push(pkt(0, 320), now);
        jb.push(pkt(1, 480), now);
        let mut got = Vec::new();
        while let Some(p) = jb.pull() {
            got.push(p.sequence);
        }
        assert_eq!(got, vec![65534, 65535, 0, 1]);
    }

    #[test]
    fn jitter_increases_with_irregular_arrival() {
        // G.711: 1 フレーム = 160 サンプル / 8000 Hz
        const FRAME_TS: u32 = 160;
        let mut jb = JitterBuffer::new(8);
        let mut now = Instant::now();
        for i in 0..10u16 {
            // 受信間隔を不均一にする
            now += std::time::Duration::from_millis(if i % 2 == 0 { 10 } else { 30 });
            jb.push(pkt(i + 1, i as u32 * FRAME_TS), now);
        }
        assert!(jb.stats().jitter > 0.0, "ジッタは正でなければならない");
    }

    #[test]
    fn drain_returns_all_remaining() {
        let mut jb = JitterBuffer::new(2);
        let now = Instant::now();
        jb.push(pkt(1, 0), now);
        jb.push(pkt(2, 160), now);
        jb.push(pkt(3, 320), now);
        let _ = jb.pull();
        let rest = jb.drain();
        assert_eq!(rest.len(), 2);
    }
}
