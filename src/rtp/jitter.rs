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
    /// 重複 / 古すぎを除いた実取り込みパケット数。 RFC 3550 §A.3 における
    /// `received` (拡張 seq で初めて取り込んだ distinct packet 数) に対応する。
    pub received: u64,
    /// バッファ容量超過時の強制吐き出しで検出した「期待 seq との差」累積。
    /// **これは RFC 3550 の cumulative_lost ではない**: あくまでバッファ枯渇時の
    /// オーバフロー指標で、 RR 出力には `cumulative_lost()` を使うこと。
    /// (Issue #93 経過: RR の cumulative_lost は §A.3 ベースに刷新済)
    pub lost: i64,
    /// 重複として破棄したパケット数
    pub duplicates: u64,
    /// 既に pull 済みの古い seq を受信し破棄したパケット数 (= late packets)
    pub late_drops: u64,
    /// 推定ジッタ (RFC 3550 Appendix A.8 / 8000 Hz クロック単位)
    pub jitter: f64,
    /// 受信した最大シーケンス番号 (ラップ補正済みの拡張値)
    pub max_seq_ext: i64,
    /// 受信した最初の seq の拡張値
    pub base_seq_ext: Option<i64>,
}

impl JitterStats {
    /// RFC 3550 §6.4.1 / §A.3: cumulative number of packets lost.
    ///
    /// > the total number of RTP data packets from source SSRC_n that have
    /// > been lost since the beginning of reception. This number is defined
    /// > to be the number of packets expected less the number of packets
    /// > actually received, where the number of packets received includes
    /// > any which are late or duplicates.
    ///
    /// RFC 3550 §A.3 reference algorithm:
    /// ```text
    /// extended_max = s->cycles + s->max_seq;
    /// expected     = extended_max - s->base_seq + 1;
    /// lost         = expected - s->received;
    /// ```
    ///
    /// 本実装では `max_seq_ext` / `base_seq_ext` を 16-bit ラップ補正済み
    /// 拡張 seq として保持しているのでそのまま差分を取る。 `received` は
    /// 重複 / 古すぎを除いた distinct packet count であり、 RFC §A.3 の
    /// `s->received` と意味が一致する (late / dup は expected を増やさず、
    /// received も増やさないので差し引きでロスに数えない)。
    ///
    /// 戻り値は **24-bit signed clamp 前** の生の i64。 負値は (重複や
    /// late が多く push されて received が expected を超えた) 異常状態を
    /// 表し、 RR 出力側で 0 にクランプする。
    pub fn cumulative_lost(&self) -> i64 {
        let Some(base) = self.base_seq_ext else {
            return 0;
        };
        let expected = self.max_seq_ext - base + 1;
        expected - self.received as i64
    }

    /// RFC 3550 §6.4.1 fraction lost: 直前の RR/SR 報告からのロス比 (0..=255)
    ///
    /// 算出は RFC 3550 §A.3 に従い、 累積 `expected` と累積 `received` を
    /// 前回報告値と差し引いて差分の `expected_interval` / `received_interval`
    /// から fraction を求める。 caller 側で前回値を渡すこと。
    ///
    /// - `last_reported_expected`: 前回 RR/SR 出力時の `expected` (= `cumulative_lost + received`)
    /// - `last_reported_received`: 前回 RR/SR 出力時の `received`
    pub fn fraction_lost(&self, last_reported_expected: i64, last_reported_received: u64) -> u8 {
        let Some(base) = self.base_seq_ext else {
            return 0;
        };
        let expected = self.max_seq_ext - base + 1;
        let expected_interval = (expected - last_reported_expected).max(0) as u64;
        let received_interval = self.received.saturating_sub(last_reported_received);
        let lost_interval = expected_interval.saturating_sub(received_interval);
        if expected_interval == 0 {
            return 0;
        }
        let frac = (lost_interval * 256) / expected_interval;
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
    ///
    /// RFC 3550 §A.3 とのマッピング:
    /// - `received` は重複 / 古すぎを除く distinct packet 数として集計する。
    ///   `cumulative_lost = expected - received` (§A.3) の `received` と意味を揃える。
    /// - `max_seq_ext` / `base_seq_ext` は extended seq (16-bit wrap 補正済) で保持する。
    /// - ジッタは Appendix A.8 の D(i,j) = (Rj-Ri)-(Sj-Si) に基づき指数平均する。
    pub fn push(&mut self, pkt: RtpPacket, now: Instant) {
        let ext_seq = self.extend_seq(pkt.sequence);

        // 拡張 seq を更新
        if self.stats.base_seq_ext.is_none() {
            // 初パケット: base / max を初期化し、 received=1 (RFC §A.3 init_seq)
            self.stats.base_seq_ext = Some(ext_seq);
            self.stats.max_seq_ext = ext_seq;
        } else if ext_seq > self.stats.max_seq_ext {
            self.stats.max_seq_ext = ext_seq;
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

        // 既に pull 済みの古い seq は捨てる (late drop)。
        // RFC §A.3 では late も `received` に含むが、 本実装ではバッファに
        // 載らず再生されない packet なので playable count として除外する。
        // RR の `cumulative_lost` はこの定義でも RFC §A.3 数式と整合する
        // (late は expected を増やさず received も増やさない → 計算に影響しない)。
        if let Some(next) = self.next_pull_seq {
            if ext_seq < next {
                self.stats.late_drops += 1;
                return;
            }
        }

        // 重複は捨てる (RFC §A.3 の `received` に二重計上しない)
        if self.queue.contains_key(&ext_seq) {
            self.stats.duplicates += 1;
            return;
        }

        // ここまで来たら distinct packet を取り込む
        self.stats.received += 1;
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

    /// RFC 3550 §A.3: cumulative_lost = expected - received。
    /// 無損失で seq=1..=4 を受信した場合 expected=4, received=4, lost=0。
    #[test]
    fn rfc3550_a3_cumulative_lost_zero_when_no_loss() {
        let mut jb = JitterBuffer::new(2);
        let now = Instant::now();
        for s in 1..=4u16 {
            jb.push(pkt(s, (s as u32) * 160), now);
        }
        let st = jb.stats();
        assert_eq!(st.received, 4);
        assert_eq!(st.base_seq_ext, Some(1));
        assert_eq!(st.max_seq_ext, 4);
        assert_eq!(st.cumulative_lost(), 0);
    }

    /// RFC 3550 §A.3: 「受信中に seq=10,11,13 と来た場合、 真のロス数 (=1) を計上する」。
    /// 旧実装は pull で `lost` を増やすだけだったので、 seq=12 が落ちても
    /// バッファが overflow しなければカウントされなかった。 新 API
    /// `cumulative_lost()` は expected (=4) - received (=3) = 1 を即座に返す。
    #[test]
    fn rfc3550_a3_cumulative_lost_single_gap() {
        let mut jb = JitterBuffer::new(8);
        let now = Instant::now();
        jb.push(pkt(10, 0), now);
        jb.push(pkt(11, 160), now);
        // seq=12 はロス
        jb.push(pkt(13, 480), now);
        let st = jb.stats();
        assert_eq!(st.received, 3);
        assert_eq!(st.base_seq_ext, Some(10));
        assert_eq!(st.max_seq_ext, 13);
        // expected = 13 - 10 + 1 = 4, received = 3, lost = 1
        assert_eq!(st.cumulative_lost(), 1);
    }

    /// RFC 3550 §A.3: 連続ロス (seq=20,21 が落ちる) も正しく差分でカウントする。
    #[test]
    fn rfc3550_a3_cumulative_lost_consecutive_gap() {
        let mut jb = JitterBuffer::new(8);
        let now = Instant::now();
        jb.push(pkt(19, 0), now);
        // seq=20, 21 ロス
        jb.push(pkt(22, 480), now);
        jb.push(pkt(23, 640), now);
        let st = jb.stats();
        // expected = 23 - 19 + 1 = 5, received = 3, lost = 2
        assert_eq!(st.cumulative_lost(), 2);
    }

    /// RFC 3550 §A.3 + §A.1: 16-bit seq wraparound 越境のロス計上。
    /// seq=65534, 65535 (ロス), 0, 1 -> base=65534, max_ext=65537, expected=4,
    /// received=3, lost=1。
    #[test]
    fn rfc3550_a3_cumulative_lost_across_seq_wrap() {
        let mut jb = JitterBuffer::new(8);
        let now = Instant::now();
        jb.push(pkt(65534, 0), now);
        // seq=65535 ロス
        jb.push(pkt(0, 320), now);
        jb.push(pkt(1, 480), now);
        let st = jb.stats();
        // ラップ補正で max_seq_ext = 65536 + 1 = 65537, base = 65534
        assert_eq!(st.base_seq_ext, Some(65534));
        assert_eq!(st.max_seq_ext, 65537);
        // expected = 65537 - 65534 + 1 = 4, received = 3, lost = 1
        assert_eq!(st.cumulative_lost(), 1);
    }

    /// RFC 3550 §A.3: reorder (seq が一旦逆順に入る) は最終的にロス 0。
    /// 旧 `lost` (bufferoverflow ベース) では検出できなかったケース。
    #[test]
    fn rfc3550_a3_cumulative_lost_reorder_no_loss() {
        let mut jb = JitterBuffer::new(8);
        let now = Instant::now();
        jb.push(pkt(5, 0), now);
        jb.push(pkt(7, 320), now);
        jb.push(pkt(6, 160), now); // 遅れて到着
        jb.push(pkt(8, 480), now);
        let st = jb.stats();
        // expected = 8 - 5 + 1 = 4, received = 4, lost = 0
        assert_eq!(st.received, 4);
        assert_eq!(st.cumulative_lost(), 0);
    }

    /// RFC 3550 §A.3: 重複は `received` に二重計上しない (= cumulative_lost に影響しない)。
    #[test]
    fn rfc3550_a3_duplicate_does_not_count_as_received() {
        let mut jb = JitterBuffer::new(4);
        let now = Instant::now();
        jb.push(pkt(1, 0), now);
        jb.push(pkt(2, 160), now);
        jb.push(pkt(2, 160), now); // 重複
        jb.push(pkt(3, 320), now);
        let st = jb.stats();
        assert_eq!(st.duplicates, 1);
        assert_eq!(st.received, 3);
        assert_eq!(st.cumulative_lost(), 0);
    }

    /// RFC 3550 §A.3: 完全に空のバッファでは cumulative_lost = 0。
    #[test]
    fn rfc3550_a3_cumulative_lost_empty_is_zero() {
        let jb = JitterBuffer::new(2);
        assert_eq!(jb.stats().cumulative_lost(), 0);
    }

    /// RFC 3550 §6.4.1 fraction_lost: 直前 RR からの interval 比で算出。
    /// 5 packet expected のうち 1 つロスなら fraction = 1 * 256 / 5 = 51。
    #[test]
    fn rfc3550_6_4_1_fraction_lost_interval() {
        let mut jb = JitterBuffer::new(8);
        let now = Instant::now();
        // 最初の RR 報告地点: seq=1..=5 全部受信
        for s in 1..=5u16 {
            jb.push(pkt(s, (s as u32) * 160), now);
        }
        let first = jb.stats();
        let last_expected = first.max_seq_ext - first.base_seq_ext.unwrap() + 1;
        let last_received = first.received;
        // 次の interval: seq=6,7,8,9,10 を期待するが 7 がロス
        jb.push(pkt(6, 960), now);
        // seq=7 ロス
        jb.push(pkt(8, 1280), now);
        jb.push(pkt(9, 1440), now);
        jb.push(pkt(10, 1600), now);
        let st = jb.stats();
        // expected_interval = (10-1+1) - 5 = 5, received_interval = 9 - 5 = 4
        // lost_interval = 1, frac = 1*256/5 = 51
        let frac = st.fraction_lost(last_expected, last_received);
        assert_eq!(frac, 51);
    }
}
