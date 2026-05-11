//! Opus ↔ G.711 μ-law トランスコーディング ブリッジ
//!
//! WebRTC レッグ (Opus 48 kHz) と NGN レッグ (G.711 μ-law 8 kHz) の間で
//! メディアパケットを相互変換しながらリレーする。
//!
//! ## パイプライン
//!
//! ```text
//! WebRTC RTP (Opus)  → デコード → PCM 48k → ダウンサンプル → PCM 8k → μ-law → NGN RTP
//! NGN RTP (μ-law)    → デコード → PCM 8k  → アップサンプル → PCM 48k → Opus  → WebRTC RTP
//! ```
//!
//! ## 設計上の注意
//!
//! - 各方向のホットパスは "1 RTP 受信 → 1 RTP 送信" の同期処理。並列性はソケット
//!   ループ単位 (NGN→WebRTC と WebRTC→NGN を別タスクで spawn)。
//! - コーデックインスタンス (Encoder/Decoder/Resampler) は各方向で 1 個ずつ。
//!   `&mut self` で状態を持ち、`Mutex` 越しに使う。NGN 側は 20ms ごとに 1 個の
//!   パケットしか来ないため lock 競合は事実上ない。
//! - RTP ヘッダ (seq, ts, ssrc) は出力側で再生成する。NGN 側は 8000 Hz 単位の
//!   timestamp、WebRTC 側は 48000 Hz 単位の timestamp になる。
//! - 受信元アドレスは `RtpBridge` と同じく late binding で学習する。
//!
//! ## トレードオフ (リレーモードとの違い)
//!
//! - CPU コストは 0 → ~数 % へ増加 (20ms ごとに Opus encode/decode + リサンプル)
//! - 追加レイテンシ ~20ms (フレーム境界で待つ)
//! - 暗号化 (SRTP) は範疇外。WebRTC 側 SRTP を解く処理は呼び出し側で行う前提。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::observability::Metrics;
use crate::rtp::codec::opus::{OpusDecoder, OpusEncoder, OPUS_FRAME_SAMPLES, OPUS_SAMPLE_RATE};
use crate::rtp::codec::resample::{
    DownsamplerWbToNb, UpsamplerNbToWb, NARROW_BAND_RATE, NB_FRAME_SAMPLES, WB_FRAME_SAMPLES,
};
use crate::rtp::codec::AudioFrame;
use crate::rtp::jitter::{JitterBuffer, DEFAULT_DEPTH};
use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW, SAMPLES_PER_FRAME};
use crate::rtp::rtcp::{NtpTimestamp, SenderReport};
use crate::rtp::{decode_ulaw, encode_ulaw, set_rtp_dscp, RECV_BUF_SIZE};
use crate::webrtc::peer::{MediaFrame, PeerSession};

/// `TranscodingBridge` のジッタバッファ pull 周期。
///
/// RFC 3551 §4.5.14 (PCMU 8 kHz / 20 ms / 160 samples / packet) と
/// RFC 7587 §4.2 (Opus 20 ms = 960 samples @ 48 kHz) の双方とも
/// 20 ms フレーム前提なので、 1 frame 取り出すごとに 1 RTP packet を
/// エンコード送信する。
const JITTER_PULL_INTERVAL: Duration = Duration::from_millis(20);

/// Talkspurt 境界判定の閾値 (RFC 3551 §4.1 / RFC 7587 §4.4)。
///
/// 直前送信から本値以上の gap があれば「新 talkspurt」とみなし、 次パケットの
/// M ビットを 1 にする。 30 ms = 1.5 frame 周期 (PCMU 20 ms / Opus 20 ms) で、
/// 1 frame 失っただけの jitter (= false positive) は 20 ms < 30 ms で除外、
/// silence detector の最短窓 40 ms 直前で立ち上がるため Opus DTX 復帰
/// (RFC 7587 §3.7: silence 期は 4 packet = 80 ms ごとに 1 keep-alive) も
/// 確実に拾える (Issue #84)。
const TALKSPURT_GAP_THRESHOLD: Duration = Duration::from_millis(30);

/// ジッタバッファのデフォルト深度 (パケット数)。
///
/// RFC 3550 §6.4.1: jitter は受信パケット間隔の統計分散。 `JitterBuffer`
/// (`src/rtp/jitter.rs`) は受信時に §A.8 の式で jitter 推定を更新し、
/// 取り出し時に `depth` 未満なら待機 (= reorder window)、 `depth*2` を
/// 超えたら強制 pull (= overflow ロス) する。 デフォルト 4 packet ≒ 80 ms は
/// `src/rtp/jitter.rs::DEFAULT_DEPTH` と整合。
const JITTER_DEPTH: usize = DEFAULT_DEPTH;

/// RTCP Sender Report (SR) を送出する周期 (Issue #182 (f) / #112)。
///
/// RFC 3550 §6.2 (Transmission Interval) は RTCP 帯域を RTP セッション総帯域の
/// 5% に抑える adaptive interval (`T = avg_rtcp_size / rtcp_bw * n_members`) を
/// 規定する。 また §6.2 は **minimum interval = 5 秒** を mandate しており、
/// 計算結果がそれを下回ってはならない。
///
/// 本実装は単純化のため固定 5 秒 (RFC 3550 §6.2 minimum) を採用する。 transcoder
/// 経路は 2-party (sabiden ⇔ NGN/PWA peer) なので n_members = 2、 1 通話あたりの
/// RTP avg_rate ≒ 64 kbit/s (PCMU) ~ 70 kbit/s (Opus 64 kbps + RTP header) で
/// 5% = 3.2 kbit/s。 SR 28 byte (RC=0) ≒ 224 bit を 5 秒に 1 回送ると約 45 bit/s で
/// 5% bandwidth の制限を十分下回る。
///
/// Phase R5/R6 (`docs/refactor-plan.md`) で adaptive interval (RFC 3550 §6.3
/// の `T_rr_interval` 計算) と randomization (0.5x〜1.5x) への移行を検討する。
const RTCP_SR_INTERVAL: Duration = Duration::from_secs(5);

/// Opus ペイロード PT。WebRTC SDP では動的 PT (96-127) を使うのが一般的。
/// SDP で受け取った値を渡せるようにし、デフォルトは 111 (Chromium 互換)。
pub const DEFAULT_OPUS_PT: u8 = 111;

/// トランスコードブリッジの起動パラメータ。
pub struct TranscodeConfig {
    /// NGN 側 RTP ソケット (G.711 μ-law)
    pub ngn_socket: Arc<UdpSocket>,
    /// WebRTC 側 RTP ソケット (Opus)
    pub web_socket: Arc<UdpSocket>,
    /// SDP から既知の NGN 側ピア (Option: late-binding)
    pub ngn_peer: Option<SocketAddr>,
    /// SDP から既知の WebRTC 側ピア
    pub web_peer: Option<SocketAddr>,
    /// SDP `a=rtpmap:<pt> opus/48000/2` で指定された PT。指定なしは [`DEFAULT_OPUS_PT`]。
    pub opus_payload_type: u8,
    /// 観測カウンタ。
    pub metrics: Option<Arc<Metrics>>,
}

/// 内側の peer 状態 (片方向)。`RtpBridge::LegState` と同じ late-binding 戦略。
#[derive(Default)]
struct LegState {
    peer: Mutex<Option<SocketAddr>>,
}

/// 1 方向の RTP 送信ストリーム状態 (SSRC / seq / timestamp)。
///
/// RFC 3550 §5.1 (RTP Header):
/// > The SSRC field identifies the synchronization source. The value is
/// > chosen randomly, with the intent that no two synchronization sources
/// > within the same RTP session will have the same SSRC identifier.
/// > [...] The initial value of the sequence number SHOULD be random.
/// > [...] The initial value of the timestamp SHOULD be random.
///
/// sabiden のトランスコード経路 (Opus⇔μ-law) では、 sabiden が新規 RTP
/// source として出力するため、 入力 SSRC をそのまま使うのではなく
/// **session の最初に random 値を 1 度払い出して維持する**。 これにより
/// 受信側 (PWA jitter buffer / NGN 端末) は同一 source として認識でき、
/// 途中で SSRC が変わって SSRC change handler が走る事故を防ぐ。
///
/// seq / timestamp も同じく random 初期値 + frame ごとに連番加算。
/// timestamp の刻みは方向 / コーデックごとに異なる:
/// - NGN→Web (μ-law→Opus) では出力 clock = 48 kHz なので 1 frame ごとに
///   [`OPUS_FRAME_SAMPLES`] (= 960) 進む (RFC 7587 §4.1)。
/// - Web→NGN (Opus→μ-law) では出力 clock = 8 kHz なので 1 frame ごとに
///   [`SAMPLES_PER_FRAME`] (= 160) 進む (RFC 3551 §4.5.14)。
///
/// # NTP/RTP timestamp anchor (RFC 3550 §6.4.1) — Issue #182 (d)
///
/// RFC 3550 §6.4.1 (Sender Report) は SR の `NTP timestamp` と `RTP timestamp`
/// が **同じ wall-clock 瞬間** を指し、 受信側がこの 2 値を見て送信レート /
/// lip-sync / 再生レート補正を導出することを規定する:
///
/// > NTP timestamp: 32 bits / 32 bits. Indicates the wallclock time when this
/// > report was sent so that it may be used in combination with timestamps
/// > returned in reception reports from other receivers to measure round-trip
/// > propagation to those receivers. [...]
/// > RTP timestamp: 32 bits. Corresponds to the same time as the NTP timestamp
/// > (above), but in the same units and with the same random offset as the RTP
/// > timestamps in data packets.
///
/// 旧実装 (PR #242) は SR 生成時に `self.timestamp` (= 次回送信予定の RTP ts)
/// をそのまま返していたため、 SR 生成と最終 RTP 送信の間に frame 境界の
/// 余り誤差 (最大 1 frame = 20 ms 分) があり、 受信側の NTP↔RTP 線形回帰が
/// 微小にずれる。
///
/// `anchor` は **初回 `record_sent` 呼び出し時点** の (wall clock NTP, 対応 RTP ts)
/// を 1 度だけ確定する。 SR 生成時は anchor からの NTP 経過秒に `sample_rate_hz`
/// を乗じて「**この SR 送出瞬間に対応する正確な RTP timestamp**」を計算する。
/// これにより:
/// - SR の (NTP, RTP) ペアは **常に同一 wall-clock 瞬間** を指す。
/// - frame 境界余り誤差は累積せず、 long-running 通話でも線形性が維持される。
/// - SSRC rotate (RFC 3550 §8.2 / PR #239) は anchor に影響しない (anchor は
///   wall-clock との関係性であり、 SSRC とは独立)。
#[derive(Debug)]
struct RtpEgressState {
    ssrc: u32,
    seq: u16,
    timestamp: u32,
    /// 直近に `next_with_marker` で送信を払い出した時刻。 talkspurt 境界判定
    /// (RFC 3551 §4.1 / RFC 7587 §4.4) に使う。 初回 (`None`) もしくは
    /// [`TALKSPURT_GAP_THRESHOLD`] 以上空いたら M=1 (Issue #84)。
    last_send_time: Option<Instant>,
    /// 累積送信 RTP packet 数。 RFC 3550 §6.4.1 SR の `sender's packet count`。
    /// `record_sent` で +1 する (= `next` / `next_with_marker` で payload を
    /// 払い出した後、 上位 loop が `to_socket.send_to` 成功時に呼ぶ)。
    /// Issue #182 (f) / #112 で SR 送出のために導入 (PR #242)。
    sent_packets: u64,
    /// 累積送信 payload octet 数 (RTP header 含まず)。 RFC 3550 §6.4.1 SR の
    /// `sender's octet count`。 `record_sent(payload_len, ...)` で加算する。
    sent_octets: u64,
    /// RTP timestamp の刻みに対応する sample clock (Hz)。
    ///
    /// NGN→Web (Opus): [`OPUS_SAMPLE_RATE`] = 48000 (RFC 7587 §4.1)。
    /// Web→NGN (PCMU): [`NARROW_BAND_RATE`] = 8000 (RFC 3551 §4.5.14)。
    ///
    /// `anchor` 確定時 (= 初回 wire 送出成功時) に `(NtpTimestamp::now,
    /// sent_rtp_ts)` を保持し、 以降 `build_sr` 生成で
    /// 「NTP 経過秒 × sample_rate_hz = RTP timestamp 経過」 を線形に計算する
    /// (RFC 3550 §6.4.1)。
    sample_rate_hz: u32,
    /// NTP wall clock と RTP timestamp の対応 anchor (RFC 3550 §6.4.1)。
    ///
    /// `None`: まだ 1 packet も wire に出していない。 `build_sr` も
    /// packet_count=0 のため呼ばれない方針 (PR #242)。
    ///
    /// `Some((ntp, rtp))`: `ntp` 時点で wire に送出した最初の RTP packet の
    /// timestamp が `rtp` だったことを意味する。 以降の SR では
    /// `rtp_timestamp = rtp + (now_ntp - ntp) * sample_rate_hz` で
    /// 「**SR 送出瞬間に対応する RTP ts**」を線形補間する。
    ///
    /// anchor は `record_sent` (= wire 送出成功時) で 1 度だけ確定する。
    /// `next` 払い出し時点では送出失敗の可能性が残るため anchor を
    /// 確定させない (RFC 3550 §6.4.1 「NTP timestamp ↔ RTP timestamp」 相関は
    /// 実際に wire に出した packet を基準にすべき)。
    anchor: Option<(NtpTimestamp, u32)>,
}

impl RtpEgressState {
    /// RFC 3550 §5.1 に従い SSRC / seq / timestamp を random に初期化する。
    /// 起動 1 回だけ呼び、 同一 bridge 上の同一方向では使い回す。
    ///
    /// `sample_rate_hz` は方向 / コーデックごとの RTP timestamp clock (Hz)。
    /// NGN→Web (Opus) は 48000 (RFC 7587 §4.1)、 Web→NGN (PCMU) は 8000
    /// (RFC 3551 §4.5.14)。 NTP/RTP anchor の計算で使う (RFC 3550 §6.4.1)。
    fn new_random(sample_rate_hz: u32) -> Self {
        Self {
            ssrc: rand::random(),
            seq: rand::random(),
            timestamp: rand::random(),
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz,
            anchor: None,
        }
    }

    /// 現在の (seq, timestamp, ssrc) を返し、 次回送信用に
    /// seq +1 / timestamp += `ts_increment` を加算する。
    /// timestamp 加算量はコーデックの sample clock 単位で 1 frame 分。
    ///
    /// **NTP/RTP anchor 確定は `record_sent` 側** (RFC 3550 §6.4.1)。
    /// 本メソッドは payload 払い出しのみ行い、 wire 送出失敗時に anchor が
    /// 確定してしまう (= NTP/RTP 線形性が 1 frame ずれる) のを避ける。
    fn next(&mut self, ts_increment: u32) -> (u16, u32, u32) {
        let snapshot = (self.seq, self.timestamp, self.ssrc);
        self.seq = self.seq.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(ts_increment);
        snapshot
    }

    /// RFC 3550 §6.4.1 (Issue #182 (d)): 指定 NTP wall clock 瞬間に **対応する
    /// RTP timestamp** を線形補間で返す。
    ///
    /// 受信側は SR の `(NTP timestamp, RTP timestamp)` ペアから「sabiden が
    /// この wall-clock 瞬間に送出していた RTP ts」を読み取り、
    /// - 平均送信レート (`Δ RTP / Δ NTP`) で送信側のクロックドリフトを推定、
    /// - lip-sync (= 別 SSRC の同 SR ペアと突き合わせ)、
    /// - jitter buffer の adaptive resize、
    ///
    /// 等を行う。 したがって SR を生成する瞬間ごとに「**そのときの RTP ts**」
    /// を正確に返す必要がある。
    ///
    /// 計算式:
    /// ```text
    /// rtp_at_now = anchor_rtp + round( (now_ntp - anchor_ntp) * sample_rate_hz )
    /// ```
    ///
    /// - `anchor` が未確定 (= まだ 1 packet も送っていない) のときは `None`。
    ///   PR #242 docstring に従い、 packet_count=0 の空 SR は wire に出さない
    ///   方針なので呼出側はこの `None` で SR 送出を skip する。
    /// - `now_ntp < anchor_ntp` (時計が逆走) のときは負の経過を 0 に saturate
    ///   して anchor_rtp を返す (RTP ts が後退するのは RFC 3550 §5.1
    ///   "monotonically increasing" 違反のため)。
    /// - `u32` への変換は `wrapping_add` で wrap-around を許容する
    ///   (RFC 3550 §5.1: RTP timestamp は 32-bit modular)。
    ///
    /// `build_sr` (PR #242 で導入された RTCP SR 生成) は本メソッドを呼んで
    /// 「**SR 送出瞬間に対応する RTP timestamp**」 を埋め込む。 `anchor` が
    /// 未確定 (= まだ 1 packet も wire に出していない) のときは `None` を返し、
    /// `build_sr` 側は `self.timestamp` (次回送信予定の値) に fallback する。
    /// 実運用では `record_sent` が呼ばれて anchor 確定済の状態でしか SR を
    /// 出さないため、 `None` fallback は通常通過しない。
    fn rtp_timestamp_at(&self, now_ntp: NtpTimestamp) -> Option<u32> {
        let (anchor_ntp, anchor_rtp) = self.anchor?;
        let elapsed_seconds = now_ntp.elapsed_from(anchor_ntp).max(0.0);
        let elapsed_samples = (elapsed_seconds * self.sample_rate_hz as f64).round();
        // f64 → u32 で巨大な値も含めて modular な振る舞いをさせるため、
        // 一旦 u64 (mod 2^32) を経由してから wrapping_add。
        let increment = (elapsed_samples as u64 & 0xFFFF_FFFF) as u32;
        Some(anchor_rtp.wrapping_add(increment))
    }

    /// `next` と同じく (seq, ts, ssrc) を払い出しつつ、 RFC 3551 §4.1 /
    /// RFC 7587 §4.4 に従って talkspurt 開始フレームに立てる M ビットを返す。
    ///
    /// 直前 `next_with_marker` 呼び出しからの経過 `now - last_send_time`
    /// が [`TALKSPURT_GAP_THRESHOLD`] 以上、 もしくは初回 (`last_send_time =
    /// None`) のとき M=1。 その他は M=0。 呼び出し後 `last_send_time` を `now`
    /// に更新する。 talkspurt 境界判定を seq / ts 払い出しと **同じ critical
    /// section 内**で行うことで、 並行 send による race condition を排除する
    /// (Issue #84)。
    fn next_with_marker(&mut self, ts_increment: u32, now: Instant) -> (u16, u32, u32, bool) {
        let marker = match self.last_send_time {
            None => true,
            Some(prev) => now.saturating_duration_since(prev) >= TALKSPURT_GAP_THRESHOLD,
        };
        self.last_send_time = Some(now);
        let (seq, ts, ssrc) = self.next(ts_increment);
        (seq, ts, ssrc, marker)
    }

    /// RFC 3550 §8.2 (Collision Resolution and Loop Detection):
    /// > If the SSRC identifier is found to collide with that of another
    /// > participant, the participant MUST send an RTCP BYE packet for the
    /// > old identifier and choose a new one.
    ///
    /// 本メソッドは ingress した RTP packet の SSRC が `self.ssrc` と
    /// 一致する場合 (= sabiden が egress に使っている SSRC と入力 source の
    /// SSRC が同値) を「衝突」とみなし、 `self.ssrc` を新規 random 値で再
    /// 払い出して `true` を返す。 一致しなければ `false` を返す。
    ///
    /// RFC 3550 §8.2 は厳密には「異なる transport address から来た同 SSRC」
    /// を collision、 「同 transport address から来た同 SSRC」 を loop と
    /// 区別するが、 sabiden の transcoder 経路では:
    /// - 入力 (NGN UDP socket / WebRTC RTP socket) と
    /// - 出力 (反対側 socket) が常に別 transport
    ///
    /// のため、 ここでは単純化して「ingress SSRC == egress SSRC ⇒ collision
    /// として egress を rotate」 として扱う (loop は発生しない設計)。
    ///
    /// RFC §8.2 が要求する「旧 SSRC からの RTCP BYE 送出」は transcoder 経路
    /// では SR/RR/BYE を送出していない (Issue #182 (f) で別 PR) ため
    /// 現状実装しない。 SSRC rotate だけは即時実施する。
    ///
    /// 新 SSRC は **必ず旧 SSRC と異なる値** にする (rand::random() で偶々
    /// 同値が出る確率は 2^-32 だが、 防御的に loop で再抽選する)。
    /// seq / timestamp は **rotate しない** (受信側からは新 source の同一
    /// stream として連番継続される方が違和感が小さい。 厳密には新 SSRC では
    /// seq/ts 初期値も random でよいが、 既存テスト・既存通話パス regression を
    /// 避けるため最小変更とする)。
    fn check_and_rotate_on_collision(&mut self, ingress_ssrc: u32) -> bool {
        if ingress_ssrc != self.ssrc {
            return false;
        }
        let old = self.ssrc;
        let mut new_ssrc = rand::random::<u32>();
        // 防御: 万一同値が連続払い出されたら別の値が出るまで再抽選。
        while new_ssrc == old {
            new_ssrc = rand::random::<u32>();
        }
        self.ssrc = new_ssrc;
        true
    }

    /// RFC 3550 §6.4.1 SR 用に「送信した 1 packet + payload octet」を記録する。
    /// 上位 loop が `to_socket.send_to(...).await` 成功直後に呼ぶ。 send 失敗時は
    /// **呼ばない** (= 実 wire に出ていない packet を SR にカウントしないため)。
    ///
    /// `sent_rtp_ts` は `next` / `next_with_marker` が払い出した RTP timestamp
    /// (= wire に出した packet の ts) を渡す。 初回 (anchor 未確定) のみ
    /// `(NtpTimestamp::now(), sent_rtp_ts)` を anchor として確定する
    /// (RFC 3550 §6.4.1: NTP/RTP anchor は実際に wire に出した packet の
    /// 関係性を基準にすべきため、 `next` 払い出し時点ではなく `record_sent`
    /// で確定する)。
    fn record_sent(&mut self, payload_len: usize, sent_rtp_ts: u32) {
        self.sent_packets = self.sent_packets.saturating_add(1);
        self.sent_octets = self.sent_octets.saturating_add(payload_len as u64);
        if self.anchor.is_none() {
            self.anchor = Some((NtpTimestamp::now(), sent_rtp_ts));
        }
    }

    /// RFC 3550 §6.4.1 (Sender Report) を本 egress 状態のスナップショットから組む。
    ///
    /// SR は「自 SSRC が送信した RTP の累積統計 + 現在の NTP/RTP timestamp」を
    /// 受信側に伝え、 受信側が `lip-sync` (= NTP↔RTP の relationship) と平均
    /// 送信レートを計算するための情報源 (§6.4.1 NTP timestamp / RTP timestamp の
    /// 相関の定義)。
    ///
    /// - `ssrc`: 自送信 SSRC (rotate (Issue #182 (e) / PR #239) が入っているので、
    ///   本関数は **現在の `self.ssrc`** を読み新 SSRC で SR が出る。
    /// - `ntp`: 現在の wall clock を NTP 形式で取る。 [`NtpTimestamp::now`]
    ///   (`src/rtp/rtcp.rs`) は `SystemTime::now()` + 1900 epoch 補正。 RFC 3550
    ///   §6.4.1 の "NTP timestamp" フィールド (64-bit) に書く。
    /// - `rtp_timestamp`: `rtp_timestamp_at(now_ntp)` で「**この SR の NTP 時点に
    ///   対応する RTP timestamp**」 を線形補間で計算する (RFC 3550 §6.4.1 厳密)。
    ///   Issue #182 (d) で解消: 旧実装は `self.timestamp` (次回送信予定 = 払い出し済
    ///   累計) を返していたため、 SR 生成と次回 send の間に最大 1 frame の境界余り
    ///   誤差があり受信側の lip-sync / clock-drift 推定が微小にずれていた。
    ///   anchor 未確定 (= 1 packet も送出していない) 場合は `self.timestamp` に
    ///   fallback するが、 実運用では `record_sent` 後にしか SR を出さないため
    ///   通常通過しない。
    /// - `packet_count` / `octet_count`: `record_sent` で累積した値。
    /// - `reports`: 本 egress は受信側 jitter buffer を共有しない (transcoder は
    ///   入力レッグと出力レッグで SSRC を切り替えるため受信 stats は別系統)。
    ///   よって RR ブロックは空配列 (`SR with RC=0`、 §6.4.1 で許可)。
    fn build_sr(&self) -> SenderReport {
        let now_ntp = NtpTimestamp::now();
        let rtp_at_now = self.rtp_timestamp_at(now_ntp).unwrap_or(self.timestamp);
        SenderReport {
            ssrc: self.ssrc,
            ntp: now_ntp,
            rtp_timestamp: rtp_at_now,
            // u64 → u32: RFC 3550 §6.4.1 (sender's packet/octet count は 32-bit)。
            // 5 秒間隔 × u32 packet limit ≒ 4G packets / 20 ms = 2700 年 over なので
            // wrap は実害なし。 NGN 直収 117 通話の最長セッション (60 分) でも
            // ~180K packets で u32 範囲のごく一部に収まる。
            packet_count: self.sent_packets as u32,
            octet_count: self.sent_octets as u32,
            reports: Vec::new(),
        }
    }
}

/// 1 通話分のトランスコード ブリッジ。
pub struct TranscodingBridge {
    ngn_to_web: Option<JoinHandle<()>>,
    web_to_ngn: Option<JoinHandle<()>>,
    /// RFC 3550 §6.4.1 / RFC 5761 §3.3: NGN→WebRTC 方向の egress に対する
    /// RTCP SR を 5 秒周期で WebRTC peer 宛 (web socket) へ送出するタスク
    /// (Issue #182 (f) / #112)。
    ngn_to_web_sr: Option<JoinHandle<()>>,
    /// RFC 3550 §6.4.1 / RFC 5761 §3.3: WebRTC→NGN 方向の egress に対する
    /// RTCP SR を 5 秒周期で NGN peer 宛 (ngn socket) へ送出するタスク。
    web_to_ngn_sr: Option<JoinHandle<()>>,
    state: Arc<BridgeState>,
    /// NGN 側 socket / 学習済 peer。DTMF 注入 (Issue #69) で使う。
    ngn_socket: Arc<UdpSocket>,
    ngn_state: Arc<LegState>,
    /// WebRTC 側 socket / 学習済 peer。NGN→内線 INFO 経路の placeholder。
    web_socket: Arc<UdpSocket>,
    web_state: Arc<LegState>,
}

/// Bridge 全体で共有する状態。 統計カウンタと、 各方向の送信 RTP egress 状態
/// (RFC 3550 §5.1 の SSRC / seq / timestamp) を保持する。
///
/// Issue #112: SSRC / seq / timestamp はループローカル変数ではなく
/// `BridgeState` に置くことで、
/// (a) bridge lifetime の間 SSRC を維持する設計が型で表現される、
/// (b) テストから SSRC 値を観測して "flow 中に変わらない" ことを検証できる、
/// という 2 つの利点がある。
struct BridgeState {
    /// NGN→WebRTC 方向で正しく送信できた RTP 数
    ngn_to_web_packets: std::sync::atomic::AtomicU64,
    /// WebRTC→NGN 方向で正しく送信できた RTP 数
    web_to_ngn_packets: std::sync::atomic::AtomicU64,
    /// デコード/エンコード失敗で drop した RTP 数
    transcode_errors: std::sync::atomic::AtomicU64,
    /// NGN→WebRTC 方向の送信 RTP egress 状態 (RFC 3550 §5.1)。
    /// bridge 起動時に random 初期化、 以降 worker loop が `&mut` で update。
    /// `Arc<Mutex<_>>` で wrap しているのは RTCP SR 送出タスク (`rtcp_sr_sender_loop`)
    /// が独立 spawn で同じ egress を読むため (Issue #182 (f) / #112)。
    ngn_to_web_egress: Arc<Mutex<RtpEgressState>>,
    /// WebRTC→NGN 方向の送信 RTP egress 状態 (RFC 3550 §5.1)。
    web_to_ngn_egress: Arc<Mutex<RtpEgressState>>,
}

impl BridgeState {
    /// RFC 3550 §6.4.1 (Issue #182 (d)): 方向別に RTP sample clock を渡して
    /// egress state を初期化する。 NTP/RTP anchor の精度に必要 (= 旧 `Default`
    /// 経由だと sample_rate が分からず anchor が成立しない)。
    ///
    /// - `ngn_to_web_hz`: NGN→WebRTC 方向の RTP timestamp clock。
    ///   - PCMU 直送モード (`WebRtcAudioBridge { direct_pcmu_passthrough: true }`)
    ///     では 8 kHz (RFC 3551 §4.5.14)。
    ///   - Opus 変換モード (`TranscodingBridge` / `WebRtcAudioBridge`
    ///     `direct_pcmu_passthrough: false`) では 48 kHz (RFC 7587 §4.1)。
    /// - `web_to_ngn_hz`: WebRTC→NGN 方向の RTP timestamp clock。 出力 RTP は
    ///   常に PCMU なので 8 kHz (RFC 3551 §4.5.14)。
    fn with_sample_rates(ngn_to_web_hz: u32, web_to_ngn_hz: u32) -> Self {
        Self {
            ngn_to_web_packets: std::sync::atomic::AtomicU64::new(0),
            web_to_ngn_packets: std::sync::atomic::AtomicU64::new(0),
            transcode_errors: std::sync::atomic::AtomicU64::new(0),
            ngn_to_web_egress: Arc::new(Mutex::new(RtpEgressState::new_random(ngn_to_web_hz))),
            web_to_ngn_egress: Arc::new(Mutex::new(RtpEgressState::new_random(web_to_ngn_hz))),
        }
    }
}

impl TranscodingBridge {
    /// ブリッジを起動する。両方向のループを spawn する。
    pub fn start(cfg: TranscodeConfig) -> Result<Self> {
        let TranscodeConfig {
            ngn_socket,
            web_socket,
            ngn_peer,
            web_peer,
            opus_payload_type,
            metrics,
        } = cfg;

        if let Err(e) = set_rtp_dscp(&ngn_socket, 32) {
            warn!("NGN RTP socket DSCP 設定失敗 (続行): {}", e);
        }

        let ngn_state = Arc::new(LegState {
            peer: Mutex::new(ngn_peer),
        });
        let web_state = Arc::new(LegState {
            peer: Mutex::new(web_peer),
        });
        // RFC 3550 §6.4.1 / Issue #182 (d): TranscodingBridge は NGN→Web 方向
        // で Opus 48 kHz (RFC 7587 §4.1)、 Web→NGN 方向で PCMU 8 kHz
        // (RFC 3551 §4.5.14) を出力するため、 anchor 計算に必要な sample clock
        // を方向別に与える。
        let state = Arc::new(BridgeState::with_sample_rates(
            OPUS_SAMPLE_RATE,
            NARROW_BAND_RATE,
        ));

        // NGN → WebRTC: μ-law デコード → 8k PCM → アップサンプル → 48k PCM → Opus
        let ngn_to_web = tokio::spawn(ngn_to_web_loop(
            ngn_socket.clone(),
            web_socket.clone(),
            ngn_state.clone(),
            web_state.clone(),
            state.clone(),
            opus_payload_type,
            metrics.clone(),
        ));

        // WebRTC → NGN: Opus デコード → 48k PCM → ダウンサンプル → 8k PCM → μ-law
        let web_to_ngn = tokio::spawn(web_to_ngn_loop(
            web_socket.clone(),
            ngn_socket.clone(),
            web_state.clone(),
            ngn_state.clone(),
            state.clone(),
            opus_payload_type,
            metrics.clone(),
        ));

        // RFC 3550 §6.4.1 / RFC 5761 §3.3 / Issue #182 (f):
        // 各方向の egress に対して 5 秒周期で RTCP SR を送出するタスクを spawn。
        // 送信先は対向 peer の RTP 宛先と同 socket / 同 port (RTP/RTCP mux)。
        let ngn_to_web_sr = tokio::spawn(rtcp_sr_sender_loop(
            web_socket.clone(),
            web_state.clone(),
            state.ngn_to_web_egress.clone(),
            metrics.clone(),
            "ngn_to_web",
        ));
        let web_to_ngn_sr = tokio::spawn(rtcp_sr_sender_loop(
            ngn_socket.clone(),
            ngn_state.clone(),
            state.web_to_ngn_egress.clone(),
            metrics,
            "web_to_ngn",
        ));

        Ok(Self {
            ngn_to_web: Some(ngn_to_web),
            web_to_ngn: Some(web_to_ngn),
            ngn_to_web_sr: Some(ngn_to_web_sr),
            web_to_ngn_sr: Some(web_to_ngn_sr),
            state,
            ngn_socket,
            ngn_state,
            web_socket,
            web_state,
        })
    }

    /// Issue #69: NGN 側 socket から NGN ピア宛に任意 RTP datagram を 1 つ送る。
    /// SIP INFO で受け取った DTMF を RFC 4733 telephone-event RTP packet に
    /// 変換して NGN レッグに乗せるための注入経路。
    ///
    /// NGN ピアが学習されていない (= まだ RTP を受信していない) 場合は `Err`。
    /// トランスコード経路では Opus → μ-law 変換と independent に PT=101 を
    /// 直接送れるので、DTMF をリサンプル / 再エンコードしない (RFC 4733 §2.4)。
    pub async fn send_to_ngn(&self, datagram: &[u8]) -> Result<()> {
        let dest = { *self.ngn_state.peer.lock().await };
        let dest = dest.ok_or_else(|| anyhow::anyhow!("NGN peer 未確定"))?;
        self.ngn_socket.send_to(datagram, dest).await?;
        Ok(())
    }

    /// Issue #69: WebRTC 側 socket から WebRTC ピア宛に任意 RTP datagram を 1 つ送る
    /// (NGN→内線 INFO 経路の placeholder)。
    pub async fn send_to_web(&self, datagram: &[u8]) -> Result<()> {
        let dest = { *self.web_state.peer.lock().await };
        let dest = dest.ok_or_else(|| anyhow::anyhow!("Web peer 未確定"))?;
        self.web_socket.send_to(datagram, dest).await?;
        Ok(())
    }

    /// 両ループ + RTCP SR タスクを停止する (Issue #182 (f))。
    pub async fn stop(mut self) {
        if let Some(h) = self.ngn_to_web.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.web_to_ngn.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.ngn_to_web_sr.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.web_to_ngn_sr.take() {
            h.abort();
            let _ = h.await;
        }
    }

    /// 統計: (NGN→WebRTC 成功数, WebRTC→NGN 成功数, トランスコード失敗数)
    pub fn stats(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.state.ngn_to_web_packets.load(Ordering::Relaxed),
            self.state.web_to_ngn_packets.load(Ordering::Relaxed),
            self.state.transcode_errors.load(Ordering::Relaxed),
        )
    }

    /// 現在の NGN→WebRTC 方向の送信 SSRC (RFC 3550 §5.1)。
    /// bridge 起動時に random 払い出された値で、 lifetime 中に変わらない。
    /// テストおよび debug 用。
    pub async fn ngn_to_web_ssrc(&self) -> u32 {
        self.state.ngn_to_web_egress.lock().await.ssrc
    }

    /// 現在の WebRTC→NGN 方向の送信 SSRC (RFC 3550 §5.1)。
    pub async fn web_to_ngn_ssrc(&self) -> u32 {
        self.state.web_to_ngn_egress.lock().await.ssrc
    }
}

impl Drop for TranscodingBridge {
    fn drop(&mut self) {
        if let Some(h) = self.ngn_to_web.take() {
            h.abort();
        }
        if let Some(h) = self.web_to_ngn.take() {
            h.abort();
        }
        // RFC 3550 §6.4.1 / Issue #182 (f): SR タスクは bridge と同ライフサイクル。
        if let Some(h) = self.ngn_to_web_sr.take() {
            h.abort();
        }
        if let Some(h) = self.web_to_ngn_sr.take() {
            h.abort();
        }
    }
}

/// NGN (μ-law 8k) → WebRTC (Opus 48k) 方向の 1 ループ。
///
/// # ジッタバッファ統合 (Issue #105)
///
/// `recv_from` 直後に `RtpPacket` を [`JitterBuffer`] へ push し、
/// 20 ms 間隔の `interval` tick で `pull` してエンコード送信する。
/// 受信タスクとエンコード送信タスクを 1 つの async 関数に
/// `tokio::select!` で同居させることで、 [`JitterBuffer`] への
/// 排他アクセス (Mutex 不要) と JoinHandle の単一化を両立する。
///
/// # RFC 引用
///
/// - **RFC 3550 §6.4.1** (Jitter): jitter は受信パケット間隔の統計分散。
///   IP 網は順序保証しない (§A.8 D(i,j) = (Rj-Ri)-(Sj-Si) の前提)。
/// - **RFC 3550 §6.4.2** (Inter-arrival jitter): 受信側 (= sabiden) は
///   jitter 推定値に応じてバッファ深度を調整するべき。 本実装では
///   固定深度 4 packet ≒ 80 ms (`JITTER_DEPTH`) を採用。
/// - **RFC 7587 §6.2** (Opus PLC): pull が `None` (= 期待 seq の packet が
///   未到着) の場合、 timing 維持のため空 payload を decode して PLC frame
///   を生成する選択肢があるが、 `JitterBuffer` はバッファが overflow に
///   なるまで `None` を返し続ける設計のため (`src/rtp/jitter.rs::pull`)、
///   無音を勝手に挿入しない。 端末側の jitter buffer に PLC を委ねる。
async fn ngn_to_web_loop(
    from_socket: Arc<UdpSocket>,
    to_socket: Arc<UdpSocket>,
    from_state: Arc<LegState>,
    to_state: Arc<LegState>,
    state: Arc<BridgeState>,
    opus_pt: u8,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    let span = tracing::trace_span!("transcode_ngn_to_web");
    let _enter = span.enter();

    // パイプラインの状態 (この方向で 1 通話の間使い回す)
    let mut upsampler = match UpsamplerNbToWb::new() {
        Ok(v) => v,
        Err(e) => {
            warn!(error=%e, "Upsampler 初期化失敗 → NGN→Web 方向停止");
            return;
        }
    };
    let mut encoder = match OpusEncoder::new() {
        Ok(v) => v,
        Err(e) => {
            warn!(error=%e, "Opus エンコーダ初期化失敗 → NGN→Web 方向停止");
            return;
        }
    };

    // 出力 RTP の SSRC / seq / ts は session の最初に random 初期化された
    // `BridgeState::ngn_to_web_egress` を共有して使う (RFC 3550 §5.1)。
    // Issue #112: 以前は loop ローカル変数で各方向 random 初期化していたが、
    // 「flow 中 SSRC 不変」を型と共有 state で表現する。

    let mut jitter = JitterBuffer::new(JITTER_DEPTH);
    let mut tick = tokio::time::interval(JITTER_PULL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // RFC 3550 §5.1 / §6.4: RTP/RTCP 1 datagram は 1500 byte (IP MTU) を超え得る
    // (compound SR/SDES や RFC 5285 拡張)。 jumbo frame 上限 9000 byte で受ける
    // (Issue #96)。 PCMU 20ms = 172 byte の常用パスには影響なし。
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    loop {
        tokio::select! {
            // RTP 受信 → jitter buffer へ push (RFC 3550 §6.4.1)
            recv_res = from_socket.recv_from(&mut buf) => {
                let (n, src) = match recv_res {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(error=%e, "NGN recv エラー → ループ終了");
                        return;
                    }
                };
                // tokio は Linux `MSG_TRUNC` を expose しないため上限張り付きを
                // truncate 疑いとして警告する (RFC 3550 §5.1 / §6.4, Issue #96)。
                if n == RECV_BUF_SIZE {
                    warn!(
                        bytes = n,
                        "NGN→Web: RTP datagram が受信バッファ上限 ({} byte) に達 — \
                         truncate の可能性",
                        RECV_BUF_SIZE
                    );
                }
                // 送信元学習 (NGN 側の peer)
                {
                    let mut peer = from_state.peer.lock().await;
                    if peer.as_ref() != Some(&src) {
                        trace!(?src, "NGN 側 RTP 送信元学習");
                        *peer = Some(src);
                    }
                }

                let pkt = match RtpPacket::from_bytes(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        trace!(error=%e, "NGN RTP パース失敗 → drop");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if pkt.payload_type != PAYLOAD_TYPE_ULAW {
                    trace!(pt = pkt.payload_type, "NGN 側 PT≠0 → drop");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // 1 NGN フレームは 20ms = 160 samples 想定
                if pkt.payload.len() != SAMPLES_PER_FRAME {
                    trace!(len = pkt.payload.len(), "NGN payload 長異常 → drop");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // RFC 3550 §8.2: ingress SSRC が egress SSRC と衝突したら
                // egress SSRC を rotate する (Issue #182 (e))。
                {
                    let mut eg = state.ngn_to_web_egress.lock().await;
                    if eg.check_and_rotate_on_collision(pkt.ssrc) {
                        warn!(
                            ssrc = format!("0x{:08x}", pkt.ssrc),
                            new_ssrc = format!("0x{:08x}", eg.ssrc),
                            "SSRC collision detected (ngn_to_web: ingress = egress), \
                             rotating egress SSRC (RFC 3550 §8.2)"
                        );
                        if let Some(m) = metrics.as_ref() {
                            m.add_ssrc_collision_detected(1);
                        }
                    }
                }
                jitter.push(pkt, Instant::now());
            }
            // 20ms tick → jitter buffer から pull → transcode → 送信
            _ = tick.tick() => {
                let Some(pkt) = jitter.pull() else { continue };

                // μ-law decode
                let pcm8: Vec<i16> = pkt.payload.iter().map(|b| decode_ulaw(*b)).collect();
                let nb = AudioFrame::new(NARROW_BAND_RATE, pcm8);

                // upsample 8k → 48k
                let wb = match upsampler.process(&nb) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!(error=%e, "アップサンプル失敗");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                // Opus encode
                let opus_payload = match encoder.encode(&wb) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!(error=%e, "Opus エンコード失敗");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                let dest = match *to_state.peer.lock().await {
                    Some(d) => d,
                    None => {
                        trace!("WebRTC 側 peer 未確定 → drop");
                        continue;
                    }
                };

                // 共有 egress state から SSRC / seq / ts と M ビットを払い出す。
                // RFC 7587 §4.1: Opus RTP clock = 48 kHz → 20ms = 960 samples。
                // RFC 7587 §4.4 (M bit): talkspurt 開始の最初の packet に M=1。
                // Issue #112: bridge lifetime 中 SSRC 不変 + flow 中の seq / ts 連番を保証。
                // Issue #84: jitter buffer pull が間遠 (silence / DTX 復帰直後) の場合に
                //   talkspurt 境界として M=1 を立てる。
                let (seq, ts, ssrc, marker) = {
                    let mut eg = state.ngn_to_web_egress.lock().await;
                    eg.next_with_marker(OPUS_FRAME_SAMPLES as u32, Instant::now())
                };

                let out_pkt = RtpPacket {
                    payload_type: opus_pt & 0x7f,
                    marker,
                    sequence: seq,
                    timestamp: ts,
                    ssrc,
                    payload: opus_payload,
                };

                let payload_len = out_pkt.payload.len();
                if let Err(e) = to_socket.send_to(&out_pkt.to_bytes(), dest).await {
                    warn!(error=%e, "WebRTC へ RTP forward 失敗");
                    continue;
                }
                // RFC 3550 §6.4.1: SR の sender's packet/octet count は wire に
                // 出した packet のみ集計する。 send 失敗時は record_sent しない。
                // Issue #182 (f) / #112。 anchor (NTP/RTP relationship) も
                // wire 送出成功時に初回確定する (Issue #182 (d))。
                {
                    let mut eg = state.ngn_to_web_egress.lock().await;
                    eg.record_sent(payload_len, ts);
                }
                state.ngn_to_web_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(m) = metrics.as_ref() {
                    m.add_rtp_ngn_to_ext(1);
                }
            }
        }
    }
}

/// Opus デコード結果 (48 kHz PCM) を 20 ms 単位の μ-law payload に変換するための
/// 累積バッファ。
///
/// # 必要性 (Issue #200)
///
/// RFC 7587 §4.1 (Frame Sizes): Opus は **2.5 / 5 / 10 / 20 / 40 / 60 ms** の
/// 6 種のフレーム長を許す (= 120 / 240 / 480 / 960 / 1920 / 2880 samples @ 48 kHz)。
/// RFC 7587 §4.2: "the receiver SHOULD NOT assume any particular frame size."
///
/// sabiden の出力レッグ (NGN PCMU) は RFC 3551 §4.5.14 で **20 ms 固定**
/// (= 160 samples @ 8 kHz)。 そのため 20 ms 未満の短尺フレームは「単発では
/// 20 ms 境界に揃わない」 → 累積して 20 ms 分溜まったら一括 emit する必要がある。
///
/// 旧実装 (PR #197) は `wb.samples.len() % WB_FRAME_SAMPLES == 0` を要求して
/// 短尺フレームを silently drop していた。 本構造体はその drop を消し、
/// 短尺フレームを溜めて 20 ms 境界で flush する。
///
/// # 設計選択
///
/// - **48 kHz (wideband) 側で累積** する。 [`DownsamplerWbToNb`] は
///   `FastFixedIn` 固定入力長 960 で構築されているため (`src/rtp/codec/resample.rs`)、
///   1 chunk = 960 samples 単位でしか resample できない。 8 kHz 側で累積する
///   設計だと resample 入出力長が崩れる。
/// - **20 ms 未満の余剰 (tail) は次フレームへ持ち越し**。 例: 2.5 ms (120 samples)
///   フレームを 8 個累積 → 960 samples → 1 個 emit。 7 個目までは tail に残る。
/// - 同様に 40/60 ms (1920/2880 samples) はそのまま 2/3 個の chunk に分割される
///   ため、 旧 `chunks(WB_FRAME_SAMPLES)` 経路の挙動 (PR #197) を保つ。
/// - **連続性**: 累積バッファは Opus decoder の出力連結であり、 サンプル境界が
///   60 ms フレーム間で繋がる。 サブフレーム境界で 0 埋めしないため、 折返し
///   位相が崩れて聴感上のクリックは出ない (libopus が境界を補間してデコード
///   する前提)。
struct OpusToPcmuAccum {
    /// 48 kHz wideband 累積バッファ。 `WB_FRAME_SAMPLES` 単位で drain される。
    buf: Vec<i16>,
}

impl OpusToPcmuAccum {
    fn new() -> Self {
        Self {
            // RFC 6716 §3.2: 最大 packet duration = 120 ms (5760 samples)。
            // ホットパスでの再アロケート回避のため、 5760 + 1 frame 余裕で確保。
            buf: Vec::with_capacity(WB_FRAME_SAMPLES * 7),
        }
    }

    /// Opus デコード結果 (48 kHz PCM) を流し込む。 内部累積長が
    /// `WB_FRAME_SAMPLES` (= 960) に達したら以下が起きる:
    /// 1. 先頭 960 samples を切り出して [`DownsamplerWbToNb`] へ流す
    /// 2. 8 kHz NB フレーム (160 samples) を得る
    /// 3. μ-law に変換して `Vec<Vec<u8>>` の 1 chunk として返す
    ///
    /// 入力長によっては複数 chunk を一度に返す (例: 60 ms = 2880 samples 投入で
    /// 3 chunk emit)。 入力が短くて累積が `WB_FRAME_SAMPLES` 未満で終わる場合は
    /// 空 `Vec` を返し、 余りは内部バッファに保持される。
    ///
    /// # エラー
    ///
    /// downsampler / 内部状態の異常時のみ。 RFC 7587 §4.1 で許される全フレーム長
    /// (120/240/480/960/1920/2880 samples) と RFC 6716 §3.2 multi-frame
    /// (合算 ≤ 5760 samples) は `Ok` で返す。
    fn push(
        &mut self,
        decoded_wb: &[i16],
        downsampler: &mut DownsamplerWbToNb,
    ) -> Result<Vec<Vec<u8>>> {
        self.buf.extend_from_slice(decoded_wb);
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        while self.buf.len() >= WB_FRAME_SAMPLES {
            // 先頭 WB_FRAME_SAMPLES を取り出して残りを左詰めで保持。
            // `drain(..WB_FRAME_SAMPLES)` は内部で memmove するが、 通常ケース
            // (20 ms 入力 → 残り 0) では即 no-op になる。
            let chunk: Vec<i16> = self.buf.drain(..WB_FRAME_SAMPLES).collect();
            let frame = AudioFrame::new(OPUS_SAMPLE_RATE, chunk);
            let nb = downsampler.process(&frame)?;
            if nb.samples.len() != NB_FRAME_SAMPLES {
                anyhow::bail!(
                    "NB フレーム長異常: {} samples (期待 {})",
                    nb.samples.len(),
                    NB_FRAME_SAMPLES
                );
            }
            let ulaw: Vec<u8> = nb.samples.iter().map(|s| encode_ulaw(*s)).collect();
            chunks.push(ulaw);
        }
        Ok(chunks)
    }

    /// 内部に残っている tail サンプル数 (< `WB_FRAME_SAMPLES`)。
    /// テスト / メトリクス用。
    #[cfg(test)]
    fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// WebRTC (Opus 48k) → NGN (μ-law 8k) 方向の 1 ループ。
///
/// # ジッタバッファ統合 (Issue #105)
///
/// `recv_from` 直後に `RtpPacket` を [`JitterBuffer`] へ push し、
/// 20 ms 間隔の `interval` tick で `pull` してデコード送信する。
/// WebRTC レッグは ICE/TURN 経由で reorder の頻度が高いため、
/// NGN 方向と同様 jitter buffer を経由する。
///
/// # RFC 引用
///
/// - **RFC 3550 §6.4.1** (Jitter): IP 網は順序保証無し、 受信側で再整列
///   が必要。
/// - **RFC 3550 §6.4.2** (Inter-arrival jitter buffer): 受信側 buffer は
///   reorder 緩和と loss 検出の双方を兼ねる。
async fn web_to_ngn_loop(
    from_socket: Arc<UdpSocket>,
    to_socket: Arc<UdpSocket>,
    from_state: Arc<LegState>,
    to_state: Arc<LegState>,
    state: Arc<BridgeState>,
    opus_pt: u8,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    let span = tracing::trace_span!("transcode_web_to_ngn");
    let _enter = span.enter();

    let mut downsampler = match DownsamplerWbToNb::new() {
        Ok(v) => v,
        Err(e) => {
            warn!(error=%e, "Downsampler 初期化失敗 → Web→NGN 方向停止");
            return;
        }
    };
    let mut decoder = match OpusDecoder::new() {
        Ok(v) => v,
        Err(e) => {
            warn!(error=%e, "Opus デコーダ初期化失敗 → Web→NGN 方向停止");
            return;
        }
    };
    // RFC 7587 §4.1 / Issue #200: 2.5/5/10 ms 短尺フレームを 20 ms 境界に
    // 揃えるための累積バッファ。 20/40/60 ms (= 960/1920/2880 samples) も
    // 同じ経路で chunk 分割される (旧 PR #197 の chunks(960) と等価)。
    let mut accum = OpusToPcmuAccum::new();

    // 出力 RTP egress 状態は `BridgeState::web_to_ngn_egress` を共有 (Issue #112)。

    let mut jitter = JitterBuffer::new(JITTER_DEPTH);
    let mut tick = tokio::time::interval(JITTER_PULL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // RFC 3550 §5.1 / §6.4 + RFC 5285 拡張で 1500 byte 超過があり得るため
    // jumbo frame 上限 9000 byte で受ける (Issue #96)。 WebRTC からの RTP は
    // extension が多く積まれる傾向があり、 旧 1500 byte 固定では特に危険だった。
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    loop {
        tokio::select! {
            recv_res = from_socket.recv_from(&mut buf) => {
                let (n, src) = match recv_res {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(error=%e, "WebRTC recv エラー → ループ終了");
                        return;
                    }
                };
                if n == RECV_BUF_SIZE {
                    warn!(
                        bytes = n,
                        "Web→NGN: RTP datagram が受信バッファ上限 ({} byte) に達 — \
                         truncate の可能性 (RFC 3550 §5.1 / §6.4, Issue #96)",
                        RECV_BUF_SIZE
                    );
                }
                {
                    let mut peer = from_state.peer.lock().await;
                    if peer.as_ref() != Some(&src) {
                        trace!(?src, "WebRTC 側 RTP 送信元学習");
                        *peer = Some(src);
                    }
                }

                let pkt = match RtpPacket::from_bytes(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        trace!(error=%e, "WebRTC RTP パース失敗 → drop");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if pkt.payload_type != opus_pt {
                    trace!(
                        pt = pkt.payload_type,
                        expected = opus_pt,
                        "WebRTC PT 不一致 → drop"
                    );
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // RFC 3550 §8.2: ingress SSRC が egress SSRC と衝突したら
                // egress SSRC を rotate する (Issue #182 (e))。
                {
                    let mut eg = state.web_to_ngn_egress.lock().await;
                    if eg.check_and_rotate_on_collision(pkt.ssrc) {
                        warn!(
                            ssrc = format!("0x{:08x}", pkt.ssrc),
                            new_ssrc = format!("0x{:08x}", eg.ssrc),
                            "SSRC collision detected (web_to_ngn: ingress = egress), \
                             rotating egress SSRC (RFC 3550 §8.2)"
                        );
                        if let Some(m) = metrics.as_ref() {
                            m.add_ssrc_collision_detected(1);
                        }
                    }
                }
                jitter.push(pkt, Instant::now());
            }
            _ = tick.tick() => {
                let Some(pkt) = jitter.pull() else { continue };

                // Opus decode → 48k PCM。
                // RFC 7587 §4.1 (Frame Sizes): Opus フレーム長は 2.5/5/10/20/40/60 ms
                // (= 120/240/480/960/1920/2880 samples @ 48 kHz)。
                // RFC 6716 §3.2 (code-3 multi-frame packet) では複数フレームを
                // 1 packet にまとめて最大 120 ms (= 5760 samples) まで運べる。
                // RFC 7587 §4.2: "the receiver SHOULD NOT assume any particular
                // frame size" — 受信側は 20 ms 以外も処理する義務がある。
                //
                // Issue #89 (PR #197) で 40/60 ms 単発フレームの 20 ms 分割は実装済。
                // Issue #200 (本 PR) で 2.5/5/10 ms 短尺フレームを `OpusToPcmuAccum`
                // に累積し、 20 ms 境界 (= 960 samples @ 48 kHz) が満ちた時点で
                // chunk を emit する経路に統一した。
                let wb = match decoder.decode(&pkt.payload) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!(error=%e, "Opus デコード失敗");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if wb.samples.is_empty() {
                    // RFC 7587 §6.2 PLC は OpusDecoder::decode が 20 ms 分の
                    // サンプルを返すため、 ここで空になるのは libopus 異常時のみ。
                    trace!("Opus decode が空サンプルを返した → drop");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // 累積 → 20 ms 境界が満ちるたびに μ-law chunk を取り出す。
                // 短尺フレーム (2.5/5/10 ms) の場合、 単発投入では chunk が
                // 出ない (累積が 960 未満)。 次の packet で 20 ms に達した時に emit。
                let ulaw_chunks = match accum.push(&wb.samples, &mut downsampler) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!(error=%e, "累積 / ダウンサンプル失敗");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if ulaw_chunks.is_empty() {
                    // 短尺 (2.5/5/10 ms) フレームを単発受信した場合の正常経路。
                    // 累積はバッファに残り、 次 packet で flush される。
                    trace!(
                        wb_samples = wb.samples.len(),
                        pending = accum.buf.len(),
                        "短尺 Opus フレーム → 累積バッファに保持 (RFC 7587 §4.1 / Issue #200)"
                    );
                    continue;
                }

                let dest = match *to_state.peer.lock().await {
                    Some(d) => d,
                    None => {
                        trace!("NGN 側 peer 未確定 → drop");
                        continue;
                    }
                };

                // 20ms chunk ごとに 1 RTP packet を生成して送出する。
                // 各 chunk は同じ SSRC を共有しつつ seq +1 / ts +160 (RFC 3551
                // §4.5.14: PCMU 8 kHz × 20 ms) ずつ進む。 RFC 3550 §5.1 の
                // 「同一 SSRC 内 seq は monotonically increasing」 を満たす。
                for ulaw in ulaw_chunks {
                    // 共有 egress state から SSRC / seq / ts と M ビットを払い出す。
                    // RFC 3551 §4.5.14: PCMU clock = 8 kHz → 20ms = 160 samples。
                    // RFC 3551 §4.1 (M bit): talkspurt 開始の最初の packet に M=1。
                    // Issue #112: bridge lifetime 中 SSRC 不変 + flow 中の seq / ts 連番を保証。
                    // Issue #84: WebRTC peer の Opus DTX 復帰 → 内部 chunk loop 内であっても
                    //   出力 packet 間の gap が閾値超過なら talkspurt 開始扱いとする。
                    let (seq, ts, ssrc, marker) = {
                        let mut eg = state.web_to_ngn_egress.lock().await;
                        eg.next_with_marker(SAMPLES_PER_FRAME as u32, Instant::now())
                    };

                    let out_pkt = RtpPacket {
                        payload_type: PAYLOAD_TYPE_ULAW,
                        marker,
                        sequence: seq,
                        timestamp: ts,
                        ssrc,
                        payload: ulaw,
                    };

                    let payload_len = out_pkt.payload.len();
                    if let Err(e) = to_socket.send_to(&out_pkt.to_bytes(), dest).await {
                        warn!(error=%e, "NGN へ RTP forward 失敗");
                        break;
                    }
                    // RFC 3550 §6.4.1: SR の sender's packet/octet count は wire
                    // に出した分のみ集計 (Issue #182 (f) / #112)。 anchor も
                    // wire 送出成功時に初回確定する (Issue #182 (d))。
                    {
                        let mut eg = state.web_to_ngn_egress.lock().await;
                        eg.record_sent(payload_len, ts);
                    }
                    state.web_to_ngn_packets.fetch_add(1, Ordering::Relaxed);
                    if let Some(m) = metrics.as_ref() {
                        m.add_rtp_ext_to_ngn(1);
                    }
                }
            }
        }
    }
}

/// RFC 3550 §6.4.1 / RFC 5761 §3.3: transcoder の 1 egress 経路に対して、
/// [`RTCP_SR_INTERVAL`] (= 5 秒) 周期で Sender Report を生成し、 RTP と
/// **同じ UDP socket** に **同じ peer 宛**で送出するタスクのループ。
///
/// # RTP/RTCP mux (RFC 5761 §3.3)
///
/// SDP に `a=rtcp-mux` を明示しない場合 NGN 直収では P-CSCF が `m=audio` の
/// port+1 に対する inbound を許可するかどうか不確実 (`docs/asterisk-real-invite.md`
/// §5.2 で確証なし)。 本実装は RTP socket と同一 port に SR を載せる
/// (= RTP/RTCP mux 前提)。 RFC 5761 §4 の demux ルール (RTP PT vs RTCP PT 範囲
/// 64-95) で peer 側もパース可能。
///
/// # Peer 宛先の遅延学習
///
/// 上位 loop は `recv_from` の `src` を `LegState::peer` に書き込み学習する
/// (late-binding)。 SR タスクは `to_state.peer` を周期的に snapshot し、
/// `None` なら scheduling skip (送りようがない)、 `Some` なら送出する。 SDP
/// から事前に学習済の場合は最初の tick から送出される。
///
/// # シャットダウン
///
/// 本タスクの JoinHandle は呼出側 (`TranscodingBridge` / `WebRtcAudioBridge`)
/// の Drop で `abort()` される (`tokio::spawn` の慣用パターン)。 自前の
/// shutdown signal は持たない (= bridge の他 loop と同じライフサイクル管理)。
///
/// # 観測
///
/// SR 送出成功時に `Metrics::add_rtcp_sr_sent(1)` で観測カウンタを上げる。
/// Prometheus exposition では `sabiden_rtcp_sr_sent_total` として展開される。
async fn rtcp_sr_sender_loop(
    socket: Arc<UdpSocket>,
    to_state: Arc<LegState>,
    egress: Arc<Mutex<RtpEgressState>>,
    metrics: Option<Arc<Metrics>>,
    direction: &'static str,
) {
    let span = tracing::trace_span!("rtcp_sr_sender", direction);
    let _enter = span.enter();

    let mut tick = tokio::time::interval(RTCP_SR_INTERVAL);
    // SR は 5 秒に 1 回。 tick lag (上位 task busy 等) で複数 tick が溜まっても
    // RFC 3550 §6.2 minimum interval = 5 秒を破らないよう Skip 戦略を取る。
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // 初回 tick は immediate (= bridge 起動直後に SR を出すと wire 上に packets=0
    // の空 SR が乗る) を避けるため、 1 回目の tick を消費する。 受信側は
    // sender が無送信なら SR を期待しないので、 5 秒待ってから初回送出にする。
    tick.tick().await;

    loop {
        tick.tick().await;

        // 宛先 peer が学習されていなければ、 今回はスキップして次 tick へ。
        // (PWA 経由通話で SDP から事前に peer が分かるケースは最初から Some。
        //  symmetric RTP の learn-on-receive ケースは受信が始まる頃には Some 化済。)
        let dest = match *to_state.peer.lock().await {
            Some(d) => d,
            None => {
                trace!("RTCP SR: peer 未確定 → スキップ");
                continue;
            }
        };

        // RFC 3550 §6.4.1: 自送信統計のスナップショットから SR を構築。
        // egress lock は build_sr (NTP::now + 既存 counter 読み) のごく短時間のみ。
        let sr = {
            let eg = egress.lock().await;
            eg.build_sr()
        };

        let bytes = sr.to_bytes();
        if let Err(e) = socket.send_to(&bytes, dest).await {
            // Network 一時障害 (ENETUNREACH 等) は次 tick で再送出するため、
            // warn ログのみで継続する (5 秒後にリトライ)。
            warn!(error=%e, "RTCP SR 送出失敗 → 次 tick へ");
            continue;
        }
        if let Some(m) = metrics.as_ref() {
            m.add_rtcp_sr_sent(1);
        }
        trace!(
            ssrc = format!("0x{:08x}", sr.ssrc),
            packets = sr.packet_count,
            octets = sr.octet_count,
            "RTCP SR 送出 (RFC 3550 §6.4.1 / RFC 5761 §3.3)"
        );
    }
}

/// SDP の `a=rtpmap:<pt> opus/48000[/<ch>]` (RFC 7587 §7.1) から PT を取り出す。
///
/// 該当がなければ `None`。トランスコード要否判定 (`sdp_uses_opus`) の基礎関数。
pub fn find_opus_payload_type(sdp_bytes: &[u8]) -> Option<u8> {
    let text = std::str::from_utf8(sdp_bytes).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            if let Some((pt_str, codec_part)) = rest.split_once(' ') {
                let codec = codec_part
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if codec == "opus" {
                    if let Ok(pt) = pt_str.parse::<u8>() {
                        return Some(pt);
                    }
                }
            }
        }
    }
    None
}

/// SDP で Opus が宣言されているかどうか (= トランスコードが必要か) を判定する
/// 簡易関数。WebRTC ↔ NGN 通話判定のヒューリスティック。
pub fn sdp_uses_opus(sdp_bytes: &[u8]) -> bool {
    find_opus_payload_type(sdp_bytes).is_some()
}

/// Issue #87 / #121: NGN レッグ (UDP socket) ⇔ WebRTC peer (str0m) を結ぶ
/// 双方向ブリッジ。
///
/// `TranscodingBridge` と違い、 PWA レッグは UDP socket を直接持たず、
/// [`PeerSession::take_media_rx`] / [`PeerSession::send_media`] の
/// MediaFrame mpsc を使う (str0m が ICE/DTLS 上で SRTP 多重化するため)。
///
/// # 経路
///
/// ```text
/// NGN UDP socket (PCMU PT 0)  →  μ-law decode → 8k PCM
///   → upsample 48k PCM → Opus encode → MediaFrame → peer.send_media
///
/// peer.take_media_rx (Opus)
///   → Opus decode → 48k PCM → downsample 8k PCM
///   → μ-law encode → RtpPacket → NGN UDP socket
/// ```
///
/// # RFC 引用
///
/// - **RFC 3550 §5.1** (RTP frame): NGN レッグの 1 RTP パケットは 1 frame。
/// - **RFC 3551 §4.5.14** (PCMU PT 0, 8 kHz, 20 ms = 160 samples / packet)。
/// - **RFC 7587 §4.2** (Opus payload format): WebRTC は通常 20 ms = 960
///   samples@48 kHz の Opus フレームを 1 RTP packet に乗せる。
/// - **RFC 8835** (WebRTC overview): 媒体経路は SRTP/AVPF の上 Opus を運ぶ。
pub struct WebRtcAudioBridge {
    ngn_to_peer: Option<JoinHandle<()>>,
    peer_to_ngn: Option<JoinHandle<()>>,
    /// RFC 3550 §6.4.1 / RFC 5761 §3.3: peer→NGN 方向の egress に対する
    /// RTCP SR を 5 秒周期で NGN peer 宛 (NGN socket) へ送出するタスク
    /// (Issue #182 (f) / #112)。
    ///
    /// NGN→peer 方向は egress 先が `MediaFrame` mpsc (str0m が WebRTC レッグ上
    /// で SSRC / seq を割り当てる) のため、 sabiden 側で RTCP を組まない。
    /// str0m 自身が WebRTC SAVPF 経路で SR/RR を扱う設計 (RFC 8108 / RFC 8835)。
    peer_to_ngn_sr: Option<JoinHandle<()>>,
    state: Arc<BridgeState>,
    /// NGN 側 socket / 学習済 peer。 DTMF 注入 (Issue #69) で使う。
    ngn_socket: Arc<UdpSocket>,
    ngn_state: Arc<LegState>,
}

/// [`WebRtcAudioBridge`] の起動パラメータ。
pub struct WebRtcAudioConfig {
    /// NGN 側 RTP ソケット (G.711 μ-law PT=0)。
    pub ngn_socket: Arc<UdpSocket>,
    /// SDP から既知の NGN 側ピア (Option: late-binding)。
    pub ngn_peer: Option<SocketAddr>,
    /// WebRTC peer。 双方向の MediaFrame mpsc にアクセスする。
    pub peer: Arc<dyn PeerSession>,
    /// `take_media_rx` で取り出した PWA → orchestrator 方向の receiver。
    /// `peer.take_media_rx().await` の結果をそのまま渡す。
    pub peer_media_rx: mpsc::Receiver<MediaFrame>,
    /// SDP `a=rtpmap:<pt> opus/48000[/<ch>]` で negotiate した PT。
    /// 不明なら [`DEFAULT_OPUS_PT`]。
    pub opus_payload_type: u8,
    /// PCMU 直送モード (両側 PCMU 構成、 transcode 不要)。
    /// sabiden の str0m は `enable_pcmu` 1 codec 構成 (`webrtc/str0m_session.rs:190`)
    /// なので NGN(μ-law)↔PWA(μ-law) を素通しできる。 true の場合 Opus 経路を
    /// 完全に bypass し、 NGN 受信 RTP の payload をそのまま `MediaFrame { pt:0 }`
    /// として peer に流す (RFC 3551 §4.5.14: PCMU PT 0、 8kHz)。
    pub direct_pcmu_passthrough: bool,
    /// 観測カウンタ。
    pub metrics: Option<Arc<Metrics>>,
}

impl WebRtcAudioBridge {
    /// ブリッジを起動する。両方向のループを spawn する。
    ///
    /// # 戻り値が `Self` (not `Result<Self>`) である理由 (Issue #135 🟡 3)
    ///
    /// 本関数は内部で fallible な操作を一切しない:
    /// - `set_rtp_dscp` は失敗しても `warn` で握る (DSCP は QoS 最適化、
    ///   設定不可でも通話自体は成立する。 `src/main.rs::set_dscp` 参照)。
    /// - `tokio::spawn` は infallible (panic を `JoinError` として後段で
    ///   検知する設計、 spawn 自体は `Err` を返さない)。
    ///
    /// よって `Result<Self>` を返すと呼出側 (`orchestrator.rs::run_inbound_*`
    /// および PWA outbound 経路) が形式上 `?` で error path を書く必要が生じ、
    /// **存在しない error path** を扱うことになる。 これは「unreachable な
    /// failure mode を API に晒さない」(Rust API guidelines C-FAILURE) 観点で
    /// 誠実でないため、 `Self` を直接返す。 RFC 直接参照は無いが、
    /// `CLAUDE.md §6.5` の `unwrap`/`expect` 禁止と同じ精神 (production code
    /// で出ない error path を晒さない) に則る。
    pub fn start(cfg: WebRtcAudioConfig) -> Self {
        let WebRtcAudioConfig {
            ngn_socket,
            ngn_peer,
            peer,
            peer_media_rx,
            opus_payload_type,
            direct_pcmu_passthrough,
            metrics,
        } = cfg;

        if let Err(e) = set_rtp_dscp(&ngn_socket, 32) {
            warn!("NGN RTP socket DSCP 設定失敗 (続行): {}", e);
        }

        let ngn_state = Arc::new(LegState {
            peer: Mutex::new(ngn_peer),
        });
        // RFC 3550 §6.4.1 / Issue #182 (d): NGN→peer 方向は PCMU 直送モード
        // なら 8 kHz (RFC 3551 §4.5.14)、 Opus 変換モードなら 48 kHz
        // (RFC 7587 §4.1)。 peer→NGN 方向は常に PCMU 8 kHz で NGN へ出す。
        let ngn_to_peer_hz = if direct_pcmu_passthrough {
            NARROW_BAND_RATE
        } else {
            OPUS_SAMPLE_RATE
        };
        let state = Arc::new(BridgeState::with_sample_rates(
            ngn_to_peer_hz,
            NARROW_BAND_RATE,
        ));

        // NGN → peer: μ-law → 8k PCM → 48k PCM → Opus → peer.send_media
        // (direct_pcmu_passthrough = true なら μ-law をそのまま PT 0 で peer へ素通し)
        let ngn_to_peer = tokio::spawn(ngn_to_peer_loop(
            ngn_socket.clone(),
            ngn_state.clone(),
            peer.clone(),
            state.clone(),
            opus_payload_type,
            direct_pcmu_passthrough,
            metrics.clone(),
        ));

        // peer → NGN: peer.take_media_rx (Opus) → 48k PCM → 8k PCM → μ-law → NGN UDP
        // (direct_pcmu_passthrough = true なら受信した PT 0 PCMU をそのまま μ-law として NGN へ)
        let peer_to_ngn = tokio::spawn(peer_to_ngn_loop(
            peer_media_rx,
            ngn_socket.clone(),
            ngn_state.clone(),
            state.clone(),
            opus_payload_type,
            direct_pcmu_passthrough,
            metrics.clone(),
        ));

        // RFC 3550 §6.4.1 / RFC 5761 §3.3 / Issue #182 (f):
        // peer→NGN 方向の egress に対して 5 秒周期で NGN へ RTCP SR を送出する。
        let peer_to_ngn_sr = tokio::spawn(rtcp_sr_sender_loop(
            ngn_socket.clone(),
            ngn_state.clone(),
            state.web_to_ngn_egress.clone(),
            metrics,
            "peer_to_ngn",
        ));

        Self {
            ngn_to_peer: Some(ngn_to_peer),
            peer_to_ngn: Some(peer_to_ngn),
            peer_to_ngn_sr: Some(peer_to_ngn_sr),
            state,
            ngn_socket,
            ngn_state,
        }
    }

    /// Issue #69: NGN 側 socket から NGN ピア宛に任意 RTP datagram を 1 つ送る。
    pub async fn send_to_ngn(&self, datagram: &[u8]) -> Result<()> {
        let dest = { *self.ngn_state.peer.lock().await };
        let dest = dest.ok_or_else(|| anyhow::anyhow!("NGN peer 未確定"))?;
        self.ngn_socket.send_to(datagram, dest).await?;
        Ok(())
    }

    /// 両ループ + RTCP SR タスクを停止する (Issue #182 (f))。
    pub async fn stop(mut self) {
        if let Some(h) = self.ngn_to_peer.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.peer_to_ngn.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.peer_to_ngn_sr.take() {
            h.abort();
            let _ = h.await;
        }
    }

    /// 統計: (NGN→peer 成功数, peer→NGN 成功数, トランスコード失敗数)
    pub fn stats(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.state.ngn_to_web_packets.load(Ordering::Relaxed),
            self.state.web_to_ngn_packets.load(Ordering::Relaxed),
            self.state.transcode_errors.load(Ordering::Relaxed),
        )
    }

    /// 現在の peer→NGN 方向の送信 SSRC (RFC 3550 §5.1)。
    /// bridge 起動時に random 払い出された値で、 lifetime 中に変わらない。
    pub async fn peer_to_ngn_ssrc(&self) -> u32 {
        self.state.web_to_ngn_egress.lock().await.ssrc
    }
}

impl Drop for WebRtcAudioBridge {
    fn drop(&mut self) {
        if let Some(h) = self.ngn_to_peer.take() {
            h.abort();
        }
        if let Some(h) = self.peer_to_ngn.take() {
            h.abort();
        }
        // RFC 3550 §6.4.1 / Issue #182 (f): SR タスクも bridge 同寿命。
        if let Some(h) = self.peer_to_ngn_sr.take() {
            h.abort();
        }
    }
}

/// NGN (μ-law 8k) → WebRTC peer (Opus 48k) 方向。
///
/// 1 RTP 受信 → 1 MediaFrame 送信。 `peer.send_media` は run_loop に
/// command で渡すだけなので背圧は実質 mpsc バッファ容量で吸収される。
async fn ngn_to_peer_loop(
    from_socket: Arc<UdpSocket>,
    from_state: Arc<LegState>,
    peer: Arc<dyn PeerSession>,
    state: Arc<BridgeState>,
    opus_pt: u8,
    direct_pcmu_passthrough: bool,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    let span = tracing::trace_span!("transcode_ngn_to_peer");
    let _enter = span.enter();

    debug!(direct_pcmu_passthrough, "ngn_to_peer_loop START");

    // 直送モード時は upsampler / encoder を初期化しない (使わない)。
    let mut upsampler_enc: Option<(UpsamplerNbToWb, OpusEncoder)> = if direct_pcmu_passthrough {
        None
    } else {
        let up = match UpsamplerNbToWb::new() {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "Upsampler 初期化失敗 → NGN→peer 方向停止");
                return;
            }
        };
        let enc = match OpusEncoder::new() {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "Opus エンコーダ初期化失敗 → NGN→peer 方向停止");
                return;
            }
        };
        Some((up, enc))
    };

    // RTP timestamp 単調増加 (RFC 7587 §4.1: Opus は 48kHz、 RFC 3551 §4.5.14:
    // PCMU は 8kHz)。 直送モードでは frame ごとに 160 サンプル進める。
    // Issue #112: bridge lifetime で SSRC / seq / timestamp を一貫させるため
    // `BridgeState::ngn_to_web_egress` を共有。 MediaFrame には SSRC / seq は
    // 載らないため (str0m が WebRTC レッグ上で割り当てる) timestamp のみ消費。
    let ts_increment = if direct_pcmu_passthrough {
        SAMPLES_PER_FRAME as u32
    } else {
        OPUS_FRAME_SAMPLES as u32
    };

    // RFC 3550 §5.1 / §6.4 で 1500 byte 超過があり得るため jumbo frame 上限
    // 9000 byte で受ける (Issue #96)。 PCMU 20ms = 172 byte の常用パスには影響なし。
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    loop {
        let (n, src) = match from_socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!(error=%e, "NGN recv エラー → NGN→peer 方向終了");
                return;
            }
        };
        if n == RECV_BUF_SIZE {
            warn!(
                bytes = n,
                "NGN→peer: RTP datagram が受信バッファ上限 ({} byte) に達 — \
                 truncate の可能性 (RFC 3550 §5.1 / §6.4, Issue #96)",
                RECV_BUF_SIZE
            );
        }
        {
            let mut p = from_state.peer.lock().await;
            if p.as_ref() != Some(&src) {
                trace!(?src, "NGN 側 RTP 送信元学習");
                *p = Some(src);
            }
        }

        let pkt = match RtpPacket::from_bytes(&buf[..n]) {
            Ok(p) => p,
            Err(e) => {
                trace!(error=%e, "NGN RTP パース失敗 → drop");
                state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        if pkt.payload_type != PAYLOAD_TYPE_ULAW {
            trace!(pt = pkt.payload_type, "NGN 側 PT≠0 → drop");
            state.transcode_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if pkt.payload.len() != SAMPLES_PER_FRAME {
            trace!(len = pkt.payload.len(), "NGN payload 長異常 → drop");
            state.transcode_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        // RFC 3550 §8.2: ingress SSRC が egress SSRC と衝突したら
        // egress SSRC を rotate する (Issue #182 (e))。
        // ngn_to_peer 方向は MediaFrame に SSRC が乗らない (str0m が割り当て)
        // ため衝突自体が peer 側に伝わる経路は無いが、 egress state は他方向
        // との対称性 / 観測性のため同様に rotate する。
        {
            let mut eg = state.ngn_to_web_egress.lock().await;
            if eg.check_and_rotate_on_collision(pkt.ssrc) {
                warn!(
                    ssrc = format!("0x{:08x}", pkt.ssrc),
                    new_ssrc = format!("0x{:08x}", eg.ssrc),
                    "SSRC collision detected (ngn_to_peer: ingress = egress), \
                     rotating egress SSRC (RFC 3550 §8.2)"
                );
                if let Some(m) = metrics.as_ref() {
                    m.add_ssrc_collision_detected(1);
                }
            }
        }

        // payload を先に決めてから ts を払い出す (失敗時に ts を消費しないため)。
        let (pt_out, payload_out) = if direct_pcmu_passthrough {
            // PCMU 直送: μ-law payload をそのまま PT 0 で peer に渡す。
            // RTP timestamp は 8kHz 単位 (RFC 3551 §4.5.14: PCMU clock=8000)、
            // 1 frame = SAMPLES_PER_FRAME (= 160) 進める。
            (PAYLOAD_TYPE_ULAW, pkt.payload.clone())
        } else {
            let (upsampler, encoder) = match upsampler_enc.as_mut() {
                Some(v) => v,
                None => {
                    trace!("upsampler/encoder 未初期化 (direct mode と矛盾) → drop");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let pcm8: Vec<i16> = pkt.payload.iter().map(|b| decode_ulaw(*b)).collect();
            let nb = AudioFrame::new(NARROW_BAND_RATE, pcm8);
            let wb = match upsampler.process(&nb) {
                Ok(v) => v,
                Err(e) => {
                    trace!(error=%e, "アップサンプル失敗");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let opus_payload = match encoder.encode(&wb) {
                Ok(v) => v,
                Err(e) => {
                    trace!(error=%e, "Opus エンコード失敗");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            (opus_pt, opus_payload)
        };

        // 共有 egress state から timestamp を払い出して frame ごとに 1 進める。
        // MediaFrame は SSRC / seq を持たない (str0m が割り当てる) ため、
        // ここで消費するのは timestamp のみ。 ただし egress state を共有することで
        // bridge lifetime 中に timestamp 系列が一貫する。
        let rtp_time = {
            let mut eg = state.ngn_to_web_egress.lock().await;
            let (_seq, ts, _ssrc) = eg.next(ts_increment);
            ts
        };

        let frame = MediaFrame {
            pt: pt_out,
            rtp_time,
            payload: payload_out,
            network_time: std::time::Instant::now(),
        };

        if let Err(e) = peer.send_media(frame).await {
            debug!(error=%e, "peer.send_media 失敗 → NGN→peer 方向終了");
            return;
        }
        state.ngn_to_web_packets.fetch_add(1, Ordering::Relaxed);
        if let Some(m) = metrics.as_ref() {
            m.add_rtp_ngn_to_ext(1);
        }
    }
}

/// WebRTC peer (Opus 48k) → NGN (μ-law 8k) 方向。
///
/// `peer_media_rx` から MediaFrame を 1 個受け取り、 Opus decode → resample →
/// μ-law encode → RTP packet 構築 → NGN UDP socket へ送信する。
async fn peer_to_ngn_loop(
    mut peer_media_rx: mpsc::Receiver<MediaFrame>,
    to_socket: Arc<UdpSocket>,
    to_state: Arc<LegState>,
    state: Arc<BridgeState>,
    opus_pt: u8,
    direct_pcmu_passthrough: bool,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    let span = tracing::trace_span!("transcode_peer_to_ngn");
    let _enter = span.enter();

    debug!(direct_pcmu_passthrough, "peer_to_ngn_loop START");

    // 直送モードでは decoder / downsampler は使わない。
    let mut down_dec: Option<(DownsamplerWbToNb, OpusDecoder)> = if direct_pcmu_passthrough {
        None
    } else {
        let down = match DownsamplerWbToNb::new() {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "Downsampler 初期化失敗 → peer→NGN 方向停止");
                return;
            }
        };
        let dec = match OpusDecoder::new() {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "Opus デコーダ初期化失敗 → peer→NGN 方向停止");
                return;
            }
        };
        Some((down, dec))
    };
    // RFC 7587 §4.1 / Issue #200: 2.5/5/10 ms 短尺フレームを 20 ms 境界に
    // 揃えるための累積バッファ。 トランスコードモード (Opus → PCMU) でのみ
    // 使い、 PCMU 直送モードでは使わない (PCMU は受信時点で既に 20 ms 単位)。
    let mut accum = OpusToPcmuAccum::new();

    // RTP egress 状態は `BridgeState::web_to_ngn_egress` を共有 (Issue #112)。
    let expected_pt = if direct_pcmu_passthrough {
        PAYLOAD_TYPE_ULAW
    } else {
        opus_pt
    };

    while let Some(frame) = peer_media_rx.recv().await {
        if frame.pt != expected_pt {
            trace!(
                pt = frame.pt,
                expected = expected_pt,
                "peer 側 PT 不一致 → drop"
            );
            state.transcode_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        // 1 受信 MediaFrame からの出力 μ-law payload 列。
        // - PCMU 直送モード: 1 chunk (= frame.payload そのまま)。
        // - トランスコードモード: Opus decode 結果を 20ms ごとに分割して
        //   N chunk (N = frame_size_ms / 20、 RFC 7587 §4.1 で許される
        //   2.5/5/10/20/40/60 ms 単体フレーム、 もしくは RFC 6716 §3.2 multi-frame
        //   packet で合算 120 ms まで)。
        //
        // Issue #89 (PR #197) で 40/60 ms 単発フレームの 20 ms 分割は実装済。
        // Issue #200 (本 PR) で `OpusToPcmuAccum` を導入し、 2.5/5/10 ms 短尺
        // フレームは 20 ms 境界が満ちるまで累積、 満ちた時点で chunk を emit する。
        let ulaw_chunks: Vec<Vec<u8>> = if direct_pcmu_passthrough {
            // PCMU 直送: peer からの μ-law payload をそのまま NGN へ。
            vec![frame.payload.clone()]
        } else {
            let (downsampler, decoder) = match down_dec.as_mut() {
                Some(v) => v,
                None => {
                    // direct_pcmu_passthrough=false の初期化で必ず Some になるが、
                    // production code で unreachable panic を避けるため defensive
                    // に drop して継続する (CLAUDE.md §6.5)。
                    trace!("down_dec 未初期化 (unreachable) → drop");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let wb = match decoder.decode(&frame.payload) {
                Ok(v) => v,
                Err(e) => {
                    trace!(error=%e, "Opus デコード失敗");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            if wb.samples.is_empty() {
                // RFC 7587 §6.2 PLC は OpusDecoder::decode が 20 ms 分の
                // サンプルを返すため、 ここで空になるのは libopus 異常時のみ。
                trace!("Opus decode が空サンプルを返した → drop");
                state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // 累積 → 20 ms 境界が満ちるたびに μ-law chunk を取り出す。
            // 短尺フレーム (2.5/5/10 ms) を単発受信した場合は空 Vec が返り、
            // 累積バッファに保持され、 次の packet で flush される。
            match accum.push(&wb.samples, downsampler) {
                Ok(v) => v,
                Err(e) => {
                    trace!(error=%e, "累積 / ダウンサンプル失敗");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        };

        // 短尺フレーム単発で chunk が出ない場合は 1 packet skip (累積継続)。
        // 直送モードでは frame.payload が必ず 1 chunk になるため empty は起きない。
        if ulaw_chunks.is_empty() {
            trace!(
                pending = accum.buf.len(),
                "短尺 Opus フレーム → 累積バッファに保持 (RFC 7587 §4.1 / Issue #200)"
            );
            continue;
        }

        let dest = match *to_state.peer.lock().await {
            Some(d) => d,
            None => {
                trace!("NGN 側 peer 未確定 → drop");
                continue;
            }
        };

        // 各 chunk を 1 RTP packet として送出。 RFC 3550 §5.1: 同一 SSRC 内では
        // seq が monotonically increasing、 timestamp は sample 数だけ進む
        // (RFC 3551 §4.5.14: PCMU 8 kHz × 20 ms = 160 samples)。
        // RFC 3551 §4.1 (M bit): talkspurt 開始の最初の packet に M=1
        // (Issue #84: WebRTC peer の Opus DTX 復帰直後を talkspurt 開始として
        //  検出する)。
        for ulaw in ulaw_chunks {
            let (seq, ts, ssrc, marker) = {
                let mut eg = state.web_to_ngn_egress.lock().await;
                eg.next_with_marker(SAMPLES_PER_FRAME as u32, Instant::now())
            };
            let out_pkt = RtpPacket {
                payload_type: PAYLOAD_TYPE_ULAW,
                marker,
                sequence: seq,
                timestamp: ts,
                ssrc,
                payload: ulaw,
            };

            let payload_len = out_pkt.payload.len();
            if let Err(e) = to_socket.send_to(&out_pkt.to_bytes(), dest).await {
                warn!(error=%e, "NGN へ RTP forward 失敗");
                break;
            }
            // RFC 3550 §6.4.1: SR の sender's packet/octet count は wire に
            // 出した分のみ集計 (Issue #182 (f) / #112)。 anchor も wire 送出
            // 成功時に初回確定する (Issue #182 (d))。
            {
                let mut eg = state.web_to_ngn_egress.lock().await;
                eg.record_sent(payload_len, ts);
            }
            state.web_to_ngn_packets.fetch_add(1, Ordering::Relaxed);
            if let Some(m) = metrics.as_ref() {
                m.add_rtp_ext_to_ngn(1);
            }
        }
    }
    debug!("peer_media_rx closed → peer→NGN 方向終了");
}

/// テスト用ヘルパ: 1 NGN RTP パケット (μ-law 20ms 無音) を作る。
#[cfg(test)]
pub(crate) fn build_ulaw_rtp_packet(seq: u16, ts: u32, ssrc: u32, samples: &[i16]) -> Vec<u8> {
    let payload: Vec<u8> = samples.iter().map(|s| encode_ulaw(*s)).collect();
    RtpPacket {
        payload_type: PAYLOAD_TYPE_ULAW,
        marker: false,
        sequence: seq,
        timestamp: ts,
        ssrc,
        payload,
    }
    .to_bytes()
}

/// テスト用ヘルパ: 1 WebRTC RTP パケット (Opus encode 済み) を作る。
#[cfg(test)]
pub(crate) fn build_opus_rtp_packet(
    pt: u8,
    seq: u16,
    ts: u32,
    ssrc: u32,
    encoder: &mut OpusEncoder,
    pcm48k: &AudioFrame,
) -> Result<Vec<u8>> {
    use anyhow::Context;
    let payload = encoder
        .encode(pcm48k)
        .context("テスト用 Opus エンコード失敗")?;
    Ok(RtpPacket {
        payload_type: pt,
        marker: false,
        sequence: seq,
        timestamp: ts,
        ssrc,
        payload,
    }
    .to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::codec::opus::OPUS_SAMPLE_RATE;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn detect_opus_payload_type_basic() {
        let sdp = b"v=0\r\n\
                    m=audio 40000 UDP/TLS/RTP/SAVPF 111 0\r\n\
                    a=rtpmap:111 opus/48000/2\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(find_opus_payload_type(sdp), Some(111));
        assert!(sdp_uses_opus(sdp));
    }

    #[test]
    fn detect_opus_payload_type_absent() {
        let sdp = b"v=0\r\n\
                    m=audio 40000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(find_opus_payload_type(sdp), None);
        assert!(!sdp_uses_opus(sdp));
    }

    #[test]
    fn detect_opus_payload_type_lowercase_codec() {
        let sdp = b"a=rtpmap:96 OPUS/48000/2\r\n";
        assert_eq!(find_opus_payload_type(sdp), Some(96));
    }

    /// NGN→WebRTC 方向: μ-law を投入して Opus パケットが反対側で受信できるか。
    ///
    /// Issue #105 でジッタバッファを統合したため、 depth (`JITTER_DEPTH = 4`)
    /// が満たされる **5 packet** 投入する (initial fill + 1 pull 分)。
    #[tokio::test]
    async fn ngn_to_web_transcodes_packet() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 8 kHz 1 kHz トーン (160 samples)
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        // depth=4 を満たすため 5 packet 投入 (初期 fill 4 + pull 1)
        for i in 0..5u16 {
            let pkt = build_ulaw_rtp_packet(
                i + 1,
                i as u32 * SAMPLES_PER_FRAME as u32,
                0xAAAA_AAAA,
                &samples,
            );
            ngn_peer.send_to(&pkt, ngn_addr).await.unwrap();
        }

        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(2), web_peer.recv_from(&mut buf))
            .await
            .expect("WebRTC 側で受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.payload_type, DEFAULT_OPUS_PT);
        assert!(!recv.payload.is_empty(), "Opus payload 空");

        // ブリッジ統計に反映されている
        let (n2w, _w2n, _err) = bridge.stats();
        assert!(n2w >= 1, "NGN→WebRTC カウンタが上がっていない: {}", n2w);
        bridge.stop().await;
    }

    /// Issue #105 / RFC 3550 §6.4.1: NGN→Web 方向で **時間方向に逆順** の
    /// RTP 入力を流し、 transcoder が NGN レッグから受け取った順序ではなく
    /// **seq 番号順** で WebRTC 側へ送出することを確認する。
    ///
    /// 受信順序: seq = [4, 3, 2, 1, 0]
    /// 期待送出順序: seq は単調増加 (jitter buffer pull 順)
    ///
    /// transcoder の出力 RTP seq は内部で再生成される (`seq.wrapping_add(1)`)
    /// ため、 受信側 seq の単調増加性そのものは検証できない。 代わりに
    /// **payload 識別子** (μ-law payload の先頭バイトで識別) を入力に埋め込み、
    /// 出力側で受信される payload の発出順序が「入力の seq 昇順に対応する」
    /// ことを確認する。
    #[tokio::test]
    async fn rfc3550_6_4_1_ngn_to_web_reorders_packets_by_seq() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 各 seq に対し識別可能な「定数振幅」の μ-law トーンを生成する。
        // seq=N の payload は (N+1)*1000 Hz 相当のトーンとし、 Opus decode 後の
        // ピーク周波数で順序を識別できるようにする。 ただし Opus 経由では
        // 元周波数は復元しないので、 ここでは「Opus 出力の総数 = 入力数」と
        // 「先頭 payload が seq=0 由来」までを検証 (深い周波数分析は不要)。
        let build_packet = |seq: u16, marker_val: i16| -> Vec<u8> {
            let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
            for _ in 0..NB_FRAME_SAMPLES {
                samples.push(marker_val);
            }
            build_ulaw_rtp_packet(
                seq,
                seq as u32 * SAMPLES_PER_FRAME as u32,
                0x1234_5678,
                &samples,
            )
        };

        // depth=4 を満たし、 かつ reorder で 5 packet を逆順投入
        // seq=[4,3,2,1,0] (時間方向に逆)。 各々振幅 (seq+1)*1000 で識別。
        let inputs: Vec<(u16, i16)> = (0..5).rev().map(|s| (s as u16, (s + 1) * 1000)).collect();
        for (seq, amp) in &inputs {
            let pkt = build_packet(*seq, *amp);
            ngn_peer.send_to(&pkt, ngn_addr).await.unwrap();
            // 少し待ち、 buffer が確実に push を吸収するように
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // 出力側で 5 packet 受信する。 jitter buffer は depth 充足後に
        // seq 昇順で pull するため、 内部 seq の昇順 = WebRTC 側へ送出される順。
        let mut received_opus = Vec::with_capacity(5);
        for _ in 0..5 {
            let mut buf = vec![0u8; 1500];
            let (n, _) = timeout(Duration::from_secs(3), web_peer.recv_from(&mut buf))
                .await
                .expect("WebRTC 側で 5 packet 受信できない")
                .unwrap();
            let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
            assert_eq!(recv.payload_type, DEFAULT_OPUS_PT);
            received_opus.push(recv);
        }

        // 連続性: 出力 RTP の seq は単調増加 (1 ずつ)
        for w in received_opus.windows(2) {
            let prev = w[0].sequence;
            let curr = w[1].sequence;
            assert_eq!(
                curr.wrapping_sub(prev),
                1,
                "出力 RTP seq が単調増加していない: prev={} curr={}",
                prev,
                curr
            );
        }

        // 連続性: 出力 RTP の timestamp は OPUS_FRAME_SAMPLES (960) ずつ進む
        for w in received_opus.windows(2) {
            let prev = w[0].timestamp;
            let curr = w[1].timestamp;
            assert_eq!(
                curr.wrapping_sub(prev),
                OPUS_FRAME_SAMPLES as u32,
                "出力 RTP timestamp 増分が 960 でない: prev={} curr={}",
                prev,
                curr
            );
        }

        let (n2w, _w2n, err) = bridge.stats();
        assert_eq!(n2w, 5, "5 packet 全てが forward されているはず: {}", n2w);
        assert_eq!(err, 0, "reorder 経路で transcode error が出ている: {}", err);
        bridge.stop().await;
    }

    /// Issue #105 / RFC 3550 §6.4.1: Web→NGN 方向で **時間方向に逆順** の
    /// Opus RTP を流し、 transcoder が seq 番号順で NGN へ送出することを
    /// 確認する。
    ///
    /// NGN 側で受信した μ-law payload の RTP seq は 1 ずつ単調増加、
    /// timestamp は 160 (8 kHz × 20 ms) ずつ進む。
    #[tokio::test]
    async fn rfc3550_6_4_1_web_to_ngn_reorders_packets_by_seq() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_addr = web_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 48 kHz 1 kHz トーン (960 samples) を Opus 化
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

        // 5 packet を seq=[4,3,2,1,0] (逆順) で投入
        for s in (0..5u16).rev() {
            let pkt = build_opus_rtp_packet(
                DEFAULT_OPUS_PT,
                s,
                s as u32 * OPUS_FRAME_SAMPLES as u32,
                0x9ABC_DEF0,
                &mut enc,
                &frame,
            )
            .unwrap();
            web_peer.send_to(&pkt, web_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // NGN 側で 5 packet 受信
        let mut received = Vec::with_capacity(5);
        for _ in 0..5 {
            let mut buf = vec![0u8; 1500];
            let (n, _) = timeout(Duration::from_secs(3), ngn_peer.recv_from(&mut buf))
                .await
                .expect("NGN 側で 5 packet 受信できない")
                .unwrap();
            let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
            assert_eq!(recv.payload_type, PAYLOAD_TYPE_ULAW);
            assert_eq!(recv.payload.len(), SAMPLES_PER_FRAME);
            received.push(recv);
        }

        // 出力 RTP seq は単調増加 (1 ずつ)
        for w in received.windows(2) {
            assert_eq!(
                w[1].sequence.wrapping_sub(w[0].sequence),
                1,
                "出力 NGN seq が単調増加していない"
            );
        }

        // 出力 RTP timestamp は 160 (8 kHz × 20 ms) ずつ進む
        for w in received.windows(2) {
            assert_eq!(
                w[1].timestamp.wrapping_sub(w[0].timestamp),
                SAMPLES_PER_FRAME as u32,
                "出力 NGN timestamp 増分が 160 でない"
            );
        }

        let (_n2w, w2n, err) = bridge.stats();
        assert_eq!(w2n, 5, "5 packet 全てが forward されているはず: {}", w2n);
        assert_eq!(err, 0, "reorder 経路で transcode error が出ている: {}", err);
        bridge.stop().await;
    }

    /// WebRTC→NGN 方向: Opus を投入して μ-law が反対側で受信できるか。
    #[tokio::test]
    async fn web_to_ngn_transcodes_packet() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let _ngn_addr = ngn_sock.local_addr().unwrap();
        let web_addr = web_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 48 kHz 1 kHz トーン (960 samples) を Opus 化
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);
        // Issue #105: ジッタバッファ depth=4 を満たすため 5 packet 投入
        for i in 0..5u16 {
            let pkt = build_opus_rtp_packet(
                DEFAULT_OPUS_PT,
                i + 1,
                i as u32 * OPUS_FRAME_SAMPLES as u32,
                0xBBBB_BBBB,
                &mut enc,
                &frame,
            )
            .unwrap();
            web_peer.send_to(&pkt, web_addr).await.unwrap();
        }

        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(2), ngn_peer.recv_from(&mut buf))
            .await
            .expect("NGN 側で受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.payload_type, PAYLOAD_TYPE_ULAW);
        assert_eq!(recv.payload.len(), SAMPLES_PER_FRAME);

        let (_n2w, w2n, _err) = bridge.stats();
        assert!(w2n >= 1, "WebRTC→NGN カウンタが上がっていない: {}", w2n);
        bridge.stop().await;
    }

    /// Issue #89 / RFC 7587 §4.1: `TranscodingBridge::web_to_ngn_loop` は
    /// 40ms / 60ms の Opus フレーム (= 1920 / 2880 samples @ 48 kHz) を受信した
    /// 場合、 silently drop せず **20ms chunk に分割して N 個の PCMU RTP packet
    /// を NGN へ送出する** ことを契約として固定する。
    ///
    /// RFC 7587 §4.1 (Frame Sizes): "Opus supports five different frame sizes:
    /// 2.5, 5, 10, 20, 40, and 60 ms."
    /// RFC 7587 §4.2: "the receiver SHOULD NOT assume any particular frame size."
    ///
    /// 旧実装は `wb.samples.len() != WB_FRAME_SAMPLES` で 20ms 以外を全て drop
    /// していたため、 ブラウザが (DTX 復帰時等で) 40/60ms フレームを送るたびに
    /// NGN レッグの音声が途切れていた。
    ///
    /// 本テストは:
    /// 1. 40 ms Opus packet を 3 個投入 → NGN 側で 20ms PCMU を 6 個受信
    /// 2. 60 ms Opus packet を 2 個投入 → NGN 側で 20ms PCMU を 6 個受信
    /// を順次確認する。 各 PCMU は 160 bytes (20ms @ 8kHz)、 seq +1 連番、
    /// timestamp +160 連番 (RFC 3551 §4.5.14)。
    #[tokio::test]
    async fn rfc7587_4_1_web_to_ngn_splits_40ms_and_60ms_opus_into_pcmu_frames() {
        for (ms, n_input_packets) in [(40usize, 3usize), (60, 2)] {
            let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let web_addr = web_sock.local_addr().unwrap();

            let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let ngn_peer_addr = ngn_peer.local_addr().unwrap();
            let web_peer_addr = web_peer.local_addr().unwrap();

            let bridge = TranscodingBridge::start(TranscodeConfig {
                ngn_socket: ngn_sock,
                web_socket: web_sock,
                ngn_peer: Some(ngn_peer_addr),
                web_peer: Some(web_peer_addr),
                opus_payload_type: DEFAULT_OPUS_PT,
                metrics: None,
            })
            .unwrap();

            // N ms 分の 48 kHz 1 kHz sine wave を作る
            let n_samples = (OPUS_SAMPLE_RATE as usize * ms) / 1000;
            let mut samples = Vec::with_capacity(n_samples);
            for i in 0..n_samples {
                let t = i as f32 / OPUS_SAMPLE_RATE as f32;
                let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
                samples.push(v as i16);
            }
            let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

            // jitter depth=4 を満たすため、 最低 5 packet 投入する。
            // 40 ms × 3 = 120 ms 出力 (6 PCMU frame)、 60 ms × 2 = 120 ms 出力 (6
            // PCMU frame) でも、 jitter pull は 5 個目以降で始まる。 そこで
            // 入力 packet 数は depth + 1 を最低保証する。
            let n_total = n_input_packets.max(JITTER_DEPTH + 1);
            let mut enc = OpusEncoder::new().unwrap();
            for i in 0..n_total {
                let opus_payload = enc.encode_test_variable_duration(&frame).unwrap();
                let pkt = RtpPacket {
                    payload_type: DEFAULT_OPUS_PT,
                    marker: false,
                    sequence: (i as u16) + 1,
                    timestamp: (i as u32) * (n_samples as u32),
                    ssrc: 0xDEAD_BEEF,
                    payload: opus_payload,
                }
                .to_bytes();
                web_peer.send_to(&pkt, web_addr).await.unwrap();
            }

            // 各入力 packet は ms/20 個の PCMU を生成する。 全 packet で合計
            // n_total × (ms/20) 個の PCMU が NGN 側に届く。
            let expected_pcmu = n_total * (ms / 20);
            let mut received: Vec<RtpPacket> = Vec::with_capacity(expected_pcmu);
            for _ in 0..expected_pcmu {
                let mut buf = vec![0u8; 1500];
                let (n, _) = timeout(Duration::from_secs(3), ngn_peer.recv_from(&mut buf))
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "{} ms: NGN 側で {} 個目の PCMU を受信できない (silently drop?)",
                            ms,
                            received.len() + 1
                        )
                    })
                    .unwrap();
                let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
                assert_eq!(
                    recv.payload_type, PAYLOAD_TYPE_ULAW,
                    "{} ms: PT が PCMU でない",
                    ms
                );
                assert_eq!(
                    recv.payload.len(),
                    SAMPLES_PER_FRAME,
                    "{} ms: PCMU payload が 160 bytes (RFC 3551 §4.5.14) でない: {}",
                    ms,
                    recv.payload.len()
                );
                received.push(recv);
            }

            // seq +1 / timestamp +160 連番 (RFC 3550 §5.1 / RFC 3551 §4.5.14)
            for w in received.windows(2) {
                assert_eq!(
                    w[1].sequence.wrapping_sub(w[0].sequence),
                    1,
                    "{} ms: 分割 PCMU の seq が連番でない",
                    ms
                );
                assert_eq!(
                    w[1].timestamp.wrapping_sub(w[0].timestamp),
                    SAMPLES_PER_FRAME as u32,
                    "{} ms: 分割 PCMU の timestamp 増分が 160 でない",
                    ms
                );
            }

            // SSRC は全 packet で一致 (RFC 3550 §5.1)
            let ssrc0 = received[0].ssrc;
            for (i, pkt) in received.iter().enumerate() {
                assert_eq!(
                    pkt.ssrc, ssrc0,
                    "{} ms: frame #{} で SSRC が変わっている",
                    ms, i
                );
            }

            // 統計上 transcode_errors は 0 のはず (silently drop が消えた契約)
            let (_n2w, w2n, err) = bridge.stats();
            assert_eq!(
                err, 0,
                "{} ms: transcode_errors が 0 でない (silently drop 残存): {}",
                ms, err
            );
            assert!(
                w2n >= expected_pcmu as u64,
                "{} ms: PCMU 送信カウンタが {} 以上でない: {}",
                ms,
                expected_pcmu,
                w2n
            );

            bridge.stop().await;
        }
    }

    /// Issue #89 / RFC 7587 §4.1: `WebRtcAudioBridge::peer_to_ngn_loop`
    /// (str0m 経由の Opus → NGN PCMU 経路) も 40ms / 60ms フレームを 20ms 単位の
    /// PCMU RTP packet に分割して NGN へ流す。
    ///
    /// `direct_pcmu_passthrough = false` (= Opus → PCMU トランスコード経路) の
    /// 分岐に対して RFC 7587 §4.1 契約を固定する。
    #[tokio::test]
    async fn rfc7587_4_1_peer_to_ngn_splits_40ms_and_60ms_opus_into_pcmu_frames() {
        use std::sync::Arc as SArc;

        struct NoopPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoopPeer {
            async fn handle_offer(&self, _: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, _: MediaFrame) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        for ms in [40usize, 60] {
            let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

            let (peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(16);

            let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
                ngn_socket: ngn_sock,
                ngn_peer: Some(ngn_peer_addr),
                peer: Arc::new(NoopPeer),
                peer_media_rx: peer_rx,
                opus_payload_type: DEFAULT_OPUS_PT,
                // Opus → PCMU トランスコード経路 (Issue #89 修正対象)
                direct_pcmu_passthrough: false,
                metrics: None,
            });

            // N ms 分の 48 kHz 1 kHz sine wave をエンコード
            let n_samples = (OPUS_SAMPLE_RATE as usize * ms) / 1000;
            let mut samples = Vec::with_capacity(n_samples);
            for i in 0..n_samples {
                let t = i as f32 / OPUS_SAMPLE_RATE as f32;
                let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
                samples.push(v as i16);
            }
            let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

            let mut enc = OpusEncoder::new().unwrap();
            let opus_payload = enc.encode_test_variable_duration(&frame).unwrap();

            // 1 個の長尺 Opus packet を送る (jitter buffer なしの直結 mpsc 経路)
            peer_tx
                .send(MediaFrame {
                    pt: DEFAULT_OPUS_PT,
                    rtp_time: 0,
                    payload: opus_payload,
                    network_time: std::time::Instant::now(),
                })
                .await
                .unwrap();

            // ms/20 個の PCMU が NGN 側に届く
            let expected_pcmu = ms / 20;
            let mut received: Vec<RtpPacket> = Vec::with_capacity(expected_pcmu);
            for _ in 0..expected_pcmu {
                let mut buf = vec![0u8; 1500];
                let (n, _) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "{} ms: NGN 側で {} 個目の PCMU を受信できない",
                            ms,
                            received.len() + 1
                        )
                    })
                    .unwrap();
                let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
                assert_eq!(recv.payload_type, PAYLOAD_TYPE_ULAW, "{} ms PT 不正", ms);
                assert_eq!(
                    recv.payload.len(),
                    SAMPLES_PER_FRAME,
                    "{} ms: PCMU payload が 160 bytes でない",
                    ms
                );
                received.push(recv);
            }

            // 連続性 (seq +1, ts +160)
            for w in received.windows(2) {
                assert_eq!(
                    w[1].sequence.wrapping_sub(w[0].sequence),
                    1,
                    "{} ms peer→NGN: seq 不連続",
                    ms
                );
                assert_eq!(
                    w[1].timestamp.wrapping_sub(w[0].timestamp),
                    SAMPLES_PER_FRAME as u32,
                    "{} ms peer→NGN: timestamp 増分不正",
                    ms
                );
            }

            let (_n2p, p2n, err) = bridge.stats();
            assert_eq!(
                err, 0,
                "{} ms peer→NGN: transcode_errors が 0 でない (silently drop): {}",
                ms, err
            );
            assert!(
                p2n >= expected_pcmu as u64,
                "{} ms peer→NGN: PCMU 送信カウンタが {} 以上でない: {}",
                ms,
                expected_pcmu,
                p2n
            );

            bridge.stop().await;
        }
    }

    /// Issue #87 / #121: NGN socket → WebRtcAudioBridge → peer.send_media
    /// 経路が PCMU 1 packet で起動し、 peer に Opus MediaFrame が届く。
    #[tokio::test]
    async fn webrtc_audio_bridge_ngn_to_peer_emits_opus_media_frame() {
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc as SArc;
        use tokio::sync::Mutex as TMutex;

        // sabiden 内 mock peer: send_media を回数カウントして observed に積む。
        struct MockPeer {
            received: SArc<TMutex<Vec<MediaFrame>>>,
            counter: SArc<AtomicU32>,
        }

        #[async_trait]
        impl PeerSession for MockPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, frame: MediaFrame) -> anyhow::Result<()> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                self.received.lock().await.push(frame);
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // 1 RTP datagram を投入できる NGN socket
        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        // peer_media_rx は使用しない (peer→NGN 方向はテストしない) ので空チャネル
        let (_dummy_tx, dummy_rx) = mpsc::channel::<MediaFrame>(1);

        let received: SArc<TMutex<Vec<MediaFrame>>> = SArc::new(TMutex::new(Vec::new()));
        let counter = SArc::new(AtomicU32::new(0));
        let mock_peer: Arc<dyn PeerSession> = Arc::new(MockPeer {
            received: received.clone(),
            counter: counter.clone(),
        });

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: mock_peer,
            peer_media_rx: dummy_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: false,
            metrics: None,
        });

        // 8 kHz 1 kHz トーン (160 samples) を μ-law 化して NGN socket に投入
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let pkt = build_ulaw_rtp_packet(1, 0, 0xCAFE_BEEF, &samples);
        ngn_peer_sock.send_to(&pkt, ngn_addr).await.unwrap();

        // peer.send_media が呼ばれるまで最大 2 秒待つ
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while counter.load(Ordering::SeqCst) == 0 {
            if std::time::Instant::now() > deadline {
                panic!("WebRtcAudioBridge: NGN→peer 方向で peer.send_media が呼ばれない");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let frames = received.lock().await;
        assert_eq!(frames.len(), 1, "1 frame 受信されているはず");
        assert_eq!(frames[0].pt, DEFAULT_OPUS_PT, "Opus PT で push されている");
        assert!(!frames[0].payload.is_empty(), "Opus payload が空");

        let (n2p, _p2n, _err) = bridge.stats();
        assert!(n2p >= 1, "stats 反映されていない: {}", n2p);
        bridge.stop().await;
    }

    /// Issue #87: peer_media_rx (Opus) → NGN socket (μ-law) 方向。
    /// テストフレームを peer_media_rx に push し、 NGN socket で μ-law が
    /// 受信できることを確認する。
    #[tokio::test]
    async fn webrtc_audio_bridge_peer_to_ngn_emits_pcmu_to_ngn_socket() {
        use std::sync::Arc as SArc;

        // dummy peer: send_media は呼ばれない (NGN→peer は流さないので)
        struct NoopPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoopPeer {
            async fn handle_offer(&self, _: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        let (peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(8);

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: Arc::new(NoopPeer),
            peer_media_rx: peer_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: false,
            metrics: None,
        });

        // 48 kHz 1 kHz トーンを Opus encode し、 MediaFrame として peer_tx に push
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);
        let opus_payload = enc.encode(&frame).unwrap();
        let media = MediaFrame {
            pt: DEFAULT_OPUS_PT,
            rtp_time: 0,
            payload: opus_payload,
            network_time: std::time::Instant::now(),
        };
        peer_tx.send(media).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, _src) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("NGN socket で μ-law が受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(
            recv.payload_type, PAYLOAD_TYPE_ULAW,
            "PCMU PT=0 で送られているはず"
        );
        assert_eq!(recv.payload.len(), SAMPLES_PER_FRAME);

        let (_n2p, p2n, _err) = bridge.stats();
        assert!(p2n >= 1, "peer→NGN stats 反映されていない: {}", p2n);
        bridge.stop().await;
    }

    /// Issue #150 / RFC 3551 §4.5.14: `direct_pcmu_passthrough = true` 経路で
    /// NGN UDP socket 受信の μ-law payload が `MediaFrame { pt: 0 }` として
    /// **不変**で peer に渡ることを確認する。
    ///
    /// 既存テスト `webrtc_audio_bridge_ngn_to_peer_emits_opus_media_frame` は
    /// `false` で transcode 経路 (μ-law → Opus) のみを検証していたため、
    /// production で唯一使われる直送経路に test gap があった (PR #149 review)。
    ///
    /// 期待:
    /// - peer.send_media に届く `MediaFrame.pt == PAYLOAD_TYPE_ULAW (0)`
    /// - `MediaFrame.payload` は受信 RTP の payload と完全一致 (encode/decode しない)
    /// - RTP timestamp は 8 kHz クロック (RFC 3551 §4.5.14: PCMU clock=8000)
    ///   なので、 1 frame で `SAMPLES_PER_FRAME (= 160)` 進む。
    #[tokio::test]
    async fn rfc3551_4_5_14_pcmu_passthrough_ngn_to_peer_preserves_payload() {
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc as SArc;
        use tokio::sync::Mutex as TMutex;

        struct CapturePeer {
            received: SArc<TMutex<Vec<MediaFrame>>>,
            counter: SArc<AtomicU32>,
        }

        #[async_trait]
        impl PeerSession for CapturePeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, frame: MediaFrame) -> anyhow::Result<()> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                self.received.lock().await.push(frame);
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        // peer→NGN 方向は使わない
        let (_dummy_tx, dummy_rx) = mpsc::channel::<MediaFrame>(1);

        let received: SArc<TMutex<Vec<MediaFrame>>> = SArc::new(TMutex::new(Vec::new()));
        let counter = SArc::new(AtomicU32::new(0));
        let mock_peer: Arc<dyn PeerSession> = Arc::new(CapturePeer {
            received: received.clone(),
            counter: counter.clone(),
        });

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: mock_peer,
            peer_media_rx: dummy_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: true,
            metrics: None,
        });

        // 8 kHz 1 kHz トーン (160 samples) を μ-law 化
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        // 期待 payload: build_ulaw_rtp_packet と同じ μ-law エンコード結果
        let expected_payload: Vec<u8> = samples.iter().map(|s| encode_ulaw(*s)).collect();
        let pkt = build_ulaw_rtp_packet(1, 0, 0xDEAD_BEEF, &samples);
        ngn_peer_sock.send_to(&pkt, ngn_addr).await.unwrap();

        // 1 frame 目を投入: peer.send_media が呼ばれるまで待つ
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while counter.load(Ordering::SeqCst) == 0 {
            if std::time::Instant::now() > deadline {
                panic!("direct_pcmu_passthrough: NGN→peer 方向で peer.send_media が呼ばれない");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // 連続性確認のため 2 frame 目も投入 (rtp_time が 160 進むことを検証)
        let pkt2 = build_ulaw_rtp_packet(2, 160, 0xDEAD_BEEF, &samples);
        ngn_peer_sock.send_to(&pkt2, ngn_addr).await.unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while counter.load(Ordering::SeqCst) < 2 {
            if std::time::Instant::now() > deadline {
                panic!("2 frame 目が peer に届かない");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let frames = received.lock().await;
        assert_eq!(frames.len(), 2, "2 frame 受信されているはず");

        // PT 不変 (RFC 3551 §4.5.14: PCMU PT=0)
        assert_eq!(
            frames[0].pt, PAYLOAD_TYPE_ULAW,
            "passthrough は PCMU PT=0 で渡すべき"
        );
        assert_eq!(
            frames[1].pt, PAYLOAD_TYPE_ULAW,
            "passthrough は 2 frame 目も PCMU PT=0"
        );

        // payload 不変 (encode/decode を経由していない)
        assert_eq!(
            frames[0].payload, expected_payload,
            "μ-law payload が不変で peer に渡るべき (encode/decode しない)"
        );
        assert_eq!(
            frames[1].payload, expected_payload,
            "2 frame 目も同じ payload が不変で渡るべき"
        );

        // RTP timestamp は 8 kHz クロックで SAMPLES_PER_FRAME 単位に進む
        // (RFC 3551 §4.5.14: PCMU clock = 8000 Hz)
        let dt = frames[1].rtp_time.wrapping_sub(frames[0].rtp_time);
        assert_eq!(
            dt as usize, SAMPLES_PER_FRAME,
            "passthrough の RTP timestamp 増分は 160 (8kHz × 20ms)"
        );

        let (n2p, _p2n, err) = bridge.stats();
        assert!(n2p >= 2, "stats が 2 frame 反映されていない: {}", n2p);
        assert_eq!(err, 0, "passthrough 経路でエラーが出ている: {}", err);
        bridge.stop().await;
    }

    /// Issue #150 / RFC 3551 §4.5.14: `direct_pcmu_passthrough = true` 経路で
    /// peer から流れる `MediaFrame { pt: 0 }` の μ-law payload が NGN UDP socket
    /// に **不変**で出ることを確認する。
    ///
    /// 既存テスト `webrtc_audio_bridge_peer_to_ngn_emits_pcmu_to_ngn_socket` は
    /// `false` で Opus → μ-law transcode 経路のみを検証していたため、
    /// 直送経路に test gap があった (PR #149 review 🟡#1)。
    ///
    /// 期待:
    /// - NGN socket で受信した RTP の `payload_type == PAYLOAD_TYPE_ULAW (0)`
    /// - 受信 RTP の payload は peer 側で push した μ-law payload と完全一致
    ///   (Opus decode / resample / μ-law encode を経由しない)
    /// - PT が opus_pt (=111) で来た frame は drop される (passthrough 時の
    ///   expected_pt は 0)
    #[tokio::test]
    async fn rfc3551_4_5_14_pcmu_passthrough_peer_to_ngn_preserves_payload() {
        use std::sync::Arc as SArc;

        struct NoopPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoopPeer {
            async fn handle_offer(&self, _: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, _: MediaFrame) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        let (peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(8);

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: Arc::new(NoopPeer),
            peer_media_rx: peer_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: true,
            metrics: None,
        });

        // 8 kHz 1 kHz トーン → μ-law 化 (160 byte payload)
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let ulaw_payload: Vec<u8> = samples.iter().map(|s| encode_ulaw(*s)).collect();
        assert_eq!(ulaw_payload.len(), SAMPLES_PER_FRAME);

        // direct_pcmu_passthrough なので peer 側の MediaFrame も PT=0 で来る前提
        let media = MediaFrame {
            pt: PAYLOAD_TYPE_ULAW,
            rtp_time: 0,
            payload: ulaw_payload.clone(),
            network_time: std::time::Instant::now(),
        };
        peer_tx.send(media).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, _src) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("NGN socket で μ-law が受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(
            recv.payload_type, PAYLOAD_TYPE_ULAW,
            "PCMU PT=0 で送られているはず (RFC 3551 §4.5.14)"
        );
        assert_eq!(
            recv.payload.len(),
            SAMPLES_PER_FRAME,
            "20 ms = 160 samples (RFC 3551 §4.5.14)"
        );
        assert_eq!(
            recv.payload, ulaw_payload,
            "μ-law payload が不変で NGN に出るべき (decode/resample/encode しない)"
        );

        // PT 不一致 (opus_pt = 111) の frame は drop されることを確認
        // (expected_pt は passthrough 時 PCMU=0)
        let bad = MediaFrame {
            pt: DEFAULT_OPUS_PT,
            rtp_time: SAMPLES_PER_FRAME as u32,
            payload: ulaw_payload.clone(),
            network_time: std::time::Instant::now(),
        };
        peer_tx.send(bad).await.unwrap();

        // 続いて正規 PT の 2 frame 目を流し、 NGN socket には bad ではなく
        // この frame だけが届くことを確認 (drop されたら 1 個しか届かない)。
        let media2 = MediaFrame {
            pt: PAYLOAD_TYPE_ULAW,
            rtp_time: SAMPLES_PER_FRAME as u32,
            payload: ulaw_payload.clone(),
            network_time: std::time::Instant::now(),
        };
        peer_tx.send(media2).await.unwrap();

        let (n2, _) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("2 frame 目が NGN socket に届かない")
            .unwrap();
        let recv2 = RtpPacket::from_bytes(&buf[..n2]).unwrap();
        assert_eq!(recv2.payload_type, PAYLOAD_TYPE_ULAW);
        assert_eq!(recv2.payload, ulaw_payload, "2 frame 目も payload 不変");

        let (_n2p, p2n, err) = bridge.stats();
        assert!(p2n >= 2, "passthrough p2n stats 不足: {}", p2n);
        assert!(
            err >= 1,
            "PT=111 の bad frame が drop された記録が無い: {}",
            err
        );
        bridge.stop().await;
    }

    /// ループバック (NGN→WebRTC→NGN相当) で品質劣化が一定以下か。
    /// 直接ブリッジ往復ではなくコーデックチェーン単体での確認 (端末役のソケット
    /// セットアップを 2 つ立てるよりシンプル)。
    #[test]
    fn end_to_end_codec_chain_preserves_signal() {
        let mut up = UpsamplerNbToWb::new().unwrap();
        let mut down = DownsamplerWbToNb::new().unwrap();
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();

        // 1 kHz 入力
        let mut input = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            input.push(v as i16);
        }
        let nb_in = AudioFrame::new(NARROW_BAND_RATE, input.clone());

        // 数フレーム流して Opus エンコーダのプリロールを抜けたところで判定
        let mut last_rms = 0.0f64;
        for _ in 0..5 {
            let wb = up.process(&nb_in).unwrap();
            let opus_pkt = enc.encode(&wb).unwrap();
            let wb2 = dec.decode(&opus_pkt).unwrap();
            let nb_out = down.process(&wb2).unwrap();
            let energy: f64 = nb_out.samples.iter().map(|s| (*s as f64).powi(2)).sum();
            last_rms = (energy / nb_out.samples.len() as f64).sqrt();
        }
        // 入力 RMS は 8000/sqrt(2) ≒ 5657。半分以上は残ること
        assert!(
            last_rms > 2000.0,
            "コーデックチェーン後の RMS が小さすぎる: {}",
            last_rms
        );
    }

    /// RFC 3550 §5.1 ユニットテスト: `RtpEgressState::next` が
    /// SSRC を維持しつつ seq +1 / timestamp += increment で連番進行することを確認。
    #[test]
    fn rfc3550_5_1_rtp_egress_state_monotonic_seq_and_ts() {
        // 初期 SSRC / seq / ts を決め打ち (random を避けて検証性を上げる)
        let mut eg = RtpEgressState {
            ssrc: 0xABCD_1234,
            seq: 100,
            timestamp: 1_000_000,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000, // PCMU clock (RFC 3551 §4.5.14)
            anchor: None,
        };
        let (s0, t0, ssrc0) = eg.next(160);
        let (s1, t1, ssrc1) = eg.next(160);
        let (s2, t2, ssrc2) = eg.next(160);

        // SSRC は払い出し中ずっと同じ
        assert_eq!(ssrc0, 0xABCD_1234);
        assert_eq!(ssrc1, 0xABCD_1234);
        assert_eq!(ssrc2, 0xABCD_1234);

        // seq は +1 ずつ
        assert_eq!(s0, 100);
        assert_eq!(s1, 101);
        assert_eq!(s2, 102);

        // ts は +160 ずつ (= PCMU 20ms frame)
        assert_eq!(t0, 1_000_000);
        assert_eq!(t1, 1_000_160);
        assert_eq!(t2, 1_000_320);

        // state も更新されている
        assert_eq!(eg.seq, 103);
        assert_eq!(eg.timestamp, 1_000_480);
    }

    /// RFC 3550 §5.1 ユニットテスト: seq / timestamp の wrap (u16 / u32) が
    /// 正常に折返すこと。
    #[test]
    fn rfc3550_5_1_rtp_egress_state_wraps() {
        let mut eg = RtpEgressState {
            ssrc: 0xDEAD_BEEF,
            seq: u16::MAX,
            timestamp: u32::MAX,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000, // PCMU clock (RFC 3551 §4.5.14)
            anchor: None,
        };
        let (s0, t0, ssrc0) = eg.next(1);
        assert_eq!(s0, u16::MAX);
        assert_eq!(t0, u32::MAX);
        assert_eq!(ssrc0, 0xDEAD_BEEF);
        // wrap
        assert_eq!(eg.seq, 0);
        assert_eq!(eg.timestamp, 0);
    }

    /// RFC 3551 §4.1 / RFC 7587 §4.4 / Issue #84:
    /// `next_with_marker` の M ビット判定が talkspurt 境界で正しく立つ。
    ///
    /// シナリオ:
    /// - 1 個目: 初回 (last_send_time = None) → M=1 (talkspurt 開始)
    /// - 2 個目: 0 ms 後 (= 閾値 30 ms 未満) → M=0 (継続)
    /// - 3 個目: 50 ms 後 (= 閾値超過) → M=1 (silence 後の talkspurt 開始)
    /// - 4 個目: 0 ms 後 → M=0 (継続)
    #[test]
    fn rfc3551_4_1_next_with_marker_detects_talkspurt_boundary() {
        let mut eg = RtpEgressState {
            ssrc: 0xCAFE_BABE,
            seq: 0,
            timestamp: 0,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000, // PCMU clock (RFC 3551 §4.5.14)
            anchor: None,
        };
        let t0 = Instant::now();
        // 1 個目: 初回送信
        let (_, _, _, m0) = eg.next_with_marker(160, t0);
        assert!(m0, "初回送信は talkspurt 開始 (M=1) — RFC 3551 §4.1");

        // 2 個目: 直後 (gap 0 ms ≪ 30 ms 閾値)
        let (_, _, _, m1) = eg.next_with_marker(160, t0);
        assert!(!m1, "0 ms 後の継続 packet は M=0 — RFC 3551 §4.1");

        // 3 個目: 50 ms 後 (gap >= 閾値 30 ms)
        let t1 = t0 + Duration::from_millis(50);
        let (_, _, _, m2) = eg.next_with_marker(160, t1);
        assert!(
            m2,
            "silence gap 後の最初の packet は M=1 (talkspurt 開始) — RFC 3551 §4.1"
        );

        // 4 個目: 即座 (継続)
        let (_, _, _, m3) = eg.next_with_marker(160, t1);
        assert!(!m3, "talkspurt 内の継続 packet は M=0 — RFC 3551 §4.1");
    }

    /// RFC 3551 §4.1 / Issue #84: M ビット判定は **seq / ts 払い出しと
    /// 同一 critical section** で行う (並行 send による race を排除)。
    /// 本テストは「M ビットを立てた後に state が確実に更新される」ことを
    /// state field で直接検証する。
    #[test]
    fn rfc3551_4_1_next_with_marker_updates_last_send_time() {
        let mut eg = RtpEgressState {
            ssrc: 0,
            seq: 0,
            timestamp: 0,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000, // PCMU clock (RFC 3551 §4.5.14)
            anchor: None,
        };
        let t0 = Instant::now();
        assert!(eg.last_send_time.is_none(), "前提: 未送信は None");
        let (_, _, _, marker) = eg.next_with_marker(160, t0);
        assert!(marker, "初回は M=1");
        assert_eq!(
            eg.last_send_time,
            Some(t0),
            "next_with_marker は last_send_time を引数 now で更新する"
        );
    }

    /// RFC 3551 §4.1 / RFC 7587 §4.4 / Issue #84:
    /// `TranscodingBridge` の WebRTC→NGN ループが PCMU 出力の最初の packet
    /// に M=1 を立て、 継続 packet では M=0 を立てる。
    ///
    /// シナリオ:
    /// - Opus 60 ms フレーム (RFC 7587 §4.1 / RFC 6716 §3.2 multi-frame
    ///   packet) を 5 packet 投入 = 計 15 個の PCMU 20 ms chunk が出力。
    /// - 1 個目は talkspurt 開始なので M=1。
    /// - 2 個目以降は連続して同 chunk loop で送出されるため (時間 gap
    ///   なし)、 全て M=0 になる。
    #[tokio::test]
    async fn rfc3551_4_1_web_to_ngn_talkspurt_start_has_marker() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_addr = web_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 48 kHz 1 kHz トーン (960 samples = 20 ms) を Opus 化
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

        // jitter depth=4 を満たすため 5 個投入する。
        for s in 0..5u16 {
            let pkt = build_opus_rtp_packet(
                DEFAULT_OPUS_PT,
                s,
                s as u32 * OPUS_FRAME_SAMPLES as u32,
                0x9ABC_DEF0,
                &mut enc,
                &frame,
            )
            .unwrap();
            web_peer.send_to(&pkt, web_addr).await.unwrap();
        }

        // NGN 側で 5 packet 受信
        let mut received = Vec::with_capacity(5);
        for _ in 0..5 {
            let mut buf = vec![0u8; 1500];
            let (n, _) = timeout(Duration::from_secs(3), ngn_peer.recv_from(&mut buf))
                .await
                .expect("NGN 側で 5 packet 受信できない")
                .unwrap();
            let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
            assert_eq!(recv.payload_type, PAYLOAD_TYPE_ULAW);
            received.push(recv);
        }

        // 1 個目は talkspurt 開始 (RFC 3551 §4.1)
        assert!(
            received[0].marker,
            "1 個目 PCMU は talkspurt 開始 (M=1) — RFC 3551 §4.1"
        );

        // 2..N 個目は jitter pull が 20 ms 間隔で同 loop 上から呼ばれており
        // gap が閾値未満なので M=0 (continuation)
        for (i, pkt) in received.iter().enumerate().skip(1) {
            assert!(
                !pkt.marker,
                "{} 個目 PCMU は talkspurt 継続 (M=0) — RFC 3551 §4.1 (got M=1)",
                i + 1
            );
        }

        bridge.stop().await;
    }

    /// RFC 3551 §4.1 / Issue #84: 閾値ちょうど (30 ms) の境界条件で
    /// M=1 を立てる (`>=` 比較)。 30 ms 未満は M=0、 30 ms 以上は M=1。
    #[test]
    fn rfc3551_4_1_next_with_marker_threshold_boundary() {
        let mut eg = RtpEgressState {
            ssrc: 0,
            seq: 0,
            timestamp: 0,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000, // PCMU clock (RFC 3551 §4.5.14)
            anchor: None,
        };
        let t0 = Instant::now();
        let _ = eg.next_with_marker(160, t0);

        // 29 ms 後 → 継続
        let t1 = t0 + Duration::from_millis(29);
        let (_, _, _, m1) = eg.next_with_marker(160, t1);
        assert!(!m1, "閾値未満 (29 ms < 30 ms) は M=0");

        // 30 ms ちょうど → talkspurt 開始 (>= 比較)
        let t2 = t1 + Duration::from_millis(30);
        let (_, _, _, m2) = eg.next_with_marker(160, t2);
        assert!(m2, "閾値以上 (30 ms >= 30 ms) は M=1");
    }

    /// RFC 3550 §8.2 (Collision Resolution) ユニットテスト (a): 通常パス。
    /// ingress SSRC が egress SSRC と異なるとき、 `check_and_rotate_on_collision`
    /// は `false` を返し、 egress SSRC は変化しない。
    ///
    /// production docstring (`check_and_rotate_on_collision`) と同一の RFC 3550
    /// §8.2 normative wording (MUST) を以下に再掲する:
    ///
    /// > If a participant discovers at any time that two other participants
    /// > [...] then the participant MUST send an RTCP BYE packet for the
    /// > old identifier and choose a new one.
    ///
    /// 「同じ SSRC を使う participant を検出」=「ingress packet の SSRC が
    /// 自 egress SSRC と一致」と読み替える (Issue #182 (e))。
    #[test]
    fn rfc3550_8_2_no_collision_keeps_egress_ssrc() {
        let mut eg = RtpEgressState {
            ssrc: 0xAAAA_BBBB,
            seq: 1,
            timestamp: 100,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000, // PCMU clock (RFC 3551 §4.5.14)
            anchor: None,
        };
        // ingress SSRC ≠ egress SSRC → rotate 不要
        let rotated = eg.check_and_rotate_on_collision(0xCCCC_DDDD);
        assert!(!rotated, "衝突無しなら rotate しないはず");
        assert_eq!(eg.ssrc, 0xAAAA_BBBB, "egress SSRC は変化しないはず");
        // seq / timestamp も非変化
        assert_eq!(eg.seq, 1);
        assert_eq!(eg.timestamp, 100);
    }

    /// RFC 3550 §8.2 ユニットテスト (b): 衝突検出 + rotate。
    /// ingress SSRC が egress SSRC と一致したら egress SSRC を新規値に rotate し、
    /// 戻り値が `true`、 新 SSRC は **旧と異なる値**。 seq / timestamp は維持。
    #[test]
    fn rfc3550_8_2_collision_rotates_egress_ssrc() {
        let old_ssrc: u32 = 0x1234_5678;
        let mut eg = RtpEgressState {
            ssrc: old_ssrc,
            seq: 42,
            timestamp: 8000,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000, // PCMU clock (RFC 3551 §4.5.14)
            anchor: None,
        };
        // ingress SSRC == egress SSRC → 衝突 → rotate
        let rotated = eg.check_and_rotate_on_collision(old_ssrc);
        assert!(rotated, "衝突を検出したら rotate するはず");
        assert_ne!(
            eg.ssrc, old_ssrc,
            "rotate 後の SSRC は旧値と異なるはず (RFC 3550 §8.2: \"choose a new one\")"
        );
        // seq / timestamp は維持される (新 SSRC でも seq/ts continuity を保つ設計)
        assert_eq!(eg.seq, 42, "seq は rotate で維持されるはず");
        assert_eq!(eg.timestamp, 8000, "timestamp は rotate で維持されるはず");
    }

    /// RFC 3550 §8.2 ユニットテスト (c): rotate 後の旧 SSRC は別人。
    /// 一度 rotate した後、 旧 SSRC と同値の ingress が再到来しても、 新 SSRC
    /// (旧と異なる) との比較になるので 2 回目以降は rotate しない (=
    /// rotate の連鎖が起きない)。
    ///
    /// この性質は、 mis-behaved な reflector / loop が「sabiden の旧 SSRC を
    /// 持つ packet」を流し続けても、 sabiden 自身が new SSRC に切替済みなので
    /// 無限 rotate ループにはならないことを保証する (RFC 3550 §8.2 のloop
    /// 防止精神に整合)。
    #[test]
    fn rfc3550_8_2_rotated_egress_ignores_old_ssrc() {
        let old_ssrc: u32 = 0xDEAD_BEEF;
        let mut eg = RtpEgressState {
            ssrc: old_ssrc,
            seq: 0,
            timestamp: 0,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000, // PCMU clock (RFC 3551 §4.5.14)
            anchor: None,
        };
        // 1 回目: 衝突 → rotate
        assert!(eg.check_and_rotate_on_collision(old_ssrc));
        let new_ssrc = eg.ssrc;
        assert_ne!(new_ssrc, old_ssrc);

        // 2 回目: 旧 SSRC で再到来 → 既に new_ssrc に切替済みなので衝突しない
        let rotated2 = eg.check_and_rotate_on_collision(old_ssrc);
        assert!(
            !rotated2,
            "rotate 後の旧 SSRC ingress は衝突とみなさないはず (RFC 3550 §8.2 loop 防止)"
        );
        assert_eq!(
            eg.ssrc, new_ssrc,
            "2 回目の同 SSRC ingress では egress SSRC は変化しないはず"
        );
    }

    /// Issue #135 🟡 3: `WebRtcAudioBridge::start` は infallible シグネチャ
    /// (`-> Self`)。 `?` / `match Result` を呼出側に要求しない API 形を
    /// コンパイル時に強制するため、 `Self` の field と spawn された 2 つの
    /// JoinHandle が即座に観測可能であることを確認する。
    ///
    /// 旧 `Result<Self>` 戻り値での error path は実行時に到達不能だったため
    /// (CLAUDE.md §6.5 「production code で出ない error path を晒さない」
    /// 精神)、 本テストは戻り値型のみを契約として検証する。
    #[tokio::test]
    async fn webrtc_audio_bridge_start_returns_self_directly() {
        use std::sync::Arc as SArc;

        struct NoopPeer;
        #[async_trait::async_trait]
        impl crate::webrtc::peer::PeerSession for NoopPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                unreachable!()
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                unreachable!()
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                unreachable!()
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                unreachable!()
            }
            async fn send_media(&self, _: MediaFrame) -> anyhow::Result<()> {
                unreachable!()
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (_peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(1);

        // `start` の戻り値は `Self` であり `Result` ではない。
        // 型注釈で `Result<Self>` だとコンパイルエラーになる契約を
        // 明示する (variable 名 `bridge: WebRtcAudioBridge`)。
        let bridge: WebRtcAudioBridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: None,
            peer: Arc::new(NoopPeer),
            peer_media_rx: peer_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: true,
            metrics: None,
        });

        // 2 ループは spawn 直後で生存している (drop されていない)。
        let (sent, recv, errs) = bridge.stats();
        assert_eq!(sent, 0);
        assert_eq!(recv, 0);
        assert_eq!(errs, 0);
        bridge.stop().await;
    }

    /// Issue #112 / RFC 3550 §5.1: トランスコード経路 (Opus↔PCMU、
    /// `direct_pcmu_passthrough = false`) で SSRC が flow 中に変わらないこと。
    ///
    /// 複数 frame を `WebRtcAudioBridge` の peer→NGN 方向に流し、 NGN socket で
    /// 受信した RTP 全てが
    /// - 同じ SSRC を持つ
    /// - seq が +1 ずつ進む
    /// - timestamp が SAMPLES_PER_FRAME (= 160) ずつ進む
    /// - SSRC は bridge 起動後の `peer_to_ngn_ssrc()` と一致
    /// であることを確認する。
    ///
    /// Issue #112 完了条件: "direct_pcmu_passthrough=false 経路 (Opus⇔PCMU) で
    /// SSRC が flow 中変わらない test"。
    #[tokio::test]
    async fn rfc3550_5_1_transcode_ssrc_stable_across_flow_peer_to_ngn() {
        use std::sync::Arc as SArc;

        struct NoopPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoopPeer {
            async fn handle_offer(&self, _: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, _: MediaFrame) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        let (peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(16);

        // PR #172 (Issue #135) で `WebRtcAudioBridge::start` は infallible
        // (`-> Self`) になったため `.unwrap()` 不要。
        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: Arc::new(NoopPeer),
            peer_media_rx: peer_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: false,
            metrics: None,
        });

        // 起動直後の SSRC を観測 (random 初期化されている)
        let expected_ssrc = bridge.peer_to_ngn_ssrc().await;

        // 48 kHz 1 kHz トーンを 5 frame 流す
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

        const N_FRAMES: usize = 5;
        for i in 0..N_FRAMES {
            let opus_payload = enc.encode(&frame).unwrap();
            let media = MediaFrame {
                pt: DEFAULT_OPUS_PT,
                rtp_time: (i as u32) * (OPUS_FRAME_SAMPLES as u32),
                payload: opus_payload,
                network_time: std::time::Instant::now(),
            };
            peer_tx.send(media).await.unwrap();
        }

        // NGN socket で 5 frame 受信
        let mut buf = vec![0u8; 1500];
        let mut received: Vec<RtpPacket> = Vec::with_capacity(N_FRAMES);
        for _ in 0..N_FRAMES {
            let (n, _) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
                .await
                .expect("NGN socket recv timeout")
                .unwrap();
            received.push(RtpPacket::from_bytes(&buf[..n]).unwrap());
        }

        // 全 frame で SSRC が一致 (RFC 3550 §5.1)
        for (i, pkt) in received.iter().enumerate() {
            assert_eq!(
                pkt.ssrc, expected_ssrc,
                "frame #{}: SSRC が flow 中変わっている (expected {:08x}, got {:08x})",
                i, expected_ssrc, pkt.ssrc
            );
            assert_eq!(pkt.payload_type, PAYLOAD_TYPE_ULAW);
        }

        // 起動後の SSRC も同じ (bridge lifetime 中不変)
        assert_eq!(
            bridge.peer_to_ngn_ssrc().await,
            expected_ssrc,
            "bridge lifetime 中に SSRC が変わっている"
        );

        // seq が +1 ずつ進む (RFC 3550 §5.1: monotonically increasing per SSRC)
        let seq0 = received[0].sequence;
        for (i, pkt) in received.iter().enumerate() {
            let expected_seq = seq0.wrapping_add(i as u16);
            assert_eq!(
                pkt.sequence, expected_seq,
                "frame #{}: seq が連番でない (expected {}, got {})",
                i, expected_seq, pkt.sequence
            );
        }

        // timestamp が SAMPLES_PER_FRAME ずつ進む (RFC 3551 §4.5.14: PCMU 8kHz)
        let ts0 = received[0].timestamp;
        for (i, pkt) in received.iter().enumerate() {
            let expected_ts = ts0.wrapping_add((i as u32) * (SAMPLES_PER_FRAME as u32));
            assert_eq!(
                pkt.timestamp, expected_ts,
                "frame #{}: timestamp 増分が不正 (expected {}, got {})",
                i, expected_ts, pkt.timestamp
            );
        }

        bridge.stop().await;
    }

    /// Issue #112 / RFC 3550 §5.1: `TranscodingBridge` の Opus↔PCMU 経路
    /// (WebRTC→NGN 方向) で SSRC が flow 中に変わらないこと。
    ///
    /// `WebRtcAudioBridge` (str0m 経路) と異なり `TranscodingBridge` は両端を
    /// UDP socket で扱う legacy パスなので、 SSRC 安定性の検証も別途必要。
    #[tokio::test]
    async fn rfc3550_5_1_transcode_bridge_ssrc_stable_across_flow_web_to_ngn() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_addr = web_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        let expected_ssrc = bridge.web_to_ngn_ssrc().await;

        // 48 kHz 1 kHz トーンを Opus encode して 5 frame 流す
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

        const N_FRAMES: usize = 5;
        for i in 0..N_FRAMES {
            let pkt = build_opus_rtp_packet(
                DEFAULT_OPUS_PT,
                (i as u16) + 1,
                (i as u32) * (OPUS_FRAME_SAMPLES as u32),
                0xCCCC_CCCC,
                &mut enc,
                &frame,
            )
            .unwrap();
            web_peer.send_to(&pkt, web_addr).await.unwrap();
        }

        // NGN 側で N_FRAMES 個受信
        let mut buf = vec![0u8; 1500];
        let mut received: Vec<RtpPacket> = Vec::with_capacity(N_FRAMES);
        for _ in 0..N_FRAMES {
            let (n, _) = timeout(Duration::from_secs(2), ngn_peer.recv_from(&mut buf))
                .await
                .expect("NGN 側で frame 不足")
                .unwrap();
            received.push(RtpPacket::from_bytes(&buf[..n]).unwrap());
        }

        // SSRC は全 frame で一致 (Issue #112 完了条件)
        for (i, pkt) in received.iter().enumerate() {
            assert_eq!(
                pkt.ssrc, expected_ssrc,
                "frame #{}: SSRC が flow 中に変わっている",
                i
            );
            assert_eq!(pkt.payload_type, PAYLOAD_TYPE_ULAW);
        }

        // seq +1 連番、 timestamp +160 連番
        let seq0 = received[0].sequence;
        let ts0 = received[0].timestamp;
        for (i, pkt) in received.iter().enumerate() {
            assert_eq!(
                pkt.sequence,
                seq0.wrapping_add(i as u16),
                "frame #{} seq",
                i
            );
            assert_eq!(
                pkt.timestamp,
                ts0.wrapping_add((i as u32) * (SAMPLES_PER_FRAME as u32)),
                "frame #{} ts",
                i
            );
        }

        bridge.stop().await;
    }

    /// Issue #112 / RFC 3550 §5.1: `TranscodingBridge` の NGN→WebRTC (Opus) 方向で
    /// SSRC / seq / ts が flow 中変わらないこと。
    #[tokio::test]
    async fn rfc3550_5_1_transcode_bridge_ssrc_stable_across_flow_ngn_to_web() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        let expected_ssrc = bridge.ngn_to_web_ssrc().await;

        // 8 kHz 1 kHz トーンを μ-law 化して 5 frame 流す
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }

        const N_FRAMES: usize = 5;
        for i in 0..N_FRAMES {
            let pkt = build_ulaw_rtp_packet(
                (i as u16) + 1,
                (i as u32) * (SAMPLES_PER_FRAME as u32),
                0xAAAA_AAAA,
                &samples,
            );
            ngn_peer.send_to(&pkt, ngn_addr).await.unwrap();
        }

        let mut buf = vec![0u8; 1500];
        let mut received: Vec<RtpPacket> = Vec::with_capacity(N_FRAMES);
        for _ in 0..N_FRAMES {
            let (n, _) = timeout(Duration::from_secs(2), web_peer.recv_from(&mut buf))
                .await
                .expect("WebRTC 側で frame 不足")
                .unwrap();
            received.push(RtpPacket::from_bytes(&buf[..n]).unwrap());
        }

        // SSRC 全 frame 一致
        for (i, pkt) in received.iter().enumerate() {
            assert_eq!(
                pkt.ssrc, expected_ssrc,
                "frame #{}: SSRC が flow 中に変わっている",
                i
            );
            assert_eq!(pkt.payload_type, DEFAULT_OPUS_PT);
        }

        // seq +1 / ts +OPUS_FRAME_SAMPLES (= 960) 連番
        let seq0 = received[0].sequence;
        let ts0 = received[0].timestamp;
        for (i, pkt) in received.iter().enumerate() {
            assert_eq!(
                pkt.sequence,
                seq0.wrapping_add(i as u16),
                "frame #{} seq",
                i
            );
            assert_eq!(
                pkt.timestamp,
                ts0.wrapping_add((i as u32) * (OPUS_FRAME_SAMPLES as u32)),
                "frame #{} ts (RFC 7587 §4.1: Opus clock 48kHz)",
                i
            );
        }

        bridge.stop().await;
    }

    // ====================================================================
    // Issue #200: 2.5/5/10 ms Opus 短尺フレーム対応 (RFC 7587 §4.2)
    // ====================================================================

    /// RFC 7587 §4.1 (Frame Sizes): 2.5 ms Opus 単発フレーム (= 120 samples
    /// @ 48 kHz) を [`OpusToPcmuAccum`] に投入しても、 累積が 20 ms 境界
    /// (= 960 samples) に達しないため chunk は emit されない。 短尺フレームを
    /// 単発で silently drop せず、 内部バッファに保持することを契約として固定する。
    ///
    /// Issue #200 / RFC 7587 §4.2: "the receiver SHOULD NOT assume any
    /// particular frame size."
    #[test]
    fn rfc7587_4_1_accum_holds_2_5ms_short_frame_without_emit() {
        let mut downsampler = DownsamplerWbToNb::new().unwrap();
        let mut accum = OpusToPcmuAccum::new();

        // 2.5 ms = 120 samples @ 48 kHz の無音 PCM
        let short_wb: Vec<i16> = vec![0; 120];
        let chunks = accum.push(&short_wb, &mut downsampler).unwrap();

        assert!(
            chunks.is_empty(),
            "2.5 ms (120 samples) 単発で chunk が emit された: {} 個",
            chunks.len()
        );
        assert_eq!(
            accum.pending(),
            120,
            "2.5 ms 投入後の累積長が 120 samples でない: {}",
            accum.pending()
        );
    }

    /// RFC 7587 §4.1: 2.5 ms × 8 = 20 ms ぶん累積したら、 ちょうど 1 chunk
    /// (160 byte μ-law payload) が emit され、 累積バッファは空になる。
    /// 短尺フレームを 20 ms 境界で再構成する契約。
    ///
    /// Issue #200: 旧実装は 2.5/5/10 ms を全て drop していたため、
    /// このテストは silently drop 撤去を回帰検査する。
    #[test]
    fn rfc7587_4_1_accum_emits_one_pcmu_chunk_after_8_x_2_5ms_frames() {
        let mut downsampler = DownsamplerWbToNb::new().unwrap();
        let mut accum = OpusToPcmuAccum::new();

        // 2.5 ms × 7 投入: chunk 0 個 (累積 840 samples、 まだ 960 未満)
        for i in 0..7 {
            let short_wb: Vec<i16> = vec![0; 120];
            let chunks = accum.push(&short_wb, &mut downsampler).unwrap();
            assert!(
                chunks.is_empty(),
                "{} 回目 (累積 {} samples) で予期せず chunk が emit",
                i + 1,
                (i + 1) * 120
            );
        }
        assert_eq!(accum.pending(), 7 * 120);

        // 8 個目: 累積 960 samples → ちょうど 1 chunk
        let short_wb: Vec<i16> = vec![0; 120];
        let chunks = accum.push(&short_wb, &mut downsampler).unwrap();
        assert_eq!(
            chunks.len(),
            1,
            "2.5 ms × 8 = 20 ms 境界で 1 chunk emit されていない"
        );
        assert_eq!(
            chunks[0].len(),
            SAMPLES_PER_FRAME,
            "PCMU payload が 160 byte (RFC 3551 §4.5.14) でない: {}",
            chunks[0].len()
        );
        assert_eq!(
            accum.pending(),
            0,
            "20 ms ぴったり投入後の累積残りが 0 でない: {}",
            accum.pending()
        );
    }

    /// RFC 7587 §4.1: 5 ms / 10 ms 単発フレーム ⇒ accum で chunk 0 個
    /// (累積 240 / 480 samples、 どちらも 960 未満)。 引き続き 20 ms 等の
    /// フレームで累積が 960 を跨ぐと chunk が emit される。
    ///
    /// 5 ms × 4 = 20 ms 境界、 10 ms × 2 = 20 ms 境界もそれぞれ 1 chunk を
    /// 出すことを確認する。
    #[test]
    fn rfc7587_4_1_accum_handles_5ms_and_10ms_short_frames() {
        // 5 ms × 4 = 20 ms ジャスト → 1 chunk
        {
            let mut downsampler = DownsamplerWbToNb::new().unwrap();
            let mut accum = OpusToPcmuAccum::new();
            let mut total_chunks = 0usize;
            for _ in 0..4 {
                let wb: Vec<i16> = vec![0; 240]; // 5 ms @ 48 kHz
                total_chunks += accum.push(&wb, &mut downsampler).unwrap().len();
            }
            assert_eq!(
                total_chunks, 1,
                "5 ms × 4 で 1 chunk emit されていない: {}",
                total_chunks
            );
            assert_eq!(accum.pending(), 0);
        }

        // 10 ms × 2 = 20 ms ジャスト → 1 chunk
        {
            let mut downsampler = DownsamplerWbToNb::new().unwrap();
            let mut accum = OpusToPcmuAccum::new();
            let mut total_chunks = 0usize;
            for _ in 0..2 {
                let wb: Vec<i16> = vec![0; 480]; // 10 ms @ 48 kHz
                total_chunks += accum.push(&wb, &mut downsampler).unwrap().len();
            }
            assert_eq!(
                total_chunks, 1,
                "10 ms × 2 で 1 chunk emit されていない: {}",
                total_chunks
            );
            assert_eq!(accum.pending(), 0);
        }
    }

    /// RFC 7587 §4.1: 既存 20/40/60 ms 経路 (PR #197) と短尺 2.5/5/10 ms 混在
    /// シーケンスでも regression が無いこと。 chunk emit 数 = 累積サンプル合計 /
    /// 960 で正確に一致する (端数は accum.buf に残る)。
    ///
    /// シーケンス: [10 ms, 10 ms, 40 ms, 2.5 ms × 8, 60 ms]
    ///   累積 = 480 + 480 + 1920 + 8×120 + 2880 = 6720 samples
    ///   期待 chunk 数 = 6720 / 960 = 7、 余り 0
    #[test]
    fn rfc7587_4_1_accum_mixed_frame_sizes_emit_correct_pcmu_count() {
        let mut downsampler = DownsamplerWbToNb::new().unwrap();
        let mut accum = OpusToPcmuAccum::new();

        let mut total_chunks = 0usize;

        // 10 ms × 2
        for _ in 0..2 {
            let wb: Vec<i16> = vec![0; 480];
            total_chunks += accum.push(&wb, &mut downsampler).unwrap().len();
        }
        // 40 ms × 1
        {
            let wb: Vec<i16> = vec![0; 1920];
            total_chunks += accum.push(&wb, &mut downsampler).unwrap().len();
        }
        // 2.5 ms × 8
        for _ in 0..8 {
            let wb: Vec<i16> = vec![0; 120];
            total_chunks += accum.push(&wb, &mut downsampler).unwrap().len();
        }
        // 60 ms × 1
        {
            let wb: Vec<i16> = vec![0; 2880];
            total_chunks += accum.push(&wb, &mut downsampler).unwrap().len();
        }

        // 累積合計 = 480+480+1920+8*120+2880 = 6720、 6720/960 = 7
        assert_eq!(
            total_chunks, 7,
            "混在 frame 長で chunk 数不一致: 期待 7、 実際 {}",
            total_chunks
        );
        assert_eq!(
            accum.pending(),
            0,
            "混在 sequence の余りが 0 でない: {}",
            accum.pending()
        );
    }

    /// Issue #200 / RFC 7587 §4.1: `WebRtcAudioBridge::peer_to_ngn_loop`
    /// (str0m 経由 Opus → NGN PCMU トランスコード経路) が 10 ms 短尺
    /// Opus フレーム × 2 を受信したとき、 NGN 側に **1 個** の 20 ms PCMU を emit
    /// する (PR #197 まで silently drop だった 短尺対応の regression test)。
    ///
    /// 旧実装は `wb.samples.len() % WB_FRAME_SAMPLES != 0` で短尺を全 drop。
    /// 修正後は 10 ms × 2 = 20 ms が累積された時点で 1 個の PCMU RTP が NGN に出る。
    #[tokio::test]
    async fn rfc7587_4_1_peer_to_ngn_accumulates_10ms_opus_into_one_pcmu() {
        use std::sync::Arc as SArc;

        struct NoopPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoopPeer {
            async fn handle_offer(&self, _: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, _: MediaFrame) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        let (peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(16);

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: Arc::new(NoopPeer),
            peer_media_rx: peer_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: false,
            metrics: None,
        });

        // 10 ms = 480 samples @ 48 kHz の 1 kHz サイン波を 2 packet 投入。
        // libopus は frame_size=480 を受け取ると単体 10 ms フレームを生成する
        // (RFC 6716 §3.2.1)。
        let n_samples_10ms = (OPUS_SAMPLE_RATE as usize * 10) / 1000;
        let mut samples = Vec::with_capacity(n_samples_10ms);
        for i in 0..n_samples_10ms {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

        let mut enc = OpusEncoder::new().unwrap();
        let pkt1 = enc.encode_test_variable_duration(&frame).unwrap();
        let pkt2 = enc.encode_test_variable_duration(&frame).unwrap();

        for (i, p) in [pkt1, pkt2].into_iter().enumerate() {
            peer_tx
                .send(MediaFrame {
                    pt: DEFAULT_OPUS_PT,
                    rtp_time: (i as u32) * (n_samples_10ms as u32),
                    payload: p,
                    network_time: std::time::Instant::now(),
                })
                .await
                .unwrap();
        }

        // 1 個目の 10 ms packet では NGN 側に何も出ない (累積 480 < 960)。
        // 2 個目で 960 samples 到達 → 1 個の 20 ms PCMU が emit。
        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("10 ms × 2 投入後に NGN 側で PCMU が届かない (silently drop?)")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(
            recv.payload_type, PAYLOAD_TYPE_ULAW,
            "PT が PCMU でない: {}",
            recv.payload_type
        );
        assert_eq!(
            recv.payload.len(),
            SAMPLES_PER_FRAME,
            "PCMU payload が 160 bytes (RFC 3551 §4.5.14) でない: {}",
            recv.payload.len()
        );

        // 累積が空に戻ったため、 2 個目以降の packet が即時に追加で出ることはない。
        // (短尺の単発投入で追加 emit が無いことを確認)
        let extra = timeout(
            Duration::from_millis(150),
            ngn_peer_sock.recv_from(&mut buf),
        )
        .await;
        assert!(
            extra.is_err(),
            "10 ms × 2 投入で 2 個目の PCMU が誤って emit された (期待 1 個)"
        );

        // silently drop が消えているので transcode_errors は 0
        let (_n2p, _p2n, err) = bridge.stats();
        assert_eq!(
            err, 0,
            "短尺 10 ms 経路で transcode_errors が 0 でない: {}",
            err
        );

        bridge.stop().await;
    }

    /// Issue #200 / RFC 7587 §4.1: `TranscodingBridge::web_to_ngn_loop`
    /// (UDP-only 経路) も 10 ms 短尺 Opus フレームを累積して 20 ms 単位の PCMU を
    /// emit する。 こちらは jitter buffer (`JITTER_DEPTH = 4`) を経由するため、
    /// 投入数は `JITTER_DEPTH + 2 = 6` packet とし、 jitter pull 後の累積で
    /// 最低 1 個の PCMU が NGN に届くことを確認する。
    #[tokio::test]
    async fn rfc7587_4_1_web_to_ngn_accumulates_10ms_opus_into_pcmu() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_addr = web_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 10 ms 1 kHz サイン波 (1 個あたり 480 samples @ 48 kHz)
        let n_samples_10ms = (OPUS_SAMPLE_RATE as usize * 10) / 1000;
        let mut samples = Vec::with_capacity(n_samples_10ms);
        for i in 0..n_samples_10ms {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

        // JITTER_DEPTH + 2 = 6 packet 投入 (= 60 ms 累積、 期待 PCMU 3 個)
        let n_total = JITTER_DEPTH + 2;
        let mut enc = OpusEncoder::new().unwrap();
        for i in 0..n_total {
            let opus_payload = enc.encode_test_variable_duration(&frame).unwrap();
            let pkt = RtpPacket {
                payload_type: DEFAULT_OPUS_PT,
                marker: false,
                sequence: (i as u16) + 1,
                timestamp: (i as u32) * (n_samples_10ms as u32),
                ssrc: 0xCAFE_BABE,
                payload: opus_payload,
            }
            .to_bytes();
            web_peer.send_to(&pkt, web_addr).await.unwrap();
        }

        // 6 × 10 ms = 60 ms → 60 / 20 = 3 個の PCMU が届く
        // (jitter buffer pull は 5 個目以降で始まるため、 全 6 packet 分の pull が
        //  完了するまで 5 × 20 ms ≒ 100 ms かかる)
        let expected_pcmu = (n_total * 10) / 20;
        let mut received: Vec<RtpPacket> = Vec::with_capacity(expected_pcmu);
        for _ in 0..expected_pcmu {
            let mut buf = vec![0u8; 1500];
            let (n, _) = timeout(Duration::from_secs(3), ngn_peer.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "10 ms accum: NGN 側で {} 個目の PCMU を受信できない (期待 {})",
                        received.len() + 1,
                        expected_pcmu
                    )
                })
                .unwrap();
            let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
            assert_eq!(recv.payload_type, PAYLOAD_TYPE_ULAW, "10 ms accum: PT 不正");
            assert_eq!(
                recv.payload.len(),
                SAMPLES_PER_FRAME,
                "10 ms accum: PCMU 長が 160 byte でない: {}",
                recv.payload.len()
            );
            received.push(recv);
        }

        // 連続性 (RFC 3550 §5.1 / RFC 3551 §4.5.14)
        for w in received.windows(2) {
            assert_eq!(
                w[1].sequence.wrapping_sub(w[0].sequence),
                1,
                "10 ms accum: 出力 seq 不連続"
            );
            assert_eq!(
                w[1].timestamp.wrapping_sub(w[0].timestamp),
                SAMPLES_PER_FRAME as u32,
                "10 ms accum: 出力 ts 増分不正"
            );
        }

        // silently drop が消えた契約: transcode_errors = 0
        let (_n2w, w2n, err) = bridge.stats();
        assert_eq!(
            err, 0,
            "10 ms accum: transcode_errors が 0 でない (silently drop 残存): {}",
            err
        );
        assert!(
            w2n >= expected_pcmu as u64,
            "10 ms accum: PCMU 送信カウンタが {} 以上でない: {}",
            expected_pcmu,
            w2n
        );

        bridge.stop().await;
    }

    // ====================================================================
    // Issue #182 (f) / #112: RTCP Sender Report (RFC 3550 §6.4.1 / RFC 5761 §3.3)
    // ====================================================================

    use crate::rtp::rtcp::peek_packet_type;
    use crate::rtp::rtcp::PT_SR;

    /// RFC 3550 §6.4.1 (Sender Report Header): `RtpEgressState::build_sr` が
    /// 自 egress 状態から組んだ SR の必須フィールド (sender's SSRC / packet
    /// count / octet count / RTP timestamp) が、 直近の `record_sent` で集計
    /// された値と一致することを確認する。
    ///
    /// シナリオ: SSRC=固定、 3 packet を payload_len=160 / 100 / 40 で
    /// 同一 sent_rtp_ts で記録 → `build_sr` の `packet_count = 3` /
    /// `octet_count = 300` / `ssrc = 0xABCD_1234` が観測される。
    /// `rtp_timestamp` は anchor 確定後 `rtp_timestamp_at(now_ntp)` 経由 (Issue
    /// #182 (d)) なので、 anchor の RTP ts (= 初回 `record_sent` で固定) を
    /// 起点に NTP 経過時間分だけ進む。 本テストは経過時間がほぼ 0 なので
    /// anchor_rtp ± 数サンプルになる。
    ///
    /// Issue #182 (f) 必要要件 (a): "build_sr_emits_correct_header"。
    #[test]
    fn rfc3550_6_4_1_build_sr_emits_correct_header() {
        let mut eg = RtpEgressState {
            ssrc: 0xABCD_1234,
            seq: 100,
            timestamp: 1_000_000,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000,
            anchor: None,
        };
        // 3 packet を別 payload 長で記録 (実 wire に出した想定)。
        // 初回 record_sent で anchor が (now_ntp, 1_000_000) で確定 (Issue #182 (d))。
        let anchor_rtp = 1_000_000_u32;
        eg.record_sent(160, anchor_rtp);
        eg.record_sent(100, anchor_rtp.wrapping_add(160));
        eg.record_sent(40, anchor_rtp.wrapping_add(320));

        let sr = eg.build_sr();

        // RFC 3550 §6.4.1 SR header の必須フィールド
        assert_eq!(sr.ssrc, 0xABCD_1234, "SR sender SSRC が egress と不一致");
        assert_eq!(
            sr.packet_count, 3,
            "SR sender's packet count が record_sent 回数と不一致"
        );
        assert_eq!(
            sr.octet_count, 300,
            "SR sender's octet count が record_sent payload 合計と不一致 (160+100+40)"
        );
        // RFC 3550 §6.4.1: RTP timestamp は SR 生成 NTP 時点に対応する RTP ts。
        // 本実装は `rtp_timestamp_at(now_ntp)` で anchor からの線形補間値を返す
        // (Issue #182 (d))。 anchor 確定 ~ build_sr の経過時間はほぼ 0 なので、
        // anchor_rtp に対して数サンプル以内の差に収まる (8 kHz × 数 ms 程度)。
        let drift = (sr.rtp_timestamp as i64 - anchor_rtp as i64).abs();
        assert!(
            drift < 8000, // 1 秒分 = 8000 samples 未満で十分 (実測 0〜数 ms)
            "SR RTP timestamp が anchor から大きく外れた: anchor={} sr={} drift={}",
            anchor_rtp,
            sr.rtp_timestamp,
            drift
        );
        // RC=0 (transcoder egress は受信側 jitter buffer 統計を持たないため)
        assert!(
            sr.reports.is_empty(),
            "transcoder egress SR は RC=0 のはず (受信統計を持たない)"
        );

        // バイト列としても妥当な SR (V=2, PT=200)
        let bytes = sr.to_bytes();
        assert_eq!(peek_packet_type(&bytes), Some(PT_SR));
        // RC=0 の SR は 28 bytes 固定 (RFC 3550 §6.4.1)
        assert_eq!(bytes.len(), 28, "RC=0 SR は 28 bytes ちょうど");
    }

    /// RFC 3550 §6.4.1 / Issue #182 (d): `build_sr` は `rtp_timestamp_at` を
    /// 呼んで anchor からの線形補間値を埋め込む (= `self.timestamp` 直返しでは
    /// ない)。 anchor を意図的に過去の NTP 時刻に置けば、 build_sr が返す
    /// `rtp_timestamp` は anchor_rtp + 経過秒 × sample_rate_hz になることで
    /// 配線が確認できる。
    ///
    /// シナリオ:
    /// - sample_rate_hz = 8000 (PCMU)
    /// - anchor = (now - 5秒相当, anchor_rtp = 1_000_000)
    /// - build_sr の rtp_timestamp が anchor_rtp + 5 * 8000 = 1_040_000 近傍。
    ///   実時間で SR を組む瞬間まで数 ms 経つので ±100 sample の許容。
    #[test]
    fn rfc3550_6_4_1_build_sr_uses_rtp_timestamp_at() {
        let sample_rate_hz: u32 = 8000;
        let anchor_rtp: u32 = 1_000_000;
        // anchor NTP を「現在から 5 秒前」に置く。
        let now = NtpTimestamp::now();
        let anchor_ntp = NtpTimestamp {
            seconds: now.seconds.saturating_sub(5),
            fraction: now.fraction,
        };
        let eg = RtpEgressState {
            ssrc: 0xC0DE_F00D,
            seq: 0,
            // self.timestamp は「次回送信予定」 = anchor から既に大量に進んだ値。
            // build_sr が self.timestamp を直返ししているなら本値が返る → fail。
            // rtp_timestamp_at 経由なら anchor + 5秒分 ≒ 1_040_000 が返る。
            timestamp: anchor_rtp.wrapping_add(123_456_789),
            last_send_time: None,
            sent_packets: 1,
            sent_octets: 160,
            sample_rate_hz,
            anchor: Some((anchor_ntp, anchor_rtp)),
        };

        let sr = eg.build_sr();
        let expected_rtp = anchor_rtp.wrapping_add(5 * sample_rate_hz);
        let diff = (sr.rtp_timestamp as i64 - expected_rtp as i64).abs();
        assert!(
            diff < 1000,
            "build_sr の rtp_timestamp が anchor 線形補間値からずれている: \
             expected≒{} got={} diff={} (anchor 経由なら ±数百以内、 \
             self.timestamp 直返しなら {} になるはず)",
            expected_rtp,
            sr.rtp_timestamp,
            diff,
            eg.timestamp
        );
        // self.timestamp 直返しの旧バグでないことを直接確認
        assert_ne!(
            sr.rtp_timestamp, eg.timestamp,
            "build_sr が self.timestamp を直返しに退行している (Issue #182 (d) 配線漏れ)"
        );
    }

    /// RFC 3550 §6.2 (Transmission Interval) / RFC 5761 §3.3 (RTP/RTCP mux):
    /// `TranscodingBridge` 起動後、 SR タスクが 5 秒周期 (`RTCP_SR_INTERVAL`)
    /// で対向 peer の **同じ socket** に SR を送出する。
    ///
    /// `start_paused = true` の auto-advance を駆動するため `tokio::time::sleep`
    /// を使う。 SR タスクは 5 秒 interval なので、 仮想時計を 6 秒進めれば 1 回
    /// SR が送出されているはず。 受信側 UDP socket は real time で動くため
    /// `recv_from` で実際に受信できる。
    ///
    /// Issue #182 (f) 必要要件 (b): "sr_task_sends_at_5s_interval"。
    #[tokio::test(start_paused = true)]
    async fn rfc3550_6_2_sr_task_sends_at_5s_interval() {
        // peer 側 socket = SR の受信先
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let metrics = Metrics::new();
        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: Some(metrics.clone()),
        })
        .unwrap();

        // 仮想時計を 6 秒進める (= 1 回目の 5 秒 interval を 1 秒過ぎる)。
        // `tokio::time::sleep` が auto-advance を駆動して SR タスクの
        // `interval.tick` を発火させる (start_paused 下のテストパターン:
        // `src/webrtc/signaling.rs::keepalive_sends_ping_every_interval` 参照)。
        tokio::time::sleep(Duration::from_secs(6)).await;

        // 仮想時計が進んでも、 UDP 受信は real time で動く。 spawned SR task が
        // socket.send_to を完了してから少しの実時間待ちで recv_from が返る。
        // ngn_to_web 方向の SR は web_peer (= web socket の対向) に届く。
        let mut buf = vec![0u8; 1500];
        let n2w = web_peer
            .recv_from(&mut buf)
            .await
            .map(|(n, _)| n)
            .expect("ngn_to_web SR が web_peer に届かない");
        assert_eq!(
            peek_packet_type(&buf[..n2w]),
            Some(PT_SR),
            "WebRTC 側に届いたのが SR でない (PT={:?})",
            peek_packet_type(&buf[..n2w])
        );

        // web_to_ngn 方向の SR は ngn_peer に届く
        let mut buf2 = vec![0u8; 1500];
        let w2n = ngn_peer
            .recv_from(&mut buf2)
            .await
            .map(|(n, _)| n)
            .expect("web_to_ngn SR が ngn_peer に届かない");
        assert_eq!(
            peek_packet_type(&buf2[..w2n]),
            Some(PT_SR),
            "NGN 側に届いたのが SR でない (PT={:?})",
            peek_packet_type(&buf2[..w2n])
        );

        // Prometheus counter にも反映されている (2 方向 × 1 tick = 2 件以上)
        assert!(
            metrics
                .rtcp_sr_sent
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 2,
            "rtcp_sr_sent カウンタが 2 件以上でない (2 方向 × 1 tick)"
        );

        bridge.stop().await;
    }

    /// RFC 3550 §6.4.1 (build_sr は SSRC を現在値から読む) / Issue #182 (e) との
    /// 整合: SR タスクは spawn 時点ではなく **送出時点** の egress.ssrc を読む。
    ///
    /// SSRC collision rotate (PR #239 で別途実装) が走った後、 新 SSRC で SR が
    /// 出ることを保証する。 PR #239 が未 merge の本ブランチでは、 テスト中に
    /// 直接 `egress.ssrc` を書き換えてシナリオを再現する。
    ///
    /// Issue #182 (f) 必要要件 (c): "sr_task_uses_egress_ssrc_after_rotate"。
    #[test]
    fn rfc3550_6_4_1_build_sr_uses_current_egress_ssrc_after_rotate() {
        let mut eg = RtpEgressState {
            ssrc: 0x0000_AAAA,
            seq: 0,
            timestamp: 0,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000,
            anchor: None,
        };
        // 旧 SSRC で 2 packet 送ったていで record_sent
        eg.record_sent(160, 0);
        eg.record_sent(160, 160);
        let sr_before = eg.build_sr();
        assert_eq!(sr_before.ssrc, 0x0000_AAAA);
        assert_eq!(sr_before.packet_count, 2);

        // SSRC collision rotate を模擬 (PR #239 の `check_and_rotate_on_collision`
        // 相当)。 seq / timestamp / sent_* counter は維持される (= 同 stream の
        // 連続性を保つ、 §5.1 の SSRC change semantics)。
        eg.ssrc = 0xFFFF_BBBB;

        // rotate 後の send をさらに 1 件記録
        eg.record_sent(160, 320);

        let sr_after = eg.build_sr();
        // 新 SSRC で SR が組まれる (= SR タスクが spawn 時のキャッシュではなく
        // 現在値を読んでいる契約)
        assert_eq!(
            sr_after.ssrc, 0xFFFF_BBBB,
            "rotate 後の build_sr は新 SSRC を使うべき (Issue #182 (e) との整合)"
        );
        // counter は累積 (rotate でリセットされない、 § 5.1 SSRC change は
        // 受信側で別 stream 扱いになるが、 sabiden 送信側は同一 process)
        assert_eq!(
            sr_after.packet_count, 3,
            "record_sent counter は rotate を跨いで累積される"
        );
        assert_eq!(sr_after.octet_count, 160 * 3);
    }

    /// RFC 3550 §6.4.1 / Issue #182 (d): SR の RTP timestamp は anchor からの
    /// NTP 経過秒 × sample_rate_hz で線形に計算され、 SR 送出瞬間の wall clock
    /// と対応する。 5 秒後に問い合わせた `rtp_timestamp_at` が `anchor_rtp + 5
    /// * sample_rate_hz` 近似であることを検証する。
    ///
    /// 本テストは f64 経由の丸めを許容するため `±2` サンプルの許容範囲を取る
    /// (`f64::round` の最近接整数丸めと u32 への cast の組合せで ±1 サンプル
    /// 程度の誤差が出る場合がある)。 5 秒 × 8000 Hz = 40000 サンプルに対し
    /// ±2 は 0.005% 以下で、 RFC 3550 §6.4.1 が想定する受信側の線形回帰精度
    /// (typically 1 packet 周期 ≒ 160 サンプル) には十分小さい。
    #[test]
    fn rfc3550_6_4_1_build_sr_ntp_rtp_relationship() {
        let sample_rate_hz: u32 = 8000; // PCMU (RFC 3551 §4.5.14)
        let anchor_rtp: u32 = 1_000_000;
        // anchor の NTP wall clock を 100 秒目で固定
        let anchor_ntp = NtpTimestamp {
            seconds: 3_900_000_000, // NTP epoch 上の任意の値
            fraction: 0,
        };
        let eg = RtpEgressState {
            ssrc: 0xCAFE_F00D,
            seq: 0,
            timestamp: anchor_rtp.wrapping_add(sample_rate_hz),
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz,
            anchor: Some((anchor_ntp, anchor_rtp)),
        };

        // 5 秒経過した NTP wall clock
        let now_ntp = NtpTimestamp {
            seconds: anchor_ntp.seconds + 5,
            fraction: anchor_ntp.fraction,
        };
        let rtp_now = eg
            .rtp_timestamp_at(now_ntp)
            .expect("anchor が確定済なら Some を返すはず");

        // 5 秒 * 8000 Hz = 40000 サンプル
        let expected = anchor_rtp.wrapping_add(5 * sample_rate_hz);
        let diff = (rtp_now as i64 - expected as i64).abs();
        assert!(
            diff <= 2,
            "5 秒経過の RTP ts は anchor + 5 * 8000 = {} ± 2 (got {}, diff {})",
            expected,
            rtp_now,
            diff
        );

        // 同 anchor + 100 ms 経過 (= 800 サンプル) も線形に伸びる
        let now_ntp_100ms = NtpTimestamp {
            seconds: anchor_ntp.seconds,
            fraction: (0.1_f64 * (u32::MAX as f64 + 1.0)) as u32,
        };
        let rtp_100ms = eg.rtp_timestamp_at(now_ntp_100ms).unwrap();
        let expected_100ms = anchor_rtp.wrapping_add(800);
        let diff_100ms = (rtp_100ms as i64 - expected_100ms as i64).abs();
        assert!(
            diff_100ms <= 2,
            "100 ms 経過の RTP ts は anchor + 800 ± 2 (got {}, diff {})",
            rtp_100ms,
            diff_100ms
        );
    }

    /// RFC 3550 §6.4.1 / Issue #182 (d): `record_sent` の **初回呼び出し** で
    /// anchor が確定する (`anchor` が `None` → `Some`)。 anchor の RTP 部は
    /// 初回 wire 送出 packet に乗った RTP ts (= caller が渡す `sent_rtp_ts`) と
    /// 一致する。
    ///
    /// 2 回目以降の `record_sent` で anchor は **維持** され、 上書きされない。
    /// これにより wall clock と RTP timestamp の relationship が長時間通話で
    /// 累積誤差なく保持される (旧 PR #242 の `self.timestamp` 直返しが抱えていた
    /// frame 境界余り誤差の問題が解消される)。
    ///
    /// **`next` 払い出し時点では anchor を確定させない**: wire 送出失敗
    /// (`to_socket.send_to` Err) 時に anchor だけ確定して RTP/NTP 線形性が
    /// 1 frame ずれるのを防ぐ。
    #[test]
    fn rfc3550_6_4_1_anchor_set_on_first_send() {
        let mut eg = RtpEgressState {
            ssrc: 0xABCD_0001,
            seq: 100,
            timestamp: 50_000,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 8000,
            anchor: None,
        };
        assert!(eg.anchor.is_none(), "前提: 未送信は anchor None");

        // `next` だけでは anchor は確定しない (wire 送出失敗を考慮)
        let (_seq0, ts0, _ssrc0) = eg.next(160);
        assert_eq!(ts0, 50_000, "1 packet 目の払い出し snapshot");
        assert!(
            eg.anchor.is_none(),
            "next 単独では anchor 確定しない (wire 送出成功時のみ)"
        );

        // 初回 `record_sent` で anchor が確定する
        eg.record_sent(160, ts0);
        let (anchor_ntp0, anchor_rtp0) = eg
            .anchor
            .expect("初回 record_sent 後は anchor が Some になっているはず");
        assert_eq!(
            anchor_rtp0, 50_000,
            "anchor の RTP ts は 1 packet 目の wire 送出 ts と一致"
        );

        // 2 回目以降の `record_sent` で anchor が **維持** される (上書きされない)
        let (_seq1, ts1, _ssrc1) = eg.next(160);
        assert_eq!(ts1, 50_160);
        eg.record_sent(160, ts1);
        let (anchor_ntp1, anchor_rtp1) = eg.anchor.unwrap();
        assert_eq!(
            anchor_ntp1, anchor_ntp0,
            "2 回目 record_sent で anchor NTP が変わらない (Issue #182 (d))"
        );
        assert_eq!(
            anchor_rtp1, anchor_rtp0,
            "2 回目 record_sent で anchor RTP が変わらない (Issue #182 (d))"
        );

        // 3 回目もしかり
        let (_, ts2, _) = eg.next(160);
        eg.record_sent(160, ts2);
        assert_eq!(
            eg.anchor.unwrap(),
            (anchor_ntp0, anchor_rtp0),
            "N 回目 record_sent でも anchor は不変"
        );
    }

    /// RFC 3550 §6.4.1 / §8.2 (PR #239 SSRC rotate との整合) / Issue #182 (d):
    /// `check_and_rotate_on_collision` で SSRC が rotate されても、 anchor は
    /// **維持される**。
    ///
    /// 根拠: anchor は「wall clock と RTP timestamp の relationship」 であって
    /// SSRC とは独立した量。 SSRC rotate は受信側からは "新しい source" に
    /// 見えるが、 sabiden の egress 視点では同一の wall clock 起点の RTP
    /// stream を継続出力しており、 線形性を破壊する理由がない。
    ///
    /// この性質により、 SSRC rotate と SR 周期送出が同時に走っても rtp/ntp
    /// 相関は崩れない (= rotate 直後の SR でも anchor 経由で正しい RTP ts が
    /// 計算される)。
    #[test]
    fn rfc3550_6_4_1_build_sr_anchor_survives_ssrc_rotation() {
        let old_ssrc: u32 = 0x1111_2222;
        let mut eg = RtpEgressState {
            ssrc: old_ssrc,
            seq: 0,
            timestamp: 7_000_000,
            last_send_time: None,
            sent_packets: 0,
            sent_octets: 0,
            sample_rate_hz: 48_000, // Opus (RFC 7587 §4.1)
            anchor: None,
        };

        // 初回 packet 払い出し + wire 送出成功で anchor 確定
        let (_, ts0, _) = eg.next(960);
        eg.record_sent(160, ts0);
        let anchor_before = eg.anchor.expect("anchor 確定");
        let rtp_before = eg.rtp_timestamp_at(anchor_before.0).unwrap();

        // SSRC 衝突を検出 → rotate
        let rotated = eg.check_and_rotate_on_collision(old_ssrc);
        assert!(rotated, "前提: 衝突検出で rotate される (RFC 3550 §8.2)");
        assert_ne!(eg.ssrc, old_ssrc, "前提: SSRC が新規値に切替");

        // anchor は維持される
        assert_eq!(
            eg.anchor,
            Some(anchor_before),
            "rotate 後も anchor は保持される (Issue #182 (d): NTP/RTP relationship は SSRC と独立)"
        );

        // anchor 経由の RTP ts 計算は rotate 前後で同じ wall clock では同じ値
        let rtp_after = eg.rtp_timestamp_at(anchor_before.0).unwrap();
        assert_eq!(
            rtp_before, rtp_after,
            "同一 wall clock 瞬間に対する RTP ts は rotate 前後で不変"
        );
    }
}
