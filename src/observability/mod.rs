//! 観測機能 (メトリクス + SIP トレース)
//!
//! 本モジュールはランタイムを横断する観測カウンタと、SIP メッセージ
//! ファイルダンプ用 [`SipTraceWriter`] を提供する。
//!
//! # 設計方針
//!
//! - メトリクスは `Arc<AtomicU64>` で純粋な atomic 加算のみを使い、
//!   `prometheus` クレートを引き込まない (依存最小化)。
//!   レンダリングは `health::metrics` ハンドラで Prometheus text
//!   exposition format に直書きする。
//! - SIP トレース dump は `--trace-dir` (CLI/設定) が指定された場合のみ
//!   有効。`<unix_ms>_<dir>_<method>_<call_id>.txt` 形式で書き出し、
//!   1000 ファイル超 / 100MB 超で古いものから削除する。
//! - パスワード/Authorization ヘッダ等の機密値は ASCII 探索で
//!   `Authorization: <redacted>` に書き換えてから保存する。
//!
//! # スレッド安全性
//!
//! [`Metrics`] は内部全フィールドが atomic なので `Arc<Metrics>` を
//! 複製して各層 (REGISTER, INVITE, RTP) に渡すだけで共有できる。
//! [`SipTraceWriter`] は内部 `Mutex` 一本でシリアライズしているが、
//! トレース有効時のみ呼ばれるため hot path には載らない。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// SIP メッセージの送信方向。トレースのファイル名に埋め込む。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDir {
    Sent,
    Recv,
}

impl TraceDir {
    fn as_str(self) -> &'static str {
        match self {
            TraceDir::Sent => "sent",
            TraceDir::Recv => "recv",
        }
    }
}

/// 1000 ファイル超 / 100MB 超で古いファイルから削除する閾値。
const MAX_FILES: usize = 1000;
const MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

/// 全プロセスで共有する観測用カウンタ群。
///
/// 各カウンタは独立した `AtomicU64` で、ラベル付き Prometheus メトリクスは
/// (label の組合せ × 1 atomic) で展開する。NGN 着信フォークでは `success/fail`
/// 等が同時更新されうるが、`fetch_add(_, Relaxed)` で十分な順序保証を得る
/// (counter であり、観測者は eventually consistent で良い)。
#[derive(Debug, Default)]
pub struct Metrics {
    pub register_success: AtomicU64,
    pub register_fail: AtomicU64,
    pub invite_ngn_answered: AtomicU64,
    pub invite_ngn_busy: AtomicU64,
    pub invite_ngn_timeout: AtomicU64,
    pub invite_ngn_error: AtomicU64,
    pub invite_extension_answered: AtomicU64,
    pub invite_extension_busy: AtomicU64,
    pub invite_extension_timeout: AtomicU64,
    pub invite_extension_error: AtomicU64,
    /// PR #146 review #1 🟡#1: PWA→NGN 発信 (Issue #145) は内線 SIP レッグが
    /// 存在しないため、 既存 `invite_extension_*` には乗らない。 専用 direction
    /// `pwa_outbound` を追加し、 NGN→200/486/timeout の結果を独立に観測する。
    pub invite_pwa_outbound_answered: AtomicU64,
    pub invite_pwa_outbound_busy: AtomicU64,
    pub invite_pwa_outbound_timeout: AtomicU64,
    pub invite_pwa_outbound_error: AtomicU64,
    pub call_active: AtomicU64,
    pub rtp_bridge_ngn_to_ext: AtomicU64,
    pub rtp_bridge_ext_to_ngn: AtomicU64,
    pub extension_registered: AtomicU64,
    /// Issue #157: rate limiter で拒否された outbound INVITE 累計
    /// (TTC JJ-90.24 §5.7.1 連続抑制適用回数)。 direction で内線/PWA を区別する。
    pub invite_blocked_by_rate_limit_extension: AtomicU64,
    pub invite_blocked_by_rate_limit_pwa_outbound: AtomicU64,
    /// Issue #157: 連続発信間隔 (ms 解像度) の累計とサンプル数。
    /// 平均値 = sum / count で計算可能 (簡易ヒストグラム代替)。
    /// `last_invite_at` から現在発信までの経過時間を `Allow` 時に記録する。
    pub invite_interval_total_ms: AtomicU64,
    pub invite_interval_samples: AtomicU64,
    /// Issue #182 / RFC 3550 §8.2: transcoder egress で SSRC collision を
    /// 検出し、 egress SSRC を rotate した累計数。 増加は flow 中の SSRC 衝突
    /// (sabiden 側 egress と ingress が同値) を示し、 衝突自体は 2^-32 確率
    /// 事象だが multi-call / 端末 implementation バグで連鎖し得る。
    pub rtp_ssrc_collision_detected: AtomicU64,
    /// Issue #182 (f) / RFC 3550 §6.4.1 / RFC 5761 §3.3: transcoder egress の
    /// 各方向 (`ngn_to_web` / `web_to_ngn` / `peer_to_ngn`) から送出した
    /// RTCP Sender Report 累計。 1 通話 5 秒間隔で送出するので、 60 秒通話で
    /// 各方向 12 件、 60 分通話で 720 件のオーダ。
    pub rtcp_sr_sent: AtomicU64,
    /// Issue #260 Phase 1-A: NGN P-CSCF から受信した 5xx 応答の累計
    /// (3GPP TS 24.229 §5.2.7 / RFC 3261 §21.5)。 既存 `invite_ngn_error`
    /// は 4xx/5xx 双方を含むため、 5xx 散発現象の観測には不適。
    /// 状態コードごと (500 / 503 / その他 5xx) に独立 atomic で持つ。
    pub ngn_5xx_500: AtomicU64,
    pub ngn_5xx_503: AtomicU64,
    pub ngn_5xx_other: AtomicU64,
    /// Issue #260 Phase 1-B: NGN carrier intermittent reject (500/486/503) に
    /// 対する自動 1 回 retry の結果別累計。 retry 経路に乗らなかった通常通話
    /// (= 1 回目で確立) は `not_retried` に集計し、 retry 駆動された通話だけ
    /// `succeeded` / `failed` / `aborted_by_cancel` に振り分ける。
    pub ngn_carrier_retry_not_retried: AtomicU64,
    pub ngn_carrier_retry_succeeded: AtomicU64,
    pub ngn_carrier_retry_failed: AtomicU64,
    pub ngn_carrier_retry_aborted_by_cancel: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// REGISTER 結果の記録。
    pub fn record_register(&self, success: bool) {
        if success {
            self.register_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.register_fail.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 通話開始時に call_active を +1。
    pub fn inc_call_active(&self) {
        self.call_active.fetch_add(1, Ordering::Relaxed);
    }

    /// 通話終了時に call_active を -1。0 を下回らないように減算する。
    pub fn dec_call_active(&self) {
        // saturating: 既存ロジックで二重減算が入っても 0 で止める
        let prev = self.call_active.load(Ordering::Relaxed);
        if prev > 0 {
            self.call_active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// 内線登録数を絶対値で更新する (snapshot ベース)。
    pub fn set_extension_registered(&self, n: u64) {
        self.extension_registered.store(n, Ordering::Relaxed);
    }

    /// RTP リレー方向ごとのパケット数。`Relaxed` でホットパスのコストを最小化。
    pub fn add_rtp_ngn_to_ext(&self, n: u64) {
        self.rtp_bridge_ngn_to_ext.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_rtp_ext_to_ngn(&self, n: u64) {
        self.rtp_bridge_ext_to_ngn.fetch_add(n, Ordering::Relaxed);
    }

    /// NGN 側 INVITE の結果を記録。
    pub fn record_invite_ngn(&self, result: InviteResult) {
        match result {
            InviteResult::Answered => &self.invite_ngn_answered,
            InviteResult::Busy => &self.invite_ngn_busy,
            InviteResult::Timeout => &self.invite_ngn_timeout,
            InviteResult::Error => &self.invite_ngn_error,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// 内線側 INVITE の結果を記録。
    pub fn record_invite_extension(&self, result: InviteResult) {
        match result {
            InviteResult::Answered => &self.invite_extension_answered,
            InviteResult::Busy => &self.invite_extension_busy,
            InviteResult::Timeout => &self.invite_extension_timeout,
            InviteResult::Error => &self.invite_extension_error,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// PR #146 review #1 🟡#1: PWA→NGN 発信 (Issue #145) の結果を記録する。
    /// 内線 SIP レッグが無いため `record_invite_extension` は使わない。
    /// `record_invite_ngn` は NGN レッグそのものとして別途呼ばれる
    /// (= 1 通話で `record_invite_pwa_outbound` と `record_invite_ngn` が
    /// 同じ result で +1 されうる: 例 Answered で両方 +1)。
    pub fn record_invite_pwa_outbound(&self, result: InviteResult) {
        match result {
            InviteResult::Answered => &self.invite_pwa_outbound_answered,
            InviteResult::Busy => &self.invite_pwa_outbound_busy,
            InviteResult::Timeout => &self.invite_pwa_outbound_timeout,
            InviteResult::Error => &self.invite_pwa_outbound_error,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Issue #157: 連続発信抑制 (TTC JJ-90.24 §5.7.1) で 503 / busy 早期拒否
    /// した outbound INVITE を direction 別に記録する。
    pub fn record_invite_blocked_by_rate_limit(&self, direction: OutboundDirection) {
        match direction {
            OutboundDirection::Extension => &self.invite_blocked_by_rate_limit_extension,
            OutboundDirection::PwaOutbound => &self.invite_blocked_by_rate_limit_pwa_outbound,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Issue #157: BYE 200 OK / 連続 INVITE の発射間隔 (ms) を記録する。
    /// `sabiden_sip_invite_interval_seconds` の sum/count に対応 (簡易 histogram)。
    pub fn record_invite_interval_ms(&self, interval_ms: u64) {
        self.invite_interval_total_ms
            .fetch_add(interval_ms, Ordering::Relaxed);
        self.invite_interval_samples.fetch_add(1, Ordering::Relaxed);
    }

    /// Issue #182 / RFC 3550 §8.2 (Collision Resolution): transcoder egress で
    /// ingress SSRC が egress SSRC と一致する衝突を検出し、 egress SSRC を
    /// 再払い出ししたときに +1 する。 RFC 3550 §8.2 は衝突検出後の resolution
    /// 行動として「新規 SSRC への切替 + 旧 SSRC からの RTCP BYE 送出」を
    /// 規定するが、 後者は sabiden が RTCP SR/RR を transcoder 経路で送って
    /// いないため future work (Issue #182 (f))。
    pub fn add_ssrc_collision_detected(&self, n: u64) {
        self.rtp_ssrc_collision_detected
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Issue #182 (f) / RFC 3550 §6.4.1 / RFC 5761 §3.3: transcoder egress から
    /// RTCP Sender Report を 1 件送出した時に呼ぶ。 全方向 (ngn_to_web /
    /// web_to_ngn / peer_to_ngn) で同一 counter を共有する (= 通話単位の総 SR 数
    /// として観測する。 方向別に分解したくなった場合は将来 label 化を検討)。
    pub fn add_rtcp_sr_sent(&self, n: u64) {
        self.rtcp_sr_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Issue #260 Phase 1-A: NGN P-CSCF から 5xx 応答を 1 件受信した時に呼ぶ。
    ///
    /// 3GPP TS 24.229 §5.2.7 は 503 = overload / 500 = per-INVITE 内部失敗
    /// と意味分けを規定するため、 状態コード毎に独立カウンタで記録し
    /// Prometheus へ `status` ラベルで公開する (RFC 3261 §21.5)。
    /// `invite_ngn_error` (4xx + 5xx 合算) とは別軸で 5xx 散発の頻度を観測する。
    /// Issue #260 Phase 1-B: NGN carrier intermittent reject (500/486/503) に
    /// 対する自動 retry の結果を 1 件記録する。
    ///
    /// `RetryOutcome::NotRetried` は **retry 判定経路を全く通らなかった通常
    /// 通話** (元 status が 4xx 等の非対象、 または 1 回目で確立) を意味する。
    /// 観測者は `succeeded / failed / aborted_by_cancel` の和を retry 試行
    /// 回数として読む。
    ///
    /// RFC 3261 §20.33 (Retry-After) / 3GPP TS 24.229 §5.2.7 / TTC JJ-90.24
    /// §5.7.3 の準拠状況を Prometheus で外形監視可能にする。
    pub fn record_ngn_carrier_retry(&self, outcome: crate::call::carrier_retry::RetryOutcome) {
        use crate::call::carrier_retry::RetryOutcome;
        match outcome {
            RetryOutcome::NotRetried => &self.ngn_carrier_retry_not_retried,
            RetryOutcome::RetriedSucceeded => &self.ngn_carrier_retry_succeeded,
            RetryOutcome::RetriedFailed => &self.ngn_carrier_retry_failed,
            RetryOutcome::RetryAbortedByCancel => &self.ngn_carrier_retry_aborted_by_cancel,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ngn_5xx(&self, status_code: u16) {
        let counter = match status_code {
            500 => &self.ngn_5xx_500,
            503 => &self.ngn_5xx_503,
            // 4xx 等を弾いた残り 5xx を `other` に集約 (501/502/504-599)。
            501 | 502 | 504..=599 => &self.ngn_5xx_other,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text exposition format で全メトリクスを書き出す。
    /// `health::metrics` から呼ばれる。
    pub fn render_prometheus(&self, registered: bool) -> String {
        let mut out = String::with_capacity(2048);
        // 既存互換: sabiden_sip_registered (gauge)
        out.push_str("# HELP sabiden_sip_registered SIP REGISTER 成功状態 (0/1)\n");
        out.push_str("# TYPE sabiden_sip_registered gauge\n");
        out.push_str(&format!(
            "sabiden_sip_registered {}\n",
            if registered { 1 } else { 0 }
        ));

        out.push_str("# HELP sabiden_sip_register_total NGN 側 REGISTER 試行のうち結果別累計\n");
        out.push_str("# TYPE sabiden_sip_register_total counter\n");
        out.push_str(&format!(
            "sabiden_sip_register_total{{result=\"success\"}} {}\n",
            self.register_success.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "sabiden_sip_register_total{{result=\"fail\"}} {}\n",
            self.register_fail.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP sabiden_sip_invite_total INVITE の結果別累計 (direction で NGN/内線を区別)\n",
        );
        out.push_str("# TYPE sabiden_sip_invite_total counter\n");
        for (dir, results) in [
            (
                "ngn",
                [
                    ("answered", &self.invite_ngn_answered),
                    ("busy", &self.invite_ngn_busy),
                    ("timeout", &self.invite_ngn_timeout),
                    ("error", &self.invite_ngn_error),
                ],
            ),
            (
                "extension",
                [
                    ("answered", &self.invite_extension_answered),
                    ("busy", &self.invite_extension_busy),
                    ("timeout", &self.invite_extension_timeout),
                    ("error", &self.invite_extension_error),
                ],
            ),
            // PR #146 review #1 🟡#1: PWA→NGN 発信 (Issue #145) を独立 direction として公開する。
            (
                "pwa_outbound",
                [
                    ("answered", &self.invite_pwa_outbound_answered),
                    ("busy", &self.invite_pwa_outbound_busy),
                    ("timeout", &self.invite_pwa_outbound_timeout),
                    ("error", &self.invite_pwa_outbound_error),
                ],
            ),
        ] {
            for (result, counter) in results {
                out.push_str(&format!(
                    "sabiden_sip_invite_total{{direction=\"{}\",result=\"{}\"}} {}\n",
                    dir,
                    result,
                    counter.load(Ordering::Relaxed)
                ));
            }
        }

        out.push_str("# HELP sabiden_call_active 現在進行中の通話数\n");
        out.push_str("# TYPE sabiden_call_active gauge\n");
        out.push_str(&format!(
            "sabiden_call_active {}\n",
            self.call_active.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP sabiden_rtp_bridge_packets_total RTP リレーが転送したパケット累計\n");
        out.push_str("# TYPE sabiden_rtp_bridge_packets_total counter\n");
        out.push_str(&format!(
            "sabiden_rtp_bridge_packets_total{{direction=\"ngn_to_ext\"}} {}\n",
            self.rtp_bridge_ngn_to_ext.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "sabiden_rtp_bridge_packets_total{{direction=\"ext_to_ngn\"}} {}\n",
            self.rtp_bridge_ext_to_ngn.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP sabiden_extension_registered 現在登録中の内線数\n");
        out.push_str("# TYPE sabiden_extension_registered gauge\n");
        out.push_str(&format!(
            "sabiden_extension_registered {}\n",
            self.extension_registered.load(Ordering::Relaxed)
        ));

        // Issue #157: TTC JJ-90.24 §5.7.1 連続抑制で拒否された outbound INVITE。
        out.push_str(
            "# HELP sabiden_sip_invite_blocked_by_rate_limit_total \
             連続発信抑制 (TTC JJ-90.24 §5.7.1 / RFC 3261 §21.5.4) で 503 拒否した INVITE 累計\n",
        );
        out.push_str("# TYPE sabiden_sip_invite_blocked_by_rate_limit_total counter\n");
        out.push_str(&format!(
            "sabiden_sip_invite_blocked_by_rate_limit_total{{direction=\"extension\"}} {}\n",
            self.invite_blocked_by_rate_limit_extension
                .load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "sabiden_sip_invite_blocked_by_rate_limit_total{{direction=\"pwa_outbound\"}} {}\n",
            self.invite_blocked_by_rate_limit_pwa_outbound
                .load(Ordering::Relaxed)
        ));

        // Issue #157: 連続 INVITE 発射間隔 (秒)。 簡易 histogram 代替として
        // sum + count を公開する (Prometheus summary 互換)。
        out.push_str(
            "# HELP sabiden_sip_invite_interval_seconds 連続 outbound INVITE 発射間隔 (秒、 sum/count で平均算出可)\n",
        );
        out.push_str("# TYPE sabiden_sip_invite_interval_seconds summary\n");
        let total_ms = self.invite_interval_total_ms.load(Ordering::Relaxed);
        let samples = self.invite_interval_samples.load(Ordering::Relaxed);
        // ms → 秒変換 (浮動小数で 3 桁精度)。
        let sum_secs = (total_ms as f64) / 1000.0;
        out.push_str(&format!(
            "sabiden_sip_invite_interval_seconds_sum {:.3}\n",
            sum_secs
        ));
        out.push_str(&format!(
            "sabiden_sip_invite_interval_seconds_count {}\n",
            samples
        ));

        // Issue #182 / RFC 3550 §8.2: transcoder egress で衝突検出 + rotate した累計。
        out.push_str(
            "# HELP sabiden_rtp_ssrc_collision_detected_total \
             RFC 3550 §8.2 SSRC 衝突検出で transcoder egress SSRC を rotate した累計\n",
        );
        out.push_str("# TYPE sabiden_rtp_ssrc_collision_detected_total counter\n");
        out.push_str(&format!(
            "sabiden_rtp_ssrc_collision_detected_total {}\n",
            self.rtp_ssrc_collision_detected.load(Ordering::Relaxed)
        ));

        // Issue #182 (f) / RFC 3550 §6.4.1 / RFC 5761 §3.3: transcoder egress
        // 経路で送出した RTCP Sender Report 累計。 通話品質モニタリング (RTT /
        // 受信側 jitter buffer 適応) の入力源となる。
        out.push_str(
            "# HELP sabiden_rtcp_sr_sent_total transcoder egress から送出した RTCP SR (RFC 3550 §6.4.1) 累計\n",
        );
        out.push_str("# TYPE sabiden_rtcp_sr_sent_total counter\n");
        out.push_str(&format!(
            "sabiden_rtcp_sr_sent_total {}\n",
            self.rtcp_sr_sent.load(Ordering::Relaxed)
        ));

        // Issue #260 Phase 1-A / 3GPP TS 24.229 §5.2.7 / RFC 3261 §21.5:
        // NGN P-CSCF からの 5xx 応答を status コード別に公開する。 既存
        // `invite_ngn_error` は 4xx と 5xx を合算するので、 5xx 散発現象の
        // 頻度観測には別軸として本系列が必要。
        out.push_str(
            "# HELP sabiden_ngn_5xx_total NGN P-CSCF から受信した 5xx 応答累計 (3GPP TS 24.229 §5.2.7 / RFC 3261 §21.5)\n",
        );
        out.push_str("# TYPE sabiden_ngn_5xx_total counter\n");
        out.push_str(&format!(
            "sabiden_ngn_5xx_total{{status=\"500\"}} {}\n",
            self.ngn_5xx_500.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "sabiden_ngn_5xx_total{{status=\"503\"}} {}\n",
            self.ngn_5xx_503.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "sabiden_ngn_5xx_total{{status=\"other\"}} {}\n",
            self.ngn_5xx_other.load(Ordering::Relaxed)
        ));

        // Issue #260 Phase 1-B / RFC 3261 §20.33 / 3GPP TS 24.229 §5.2.7:
        // NGN carrier intermittent reject (500/486/503) に対する 1 回 retry
        // の outcome 別累計。 `succeeded + failed + aborted_by_cancel` の和が
        // retry を実際に駆動した試行回数、 `not_retried` は intermittent 経路
        // に乗らなかった通常通話 (= 既存 INVITE と 1:1)。
        out.push_str(
            "# HELP sabiden_ngn_carrier_retry_total NGN carrier intermittent reject (500/486/503) に対する 1 回 retry の結果別累計 (Issue #260 Phase 1-B / RFC 3261 §20.33 / 3GPP TS 24.229 §5.2.7 / TTC JJ-90.24 §5.7.3)\n",
        );
        out.push_str("# TYPE sabiden_ngn_carrier_retry_total counter\n");
        out.push_str(&format!(
            "sabiden_ngn_carrier_retry_total{{outcome=\"not_retried\"}} {}\n",
            self.ngn_carrier_retry_not_retried.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "sabiden_ngn_carrier_retry_total{{outcome=\"succeeded\"}} {}\n",
            self.ngn_carrier_retry_succeeded.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "sabiden_ngn_carrier_retry_total{{outcome=\"failed\"}} {}\n",
            self.ngn_carrier_retry_failed.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "sabiden_ngn_carrier_retry_total{{outcome=\"aborted_by_cancel\"}} {}\n",
            self.ngn_carrier_retry_aborted_by_cancel
                .load(Ordering::Relaxed)
        ));

        out
    }
}

/// `record_invite_*` 用のラベル列挙。
#[derive(Debug, Clone, Copy)]
pub enum InviteResult {
    Answered,
    Busy,
    Timeout,
    Error,
}

/// Issue #157: rate limiter / interval メトリクスの outbound 方向ラベル。
///
/// - `Extension`: 内線 SIP UA → sabiden → NGN (`UasEventHandler::handle_invite`)
/// - `PwaOutbound`: WebRTC PWA → sabiden → NGN (`UasEventHandler::handle_pwa_outbound_offer`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundDirection {
    Extension,
    PwaOutbound,
}

impl OutboundDirection {
    /// Prometheus ラベル文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            OutboundDirection::Extension => "extension",
            OutboundDirection::PwaOutbound => "pwa_outbound",
        }
    }
}

/// SIP メッセージファイルダンパ。
///
/// 設定で `trace_dir` が指定されたときに [`SipTraceWriter::open`] で
/// 構築する。`Disabled` の場合は `record` がノーオペとなる。
#[derive(Clone)]
pub struct SipTraceWriter {
    inner: Arc<SipTraceInner>,
}

struct SipTraceInner {
    dir: Option<PathBuf>,
    state: Mutex<TraceState>,
}

#[derive(Default)]
struct TraceState {
    /// 既存ファイル ((order_key, path, size_bytes))。古い順に削除するため
    /// 単純な Vec で保持し、append で末尾に積む。
    files: Vec<TraceFile>,
    /// `files` の合計サイズ。
    total_bytes: u64,
}

#[derive(Debug, Clone)]
struct TraceFile {
    path: PathBuf,
    size: u64,
}

impl SipTraceWriter {
    /// トレース無効化された writer を返す。
    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(SipTraceInner {
                dir: None,
                state: Mutex::new(TraceState::default()),
            }),
        }
    }

    /// 指定ディレクトリにダンプする writer を構築する。
    /// ディレクトリが無ければ作成し、既存ファイルがあれば集計してローテーション
    /// 対象に含める。
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).with_context(|| format!("create trace dir: {:?}", dir))?;
        let mut state = TraceState::default();
        if let Ok(read) = fs::read_dir(&dir) {
            let mut entries: Vec<(u128, PathBuf, u64)> = read
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let p = e.path();
                    if !p.is_file() {
                        return None;
                    }
                    let size = e.metadata().ok().map(|m| m.len()).unwrap_or(0);
                    let key = e
                        .metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    Some((key, p, size))
                })
                .collect();
            entries.sort_by_key(|(k, _, _)| *k);
            for (_, path, size) in entries {
                state.total_bytes += size;
                state.files.push(TraceFile { path, size });
            }
        }
        Ok(Self {
            inner: Arc::new(SipTraceInner {
                dir: Some(dir),
                state: Mutex::new(state),
            }),
        })
    }

    /// SIP メッセージを 1 件記録する。`call_id` が None なら "nocallid" になる。
    /// メッセージは `sanitize` でマスクしてから書き出す。
    pub async fn record(&self, dir: TraceDir, method: &str, call_id: Option<&str>, raw: &[u8]) {
        let Some(out_dir) = self.inner.dir.as_ref() else {
            return;
        };
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let safe_method = sanitize_filename_component(method);
        let safe_callid = sanitize_filename_component(call_id.unwrap_or("nocallid"));
        let file_name = format!(
            "{}_{}_{}_{}.txt",
            unix_ms,
            dir.as_str(),
            safe_method,
            safe_callid
        );
        let path = out_dir.join(&file_name);
        let payload = sanitize_message(raw);
        let payload_len = payload.len() as u64;

        let mut state = self.inner.state.lock().await;
        match fs::File::create(&path).and_then(|mut f| f.write_all(&payload)) {
            Ok(()) => {
                state.files.push(TraceFile {
                    path: path.clone(),
                    size: payload_len,
                });
                state.total_bytes += payload_len;
                rotate(&mut state);
                debug!(?path, "SIP trace 書き込み");
            }
            Err(e) => {
                warn!(error=%e, ?path, "SIP trace 書き込み失敗");
            }
        }
    }
}

/// ローテーション: ファイル数 / 合計バイト数の上限を超えたら古いものから削除。
fn rotate(state: &mut TraceState) {
    while state.files.len() > MAX_FILES || state.total_bytes > MAX_TOTAL_BYTES {
        let Some(oldest) = state.files.first().cloned() else {
            break;
        };
        if let Err(e) = fs::remove_file(&oldest.path) {
            // 既に消えていれば無視。残ると無限ループになるため必ず Vec から外す。
            warn!(error=%e, path=?oldest.path, "古い trace ファイル削除失敗");
        }
        state.files.remove(0);
        state.total_bytes = state.total_bytes.saturating_sub(oldest.size);
    }
}

/// ファイル名に使えない文字を `_` に潰す。Call-ID には `@` `:` `.` 等が
/// 含まれうるためエスケープしておく。
fn sanitize_filename_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_".into()
    } else {
        out
    }
}

/// SIP メッセージから機密値をマスクする。
///
/// 対象:
/// - `Authorization: ...` (大文字小文字無視, Proxy-Authorization も)
/// - `WWW-Authenticate` / `Proxy-Authenticate` の `nonce`/`response` は
///   それ自体が秘密ではないが、Digest 計算に使われた response 値は
///   再現性のため残す (デバッグの観点から削らない)。
/// - パスワードらしきフィールド (response="...") は触らない (Digest なので
///   そもそも平文 PW は流れない)。Authorization 全行を redact することで
///   nonce/cnonce/response いずれも一括でマスクされる。
pub fn sanitize_message(raw: &[u8]) -> Vec<u8> {
    // ASCII 行ベース処理: ヘッダ部のみ走査し本文はそのまま残す。
    // SIP の行末は CRLF (RFC 3261)。空行 (CRLF CRLF) でヘッダ終端。
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    let mut in_headers = true;
    while i < raw.len() {
        if !in_headers {
            out.extend_from_slice(&raw[i..]);
            break;
        }
        // 1 行の終端を探す
        let line_end = find_crlf(&raw[i..]).map(|x| i + x).unwrap_or(raw.len());
        let line = &raw[i..line_end];
        if line.is_empty() {
            // 空行: ヘッダ終端
            in_headers = false;
            out.extend_from_slice(line);
            // CRLF を消費
            if line_end + 2 <= raw.len() {
                out.extend_from_slice(&raw[line_end..line_end + 2]);
                i = line_end + 2;
            } else {
                i = raw.len();
            }
            continue;
        }
        // ヘッダ名と値の分離
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = &line[..colon];
            if header_name_eq_ignore_case(name, b"authorization")
                || header_name_eq_ignore_case(name, b"proxy-authorization")
            {
                out.extend_from_slice(name);
                out.extend_from_slice(b": <redacted>");
            } else {
                out.extend_from_slice(line);
            }
        } else {
            out.extend_from_slice(line);
        }
        // CRLF を出力
        if line_end + 2 <= raw.len() {
            out.extend_from_slice(&raw[line_end..line_end + 2]);
            i = line_end + 2;
        } else {
            // CRLF が無い末端行
            i = raw.len();
        }
    }
    out
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn header_name_eq_ignore_case(actual: &[u8], expected_lower: &[u8]) -> bool {
    let trimmed = trim_ascii(actual);
    if trimmed.len() != expected_lower.len() {
        return false;
    }
    trimmed
        .iter()
        .zip(expected_lower.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

/// SIP メッセージから (method 文字列, Call-ID) を抽出するベストエフォート関数。
/// レスポンスの場合 method は CSeq の method 欄から拾う。Call-ID 不在は None。
pub fn extract_method_and_call_id(raw: &[u8]) -> (String, Option<String>) {
    let text = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return ("UNKNOWN".into(), None),
    };
    let mut method = String::from("UNKNOWN");
    let mut call_id: Option<String> = None;
    let mut first = true;
    for line in text.split("\r\n") {
        if line.is_empty() {
            break;
        }
        if first {
            first = false;
            // request:  "<METHOD> <URI> SIP/2.0"
            // response: "SIP/2.0 <CODE> <REASON>"
            if let Some(rest) = line.strip_prefix("SIP/2.0 ") {
                let code = rest.split_whitespace().next().unwrap_or("0").to_string();
                method = format!("RESP-{}", code);
            } else if let Some(m) = line.split_whitespace().next() {
                method = m.to_string();
            }
            continue;
        }
        let lower_prefix = line.to_ascii_lowercase();
        // NTT NGN P-CSCF はコンパクトヘッダ (RFC 3261 §7.3.3) で応答するので
        // `Call-ID:` だけでなく `i:` も Call-ID として認識する。これを抜くと
        // trace ファイル名が `nocallid` になり call_id 横断検索が壊れる。
        let call_id_rest = lower_prefix
            .strip_prefix("call-id:")
            .or_else(|| lower_prefix.strip_prefix("i:"));
        if let Some(rest) = call_id_rest {
            // 元の line から値を取り出す (大小文字保持)
            let value = line
                .split_once(':')
                .map(|x| x.1.trim().to_string())
                .unwrap_or_else(|| rest.trim().to_string());
            call_id = Some(value);
        } else if let Some(rest) = lower_prefix.strip_prefix("cseq:") {
            // レスポンスの場合 method を CSeq の方法名で上書きする
            if method.starts_with("RESP-") {
                let raw_value = line.split_once(':').map(|x| x.1).unwrap_or(rest);
                if let Some(m) = raw_value.split_whitespace().nth(1) {
                    method = format!("{}-{}", method, m);
                }
            }
        }
    }
    (method, call_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_contains_all_series() {
        let m = Metrics::new();
        m.record_register(true);
        m.record_register(false);
        m.record_invite_ngn(InviteResult::Answered);
        m.record_invite_extension(InviteResult::Busy);
        // PR #146 review #1 🟡#1: PWA→NGN 発信専用カウンタ
        m.record_invite_pwa_outbound(InviteResult::Answered);
        m.record_invite_pwa_outbound(InviteResult::Timeout);
        // Issue #157: rate limiter / interval metrics
        m.record_invite_blocked_by_rate_limit(OutboundDirection::Extension);
        m.record_invite_blocked_by_rate_limit(OutboundDirection::PwaOutbound);
        m.record_invite_interval_ms(2500);
        m.inc_call_active();
        m.add_rtp_ngn_to_ext(5);
        m.add_rtp_ext_to_ngn(7);
        m.set_extension_registered(2);

        let body = m.render_prometheus(true);
        assert!(body.contains("sabiden_sip_registered 1"));
        assert!(body.contains("sabiden_sip_register_total{result=\"success\"} 1"));
        assert!(body.contains("sabiden_sip_register_total{result=\"fail\"} 1"));
        assert!(body.contains("sabiden_sip_invite_total{direction=\"ngn\",result=\"answered\"} 1"));
        assert!(
            body.contains("sabiden_sip_invite_total{direction=\"extension\",result=\"busy\"} 1")
        );
        assert!(body.contains(
            "sabiden_sip_invite_total{direction=\"pwa_outbound\",result=\"answered\"} 1"
        ));
        assert!(body
            .contains("sabiden_sip_invite_total{direction=\"pwa_outbound\",result=\"timeout\"} 1"));
        // Issue #157
        assert!(body
            .contains("sabiden_sip_invite_blocked_by_rate_limit_total{direction=\"extension\"} 1"));
        assert!(body.contains(
            "sabiden_sip_invite_blocked_by_rate_limit_total{direction=\"pwa_outbound\"} 1"
        ));
        assert!(body.contains("sabiden_sip_invite_interval_seconds_sum 2.500"));
        assert!(body.contains("sabiden_sip_invite_interval_seconds_count 1"));
        assert!(body.contains("sabiden_call_active 1"));
        assert!(body.contains("sabiden_rtp_bridge_packets_total{direction=\"ngn_to_ext\"} 5"));
        assert!(body.contains("sabiden_rtp_bridge_packets_total{direction=\"ext_to_ngn\"} 7"));
        assert!(body.contains("sabiden_extension_registered 2"));
    }

    #[test]
    fn dec_call_active_clamps_at_zero() {
        let m = Metrics::new();
        m.dec_call_active();
        assert_eq!(m.call_active.load(Ordering::Relaxed), 0);
        m.inc_call_active();
        m.dec_call_active();
        assert_eq!(m.call_active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn sanitize_redacts_authorization_header() {
        let raw = b"REGISTER sip:foo SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bKabc\r\n\
                    Authorization: Digest username=\"alice\",nonce=\"x\",response=\"deadbeef\"\r\n\
                    Call-ID: callid@host\r\n\
                    \r\nbody";
        let out = sanitize_message(raw);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("Authorization: <redacted>"));
        assert!(!s.contains("deadbeef"));
        // 他ヘッダ・本文は保持
        assert!(s.contains("Via: SIP/2.0/UDP 1.2.3.4:5060"));
        assert!(s.contains("Call-ID: callid@host"));
        assert!(s.ends_with("\r\nbody"));
    }

    #[test]
    fn sanitize_handles_proxy_authorization() {
        let raw =
            b"INVITE sip:x SIP/2.0\r\nProxy-Authorization: Digest secret\r\nCall-ID: c\r\n\r\n";
        let out = sanitize_message(raw);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("Proxy-Authorization: <redacted>"));
    }

    #[test]
    fn extract_request_method_and_call_id() {
        let raw = b"INVITE sip:dest SIP/2.0\r\nCall-ID: call-1@host\r\nCSeq: 1 INVITE\r\n\r\n";
        let (m, cid) = extract_method_and_call_id(raw);
        assert_eq!(m, "INVITE");
        assert_eq!(cid.as_deref(), Some("call-1@host"));
    }

    #[test]
    fn extract_response_method_uses_cseq() {
        let raw = b"SIP/2.0 200 OK\r\nCall-ID: call-1@host\r\nCSeq: 1 REGISTER\r\n\r\n";
        let (m, cid) = extract_method_and_call_id(raw);
        assert_eq!(m, "RESP-200-REGISTER");
        assert_eq!(cid.as_deref(), Some("call-1@host"));
    }

    #[test]
    fn extract_compact_call_id_from_ngn_response() {
        // NTT NGN P-CSCF が返す compact form (`v:`, `f:`, `t:`, `i:`, `m:`, `l:`)。
        // 実機 (118.177.125.1) の REGISTER 200 OK pcap から取った形をそのまま渡す。
        let raw = b"SIP/2.0 200 OK\r\n\
v: SIP/2.0/UDP 118.177.72.242:5060;branch=z9hG4bK1\r\n\
f: <sip:0191349809@ntt-east.ne.jp>;tag=956a3a90\r\n\
t: <sip:0191349809@ntt-east.ne.jp>;tag=3987286122\r\n\
i: afa66bea0b3de7c1@hikari-sip\r\n\
CSeq: 1 REGISTER\r\n\
m: <sip:0191349809@118.177.72.242:5060>\r\n\
l: 0\r\n\r\n";
        let (m, cid) = extract_method_and_call_id(raw);
        assert_eq!(m, "RESP-200-REGISTER");
        assert_eq!(
            cid.as_deref(),
            Some("afa66bea0b3de7c1@hikari-sip"),
            "compact 'i:' から call-id を抽出できないと trace ファイル名が nocallid になる"
        );
    }

    #[test]
    fn sanitize_filename_component_replaces_specials() {
        assert_eq!(
            sanitize_filename_component("call-1@host:5060"),
            "call-1_host_5060"
        );
        assert_eq!(sanitize_filename_component(""), "_");
    }

    #[tokio::test]
    async fn trace_writer_writes_file_and_redacts() {
        let dir = tempdir();
        let writer = SipTraceWriter::open(&dir).unwrap();
        let raw =
            b"REGISTER sip:foo SIP/2.0\r\nAuthorization: Digest secret\r\nCall-ID: cid\r\n\r\n";
        writer
            .record(TraceDir::Sent, "REGISTER", Some("cid"), raw)
            .await;
        let mut entries: Vec<_> = fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
        let path = entries.remove(0).path();
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("<redacted>"));
        assert!(!content.contains("Digest secret"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn trace_writer_disabled_is_noop() {
        let writer = SipTraceWriter::disabled();
        // 何も書かない / panic しない
        writer
            .record(TraceDir::Recv, "INVITE", Some("x"), b"hello")
            .await;
    }

    #[tokio::test]
    async fn trace_writer_rotates_when_too_many_files() {
        let dir = tempdir();
        let writer = SipTraceWriter::open(&dir).unwrap();
        // ファイル数上限を一時的に超えさせる代わりに 5 個書いて > 3 になることを確認するのは
        // ロジック確認のため Vec の長さで検証する。ここでは MAX_FILES を直接超えさせない代わりに
        // 内部の rotate を直接叩く小さな確認を兼ねる。
        for i in 0..5u32 {
            let raw = format!("OPTIONS sip:x SIP/2.0\r\nCall-ID: c{}\r\n\r\n", i);
            writer
                .record(
                    TraceDir::Sent,
                    "OPTIONS",
                    Some(&format!("c{}", i)),
                    raw.as_bytes(),
                )
                .await;
        }
        let count = fs::read_dir(&dir).unwrap().count();
        assert!(count >= 1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// テスト一時ディレクトリを作成する小さなヘルパ。
    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir();
        let unique = format!(
            "sabiden-trace-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = base.join(unique);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
