//! Outbound INVITE per-AOR rate limiter (Issue #157)
//!
//! NTT NGN 直収における連続発信抑制を実装する。
//!
//! # 仕様根拠 (TTC JJ-90.24 v2)
//!
//! [TTC JJ-90.24v2](https://www.ttc.or.jp/application/files/5815/5418/4886/JJ-90.24v2.pdf)
//! は NTT 東西の SIP プロトコル準拠仕様 (拘束力あり)。
//!
//! - **§5.7.1 (輻輳制御への考慮)**: 「SIP 端末では短い時間に連続したリクエストの
//!   送信を制限する機能を持つべき」。 HGW 標準実装は送信側で per-AOR の
//!   min-interval を持っており、 直収端末 (sabiden) もこれに準拠する。
//! - **§5.7.3 (INVITE リクエストのリトライ)**: 「事業者 SIP 網の処理輻輳等、
//!   事業者 SIP 網に何らかの問題が発生している可能性があるため、 Retry-After
//!   ヘッダによって指定された時間内には同じ Request-URI に対する INVITE
//!   リクエストの送信をリトライしないようにすべきである」 。 INVITE 5xx の
//!   自動 retry は spec 違反。
//!
//! # 関連 RFC
//!
//! - **RFC 3261 §21.5.4 (503 Service Unavailable)**: ローカルに過負荷を検知した
//!   端末は 503 を返し、 Retry-After (RFC 3261 §20.33) で再試行までの秒数を
//!   示してよい。 sabiden の rate limiter は spec 整合解として、 ローカルで
//!   抑制した INVITE に対して 503 + Retry-After を内線/PWA に返し、
//!   呼び出し側が即座に再発信しないようにする。
//! - **RFC 3261 §20.33 (Retry-After)**: ヘッダ値は秒数 (`Retry-After: 5`)。
//!   コメント / parameter は許容されるが、 sabiden 内部では plain seconds の
//!   みパースする。
//!
//! # 設計
//!
//! - **per-AOR**: 直収では 1 AOR (= 1 電話番号) しか REGISTER しないが、
//!   将来の multi-account / 内線 SIP 端末ごとの個別制御を見据えて key を AOR
//!   にする。 1 AOR しか無い運用ではグローバル rate limiter として動く。
//! - **min_interval**: 通常時の連投制限 (例 3 秒)。 HGW 推定値で、 実機調整可能。
//! - **failure_backoff**: 直前 INVITE が 5xx で終わった場合の追加 backoff。
//!   段階的に倍化 (5 / 10 / 30 秒) させて NGN 側 cooldown と整合させる。
//! - **NGN Retry-After 受信**: NGN P-CSCF から 5xx + Retry-After で
//!   wait 値が返ってきた場合は、 backoff より大きければ Retry-After を採用。
//!
//! # 統合点
//!
//! - PWA→NGN: `UasEventHandler::handle_pwa_outbound_offer` (`PwaOutboundHandler` 実装)
//! - 内線→NGN: `UasEventHandler::handle_invite` (`UasEvent::Invite` 経路)
//! - 失敗時の backoff 更新: NGN INVITE 結果 (`InviteOutcome::Failed`) の status を
//!   `record_failure` でフィードバックする。
//!
//! # 既存パスへの影響
//!
//! - 117 通話パス (`docs/asterisk-real-invite.md`): 単発発信なので min_interval が
//!   小さい (例 3 秒) 範囲では 1 通話目は全く影響しない。 連投時にのみ 503 + Retry-After
//!   で早期拒否される。 これが本 issue の DoD。
//! - 内線→NGN REGISTER パス: 触らない (`src/sip/register.rs` は禁止領域)。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `OutboundRateLimiter` の判定結果。
///
/// - `Allow { previous_interval }`: 発信を許可。 呼び出し側はこれを受け取って
///   即座に INVITE を構築する。 `previous_interval` は同 AOR の **直前の許可**
///   から今回までの経過時間。 初回発信 (= 初許可) では `None`。 呼び出し側は
///   この値を `Metrics::record_invite_interval_ms` に流して
///   `sabiden_sip_invite_interval_seconds` の sum/count に集計する (Issue #157
///   観測点)。
/// - `Deny { retry_after }`: 発信を拒否。 内線/PWA には 503 + `Retry-After:
///   <retry_after.as_secs()>` を返す (RFC 3261 §21.5.4, §20.33)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// 発信を許可する。
    Allow {
        /// 同 AOR の直前許可からの経過時間。 初回は `None`。 メトリクス
        /// (`sabiden_sip_invite_interval_seconds`) への記録に使う。
        previous_interval: Option<Duration>,
    },
    /// 発信を拒否する。 呼び出し側は 503 Service Unavailable + Retry-After を返す。
    Deny {
        /// 次回発信までに待つべき秒数 (`Retry-After` ヘッダ用)。
        ///
        /// 0 秒で deny は許されない (= 拒否しているのに即時再試行を許可するのは矛盾)。
        /// 内部実装は必ず 1 秒以上を返す (`as_secs` の切り捨てで 0 にならないよう、
        /// `round_up_secs` で切り上げる)。
        retry_after: Duration,
    },
}

/// Per-AOR の最後の INVITE 発射時刻と、 5xx backoff 状態。
///
/// `Mutex` で囲んで全 AOR 表を一括ロックする。 同時 INVITE 数は SIP 端末あたり
/// 多くて 数本 / 秒 なので、 ロック競合は実質的に発生しない (BYE / RTP のような
/// hot path には乗らない)。
#[derive(Debug, Clone)]
struct AorState {
    /// 最後に発信を許可した時刻。
    last_allowed_at: Instant,
    /// 直前の 5xx 発火回数。 0 なら通常 min_interval のみ、 1 以上なら
    /// `backoff_step_for(failure_streak)` を加算する。
    failure_streak: u32,
    /// NGN 等から `Retry-After: N` を受信した場合の絶対時刻。
    /// `Some(t)` の間は `now < t` なら必ず Deny。
    retry_after_until: Option<Instant>,
}

/// per-AOR rate limiter (TTC JJ-90.24 §5.7.1 / §5.7.3 準拠)。
///
/// `check_and_record` を発信前に呼び、 `Allow` なら INVITE を構築、
/// `Deny` なら 503 + Retry-After を返す。 INVITE 完了後 (成功 / 失敗とも)
/// `record_failure` または `record_success` で結果をフィードバックする。
///
/// # スレッド安全性
///
/// 内部全状態は `Mutex<HashMap<AOR, AorState>>` 1 本で保護する。 lock 区間は
/// 純 in-memory の HashMap 操作のみ (await を跨がない) なので、
/// `std::sync::Mutex` を使う。 `tokio::sync::Mutex` は不要。
pub struct OutboundRateLimiter {
    state: Mutex<HashMap<String, AorState>>,
    config: RateLimiterConfig,
}

/// `OutboundRateLimiter` の動作パラメータ。
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// 通常時の連続発信最低間隔 (TTC JJ-90.24 §5.7.1)。
    ///
    /// HGW 標準実装と整合する推定値: 3 秒。 実機で調整する場合は config から
    /// 受け取る (本 PR では hard-code default を提供、 必要に応じて
    /// `NgnInboundConfig` 等に追加可能)。
    pub min_interval: Duration,
    /// 5xx 直後の backoff 段階。 `failure_streak` ごとに対応する Duration を
    /// 加算する (vector の末尾を超えたら最後の値を使う)。
    ///
    /// 既定: 5 秒 / 10 秒 / 30 秒 (HGW 実装と TTC §5.7.1 連続抑制を踏まえた値)。
    pub failure_backoff_steps: Vec<Duration>,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(3),
            failure_backoff_steps: vec![
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(30),
            ],
        }
    }
}

impl OutboundRateLimiter {
    /// 既定パラメータで構築する。
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// パラメータを指定して構築する。
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// 設定値への read-only アクセス。
    pub fn config(&self) -> &RateLimiterConfig {
        &self.config
    }

    /// `aor` からの発信を許可するか判定する。
    ///
    /// `Allow` の場合、 内部の `last_allowed_at` は **更新する**
    /// (= 次回の min_interval 起算を「now」にする)。 つまり呼び出し側で
    /// `Allow` を受けた後の INVITE 構築に失敗 (= 実際には NGN に投げない)
    /// しても、 rate limiter としてはカウント済み扱いになる。
    /// これは spec §5.7.1 の保守的解釈 (短時間連投を物理的に防ぐ): 失敗
    /// 経路もまとめて抑制対象とすることで、 NGN 側 cooldown を起こさない。
    ///
    /// `Deny` の場合は何も更新しない (= 拒否は副作用なし)。
    ///
    /// 戻り値の `retry_after` は最低 1 秒 (RFC 3261 §20.33: Retry-After は
    /// 秒単位整数)。
    #[must_use]
    pub fn check_and_record(&self, aor: &str) -> RateLimitDecision {
        self.check_and_record_at(aor, Instant::now())
    }

    /// テスト用: `now` を外部から渡す版。 production code からは
    /// `check_and_record` を使う。
    pub(crate) fn check_and_record_at(&self, aor: &str, now: Instant) -> RateLimitDecision {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // poisoned: 1 度だけ採掘して継続する。 panic させると上位
                // (UAS event loop) ごと落ちて REGISTER 含む全機能が停止する
                // (CLAUDE.md §6.5: production code で panic 禁止)。
                poisoned.into_inner()
            }
        };

        let entry = state.get(aor).cloned();

        // 全体待ち時間を計算する: min_interval + (failure backoff) + (NGN Retry-After 残り)。
        // ベース interval は通常 min_interval、 直前失敗があれば対応 backoff を採用。
        let allow_at = match entry.as_ref() {
            None => {
                // 初回発信は無条件 Allow。
                None
            }
            Some(s) => {
                let mut wait = self.config.min_interval;
                if s.failure_streak > 0 {
                    let idx = (s.failure_streak as usize - 1)
                        .min(self.config.failure_backoff_steps.len().saturating_sub(1));
                    if let Some(step) = self.config.failure_backoff_steps.get(idx) {
                        // backoff は min_interval を吸収する (より長い方を採用)。
                        if *step > wait {
                            wait = *step;
                        }
                    }
                }
                let interval_until = s.last_allowed_at + wait;
                let ra_until = s.retry_after_until;
                Some(match ra_until {
                    Some(ra) if ra > interval_until => ra,
                    _ => interval_until,
                })
            }
        };

        if let Some(allow_at) = allow_at {
            if now < allow_at {
                let remaining = allow_at.duration_since(now);
                return RateLimitDecision::Deny {
                    retry_after: round_up_secs(remaining),
                };
            }
        }

        // Allow → state を更新する。 failure_streak / retry_after_until は
        // **解除しない**: 次の INVITE 結果 (record_success / record_failure)
        // が来るまで保留する。 ただし retry_after_until が経過済なら None に
        // 落とす (= 過去の Retry-After は既に消化済み)。
        let cleared_retry_after_until = entry
            .as_ref()
            .and_then(|s| s.retry_after_until)
            .filter(|ra| *ra > now);

        // 直前許可からの経過時間を `previous_interval` で返す。 初回 (= entry None)
        // では None。 これを呼出側が
        // `Metrics::record_invite_interval_ms` に流して
        // `sabiden_sip_invite_interval_seconds_{sum,count}` を更新する。
        // 単調時計 (`Instant`) で計測しているため負値や巻き戻りはない (RFC 3550
        // §6.3.1 が NTP 時計を避けるのと同じ理由)。
        let previous_interval = entry
            .as_ref()
            .map(|s| now.saturating_duration_since(s.last_allowed_at));

        let updated = AorState {
            last_allowed_at: now,
            failure_streak: entry.as_ref().map(|s| s.failure_streak).unwrap_or(0),
            retry_after_until: cleared_retry_after_until,
        };
        state.insert(aor.to_string(), updated);
        RateLimitDecision::Allow { previous_interval }
    }

    /// 直前の INVITE が 5xx で失敗した場合に呼ぶ。 `failure_streak` を 1 増やす。
    ///
    /// - `status_code`: NGN から返ってきた response status。 5xx のみ streak を増やす
    ///   (6xx は端末固有の決定的拒否なので backoff せず、 4xx も同様に skip)。
    /// - `retry_after_secs`: `Retry-After` ヘッダ値 (秒)。 NGN が指定した時間内は
    ///   絶対的に Deny される (TTC §5.7.3)。
    pub fn record_failure(&self, aor: &str, status_code: u16, retry_after_secs: Option<u32>) {
        self.record_failure_at(aor, status_code, retry_after_secs, Instant::now());
    }

    /// テスト用: `now` を外部から渡す版。
    pub(crate) fn record_failure_at(
        &self,
        aor: &str,
        status_code: u16,
        retry_after_secs: Option<u32>,
        now: Instant,
    ) {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = state.entry(aor.to_string()).or_insert_with(|| AorState {
            last_allowed_at: now,
            failure_streak: 0,
            retry_after_until: None,
        });
        // 5xx のみ backoff streak を進める。 4xx (例 486 Busy Here) は通常
        // 呼び出し先の状態なので NGN 側 cooldown の対象ではない (TTC §5.7.3
        // は 5xx を「事業者 SIP 網の処理輻輳」と扱う)。
        if (500..600).contains(&status_code) {
            entry.failure_streak = entry.failure_streak.saturating_add(1);
        }
        // Retry-After: 5xx でなくても付与されうるが、 spec 上 retry 禁止対象は
        // 5xx (§5.7.3)。 安全側に倒し、 5xx 限定で記録する。
        if (500..600).contains(&status_code) {
            if let Some(secs) = retry_after_secs {
                let until = now + Duration::from_secs(secs as u64);
                // 既存より長い値だけ採用 (短くする = 拒否時間短縮は許可しない)。
                entry.retry_after_until = Some(match entry.retry_after_until {
                    Some(prev) if prev > until => prev,
                    _ => until,
                });
            }
        }
    }

    /// 直前の INVITE が成功 (2xx) で終わった場合に呼ぶ。 `failure_streak` を 0 にリセット。
    ///
    /// 通話が成立した = NGN は受け入れた = 連投抑制状態が解除されたと解釈する。
    pub fn record_success(&self, aor: &str) {
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = state.get_mut(aor) {
            entry.failure_streak = 0;
            entry.retry_after_until = None;
        }
    }

    /// テスト用: 内部状態の snapshot。
    #[cfg(test)]
    fn snapshot(&self, aor: &str) -> Option<(Instant, u32, Option<Instant>)> {
        let state = self.state.lock().ok()?;
        state
            .get(aor)
            .map(|s| (s.last_allowed_at, s.failure_streak, s.retry_after_until))
    }
}

impl Default for OutboundRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for OutboundRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundRateLimiter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// `Duration` を切り上げで秒整数化する (RFC 3261 §20.33: Retry-After は整数秒)。
///
/// 例: 2.3 秒 → 3 秒、 0.4 秒 → 1 秒 (最低 1 秒保証)。
fn round_up_secs(d: Duration) -> Duration {
    let mut secs = d.as_secs();
    if d.subsec_nanos() > 0 {
        secs = secs.saturating_add(1);
    }
    if secs == 0 {
        secs = 1;
    }
    Duration::from_secs(secs)
}

/// 5xx 応答の `Retry-After` ヘッダ (RFC 3261 §20.33) をパースする。
///
/// 文法:
///
/// ```text
/// Retry-After  =  "Retry-After" HCOLON delta-seconds
///                 [ comment ] *( SEMI retry-param )
/// retry-param  =  ("duration" EQUAL delta-seconds) / generic-param
/// ```
///
/// sabiden は実装簡略化のため、 先頭の delta-seconds (10 進整数) のみを取り出す。
/// `5` / `5;duration=10` / `5 (NGN cooldown)` などはいずれも `5` を返す。
/// パース失敗 / 負値 / 32bit 超え時は `None` を返す。
pub fn parse_retry_after(value: &str) -> Option<u32> {
    // 先頭の連続数字だけ取り出す。 trim_start で空白を許容 (RFC 3261 §7.3.1)。
    let trimmed = value.trim_start();
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TTC JJ-90.24 §5.7.1: 初回発信は必ず Allow される。 初回 `previous_interval`
    /// は `None` (直前許可が存在しないため)。
    #[test]
    fn ttc_5_7_1_first_invite_is_allowed() {
        let limiter = OutboundRateLimiter::new();
        let decision = limiter.check_and_record("0312345678");
        assert_eq!(
            decision,
            RateLimitDecision::Allow {
                previous_interval: None
            }
        );
    }

    /// TTC JJ-90.24 §5.7.1: min_interval 内の 2 回目発信は Deny される。
    /// Retry-After は min_interval 以内の正の秒数 (RFC 3261 §20.33)。
    #[test]
    fn ttc_5_7_1_second_invite_within_min_interval_is_denied() {
        let limiter = OutboundRateLimiter::with_config(RateLimiterConfig {
            min_interval: Duration::from_secs(3),
            failure_backoff_steps: vec![],
        });
        let t0 = Instant::now();
        assert!(matches!(
            limiter.check_and_record_at("0312345678", t0),
            RateLimitDecision::Allow {
                previous_interval: None
            }
        ));
        // 1 秒後は Deny (min_interval=3s なので 2 秒 retry-after)。
        let t1 = t0 + Duration::from_secs(1);
        let decision = limiter.check_and_record_at("0312345678", t1);
        match decision {
            RateLimitDecision::Deny { retry_after } => {
                assert_eq!(retry_after, Duration::from_secs(2));
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    /// TTC JJ-90.24 §5.7.1: min_interval 経過後は Allow に戻る。 2 本目の Allow
    /// では `previous_interval = Some(3s)` (1 本目発信からの経過時間) が返り、
    /// 呼出側が metrics に流す。
    #[test]
    fn ttc_5_7_1_invite_after_min_interval_is_allowed() {
        let limiter = OutboundRateLimiter::with_config(RateLimiterConfig {
            min_interval: Duration::from_secs(3),
            failure_backoff_steps: vec![],
        });
        let t0 = Instant::now();
        assert!(matches!(
            limiter.check_and_record_at("0312345678", t0),
            RateLimitDecision::Allow {
                previous_interval: None
            }
        ));
        // 3 秒経過後は再度 Allow。 2 本目は previous_interval=Some(3s)。
        let t1 = t0 + Duration::from_secs(3);
        match limiter.check_and_record_at("0312345678", t1) {
            RateLimitDecision::Allow {
                previous_interval: Some(d),
            } => {
                assert_eq!(d, Duration::from_secs(3));
            }
            other => panic!("expected Allow with previous_interval, got {:?}", other),
        }
    }

    /// per-AOR: 別 AOR からの発信は互いに干渉しない。
    #[test]
    fn rate_limiter_is_per_aor() {
        let limiter = OutboundRateLimiter::with_config(RateLimiterConfig {
            min_interval: Duration::from_secs(3),
            failure_backoff_steps: vec![],
        });
        let t0 = Instant::now();
        assert!(matches!(
            limiter.check_and_record_at("alice", t0),
            RateLimitDecision::Allow {
                previous_interval: None
            }
        ));
        // 別 AOR (bob) は影響を受けない (初回 Allow)。
        assert!(matches!(
            limiter.check_and_record_at("bob", t0 + Duration::from_millis(100)),
            RateLimitDecision::Allow {
                previous_interval: None
            }
        ));
    }

    /// TTC JJ-90.24 §5.7.1 連続抑制: 5xx 後は backoff が effective interval を伸ばす。
    /// 1 回目 5xx → step[0] = 5 秒、 2 回目 → step[1] = 10 秒。
    #[test]
    fn ttc_5_7_1_failure_backoff_extends_interval() {
        let limiter = OutboundRateLimiter::with_config(RateLimiterConfig {
            min_interval: Duration::from_secs(3),
            failure_backoff_steps: vec![Duration::from_secs(5), Duration::from_secs(10)],
        });
        let t0 = Instant::now();
        assert!(matches!(
            limiter.check_and_record_at("0312345678", t0),
            RateLimitDecision::Allow {
                previous_interval: None
            }
        ));
        // 500 で失敗を記録。
        limiter.record_failure_at("0312345678", 500, None, t0 + Duration::from_secs(1));
        // 4 秒後 (min_interval=3 は超えるが backoff=5 未満) は Deny。
        let decision = limiter.check_and_record_at("0312345678", t0 + Duration::from_secs(4));
        match decision {
            RateLimitDecision::Deny { retry_after } => {
                // backoff=5 - (4 - 0) = 1 秒
                assert_eq!(retry_after, Duration::from_secs(1));
            }
            other => panic!("expected Deny, got {:?}", other),
        }
        // 6 秒後 (backoff=5 を超える) は Allow。 previous_interval=Some(6s)。
        match limiter.check_and_record_at("0312345678", t0 + Duration::from_secs(6)) {
            RateLimitDecision::Allow {
                previous_interval: Some(d),
            } => {
                assert_eq!(d, Duration::from_secs(6));
            }
            other => panic!("expected Allow, got {:?}", other),
        }
    }

    /// TTC JJ-90.24 §5.7.3 / RFC 3261 §20.33: NGN が Retry-After: N を返した場合、
    /// その時間内は backoff より厳しく拒否される。
    #[test]
    fn rfc3261_20_33_retry_after_extends_deny_window() {
        let limiter = OutboundRateLimiter::with_config(RateLimiterConfig {
            min_interval: Duration::from_secs(3),
            failure_backoff_steps: vec![Duration::from_secs(5)],
        });
        let t0 = Instant::now();
        assert!(matches!(
            limiter.check_and_record_at("0312345678", t0),
            RateLimitDecision::Allow {
                previous_interval: None
            }
        ));
        // 500 + Retry-After: 60 を記録。
        limiter.record_failure_at("0312345678", 500, Some(60), t0 + Duration::from_secs(1));
        // backoff=5 を超えたが、 Retry-After 60 が effective。
        let decision = limiter.check_and_record_at("0312345678", t0 + Duration::from_secs(10));
        match decision {
            RateLimitDecision::Deny { retry_after } => {
                // 60 - (10 - 1) = 51 秒
                assert!(
                    retry_after >= Duration::from_secs(50)
                        && retry_after <= Duration::from_secs(52),
                    "expected ~51s, got {:?}",
                    retry_after
                );
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    /// 2xx 成功で failure_streak がリセットされる。
    #[test]
    fn record_success_resets_failure_streak() {
        let limiter = OutboundRateLimiter::with_config(RateLimiterConfig {
            min_interval: Duration::from_secs(3),
            failure_backoff_steps: vec![Duration::from_secs(5)],
        });
        let t0 = Instant::now();
        let _ = limiter.check_and_record_at("0312345678", t0);
        limiter.record_failure_at("0312345678", 500, None, t0);
        let snap = limiter.snapshot("0312345678").unwrap();
        assert_eq!(snap.1, 1, "1 回失敗で streak=1");
        limiter.record_success("0312345678");
        let snap = limiter.snapshot("0312345678").unwrap();
        assert_eq!(snap.1, 0, "成功で streak がリセットされる");
    }

    /// 4xx は backoff streak を進めない (TTC §5.7.3 は 5xx 対象)。
    #[test]
    fn rate_limiter_4xx_does_not_increment_failure_streak() {
        let limiter = OutboundRateLimiter::new();
        let t0 = Instant::now();
        let _ = limiter.check_and_record_at("0312345678", t0);
        limiter.record_failure_at("0312345678", 486, None, t0);
        let snap = limiter.snapshot("0312345678").unwrap();
        assert_eq!(snap.1, 0, "486 Busy Here は backoff 対象外");
    }

    /// `round_up_secs`: subsec ns があれば +1 秒、 0 秒入力なら 1 秒に bump。
    #[test]
    fn round_up_secs_rounds_up_and_min_1() {
        assert_eq!(
            round_up_secs(Duration::from_millis(100)),
            Duration::from_secs(1)
        );
        assert_eq!(
            round_up_secs(Duration::from_millis(2300)),
            Duration::from_secs(3)
        );
        assert_eq!(
            round_up_secs(Duration::from_secs(5)),
            Duration::from_secs(5)
        );
        assert_eq!(round_up_secs(Duration::ZERO), Duration::from_secs(1));
    }

    /// RFC 3261 §20.33: Retry-After ヘッダの delta-seconds を抽出する。
    #[test]
    fn rfc3261_20_33_parse_retry_after_plain_integer() {
        assert_eq!(parse_retry_after("5"), Some(5));
        assert_eq!(parse_retry_after("120"), Some(120));
        assert_eq!(parse_retry_after(" 30"), Some(30), "leading space は許容");
    }

    /// RFC 3261 §20.33: comment / generic-param 付きでも delta-seconds を取り出す。
    #[test]
    fn rfc3261_20_33_parse_retry_after_with_comment_and_param() {
        assert_eq!(parse_retry_after("5 (NGN cooldown)"), Some(5));
        assert_eq!(parse_retry_after("60;duration=120"), Some(60));
        assert_eq!(parse_retry_after("18000;duration=3600"), Some(18000));
    }

    /// 数字が無い / 負値 / 不正な入力では None。
    #[test]
    fn parse_retry_after_rejects_invalid_input() {
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("abc"), None);
        assert_eq!(parse_retry_after("-5"), None);
    }

    /// Issue #157 観測点: 連続発信間隔 (`previous_interval`) は同 AOR の
    /// 直前 Allow からの経過時間として正しく返る。 初回は `None`。
    /// `Metrics::record_invite_interval_ms` に流して
    /// `sabiden_sip_invite_interval_seconds_{sum,count}` を埋める呼出側契約。
    #[test]
    fn allow_carries_previous_interval_for_metrics() {
        let limiter = OutboundRateLimiter::with_config(RateLimiterConfig {
            min_interval: Duration::from_secs(1),
            failure_backoff_steps: vec![],
        });
        let t0 = Instant::now();
        // 1 本目: 初回なので None。
        match limiter.check_and_record_at("0312345678", t0) {
            RateLimitDecision::Allow { previous_interval } => {
                assert!(previous_interval.is_none());
            }
            other => panic!("expected Allow, got {:?}", other),
        }
        // 2 本目: t0+5s → previous_interval = 5s。
        match limiter.check_and_record_at("0312345678", t0 + Duration::from_secs(5)) {
            RateLimitDecision::Allow {
                previous_interval: Some(d),
            } => {
                assert_eq!(d, Duration::from_secs(5));
            }
            other => panic!("expected Allow with 5s, got {:?}", other),
        }
        // 3 本目: t0+10s → previous_interval = 5s (2 本目からの差分)。
        match limiter.check_and_record_at("0312345678", t0 + Duration::from_secs(10)) {
            RateLimitDecision::Allow {
                previous_interval: Some(d),
            } => {
                assert_eq!(d, Duration::from_secs(5));
            }
            other => panic!("expected Allow with 5s, got {:?}", other),
        }
        // 別 AOR は独立 (初回 = None)。
        match limiter.check_and_record_at("alice", t0 + Duration::from_secs(11)) {
            RateLimitDecision::Allow { previous_interval } => {
                assert!(
                    previous_interval.is_none(),
                    "別 AOR の初回は previous_interval が None でなければならない"
                );
            }
            other => panic!("expected Allow for alice, got {:?}", other),
        }
    }

    /// failure_streak が backoff_steps の長さを超えても最後の step が使われる
    /// (saturating index)。
    #[test]
    fn failure_streak_clamps_to_last_backoff_step() {
        let limiter = OutboundRateLimiter::with_config(RateLimiterConfig {
            min_interval: Duration::from_secs(3),
            failure_backoff_steps: vec![Duration::from_secs(5), Duration::from_secs(30)],
        });
        let t0 = Instant::now();
        let _ = limiter.check_and_record_at("0312345678", t0);
        // 3 回失敗 (streak=3, 配列 index は最後の 30s に飽和)。
        limiter.record_failure_at("0312345678", 500, None, t0);
        limiter.record_failure_at("0312345678", 500, None, t0);
        limiter.record_failure_at("0312345678", 500, None, t0);
        // 15 秒後 (min_interval=3, backoff=30 → effective wait=30) は Deny。
        let decision = limiter.check_and_record_at("0312345678", t0 + Duration::from_secs(15));
        match decision {
            RateLimitDecision::Deny { retry_after } => {
                // 30 - 15 = 15 秒
                assert_eq!(retry_after, Duration::from_secs(15));
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }
}
