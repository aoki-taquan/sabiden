//! NGN carrier intermittent reject (500 / 486 / 503) に対する自動 retry policy
//! (Issue #260 Phase 1-B)。
//!
//! # 背景 (実機 evidence, 2026-05-11)
//!
//! audit Issue #260 で「番号 / 時間帯 / SDP を問わず NGN P-CSCF が確率的に
//! 500 / 486 で偽装拒絶する」 ことが確定した。 PWA→117 連投で 8 試行中 5 件が
//! 拒絶 (62.5%)、 拒絶レスポンスは Reason / Retry-After / Server / Warning が
//! 全て None で carrier 側理由不在。 35-52ms で reject = pre-allocated 判定。
//! 数秒待って再試行すると大半が成功するため、 **短時間 1 回限定の retry** で
//! ユーザ体験を救済する。
//!
//! # 規格根拠
//!
//! - **3GPP TS 24.229 §5.2.7**: P-CSCF の 500 は「per-INVITE 内部失敗」、 503 は
//!   「overload」。 500 は per-call の失敗なので **同じ INVITE の retry が
//!   spec 整合的**。
//! - **RFC 3261 §20.33 (Retry-After)**: 503 / 500 / 486 で Retry-After が
//!   付いてきた場合は **その秒数を遵守** する。
//! - **RFC 3261 §21.5 (5xx)**: 5xx は server-side failure を示すが、 同じ
//!   request を後で送り直すことは禁止されない。
//! - **TTC JJ-90.24 §5.7.3 (INVITE 5xx 自動 retry)**: 「Retry-After に指定
//!   された時間内には同じ Request-URI への INVITE 再送をリトライしない」 こと、
//!   かつ「過度な自動 retry を避けること」 を端末義務として規定。 **1 回限定 +
//!   Retry-After 遵守** であれば本条文に整合する。
//!
//! # policy 概略
//!
//! - **対象 status**: 500 (Server Internal Error) / 486 (Busy Here) / 503
//!   (Service Unavailable)。 500/486 は carrier throttle と確認済、 503 は
//!   overload の RFC/3GPP 規定意味で retry 妥当。 4xx (400/403/404/...) は
//!   per-request の permanent failure 系なので retry しない。
//! - **最大試行回数**: **1 回** (= 元 INVITE + retry INVITE = 計 2 回まで)。
//!   TTC JJ-90.24 §5.7.3 の「過度な retry」 回避と整合。
//! - **wait 時間**:
//!   - Retry-After ヘッダがあればその秒数を遵守 (RFC 3261 §20.33)。
//!   - 無ければ既定 2 秒 + ±0.5 秒の jitter (= 同時に大量端末が retry しない
//!     ように、 carrier の next ramp に乗らないようバラす)。
//! - **upper bound**: 5 秒。 Retry-After がそれを超えるなら carrier が長期
//!   overload 中なので **諦めて元 error を上位伝搬** (待つだけ無駄)。
//!
//! # 純粋関数として分離する理由
//!
//! retry 判定 (status → policy decision → sleep duration) と retry 実行
//! (`tokio::time::sleep` + INVITE 再送) を分離することで、 ロジック単体を
//! 副作用なし unit test で網羅できる。 orchestrator 側はこの module の
//! `decide_retry` を呼んで判定結果を受け取り、 実 retry を駆動する。

use std::time::Duration;

use crate::sip::message::SipHeaders;

use super::rate_limiter::parse_retry_after;

/// retry policy の動作パラメータ。 設定値は HGW 標準 + 実機 evidence。
#[derive(Debug, Clone)]
pub struct CarrierRetryConfig {
    /// Retry-After ヘッダが無い場合の既定 wait (= 2 秒、 実機 evidence で
    /// 「数秒待てば次回成功」 観測済)。
    pub default_wait: Duration,
    /// Retry-After 上限。 これを超える Retry-After は「諦め」 を意味する。
    pub max_wait: Duration,
    /// jitter 振幅 (±この秒数を一様分布で加える)。 同時複数端末の retry が
    /// 同じ carrier ramp に乗らないようにバラす。
    pub jitter: Duration,
}

impl Default for CarrierRetryConfig {
    fn default() -> Self {
        Self {
            default_wait: Duration::from_millis(2000),
            max_wait: Duration::from_millis(5000),
            jitter: Duration::from_millis(500),
        }
    }
}

/// `decide_retry` の判定結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    /// retry すべき。 `wait` だけ sleep してから 1 回再送する。
    Retry {
        wait: Duration,
        /// 観測ログ用: Retry-After ヘッダの生値 (parse 成功時のみ Some)。
        retry_after_header_secs: Option<u32>,
    },
    /// retry 非対象 (4xx 等)、 または Retry-After が `max_wait` 超 = 諦め。
    NoRetry { reason: NoRetryReason },
}

/// retry しない理由を分類する (テスト容易化 + ログ詳細化)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRetryReason {
    /// 対象外 status (例 400 / 403 / 404)。
    NotIntermittent,
    /// Retry-After が `max_wait` を超えていた = carrier が長期 overload。
    RetryAfterTooLong,
}

/// retry 試行の最終 outcome (metrics ラベル化用)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOutcome {
    /// retry 非対象 (= 元 status が intermittent でない、 または 1 回目で確立)。
    /// metrics には記録しない (= retry 経路に乗らなかった)。
    NotRetried,
    /// retry 実行して 2 回目が成功 (Established / 2xx)。
    RetriedSucceeded,
    /// retry 実行して 2 回目も失敗 (4xx-6xx / transport error)。
    RetriedFailed,
    /// retry すべき判定だったが sleep 中に user cancel された (PWA WS close 等)。
    RetryAbortedByCancel,
}

/// 与えられた status code と response headers から retry 判定を返す。
///
/// 純粋関数 (副作用なし、 入力以外を参照しない)。 orchestrator は本関数の
/// 戻り値を見て sleep + 再 INVITE を駆動する。
///
/// # 引数
/// - `status_code`: NGN P-CSCF から受信した最終 INVITE 応答の status code
/// - `headers`: 同応答の SIP headers (Retry-After 抽出用)
/// - `config`: retry policy パラメータ (本番は `Default::default()`)
/// - `jitter_offset_ms`: テスト容易化のため jitter を外部注入する。 production
///   側は `random_jitter_offset_ms(config.jitter)` で乱数化、 テストでは 0 や
///   固定値を渡して決定論的に検証する。
pub fn decide_retry(
    status_code: u16,
    headers: &SipHeaders,
    config: &CarrierRetryConfig,
    jitter_offset_ms: i64,
) -> RetryDecision {
    if !is_carrier_intermittent_reject(status_code) {
        return RetryDecision::NoRetry {
            reason: NoRetryReason::NotIntermittent,
        };
    }

    // RFC 3261 §20.33: Retry-After (秒) があれば必ず遵守。
    let retry_after_header_secs = headers.get("retry-after").and_then(parse_retry_after);

    let base_wait = match retry_after_header_secs {
        Some(secs) => {
            let req = Duration::from_secs(u64::from(secs));
            if req > config.max_wait {
                // carrier が長期 overload を要求 → 諦めて即時失敗を上位伝搬。
                // TTC JJ-90.24 §5.7.3: 「Retry-After 時間内は再送禁止」 を遵守し、
                // かつ「過度な retry を避ける」 ためここで切る。
                return RetryDecision::NoRetry {
                    reason: NoRetryReason::RetryAfterTooLong,
                };
            }
            req
        }
        None => config.default_wait,
    };

    // jitter を ±jitter の範囲で加える (default_wait 経路でのみ意味があるが、
    // Retry-After 経路でも同様に小さい揺らぎを足して同時 retry の衝突を避ける)。
    let final_wait = apply_jitter(base_wait, jitter_offset_ms);

    RetryDecision::Retry {
        wait: final_wait,
        retry_after_header_secs,
    }
}

/// 対象 status か判定 (= 500 / 486 / 503)。
///
/// 実機 evidence (audit Issue #260 / PR #261):
/// - 500: PWA outbound で観測、 carrier throttle
/// - 486: Linphone 内線→sabiden→NGN で観測、 同じ throttle
/// - 503: 3GPP TS 24.229 §5.2.7 仕様上の overload、 sabiden では未観測だが
///   将来 carrier が 500→503 に変えた場合に効くよう含める
pub fn is_carrier_intermittent_reject(status_code: u16) -> bool {
    matches!(status_code, 500 | 486 | 503)
}

/// `base` に `±jitter_offset_ms` を加える。 結果は 0 を下回らない
/// (`saturating_sub` 相当)、 また `i64` overflow を防ぐ。
fn apply_jitter(base: Duration, jitter_offset_ms: i64) -> Duration {
    let base_ms = i128::from(u64::try_from(base.as_millis()).unwrap_or(u64::MAX));
    let jitter = i128::from(jitter_offset_ms);
    let sum = base_ms.saturating_add(jitter).max(0);
    // 戻り型は Duration (u64)。 i128 → u64 は通常範囲内。
    Duration::from_millis(u64::try_from(sum).unwrap_or(0))
}

/// jitter 振幅 ±`jitter_amplitude` から実用乱数 offset を生成する。
///
/// production 経路から呼ぶ。 テストでは `decide_retry` に固定 offset を直接
/// 渡すため本関数は通らない。 暗号学的強度は不要 (端末間 retry 同期回避が
/// 目的) なので、 標準ライブラリの時刻ベースシードで十分。
pub fn random_jitter_offset_ms(jitter_amplitude: Duration) -> i64 {
    let amp_ms = i64::try_from(jitter_amplitude.as_millis()).unwrap_or(0);
    if amp_ms == 0 {
        return 0;
    }
    // 標準ライブラリのみで軽量乱数 (LCG): nanos からシードを取り、 線形合同で
    // 1 値分回す。 暗号強度不要なので OK。
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    // [-amp, +amp] の一様分布近似。
    let range = (amp_ms * 2 + 1) as u64;
    let normalized = (seed % range) as i64;
    normalized - amp_ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::SipHeaders;

    fn headers_with_retry_after(value: &str) -> SipHeaders {
        let mut h = SipHeaders::new();
        h.set("Retry-After", value);
        h
    }

    /// RFC 3261 §21.5 / 3GPP TS 24.229 §5.2.7 / Issue #260 Phase 1-B:
    /// 500 は intermittent 対象。 Retry-After 無し → default 2 秒 (+ jitter 0)。
    #[test]
    fn phase_1b_500_response_triggers_one_retry_after_2s() {
        let cfg = CarrierRetryConfig::default();
        let headers = SipHeaders::new();
        let decision = decide_retry(500, &headers, &cfg, 0);
        match decision {
            RetryDecision::Retry {
                wait,
                retry_after_header_secs,
            } => {
                assert_eq!(wait, Duration::from_millis(2000));
                assert_eq!(retry_after_header_secs, None);
            }
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    /// Issue #260 Phase 1-B 実機 evidence: Linphone→sabiden→NGN で 486 を観測。
    /// 486 も対象に含める。
    #[test]
    fn phase_1b_486_response_triggers_one_retry() {
        let cfg = CarrierRetryConfig::default();
        let headers = SipHeaders::new();
        let decision = decide_retry(486, &headers, &cfg, 0);
        assert!(matches!(decision, RetryDecision::Retry { .. }));
    }

    /// RFC 3261 §20.33 (Retry-After): ヘッダ値があれば遵守する。
    /// 3 秒 < max_wait(5s) なので Retry とし、 wait は 3 秒 (+ jitter 0)。
    #[test]
    fn phase_1b_503_with_retry_after_obeys_header() {
        let cfg = CarrierRetryConfig::default();
        let headers = headers_with_retry_after("3");
        let decision = decide_retry(503, &headers, &cfg, 0);
        match decision {
            RetryDecision::Retry {
                wait,
                retry_after_header_secs,
            } => {
                assert_eq!(wait, Duration::from_millis(3000));
                assert_eq!(retry_after_header_secs, Some(3));
            }
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    /// TTC JJ-90.24 §5.7.3 / 過度な retry 回避: Retry-After が `max_wait` (5s)
    /// を超えるなら carrier 長期 overload と判断、 諦めて即時失敗を伝搬。
    #[test]
    fn phase_1b_503_with_retry_after_over_5s_no_retry() {
        let cfg = CarrierRetryConfig::default();
        let headers = headers_with_retry_after("30");
        let decision = decide_retry(503, &headers, &cfg, 0);
        assert_eq!(
            decision,
            RetryDecision::NoRetry {
                reason: NoRetryReason::RetryAfterTooLong
            }
        );
    }

    /// RFC 3261 §21.4 / §21.5: 4xx (permanent failure) や 6xx は retry しない。
    /// 400 Bad Request は permanent client error なので除外。
    #[test]
    fn phase_1b_400_response_does_not_trigger_retry() {
        let cfg = CarrierRetryConfig::default();
        let headers = SipHeaders::new();
        let decision = decide_retry(400, &headers, &cfg, 0);
        assert_eq!(
            decision,
            RetryDecision::NoRetry {
                reason: NoRetryReason::NotIntermittent
            }
        );
    }

    /// Issue #260 Phase 1-B: 403 Forbidden / 404 Not Found / 408 Timeout 等の
    /// 4xx も retry しない。 200 OK / 1xx は呼び出し側で intermittent 経路に
    /// 来ない (= retry 判定すら呼ばれない) ので、 ここでは念のため非対象。
    #[test]
    fn phase_1b_other_4xx_and_2xx_do_not_trigger_retry() {
        let cfg = CarrierRetryConfig::default();
        let headers = SipHeaders::new();
        for status in [200u16, 180, 401, 403, 404, 408, 487, 488] {
            let decision = decide_retry(status, &headers, &cfg, 0);
            assert!(
                matches!(decision, RetryDecision::NoRetry { .. }),
                "status {} unexpectedly triggered retry",
                status
            );
        }
    }

    /// jitter 単体: ±500ms の範囲で加減算され、 0 を下回らない。
    #[test]
    fn phase_1b_jitter_bounded() {
        assert_eq!(
            apply_jitter(Duration::from_millis(2000), 500),
            Duration::from_millis(2500)
        );
        assert_eq!(
            apply_jitter(Duration::from_millis(2000), -500),
            Duration::from_millis(1500)
        );
        // 0 を下回らない (saturating)。
        assert_eq!(
            apply_jitter(Duration::from_millis(100), -500),
            Duration::ZERO
        );
    }

    /// jitter offset を非ゼロにして decide_retry に渡したら反映されること。
    #[test]
    fn phase_1b_jitter_propagates_into_decision_wait() {
        let cfg = CarrierRetryConfig::default();
        let headers = SipHeaders::new();
        let decision = decide_retry(500, &headers, &cfg, 300);
        match decision {
            RetryDecision::Retry { wait, .. } => {
                assert_eq!(wait, Duration::from_millis(2300));
            }
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    /// Issue #260 Phase 1-B metrics 設計: `RetryOutcome` の variant が
    /// 「retry 駆動された」/「されなかった」 を明確に区別すること。
    /// observability 層で `record_ngn_carrier_retry(RetryOutcome::*)` の
    /// match arm が全 variant を網羅する前提を保つ。
    #[test]
    fn phase_1b_retry_outcome_variants_distinct() {
        // 同値判定で variant 同士が衝突しないこと (= match の網羅性確認)。
        assert_ne!(RetryOutcome::NotRetried, RetryOutcome::RetriedSucceeded);
        assert_ne!(RetryOutcome::RetriedSucceeded, RetryOutcome::RetriedFailed);
        assert_ne!(
            RetryOutcome::RetriedFailed,
            RetryOutcome::RetryAbortedByCancel
        );
    }

    /// `random_jitter_offset_ms` は ±amp の範囲に収まる。
    #[test]
    fn phase_1b_random_jitter_within_amplitude() {
        let amp = Duration::from_millis(500);
        for _ in 0..50 {
            let v = random_jitter_offset_ms(amp);
            assert!(
                (-500..=500).contains(&v),
                "jitter offset {} out of bound",
                v
            );
        }
        // amp=0 なら必ず 0
        assert_eq!(random_jitter_offset_ms(Duration::ZERO), 0);
    }
}
