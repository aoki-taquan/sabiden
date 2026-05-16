//! 着信ルーティングルールエンジン (Issue #295)
//!
//! NGN inbound INVITE のフォーク先内線を、 時間帯 / 曜日 / 発信者番号に
//! 基づいて絞り込む。 旧実装は `registrar.snapshot()` (= 全登録内線) を
//! そのまま `fork_to_bindings` に渡していたため、 営業時間外でも全端末が
//! 鳴る挙動だった。 Issue #295 では config.toml に `[[routing.rule]]`
//! セクションを導入し、 優先度順で最初に match した rule の `fork =
//! [<aor>, ...]` を採用する。
//!
//! ## 設計判断: trait 引数ではなく "filter on snapshot" モデル
//!
//! 既存 `extensions.snapshot()` の戻り値 `Vec<(String, Binding)>` を
//! filter する純粋関数 (`evaluate`) として実装する。 これにより:
//!
//! - registrar / orchestrator の責務を変えずに済む (= regression リスク 0)。
//! - rules engine 自体は registrar / call / SIP 層への依存無し、 単体 unit
//!   test がそのまま可能 (`docs/test-strategy.md` §2.1 Unit ガイドライン)。
//! - 後方互換: rule 無し / 全 rule no-match なら `evaluate` は `None`
//!   を返し、 呼出側 (`NgnInboundHandler::handle_invite`) は従来通り
//!   `snapshot()` をそのまま `fork_to_bindings` に渡す (= 既存 117 通話
//!   / fork all-fail → voicemail 経路に影響なし、 Issue #295 触らない領域
//!   制約と整合)。
//!
//! ## RFC 引用 (CLAUDE.md §6.2)
//!
//! 着信ルーティング自体は **アプリケーション層の business rule** であり、
//! 単一 RFC に直接対応しない。 ただし以下は遵守する:
//!
//! - **RFC 3261 §16.7 (Stateful Proxy Forking)**: 「target を絞る方針」 は
//!   §16.4-5 / §16.7 で proxy 一般に許容される (administrative policy)。
//!   sabiden は B2BUA なので §16 の MUST/SHOULD を文字通り適用する立場には
//!   無いが、 "rules で fork target を絞る" 設計自体は §16.4 "Determining
//!   Targets" の意図と整合する。
//! - **RFC 3261 §20.20 / §20.39 (From / To)**: `from_number` は受信 INVITE
//!   の From URI から user 部のみ抽出して比較する。 NGN inbound では carrier
//!   IMS が PAI/PPI を剥がして `anonymous@anonymous.invalid` を載せてくる
//!   ケースが観測されており (memory `project_ngn_inbound_caller_id_stripped`)、
//!   この場合 `from_number = "anonymous"` で評価される。 rule 側が `"anonymous"`
//!   を明示列挙すれば match する設計。
//!
//! ## 時刻処理 (chrono)
//!
//! - `chrono::Local::now()` で wall-clock を取得し、 `weekday()` / `time()`
//!   で曜日 / HH:MM を抽出する。
//! - `evaluate` 自体は `now: DateTime<Local>` を引数で受ける純粋関数。
//!   テストは固定 timestamp を流し込んで決定的に検証可能 (= flaky 防止、
//!   `docs/test-strategy.md` §3.1)。
//! - `time_range = "09:00-18:00"`: HH:MM-HH:MM。 24h 跨ぎ (`22:00-06:00`)
//!   は「終端 < 始端」 なら "wrap around midnight" として OR 解釈
//!   (= `now >= start || now < end`)。 同値 (`09:00-09:00`) は 24h 全マッチ
//!   ではなく 0 秒幅扱い (= match しない、 退化形)。

#[cfg(test)]
use chrono::TimeZone;
use chrono::{DateTime, Datelike, Local, NaiveTime, Weekday};
use serde::{Deserialize, Serialize};

use crate::sip::registrar::Binding;

/// `[[routing.rule]]` の集合 (TOML root の `routing.rule` 配列に対応)。
///
/// `evaluate` 呼出時に **`priority` 降順** で評価し、 最初に match した
/// rule の `fork` を採用する。 同値 priority の場合は宣言順 (TOML 配列
/// 順) を維持する (`sort_by` 安定ソート)。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RoutingRules {
    /// 個別 rule のリスト。 空なら `evaluate` は常に `None` (= fallback)
    /// を返す (後方互換、 Issue #295 DoD)。
    #[serde(default, rename = "rule")]
    pub rules: Vec<RoutingRule>,
}

/// 1 件のルーティングルール。
///
/// match 条件 (`match_`) を全部 AND で評価し、 全部 satisfy なら採用、
/// `fork` (= AOR 名のリスト) を内線 binding 名で filter する。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingRule {
    /// rule 識別子 (ログ / メトリクス用)。 一意性は強制しない (運用側責任)。
    pub name: String,
    /// 優先度。 大きいほど先に評価。 既定 0 (= 最低優先度)。
    #[serde(default)]
    pub priority: i32,
    /// match 条件 (全部 AND、 省略項目は「無条件マッチ」)。
    ///
    /// TOML 側は `[[routing.rule]] match.weekday = [...]` のようにフラット
    /// 表記で書けるよう、 ここでは `match_` フィールドに `#[serde(rename =
    /// "match")]` を付ける (`match` は Rust の予約語のためフィールド名には
    /// できない)。
    #[serde(default, rename = "match")]
    pub match_: MatchSpec,
    /// match 時に fork する AOR (内線 username) のリスト。
    ///
    /// 空 `[]` は **「誰にも fork しない」** を意味する。 呼出側 (`handle_invite`)
    /// は空ベクタを受け取った場合、 `bindings.is_empty()` 経路に乗って voicemail
    /// もしくは 480 を返す (= Issue #295 の `after_hours` rule で voicemail
    /// 直行を実現する想定)。
    #[serde(default)]
    pub fork: Vec<String>,
}

/// rule の match 条件。 各フィールドは Option<…> で「省略 = 無条件マッチ」。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MatchSpec {
    /// 評価時刻の曜日 (`Local` time zone) がここに含まれていれば match。
    /// 省略時は全曜日マッチ。
    ///
    /// 受理表記 (case-insensitive): `mon` / `tue` / `wed` / `thu` / `fri` /
    /// `sat` / `sun` および 3 文字以外でも頭 3 文字一致 (`monday` 等) を許容。
    #[serde(default)]
    pub weekday: Option<Vec<String>>,
    /// 評価時刻 (HH:MM, 秒切り捨て) がこの範囲に入っていれば match。
    /// 省略時は全時間帯マッチ。
    ///
    /// 表記: `"HH:MM-HH:MM"` (24 時間制)。 終端 < 始端なら midnight wrap
    /// として OR 評価する (例 `22:00-06:00` は 22:00..24:00 ∪ 00:00..06:00)。
    /// 範囲は **半開区間** `[start, end)`。 同値 (`09:00-09:00`) は退化形で
    /// match しない (= 0 秒幅)。
    #[serde(default)]
    pub time_range: Option<String>,
    /// 発信者番号 (受信 INVITE From URI の user 部) がここに含まれていれば
    /// match。 省略時は全番号マッチ。
    ///
    /// # 特殊値
    ///
    /// - `"anonymous"`: NGN inbound で carrier IMS が PAI を剥がし
    ///   `anonymous@anonymous.invalid` を載せた **明示的非通知** (memory
    ///   `project_ngn_inbound_caller_id_stripped`)。 rule 側で `"anonymous"`
    ///   を明示列挙すれば非通知 ⇒ 特定 fork を表現可能。
    /// - `"unknown"`: sabiden が From URI から user 部を抽出できなかった
    ///   **フォールバック** (orchestrator の `extract_user_from_sip_uri` が
    ///   `None` を返した場合)。 通常 NGN inbound では発生しないが、 防御的に
    ///   `"unknown"` で評価される。 `"anonymous"` (carrier 由来) と別物。
    #[serde(default)]
    pub from_number: Option<Vec<String>>,
}

/// `evaluate` の戻り値。
///
/// - `Matched(Vec<(aor, Binding)>)`: rule が 1 件 match し、 `fork` に
///   列挙された AOR で binding を filter した結果 (空 vec も含む)。
///   空 vec は **「voicemail / 480 直行」** を意味する (after_hours rule)。
/// - `NoRule`: rule が 1 件も match しなかった。 呼出側は **registrar
///   全 binding** で従来挙動を維持する (後方互換、 Issue #295 DoD)。
#[derive(Debug, Clone)]
pub enum RoutingDecision {
    /// rule の `fork` で filter 済 binding 集合 (空 vec は voicemail 直行)。
    Matched {
        /// 採用された rule 名 (ログ / メトリクス用)。
        rule_name: String,
        /// fork 対象 binding (順序は rule.fork の宣言順を維持)。
        ///
        /// 注: `Binding` は `PartialEq` を実装しないため (内部に `Instant` /
        /// `Arc<dyn PeerSession>` を持つ)、 `RoutingDecision` 自体も `PartialEq`
        /// を derive できない。 テスト側は `rule_name` と `bindings` の AOR
        /// だけを取り出して assert する。
        bindings: Vec<(String, Binding)>,
    },
    /// どの rule にも match しなかった。 呼出側は registrar 全 binding を fork する。
    NoRule,
}

impl RoutingDecision {
    /// テスト用: `NoRule` 判定の便利関数。
    #[cfg(test)]
    pub fn is_no_rule(&self) -> bool {
        matches!(self, RoutingDecision::NoRule)
    }
}

impl RoutingRules {
    /// rule リストが空かどうか。 `true` なら evaluate は常に `NoRule` を返す。
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 全 rule を `priority` 降順 (同値は宣言順) で評価し、 最初に match した
    /// rule の `fork` を採用する。
    ///
    /// # 引数
    ///
    /// - `now`: 評価時刻。 wall-clock (`Local::now()`) を呼出側で取って渡す
    ///   ことで、 関数自体は決定的 (テストで固定値を流し込める)。
    /// - `from_number`: 発信者番号 (例 `"0312345678"` / `"anonymous"`)。
    ///   `MatchSpec::from_number` との比較は **完全一致** (大文字小文字差
    ///   は許容しない、 SIP user 部は case-sensitive、 RFC 3261 §19.1.4)。
    /// - `all_bindings`: 登録済み内線 (`registrar.snapshot()` の戻り値)。
    ///   match 時はこのうち `rule.fork` に列挙された AOR のみを抽出する。
    ///
    /// # 戻り値
    ///
    /// - `RoutingDecision::Matched`: いずれかの rule が match した。
    /// - `RoutingDecision::NoRule`: rule リストが空、 または全 rule no-match。
    pub fn evaluate(
        &self,
        now: DateTime<Local>,
        from_number: &str,
        all_bindings: &[(String, Binding)],
    ) -> RoutingDecision {
        if self.rules.is_empty() {
            return RoutingDecision::NoRule;
        }
        // priority 降順安定ソート (同値は宣言順を維持)。
        let mut indexed: Vec<(usize, &RoutingRule)> = self.rules.iter().enumerate().collect();
        indexed.sort_by(|(ia, a), (ib, b)| b.priority.cmp(&a.priority).then(ia.cmp(ib)));

        for (_, rule) in indexed {
            if rule.matches(now, from_number) {
                let bindings = filter_bindings_by_aor(all_bindings, &rule.fork);
                return RoutingDecision::Matched {
                    rule_name: rule.name.clone(),
                    bindings,
                };
            }
        }
        RoutingDecision::NoRule
    }
}

impl RoutingRule {
    /// 全 match 条件 (`weekday` / `time_range` / `from_number`) を AND 評価。
    /// 省略フィールドは無条件 true。
    fn matches(&self, now: DateTime<Local>, from_number: &str) -> bool {
        if let Some(weekdays) = &self.match_.weekday {
            let today = now.weekday();
            if !weekdays.iter().any(|w| parse_weekday(w) == Some(today)) {
                return false;
            }
        }
        if let Some(range_str) = &self.match_.time_range {
            match parse_time_range(range_str) {
                Some((start, end)) => {
                    if !time_in_range(now.time(), start, end) {
                        return false;
                    }
                }
                None => {
                    // パース失敗は **無条件 unmatch** で安全側に倒す
                    // (運用ミス時に「常時全 fork」 になるのを防ぐため)。
                    // load 時に validate しているので production では到達しない。
                    return false;
                }
            }
        }
        if let Some(numbers) = &self.match_.from_number {
            if !numbers.iter().any(|n| n == from_number) {
                return false;
            }
        }
        true
    }

    /// `time_range` フィールドの構文検証。 `Config::load` から起動時に呼ぶ
    /// (= 不正値で起動を fail-fast にする)。
    pub fn validate(&self) -> Result<(), String> {
        if let Some(range_str) = &self.match_.time_range {
            parse_time_range(range_str).ok_or_else(|| {
                format!("rule '{}': invalid time_range '{}'", self.name, range_str)
            })?;
        }
        if let Some(weekdays) = &self.match_.weekday {
            for w in weekdays {
                if parse_weekday(w).is_none() {
                    return Err(format!("rule '{}': invalid weekday '{}'", self.name, w));
                }
            }
        }
        Ok(())
    }
}

/// `RoutingRules` 全体の validate (起動時 fail-fast 用)。
pub fn validate_rules(rules: &RoutingRules) -> Result<(), String> {
    for rule in &rules.rules {
        rule.validate()?;
    }
    Ok(())
}

fn parse_weekday(s: &str) -> Option<Weekday> {
    let lower = s.trim().to_ascii_lowercase();
    // 頭 3 文字での match を許容 ("monday" / "mon" / "MON" を同等視)。
    let head = if lower.len() >= 3 {
        &lower[..3]
    } else {
        &lower[..]
    };
    match head {
        "mon" => Some(Weekday::Mon),
        "tue" => Some(Weekday::Tue),
        "wed" => Some(Weekday::Wed),
        "thu" => Some(Weekday::Thu),
        "fri" => Some(Weekday::Fri),
        "sat" => Some(Weekday::Sat),
        "sun" => Some(Weekday::Sun),
        _ => None,
    }
}

fn parse_time_range(s: &str) -> Option<(NaiveTime, NaiveTime)> {
    let (start_s, end_s) = s.split_once('-')?;
    let start = NaiveTime::parse_from_str(start_s.trim(), "%H:%M").ok()?;
    let end = NaiveTime::parse_from_str(end_s.trim(), "%H:%M").ok()?;
    Some((start, end))
}

/// 半開区間 `[start, end)` 判定。 終端 < 始端なら midnight wrap として
/// OR 評価 (`>= start || < end`)。 同値 (退化形) は常に false。
fn time_in_range(now: NaiveTime, start: NaiveTime, end: NaiveTime) -> bool {
    if start == end {
        return false;
    }
    if start < end {
        now >= start && now < end
    } else {
        // wrap around midnight (例 22:00-06:00)
        now >= start || now < end
    }
}

fn filter_bindings_by_aor(all: &[(String, Binding)], wanted: &[String]) -> Vec<(String, Binding)> {
    // rule.fork の宣言順を維持しつつ、 registrar に存在する AOR のみ採用。
    // 未登録 AOR (= rule 設定ミス / まだ REGISTER していない端末) は静かに
    // skip (= 当該 rule の他端末で fork、 全員未登録なら voicemail / 480)。
    let mut result = Vec::with_capacity(wanted.len());
    for aor in wanted {
        if let Some(entry) = all.iter().find(|(k, _)| k == aor) {
            result.push(entry.clone());
        }
    }
    result
}

/// テスト用ヘルパ: 任意の HH:MM の `DateTime<Local>` を曜日指定で組み立てる。
#[cfg(test)]
fn dt(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Local> {
    Local
        .with_ymd_and_hms(year, month, day, hour, minute, 0)
        .single()
        .expect("dt construct")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::sip::registrar::{Binding, ExtTransport};
    use chrono::Timelike;
    use std::time::{Duration, Instant};

    fn mock_bindings(aors: &[&str]) -> Vec<(String, Binding)> {
        aors.iter()
            .map(|a| {
                (
                    a.to_string(),
                    Binding {
                        contact_uri: format!("sip:{}@127.0.0.1:5060", a),
                        remote: "127.0.0.1:5060".parse().expect("addr"),
                        expires_at: Instant::now() + Duration::from_secs(3600),
                        transport: ExtTransport::Sip,
                    },
                )
            })
            .collect()
    }

    fn rule(name: &str, prio: i32, m: MatchSpec, fork: &[&str]) -> RoutingRule {
        RoutingRule {
            name: name.to_string(),
            priority: prio,
            match_: m,
            fork: fork.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// DoD ケース 1: 空 rule リスト → `NoRule` (= 後方互換、 全 fork fallback)。
    #[test]
    fn empty_rules_yields_no_rule_fallback() {
        let rules = RoutingRules::default();
        let bindings = mock_bindings(&["iphone", "android"]);
        let decision = rules.evaluate(dt(2026, 5, 15, 10, 0), "0312345678", &bindings);
        assert!(decision.is_no_rule(), "expected NoRule, got {:?}", decision);
    }

    /// DoD ケース 2: 時間帯 match (営業時間内 → office_hours rule 採用)。
    /// 月曜 10:00 / 09:00-18:00 → match。
    #[test]
    fn time_range_in_office_hours_matches() {
        let rules = RoutingRules {
            rules: vec![rule(
                "office_hours",
                100,
                MatchSpec {
                    weekday: None,
                    time_range: Some("09:00-18:00".to_string()),
                    from_number: None,
                },
                &["iphone", "office-phone"],
            )],
        };
        let bindings = mock_bindings(&["iphone", "office-phone", "boss-mobile"]);
        let decision = rules.evaluate(dt(2026, 5, 18, 10, 0), "0312345678", &bindings);
        match decision {
            RoutingDecision::Matched {
                rule_name,
                bindings,
            } => {
                assert_eq!(rule_name, "office_hours");
                let aors: Vec<&str> = bindings.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(aors, vec!["iphone", "office-phone"]);
            }
            other => panic!("expected Matched, got {:?}", other),
        }
    }

    /// DoD ケース 3: 時間帯 out (営業時間外、 18:01 / 09:00-18:00 → unmatch)
    /// → 他に rule 無いなら NoRule。
    #[test]
    fn time_range_out_of_office_hours_yields_no_rule() {
        let rules = RoutingRules {
            rules: vec![rule(
                "office_hours",
                100,
                MatchSpec {
                    weekday: None,
                    time_range: Some("09:00-18:00".to_string()),
                    from_number: None,
                },
                &["iphone"],
            )],
        };
        let bindings = mock_bindings(&["iphone"]);
        // 18:00 は半開区間 [09:00, 18:00) で「end と等しい」 → unmatch。
        let decision = rules.evaluate(dt(2026, 5, 18, 18, 0), "0312345678", &bindings);
        assert!(decision.is_no_rule(), "expected NoRule, got {:?}", decision);
    }

    /// DoD ケース 4: 曜日 match (月-金 → 平日マッチ、 土曜 → unmatch)。
    #[test]
    fn weekday_match_weekdays_only() {
        let rules = RoutingRules {
            rules: vec![rule(
                "weekday_only",
                50,
                MatchSpec {
                    weekday: Some(vec![
                        "mon".to_string(),
                        "tue".to_string(),
                        "wed".to_string(),
                        "thu".to_string(),
                        "fri".to_string(),
                    ]),
                    time_range: None,
                    from_number: None,
                },
                &["iphone"],
            )],
        };
        let bindings = mock_bindings(&["iphone"]);
        // 2026-05-18 = 月曜
        let decision = rules.evaluate(dt(2026, 5, 18, 10, 0), "0312345678", &bindings);
        assert!(matches!(decision, RoutingDecision::Matched { .. }));
        // 2026-05-16 = 土曜 → unmatch → NoRule
        let decision_sat = rules.evaluate(dt(2026, 5, 16, 10, 0), "0312345678", &bindings);
        assert!(matches!(decision_sat, RoutingDecision::NoRule));
    }

    /// DoD ケース 5: from_number 完全一致 (VIP 番号 → boss-mobile)。
    #[test]
    fn from_number_exact_match() {
        let rules = RoutingRules {
            rules: vec![rule(
                "vip_customer",
                200,
                MatchSpec {
                    weekday: None,
                    time_range: None,
                    from_number: Some(vec!["0312345678".to_string(), "0398765432".to_string()]),
                },
                &["boss-mobile"],
            )],
        };
        let bindings = mock_bindings(&["iphone", "boss-mobile"]);
        let decision = rules.evaluate(dt(2026, 5, 18, 23, 0), "0312345678", &bindings);
        match decision {
            RoutingDecision::Matched {
                rule_name,
                bindings,
            } => {
                assert_eq!(rule_name, "vip_customer");
                let aors: Vec<&str> = bindings.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(aors, vec!["boss-mobile"]);
            }
            other => panic!("expected Matched, got {:?}", other),
        }
        // 別番号 → unmatch
        let decision_other = rules.evaluate(dt(2026, 5, 18, 23, 0), "0398888888", &bindings);
        assert!(matches!(decision_other, RoutingDecision::NoRule));
    }

    /// DoD ケース 6: priority 降順 + 同値は宣言順 + 最初に match した rule 採用。
    ///
    /// vip(200) > office_hours(100) > after_hours(0) の順で評価し、
    /// vip が match すれば office_hours は無視される。
    #[test]
    fn priority_descending_first_match_wins() {
        let rules = RoutingRules {
            rules: vec![
                // 宣言順は逆 (= sort で priority 200 が先頭に来ることを検証)
                rule(
                    "after_hours",
                    0,
                    MatchSpec::default(),
                    &[], // 空 fork = voicemail 直行
                ),
                rule(
                    "office_hours",
                    100,
                    MatchSpec {
                        weekday: None,
                        time_range: Some("09:00-18:00".to_string()),
                        from_number: None,
                    },
                    &["iphone", "office-phone"],
                ),
                rule(
                    "vip_customer",
                    200,
                    MatchSpec {
                        weekday: None,
                        time_range: None,
                        from_number: Some(vec!["0312345678".to_string()]),
                    },
                    &["boss-mobile"],
                ),
            ],
        };
        let bindings = mock_bindings(&["iphone", "office-phone", "boss-mobile"]);
        // 月曜 10:00 + VIP 番号 → vip が最優先で勝つ
        let decision = rules.evaluate(dt(2026, 5, 18, 10, 0), "0312345678", &bindings);
        match decision {
            RoutingDecision::Matched {
                rule_name,
                bindings: b,
            } => {
                assert_eq!(rule_name, "vip_customer");
                let aors: Vec<&str> = b.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(aors, vec!["boss-mobile"]);
            }
            other => panic!("expected Matched(vip_customer), got {:?}", other),
        }
        // 月曜 10:00 + 他番号 → office_hours が次点で勝つ
        let decision = rules.evaluate(dt(2026, 5, 18, 10, 0), "0398888888", &bindings);
        match decision {
            RoutingDecision::Matched {
                rule_name,
                bindings: b,
            } => {
                assert_eq!(rule_name, "office_hours");
                let aors: Vec<&str> = b.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(aors, vec!["iphone", "office-phone"]);
            }
            other => panic!("expected Matched(office_hours), got {:?}", other),
        }
        // 月曜 23:00 + 他番号 → after_hours (priority 0, 空 fork = voicemail)
        let decision = rules.evaluate(dt(2026, 5, 18, 23, 0), "0398888888", &bindings);
        match decision {
            RoutingDecision::Matched {
                rule_name,
                bindings: b,
            } => {
                assert_eq!(rule_name, "after_hours");
                assert!(b.is_empty(), "after_hours fork should be empty (voicemail)");
            }
            other => panic!("expected Matched(after_hours), got {:?}", other),
        }
    }

    /// DoD ケース 7: 全 rule no-match → NoRule (= 全 fork fallback)。
    /// office_hours のみ定義、 土曜 23:00 で評価 (時間外) → NoRule。
    #[test]
    fn all_rules_no_match_yields_no_rule() {
        let rules = RoutingRules {
            rules: vec![rule(
                "office_hours",
                100,
                MatchSpec {
                    weekday: Some(vec!["mon".to_string(), "fri".to_string()]),
                    time_range: Some("09:00-18:00".to_string()),
                    from_number: None,
                },
                &["iphone"],
            )],
        };
        let bindings = mock_bindings(&["iphone", "android"]);
        // 土曜 23:00 (weekday も time_range も unmatch)
        let decision = rules.evaluate(dt(2026, 5, 16, 23, 0), "0398888888", &bindings);
        assert!(decision.is_no_rule(), "expected NoRule, got {:?}", decision);
    }

    /// midnight wrap: `22:00-06:00` は 22:00..24:00 ∪ 00:00..06:00 を OR で覆う。
    #[test]
    fn time_range_wraps_around_midnight() {
        let rules = RoutingRules {
            rules: vec![rule(
                "night_shift",
                10,
                MatchSpec {
                    weekday: None,
                    time_range: Some("22:00-06:00".to_string()),
                    from_number: None,
                },
                &["night-phone"],
            )],
        };
        let bindings = mock_bindings(&["night-phone"]);
        // 23:30 → match
        assert!(matches!(
            rules.evaluate(dt(2026, 5, 18, 23, 30), "0", &bindings),
            RoutingDecision::Matched { .. }
        ));
        // 02:00 → match
        assert!(matches!(
            rules.evaluate(dt(2026, 5, 18, 2, 0), "0", &bindings),
            RoutingDecision::Matched { .. }
        ));
        // 12:00 → unmatch
        assert!(matches!(
            rules.evaluate(dt(2026, 5, 18, 12, 0), "0", &bindings),
            RoutingDecision::NoRule
        ));
    }

    /// 未登録 AOR (= rule.fork に列挙されているが registrar に存在しない) は
    /// 静かに skip。 全員未登録なら空 vec を返す (= voicemail 直行と同じ扱い)。
    #[test]
    fn unregistered_aor_in_fork_is_silently_skipped() {
        let rules = RoutingRules {
            rules: vec![rule(
                "office_hours",
                100,
                MatchSpec::default(),
                &["iphone", "ghost-phone"], // ghost-phone は registrar 不在
            )],
        };
        let bindings = mock_bindings(&["iphone", "android"]);
        let decision = rules.evaluate(dt(2026, 5, 18, 10, 0), "0", &bindings);
        match decision {
            RoutingDecision::Matched {
                rule_name,
                bindings: b,
            } => {
                assert_eq!(rule_name, "office_hours");
                let aors: Vec<&str> = b.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(aors, vec!["iphone"]); // ghost-phone は skip
            }
            other => panic!("expected Matched, got {:?}", other),
        }
    }

    /// from_number = "anonymous" (NGN 非通知) の rule マッチを検証。
    /// memory `project_ngn_inbound_caller_id_stripped`: carrier IMS が PAI を
    /// 剥がして From を anonymous@anonymous.invalid に書き換える挙動。
    #[test]
    fn from_number_matches_anonymous_for_stripped_caller_id() {
        let rules = RoutingRules {
            rules: vec![rule(
                "block_anonymous",
                300,
                MatchSpec {
                    weekday: None,
                    time_range: None,
                    from_number: Some(vec!["anonymous".to_string()]),
                },
                &[], // 非通知は voicemail 直行 (空 fork)
            )],
        };
        let bindings = mock_bindings(&["iphone"]);
        let decision = rules.evaluate(dt(2026, 5, 18, 10, 0), "anonymous", &bindings);
        match decision {
            RoutingDecision::Matched {
                rule_name,
                bindings: b,
            } => {
                assert_eq!(rule_name, "block_anonymous");
                assert!(b.is_empty());
            }
            other => panic!("expected Matched(block_anonymous), got {:?}", other),
        }
    }

    /// 同値 priority は宣言順を維持 (`sort_by` 安定ソート保証)。
    #[test]
    fn equal_priority_preserves_declaration_order() {
        let rules = RoutingRules {
            rules: vec![
                rule("first", 100, MatchSpec::default(), &["iphone"]),
                rule("second", 100, MatchSpec::default(), &["android"]),
            ],
        };
        let bindings = mock_bindings(&["iphone", "android"]);
        let decision = rules.evaluate(dt(2026, 5, 18, 10, 0), "0", &bindings);
        match decision {
            RoutingDecision::Matched { rule_name, .. } => {
                assert_eq!(rule_name, "first");
            }
            other => panic!("expected Matched(first), got {:?}", other),
        }
    }

    /// validate: 不正な time_range / weekday は起動時 fail-fast。
    #[test]
    fn validate_rejects_invalid_time_range_and_weekday() {
        let bad_time = RoutingRules {
            rules: vec![rule(
                "bad",
                0,
                MatchSpec {
                    weekday: None,
                    time_range: Some("25:00-26:00".to_string()),
                    from_number: None,
                },
                &[],
            )],
        };
        assert!(validate_rules(&bad_time).is_err());

        let bad_wd = RoutingRules {
            rules: vec![rule(
                "bad",
                0,
                MatchSpec {
                    weekday: Some(vec!["funday".to_string()]),
                    time_range: None,
                    from_number: None,
                },
                &[],
            )],
        };
        assert!(validate_rules(&bad_wd).is_err());

        let good = RoutingRules {
            rules: vec![rule(
                "good",
                0,
                MatchSpec {
                    weekday: Some(vec!["monday".to_string()]),
                    time_range: Some("09:00-18:00".to_string()),
                    from_number: None,
                },
                &[],
            )],
        };
        assert!(validate_rules(&good).is_ok());
    }

    /// 互換: now の hour に関わらず空 weekday 配列はパースエラーではなく
    /// 「無条件マッチ」 (= MatchSpec::default の Option::None と等価では
    /// ないので注意: 空 vec は「どの曜日にも該当しない」 とすべきか? 本実装は
    /// `any()` を使うので空 vec は **常に false** を返す = 当該 rule は
    /// 全曜日で unmatch する)。 これは "weekday = []" を書いた人の意図と
    /// 一致する (= "weekday 制限が空集合なら誰にもマッチしない")。
    #[test]
    fn empty_weekday_list_never_matches() {
        let rules = RoutingRules {
            rules: vec![rule(
                "empty_weekday",
                0,
                MatchSpec {
                    weekday: Some(vec![]),
                    time_range: None,
                    from_number: None,
                },
                &["iphone"],
            )],
        };
        let bindings = mock_bindings(&["iphone"]);
        let decision = rules.evaluate(dt(2026, 5, 18, 10, 0), "0", &bindings);
        assert!(decision.is_no_rule(), "expected NoRule, got {:?}", decision);
    }

    /// Timelike trait の sanity (本モジュールが now.time() を使うことの確認)。
    /// chrono の API contract が崩れていないか保険。
    #[test]
    fn chrono_time_components_match_expected() {
        let d = dt(2026, 5, 18, 10, 30);
        assert_eq!(d.hour(), 10);
        assert_eq!(d.minute(), 30);
        assert_eq!(d.weekday(), Weekday::Mon);
    }
}
