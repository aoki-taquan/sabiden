//! 通話履歴 (in-memory ring buffer) — Issue #278.
//!
//! NGN 着信 / NGN 発信 / PWA 発信 の 3 経路で発生した通話の開始時刻・通話時間・
//! 結果を [`CallLog`] に集約し、 PWA の「最近の通話」 UI で利用可能な JSON API
//! (`GET /api/call-log/recent`) として公開する。 永続化 (sqlite 化) は別 issue。
//!
//! # 設計方針
//!
//! - **Ring buffer**: `VecDeque<CallLogEntry>` を `Mutex` でガードし、 `max_size`
//!   を超えたら古い方から落とす (= `pop_front`)。 メモリ上限を確定値で押さえる
//!   ことで運用中の RSS 暴走を防ぐ。
//! - **call_id を一意 key にする**: `record_start` で in-place エントリを作り、
//!   `record_end` は同じ `call_id` を線形検索して `duration` と `outcome` を
//!   書き込む。 ring buffer から既に追い出された場合は no-op (古い通話の cleanup
//!   が遅延しても再エントリを作らない)。 RFC 3261 §8.1.1.4 によれば Call-ID は
//!   per-dialog で globally unique なので key としては十分。
//! - **Mutex 一本**: `std::sync::Mutex` を使い hot path にも乗せられる粒度に保つ
//!   (現状の write は通話開始/終了の数ヘルツ程度で contention は皆無)。 async
//!   ロックは不要 (CallLogEntry 構築は IO を含まない)。
//! - **クローン伝搬は `Arc<CallLog>`**: `Metrics` と同じく Arc 共有で各 handler に
//!   渡す。 トランスポート層は触らない。
//!
//! # 経路の hook 規約 (`src/call/orchestrator.rs` 側)
//!
//! - `record_start(Direction, remote, call_id)` は **INVITE 送出時 or 受信時の
//!   最初** に呼ぶ (= 通話試行の出現時刻を残す)。
//! - `record_end(call_id, Outcome)` は以下のいずれかに呼ぶ:
//!   - 200 OK 確立後の BYE 受信 / 送出 → [`Outcome::Answered`] (`duration` 計算)
//!   - 非 2xx 最終応答 (4xx / 5xx / timeout) → [`Outcome::Failed`] / [`Outcome::Cancelled`]
//!   - 着信が応答前に終了 (CANCEL / timeout) → [`Outcome::Missed`]
//!
//! # シリアライズ
//!
//! `serde::Serialize` を実装して `GET /api/call-log/recent` から JSON 出力する。
//! `SystemTime` は Unix epoch ms に変換する (`as_unix_ms()`)、 `Duration` は秒
//! (`as_secs_f64()`) で公開する。 PWA 側 (React) で `Date` / `Number` に
//! そのまま渡せる形にしておく。

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// 通話の方向。
///
/// - [`Direction::Outbound`]: sabiden → NGN への発信 (内線→NGN / PWA→NGN)
/// - [`Direction::Inbound`]: NGN → sabiden への着信 (NGN→内線 / NGN→PWA)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Outbound,
    Inbound,
}

/// 通話結果。
///
/// `Failed(u16)` は最終応答 status code (例 486 / 500 / 503 等) を保持し、 PWA UI
/// 側で「相手話中」「NGN 一時障害」を区別表示できるようにする (RFC 3261 §21)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Outcome {
    /// 200 OK で確立した通話 (`duration` が有効値)。
    Answered,
    /// 着信側が応答せずに終了した (CANCEL / timeout / 487 Request Terminated)。
    Missed,
    /// 非 2xx 最終応答で確立できなかった (status code を保持)。
    Failed {
        /// SIP 最終応答 status code (RFC 3261 §21)。
        status: u16,
    },
    /// 発信側が応答前に CANCEL した。
    Cancelled,
}

/// 1 件の通話履歴。
///
/// `call_id` は SIP Call-ID (RFC 3261 §8.1.1.4) で、 同一通話の `record_start` /
/// `record_end` を突合するための key として利用する。
#[derive(Debug, Clone, Serialize)]
pub struct CallLogEntry {
    pub direction: Direction,
    pub remote_number: String,
    /// 通話開始時刻 (Unix epoch ms)。 JSON 出力では `start_unix_ms` フィールド。
    #[serde(serialize_with = "serialize_system_time_ms", rename = "start_unix_ms")]
    pub start_time: SystemTime,
    /// 通話時間 (秒)。 `Outcome::Answered` の場合のみ Some。
    #[serde(serialize_with = "serialize_duration_secs", rename = "duration_secs")]
    pub duration: Option<Duration>,
    pub outcome: Option<Outcome>,
    pub call_id: String,
}

impl CallLogEntry {
    /// `record_start` 時点の暫定エントリを作る (outcome / duration は未確定)。
    fn new_started(direction: Direction, remote_number: String, call_id: String) -> Self {
        Self {
            direction,
            remote_number,
            start_time: SystemTime::now(),
            duration: None,
            outcome: None,
            call_id,
        }
    }
}

/// `SystemTime` を Unix epoch ms (u64) に変換して serialize する。
///
/// 1970 年以前の値 (= `duration_since(UNIX_EPOCH)` が Err) は 0 にフォールバックする。
fn serialize_system_time_ms<S>(t: &SystemTime, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let ms = t
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    ser.serialize_u64(ms)
}

/// `Option<Duration>` を `Option<f64>` (秒) に変換して serialize する。
fn serialize_duration_secs<S>(d: &Option<Duration>, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match d {
        Some(d) => ser.serialize_some(&d.as_secs_f64()),
        None => ser.serialize_none(),
    }
}

/// 通話履歴 ring buffer。
///
/// `max_size` を超えたら古い方から落とす (FIFO)。 `record_end` は ring buffer 内
/// の `call_id` を線形検索するため、 size = O(100) 程度で運用する想定。 サイズが
/// 大きくなる場合 (例 10000+) は別途 `HashMap<call_id, index>` を併設すること。
#[derive(Debug)]
pub struct CallLog {
    entries: Mutex<VecDeque<CallLogEntry>>,
    max_size: usize,
}

impl CallLog {
    /// 指定された ring buffer 容量で `CallLog` を作る。
    ///
    /// `max_size` が 0 のとき: 全エントリが即 evict される (= ring buffer 無効)。
    /// production では 100 件程度を想定。
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_size.min(1024))),
            max_size,
        }
    }

    /// 通話試行の開始を記録する。
    ///
    /// 既に同じ `call_id` の entry がある場合は **新規に追加しない** (重複防止)。
    /// 通常は INVITE 受信時 / 送出時に 1 回だけ呼ばれる前提だが、 リトライ経路
    /// (Issue #260 Phase 1-B 等) で多重 record_start が来ても old entry を保つ。
    pub fn record_start(&self, direction: Direction, remote_number: String, call_id: String) {
        let mut entries = match self.entries.lock() {
            Ok(g) => g,
            // PoisonError: 他スレッドが panic した状態でも履歴は best-effort で
            // 受け付けたい。 lock を回復して書き込みを続行する。 production code
            // で panic/unwrap 禁止 (CLAUDE.md §6.5) を踏まえ、 `.into_inner()`
            // で内部を取り出す。
            Err(poisoned) => poisoned.into_inner(),
        };
        if entries.iter().any(|e| e.call_id == call_id) {
            return;
        }
        if self.max_size == 0 {
            return;
        }
        entries.push_back(CallLogEntry::new_started(direction, remote_number, call_id));
        while entries.len() > self.max_size {
            entries.pop_front();
        }
    }

    /// 通話の終了を記録する。
    ///
    /// `call_id` に該当する entry が ring buffer に残っていれば `outcome` と
    /// `duration` を埋める。 既に evict 済 / そもそも `record_start` を通って
    /// いない場合は no-op (= 黙って捨てる、 これにより 481 / 491 等 sabiden 側で
    /// 履歴を残したくない経路は record_start を呼ばないだけで除外できる)。
    pub fn record_end(&self, call_id: &str, outcome: Outcome) {
        let mut entries = match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // 最新通話 (= 末尾) から逆向きに線形検索: 同 Call-ID の二重発火が来ても
        // 最近の entry を更新する。 Call-ID は本来 unique (RFC 3261 §8.1.1.4) なので
        // 競合は起きないが、 e2e test での fixture 再利用に強くしておく。
        let now = SystemTime::now();
        for entry in entries.iter_mut().rev() {
            if entry.call_id == call_id {
                if entry.outcome.is_none() {
                    // start_time → now の差分を duration として確定。
                    // Answered 以外でも経過時間自体は有用 (例 Missed まで何秒鳴ったか)。
                    entry.duration = now.duration_since(entry.start_time).ok();
                }
                entry.outcome = Some(outcome);
                return;
            }
        }
    }

    /// 最新 `n` 件を新しい順に返す。
    ///
    /// `n` が ring buffer 長を超える場合は全件を返す。 `n == 0` の場合は空 Vec。
    pub fn recent(&self, n: usize) -> Vec<CallLogEntry> {
        if n == 0 {
            return Vec::new();
        }
        let entries = match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let take = n.min(entries.len());
        entries.iter().rev().take(take).cloned().collect()
    }

    /// ring buffer の現在保有件数。
    pub fn len(&self) -> usize {
        match self.entries.lock() {
            Ok(g) => g.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// 内部 ring buffer が空かどうか。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    /// 通話開始 → 終了の素直なフロー: outcome / duration が確定し、 recent に出る。
    #[test]
    fn record_start_then_end_sets_outcome_and_duration() {
        let log = CallLog::new(8);
        log.record_start(Direction::Outbound, "117".into(), "cid-1".into());
        thread::sleep(StdDuration::from_millis(10));
        log.record_end("cid-1", Outcome::Answered);

        let recent = log.recent(10);
        assert_eq!(recent.len(), 1);
        let entry = &recent[0];
        assert_eq!(entry.direction, Direction::Outbound);
        assert_eq!(entry.remote_number, "117");
        assert_eq!(entry.call_id, "cid-1");
        assert!(matches!(entry.outcome, Some(Outcome::Answered)));
        let d = entry
            .duration
            .expect("duration must be set after record_end");
        assert!(d >= StdDuration::from_millis(5));
    }

    /// ring buffer 上限超過: 古い順に evict される (FIFO)。
    #[test]
    fn ring_buffer_overflow_evicts_oldest() {
        let log = CallLog::new(3);
        for i in 0..5 {
            log.record_start(
                Direction::Inbound,
                format!("0312345{:03}", i),
                format!("cid-{}", i),
            );
        }
        // 5 件投入 → 古い 2 件は脱落、 cid-2 / cid-3 / cid-4 が残る。
        assert_eq!(log.len(), 3);
        let recent = log.recent(10);
        let ids: Vec<&str> = recent.iter().map(|e| e.call_id.as_str()).collect();
        // recent() は新しい順なので [cid-4, cid-3, cid-2]
        assert_eq!(ids, vec!["cid-4", "cid-3", "cid-2"]);
    }

    /// `record_end` だけが呼ばれて record_start が無い場合は no-op。
    /// 既に ring buffer から evict された通話に対しても同様。
    #[test]
    fn record_end_without_start_is_noop() {
        let log = CallLog::new(4);
        log.record_end("nonexistent", Outcome::Answered);
        assert!(log.is_empty());
    }

    /// `recent(n)` が ring buffer 長より大きくても panic せず全件を返す。
    /// `recent(0)` は空。
    #[test]
    fn recent_boundary_cases() {
        let log = CallLog::new(4);
        log.record_start(Direction::Outbound, "117".into(), "cid-a".into());
        log.record_start(Direction::Inbound, "0312345678".into(), "cid-b".into());

        let all = log.recent(100);
        assert_eq!(all.len(), 2);

        let none = log.recent(0);
        assert!(none.is_empty());
    }

    /// `Outcome::Failed { status }` は status code を保持し、 JSON に序列化される。
    #[test]
    fn outcome_failed_serializes_with_status() {
        let log = CallLog::new(2);
        log.record_start(Direction::Outbound, "0501234567".into(), "cid-x".into());
        log.record_end("cid-x", Outcome::Failed { status: 486 });

        let recent = log.recent(1);
        assert_eq!(recent.len(), 1);
        let json = serde_json::to_string(&recent[0]).expect("serialize");
        // serde tag = "kind" + status フィールドが入る
        assert!(json.contains("\"kind\":\"failed\""), "got: {json}");
        assert!(json.contains("\"status\":486"), "got: {json}");
        // direction / remote_number / call_id も入る
        assert!(json.contains("\"direction\":\"outbound\""));
        assert!(json.contains("\"remote_number\":\"0501234567\""));
        assert!(json.contains("\"call_id\":\"cid-x\""));
        // start_unix_ms (リネーム済) と duration_secs キー
        assert!(json.contains("\"start_unix_ms\""));
        assert!(json.contains("\"duration_secs\""));
    }

    /// 同 call_id の重複 `record_start` は無視され、 元 entry が保たれる。
    #[test]
    fn duplicate_record_start_is_ignored() {
        let log = CallLog::new(4);
        log.record_start(Direction::Outbound, "117".into(), "cid-dup".into());
        // 2 回目は無視されるべき (= entry 数 1、 remote_number 上書きされない)。
        log.record_start(Direction::Outbound, "INVALID".into(), "cid-dup".into());

        let recent = log.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].remote_number, "117");
    }

    /// `max_size == 0` の境界: 全エントリ即 drop されるが panic しない。
    #[test]
    fn zero_capacity_disables_logging() {
        let log = CallLog::new(0);
        log.record_start(Direction::Inbound, "x".into(), "cid-zero".into());
        log.record_end("cid-zero", Outcome::Missed);
        assert!(log.is_empty());
        assert!(log.recent(5).is_empty());
    }

    /// `Outcome::Missed` / `Cancelled` も duration が確定する (Answered 限定でない)。
    #[test]
    fn missed_outcome_still_sets_duration() {
        let log = CallLog::new(2);
        log.record_start(Direction::Inbound, "0312345678".into(), "cid-miss".into());
        thread::sleep(StdDuration::from_millis(5));
        log.record_end("cid-miss", Outcome::Missed);

        let recent = log.recent(1);
        assert_eq!(recent.len(), 1);
        assert!(matches!(recent[0].outcome, Some(Outcome::Missed)));
        assert!(recent[0].duration.is_some());
    }
}
