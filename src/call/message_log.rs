//! SMS (RFC 3428 MESSAGE) ring buffer — Issue #299.
//!
//! NGN / 内線 SIP UA から受信した MESSAGE 本文 (= IM / SMS short-message
//! body)、 および sabiden が送信した MESSAGE のメタデータを ring buffer に
//! 保持し、 `GET /api/sms/recent` (PWA UI の SMS タイムライン用) に供する。
//!
//! # RFC 3428 §2 (motivation)
//!
//! > "The Session Initiation Protocol (SIP) is an application layer protocol
//! >  for establishing, terminating, and modifying multimedia sessions."
//!
//! RFC 3428 §1 にあるとおり、 `MESSAGE` request は SIP の transport を借りた
//! pager-mode 即時メッセージング (= ダイアログを張らない単発リクエスト) で、
//! 戻り値の 200 OK は「**受領した**」ことの ack に過ぎず、 配送 / 表示の保証は
//! しない (RFC 3428 §4 / §7)。 したがって本 ring buffer は to-be-delivered
//! キューではなく、 既に受信 / 送信した messages の **観測ログ** として
//! 振る舞う (CallLog (Issue #278) と同じ責務)。
//!
//! # 設計方針
//!
//! - **Ring buffer**: `VecDeque<SmsMessage>` を `Mutex` でガードし、 `max_size`
//!   を超えたら古い方から `pop_front` で落とす (= `CallLog` と同じ pattern)。
//! - **direction**: 受信 (`Inbound`) / 送信 (`Outbound`) を区別。 PWA UI で
//!   タイムライン色分けに使う。
//! - **call_id 不要**: `MESSAGE` は dialog を作らない (RFC 3428 §4) ので、
//!   通話履歴のような突合 key は持たない。 各メッセージは独立。
//! - **同期 `std::sync::Mutex`**: write は秒数件以下の頻度なので contention 皆無。
//!   IO を含まないので tokio Mutex 不要。
//!
//! # シリアライズ
//!
//! `serde::Serialize` を実装して `GET /api/sms/recent` から JSON 出力する。
//! `SystemTime` は Unix epoch ms に変換 (CallLog と同じ)、 `body` は
//! UTF-8 String (本実装は `text/plain` のみ store する。 binary / CPIM は
//! 上位層で text にしてから push する想定; 失敗時は `[non-text body, N bytes]`
//! のような sentinel を入れる)。

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// SMS / MESSAGE の方向。
///
/// - [`Direction::Inbound`]: NGN / 内線 UA から sabiden が受信した MESSAGE。
/// - [`Direction::Outbound`]: sabiden が NGN / 内線へ送出した MESSAGE。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// 1 件の SMS 履歴。
///
/// RFC 3428 §7: MESSAGE は SIP dialog を張らない (`To-tag` を持たない) ので、
/// Call-ID は per-message でユニークだが「同一会話」を表す key にはならない。
/// PWA UI 側で同 (`from`, `to`) ペアを束ねて会話表示するならアプリ層で行う。
#[derive(Debug, Clone, Serialize)]
pub struct SmsMessage {
    pub direction: Direction,
    /// 発信元 SIP URI (例 `"sip:0312345678@ntt-east.ne.jp"`) または短縮表現。
    /// RFC 3428 §4: From header から抽出する。 sabiden 側で URI → display 形式
    /// 変換はしない (PWA 側の責務)。
    pub from: String,
    /// 宛先 SIP URI / 電話番号。 RFC 3428 §4: Request-URI または To header 由来。
    pub to: String,
    /// メッセージ本文 (UTF-8 text)。 RFC 3428 §10: `text/plain;charset=utf-8`
    /// が IETF 推奨の Content-Type。 sabiden は本ログには text body のみ
    /// 格納し、 非テキスト (`application/im-iscomposing+xml` 等) は上位で
    /// 判定し別経路 (= debug log) に流す想定 (`store` する callsite の責務)。
    pub body: String,
    /// 受信 / 送信時刻 (Unix epoch ms)。 JSON 出力では `timestamp_unix_ms`。
    #[serde(
        serialize_with = "serialize_system_time_ms",
        rename = "timestamp_unix_ms"
    )]
    pub timestamp: SystemTime,
}

impl SmsMessage {
    /// 新規 message entry を作る (timestamp は `SystemTime::now()`)。
    pub fn new_now(direction: Direction, from: String, to: String, body: String) -> Self {
        Self {
            direction,
            from,
            to,
            body,
            timestamp: SystemTime::now(),
        }
    }
}

/// Issue #299: 受信 SIP MESSAGE (`SipRequest`) から `SmsMessage` を抽出する。
///
/// # RFC 3428 §10 (Content-Type policy)
///
/// > "The default MIME type for a MESSAGE request is text/plain. ... A
/// >  receiver of a MESSAGE request SHOULD ... support text/plain;charset=utf-8."
///
/// 本実装は **`text/plain` で始まる Content-Type** (charset 修飾子の有無問わず)
/// のみ取り扱う。 それ以外 (`message/cpim`、 `application/im-iscomposing+xml`
/// 等) は `None` を返し、 呼出側で「body 破棄」 として 200 OK 受け流しに留める
/// (CPIM サポートは別 Issue で拡張する)。
///
/// UTF-8 で復号できない body も `None` (production code で panic 禁止、
/// CLAUDE.md §6.5)。
///
/// `from` / `to` は SIP From / To ヘッダの **raw 文字列** をそのまま入れる。
/// 表示名 / URI 分離は PWA 側の責務 (本 ring buffer は観測ログ責務)。
pub fn sms_from_inbound_message(req: &crate::sip::message::SipRequest) -> Option<SmsMessage> {
    let ct = req
        .headers
        .get("content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    if !ct.starts_with("text/plain") {
        return None;
    }
    let body = std::str::from_utf8(&req.body).ok()?.to_string();
    let from = req.headers.get("from").unwrap_or("").to_string();
    let to = req.headers.get("to").unwrap_or("").to_string();
    Some(SmsMessage::new_now(Direction::Inbound, from, to, body))
}

/// `SystemTime` を Unix epoch ms (u64) にして serialize する (CallLog と同様)。
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

/// SMS 履歴 ring buffer。
///
/// `max_size` を超えたら古い方から `pop_front`。 `len` / `recent` 提供。
/// `Arc<MessageLog>` で各 handler に渡す。 [`CallLog`](super::super::observability::call_log::CallLog)
/// の SMS 版で API 設計を揃えてある。
#[derive(Debug)]
pub struct MessageLog {
    entries: Mutex<VecDeque<SmsMessage>>,
    max_size: usize,
}

impl MessageLog {
    /// 指定容量で ring buffer を作る。 `max_size == 0` のとき全て evict (= 無効)。
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_size.min(1024))),
            max_size,
        }
    }

    /// 1 件 push する。 `max_size` 超過は `pop_front` で揃える。
    ///
    /// `record_start` / `record_end` を分ける CallLog と違い、 MESSAGE は単発
    /// (RFC 3428 §7: dialog を作らない) なので push 1 回で完結する。
    ///
    /// PoisonError は `into_inner` で握って best-effort で書き込む
    /// (CallLog と同じ方針、 CLAUDE.md §6.5 で panic/unwrap 禁止)。
    pub fn push(&self, msg: SmsMessage) {
        if self.max_size == 0 {
            return;
        }
        let mut entries = match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        entries.push_back(msg);
        while entries.len() > self.max_size {
            entries.pop_front();
        }
    }

    /// 最新 `n` 件を新しい順 (= 末尾から) で返す。
    pub fn recent(&self, n: usize) -> Vec<SmsMessage> {
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

    /// 現在の保有件数。
    pub fn len(&self) -> usize {
        match self.entries.lock() {
            Ok(g) => g.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// 空か判定する。 ring buffer のセマンティクス上 `len() == 0` と同義。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3428 §7 と CallLog (Issue #278) と同じく、 push 順序が保たれ recent は
    /// 新しい順で返ること。
    #[test]
    fn rfc3428_push_then_recent_returns_newest_first() {
        let log = MessageLog::new(10);
        log.push(SmsMessage::new_now(
            Direction::Inbound,
            "sip:alice@example.test".into(),
            "sip:bob@example.test".into(),
            "hello".into(),
        ));
        log.push(SmsMessage::new_now(
            Direction::Outbound,
            "sip:bob@example.test".into(),
            "sip:alice@example.test".into(),
            "world".into(),
        ));
        let r = log.recent(10);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].body, "world", "最新が先頭");
        assert_eq!(r[0].direction, Direction::Outbound);
        assert_eq!(r[1].body, "hello");
        assert_eq!(r[1].direction, Direction::Inbound);
    }

    /// `max_size` を超えたら古いものが捨てられる (= ring buffer 振る舞い)。
    #[test]
    fn ring_buffer_evicts_oldest_when_over_max_size() {
        let log = MessageLog::new(3);
        for i in 0..5 {
            log.push(SmsMessage::new_now(
                Direction::Inbound,
                "sip:from@x".into(),
                "sip:to@x".into(),
                format!("m{i}"),
            ));
        }
        assert_eq!(log.len(), 3);
        let r = log.recent(10);
        // 最新 3 件: m4 m3 m2 (m0 m1 は evict)。
        assert_eq!(
            r.iter().map(|m| m.body.as_str()).collect::<Vec<_>>(),
            vec!["m4", "m3", "m2"]
        );
    }

    /// `max_size = 0` は no-op (全 push が捨てられる)。
    #[test]
    fn max_size_zero_disables_buffer() {
        let log = MessageLog::new(0);
        log.push(SmsMessage::new_now(
            Direction::Inbound,
            "sip:from@x".into(),
            "sip:to@x".into(),
            "x".into(),
        ));
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
    }

    /// `recent(0)` は空 Vec (CallLog と同じ semantics)。
    #[test]
    fn recent_zero_returns_empty() {
        let log = MessageLog::new(10);
        log.push(SmsMessage::new_now(
            Direction::Inbound,
            "sip:from@x".into(),
            "sip:to@x".into(),
            "x".into(),
        ));
        assert!(log.recent(0).is_empty());
    }

    /// `recent(n)` の `n` がバッファ長を超えても panic せず全件返す。
    #[test]
    fn recent_n_larger_than_buffer_returns_all() {
        let log = MessageLog::new(10);
        log.push(SmsMessage::new_now(
            Direction::Outbound,
            "sip:from@x".into(),
            "sip:to@x".into(),
            "only".into(),
        ));
        let r = log.recent(100);
        assert_eq!(r.len(), 1);
    }

    /// JSON serialize が `direction` lowercase / `timestamp_unix_ms` u64 を含む。
    #[test]
    fn serializes_with_lowercase_direction_and_unix_ms() {
        let msg = SmsMessage::new_now(
            Direction::Inbound,
            "sip:a@x".into(),
            "sip:b@x".into(),
            "hi".into(),
        );
        let j = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(j["direction"], "inbound");
        assert_eq!(j["from"], "sip:a@x");
        assert_eq!(j["to"], "sip:b@x");
        assert_eq!(j["body"], "hi");
        assert!(j["timestamp_unix_ms"].is_u64());
    }
}
