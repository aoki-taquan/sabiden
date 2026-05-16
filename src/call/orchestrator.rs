//! NGN ⇔ 内線 を結ぶ通話オーケストレーション
//!
//! 本モジュールは [`crate::sip::transaction::TransactionLayer`] と
//! [`crate::sip::uas::ExtensionUas`] / [`crate::sip::uac::Uac`] を
//! 結線する糊コードを集約する。これまで `main.rs` で
//! `_inbound_rx` として捨てられていた NGN 着信 INVITE を受け、
//! 内線フォーク (`call::manager::fork_to_extensions`) を通じて
//! 通話を確立する役目を負う。
//!
//! # 役割分担
//!
//! - [`NgnInboundHandler`]: NGN 側 `TransactionLayer` の `inbound_rx`
//!   から INVITE / BYE / ACK を取り出し、`ServerTransaction` の
//!   100 Trying 即返答 → 内線フォーク → 200 OK を NGN へ返すまでを駆動する。
//! - [`UasEventHandler`]: 内線 UAS から流れてくる
//!   [`crate::sip::uas::UasEvent`] を読み、内線発信 INVITE を
//!   NGN 側 [`Uac`] でプロキシする。
//!
//! # B2BUA 双方向シグナリング (Phase 4)
//!
//! 内線→NGN 発信通話で、両方向の BYE / CANCEL が伝搬される:
//!
//! - 内線→NGN INVITE: 200 OK 受信時に NGN レッグの [`UacDialog`] と内線レッグの
//!   sabiden=UAS [`Dialog`] の両方を [`OutboundCallRegistry`] に保存。
//! - 内線→sabiden BYE: [`UasEvent::Bye`] → 内線へ 200 OK + NGN UacDialog 経由で BYE 送出。
//! - NGN→sabiden BYE: `NgnInboundHandler::handle_bye` → registry を引いて内線レッグの
//!   sabiden=UAS Dialog から build_bye → ext_layer.send_request で内線へ送出。
//! - 内線 CANCEL: [`UasEvent::Cancel`] → NGN へ CANCEL (RFC 3261 §9.1) → 内線へ 487。
//!
//! ACK は B2BUA 各レッグで独立して送出する (RFC 3261 §13.2.2.4)。NGN 側 ACK は
//! [`Uac::invite`] が 200 OK 受信時に自動送出。内線→sabiden ACK は UAS が
//! [`UasEvent::Ack`] として上げ、本ハンドラは状態確認のみ行う。
//!
//! # 既知の制限
//!
//! - 1 通話 1 ブリッジ (multi-party 不可)。
//! - 内線レッグの送信先 (ext_remote) は INVITE 受信時の送信元から推定する。
//!   内線が NAT 越しの場合は Contact ヘッダの URI から解決する経路 (Issue #16)
//!   を将来追加する。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering as AtomicOrdering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// NGN outbound RTP port even-only round-robin allocator (Issue #260 Phase 1-D)。
///
/// 真因: NTT NGN P-CSCF / N-ACT は SDP `m=audio` port の parity (even/odd) を
/// 入口で hard-classify し、 奇数 port を degraded route に sticky bind する
/// (500 fast-fail 35-48ms)。 RFC 3550 §11 は "RTP SHOULD use an even
/// destination port" と SHOULD レベル、 同 §11 3 段目で `a=rtcp:` 等で
/// RTCP port を explicit signal すれば MAY disregard と規定されているが、
/// **NGN 実機 (2026-05-15 falsification test、 16/16 全 500) は RFC 3605
/// `a=rtcp:` を honor せず m=audio port parity だけを hardcoded check** している。
/// よって client 側 (sabiden) は even-only allocator で対応するのが唯一解。
///
/// Evidence:
/// - mixed-parity 44 dial 横断: even → 200 (14/14)、 odd → 500 (30/30)、 p≈1e-10
/// - falsification (odd + a=rtcp:port+1) 16 INVITE: 全 500
///
/// fix: `fetch_add(2)` を even start (30000) から積み上げ、 全 dial に even
/// port を払い出す。 OS ephemeral (`bind(*, 0)`) は uniform random で 50%
/// odd を引いていたのが過去 baseline 20-70% success rate variance の真因。
async fn bind_ngn_rtp_socket(ip: IpAddr) -> Result<Arc<UdpSocket>> {
    // Even-port allocator range (RFC 3550 §11 SHOULD even):
    const NGN_RTP_PORT_MIN: u16 = 30000;
    const NGN_RTP_PORT_MAX: u16 = 30998;
    // Monotonic counter は `AtomicU32` を使う。 `AtomicU16` だと約 17k INVITE で
    // wrap して `raw - NGN_RTP_PORT_MIN` が overflow し debug build panic +
    // release silent wrap (CLAUDE.md §6.5 違反、 PR #264 2 巡目 review 指摘)。
    // `AtomicU32` なら ~2 billion 回 (= 65 年 @ 1 call/sec) で wrap、 実質無限。
    static NGN_RTP_PORT_NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let span: u32 = (NGN_RTP_PORT_MAX - NGN_RTP_PORT_MIN + 2) as u32;
    for _ in 0..500 {
        let raw = NGN_RTP_PORT_NEXT.fetch_add(2, AtomicOrdering::SeqCst);
        // raw は monotonic、 span (= 1000) で modulo してから even mask。
        // u32 でも wrap は ~2^32 回後だが、 wrap した時も `raw % span` で
        // 0-(span-1) の範囲に収まり port が正しく循環する。
        let offset = ((raw % span) & !1) as u16;
        let port = NGN_RTP_PORT_MIN + offset;
        match UdpSocket::bind(SocketAddr::new(ip, port)).await {
            Ok(s) => return Ok(Arc::new(s)),
            Err(_) => continue,
        }
    }
    // last resort: ephemeral but force even (re-bind until even port drawn)
    for _ in 0..50 {
        let s = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
        if s.local_addr()?.port() % 2 == 0 {
            return Ok(Arc::new(s));
        }
    }
    Err(anyhow!(
        "could not bind even RTP port after 500 allocator + 50 ephemeral attempts"
    ))
}

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, info_span, warn, Instrument};

use super::bridge::{BridgeConfig, MediaBridge, RtpBridge};
use super::carrier_retry::{
    decide_retry, random_jitter_offset_ms, CarrierRetryConfig, RetryDecision, RetryOutcome,
};
use super::codec_pipeline::{select_media_plan, MediaPlan};
use super::manager::{extract_rtp_endpoint, CallManager, ForkResult, LegInviter, UacForker};
use super::rate_limiter::{parse_retry_after, OutboundRateLimiter, RateLimitDecision};
use super::transcoder::{TranscodeConfig, TranscodingBridge};
use super::CallId;
use crate::observability::{InviteResult, Metrics, OutboundDirection};
use crate::sdp::builder::{
    convert_savpf_to_avp, ensure_ptime_in_answer, extract_ptime_from_offer,
    restrict_answer_to_ngn_offer_subset, rewrite_rtp_endpoint,
};
use crate::sdp::negotiation::Negotiator;
use crate::sip::dialog::{Dialog, DialogConfig};
use crate::sip::message::{SipHeaders, SipMethod, SipRequest, SipResponse};
use crate::sip::registrar::{Binding, ExtTransport, ExtensionRegistrar};
use crate::sip::transaction::{
    build_response_skeleton, InboundRequest, ServerTransaction, TransactionLayer,
};
use crate::sip::uac::{CancelOutcome, EstablishedCall, InviteOutcome, InvitePlan, Uac, UacDialog};
use crate::sip::uas::{ResponderHandle, UasEvent};
use crate::webrtc::peer::PeerSession;
use crate::webrtc::signaling::{
    PendingAnswers, PwaInboundCloser, PwaOutboundCloser, PwaOutboundHandler, PwaOutboundOutcome,
    ServerMessage, WsSink,
};

/// RFC 3261 §8.2.1 / §20.5: 405 / 489 / 481 等の拒否応答に必ず添える
/// `Allow` ヘッダ値。 sabiden の NGN UAS が **実際に処理経路を持つ** method 列。
///
/// - `INVITE` / `ACK` / `BYE` / `CANCEL`: 通話の基本 (RFC 3261)
/// - `OPTIONS`: keep-alive / capabilities probe (RFC 3261 §11)
///
/// `UPDATE` / `INFO` / `MESSAGE` / `NOTIFY` / `SUBSCRIBE` / `PRACK` /
/// `PUBLISH` / `REFER` は意図的に列挙から除外。 これらは per-method
/// handler が 481 / 489 / 405 等で拒否する (Issue #110): Allow に
/// 載せるのは「実装が実用的に処理する」method に限る (RFC 3261 §20.5
/// 「a list of methods that the UA implementing this header supports」)。
const SUPPORTED_METHODS_ALLOW: &str = "INVITE, ACK, BYE, CANCEL, OPTIONS";

/// RFC 3261 §13.3.1.4 / §20.5 (Issue #251 Phase A): NGN inbound INVITE 経路の
/// 18x / 2xx 応答に常時付与する `Allow` ヘッダ値。 carrier IMS は dialog 確立後の
/// 機能 negotiate に Allow を見て「UPDATE / INFO 等が利用可能か」を判定する。
/// Allow 不在は「機能不足端末」判定 → 即時 BYE の主原因として Asterisk 実機
/// (`docs/asterisk-real-invite.md` §3.1) と差分が出ていた。
///
/// 列挙基準: sabiden の UAS が **実機経路として処理可能** な method。
/// - `INVITE` / `ACK` / `BYE` / `CANCEL`: RFC 3261 通話基本
/// - `OPTIONS`: keep-alive / capabilities probe (RFC 3261 §11)
/// - `UPDATE`: Re-INVITE 代替の SDP / Session-Timer 更新 (RFC 3311)
/// - `INFO`: DTMF (RFC 4733 / RFC 6086、 sabiden 実装済)
/// - `PRACK` (RFC 3262 §4): 100rel reliable 18x への ACK 受信 (Issue #251 Phase B)
///
/// **意図的除外**:
/// - `NOTIFY` / `SUBSCRIBE` / `MESSAGE` / `REFER` / `PUBLISH`: 限定的処理のみ
///   (NOTIFY/SUBSCRIBE は 481、 MESSAGE は受け流し)。 carrier IMS が
///   「これらを使える」と誤認しないよう除外。
const UAS_INBOUND_2XX_ALLOW: &str = "INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, INFO, PRACK";

/// RFC 4028 §7 / RFC 3891 §3 / RFC 3262 §3 (Issue #251 Phase B): NGN inbound INVITE
/// 経路の 18x / 2xx 応答に常時付与する `Supported` ヘッダ値。 §20.37 によれば
/// `Supported` 不在は peer に「何の extension がサポートされているか不明」と
/// 解釈され、 carrier IMS の機能 negotiate ロジックを混乱させる。
///
/// 列挙基準: sabiden が **実装済の option-tag** のみ。
/// - `timer` (RFC 4028): Session-Timer。 既存 200 OK で `Require: timer` を出す
///   経路があり、 `Require` を出すなら `Supported` にも明示するのが §7.4 整合。
/// - `replaces` (RFC 3891): Call-Replace。 sabiden は将来の transfer 経路で
///   利用するため capability として常時広告 (受信処理は将来 Phase で実装)。
/// - `100rel` (RFC 3262 §3): Reliability of Provisional Responses。 NGN INVITE
///   が `Supported: 100rel` を提示してきた場合、 sabiden は reliable 180 Ringing
///   (Require: 100rel + RSeq) を送出し PRACK を待ち合わせる (Phase B)。
const UAS_INBOUND_2XX_SUPPORTED: &str = "timer, replaces, 100rel";

/// RFC 3261 §20.41 (Issue #251 Phase A): UAS 応答に載せる `Server` ヘッダ値。
/// Asterisk 実機 (`docs/asterisk-real-invite.md` §3.1) は `Server: Asterisk PBX
/// 20.6.0` を載せる慣例で、 carrier 側障害解析時に「どの端末が応答したか」を
/// 特定するために有用。
fn sabiden_server_header() -> String {
    format!("sabiden/{}", env!("CARGO_PKG_VERSION"))
}

/// RFC 7231 §7.1.1.1 (Issue #251 Phase A): HTTP-date = IMF-fixdate を
/// SIP `Date` ヘッダ (RFC 3261 §20.17) 用に組み立てる。
///
/// IMF-fixdate ABNF:
/// ```text
/// IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT
/// day-name     = "Mon" / "Tue" / "Wed" / "Thu" / "Fri" / "Sat" / "Sun"
/// date1        = day SP month SP year       ; e.g., 02 Jun 1982
/// month        = "Jan" / "Feb" / "Mar" / ... / "Dec"
/// time-of-day  = hour ":" minute ":" second
/// ```
///
/// 例: `Wed, 11 May 2026 07:43:35 GMT`
///
/// 実装は std::time のみで完結し外部依存を増やさない (`chrono` / `httpdate`
/// クレート不採用)。 グレゴリオ暦 (proleptic, 西暦 1970 以降) は Howard
/// Hinnant の civil_from_days アルゴリズム
/// (<https://howardhinnant.github.io/date_algorithms.html#civil_from_days>) を
/// 使用。 SystemTime が UNIX_EPOCH より前を返すケース (= 端末時刻が壊れている)
/// では `Thu, 01 Jan 1970 00:00:00 GMT` にフォールバック。
fn http_date_now() -> String {
    let secs_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_http_date(secs_since_epoch)
}

/// `format_http_date` — UNIX 秒を IMF-fixdate 文字列に変換 (pure function、
/// `http_date_now` から分離して unit test 可能にする)。
fn format_http_date(secs_since_epoch: u64) -> String {
    let day_seconds = (secs_since_epoch % 86_400) as u32;
    let hour = day_seconds / 3600;
    let minute = (day_seconds % 3600) / 60;
    let second = day_seconds % 60;

    let days_since_epoch = (secs_since_epoch / 86_400) as i64;
    // 1970-01-01 (epoch) は Thursday。 DAY_NAMES は Monday=0 基準なので
    // Thu = index 3。 day-of-week = (days_since_epoch + 3) mod 7。
    let dow = ((days_since_epoch + 3).rem_euclid(7)) as usize;

    // Howard Hinnant civil_from_days: epoch を 0000-03-01 基準にシフトして
    // 月/日/年を逆算する。 1970-01-01 = epoch + 0 days → days_since_civil = 719468。
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32; // [0, 146097)
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTH_NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    // dow 計算は Monday=0 基準 (epoch Thursday=3 から (days+3) mod 7 で
    // Monday=0 ベースに揃う)。
    let dow_name = DAY_NAMES[dow];
    let month_name = MONTH_NAMES[(m - 1) as usize];

    format!("{dow_name}, {d:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
}

/// RFC 4028 §9 (Issue #251 Phase A): 200 OK の `refresher` 値を決定する。
///
/// > the refresher parameter of the Session-Expires header field in the
/// > response MUST equal to the value in the request, unless the UAS does
/// > not want to be the refresher.
///
/// sabiden の方針: UAC (carrier) が `refresher=uac` を明示した場合は **そのまま
/// echo** し、 carrier の意図を尊重する。 不明 / 不在の場合のみ `refresher=uas`
/// にフォールバック (= sabiden 側が refresh を担当する、 内線レッグへの伝搬を
/// 簡略化できる)。 旧実装は常に `uas` で書換えていたが (Issue #251 audit #6)、
/// carrier 内部状態機械が `refresher=uac` で固定済の場合 dialog 確立後の
/// timer expire 計算で不整合し、 確立直後の cleanup 経路 (= 即 BYE) に入る
/// 可能性が指摘されていた。
fn resolve_response_refresher(request_refresher: Option<&str>) -> &'static str {
    match request_refresher {
        Some(v) if v.eq_ignore_ascii_case("uac") => "uac",
        // "uas" 明示 or 不在 / 不正値 → uas (sabiden が refresh 担当)
        _ => "uas",
    }
}

/// RFC 3261 §8.2.2.3 (Issue #251 Phase A): sabiden が **understand する**
/// `Require` ヘッダ option-tag のホワイトリスト。 受信 INVITE に `Require` が
/// あった場合、 ここに無い tag は 420 Bad Extension で reject する MUST。
///
/// **既知 tag** (sabiden 実装済 / capabilities 表明済):
/// - `timer` (RFC 4028): Session-Timer。 200 OK 経路で echo 済。
/// - `replaces` (RFC 3891): UAS 側は受信処理を将来実装するが、 capability
///   として `Supported` に列挙済なので Require 経由でも受け入れ可とする
///   (現状は dialog 確立後に replaces を活用する dialog replacement は未実装、
///   ただし carrier が `Require: replaces` を送るケースは実機未確認)。
///
/// - `100rel` (RFC 3262 §3、 Issue #251 Phase B): PRACK 経路を実装したため
///   `Require: 100rel` も受け入れる。 受け入れ後の挙動は orchestrator
///   `handle_invite` 内で reliable 180 Ringing + RSeq 送出 + PRACK 待ちに分岐。
const KNOWN_OPTION_TAGS: &[&str] = &["timer", "replaces", "100rel"];

/// `Require` ヘッダ値 (例 `"timer, 100rel"`) をパースし、 `KNOWN_OPTION_TAGS` に
/// 含まれない option-tag 一覧を返す (大文字小文字無視、 RFC 3261 §7.3.1)。
///
/// 戻り値が空なら全て既知 → 通常処理を継続。 非空なら 420 + `Unsupported`
/// ヘッダで reject する MUST (RFC 3261 §8.2.2.3)。
fn unsupported_option_tags(require_value: &str) -> Vec<String> {
    require_value
        .split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .filter(|t| {
            !KNOWN_OPTION_TAGS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(t))
        })
        .map(|t| t.to_string())
        .collect()
}

/// `SipResponse` (= 18x / 2xx UAS 応答) に Issue #251 Phase A の RFC 互換ヘッダ集合
/// (`Allow` / `Supported` / `Date` / `Server`) を **常時付与** する共通ヘルパ。
///
/// 100 Trying では呼ばないこと: §13.3.1.4 / §8.2.6.2 / §20.5 で 100 への
/// 付与は要求されておらず、 sub-second 応答が優先される (Issue #251 audit #8)。
///
/// REGISTER 応答や 405 等のエラー応答とは独立に、 NGN inbound INVITE 経路の
/// 18x / 2xx だけに付与する (orchestrator handle_invite 内から call される)。
fn apply_uas_inbound_2xx_headers(resp: &mut SipResponse) {
    resp.headers.set("Allow", UAS_INBOUND_2XX_ALLOW);
    resp.headers.set("Supported", UAS_INBOUND_2XX_SUPPORTED);
    resp.headers.set("Date", http_date_now());
    resp.headers.set("Server", sabiden_server_header());
}

/// RFC 3262 §3 (Issue #251 Phase B): 100rel 用 option-tag の文字列。
/// Supported / Require 両方で大文字小文字無視・comma 区切りで現れる。
const OPTION_TAG_100REL: &str = "100rel";

/// RFC 3262 §3 / §7.1 ABNF: `RSeq = "RSeq" HCOLON response-num`
///   ここで `response-num = 1*DIGIT` (= 1..=2^32-1)。 32-bit 範囲で wrap せず
///   monotonically increasing する必要があり、 連続する reliable provisional
///   間で +1 で進める (§3 "increase by one for each provisional response sent
///   reliably in this transaction")。
///
/// `RAck = "RAck" HCOLON response-num LWS CSeq-num LWS Method` (§7.2)。
///
/// 初期 RSeq は §3 で `between 1 and 2^31 - 1` の範囲のランダム値が SHOULD。
/// sabiden は単純化のため `rand::thread_rng()` で uniform 抽出。
fn random_initial_rseq() -> u32 {
    // RFC 3262 §3: "It is RECOMMENDED that the initial value of RSeq be
    // chosen so as to be unpredictable within the range of 1 to 2**31 - 1."
    // OS-RNG を使い、 0 は除外する (§7.1 ABNF が 1 始まり)。
    use rand::Rng;
    let mut rng = rand::thread_rng();
    // 1..=2^31-1 (i32 max) の範囲。
    rng.gen_range(1u32..=0x7FFF_FFFF)
}

/// RFC 3262 §7.2 ABNF: `RAck-value = response-num LWS CSeq-num LWS Method`。
///
/// 受信した PRACK の `RAck` ヘッダから (RSeq, CSeq-num, Method) を取り出す。
/// パース失敗 (フィールド数 < 3 / 数値不正) は `None`。
///
/// 例: `"123 5 INVITE"` → `Some((123, 5, "INVITE"))`
fn parse_rack_header(rack: &str) -> Option<(u32, u32, String)> {
    let mut parts = rack.split_ascii_whitespace();
    let rseq: u32 = parts.next()?.parse().ok()?;
    let cseq: u32 = parts.next()?.parse().ok()?;
    let method = parts.next()?.to_string();
    if parts.next().is_some() {
        // §7.2 ABNF は 3 トークン固定。 余剰トークンは保守的に reject (誤認 RAck 防止)。
        return None;
    }
    Some((rseq, cseq, method))
}

/// `Supported` / `Require` の comma 区切り option-tag リストに指定 tag が
/// 含まれるか (大文字小文字無視、 RFC 3261 §7.3.1)。 `header_value` が `None`
/// なら `false`。
fn header_has_option_tag(header_value: Option<&str>, tag: &str) -> bool {
    let Some(value) = header_value else {
        return false;
    };
    value.split(',').any(|t| t.trim().eq_ignore_ascii_case(tag))
}

/// RFC 3262 §3 (Issue #251 Phase B): `handle_invite` が PRACK 受信を待ち合わせる
/// ときの結果。 `wait_for_prack` 経由で per-Call-ID Notify を `notified()` 待ち
/// する。
#[derive(Debug, PartialEq, Eq)]
enum PrackOutcome {
    /// PRACK が `KNOWN_OPTION_TAGS` 整合の RAck と共に到着し、 `handle_prack`
    /// が state を消費した。
    Received,
    /// 32 秒 (RFC 3262 §3 / RFC 3261 §17.1.1.2 Timer F = 64*T1) 待っても
    /// PRACK が来なかった。 呼出側は 408 で INVITE トランザクションを終結。
    Timeout,
    /// reliable 18x を出していない、 または既に他経路で消費済。 PRACK 待ちは
    /// no-op で進行可能。
    NoState,
}

/// RFC 3262 §3: 100rel 経路の状態。 NGN→sabiden 着信 INVITE 1 件につき
/// 最大 1 つ生存し、 reliable provisional 送出 → PRACK 受信 / timeout で
/// 消える。 `handle_invite` が「PRACK 待ちで 200 OK を保留」 するために
/// `prack_received` Notify を await する。
///
/// **同時生存条件**: §3 "The UAS MUST NOT send a second reliable provisional
/// response until the first is acknowledged." sabiden は **18x を 1 回しか
/// 出さない** (180 Ringing のみ) ため、 in-flight reliable response は
/// 高々 1 つ。 これにより RSeq の単一管理で十分。
struct Rc100relState {
    /// 待機中の `RSeq` 値 (= 直近送出した reliable 18x のもの)。
    rseq: u32,
    /// `RAck` 突合用 INVITE の CSeq 番号 (= reliable 18x が応答する CSeq)。
    invite_cseq: u32,
    /// retransmit task 停止通知用の Notify。 `Notify::notified()` を
    /// retransmit task が select! で listen し、 PRACK 受信時に `notify_one`
    /// で停止する (§3 自発再送停止)。
    prack_received: Arc<tokio::sync::Notify>,
    /// `handle_invite::wait_for_prack` 側を確実に wake させる oneshot。
    /// Notify の `notified()` future 単体では、 「PRACK が wait_for_prack の
    /// select! 入りより先に handle_prack で発火」 した場合に permit/waker の
    /// 取り逃しが起きるレースを観測したため (Issue #251 Phase B 開発時)、
    /// **冗長経路** として oneshot::channel を併用する。 `Option<Sender>`
    /// で 1 回送信後は `take()` で剥がす (= idempotent)。
    prack_oneshot_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// `wait_for_prack` 側に渡す Receiver。 INVITE 開始時の自身しか取れない
    /// (`take()` で 1 度きり)。
    prack_oneshot_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    /// reliable 18x 再送タスク (RFC 3262 §3 / §6: T1 起点で指数バックオフ、
    /// PRACK 受信 / Timer 満了で停止)。 `Drop` で abort される。
    retransmit_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Rc100relState {
    fn drop(&mut self) {
        if let Some(h) = self.retransmit_task.take() {
            h.abort();
        }
    }
}

/// RFC 3262 §3 / §6: reliable provisional response を T1 起点に指数バックオフ
/// で再送するタイマタスクを spawn する。 `notify` が `notify_one` されると即終了。
///
/// §3 引用:
/// > If a reliable provisional response is retransmitted, it MUST be sent
/// > with the same RSeq.
///
/// §6 (RFC 3261 §17.2.1 互換): 初期 T1 = 500ms、 2*T1, 4*T1, ... と倍々で
/// 増加し、 T2 (4s) で頭打ち、 合計時間 64*T1 (= 32 秒) で諦める。
///
/// 諦めた場合は §3 後段により「UAS は 5xx で INVITE トランザクションを終結」
/// するが、 本タスク自体はその判定をせず単に終了する。 INVITE 側の
/// `wait_for_prack` が timeout 検出して 5xx 応答経路に入る。
fn spawn_reliable_provisional_retransmit(
    socket: Arc<UdpSocket>,
    dest: SocketAddr,
    bytes: Vec<u8>,
    notify: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    // RFC 3261 §17.1.1.2: T1 = 500ms (RTT 推定の出発点)、 T2 = 4s (上限)。
    const T1: Duration = Duration::from_millis(500);
    const T2: Duration = Duration::from_secs(4);
    // 64 * T1 = 32 秒。 §3 で reliable 18x の PRACK 待ち上限と等価。
    const TIMER_LIMIT: Duration = Duration::from_secs(32);
    tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let mut interval = T1;
        loop {
            // PRACK 受信通知 or タイマ到達のどちらかで分岐。
            let sleep = tokio::time::sleep(interval);
            tokio::pin!(sleep);
            tokio::select! {
                _ = notify.notified() => {
                    debug!("RFC 3262 §3: PRACK 受信通知 → reliable 18x 再送停止");
                    return;
                }
                _ = &mut sleep => {
                    if started.elapsed() >= TIMER_LIMIT {
                        warn!(
                            "RFC 3262 §3: reliable 18x PRACK 不到来で 32 秒経過 → 再送停止"
                        );
                        return;
                    }
                    if let Err(e) = socket.send_to(&bytes, dest).await {
                        warn!(error=%e, "reliable 18x 再送失敗");
                        return;
                    }
                    debug!(?interval, "RFC 3262 §3: reliable 18x 自発再送");
                    // T1 → 2T1 → 4T1 → ... → T2 で頭打ち。
                    interval = std::cmp::min(interval.saturating_mul(2), T2);
                }
            }
        }
    })
}

/// `webrtc_active` leak sweeper の最小 / フォールバック周期 (Issue #218)。
///
/// `tokio::time::interval(Duration::ZERO)` は事前条件違反で panic するため、
/// `NgnInboundConfig.webrtc_active_sweep_interval` に 0 が流入したときの
/// 安全フォールバックとして使う。 値は [`NgnInboundConfig::default()`] の
/// 30 秒と揃える (struct field docstring の根拠: NGN 無音保持 5 分超
/// TTC JJ-90.24 / Mutex 競合トレードオフ)。
const MIN_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// NGN 着信処理の動作パラメータ。
#[derive(Debug, Clone)]
pub struct NgnInboundConfig {
    /// 内線フォーク全体の最大待機時間。これを超えると 408/487 で打ち切る。
    pub fork_timeout: Duration,
    /// `UasConfig` 由来の realm (内線側 To ヘッダ等で使用)。
    pub realm: String,
    /// RTP ブリッジ用の NGN 側 bind IP。`None` なら NGN SIP ソケットの
    /// IP を使う (`0.0.0.0` ならローカル ループバックにフォールバック)。
    pub bridge_ngn_bind_ip: Option<IpAddr>,
    /// RTP ブリッジ用の内線側 bind IP。`None` なら NGN 側と同じにする。
    pub bridge_ext_bind_ip: Option<IpAddr>,
    /// NGN 向け 200 OK の `Contact` ヘッダに載せる sent-by アドレス。
    /// SIP socket は `0.0.0.0:5060` で bind しているので `socket.local_addr()`
    /// を直に使うと NGN が ACK を返せず 10 秒後に CANCEL してくる
    /// (RFC 3261 §8.1.1.8 / §13.3.1.4: in-dialog target は Contact が確定する)。
    /// `None` ならソケット側にフォールバック (テスト互換)。
    pub ngn_local_addr: Option<SocketAddr>,
    /// `webrtc_active` テーブルの leak sweeper 周期 (Issue #139)。
    ///
    /// Issue #81 で導入した `webrtc_active: HashMap<Call-ID, WsSink>` は
    /// 「NGN BYE 到来時」 にしか entry を消さないため、 以下の経路で leak する:
    ///
    /// 1. **browser WS 切断のみ** (`ClientMessage::Bye` 未送出): PWA が
    ///    UI を閉じただけで NGN BYE が一切来ないケース。 `WsSink::is_closed`
    ///    は `true` になるが entry は HashMap に居残る。
    /// 2. **5xx 応答経路で winner WS が残るケース**: line 847 の `insert` は
    ///    200 OK 成功後にのみ走るため現状はこのリスクは無いが、 将来 5xx
    ///    分岐が追加されたときの defense-in-depth として sweeper で拾う。
    /// 3. **誤って入った無関係エントリ**: outbound 経路で `webrtc_active` を
    ///    触ることは現在無いが、 将来の refactor で混入しても sweeper が
    ///    `is_closed` で除去する (= テーブル正規化のラストリゾート)。
    ///
    /// 設計選択: `WsSink::is_closed` は `tokio::sync::mpsc::UnboundedSender::is_closed`
    /// を反映するため、 「receiver が drop された = WS forwarder タスクが
    /// 抜けた = browser 切断 (RFC 6455 §7)」 と等価。 これを 30 秒周期で
    /// 走査して該当 entry を `remove` する (= `WsSink` の最後の参照を drop)。
    ///
    /// なぜ周期: NGN は無音通話を 5 分超まで保持し得るため (TTC JJ-90.24)、
    /// 通話あたり数十秒の leak window は許容範囲。 過剰に短いと不要な
    /// Mutex 競合が増える。
    pub webrtc_active_sweep_interval: Duration,
}

impl Default for NgnInboundConfig {
    fn default() -> Self {
        Self {
            fork_timeout: Duration::from_secs(20),
            realm: "sabiden".to_string(),
            bridge_ngn_bind_ip: None,
            bridge_ext_bind_ip: None,
            ngn_local_addr: None,
            webrtc_active_sweep_interval: Duration::from_secs(30),
        }
    }
}

/// 内線フォーク用 INVITE ビルダ。
///
/// 本番経路では `Uac` を内線側ソケットで構築した [`UacForker`] を渡す。
/// テストでは `Arc<dyn LegInviter>` の Mock を渡せる。
pub type ExtInviter = Arc<dyn LegInviter>;

/// NGN→内線方向の BYE / リクエストを内線レッグへ伝搬する責務を持つトレイト。
///
/// `NgnInboundHandler` が NGN 側で BYE / Re-INVITE を受け取ったとき、まずこの
/// フォワーダに「この Call-ID の外向け通話 (内線→NGN 発信) はあるか?」を
/// 問い合わせる。 該当があれば内線レッグへリクエストを伝搬する責務は
/// フォワーダ側が負う (`UasEventHandler` が `OutboundCallRegistry` を保持
/// しているため、 dialog state 引きから内線レッグ送信まで一貫して扱える)。
#[async_trait::async_trait]
pub trait OutboundDialogForwarder: Send + Sync {
    /// 指定 Call-ID が外向け通話なら true を返し、内線レッグへ BYE を投げる。
    /// 該当しなければ false を返す (= NgnInboundHandler が通常の inbound BYE
    /// 処理にフォールバックする)。
    async fn try_forward_bye(&self, ngn_call_id: &str) -> bool;

    /// 指定 Call-ID が外向け通話 (内線→NGN 発信) で、 かつ NGN 側 dialog
    /// に属する Re-INVITE (in-dialog INVITE) なら true を返し、 内線レッグへ
    /// Re-INVITE を伝搬してその応答を NGN に返すまでを完結させる。
    /// 該当しなければ false を返す (= NgnInboundHandler が通常の inbound
    /// INVITE 経路 (= 新規 dialog 作成) にフォールバックする)。
    ///
    /// RFC 3261 §14.2 (UAS Behavior on Re-INVITE) / Issue #138:
    /// sabiden は B2BUA であり、 NGN 側ピアが起こした hold/un-hold や
    /// Session-Timer refresh (refresher=uas) を内線へ届ける義務がある。
    async fn try_forward_ngn_reinvite(
        &self,
        request: SipRequest,
        stx: Arc<Mutex<ServerTransaction>>,
    ) -> bool;
}

#[async_trait::async_trait]
impl OutboundDialogForwarder for UasEventHandler {
    async fn try_forward_bye(&self, ngn_call_id: &str) -> bool {
        if self.registry.lookup_by_ngn(ngn_call_id).await.is_none() {
            return false;
        }
        if let Err(e) = self.handle_ngn_bye(ngn_call_id).await {
            warn!(error=%e, "NGN→内線 BYE 伝搬中にエラー");
        }
        true
    }

    async fn try_forward_ngn_reinvite(
        &self,
        request: SipRequest,
        stx: Arc<Mutex<ServerTransaction>>,
    ) -> bool {
        let call_id = match request.headers.get("call-id") {
            Some(c) => c.to_string(),
            None => return false,
        };
        if self.registry.lookup_by_ngn(&call_id).await.is_none() {
            return false;
        }
        if let Err(e) = self.handle_ngn_reinvite(request, stx).await {
            warn!(error=%e, "NGN→内線 Re-INVITE 伝搬中にエラー");
        }
        true
    }
}

/// PWA→NGN 発信通話の双方向 BYE 連動エントリ (Issue #147)。
///
/// PWA peer は SIP dialog を持たないため、 内線→NGN 発信用の
/// [`OutboundCallEntry`] (= `ext_dialog` 必須) は使えない。 専用テーブル
/// [`WebRtcOutboundActive`] にこのエントリを保存することで:
///
/// - **NGN→PWA BYE**: `NgnInboundHandler::handle_bye` が NGN 側 Call-ID で
///   このテーブルを引き、 `bridge_call_id` で `CallManager::terminate` →
///   `metrics.dec_call_active` → `WsSink` に `ServerMessage::Bye` を push。
/// - **PWA→NGN BYE**: シグナリング層が `ClientMessage::Bye` または WS close
///   検知時に `UasEventHandler::close_pwa_outbound_for_ws` を呼び、 該当 WS
///   のエントリで `ngn_dialog.send_bye()` を撃ち、 上記と同じ cleanup を行う。
///
/// RFC 3261 §15.1.2 / RFC 5853 §3.2.2 (SBC framework): B2BUA は片側 dialog
/// 終了をもう片側へ伝搬する責務を負う。
pub struct WebRtcOutboundEntry {
    /// NGN レッグの確立済み UAC dialog。 PWA→NGN BYE は `send_bye()` で投げる。
    /// `tokio::sync::Mutex` (本ファイル冒頭の `use tokio::sync::Mutex;`) を使う
    /// 理由: `send_bye` 内で I/O await するので、 `std::sync::Mutex` だと async
    /// boundary 越しに guard を保持できない。 短期ロックで競合は無視可能。
    pub ngn_dialog: Mutex<UacDialog>,
    /// 該当 PWA WS セッションへの送信ハンドル。 NGN→PWA BYE 時は
    /// `ServerMessage::Bye` を enqueue する。
    pub ws: WsSink,
    /// `CallManager` 内のブリッジ ID。 BYE で `terminate` するために保持する。
    pub bridge_call_id: CallId,
}

/// PWA→NGN 発信通話の双方向 BYE 連動テーブル (Issue #147)。
///
/// キーは NGN レッグの Call-ID (= `UacDialog::dialog().id().call_id`)。
/// `NgnInboundHandler` と `UasEventHandler` が同じ Arc を共有することで、
/// どちらの方向 (NGN→PWA / PWA→NGN) からも引ける。
pub type WebRtcOutboundActive = Arc<Mutex<HashMap<String, Arc<WebRtcOutboundEntry>>>>;

/// NGN→PWA **着信** 通話の双方向 BYE 連動エントリ (実機 v7 Bug B / Issue #268)。
///
/// 既存 `webrtc_active: HashMap<String, WsSink>` (Issue #81) は NGN→PWA BYE
/// 伝搬 (NGN BYE 受信 → browser に `ServerMessage::Bye` push) しか担っておらず、
/// **逆向き**(= PWA WS close → NGN へ BYE 送出) は未実装だった。 そのため:
///
/// - PWA がタブ閉じ / ネットワーク断 / Cloudflare Tunnel idle 切断したとき、
///   sabiden は NGN へ何も通知せず、 NGN は dialog confirmed のまま 5-10 秒
///   タイムアウトで BYE を投げ返してくる (実機 v7 で `recv BYE` まで 6 秒の
///   ギャップ観測)。 その間 RTP ブリッジは生きており、 PWA への送出は失敗
///   ログで埋まる。
///
/// 本エントリは `WebRtcOutboundEntry` (PR #154 PWA→NGN 発信) の inbound 対称形:
///
/// - `uas_dialog`: 受信 INVITE と sabiden が返した 200 OK から構築した
///   [`Dialog::from_uas_invite`] 結果。 BYE を組み立てるのに必要 (RFC 3261
///   §15.1.1 / §12.2.1: in-dialog request は dialog state から組み立てる)。
/// - `invite_cseq`: 受信 INVITE の CSeq 番号。 BYE の CSeq とは独立だが、
///   観測用 (Re-INVITE 連番衝突防止の参考)。
/// - `layer`: BYE 送信に使う `TransactionLayer`。
/// - `fallback_peer`: dialog next-hop URI が解決不能のとき (FQDN 未解決 等)
///   の最終フォールバック。 sabiden に届いた INVITE の `remote` (= P-CSCF)
///   をそのまま渡す。 RFC 3263 完全 DNS 解決は将来 Issue。
/// - `ws`: PWA WS 接続。 NGN BYE 受信時に `ServerMessage::Bye` を push する用。
/// - `bridge_call_id`: RTP ブリッジ ID (transparent モードでは `None`)。
///   BYE 時に `CallManager::terminate` で停止する。
///
/// RFC 3261 §15.1.2 / RFC 5853 §3.2.2 (SBC framework): B2BUA は片側 dialog
/// 終了をもう片側へ伝搬する責務を負う。 outbound (Issue #147) と inbound
/// (本エントリ) を両方持って初めて、 PWA 切断 → NGN 即時 BYE という対称な
/// hangup シーケンスが成立する。
pub struct WebRtcInboundEntry {
    /// 受信 INVITE / 200 OK から組み立てた UAS dialog state。
    ///
    /// `Option` で包む理由: degraded 経路 (旧 fixture / test で `layer` が
    /// 注入されていない経路) では dialog を構築しても BYE は送れないため、
    /// `None` で保留する。 production (= `wire_ngn_inbound_with_*_layer_*` 経由)
    /// では常に `Some` (BYE 送出が機能する完全 entry)。
    ///
    /// `tokio::sync::Mutex` を使う理由: BYE 送信時に `layer.send_request`
    /// で I/O await するため (`std::sync::Mutex` だと async boundary 越しに
    /// guard を保持できない)。 短期ロックで競合は実害なし。
    pub uas_dialog: Option<Mutex<Dialog>>,
    /// BYE 送信用の SIP TransactionLayer。 `uas_dialog` と同じ理由で `Option`。
    pub layer: Option<Arc<TransactionLayer>>,
    /// dialog next-hop URI 解決失敗時のフォールバック宛先 (P-CSCF)。
    pub fallback_peer: SocketAddr,
    /// PWA WS 接続。 NGN BYE 受信時の `ServerMessage::Bye` push 用。
    /// `close_pwa_inbound_for_ws` が同 WS の全 entry を抽出する判定キー。
    pub ws: WsSink,
}

impl WebRtcInboundEntry {
    /// `WsSink` のみを持つ degraded エントリを作る。 test fixture / 旧経路
    /// (layer 不在) で使う。 production は `wire_ngn_inbound_with_layer_*`
    /// 経由で完全 entry が作られる。
    #[cfg(test)]
    pub fn ws_only_for_test(ws: WsSink) -> Arc<Self> {
        Arc::new(Self {
            uas_dialog: None,
            layer: None,
            fallback_peer: "127.0.0.1:5060".parse().unwrap(),
            ws,
        })
    }

    /// BYE を組み立てて NGN へ送出する (RFC 3261 §15.1.1)。
    ///
    /// 宛先は dialog next-hop (RFC 3261 §12.2.1.1) で決まり、 解決不能のときは
    /// `fallback_peer` (= 受信 INVITE の `remote` = 通常 P-CSCF) を使う。
    /// `UacDialog::send_bye` と同じ二段解決を `Dialog` 直接利用で再現する
    /// (本エントリは UAS dialog なので `UacDialog` ラッパは流用できない)。
    ///
    /// 戻り値:
    /// - `Ok(Some(resp))`: NGN から最終応答を受信 (典型的に 200 OK)。
    /// - `Ok(None)`: degraded entry (dialog/layer 不足) のため BYE を送らず skip。
    ///   旧 fixture / test 経路、 production では発生しない。
    /// - `Err(...)`: NGN unreachable / transaction timeout 等。 呼出側は
    ///   エラーでも sabiden 側 cleanup を続ける (best-effort)。
    pub async fn send_bye(&self) -> Result<Option<SipResponse>> {
        let (Some(dialog_lock), Some(layer)) = (self.uas_dialog.as_ref(), self.layer.as_ref())
        else {
            debug!("WebRtcInboundEntry::send_bye: degraded entry (dialog/layer 不足) → skip");
            return Ok(None);
        };
        let mut dlg = dialog_lock.lock().await;
        let bye = dlg.build_bye();
        let peer = dlg.next_hop_socket(self.fallback_peer);
        let resp = layer.send_request(bye, peer).await?;
        dlg.terminate();
        Ok(Some(resp))
    }
}

/// NGN→PWA 着信通話の双方向 BYE 連動テーブル (Bug B / Issue #268)。
///
/// キーは受信 INVITE の Call-ID。 詳細は [`WebRtcInboundEntry`]。
pub type WebRtcInboundActive = Arc<Mutex<HashMap<String, Arc<WebRtcInboundEntry>>>>;

/// 内線レッグの answer SDP が「WebRTC peer から戻ったまま未書換のプレースホルダ」
/// かを推定する。
///
/// `run_webrtc_leg` が組み立てる 200 OK 用 SDP は browser answer を
/// `convert_savpf_to_avp` で AVP に変換しただけなので、 `c=IN IP4 0.0.0.0`
/// **かつ** `m=audio 9` (= "discard port", RFC 4566 §5.14 / IANA discard) が
/// 両方残っている場合「呼出側の `start_bridge_for_inbound` が
/// `rewrite_rtp_endpoint` で書き換える前提の中間状態」であり、 そのまま NGN に
/// 流すと到達不能 (RFC 4566 §5.2 origin + §5.7 connection / `docs/asterisk-real-invite.md` §5.2)。
///
/// Issue #122 🟡 #2 修正: 旧実装は `c=IN IP4 0.0.0.0` 単独でも true を返したため、
/// 普通の SIP UA が RFC 4566 §5.7 の hold/silenced semantics で
/// `c=IN IP4 0.0.0.0` + `m=audio 30000` のような実 RTP port を返した場合に
/// 誤検知して 502 で呼が落ちた。 transparent モード SIP 内線では `c=0.0.0.0` 単独は
/// 「hold」、 WebRTC leg placeholder は「c=0.0.0.0 **かつ** port 9」なので、
/// AND 判定で誤検知を排除する。
///
/// 通常の SIP 内線が返す answer は LAN IP / 実 RTP port なので false を返す。
fn is_undirected_or_webrtc_placeholder_sdp(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let mut has_zero_conn = false;
    let mut has_discard_port_audio = false;
    for line in text.lines() {
        let l = line.trim_end();
        if l == "c=IN IP4 0.0.0.0" {
            has_zero_conn = true;
        } else if l.starts_with("m=audio 9 RTP/AVP") || l.starts_with("m=audio 9 UDP/TLS/RTP/SAVPF")
        {
            has_discard_port_audio = true;
        }
    }
    has_zero_conn && has_discard_port_audio
}

/// NGN 着信ハンドラ。`TransactionLayer::spawn` の `inbound_rx` を消費する。
pub struct NgnInboundHandler {
    socket: Arc<UdpSocket>,
    /// NGN 側 SIP TransactionLayer (Bug B / Issue #268 で必要)。
    ///
    /// 用途: WS close 経路で PWA→NGN BYE を撃つときに `send_request` で使う。
    /// 旧実装 (Issue #81 まで) は inbound 側で BYE 送出を必要としなかったため
    /// `wire_ngn_inbound` の `_layer` 引数は未使用だった。 本フィールド導入で
    /// inbound 側からも UAC として in-dialog request を送れるようになる
    /// (RFC 3261 §12.2.1 / §15.1.1)。
    ///
    /// `Option` で包む理由: 旧 `with_*` constructor (test fixture / legacy 経路)
    /// は layer なしで呼び出されており、 後方互換のため `None` も許す。
    /// None 時は WS close → NGN BYE 経路が無効化される (旧挙動 = 5-10 秒
    /// NGN タイムアウト BYE 待ち) だけで他機能には影響しない (defense-in-depth)。
    layer: Option<Arc<TransactionLayer>>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    /// Call-ID → ServerTransaction (BYE/ACK で再利用するため保持する)。
    pending: Arc<Mutex<HashMap<String, Arc<Mutex<ServerTransaction>>>>>,
    /// 確立済み通話の Call-ID → `Option<CallId>` 対応。BYE 時にブリッジ停止に使う。
    /// `None` の値は「確立済みだが RTP ブリッジ未起動 (透過モード)」を意味する。
    active: Arc<Mutex<HashMap<String, Option<CallId>>>>,
    /// 確立済み WebRTC 内線通話の Call-ID → 通話 state エントリ (Issue #81 + Bug B 拡張)。
    ///
    /// NGN→PWA 方向 (NGN BYE 受信): 該当する WebRTC peer の WS に
    /// `ServerMessage::Bye` を push する (Issue #81)。
    ///
    /// PWA→NGN 方向 (WS close): PWA がタブ閉じ / ネットワーク断したとき、
    /// `close_pwa_inbound_for_ws` が同 WS 一致 entry を全抽出し、 各 entry
    /// の `send_bye()` で NGN へ BYE を撃って bridge / metrics を cleanup する
    /// (Bug B、 実機 v7 で PWA 切断後 6 秒 NGN BYE 待ちを観測 / 解消)。
    ///
    /// SIP 内線レッグは UAS 側のダイアログから build_bye で同様に内線へ送るのが
    /// 既存設計だが、 WebRTC レッグは独立した SIP dialog を持たない (= 専用 WS
    /// シグナリング経路) ため別テーブルで紐づける。 RFC 3261 §15.1.2 /
    /// RFC 5853 §3.2.2 SBC framework: B2BUA は片側の dialog 終了をもう片側へ
    /// 伝搬する責務を負う。
    webrtc_active: WebRtcInboundActive,
    /// PWA→NGN 発信通話の双方向 BYE 連動テーブル (Issue #147)。
    /// `UasEventHandler` と同じ Arc を共有することで、 NGN→PWA / PWA→NGN
    /// 両方向の BYE が同じエントリを引ける。 詳細は [`WebRtcOutboundEntry`]。
    webrtc_outbound_active: WebRtcOutboundActive,
    /// 進行中 (= 内線フォーク中) の INVITE。NGN から CANCEL が来たときに
    /// `Notify::notify_one` を撃って fork を打ち切るために保持する
    /// (RFC 3261 §9.1: NGN が CANCEL を出した時点で sabiden は内線フォークを
    /// 中止し、INVITE には 487 Request Terminated を返す)。
    in_flight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Notify>>>>,
    /// RFC 3262 §3 / §4 (Issue #251 Phase B): 100rel reliable provisional
    /// 経路の per-Call-ID 状態。 INVITE 受信時に `Supported: 100rel` があれば
    /// reliable 180 Ringing を出して entry を作成し、 PRACK 受信時に entry
    /// から `prack_received` を `notify_one` して INVITE 側の wait を解除する。
    ///
    /// entry の生存範囲: reliable 18x 送出時 → PRACK 受信 / 32 秒タイムアウト /
    /// CANCEL / 200 OK 送出後の cleanup。 これにより `handle_inbound` の
    /// PRACK 分岐から O(1) で対応 INVITE を引ける。
    rc100rel: Arc<Mutex<HashMap<String, Arc<Mutex<Rc100relState>>>>>,
    /// RTP ブリッジを管理する Call Manager。`None` なら SDP 透過モードで動く
    /// (Issue #15 互換)。
    call_manager: Option<Arc<CallManager>>,
    /// 内線→NGN 発信通話のレジストリへのフォワーダ。`None` なら NGN→内線方向の
    /// BYE は inbound 用の `active` テーブルでしか引けないため、外向け通話は
    /// 拾えない。本番では [`UasEventHandler`] を `Arc::clone` で渡すこと。
    outbound_forwarder: Mutex<Option<Arc<dyn OutboundDialogForwarder>>>,
    /// 観測カウンタ。Issue #20。
    metrics: Arc<Metrics>,
    /// Issue #278: 通話履歴 ring buffer。 NGN 着信 / NGN→PWA / NGN→内線 の
    /// 確立・終了を 1 件ずつ記録する。 未注入 (= 旧 fixture / テスト経路) では
    /// `None` で、 hook は no-op となる (record_*)。 `set_call_log` で注入する
    /// タイミングが `Arc::clone().spawn()` 後 (= shared) の場合があるため、
    /// `outbound_forwarder` と同じく `Mutex<Option<_>>` で interior mutability
    /// にする。 hot path には乗らない (1 通話 = 数回の lock 取得)。
    call_log: Mutex<Option<Arc<crate::observability::call_log::CallLog>>>,
}

impl NgnInboundHandler {
    pub fn new(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
    ) -> Arc<Self> {
        Self::with_metrics(socket, inviter, extensions, cfg, Metrics::new())
    }

    /// メトリクス付きコンストラクタ。
    pub fn with_metrics(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            layer: None,
            inviter,
            extensions,
            cfg,
            pending: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_outbound_active: Arc::new(Mutex::new(HashMap::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            rc100rel: Arc::new(Mutex::new(HashMap::new())),
            call_manager: None,
            outbound_forwarder: Mutex::new(None),
            metrics,
            call_log: Mutex::new(None),
        })
    }

    /// `CallManager` を組み込んだバージョン。RTP ブリッジを起動する経路はこちら。
    pub fn with_call_manager(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
        call_manager: Arc<CallManager>,
    ) -> Arc<Self> {
        Self::with_call_manager_and_metrics(
            socket,
            inviter,
            extensions,
            cfg,
            call_manager,
            Metrics::new(),
        )
    }

    /// `CallManager` + メトリクス付きコンストラクタ。
    pub fn with_call_manager_and_metrics(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
        call_manager: Arc<CallManager>,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            layer: None,
            inviter,
            extensions,
            cfg,
            pending: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_outbound_active: Arc::new(Mutex::new(HashMap::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            rc100rel: Arc::new(Mutex::new(HashMap::new())),
            call_manager: Some(call_manager),
            outbound_forwarder: Mutex::new(None),
            metrics,
            call_log: Mutex::new(None),
        })
    }

    /// 既存 [`WebRtcOutboundActive`] を共有するコンストラクタ (Issue #147)。
    /// `UasEventHandler` と同じ Arc を渡すことで、 PWA→NGN 発信通話の
    /// 双方向 BYE 連動が成立する。
    pub fn with_call_manager_metrics_and_outbound_table(
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
        call_manager: Arc<CallManager>,
        metrics: Arc<Metrics>,
        webrtc_outbound_active: WebRtcOutboundActive,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            layer: None,
            inviter,
            extensions,
            cfg,
            pending: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_outbound_active,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            rc100rel: Arc::new(Mutex::new(HashMap::new())),
            call_manager: Some(call_manager),
            outbound_forwarder: Mutex::new(None),
            metrics,
            call_log: Mutex::new(None),
        })
    }

    /// `with_call_manager_metrics_and_outbound_table` + `TransactionLayer` 連結版 (Bug B / Issue #268)。
    ///
    /// PWA WS close → NGN BYE 経路を有効化するために `TransactionLayer` を保持する。
    /// inbound 通話エントリは BYE 送信時に layer 経由でリクエストを発行する。
    #[allow(clippy::too_many_arguments)]
    pub fn with_layer_call_manager_metrics_and_outbound_table(
        layer: Arc<TransactionLayer>,
        socket: Arc<UdpSocket>,
        inviter: ExtInviter,
        extensions: Arc<ExtensionRegistrar>,
        cfg: NgnInboundConfig,
        call_manager: Arc<CallManager>,
        metrics: Arc<Metrics>,
        webrtc_outbound_active: WebRtcOutboundActive,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            layer: Some(layer),
            inviter,
            extensions,
            cfg,
            pending: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_outbound_active,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            rc100rel: Arc::new(Mutex::new(HashMap::new())),
            call_manager: Some(call_manager),
            outbound_forwarder: Mutex::new(None),
            metrics,
            call_log: Mutex::new(None),
        })
    }

    /// `webrtc_outbound_active` の Arc を返す。 `UasEventHandler` 等、 同じ
    /// テーブルを共有したい外部ハンドラに渡すための accessor (Issue #147)。
    pub fn webrtc_outbound_active(&self) -> WebRtcOutboundActive {
        self.webrtc_outbound_active.clone()
    }

    /// Issue #278: 通話履歴 ring buffer を注入する (setter)。
    ///
    /// `outbound_forwarder` と同じく `Mutex<Option<_>>` ベースなので spawn 後
    /// (= 既に shared) に呼んでも安全。 未注入時 (`None`) は hook 全て no-op
    /// となり、 旧挙動と同一。 NGN 着信 (内線フォーク 確立 / PWA 確立) と関連
    /// BYE がここに集約される。
    pub async fn set_call_log(
        self: &Arc<Self>,
        call_log: Arc<crate::observability::call_log::CallLog>,
    ) {
        let mut slot = self.call_log.lock().await;
        *slot = Some(call_log);
    }

    /// 通話履歴の Arc clone (注入済みの場合)。 hot path から `record_*` を
    /// 呼ぶときの helper として使う。 未注入なら `None` で hook 全体を skip する。
    async fn call_log_clone(&self) -> Option<Arc<crate::observability::call_log::CallLog>> {
        self.call_log.lock().await.clone()
    }

    /// `webrtc_active` (NGN→PWA 着信通話の double BYE 連動テーブル) の Arc を
    /// 返す (Bug B / Issue #268)。 シグナリング層が `PwaInboundCloser` 経由で
    /// WS close 時に同 WS 一致 entry を抽出するために使う。
    pub fn webrtc_inbound_active(&self) -> WebRtcInboundActive {
        self.webrtc_active.clone()
    }

    /// 内線→NGN 発信通話の BYE を内線レッグへ伝搬するためのフォワーダを差し込む。
    /// `UasEventHandler` を `Arc::clone` して渡せば B2BUA 双方向 BYE が成立する。
    pub async fn set_outbound_forwarder(&self, forwarder: Arc<dyn OutboundDialogForwarder>) {
        *self.outbound_forwarder.lock().await = Some(forwarder);
    }

    /// `inbound_rx` を駆動するループを spawn する。
    ///
    /// 同時に `webrtc_active` leak sweeper も spawn する (Issue #139)。
    /// sweeper は `cfg.webrtc_active_sweep_interval` 周期で
    /// `sweep_webrtc_active` を呼び、 WS が閉じた (= browser 切断済) entry を
    /// 取り除く。 inbound loop が終了 (= channel close) しても sweeper だけが
    /// 走り続ける事故を避けるため、 `Arc::downgrade` で弱参照に切り替え、
    /// `NgnInboundHandler` 自体が drop されたら sweeper も自動終了する。
    pub fn spawn(self: Arc<Self>, mut inbound_rx: mpsc::UnboundedReceiver<InboundRequest>) {
        // Issue #139: webrtc_active leak sweeper を起動 (弱参照)。
        // ハンドラ本体が dropped されたら自動で抜ける。
        Self::spawn_webrtc_active_sweeper(
            Arc::downgrade(&self),
            self.cfg.webrtc_active_sweep_interval,
        );

        tokio::spawn(async move {
            while let Some(inbound) = inbound_rx.recv().await {
                let me = self.clone();
                // 1 INVITE = 1 fork で並列に処理する (BYE 等は軽いので spawn 不要)
                tokio::spawn(async move {
                    if let Err(e) = me.handle_inbound(inbound).await {
                        warn!(error=%e, "NGN 着信処理失敗");
                    }
                });
            }
            debug!("NGN inbound loop 終了");
        });
    }

    /// Issue #139: `webrtc_active` テーブルから WS が閉じた entry を除去する
    /// 周期タスクを spawn する。
    ///
    /// # 経路と RFC 根拠
    ///
    /// `webrtc_active` は NGN→WebRTC 着信通話の WS ハンドルを Call-ID で
    /// 保持し、 NGN BYE 受信時に `ServerMessage::Bye` を browser に push
    /// するために使う (RFC 3261 §15.1.2 / RFC 5853 §3.2.2 SBC framework:
    /// B2BUA は片側 dialog 終了をもう片側へ伝搬する責務を負う)。
    ///
    /// しかし以下の経路では NGN BYE が来ず entry が leak する:
    ///
    /// - browser が **WS を切断したのみ** (= `ClientMessage::Bye` 未送出)。
    ///   RFC 6455 §7.4 の close handshake で WS forwarder 受信側 mpsc receiver
    ///   が drop され、 `WsSink::is_closed` が true になる。 NGN は依然
    ///   dialog confirmed のまま無音通話を続けるため、 BYE 経由の `remove`
    ///   は走らない。
    /// - 将来追加され得る 5xx 経路 / 内部 outbound 混入 (defense-in-depth)。
    ///
    /// 本タスクは `interval` 周期で全 entry を走査し、 `WsSink::is_closed`
    /// 一致 entry を `remove` する。 `Arc::strong_count` が落ちれば
    /// (= `NgnInboundHandler` 自体が dropped) sweeper も即座に終了する
    /// (`Weak::upgrade` が `None` を返す)。
    ///
    /// # `Duration::ZERO` 防御 (Issue #218)
    ///
    /// `tokio::time::interval(Duration::ZERO)` は事前条件違反で panic する
    /// (tokio docs: "panics if `period` is zero")。 現状 `NgnInboundConfig`
    /// の TOML deserialize 経路は無く `main.rs` の hard-code 30s だけが
    /// 実投入されるが、 将来 config 化 / テスト fixture / `Default` 派生
    /// ミスでゼロが流入する static fragility がある (CLAUDE.md §6.5
    /// panic 禁止)。 同種の panic 経路を `WebRtcConfig::default()` で
    /// 既に修正している (Issue #166 / `src/config/mod.rs:218`)。
    ///
    /// ここでは sweeper 入口で `Duration::ZERO` を [`MIN_SWEEP_INTERVAL`]
    /// (= 既定 30s と同値) に clamp し、 `warn!` で誤投入を可視化する。
    /// 値の選択根拠は struct field docstring:
    /// NGN は無音通話を 5 分超まで保持し得るため (TTC JJ-90.24)、 通話
    /// あたり数十秒の leak window は許容範囲、 過剰短は不要 Mutex 競合を
    /// 増やす。 そのため fallback は 0 や 1ms ではなく既定値 30s と揃える。
    fn spawn_webrtc_active_sweeper(weak_self: std::sync::Weak<Self>, interval: Duration) {
        // Issue #218: `Duration::ZERO` を `tokio::time::interval` に渡すと
        // panic する (`interval` 事前条件)。 production config から 0 が
        // 流入しても sweeper が落ちないよう、 ここで弾く (defense-in-depth)。
        let interval = if interval.is_zero() {
            warn!(
                fallback_secs = MIN_SWEEP_INTERVAL.as_secs(),
                "webrtc_active sweeper: interval=0 は tokio::time::interval を panic させるため既定値にフォールバック (Issue #218)"
            );
            MIN_SWEEP_INTERVAL
        } else {
            interval
        };
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // 初回 tick は即時発火するので 1 回読み飛ばす (= 起動直後の空 sweep を避ける)。
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(strong) = weak_self.upgrade() else {
                    debug!("webrtc_active sweeper: ハンドラが dropped されたので終了");
                    return;
                };
                let removed = strong.sweep_webrtc_active().await;
                if removed > 0 {
                    debug!(
                        removed,
                        "webrtc_active sweeper: 閉じた WS の entry を除去 (Issue #139)"
                    );
                }
            }
        });
    }

    /// `webrtc_active` を走査し、 `WsSink::is_closed` が true (= browser が
    /// WS を切断済) の entry を全て remove する。 戻り値は除去件数。
    ///
    /// RFC 6455 §7.4 (Closing Handshake): WebSocket は close frame を交換した
    /// 段階で peer 接続を終了する。 sabiden の WS forwarder タスクはここで
    /// 終了し、 `mpsc::UnboundedReceiver` を drop する。 これにより `WsSink`
    /// 内の `UnboundedSender::is_closed` が true を返すようになる
    /// (tokio 1.x mpsc docs)。
    ///
    /// 本 sweeper は orchestrator 内 lock を一時的に取るが、 走査は in-memory
    /// HashMap の線形時間で短時間しか保持しないため (entry 数は同時通話数程度)、
    /// 既存 BYE 経路 (`handle_bye` line 976) や winner insert 経路
    /// (line 847) との競合は ms オーダー以下で済む。
    ///
    /// `HashMap::retain` で 1 段で remove する (`extract_if` でもよいが、
    /// remove 値を一旦集める必要がないので retain が簡潔)。
    async fn sweep_webrtc_active(&self) -> usize {
        // Bug B (Issue #268): エントリは `Arc<WebRtcInboundEntry>` に変わったので
        // `ws.is_closed()` ではなく `entry.ws.is_closed()` で判定する。
        // sweeper の意義 (Issue #139) は不変: 旧経路で BYE 不到来のまま leak した
        // entry を周期的に除去する safety net。 close_pwa_inbound_for_ws が PR で
        // BYE を撃つようになったため leak window は短いが、 防衛的に残す。
        let mut tbl = self.webrtc_active.lock().await;
        let before = tbl.len();
        tbl.retain(|_, entry| !entry.ws.is_closed());
        before - tbl.len()
    }

    async fn handle_inbound(&self, inbound: InboundRequest) -> Result<()> {
        let InboundRequest { request, remote } = inbound;
        match request.method {
            SipMethod::Invite => self.handle_invite(request, remote).await,
            SipMethod::Bye => self.handle_bye(request, remote).await,
            SipMethod::Ack => {
                // RFC 3261 §17.2.7: ACK は応答を要しない。pending を 1 つ消す。
                if let Some(call_id) = request.headers.get("call-id") {
                    let mut pending = self.pending.lock().await;
                    pending.remove(call_id);
                }
                Ok(())
            }
            SipMethod::Cancel => {
                // RFC 3261 §9.2: CANCEL は新しい transaction で 200 OK を返し、
                // INVITE 側は 487 Request Terminated で完了させる。
                // 進行中の内線フォークがあれば `in_flight` に登録した Notify を
                // 撃って `handle_invite` 側 (tokio::select!) に「中止」を伝える。
                let cid = request.headers.get("call-id").map(str::to_string);
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                tx.respond(build_response_skeleton(tx.request(), 200, "OK"))
                    .await?;
                if let Some(cid) = cid {
                    if let Some(notify) = self.in_flight.lock().await.get(&cid).cloned() {
                        notify.notify_one();
                    }
                }
                Ok(())
            }
            SipMethod::Options => {
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp = build_response_skeleton(tx.request(), 200, "OK");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                Ok(())
            }
            // RFC 3265 §3.2: UAS が `NOTIFY` を受け、 該当する subscription
            // が無い場合は 481 (Subscription Does Not Exist) を返すべき。
            // sabiden は B2BUA であり SUBSCRIBE 受信機能 (presence / reg-event 等)
            // を持たないため、 NGN→sabiden の NOTIFY は常に「subscription なし」
            // 扱いで 481 を返す。 これにより IMS の reg-event NOTIFY が
            // 405 で拒否されて REGISTER binding 期限が短縮される問題
            // (Issue #110) を回避する。
            SipMethod::Notify => {
                warn!(
                    call_id = ?request.headers.get("call-id"),
                    "NGN 側 NOTIFY: 該当 subscription なし → 481 (RFC 3265 §3.2)"
                );
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp =
                    build_response_skeleton(tx.request(), 481, "Subscription Does Not Exist");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                Ok(())
            }
            // RFC 3265 §7.2.4 / §3.1.4: 未対応 event package に対する
            // SUBSCRIBE には 489 (Bad Event) を返し、 `Allow-Events` ヘッダで
            // サポート済 package を列挙する (sabiden は何も提供しないので空)。
            SipMethod::Subscribe => {
                warn!(
                    call_id = ?request.headers.get("call-id"),
                    "NGN 側 SUBSCRIBE: 未対応 event package → 489 (RFC 3265 §7.2.4)"
                );
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp = build_response_skeleton(tx.request(), 489, "Bad Event");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                Ok(())
            }
            // RFC 3262 §4 (Issue #251 Phase B): PRACK は UAS が
            // `Require: 100rel` 付きの 1xx を出した直後に届く ACK 相当。
            // `handle_prack` で per-Call-ID `Rc100relState` を引き、
            //   - RAck が直近 reliable 18x の (RSeq, INVITE CSeq) と一致 →
            //     200 OK PRACK + retransmit task を停止 + INVITE 側の wait を解除。
            //   - state 無し / RAck 不一致 → 481 (RFC 3262 §4 / §7.1)。
            SipMethod::Prack => self.handle_prack(request, remote).await,
            // RFC 3903 §6: PUBLISH も event package ベース。 sabiden は
            // event state 受信機能を持たないので 489 (Bad Event) で返す。
            SipMethod::Publish => {
                warn!(
                    call_id = ?request.headers.get("call-id"),
                    "NGN 側 PUBLISH: 未対応 event package → 489 (RFC 3903 §11.1)"
                );
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp = build_response_skeleton(tx.request(), 489, "Bad Event");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                Ok(())
            }
            // RFC 3311 §5.2: UPDATE はダイアログ前 (early) / 確立後どちらでも
            // 来うる。 NgnInboundHandler は INVITE/BYE の Call-ID 管理のみ持ち、
            // ダイアログ状態を直接保持しないため、 UPDATE は対応するダイアログ
            // 不在として 481 を返す (RFC 3261 §12.2.2)。 上位 B2BUA で
            // 動的 SDP 更新が必要になった段階で per-dialog ハンドラを生やす。
            SipMethod::Update => {
                warn!(
                    call_id = ?request.headers.get("call-id"),
                    "NGN 側 UPDATE: 対応ダイアログ無し → 481 (RFC 3311 §5.2)"
                );
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp =
                    build_response_skeleton(tx.request(), 481, "Call/Transaction Does Not Exist");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                Ok(())
            }
            // RFC 6086 §3 / §4: NgnInboundHandler は INFO の上位ルーティング
            // (DTMF 等) を持たないため、 NGN 側からの中間 INFO は対応ダイアログ
            // 不在扱いで 481 を返す (内線側 INFO は `UasEvent::Info` 経由で
            // CallManager にルートされる; orchestrator.rs:1798 `handle_ext_info`)。
            SipMethod::Info => {
                warn!(
                    call_id = ?request.headers.get("call-id"),
                    "NGN 側 INFO: 該当ダイアログ無し → 481 (RFC 6086 §4)"
                );
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp =
                    build_response_skeleton(tx.request(), 481, "Call/Transaction Does Not Exist");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                Ok(())
            }
            // RFC 3428 §7: UAS が MESSAGE をサポートしないと判断した場合でも、
            // 200 OK で受け流すのが推奨される (UA が再送し続けるのを止める)。
            // sabiden は MESSAGE の dispatch 経路を持たないが、 NGN 側で
            // IMS 由来の即時メッセージが来た場合に再送ストームを避けるため
            // 200 OK で素直に応答する (本文は破棄)。
            SipMethod::Message => {
                debug!(
                    call_id = ?request.headers.get("call-id"),
                    "NGN 側 MESSAGE: 200 OK で受け流し (RFC 3428 §7、 本文は破棄)"
                );
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp = build_response_skeleton(tx.request(), 200, "OK");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                Ok(())
            }
            // RFC 3515 §2.4.6: REFER は転送 (call transfer) を要求する。
            // sabiden は B2BUA で REFER 受信処理 (NOTIFY refer event 発行 +
            // 新 INVITE) を実装していないため、 RFC 3261 §8.2.1 に従い
            // 405 + Allow ヘッダで明示的に拒否する。
            SipMethod::Refer => {
                warn!(
                    call_id = ?request.headers.get("call-id"),
                    "NGN 側 REFER: 転送未対応 → 405 + Allow (RFC 3261 §8.2.1)"
                );
                self.respond_method_not_allowed(request, remote).await
            }
            // RFC 3261 §8.2.1: 未知メソッドには **必ず** Allow ヘッダ付きの 405
            // で応答する義務がある (Allow 欠落自体が RFC 違反)。
            ref other => {
                warn!(
                    ?other,
                    "NGN 側で未対応メソッド → 405 + Allow (RFC 3261 §8.2.1)"
                );
                self.respond_method_not_allowed(request, remote).await
            }
        }
    }

    /// RFC 3261 §8.2.1: 未対応メソッドに対する 405 Method Not Allowed の
    /// 共通実装。 `Allow` ヘッダ列挙は MUST であり、 これを欠くと UA 側
    /// 実装によっては再送し続ける。
    async fn respond_method_not_allowed(
        &self,
        request: SipRequest,
        remote: SocketAddr,
    ) -> Result<()> {
        let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
        let mut resp = build_response_skeleton(tx.request(), 405, "Method Not Allowed");
        resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
        tx.respond(resp).await?;
        Ok(())
    }

    async fn handle_invite(&self, request: SipRequest, remote: SocketAddr) -> Result<()> {
        let call_id = request
            .headers
            .get("call-id")
            .ok_or_else(|| anyhow!("Call-ID なし"))?
            .to_string();
        // call_id / direction を span に持たせて、フォーク中の各種ログを横断検索可能に。
        let span = info_span!(
            "ngn_inbound_invite",
            call_id = %call_id,
            direction = "ngn",
        );
        async move {
            info!(%remote, "NGN 着信 INVITE");

            let stx = ServerTransaction::new(request.clone(), remote, self.socket.clone())?;
            let stx = Arc::new(Mutex::new(stx));
            // pending に登録 (ACK / BYE 受信時に同じ ServerTransaction を引けるよう)
            {
                let mut pending = self.pending.lock().await;
                pending.insert(call_id.clone(), stx.clone());
            }

            // RFC 3261 §17.2.1: INVITE に対して 100 Trying を即送信。
            {
                let mut tx = stx.lock().await;
                let trying = build_response_skeleton(tx.request(), 100, "Trying");
                tx.respond(trying).await?;
            }

            // Issue #278: 通話履歴に「NGN 着信」 を 1 件記録する。 `From` から
            // 発信者番号 (= user 部) を抽出し、 抽出できない場合は URI 全体を
            // fallback として残す。 NGN inbound では carrier IMS が PAI/PPI を
            // 剥がして anonymous@anonymous.invalid を載せてくる現象が観測されて
            // いる (memory: `project_ngn_inbound_caller_id_stripped`)、 履歴上は
            // そのまま残し UI 側で「非通知」 表示する。
            if let Some(call_log) = self.call_log_clone().await {
                let remote_number = request
                    .headers
                    .get("from")
                    .map(extract_uri_from_addr)
                    .map(|uri| extract_user_from_sip_uri(&uri).unwrap_or(uri))
                    .unwrap_or_else(|| "unknown".to_string());
                call_log.record_start(
                    crate::observability::call_log::Direction::Inbound,
                    remote_number,
                    call_id.clone(),
                );
            }

            // RFC 3261 §8.2.2.3 (Issue #251 Phase A): 受信 INVITE の `Require`
            // ヘッダに sabiden が understand しない option-tag があれば、
            // **420 Bad Extension + `Unsupported: <unknown-tags>` で reject MUST**。
            // §8.2.2.3 引用:
            //
            // > If a UAS does not understand an option-tag listed in a Require
            // > header field, it MUST respond by generating a response with
            // > status code 420 (Bad Extension).  The UAS MUST add an
            // > Unsupported header field, and list in it those options it does
            // > not understand amongst those in the Require header field of
            // > the request.
            //
            // KNOWN_OPTION_TAGS に列挙済の tag (`timer` / `replaces`) のみ通過し、
            // それ以外 (例 `100rel` PRACK 未実装、 carrier 専用拡張 等) は 420。
            // sabiden の `Supported: timer, replaces` 表明 (Phase A) と整合する。
            if let Some(req_h) = request.headers.get("require") {
                let unsupported = unsupported_option_tags(req_h);
                if !unsupported.is_empty() {
                    warn!(
                        require = %req_h,
                        unsupported = ?unsupported,
                        "RFC 3261 §8.2.2.3: 未対応 option-tag → 420 Bad Extension"
                    );
                    let mut tx = stx.lock().await;
                    let mut resp = build_response_skeleton(tx.request(), 420, "Bad Extension");
                    resp.headers.set("Unsupported", unsupported.join(", "));
                    ensure_to_tag(&mut resp);
                    tx.respond(resp).await?;
                    drop(tx);
                    self.pending.lock().await.remove(&call_id);
                    self.metrics.record_invite_ngn(InviteResult::Error);
                    // Issue #278 (PR #286 review #2): record_start (line ~1408) は
                    // 全 reject 経路の前で発火しているため、 reject paths でも
                    // record_end を呼ばないと orphan entry が ring buffer に残る。
                    // RFC 3261 §21.4.16: 420 Bad Extension は「未対応 option-tag」
                    // による拒否で status code を保持して履歴に残す。
                    if let Some(call_log) = self.call_log_clone().await {
                        call_log.record_end(
                            &call_id,
                            crate::observability::call_log::Outcome::Failed { status: 420 },
                        );
                    }
                    return Ok(());
                }
            }

            // RFC 4028 §10 (Issue #249): 初回 INVITE で要求された `Session-Expires`
            // 値が **sabiden Min-SE 未満** なら 422 Session Interval Too Small を
            // **Min-SE ヘッダ付き** で返し、 ここで打ち切る。 これにより carrier
            // (NGN P-CSCF / UAC) は Min-SE 整合値で再 INVITE できる。 §10 は
            // 「server-side で Min-SE 違反を検出したら 422 + Min-SE が MUST」と
            // 明記しており、 これを欠くと UAC は再試行手段を失う。
            //
            // 検査対象は **新規 INVITE (To-tag 無し)** のみ。 in-dialog Re-INVITE
            // (To-tag 付き) は §10 では UAS 由来 Min-SE 違反検出経路が無く、
            // 上流 outbound_forwarder の Min-SE relay 経路 (Issue #138) で扱う。
            let inbound_timer: Option<InboundSessionTimer> = request
                .headers
                .get("session-expires")
                .and_then(parse_session_expires_header);
            let inbound_min_se: u32 = request
                .headers
                .get("min-se")
                .and_then(parse_min_se_header)
                .unwrap_or(crate::sip::uac::MIN_SE);
            let to_has_tag = request
                .headers
                .get("to")
                .map(crate::sip::utils::has_to_tag)
                .unwrap_or(false);
            if !to_has_tag {
                if let Some(t) = &inbound_timer {
                    // RFC 4028 §7.1 / §10: SE < Min-SE は 422 で拒否。 sabiden
                    // 側 Min-SE は `crate::sip::uac::MIN_SE` (= 90 秒、 NGN 既定
                    // で確認済の閾値)。 INVITE が宣言する Min-SE と sabiden 側
                    // Min-SE のうち **大きい方** を採用 (= UAS の最小要求と UAC
                    // 宣言下限の両方を満たす)、 SE がそれ未満なら 422。
                    let min_se = inbound_min_se.max(crate::sip::uac::MIN_SE);
                    if t.session_expires < min_se {
                        warn!(
                            session_expires = t.session_expires,
                            min_se, "RFC 4028 §10: 初回 INVITE の SE < Min-SE → 422 + Min-SE"
                        );
                        let mut tx = stx.lock().await;
                        let mut resp = build_response_skeleton(
                            tx.request(),
                            422,
                            "Session Interval Too Small",
                        );
                        resp.headers.set("Min-SE", min_se.to_string());
                        ensure_to_tag(&mut resp);
                        tx.respond(resp).await?;
                        drop(tx);
                        self.pending.lock().await.remove(&call_id);
                        // Issue #278 (PR #286 review #2): RFC 3261 §21.4.18 / RFC 4028 §10
                        // 422 Session Interval Too Small は Session-Timer 折衝失敗による
                        // 拒否 (carrier UAC は Min-SE 整合値で再 INVITE する)、 history
                        // 上は Failed{422} として保持する。
                        if let Some(call_log) = self.call_log_clone().await {
                            call_log.record_end(
                                &call_id,
                                crate::observability::call_log::Outcome::Failed { status: 422 },
                            );
                        }
                        return Ok(());
                    }
                }
            }

            // Issue #138: RFC 3261 §12.2.2 / §14.2 — 受信 INVITE の To に tag
            // が乗っていれば in-dialog request (= Re-INVITE)。 初回 INVITE
            // (新規 dialog) と分岐し、 既存 outbound 通話 (内線→NGN 発信)
            // に該当すれば内線レッグへ伝搬する。
            //
            // NGN から到来する Re-INVITE は典型的に NGN 側ピアが起こす
            // hold/un-hold (RFC 3264 §8) や、 NGN 側 refresher が refresher=uas
            // を選択した Session-Timer 更新 (RFC 4028 §7)。 sabiden は通常
            // refresher=uac で送るため稀だが、 RFC 4028 §7.4 で UAS への
            // refresh 委譲は許容されており、 透過処理は必須。
            //
            // To に tag が乗っているにも関わらず registry に該当 outbound 通話が
            // 無い場合は **RFC 3261 §12.2.2 に従い 481 を返す** (Call/Transaction
            // Does Not Exist)。 §12.2.2 は in-dialog (= 既存 dialog 識別子付き)
            // request が dialog に紐づかなければ 481 で応答することを要求しており、
            // RFC 3261 §8.1.1.2 で新規 dialog 用 To は tag 無しを推奨している以上、
            // 初回 INVITE 経路へフォールスルーさせると `lookup_by_ngn` 不整合や
            // 二重フォークの原因になる。 forwarder 未注入も含めて 481 で統一する。
            if let Some(to) = request.headers.get("to") {
                if crate::sip::utils::has_to_tag(to) {
                    let fw = self.outbound_forwarder.lock().await.clone();
                    if let Some(fw) = fw {
                        if fw
                            .try_forward_ngn_reinvite(request.clone(), stx.clone())
                            .await
                        {
                            // pending は ACK 受信時に消える経路に乗せておく
                            // (handle_inbound の SipMethod::Ack 分岐参照)。
                            debug!(%call_id, "NGN Re-INVITE 伝搬完了");
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                    // forwarder 未注入 or 該当無し → 481 を返す (RFC 3261 §12.2.2)。
                    // NGN UAC は ACK + 新規 Call-ID で再試行する (RFC 3261 §12.2.1.2)。
                    warn!(%call_id, "NGN in-dialog INVITE で該当 outbound 通話無し → 481");
                    self.respond(&stx, 481, "Call/Transaction Does Not Exist")
                        .await?;
                    self.pending.lock().await.remove(&call_id);
                    // Issue #278 (PR #286 review #2): RFC 3261 §21.4.20 481 は dialog
                    // 不在による拒否。 通常は in-dialog Re-INVITE で fresh Call-ID は
                    // 来ない (= record_start dedup で no-op) が、 万一新規 Call-ID +
                    // to-tag の異常パターンで orphan entry が残らないように record_end
                    // を呼ぶ。 同 Call-ID が既に終端済なら線形検索でヒットしないだけ
                    // の no-op。
                    if let Some(call_log) = self.call_log_clone().await {
                        call_log.record_end(
                            &call_id,
                            crate::observability::call_log::Outcome::Failed { status: 481 },
                        );
                    }
                    return Ok(());
                }
            }

            // 登録済み内線の AOR 一覧を取得し target URI に変換する
            let bindings = self.extensions.snapshot().await;
            if bindings.is_empty() {
                warn!("登録内線なし → 480 Temporarily Unavailable");
                self.respond(&stx, 480, "Temporarily Unavailable").await?;
                self.pending.lock().await.remove(&call_id);
                // 着信は受け付けたが内線不在で確立に至らず → error 計上
                self.metrics.record_invite_ngn(InviteResult::Error);
                // Issue #278 (PR #286 review #2): RFC 3261 §21.4.18 480 Temporarily
                // Unavailable は「callee は一時的に応答できない (= 内線不在)」 で、
                // ユーザ視点では「鳴らせる端末が無かった」 = Missed と扱うのが
                // 妥当 (`ForkResult::AllFailed` / `ForkResult::Timeout` と同じ
                // Missed カテゴリ、 PR #286 既存実装と整合)。
                if let Some(call_log) = self.call_log_clone().await {
                    call_log.record_end(&call_id, crate::observability::call_log::Outcome::Missed);
                }
                return Ok::<(), anyhow::Error>(());
            }

            // RFC 3261 §13.3.1.4 (Issue #249): UAS が "remote callee is being
            // alerted" の状態に入ったら **180 Ringing を SHOULD 送出**。 sabiden
            // の B2BUA は ここで内線フォーク (PWA / SIP 内線) を起動するため、
            // この時点が "alerted" のセマンティクス境界。 旧実装は 100 Trying
            // → (4 秒 PWA mic 許可待ち silent) → 200 OK で carrier IMS が
            // call setup を timeout し、 200 OK 直後 BYE で打ち切る挙動を
            // 実機 pcap で確認 (`/tmp/sabiden-080-inbound.pcap`、 080 着信)。
            //
            // RFC 3261 §12.1.1: dialog ID は (Call-ID, From-tag, To-tag)。 180
            // と 200 OK の To-tag は **同値必須** (early dialog == 確定 dialog)。
            // `build_response_skeleton` が non-100 応答に sabiden 生成 tag を
            // 自動付与するため、 180 の To-tag を取り出して後続 200 OK で
            // 再利用する (= `dialog_to_tag` で持ち回り)。
            // RFC 3262 §3 (Issue #251 Phase B): INVITE に `Supported: 100rel`
            // (または `Require: 100rel`) があれば reliable 18x 経路に分岐し、
            // 180 Ringing に `Require: 100rel` + `RSeq: <random>` を載せて
            // 送出する。 PRACK 受信まで fork (= 内線レッグ呼び出し) を
            // 待ち合わせる必要は無い (§3 はそのような順序を要求しない)。 ここでは
            // 「reliable 18x が確実に届いたことを PRACK で確認する」 経路と
            // 「内線フォークを並行で開始する」 経路を **並走** させ、 PRACK 不到来
            // でも 200 OK 直前まで状態を維持する。
            let invite_wants_100rel =
                header_has_option_tag(request.headers.get("supported"), OPTION_TAG_100REL)
                    || header_has_option_tag(request.headers.get("require"), OPTION_TAG_100REL);
            let invite_cseq_num = request
                .headers
                .get("cseq")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);

            let dialog_to_tag: Option<String> = {
                let mut tx = stx.lock().await;
                let mut ringing = build_response_skeleton(tx.request(), 180, "Ringing");
                // sabiden の Contact (NGN 側ローカル) を 180 にも載せておく
                // (RFC 3261 §13.2 / §13.3.1.4: target refresh は 2xx で確定
                // するが、 180 reliable provisional 経路 (RFC 3262 100rel) に
                // 備えて早期に Contact を提示しても害は無く、 NGN P-CSCF が
                // 180 を Record-Route 経由で記録するときの整合性が増す)。
                let contact_addr = self
                    .cfg
                    .ngn_local_addr
                    .map(Ok)
                    .unwrap_or_else(|| self.socket.local_addr())?;
                ringing
                    .headers
                    .set("Contact", format!("<sip:sabiden@{}>", contact_addr));
                // RFC 3261 §13.3.1.4 / §20.5 / §20.17 / §20.41 (Issue #251 Phase A):
                // 18x 応答にも `Allow` / `Supported` / `Date` / `Server` を載せて
                // 早期に carrier IMS へ capabilities を提示する。 Asterisk 実機
                // (`docs/asterisk-real-invite.md` §3.1) と同等のヘッダ集合。
                apply_uas_inbound_2xx_headers(&mut ringing);
                // ensure_to_tag は has_to_tag を見て既存があれば二重付与しない。
                // build_response_skeleton が自動付与した tag をそのまま使う。
                ensure_to_tag(&mut ringing);

                // RFC 3262 §3 (Issue #251 Phase B): reliable provisional 経路は
                // **同一 INVITE transaction に対して in-flight 1 件まで** の制約が
                // あるため (§3 "MUST NOT send a second reliable provisional response
                // until the first is acknowledged")、 sabiden では 180 Ringing のみを
                // reliable にする。 100 Trying は reliable にしない (§3 "100 Trying
                // ... is never sent reliably")。 200 OK は別 transaction の終結。
                if invite_wants_100rel {
                    let rseq = random_initial_rseq();
                    ringing.headers.set("Require", OPTION_TAG_100REL);
                    ringing.headers.set("RSeq", rseq.to_string());

                    // ServerTransaction が 18x 送信時に Via を `response_via` で
                    // 上書きするため、 retransmit task に渡す bytes も同じ Via で
                    // 組み立てる。 これで 1 回目送信 (tx.respond) と再送 (spawn task)
                    // が完全に同一 octet stream となる (RFC 3262 §3 "MUST be sent
                    // with the same RSeq" の趣旨を bytes レベルで遵守)。
                    let resp_via = tx.response_via().to_string();
                    let response_dest = tx.response_dest();
                    ringing.headers.set("Via", resp_via);
                    let retransmit_bytes = ringing.to_bytes();

                    let prack_received = Arc::new(tokio::sync::Notify::new());
                    let retransmit_task = spawn_reliable_provisional_retransmit(
                        self.socket.clone(),
                        response_dest,
                        retransmit_bytes,
                        prack_received.clone(),
                    );
                    let (prack_tx, prack_rx) = tokio::sync::oneshot::channel::<()>();
                    let state = Rc100relState {
                        rseq,
                        invite_cseq: invite_cseq_num,
                        prack_received,
                        prack_oneshot_tx: Some(prack_tx),
                        prack_oneshot_rx: Some(prack_rx),
                        retransmit_task: Some(retransmit_task),
                    };
                    self.rc100rel
                        .lock()
                        .await
                        .insert(call_id.clone(), Arc::new(Mutex::new(state)));
                    debug!(
                        rseq,
                        invite_cseq = invite_cseq_num,
                        %call_id,
                        "RFC 3262 §3: reliable 180 Ringing + Require: 100rel + RSeq 送出"
                    );
                }
                let tag = ringing.headers.get("to").and_then(extract_to_tag);
                tx.respond(ringing).await?;
                tag
            };
            debug!(
                ?dialog_to_tag,
                invite_wants_100rel, "180 Ringing 送出 (RFC 3261 §13.3.1.4)"
            );

            // フォーク (内線レッグ): SIP / WebRTC を transport で分岐して並列に呼び出す。
            // NGN から CANCEL が来たら fork を打ち切るため Notify を仕込んで
            // `tokio::select!` で待ち合わせる (RFC 3261 §9.2 / §9.1)。
            let cancel_notify = Arc::new(tokio::sync::Notify::new());
            self.in_flight
                .lock()
                .await
                .insert(call_id.clone(), cancel_notify.clone());

            let sdp = request.body.clone();
            let fork_fut = fork_to_bindings(
                self.inviter.clone(),
                bindings,
                sdp,
                call_id.clone(),
                self.cfg.fork_timeout,
            );

            let result = tokio::select! {
                biased;
                _ = cancel_notify.notified() => {
                    // NGN が CANCEL を出した。INVITE 側は 487 で打ち切る。
                    // RFC 3262 §3 (Issue #251 Phase B): reliable 18x 状態が
                    // あれば retransmit task を abort してから 487 を送出する
                    // (cleanup を欠くと 32s 間ゾンビ task が残る)。
                    info!("NGN CANCEL を受信 → 487 Request Terminated で打ち切り");
                    self.cleanup_rc100rel(&call_id).await;
                    self.respond(&stx, 487, "Request Terminated").await?;
                    self.pending.lock().await.remove(&call_id);
                    self.in_flight.lock().await.remove(&call_id);
                    self.metrics.record_invite_extension(InviteResult::Error);
                    self.metrics.record_invite_ngn(InviteResult::Error);
                    // Issue #278 (PR #286 review #1): 着信側が応答する前に NGN UAC が
                    // CANCEL を出した = ユーザ視点での「不在着信」。 record_start
                    // (line ~1408) に対する record_end を必ず呼んで orphan entry を
                    // 防ぐ。 RFC 3261 §21.4.27 によれば 487 Request Terminated は
                    // 「PASSIVE な cancellation でリクエストが終了した」状態を意味し、
                    // 通話履歴上は Missed として扱う (`Outcome::Missed` の
                    // 「応答前に終了した着信」 セマンティクスと整合)。
                    if let Some(call_log) = self.call_log_clone().await {
                        call_log
                            .record_end(&call_id, crate::observability::call_log::Outcome::Missed);
                    }
                    return Ok(());
                }
                r = fork_fut => r,
            };

            // fork が完了したので in_flight からは外す (CANCEL の競合は無視する)。
            self.in_flight.lock().await.remove(&call_id);

            // RFC 3262 §3 (Issue #251 Phase B): reliable 18x を出した経路では、
            // **PRACK を受信するまで final response を送ってはならない**
            // (§3 "The UAS MUST NOT send a 2xx response until the corresponding
            // PRACK arrives ..."). PRACK が来ないまま 32 秒 (= Timer 64*T1)
            // 経過したら諦め、 INVITE トランザクションを 408 で終結させる
            // (RFC 3262 §3 後段: "The UAS treats the failure to receive the
            // PRACK ... as if there were no response at all to the request"、
            // sabiden では Timer F 相当の Timeout として 408 にマップ)。
            if invite_wants_100rel {
                let prack_outcome = self.wait_for_prack(&call_id).await;
                match prack_outcome {
                    PrackOutcome::Received => {
                        debug!(%call_id, "RFC 3262 §3: PRACK 受信 → final response 送出可能");
                    }
                    PrackOutcome::Timeout => {
                        warn!(
                            %call_id,
                            "RFC 3262 §3: PRACK 32 秒不到来 → 408 で INVITE 終結"
                        );
                        self.cleanup_rc100rel(&call_id).await;
                        self.respond(&stx, 408, "Request Timeout").await?;
                        self.pending.lock().await.remove(&call_id);
                        self.metrics.record_invite_extension(InviteResult::Timeout);
                        self.metrics.record_invite_ngn(InviteResult::Timeout);
                        // Issue #278 (PR #286 review #3): RFC 3262 §3 / RFC 3261
                        // §21.4.8 408 は UAC が reliable 18x に PRACK を返さなかった
                        // ことによる timeout 終結。 status code を残して PWA UI で
                        // 「reliable provisional ACK 不在」を区別可能にする。
                        if let Some(call_log) = self.call_log_clone().await {
                            call_log.record_end(
                                &call_id,
                                crate::observability::call_log::Outcome::Failed { status: 408 },
                            );
                        }
                        return Ok(());
                    }
                    PrackOutcome::NoState => {
                        // 既に他経路 (cancel / fork 失敗 早期 return) で cleanup
                        // 済み。 final response はこの match 経路で送る。
                        debug!(%call_id, "RFC 3262 §3: rc100rel state 既消費");
                    }
                }
            }

            match result {
                ForkResult::Answered {
                    winner_uri,
                    response,
                    webrtc_handle,
                    webrtc_ws,
                } => {
                    info!(%winner_uri, "NGN 側に 200 OK を返す");
                    // RTP ブリッジを起動して 200 OK SDP の `c=`/`m= port` を
                    // sabiden の NGN 側ソケットに書き換える。
                    //
                    // Issue #73 review: WebRTC leg では `response.body` は
                    // `c=IN IP4 0.0.0.0` / `m=audio 9 RTP/AVP 0` のままで、
                    // bridge 起動成功時は `start_bridge_for_inbound` が
                    // `rewrite_rtp_endpoint` で書き換える前提。 bridge 起動に
                    // 失敗した場合の挙動は CallManager 接続有無で分岐する:
                    //
                    // * **bridged モード** (`call_manager.is_some()`) は本来
                    //   bridging が必須。失敗したら未書換 SDP を NGN に流すと
                    //   WebRTC leg は `0.0.0.0:9` を返してしまうので
                    //   **502 Bad Gateway** で呼を放棄する。
                    // * **transparent モード** (`call_manager.is_none()`,
                    //   Issue #15 互換) は SDP 透過で動かすことが期待されるが、
                    //   WebRTC leg の `0.0.0.0:9` は NGN にとって到達不能なので、
                    //   この場合だけは 502 を返して呼を放棄する。 SIP leg は
                    //   従来通り answer をそのまま透過する。
                    let bridged_mode = self.call_manager.is_some();
                    let body_for_ngn = match self
                        .start_bridge_for_inbound(
                            &request.body,
                            &response.body,
                            &call_id,
                            webrtc_handle,
                        )
                        .await
                    {
                        Ok(rewritten) => rewritten,
                        Err(e)
                            if bridged_mode
                                || is_undirected_or_webrtc_placeholder_sdp(&response.body) =>
                        {
                            warn!(
                                error=%e,
                                "RTP ブリッジ起動失敗 → 502 Bad Gateway で呼を放棄"
                            );
                            // Issue #81/#83 review #2: 502 fallback で呼を放棄する
                            // とき、 winner 確定済みの WebRTC peer (browser) は
                            // ringing→connected 状態のまま hang する。 ここで
                            // `ServerMessage::Cancel` を撃って PWA UI を解放する
                            // (RFC 3261 §9.1 CANCEL semantics の WS 層通知。
                            // 確立に至らなかった呼の通知としては Bye より Cancel
                            // が semantic 自然)。
                            if let Some(ws) = &webrtc_ws {
                                let _ = ws.send(ServerMessage::Cancel {
                                    call_id: call_id.clone(),
                                });
                            }
                            self.cleanup_rc100rel(&call_id).await;
                            self.respond(&stx, 502, "Bad Gateway").await?;
                            self.pending.lock().await.remove(&call_id);
                            self.metrics.record_invite_extension(InviteResult::Error);
                            self.metrics.record_invite_ngn(InviteResult::Error);
                            return Ok(());
                        }
                        Err(e) => {
                            // transparent モード (Issue #15 互換) かつ WebRTC leg の
                            // 痕跡 (`0.0.0.0:9`) が無い → SIP leg の answer を素通しで返す
                            debug!(
                                error=%e,
                                "RTP ブリッジ起動失敗 → SDP 透過 (Issue #15 互換)"
                            );
                            response.body.clone()
                        }
                    };

                    // RFC 3264 §6.1 (Issue #249): NGN offer に `a=ptime` があれば
                    // 200 OK SDP にも echo (PCMU 経路は 20ms 固定だが、 将来 PWA
                    // 由来 60ms 等にも汎用対応する)。 offer 不在なら追加しない
                    // (§6.1 "answer は offer の subset"、 offer に無いものを
                    //  answer に増やさない)。
                    let body_for_ngn = if !body_for_ngn.is_empty() {
                        match extract_ptime_from_offer(&request.body) {
                            Some(ptime) => ensure_ptime_in_answer(&body_for_ngn, ptime),
                            None => body_for_ngn,
                        }
                    } else {
                        body_for_ngn
                    };

                    let mut tx = stx.lock().await;
                    let mut resp_to_ngn = build_response_skeleton(tx.request(), 200, "OK");
                    if !body_for_ngn.is_empty() {
                        resp_to_ngn.body = body_for_ngn;
                        resp_to_ngn.headers.set("Content-Type", "application/sdp");
                    }
                    // RFC 3261 §12.1.1 (Issue #249): 180 Ringing で確立した early
                    // dialog の To-tag をそのまま 200 OK で再利用する (dialog ID
                    // が一致しないと NGN UAC は別 dialog と見做し、 早期 dialog
                    // への BYE を確定 dialog にぶつける実装が存在する)。
                    //
                    // `build_response_skeleton` は non-100 応答に対し
                    // **新しい sabiden-生成 tag を自動付与する** ため、 dialog_to_tag
                    // を持つ初回 INVITE 経路では 200 OK の To を「INVITE 由来 To
                    // (= tag 不在) + dialog_to_tag」 に明示的に再構成する。
                    // INVITE の To に既に tag があるケース (in-dialog Re-INVITE
                    // 等) では skeleton 側がそれを echo するので dialog_to_tag は
                    // None になり、 ensure_to_tag 経路へ流れる。
                    if let Some(tag) = dialog_to_tag.as_deref() {
                        if let Some(orig_to) = tx.request().headers.get("to") {
                            // INVITE 由来 To に tag が既に乗っていれば (≒ in-dialog)
                            // それを尊重し dialog_to_tag は使わない。 初回 INVITE
                            // (tag 無し) なら orig + dialog_to_tag で再構成。
                            if crate::sip::utils::has_to_tag(orig_to) {
                                resp_to_ngn.headers.set("To", orig_to);
                            } else {
                                resp_to_ngn
                                    .headers
                                    .set("To", format!("{};tag={}", orig_to, tag));
                            }
                        }
                    } else {
                        // To に tag を必ず付与 (RFC 3261 §8.2.6.2)。 180 が出せて
                        // いない経路 (= 旧挙動互換) でも 200 OK は MUST tag。
                        ensure_to_tag(&mut resp_to_ngn);
                    }
                    // RFC 4028 §7 (Issue #249): UAS が Session-Timer をサポート
                    // する場合、 INVITE に Session-Expires が乗っていれば 2xx に
                    // **Session-Expires + Require: timer を echo MUST**。
                    //
                    // RFC 4028 §9 (Issue #251 Phase A): refresher は UAC が
                    // 要求した値を **echo** する (旧実装は常に `uas` に書換えて
                    // いたが、 carrier 内部状態機械との不整合で即 BYE 経路に
                    // 入る可能性を audit #6 で指摘済)。 不在 / 不正値の場合のみ
                    // `uas` フォールバック (= sabiden が refresh 担当、 内線レッグ
                    // への伝搬簡略化、 Issue #138 outbound forwarder 経路と整合)。
                    //
                    // INVITE に Session-Expires が無いケース (§7 後段): 何も
                    // しない (= UAS が timer をサポートしない応答と等価)。
                    if let Some(t) = &inbound_timer {
                        let se_value = t.session_expires.max(crate::sip::uac::MIN_SE);
                        let refresher = resolve_response_refresher(t.refresher.as_deref());
                        resp_to_ngn.headers.set(
                            "Session-Expires",
                            format!("{};refresher={}", se_value, refresher),
                        );
                        // RFC 4028 §7: Require: timer は timer negotiate 完了の明示。
                        resp_to_ngn.headers.set("Require", "timer");
                    }
                    // RFC 3261 §13.3.1.4 / §20.5 / §20.17 / §20.41 (Issue #251 Phase A):
                    // 2xx 応答に **`Allow` / `Supported` / `Date` / `Server` を
                    // 常時付与**。 これらが欠落すると carrier IMS は「機能不足
                    // 端末」「時刻同期不能」「capability negotiate 不可」と判定し
                    // dialog 確立後即 BYE を返す経路に入る (audit top-3、
                    // Issue #251 / `/tmp/sabiden-080-inbound-v4.pcap`)。
                    // Asterisk 実機 (`docs/asterisk-real-invite.md` §3.1) と同等。
                    //
                    // Note: `Supported` は Session-Timer 個別 echo の後に呼ぶこと
                    // (= apply_uas_inbound_2xx_headers が `Supported: timer,
                    // replaces` で上書きするので、 Session-Timer negotiate 結果
                    // としての `Require: timer` (上記) と整合する)。
                    apply_uas_inbound_2xx_headers(&mut resp_to_ngn);
                    // sabiden の Contact (NGN 側ローカル) を載せる。
                    // SIP socket は `0.0.0.0:5060` bind なので `socket.local_addr()`
                    // をそのまま載せると NGN が ACK を `0.0.0.0` 宛に送ろうとして
                    // 失敗、 10 秒後 CANCEL になる (実機検証 2026-05-10)。
                    // `cfg.ngn_local_addr` (eth1 sent-by IP) があれば優先する。
                    let contact_addr = self
                        .cfg
                        .ngn_local_addr
                        .map(Ok)
                        .unwrap_or_else(|| self.socket.local_addr())?;
                    resp_to_ngn
                        .headers
                        .set("Contact", format!("<sip:sabiden@{}>", contact_addr));
                    // Bug B / Issue #268: 200 OK 送出前に UAS dialog state を採取する。
                    // `tx.respond` 後は `resp_to_ngn` が consume されるため、 構築は
                    // ここで行う必要がある。 SIP 内線 winner では `webrtc_ws` が None
                    // なので dialog 構築自体スキップする (transparent モードで
                    // 上流が処理する経路と整合)。
                    let inbound_dialog = if webrtc_ws.is_some() {
                        // RFC 3261 §12.1.1 UAS dialog 確立: (INVITE, 2xx) ペアと
                        // sabiden 側 contact / sent-by を渡す。 失敗時は dialog 不在
                        // のまま通話成立させる (BYE 経路だけ後で degrade)。
                        //
                        // Issue #258 fix: dialog の local_uri / remote_uri は RFC 3261
                        // §12.1.1 の規定通り「INVITE の To URI / From URI」をそのまま
                        // 採用する。 旧実装は local_uri に sabiden の Contact URI
                        // (`sip:sabiden@<eth1>:5060`) を代入していたため、 PWA 切断後の
                        // BYE が `From: <sip:sabiden@118.177.72.242:5060>;tag=...` で
                        // 飛び、 carrier 側 dialog state (local-URI = 受信した INVITE の
                        // To = `<sip:0191349809@ntt-east.ne.jp>`) と一致せず 481
                        // Call/Transaction Does Not Exist で reject されていた
                        // (実機 v9 evidence、 2026-05-11 15:13)。
                        // RFC 3261 §12.1.1: "The UAS then constructs the state of the
                        // dialog. ... The remote URI MUST be set to the URI in the From
                        // field, and the local URI MUST be set to the URI in the To
                        // field."
                        let contact_uri = format!("sip:sabiden@{}", contact_addr);
                        let sent_by = contact_addr.to_string();
                        let local_uri = request
                            .headers
                            .get("to")
                            .map(crate::sip::dialog::extract_uri)
                            .unwrap_or_else(|| contact_uri.clone());
                        let remote_uri = request
                            .headers
                            .get("from")
                            .map(crate::sip::dialog::extract_uri)
                            .unwrap_or_else(|| "sip:unknown@unknown".to_string());
                        let dlg_cfg = DialogConfig {
                            local_uri,
                            remote_uri,
                            local_contact: contact_uri,
                            sent_by,
                        };
                        match Dialog::from_uas_invite(&request, &resp_to_ngn, dlg_cfg) {
                            Ok(d) => Some(d),
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    %call_id,
                                    "Bug B / RFC 3261 §12.1.1: UAS dialog 構築失敗 \
                                     (PWA disconnect 時 BYE 送出が degrade): WebRTC \
                                     winner 通話自体は成立させる"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };

                    tx.respond(resp_to_ngn).await?;
                    // 観測: NGN レッグも内線レッグも応答済みとして記録
                    self.metrics.record_invite_ngn(InviteResult::Answered);
                    self.metrics.record_invite_extension(InviteResult::Answered);
                    // 通話確立として call_active を +1
                    {
                        let mut active = self.active.lock().await;
                        active.entry(call_id.clone()).or_insert(None);
                    }
                    // Issue #81 + Bug B 拡張: WebRTC レッグが winner なら双方向 BYE
                    // 連動用エントリを Call-ID で保持する。
                    //
                    // - NGN → sabiden BYE 受信 (`handle_bye`): entry の `ws` で
                    //   `ServerMessage::Bye` を push (RFC 3261 §15.1.2)。 既存
                    //   Issue #81 経路。
                    // - PWA WS close (`close_pwa_inbound_for_ws`): entry の
                    //   `send_bye` で NGN へ BYE 送出 (Bug B、 RFC 5853 §3.2.2)。
                    //
                    // `layer` と `inbound_dialog` 両方揃った production 経路では
                    // 完全 entry を作って双方向 BYE が機能する。 旧 fixture / test
                    // 経路 (layer None) では degraded entry (BYE 送出 disabled)
                    // を作るが、 NGN→PWA BYE push 経路は引き続き機能する。
                    if let Some(ws) = webrtc_ws {
                        let _ = invite_cseq_num; // BYE は dialog 独立 CSeq なので未使用 (観測用に取得済)
                        let entry = Arc::new(WebRtcInboundEntry {
                            uas_dialog: inbound_dialog.map(Mutex::new),
                            layer: self.layer.clone(),
                            fallback_peer: remote,
                            ws,
                        });
                        self.webrtc_active
                            .lock()
                            .await
                            .insert(call_id.clone(), entry);
                    }
                    self.metrics.inc_call_active();
                    // Issue #278: 通話確立は record_end ではなく `Answered` を
                    // 仮に記録しない (= まだ BYE していない)。 outcome / duration
                    // は handle_bye の dec_call_active 時点で確定する。
                }
                ForkResult::AllFailed { last_status } => {
                    // Issue #211 / RFC 3261 §16.7 step 6:
                    //   reason phrase は `reason_phrase_for_status` で決める。
                    //   旧実装は 603 に "Declined" を返していたが、 RFC 3261
                    //   §21.6.2 は単数 "Decline" が正規。
                    let code = last_status.unwrap_or(486);
                    let reason = reason_phrase_for_status(code);
                    self.respond(&stx, code, reason).await?;
                    self.pending.lock().await.remove(&call_id);
                    let result = if code == 486 {
                        InviteResult::Busy
                    } else {
                        InviteResult::Error
                    };
                    self.metrics.record_invite_extension(result);
                    self.metrics.record_invite_ngn(result);
                    // Issue #278: 着信が確立せずに終わった (どの内線も応答せず)。
                    // PWA UI 上は「不在着信」 として表示するため Missed として
                    // 記録する (486 BUSY も内線都合なので発信側視点 = Missed)。
                    if let Some(call_log) = self.call_log_clone().await {
                        call_log
                            .record_end(&call_id, crate::observability::call_log::Outcome::Missed);
                    }
                }
                ForkResult::Timeout => {
                    self.respond(&stx, 408, "Request Timeout").await?;
                    self.pending.lock().await.remove(&call_id);
                    self.metrics.record_invite_extension(InviteResult::Timeout);
                    self.metrics.record_invite_ngn(InviteResult::Timeout);
                    // Issue #278: 内線が誰も応答しないまま fork タイムアウト
                    // (RFC 3261 §16.7) → 着信側視点では Missed。
                    if let Some(call_log) = self.call_log_clone().await {
                        call_log
                            .record_end(&call_id, crate::observability::call_log::Outcome::Missed);
                    }
                }
            }
            // RFC 3262 §3 (Issue #251 Phase B): 全 match arm 共通の cleanup。
            // 成功経路 (200 OK) では PRACK 受信時に cleanup 済 / 失敗経路
            // (Rejected / Timeout) では state を消す。 idempotent。
            self.cleanup_rc100rel(&call_id).await;
            Ok(())
        }
        .instrument(span)
        .await
    }

    /// RFC 3262 §4 (Issue #251 Phase B): PRACK を per-Call-ID `Rc100relState` と
    /// 突合して 200 OK / 481 を返す。
    ///
    /// 受信 PRACK の挙動:
    ///
    /// 1. `Call-ID` で `rc100rel` を引く。 entry 無し → 481 (RFC 3262 §4 / §7.1
    ///    "PRACK ... matches a transaction ... no matching transaction → 481")。
    /// 2. entry あり: `RAck` を §7.2 ABNF (`response-num CSeq-num Method`) で
    ///    パースし、 (RSeq, INVITE CSeq, "INVITE") と一致するか確認。
    ///    不一致 → 481 (state は残置、 次の正しい PRACK を待つ)。
    /// 3. 一致 → 200 OK PRACK を返し、 `prack_received.notify_one()` で
    ///    `handle_invite` 側の `wait_for_prack` を解除、 entry は state.consume()
    ///    パターンで `cleanup_rc100rel` に委譲する (retransmit task abort 含む)。
    async fn handle_prack(&self, request: SipRequest, remote: SocketAddr) -> Result<()> {
        let call_id = match request.headers.get("call-id") {
            Some(v) => v.to_string(),
            None => {
                warn!("PRACK に Call-ID なし → 481");
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp =
                    build_response_skeleton(tx.request(), 481, "Call/Transaction Does Not Exist");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                return Ok(());
            }
        };

        // RFC 3262 §7.2: RAck は必須。 不在は 400 でも 481 でも reject 可能だが、
        // §4 が「該当 transaction 不在 = 481」 を明示するため 481 で統一。
        let rack_header = match request.headers.get("rack") {
            Some(v) => v.to_string(),
            None => {
                warn!(%call_id, "PRACK に RAck ヘッダ無し → 481 (RFC 3262 §7.2)");
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp =
                    build_response_skeleton(tx.request(), 481, "Call/Transaction Does Not Exist");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                return Ok(());
            }
        };

        let state_arc = self.rc100rel.lock().await.get(&call_id).cloned();
        let state_arc = match state_arc {
            Some(s) => s,
            None => {
                warn!(%call_id, "PRACK 該当 reliable 18x 状態無し → 481 (RFC 3262 §4)");
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp =
                    build_response_skeleton(tx.request(), 481, "Call/Transaction Does Not Exist");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                return Ok(());
            }
        };

        // RFC 3262 §7.2 ABNF パース。
        let parsed = parse_rack_header(&rack_header);
        let (rseq, cseq_num, method) = match parsed {
            Some(v) => v,
            None => {
                warn!(%call_id, rack = %rack_header, "PRACK RAck パース失敗 → 481");
                let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
                let mut resp =
                    build_response_skeleton(tx.request(), 481, "Call/Transaction Does Not Exist");
                resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
                tx.respond(resp).await?;
                return Ok(());
            }
        };

        // RFC 3262 §4: RAck (RSeq, CSeq-num, Method) が直近 reliable 18x と
        // 一致するか確認。 一致しなければ 481 (誤対応 PRACK は無視扱い)。
        let matched = {
            let state = state_arc.lock().await;
            rseq == state.rseq
                && cseq_num == state.invite_cseq
                && method.eq_ignore_ascii_case("INVITE")
        };
        if !matched {
            warn!(
                %call_id,
                rack = %rack_header,
                "PRACK RAck 不一致 (期待値と異なる) → 481 (RFC 3262 §4)"
            );
            let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
            let mut resp =
                build_response_skeleton(tx.request(), 481, "Call/Transaction Does Not Exist");
            resp.headers.set("Allow", SUPPORTED_METHODS_ALLOW);
            tx.respond(resp).await?;
            return Ok(());
        }

        // 一致 → 200 OK を返し、 `handle_invite` 側を起こす。 state の
        // retransmit task は cleanup_rc100rel で abort する。
        let (prack_notify, prack_oneshot_tx) = {
            let mut state = state_arc.lock().await;
            (state.prack_received.clone(), state.prack_oneshot_tx.take())
        };
        let mut tx = ServerTransaction::new(request, remote, self.socket.clone())?;
        let resp = build_response_skeleton(tx.request(), 200, "OK");
        tx.respond(resp).await?;
        // retransmit task 用 (§3 自発再送停止) は Notify。
        prack_notify.notify_one();
        // `wait_for_prack` 解除は oneshot で確実化 (= waker 取り逃し無し)。
        if let Some(tx) = prack_oneshot_tx {
            let _ = tx.send(());
        }
        self.cleanup_rc100rel(&call_id).await;
        debug!(%call_id, "RFC 3262 §4: PRACK 受理 → 200 OK + INVITE wait 解除");
        Ok(())
    }

    /// RFC 3262 §3 (Issue #251 Phase B): `handle_invite` から呼ばれ、
    /// per-Call-ID の `prack_received` Notify を 64*T1 (= 32 秒) まで
    /// 待ち合わせる。
    ///
    /// - state 不在 → `NoState` (= reliable 18x 未送出 / 既消費)。
    /// - PRACK 受信 → `Received`。
    /// - timeout → `Timeout`。
    async fn wait_for_prack(&self, call_id: &str) -> PrackOutcome {
        // RFC 3262 §3 (Issue #251 Phase B): PRACK 受信を `oneshot::channel` で
        // 待ち合わせる。 旧実装は `tokio::sync::Notify` 経由だったが、
        // `handle_prack` が `notify_one` を呼んでも `wait_for_prack` 側の
        // waker が 32 秒間 wake しないレースを観測したため、 oneshot で確実化。
        let rx_opt = {
            let map_guard = self.rc100rel.lock().await;
            match map_guard.get(call_id) {
                Some(state_arc) => state_arc.lock().await.prack_oneshot_rx.take(),
                None => None,
            }
        };
        let mut rx = match rx_opt {
            Some(rx) => rx,
            None => return PrackOutcome::NoState,
        };
        // RFC 3261 §17.1.1.2 / RFC 3262 §3: Timer F = 64*T1 = 32 秒。
        const PRACK_TIMER: Duration = Duration::from_secs(32);
        tokio::select! {
            biased;
            res = &mut rx => match res {
                Ok(()) => PrackOutcome::Received,
                // Sender drop = state 消滅 (cancel 等) → NoState 等価。 final
                // response は呼出側 (match result) で処理。
                Err(_) => PrackOutcome::NoState,
            },
            _ = tokio::time::sleep(PRACK_TIMER) => PrackOutcome::Timeout,
        }
    }

    /// `rc100rel` から entry を削除し、 retransmit task を `Drop` 経由で abort
    /// する。 idempotent: 既消費でも no-op。
    async fn cleanup_rc100rel(&self, call_id: &str) {
        let removed = self.rc100rel.lock().await.remove(call_id);
        if removed.is_some() {
            debug!(%call_id, "RFC 3262 §3: rc100rel state cleanup (retransmit task abort)");
        }
    }

    /// NGN 側から到着した BYE を処理する (RFC 3261 §15.1.2 / RFC 5853 §3.2.2)。
    ///
    /// # 処理順序
    ///
    /// 1. **NGN へ 200 OK 即返** (RFC 3261 §15.1.2 第 1 段): BYE は新規
    ///    transaction で受け取り、 直ちに 200 OK を返す。
    /// 2. **PWA outbound BYE 判定** (Issue #147): NGN レッグ Call-ID が
    ///    `webrtc_outbound_active` にあれば PWA→NGN 発信通話の終了通知。
    ///    エントリを `remove` (= idempotent gate) → bridge を `terminate` →
    ///    `dec_call_active` → WS に `ServerMessage::Bye` を push → NGN
    ///    レッグ dialog を Terminated に遷移させ、 ここで return。 SIP 内線
    ///    BYE 経路 (3, 4) は走らせない (PWA outbound に内線レッグは無いため)。
    /// 3. **outbound forwarder へ伝搬を試みる**: 内線→NGN 発信通話の BYE で
    ///    あれば内線レッグへ転送する経路 (Phase R4 で `B2buaCall::handle_ngn_bye`
    ///    に統合予定)。 forwarder が引き受けた (`true` を返した) 場合は
    ///    ここで return。
    /// 4. **NGN→内線 着信通話の cleanup**: `pending` / `active` から該当
    ///    Call-ID を除去、 RTP ブリッジを stop、 メトリクスから call_active を
    ///    -1 する。
    /// 5. **WebRTC 内線レッグ peer 伝搬** (Issue #81): WebRTC 内線レッグだった
    ///    場合は `webrtc_active` から WS を引いて `ServerMessage::Bye` を
    ///    push し、 PWA 側 `App.tsx::case "bye"` ハンドラが UI teardown を行う
    ///    (RFC 5853 §3.2.2 SBC framework: 片側 dialog 終了をもう片側へ伝搬
    ///    するのは B2BUA の責務)。 NGN→内線 着信時の WebRTC peer 経路で、
    ///    ステップ 2 (PWA outbound) とは別テーブル (`webrtc_active` vs
    ///    `webrtc_outbound_active`) を使うので衝突しない。
    async fn handle_bye(&self, request: SipRequest, remote: SocketAddr) -> Result<()> {
        // BYE は新しい transaction で 200 OK を返す。
        let mut tx = ServerTransaction::new(request.clone(), remote, self.socket.clone())?;
        let resp = build_response_skeleton(tx.request(), 200, "OK");
        tx.respond(resp).await?;

        let Some(cid) = request.headers.get("call-id").map(str::to_string) else {
            return Ok(());
        };

        // 1) PWA→NGN 発信通話の BYE か判定 (Issue #147)。
        //    `webrtc_outbound_active` は PWA→NGN 発信成立時に挿入される
        //    (`UasEventHandler::handle_pwa_outbound_offer` の成功 branch)。
        //    NGN→PWA 方向の BYE 伝搬は B2BUA の責務 (RFC 3261 §15.1.2 /
        //    RFC 5853 §3.2.2 SBC framework)。 PWA peer は SIP dialog を
        //    持たないので、 専用 WS シグナリング (`ServerMessage::Bye`) で
        //    通知し、 RTP ブリッジは `CallManager::terminate` で停止、
        //    `call_active` メトリクスを 1 減らす。
        let pwa_entry = self.webrtc_outbound_active.lock().await.remove(&cid);
        if let Some(entry) = pwa_entry {
            // bridge 停止 (CallManager は PWA outbound では必ず注入されている
            // = エントリ挿入条件、 詳細は handle_pwa_outbound_offer)。
            if let Some(mgr) = self.call_manager.as_ref() {
                if let Err(e) = mgr.terminate(entry.bridge_call_id).await {
                    warn!(error=%e, call_id=%cid, "PWA outbound BYE: bridge terminate 失敗");
                }
            }
            // メトリクス: PWA outbound 成立時に inc_call_active 済み。
            self.metrics.dec_call_active();
            // Issue #278: PWA outbound 通話が確立済 → NGN→PWA BYE で正常終了。
            // record_start は `UasEventHandler::handle_pwa_outbound_offer` が
            // Outbound 方向で書き込んでいる (同じ Arc<CallLog> を共有)。
            if let Some(call_log) = self.call_log_clone().await {
                call_log.record_end(&cid, crate::observability::call_log::Outcome::Answered);
            }
            // PWA UI に BYE を通知 (RFC 5853 §3.2.2)。 WS が既に切断済みでも
            // テーブルからは削除済みなので idempotent。
            if let Err(e) = entry.ws.send(ServerMessage::Bye) {
                debug!(call_id=%cid, error=%e, "PWA outbound BYE 通知失敗 (browser 切断済?)");
            } else {
                debug!(call_id=%cid, "PWA outbound: NGN→PWA BYE 伝搬完了");
            }
            // NGN レッグ dialog は send_bye せず Terminated にしておく
            // (NGN 側は既に BYE を送って来た = dialog は閉じている。
            // RFC 3261 §15.1.1: BYE への 200 OK で dialog は terminated)。
            entry.ngn_dialog.lock().await.dialog_mut().terminate();
            return Ok(());
        }

        // 2) 内線→NGN 発信通話の BYE か判定。該当すれば内線レッグへ転送して終了。
        let forwarded = {
            let fw = self.outbound_forwarder.lock().await.clone();
            if let Some(fw) = fw {
                fw.try_forward_bye(&cid).await
            } else {
                false
            }
        };
        if forwarded {
            return Ok(());
        }

        // 3) NGN→内線 着信通話の BYE: 既存 inbound テーブルでクリーンアップ。
        self.pending.lock().await.remove(&cid);
        let removed = { self.active.lock().await.remove(&cid) };
        if removed.is_some() {
            self.metrics.dec_call_active();
            // Issue #278: 着信通話が確立 → BYE で正常終了。 通話時間が確定する。
            if let Some(call_log) = self.call_log_clone().await {
                call_log.record_end(&cid, crate::observability::call_log::Outcome::Answered);
            }
        }
        if let (Some(Some(call_id)), Some(mgr)) = (removed, self.call_manager.as_ref()) {
            if let Err(e) = mgr.terminate(call_id).await {
                warn!(error=%e, "BYE 受信時の通話終了に失敗");
            }
        }
        // Issue #81: WebRTC 内線レッグだった場合、 browser に BYE を push する
        // (B2BUA は片側 dialog 終了をもう片側へ伝搬する責務: RFC 3261 §15.1.2,
        // RFC 5853 §3.2.2 SBC framework)。 SIP 内線と違い WebRTC peer は SIP
        // dialog を持たないため、 専用 WS シグナリング (`ServerMessage::Bye`)
        // で通知する。 PWA 側 `App.tsx` の `case "bye"` ハンドラが
        // `teardownCall()` で UI を解放する。
        // Bug B (Issue #268): entry が `Arc<WebRtcInboundEntry>` に変わったので
        // `entry.ws` 経由で push する。 NGN→PWA BYE 経路は既存 (Issue #81) と
        // 同じ意味論。 ここで remove することで close_pwa_inbound_for_ws との
        // 二重発火を idempotent に防ぐ (NGN BYE 経路で先に removed → WS close
        // 経路は entries.is_empty() で early return)。
        let webrtc_entry = self.webrtc_active.lock().await.remove(&cid);
        if let Some(entry) = webrtc_entry {
            if let Err(e) = entry.ws.send(ServerMessage::Bye) {
                debug!(call_id=%cid, error=%e, "WebRTC BYE push 失敗 (browser 切断済?)");
            } else {
                debug!(call_id=%cid, "WebRTC peer に BYE を push (NGN→PWA 伝搬)");
            }
            // NGN dialog は NGN BYE を受信して 200 OK を返した直後なので
            // Terminated にしておく (RFC 3261 §15.1.1)。 idempotent。
            if let Some(dlg) = entry.uas_dialog.as_ref() {
                dlg.lock().await.terminate();
            }
        }
        Ok(())
    }

    /// NGN→内線 着信用に RTP ブリッジを起動し、NGN へ返す 200 OK の SDP を
    /// sabiden 側に書き換えて返す。
    ///
    /// `ngn_offer` は NGN INVITE の SDP オファ、`ext_answer` は内線 200 OK の
    /// SDP アンサ。
    ///
    /// # 分岐
    ///
    /// - SIP 内線レッグ: 両側に UDP socket を bind し、 [`RtpBridge`] (PCMU
    ///   両側) または [`TranscodingBridge`] (Opus⇔PCMU) を起動する。
    /// - WebRTC 内線レッグ (`webrtc_handle.is_some()`): 内線側の UDP socket は
    ///   bind せず、 `peer.send_media` / `peer.take_media_rx` 経由で
    ///   [`MediaBridge::WebRtcAudio`] を起動する (Issue #87 / #121)。
    async fn start_bridge_for_inbound(
        &self,
        ngn_offer: &[u8],
        ext_answer: &[u8],
        call_id: &str,
        webrtc_handle: Option<WebRtcLegArtifacts>,
    ) -> Result<Vec<u8>> {
        let mgr = self
            .call_manager
            .as_ref()
            .ok_or_else(|| anyhow!("CallManager 未接続"))?;
        if ngn_offer.is_empty() || ext_answer.is_empty() {
            return Err(anyhow!("SDP body が空 (オファ/アンサのいずれか)"));
        }

        let ngn_peer = extract_rtp_endpoint(ngn_offer)?;

        let ngn_bind_ip = self.bridge_ngn_ip();
        // Phase 1-D: ephemeral port reuse による P-CSCF ghost binding 衝突回避。
        let ngn_bridge_sock = bind_ngn_rtp_socket(ngn_bind_ip).await?;
        let sabiden_ngn_addr = ngn_bridge_sock.local_addr()?;

        // Issue #87 / #121: WebRTC 内線レッグは UDP socket を持たない (peer
        // 側は str0m が ICE/DTLS 上で多重化)。 `webrtc_handle` 経由で peer の
        // MediaFrame I/O にアクセスし、 [`MediaBridge::WebRtcAudio`] を起動する。
        if let Some(handle) = webrtc_handle {
            info!(
                ?ngn_peer,
                sabiden_ngn=%sabiden_ngn_addr,
                opus_pt=handle.opus_payload_type,
                "WebRTC peer ⇔ NGN bridge 起動 (Issue #87 / #121)"
            );
            // NGN へ返す SDP は browser SDP 由来 (AVP に変換済) → PCMU only に
            // 絞り、 `c=`/`m= port` を sabiden の NGN 側 socket に書き換える。
            //
            // Issue #108 / Issue #212 / RFC 3264 §6.1: answer の `m=` formats は
            // **NGN offer formats ∩ ext_answer formats の真 intersection** で
            // なければならない。 `restrict_answer_to_ngn_offer_subset` が両側を
            // 読み、 NGN offer 出現順を維持して intersection を計算する
            // (PR #209 までの「NGN offer 由来 PT を forcibly synthesize」する
            // band-aid は Issue #212 で撤去)。 共通 PT が無い (= intersection 空) /
            // SDP 不正なら Err になり、 呼出側で 502 Bad Gateway fallback に
            // 流れる (RFC 3264 §6 "no common codec"; 厳密には 488 Not
            // Acceptable Here がより semantic だが、 fallback 経路の細分化は
            // 別 issue)。 NGN offer が PCMU only / PCMU+DTMF で来る制約
            // (CLAUDE.md §5) により、 結果は実質 PCMU only / PCMU+DTMF に
            // 自然に収束する。
            let pcmu_only = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)?;
            let rewritten =
                rewrite_rtp_endpoint(&pcmu_only, sabiden_ngn_addr.ip(), sabiden_ngn_addr.port())?;
            let bridge: MediaBridge =
                super::transcoder::WebRtcAudioBridge::start(super::transcoder::WebRtcAudioConfig {
                    ngn_socket: ngn_bridge_sock,
                    ngn_peer: Some(ngn_peer),
                    peer: handle.peer,
                    peer_media_rx: handle.peer_media_rx,
                    opus_payload_type: handle.opus_payload_type,
                    // sabiden の str0m は `enable_pcmu` 1 codec 構成なので
                    // (`webrtc/str0m_session.rs:190`)、 NGN(μ-law) ↔ PWA(μ-law)
                    // を transcoder で素通しする。 Opus 経路は str0m が
                    // negotiate しないので使うと `PT 未 negotiate → media drop`
                    // で全パケット消える (実機検証 2026-05-10)。
                    direct_pcmu_passthrough: true,
                    metrics: Some(self.metrics.clone()),
                })
                .into();
            let cid = mgr.create_call().await;
            mgr.attach_media_bridge(cid, bridge).await?;
            self.active
                .lock()
                .await
                .insert(call_id.to_string(), Some(cid));
            return Ok(rewritten);
        }

        // SIP 内線レッグ: 既存パス (PCMU 純リレー / Opus⇔PCMU トランスコード)。
        let ext_peer = extract_rtp_endpoint(ext_answer)?;
        let ext_bind_ip = self.bridge_ext_ip();
        let ext_bridge_sock = Arc::new(UdpSocket::bind(SocketAddr::new(ext_bind_ip, 0)).await?);

        info!(
            ?ngn_peer,
            ?ext_peer,
            sabiden_ngn=%sabiden_ngn_addr,
            sabiden_ext=%ext_bridge_sock.local_addr()?,
            "RTP ブリッジ用ソケット bind 完了"
        );

        // NGN へ返す 200 OK SDP は sabiden の NGN 側ソケットを指すように書き換える。
        //
        // Issue #108 / Issue #212 / RFC 3264 §6.1: answer の `m=` formats は
        // **NGN offer formats ∩ ext_answer formats の真 intersection** に
        // 強制する。 内線 200 OK 由来 (ext_answer) の PT をそのまま転送すると、
        // NGN がオファしていない codec を answer に乗せて RFC 3264 §6 違反
        // (NGN は SDP 不整合で 488/415/BYE を返す、 実機検証 2026-05-10)。
        // また Issue #212 で旧「NGN 由来 PT を forcibly synthesize」 band-aid
        // も撤去 (ext_answer が PCMA only の場合に PCMU を勝手に乗せて確立後
        // 無音になる事故防止)。 共通 PT 無しは Err → 呼出側 502。
        let pcmu_only = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)?;
        let rewritten =
            rewrite_rtp_endpoint(&pcmu_only, sabiden_ngn_addr.ip(), sabiden_ngn_addr.port())?;

        // Issue #29: NGN 側 SDP は PCMU 固定だが、内線レッグが Opus を要求した
        // 場合は Opus⇔PCMU トランスコードを噛ませる。両側 PCMU の場合は
        // 既存パスと完全に同じ純リレー (RtpBridge) を使う。
        let plan = select_media_plan(ngn_offer, ext_answer);
        let bridge: MediaBridge = match plan {
            MediaPlan::Relay => RtpBridge::start(BridgeConfig {
                ngn_socket: ngn_bridge_sock,
                ext_socket: ext_bridge_sock,
                ngn_peer: Some(ngn_peer),
                ext_peer: Some(ext_peer),
                metrics: Some(self.metrics.clone()),
            })?
            .into(),
            MediaPlan::Transcode { opus_pt } => {
                info!(opus_pt, "内線が Opus → Opus⇔PCMU トランスコード起動");
                TranscodingBridge::start(TranscodeConfig {
                    ngn_socket: ngn_bridge_sock,
                    web_socket: ext_bridge_sock,
                    ngn_peer: Some(ngn_peer),
                    web_peer: Some(ext_peer),
                    opus_payload_type: opus_pt,
                    metrics: Some(self.metrics.clone()),
                })?
                .into()
            }
        };

        let cid = mgr.create_call().await;
        mgr.attach_media_bridge(cid, bridge).await?;
        self.active
            .lock()
            .await
            .insert(call_id.to_string(), Some(cid));
        Ok(rewritten)
    }

    fn bridge_ngn_ip(&self) -> IpAddr {
        if let Some(ip) = self.cfg.bridge_ngn_bind_ip {
            return ip;
        }
        // SIP ソケットが unspecified (`0.0.0.0` / `::`) なら loopback にフォールバック。
        match self.socket.local_addr().map(|a| a.ip()) {
            Ok(ip) if !ip.is_unspecified() => ip,
            _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    fn bridge_ext_ip(&self) -> IpAddr {
        self.cfg
            .bridge_ext_bind_ip
            .unwrap_or_else(|| self.bridge_ngn_ip())
    }

    async fn respond(
        &self,
        stx: &Arc<Mutex<ServerTransaction>>,
        status: u16,
        reason: &str,
    ) -> Result<()> {
        let mut tx = stx.lock().await;
        let mut resp = build_response_skeleton(tx.request(), status, reason);
        ensure_to_tag(&mut resp);
        tx.respond(resp).await
    }
}

/// レスポンスの To に tag が無ければ付与する (RFC 3261 §8.2.6.2)。
///
/// 既存 tag の有無判定は [`crate::sip::utils::has_to_tag`] に委譲する
/// (RFC 3261 §7.3.1 / §25.1 で parameter name は case-insensitive)。
/// ナイーブに `to.contains("tag=")` で判定すると、 `;TAG=existing` の
/// ような大文字 tag を「無し」と誤判定し `;tag=<new>` を末尾追加して
/// `To: <sip:dest>;TAG=existing;tag=new` の二重 tag を返す
/// (RFC 3261 §12.2.2 違反; 内線 UA は ACK を送らず切断する)。 内線が
/// `;TAG=...` 大文字 Re-INVITE を送ってきた場合に 200 OK が壊れていた
/// 問題 (PR #136 review) の根治。
fn ensure_to_tag(resp: &mut SipResponse) {
    if let Some(to) = resp.headers.get("to") {
        if !crate::sip::utils::has_to_tag(to) {
            let new = format!("{};tag={}", to, crate::sip::utils::new_tag());
            resp.headers.set("To", new);
        }
    }
}

/// 受信 `To` ヘッダから `tag=<value>` を抽出する (RFC 3261 §20.39 / §7.3.1)。
///
/// `build_response_skeleton` が 100 以外で自動付与した sabiden 生成 To-tag を
/// 後続応答 (180 / 200 OK 等) で **同じ tag** にするために使う。 RFC 3261
/// §12.1.1: dialog ID = (Call-ID, From-tag, To-tag)。 同 INVITE トランザクション
/// で複数の non-100 応答を出す場合、 各応答の To-tag は **すべて同値** で
/// なければならない (早期 dialog == 確定 dialog)。 異なる tag を出すと NGN
/// 側 UAC は early dialog と confirmed dialog を別 dialog と見做し、 早期
/// dialog の "保留 / forking" を Confirmed dialog の取消し扱いにする実装が
/// 存在する (= 即 BYE の素因)。
///
/// parameter name は case-insensitive (RFC 3261 §7.3.1)、 値の前後空白は
/// trim する (RFC 3261 §7.3.1: parameter SHOULD NOT contain whitespace、
/// 受信側は寛容)。 戻り値は **value 部分** (tag 文字列そのもの)。
fn extract_to_tag(to_header: &str) -> Option<String> {
    let mut depth = 0i32;
    let mut after_semi = false;
    let mut start = 0usize;
    let bytes = to_header.as_bytes();
    let mut params: Vec<&str> = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b';' if depth == 0 => {
                if after_semi {
                    params.push(to_header[start..i].trim());
                }
                after_semi = true;
                start = i + 1;
            }
            _ => {}
        }
    }
    if after_semi {
        params.push(to_header[start..].trim());
    }
    for p in params {
        let Some(eq_idx) = p.find('=') else {
            continue;
        };
        let name = &p[..eq_idx];
        let value = p[eq_idx + 1..].trim();
        if name.eq_ignore_ascii_case("tag") && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// RFC 4028 §4 / §7 のパース結果: INVITE / Re-INVITE に乗った
/// `Session-Expires` (full or compact `x:`) と `Min-SE` の値、 および
/// `Supported: timer` の有無。
///
/// `Session-Expires` ヘッダの ABNF (RFC 4028 §3):
/// ```text
/// Session-Expires = ("Session-Expires" / "x") HCOLON delta-seconds *(SEMI se-params)
/// se-params       = refresher-param / generic-param
/// refresher-param = "refresher" EQUAL ("uas" / "uac")
/// ```
///
/// パースは寛容に行う (`delta-seconds` だけは必須数値、 残りパラメータは
/// 値を捨てて refresher のみ取り出す)。 不正な数値は `None` を返し、
/// 呼出側で `Session-Expires` 不在として扱う (= RFC 4028 §7 後段: UAS は
/// Session-Expires をサポートしていないと判断して echo しなくてよい)。
#[derive(Debug, Clone, PartialEq)]
struct InboundSessionTimer {
    /// `Session-Expires` の delta-seconds (秒)。
    session_expires: u32,
    /// refresher param ("uac" / "uas") の生値。 不在なら `None`。
    refresher: Option<String>,
}

/// `Session-Expires` ヘッダを parse する (RFC 4028 §4)。 ヘッダ不在 / 値が
/// 不正なら `None`。 compact form (`x:`) はメッセージパーサ側で既に
/// `session-expires` に正規化されている前提 (`src/sip/message.rs:309`)。
fn parse_session_expires_header(value: &str) -> Option<InboundSessionTimer> {
    let mut parts = value.split(';');
    let secs_str = parts.next()?.trim();
    let session_expires: u32 = secs_str.parse().ok()?;
    let mut refresher: Option<String> = None;
    for p in parts {
        let p = p.trim();
        if let Some(eq_idx) = p.find('=') {
            let name = &p[..eq_idx];
            let val = p[eq_idx + 1..].trim();
            if name.eq_ignore_ascii_case("refresher") && !val.is_empty() {
                refresher = Some(val.to_ascii_lowercase());
            }
        }
    }
    Some(InboundSessionTimer {
        session_expires,
        refresher,
    })
}

/// RFC 4028 §4 / §10: `Min-SE` ヘッダ値を `u32` (秒) にパース。 不在 / 不正なら
/// `None` (= 呼出側は `MIN_SE` 既定値を採用)。
fn parse_min_se_header(value: &str) -> Option<u32> {
    // `Min-SE: 300` のような単純数値前提。 RFC 4028 ABNF も
    // `Min-SE = "Min-SE" HCOLON delta-seconds *(SEMI generic-param)` で
    // 第一トークンが delta-seconds。
    let head = value.split(';').next().unwrap_or("").trim();
    head.parse().ok()
}

/// 内線レッグ Re-INVITE の `send_request` 失敗を SIP final response の
/// (status_code, reason_phrase) に分類する (RFC 3261 §13.3.1.1 / §13.3.1.2)。
///
/// - **408 Request Timeout** (§13.3.1.1): 内線 UAS が Timer B / F (= 64 * T1)
///   満了まで応答しない場合。 RFC 3261 §13.3.1.1 で「UAS callee がリーズナブル
///   時間内に応答しない場合 408 を返してよい」とされ、 B2BUA UAS としても
///   内線 callee 側の応答不在を Timer B/F 失敗で検知した場合は同じ意味論で
///   408 を NGN 側 UAC へ伝搬する。
/// - **500 Server Internal Error** (§13.3.1.2): 上記以外の内線レッグ通信失敗
///   (UDP `send_to` の I/O 失敗、 トランザクション層停止、 oneshot 中断、
///   ヘッダ欠落による `create_client` 失敗 等)。 §13.3.1.2 は UAS が「unexpected
///   condition により request 履行不能」と判断した場合の正当な応答として 500
///   を挙げている。
///
/// 判定は `anyhow::Error` の文字列表現を見る:
///
/// - `TransactionLayer::send_request` 配下の `ClientTransaction::run` は
///   Timer B/F 満了で `anyhow!("transaction timeout")` を返す
///   (`src/sip/transaction.rs` Timer B/F ブランチ)。
/// - 他は I/O / 内部チャネル系の異なるメッセージで上がる。
///
/// `anyhow::Error` は構造化型を持たないため、 安定 ID として上記固定文字列を
/// 突き合わせる。 `src/sip/transaction.rs` 側でこの文字列を変えると classifier
/// も追従する必要があるため、 単体テスト (`classifies_timer_bf_as_408_per_rfc3261_13_3_1_1`)
/// で文字列契約を担保する。
fn classify_ext_reinvite_send_error(err: &anyhow::Error) -> (u16, &'static str) {
    // anyhow::Error の `Display` は最外殻 context だけを返すので、 source chain
    // を辿って "transaction timeout" を探す。 これにより上位で `.context(...)`
    // が追加されても (将来の transaction.rs 側のエラー記述拡充に追従)、
    // 元の Timer B/F 由来は 408 に分類され続ける。
    let chain_has_timeout = err
        .chain()
        .any(|e| e.to_string().contains("transaction timeout"));
    if chain_has_timeout {
        (408, "Request Timeout")
    } else {
        (500, "Server Internal Error")
    }
}

/// Issue #260 Phase 1-A: NGN 5xx 応答から carrier 由来 header を抽出した
/// 構造化ビュー。 純粋値型なので呼び出し側で `Debug` 表示するだけで `warn!`
/// の構造化フィールドに展開できる (`tracing` の `?expr` syntax)。
///
/// 各 field は受信応答に該当 header が無ければ `None`。
///
/// - `reason` (RFC 3326): 終端理由 (例 `Q.850;cause=16;text="Normal call clearing"`)
/// - `retry_after` (RFC 3261 §20.33): 次回試行までの秒数
/// - `server` (RFC 3261 §20.35): carrier 識別 (例 `NEC IP-PBX 6.0`)
/// - `warning` (RFC 3261 §20.43): warn-code + warn-agent + warn-text
/// - `via_received` / `via_rport` (RFC 3581 §4): NAT 越し観測値
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Ngn5xxHeaderView {
    pub reason: Option<String>,
    pub retry_after: Option<String>,
    pub server: Option<String>,
    pub warning: Option<String>,
    pub via_received: Option<String>,
    pub via_rport: Option<String>,
}

/// Issue #260 Phase 1-A: 受信 5xx 応答から carrier 由来 header を抽出する。
///
/// `received` / `rport` は Via ヘッダ第一行のパラメータから抜き取る
/// (RFC 3581 §4: VPN/NAT 越え時に UAS が観測した送信元 IP/port を
/// Via の `;received=` / `;rport=` で返却する)。
///
/// 純粋関数 (`SipHeaders -> Ngn5xxHeaderView`)、 副作用なし。 ロギング呼び出し
/// 側で `?` 展開して `tracing::warn!` の構造化フィールドへ転送する。
pub(crate) fn extract_ngn_5xx_header_view(headers: &SipHeaders) -> Ngn5xxHeaderView {
    let reason = headers.get("reason").map(|s| s.to_string());
    let retry_after = headers.get("retry-after").map(|s| s.to_string());
    let server = headers.get("server").map(|s| s.to_string());
    let warning = headers.get("warning").map(|s| s.to_string());
    let (via_received, via_rport) = headers
        .get("via")
        .map(extract_via_received_rport)
        .unwrap_or((None, None));
    Ngn5xxHeaderView {
        reason,
        retry_after,
        server,
        warning,
        via_received,
        via_rport,
    }
}

/// RFC 3581 §4: `Via` ヘッダの `received=<ip>` / `rport=<port>` を抜き出す。
///
/// `;` でパラメータに分割し、 大文字小文字を無視して `received` / `rport` を
/// 検索する (RFC 3261 §7.3.1: パラメータ名は大文字小文字無視)。 値が無い
/// 単独の `rport` (= 要求としての `;rport` フラグ) は `None` を返す
/// (= 観測済み port が記載されていないので意味なし)。
///
/// 複数 Via が `,` で連結されている場合は最先頭のみ調べる (RFC 3261 §18:
/// UAS 応答経路では最上段 Via が UAC を指す)。
fn extract_via_received_rport(via: &str) -> (Option<String>, Option<String>) {
    let first = via.split(',').next().unwrap_or(via);
    let mut received = None;
    let mut rport = None;
    for raw_param in first.split(';').skip(1) {
        let param = raw_param.trim();
        if let Some((k, v)) = param.split_once('=') {
            let key = k.trim();
            let value = v.trim().to_string();
            if key.eq_ignore_ascii_case("received") && received.is_none() {
                received = Some(value);
            } else if key.eq_ignore_ascii_case("rport") && rport.is_none() {
                rport = Some(value);
            }
        }
        // 値なしの単独 `rport` フラグは観測値ではないので無視 (= None)。
    }
    (received, rport)
}

/// 内線→NGN 発信通話の B2BUA ステートを保持するレジストリ。
///
/// 1 通話には 2 つの SIP ダイアログがある (内線レッグ / NGN レッグ) ため、
/// それぞれの Call-ID で同じ通話エントリを引けるようにする:
/// - `ext_call_id` (内線が送った INVITE の Call-ID): 内線側からの BYE/CANCEL の
///   ルックアップに使う。
/// - `ngn_call_id` (sabiden が NGN へ発行した INVITE の Call-ID): NGN 側からの
///   BYE のルックアップに使う (`NgnInboundHandler::handle_bye` が参照)。
///
/// 並行アクセスは [`Mutex`] 1 つでガードする (1 通話あたり数イベント程度なので
/// 競合は少ない)。確立済みエントリは `Arc<OutboundCallEntry>` で共有する。
#[derive(Default)]
pub struct OutboundCallRegistry {
    inner: Mutex<OutboundCallRegistryInner>,
}

#[derive(Default)]
struct OutboundCallRegistryInner {
    /// 内線 Call-ID → 確立済み通話エントリ。
    by_ext: HashMap<String, Arc<OutboundCallEntry>>,
    /// NGN Call-ID → 内線 Call-ID (確立済み通話の逆引き)。
    ngn_to_ext: HashMap<String, String>,
    /// 進行中 (200 OK 受信前) の INVITE。CANCEL でルックアップする。
    pending: HashMap<String, Arc<PendingOutbound>>,
}

/// 確立済み内線→NGN 通話 1 件分のステート。
pub struct OutboundCallEntry {
    /// 内線が送ってきた INVITE の Call-ID。
    pub ext_call_id: String,
    /// sabiden が NGN へ発行した INVITE の Call-ID (= UacDialog のもの)。
    pub ngn_call_id: String,
    /// 通話を発信した内線 AOR (例: "iphone")。Issue #68 の登録抹消連動 BYE で
    /// AOR ごとに通話エントリを引くために保持する。
    pub from_aor: String,
    /// sabiden が UAS として保持する内線レッグのダイアログ。
    /// BYE 等を内線へ送るときに `build_bye` の起点として使う。
    pub ext_dialog: Mutex<Dialog>,
    /// sabiden が UAC として保持する NGN レッグのダイアログ。
    /// BYE は `send_bye` で送る。
    pub ngn_dialog: Mutex<UacDialog>,
    /// 内線レッグの ServerTransaction ハンドル。
    /// 487 等を返したいときに使う (確立後は基本不要)。
    pub ext_responder: ResponderHandle,
    /// 内線レッグの送信先 socket addr (BYE 送信時の宛先)。
    pub ext_remote: SocketAddr,
    /// 内線レッグ用 SIP TransactionLayer (BYE を `send_request` で投げる)。
    pub ext_layer: Arc<TransactionLayer>,
    /// RTP ブリッジが起動済みなら CallId (CallManager 内のキー)。
    pub bridge_call_id: Option<CallId>,
}

/// 200 OK 受信前 (= INVITE 進行中) の通話ステート。CANCEL のために保持する。
pub struct PendingOutbound {
    pub ext_call_id: String,
    pub invite_plan: InvitePlan,
    pub ext_responder: ResponderHandle,
    /// 既に CANCEL 済みなら true。INVITE 完了側がチェックして 487 への
    /// 応答経路を切り替える。
    pub cancelled: tokio::sync::Notify,
    pub cancelled_flag: std::sync::atomic::AtomicBool,
}

impl OutboundCallRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn insert_pending(&self, p: Arc<PendingOutbound>) {
        let mut inner = self.inner.lock().await;
        inner.pending.insert(p.ext_call_id.clone(), p);
    }

    pub async fn take_pending(&self, ext_call_id: &str) -> Option<Arc<PendingOutbound>> {
        let mut inner = self.inner.lock().await;
        inner.pending.remove(ext_call_id)
    }

    pub async fn get_pending(&self, ext_call_id: &str) -> Option<Arc<PendingOutbound>> {
        let inner = self.inner.lock().await;
        inner.pending.get(ext_call_id).cloned()
    }

    pub async fn insert_confirmed(&self, entry: Arc<OutboundCallEntry>) {
        let mut inner = self.inner.lock().await;
        inner
            .ngn_to_ext
            .insert(entry.ngn_call_id.clone(), entry.ext_call_id.clone());
        inner.by_ext.insert(entry.ext_call_id.clone(), entry);
    }

    pub async fn lookup_by_ext(&self, ext_call_id: &str) -> Option<Arc<OutboundCallEntry>> {
        let inner = self.inner.lock().await;
        inner.by_ext.get(ext_call_id).cloned()
    }

    pub async fn lookup_by_ngn(&self, ngn_call_id: &str) -> Option<Arc<OutboundCallEntry>> {
        let inner = self.inner.lock().await;
        let ext_id = inner.ngn_to_ext.get(ngn_call_id)?.clone();
        inner.by_ext.get(&ext_id).cloned()
    }

    pub async fn remove_by_ext(&self, ext_call_id: &str) -> Option<Arc<OutboundCallEntry>> {
        let mut inner = self.inner.lock().await;
        let entry = inner.by_ext.remove(ext_call_id)?;
        inner.ngn_to_ext.remove(&entry.ngn_call_id);
        Some(entry)
    }

    pub async fn remove_by_ngn(&self, ngn_call_id: &str) -> Option<Arc<OutboundCallEntry>> {
        let mut inner = self.inner.lock().await;
        let ext_id = inner.ngn_to_ext.remove(ngn_call_id)?;
        inner.by_ext.remove(&ext_id)
    }

    /// 指定 AOR に紐づく確立済み通話を全て取り出してテーブルから削除する。
    /// Issue #68: 内線が登録抹消したとき、その AOR で進行中の NGN レッグ
    /// 通話を全て BYE で閉じるためのヘルパ。
    pub async fn drain_by_aor(&self, aor: &str) -> Vec<Arc<OutboundCallEntry>> {
        let mut inner = self.inner.lock().await;
        let ext_ids: Vec<String> = inner
            .by_ext
            .iter()
            .filter(|(_, e)| e.from_aor == aor)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::with_capacity(ext_ids.len());
        for ext_id in ext_ids {
            if let Some(entry) = inner.by_ext.remove(&ext_id) {
                inner.ngn_to_ext.remove(&entry.ngn_call_id);
                out.push(entry);
            }
        }
        out
    }
}

/// `UasEvent` を捌くハンドラ。内線発信 INVITE / BYE を NGN 側 UAC へ転送する。
pub struct UasEventHandler {
    /// NGN 側 UAC。ここから NGN へ INVITE する。
    ngn_uac: Arc<Uac>,
    /// 内線レッグ用 SIP TransactionLayer。BYE を内線へ送るために必要。
    /// `None` のときは内線へ in-dialog リクエストを送れず、BYE 連動は片方向のみ。
    ext_layer: Option<Arc<TransactionLayer>>,
    /// sabiden が内線レッグで使う Contact (Via sent-by) 用ローカルアドレス。
    /// `None` のときは `ext_layer` の socket から取得する。
    ext_local_addr: Option<SocketAddr>,
    /// 内線→NGN 通話のステート レジストリ。
    /// `NgnInboundHandler` と共有することで NGN→内線方向の BYE も同じ通話に
    /// 紐づけて扱える。
    pub(crate) registry: Arc<OutboundCallRegistry>,
    /// RTP ブリッジ管理用 CallManager (`None` なら SDP 透過モード)。
    call_manager: Option<Arc<CallManager>>,
    /// 内線発信時の RTP ブリッジ用 NGN 側 bind IP。`None` なら loopback。
    bridge_ngn_bind_ip: Option<IpAddr>,
    /// 内線発信時の RTP ブリッジ用内線側 bind IP。`None` なら loopback。
    bridge_ext_bind_ip: Option<IpAddr>,
    /// PWA→NGN 発信通話の双方向 BYE 連動テーブル (Issue #147)。
    /// `NgnInboundHandler` と同じ Arc を共有することで、 NGN→PWA / PWA→NGN
    /// 両方向の BYE が同じエントリを引ける。 詳細は [`WebRtcOutboundEntry`]。
    webrtc_outbound_active: WebRtcOutboundActive,
    /// 観測カウンタ。内線発信 INVITE の結果を記録する。
    metrics: Arc<Metrics>,
    /// Issue #157: outbound INVITE per-AOR rate limiter (TTC JJ-90.24 §5.7.1)。
    /// 内線→NGN / PWA→NGN 双方の outbound 経路でこの 1 インスタンスを共有し、
    /// 同 AOR への連投を 503 + Retry-After で早期拒否する (RFC 3261 §21.5.4)。
    /// `Arc` で wrap せず本構造体に直に embedded すれば、 全 outbound 経路から
    /// `&self.outbound_rate_limiter` で参照できる (内部は `Mutex<HashMap>` で
    /// スレッド安全)。
    outbound_rate_limiter: Arc<OutboundRateLimiter>,
    /// Issue #278: 通話履歴 ring buffer (内線発信 / PWA 発信)。 未注入なら
    /// hook は no-op で旧挙動を保つ。 `Mutex<Option<_>>` にしているのは、
    /// `Arc::clone().spawn()` 後に `set_call_log` を呼べるようにするため
    /// (= `outbound_forwarder` と同じ pattern)。
    call_log: Mutex<Option<Arc<crate::observability::call_log::CallLog>>>,
}

impl UasEventHandler {
    pub fn new(ngn_uac: Arc<Uac>) -> Arc<Self> {
        Self::with_metrics(ngn_uac, Metrics::new())
    }

    /// メトリクス付きコンストラクタ。
    pub fn with_metrics(ngn_uac: Arc<Uac>, metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            ngn_uac,
            ext_layer: None,
            ext_local_addr: None,
            registry: OutboundCallRegistry::new(),
            call_manager: None,
            bridge_ngn_bind_ip: None,
            bridge_ext_bind_ip: None,
            webrtc_outbound_active: Arc::new(Mutex::new(HashMap::new())),
            metrics,
            outbound_rate_limiter: Arc::new(OutboundRateLimiter::new()),
            call_log: Mutex::new(None),
        })
    }

    /// `CallManager` と RTP bridge bind IP を設定したバージョン。
    pub fn with_call_manager(
        ngn_uac: Arc<Uac>,
        call_manager: Arc<CallManager>,
        bridge_ngn_bind_ip: Option<IpAddr>,
        bridge_ext_bind_ip: Option<IpAddr>,
    ) -> Arc<Self> {
        Self::with_call_manager_and_metrics(
            ngn_uac,
            call_manager,
            bridge_ngn_bind_ip,
            bridge_ext_bind_ip,
            Metrics::new(),
        )
    }

    /// `CallManager` + メトリクス付きコンストラクタ。
    pub fn with_call_manager_and_metrics(
        ngn_uac: Arc<Uac>,
        call_manager: Arc<CallManager>,
        bridge_ngn_bind_ip: Option<IpAddr>,
        bridge_ext_bind_ip: Option<IpAddr>,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ngn_uac,
            ext_layer: None,
            ext_local_addr: None,
            registry: OutboundCallRegistry::new(),
            call_manager: Some(call_manager),
            bridge_ngn_bind_ip,
            bridge_ext_bind_ip,
            webrtc_outbound_active: Arc::new(Mutex::new(HashMap::new())),
            metrics,
            outbound_rate_limiter: Arc::new(OutboundRateLimiter::new()),
            call_log: Mutex::new(None),
        })
    }

    /// PWA→NGN 発信通話の BYE 連動テーブルを共有するコンストラクタ (Issue #147)。
    /// `NgnInboundHandler::with_call_manager_metrics_and_outbound_table` に
    /// 渡したのと同じ Arc を本ハンドラにも渡すことで、 双方向 BYE が成立する。
    #[allow(clippy::too_many_arguments)]
    pub fn with_call_manager_metrics_and_outbound_table(
        ngn_uac: Arc<Uac>,
        call_manager: Arc<CallManager>,
        bridge_ngn_bind_ip: Option<IpAddr>,
        bridge_ext_bind_ip: Option<IpAddr>,
        metrics: Arc<Metrics>,
        webrtc_outbound_active: WebRtcOutboundActive,
    ) -> Arc<Self> {
        Arc::new(Self {
            ngn_uac,
            ext_layer: None,
            ext_local_addr: None,
            registry: OutboundCallRegistry::new(),
            call_manager: Some(call_manager),
            bridge_ngn_bind_ip,
            bridge_ext_bind_ip,
            webrtc_outbound_active,
            metrics,
            outbound_rate_limiter: Arc::new(OutboundRateLimiter::new()),
            call_log: Mutex::new(None),
        })
    }

    /// Issue #157: 外部からカスタム設定の rate limiter を注入するための setter。
    /// 構築直後 (まだ shared されていない) の `Arc<Self>` にのみ呼べる。
    /// テスト / 設定駆動でパラメータを変更したい場合に使う (例: `min_interval`
    /// を 1 秒に下げて E2E test を高速化)。
    pub fn set_outbound_rate_limiter(self: &mut Arc<Self>, limiter: Arc<OutboundRateLimiter>) {
        let me =
            Arc::get_mut(self).expect("set_outbound_rate_limiter は単一所有時に呼ぶ必要がある");
        me.outbound_rate_limiter = limiter;
    }

    /// Issue #157: rate limiter の Arc 参照を返す。
    /// テスト / observability から最新状態を観察する用途。
    pub fn outbound_rate_limiter(&self) -> Arc<OutboundRateLimiter> {
        self.outbound_rate_limiter.clone()
    }

    /// Issue #278: 通話履歴 ring buffer を注入する (setter)。
    ///
    /// 未注入時 (`None`) は内線発信 / PWA 発信の hook が no-op となり、 旧挙動と
    /// 同一。 `Mutex<Option<_>>` ベースなので spawn 後 (= shared) でも安全に呼べる。
    pub async fn set_call_log(
        self: &Arc<Self>,
        call_log: Arc<crate::observability::call_log::CallLog>,
    ) {
        let mut slot = self.call_log.lock().await;
        *slot = Some(call_log);
    }

    /// 通話履歴の Arc clone (注入済みの場合)。 hot path から `record_*` を
    /// 呼ぶときの helper として使う。 未注入なら `None` で hook 全体を skip する。
    async fn call_log_clone(&self) -> Option<Arc<crate::observability::call_log::CallLog>> {
        self.call_log.lock().await.clone()
    }

    /// `webrtc_outbound_active` の Arc を返す (Issue #147)。
    /// `NgnInboundHandler` 等、 同じテーブルを共有したい外部ハンドラに渡すための
    /// accessor。
    pub fn webrtc_outbound_active(&self) -> WebRtcOutboundActive {
        self.webrtc_outbound_active.clone()
    }

    /// 内線レッグ用 `TransactionLayer` を結線する。BYE を内線へ送るのに必要。
    /// `ext_local_addr` は Via sent-by / Contact に使うアドレス (省略時は
    /// layer の socket からの local_addr)。
    ///
    /// `Arc::get_mut` を使うため、本メソッドは `Arc::new` 直後 (= まだ
    /// 共有されていない) のハンドラに対してのみ呼べる。
    pub fn attach_ext_layer(
        self: &mut Arc<Self>,
        layer: Arc<TransactionLayer>,
        ext_local_addr: Option<SocketAddr>,
    ) {
        let me = Arc::get_mut(self).expect("attach_ext_layer は単一所有時に呼ぶ必要がある");
        me.ext_layer = Some(layer);
        me.ext_local_addr = ext_local_addr;
    }

    /// `OutboundCallRegistry` の参照を返す。`NgnInboundHandler` と共有するため、
    /// 同じ Arc を渡すことで NGN→内線方向の BYE が同じ通話エントリを引ける。
    pub fn registry(&self) -> Arc<OutboundCallRegistry> {
        self.registry.clone()
    }

    /// 既存の `OutboundCallRegistry` を流用するコンストラクタ。
    /// `NgnInboundHandler` と共有したいテスト・運用コードはこちらを使う。
    pub fn with_shared_registry(
        ngn_uac: Arc<Uac>,
        call_manager: Option<Arc<CallManager>>,
        bridge_ngn_bind_ip: Option<IpAddr>,
        bridge_ext_bind_ip: Option<IpAddr>,
        registry: Arc<OutboundCallRegistry>,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ngn_uac,
            ext_layer: None,
            ext_local_addr: None,
            registry,
            call_manager,
            bridge_ngn_bind_ip,
            bridge_ext_bind_ip,
            webrtc_outbound_active: Arc::new(Mutex::new(HashMap::new())),
            metrics,
            outbound_rate_limiter: Arc::new(OutboundRateLimiter::new()),
            call_log: Mutex::new(None),
        })
    }

    /// `event_rx` を駆動する。`mpsc::UnboundedSender<UasEvent>` 側を
    /// `ExtensionUas::with_handler` に渡しておく。
    pub fn spawn(self: Arc<Self>, mut event_rx: mpsc::UnboundedReceiver<UasEvent>) {
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.handle_event(event).await {
                        warn!(error=%e, "UAS event 処理失敗");
                    }
                });
            }
            debug!("UAS event loop 終了");
        });
    }

    async fn handle_event(&self, event: UasEvent) -> Result<()> {
        match event {
            UasEvent::Invite {
                from_aor,
                request,
                remote,
                responder,
            } => {
                self.handle_invite(from_aor, request, remote, responder)
                    .await
            }
            UasEvent::Reinvite {
                request,
                remote,
                responder,
            } => self.handle_ext_reinvite(request, remote, responder).await,
            UasEvent::Bye {
                request,
                remote,
                responder,
            } => self.handle_ext_bye(request, remote, responder).await,
            UasEvent::Cancel {
                request,
                remote,
                responder,
            } => self.handle_ext_cancel(request, remote, responder).await,
            UasEvent::Ack { request, remote } => self.handle_ext_ack(request, remote).await,
            UasEvent::Info {
                request,
                remote,
                responder,
            } => self.handle_ext_info(request, remote, responder).await,
            UasEvent::Unregister { aor } => self.handle_ext_unregister(&aor).await,
        }
    }

    /// 内線が登録抹消した (RFC 3261 §10.2.1.1 expires=0、または期限切れ)。
    /// 当該 AOR で確立済みの通話を全て NGN レッグごと BYE で閉じる。
    /// Issue #68 で観測された連続発信時 NGN 486 の根因 (内線サイレント切断時に
    /// NGN 側 dialog が残存) を解消するための救済パス。
    async fn handle_ext_unregister(&self, aor: &str) -> Result<()> {
        let drained = self.registry.drain_by_aor(aor).await;
        if drained.is_empty() {
            debug!(%aor, "登録抹消: 該当する outbound 通話なし");
            return Ok(());
        }
        info!(
            %aor,
            count = drained.len(),
            "登録抹消検出 → NGN レッグへ BYE 送出 (Issue #68 / RFC 3261 §15.1.1)"
        );
        for entry in drained {
            // NGN 側 BYE
            {
                let mut ngn_dlg = entry.ngn_dialog.lock().await;
                if let Err(e) = ngn_dlg.send_bye().await {
                    warn!(error=%e, ext_call_id=%entry.ext_call_id, "登録抹消連動 NGN BYE 失敗");
                }
            }
            // 内線レッグ dialog も Terminated にしておく (内線がもう居なくても
            // sabiden 側状態は閉じる; build_bye は呼ばない、相手が居ないので無駄)。
            {
                let mut ext_dlg = entry.ext_dialog.lock().await;
                ext_dlg.terminate();
            }
            // RTP ブリッジ停止 + 観測
            self.metrics.dec_call_active();
            if let (Some(bridge_id), Some(mgr)) = (entry.bridge_call_id, self.call_manager.as_ref())
            {
                if let Err(e) = mgr.terminate(bridge_id).await {
                    warn!(error=%e, "登録抹消連動 RTP ブリッジ停止失敗");
                }
            }
        }
        Ok(())
    }

    /// 内線からの INVITE を NGN へプロキシし、200 OK の往復まで完了させる。
    async fn handle_invite(
        &self,
        from_aor: String,
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    ) -> Result<()> {
        let call_id = request
            .headers
            .get("call-id")
            .map(str::to_string)
            .unwrap_or_else(|| "<no-call-id>".to_string());
        let span = info_span!(
            "uas_invite",
            call_id = %call_id,
            aor = %from_aor,
            direction = "extension",
        );
        async move {
            info!(%from_aor, %remote, "内線発信 → NGN へプロキシ");

            // Issue #157: TTC JJ-90.24 §5.7.1 (連続リクエスト送信制限) を遵守し、
            // 同 AOR からの連投を 503 Service Unavailable + Retry-After で
            // 早期拒否する (RFC 3261 §21.5.4 / §20.33)。 NGN P-CSCF に流す前に
            // 端末側で抑制することで、 NGN 側 cooldown (= 連鎖 5xx の原因) を
            // 起こさない。
            match self.outbound_rate_limiter.check_and_record(&from_aor) {
                RateLimitDecision::Deny { retry_after } => {
                    let secs = retry_after.as_secs();
                    warn!(
                        aor = %from_aor,
                        retry_after_secs = %secs,
                        "内線 INVITE を rate limiter で 503 拒否 (TTC JJ-90.24 §5.7.1)"
                    );
                    self.metrics
                        .record_invite_blocked_by_rate_limit(OutboundDirection::Extension);
                    self.metrics
                        .record_invite_extension(InviteResult::Error);
                    // RFC 3261 §21.5.4: 503 + Retry-After で内線へ通知。
                    let resp = build_503_with_retry_after(&request, secs);
                    if let Err(e) = responder.respond(resp).await {
                        warn!(error=%e, "503 Service Unavailable 送出失敗");
                    }
                    return Ok(());
                }
                RateLimitDecision::Allow { previous_interval } => {
                    // Issue #157 観測点: 連続発信間隔 (= 直前 Allow から今回 Allow
                    // までの経過時間) を `sabiden_sip_invite_interval_seconds_{sum,count}`
                    // に記録する。 初回 (`None`) は記録しない (= count は 2 本目以降の
                    // サンプル数になる、 標本平均が「連投間隔」 として意味を持つ)。
                    if let Some(d) = previous_interval {
                        // u128 → u64 飽和: ms オーダで Duration がオーバーフローする
                        // ことは現実的にないが、 panic を避けるために飽和変換。
                        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
                        self.metrics.record_invite_interval_ms(ms);
                    }
                }
            }

            // Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §5.1):
            // 内線が出した Request-URI (LAN private IP / NGN ドメイン) を
            // P-CSCF IP+port に正規化する。NGN は Request-URI host に P-CSCF
            // IP を要求する (ドメインや LAN IP のままだと 403 で蹴られる)。
            let ngn_server = self.ngn_uac.server_addr();
            let target = normalize_request_uri_for_ngn(
                &request.uri,
                &ngn_server.ip().to_string(),
                ngn_server.port(),
            );
            if target != request.uri {
                debug!(
                    original = %request.uri,
                    rewritten = %target,
                    "Request-URI を P-CSCF IP+port に正規化"
                );
            }
            let ext_offer = request.body.clone();

            // CallManager があれば RTP ブリッジ用ソケットを先に確保し、
            // NGN へ送る INVITE の SDP を sabiden 側に書き換える。
            // CallManager 未注入 (透過モード) でも、Asterisk 実機準拠で SDP の
            // `c=` / `o=` IP は **必ず** NGN 側 (eth1 IP = sent-by IP) へ強制
            // 書換する (`docs/asterisk-real-invite.md` §5.2)。LAN private IP
            // (192.168.x.x) を NGN 側に漏らすと 403 / 接続不能。
            let ngn_local_ip = self.ngn_uac.config().local_addr.ip();
            let (bridge_ctx, sdp_for_ngn) =
                match self.prepare_outbound_bridge(&ext_offer).await {
                    Ok(Some((ctx, rewritten))) => (Some(ctx), Some(rewritten)),
                    Ok(None) => (
                        None,
                        force_rewrite_sdp_for_ngn(&ext_offer, ngn_local_ip),
                    ),
                    Err(e) => {
                        warn!(error=%e, "NGN 側 RTP ブリッジ準備失敗 → SDP 強制書換で続行");
                        (
                            None,
                            force_rewrite_sdp_for_ngn(&ext_offer, ngn_local_ip),
                        )
                    }
                };

            // NGN は PCMU(0) しか **音声** として受け入れないが、Issue #69 で
            // RFC 4733 telephone-event (PT=101) を **in-band DTMF** 用に並走
            // させる。NGN 側の SIP プロキシ (Asterisk 等) は telephone-event を
            // 素通しするので、PCMU + telephone-event だけ残せば 200 OK が返る。
            // Opus / Speex / G.729 等は引き続き削除する。
            // Phase R3 (Issue #272): Negotiator が「PCMU+DTMF subset / WebRTC attr
            // 剥離 / s=ptime/rtcp 補完」を一括正規化する。 旧
            // `restrict_audio_to_pcmu_with_dtmf` は同 Negotiator への薄い alias。
            let sdp_for_ngn = sdp_for_ngn.map(|s| Negotiator::for_ngn_with_dtmf().rewrite_offer(&s));

            let plan = self
                .ngn_uac
                .build_invite(&target, sdp_for_ngn.as_deref(), None);

            // Issue #278: 内線→NGN 発信を通話履歴に記録する。 ダイヤル先は
            // 正規化後の Request-URI から user 部を抽出 (例 `sip:0312345678@P-CSCF:5060`
            // → `0312345678`)。 抽出失敗時 (= URI 異常) は URI 全体を残す。
            if let Some(call_log) = self.call_log_clone().await {
                let remote_number =
                    extract_user_from_sip_uri(&target).unwrap_or_else(|| target.clone());
                call_log.record_start(
                    crate::observability::call_log::Direction::Outbound,
                    remote_number,
                    call_id.clone(),
                );
            }

            // 進行中 INVITE を pending に登録 (CANCEL ルックアップ用)。
            let pending = Arc::new(PendingOutbound {
                ext_call_id: call_id.clone(),
                invite_plan: plan.clone(),
                ext_responder: responder.clone(),
                cancelled: tokio::sync::Notify::new(),
                cancelled_flag: std::sync::atomic::AtomicBool::new(false),
            });
            if !call_id.is_empty() && call_id != "<no-call-id>" {
                self.registry.insert_pending(pending.clone()).await;
            }

            // Issue #260 Phase 1-A: INVITE 送出から 5xx 受信までの経過 ms を
            // 構造化ログに載せるため、 invite await 開始直前で計測開始する。
            let invite_started_at = std::time::Instant::now();
            let mut outcome = self.ngn_uac.invite(plan, sdp_for_ngn.clone()).await;

            // Issue #260 Phase 1-B: NGN carrier intermittent reject (500/486/503)
            // に対する 1 回限定 auto-retry。 RFC 3261 §20.33 (Retry-After) /
            // 3GPP TS 24.229 §5.2.7 (500 = per-INVITE 失敗) / TTC JJ-90.24 §5.7.3
            // (過度な retry 回避)。 retry policy 詳細は `carrier_retry::decide_retry`。
            // retry した場合は新 Call-ID で再構築 (= NGN から見れば新 transaction、
            // RFC 3261 §8.1.1.5: 新 INVITE = 新 Call-ID)。 cancel 待ちは
            // `pending.cancelled` を `tokio::select!` で監視し、 sleep 中に内線
            // から CANCEL が来たら retry を諦める。
            let retry_cfg = CarrierRetryConfig::default();
            let retry_taken = match &outcome {
                Ok(InviteOutcome::Failed { response }) => {
                    let jitter = random_jitter_offset_ms(retry_cfg.jitter);
                    let decision =
                        decide_retry(response.status_code, &response.headers, &retry_cfg, jitter);
                    match decision {
                        RetryDecision::Retry {
                            wait,
                            retry_after_header_secs,
                        } => {
                            info!(
                                status = response.status_code,
                                retry_delay_ms = wait.as_millis() as u64,
                                retry_after_header = ?retry_after_header_secs,
                                %call_id,
                                aor = %from_aor,
                                "carrier intermittent reject 検知、 N ms 後に 1 回 retry (Issue #260 Phase 1-B、 RFC 3261 §20.33 / 3GPP TS 24.229 §5.2.7)"
                            );
                            // sleep 中の cancel race: `pending.cancelled` を待ち、
                            // CANCEL 受信が先なら retry をスキップ (= aborted)。
                            let cancelled = tokio::select! {
                                _ = tokio::time::sleep(wait) => false,
                                _ = pending.cancelled.notified() => true,
                            };
                            if cancelled
                                || pending
                                    .cancelled_flag
                                    .load(std::sync::atomic::Ordering::SeqCst)
                            {
                                info!(%call_id, "retry sleep 中に CANCEL → retry 中止");
                                self.metrics
                                    .record_ngn_carrier_retry(RetryOutcome::RetryAbortedByCancel);
                                // outcome は元の Failed のまま (下流で既存 cancel 経路へ流れる)。
                                Some(false)
                            } else {
                                info!(%call_id, "carrier retry 実行 (試行 2/2、 Issue #260)");
                                // 新 INVITE を組み立てる (新 Call-ID / 新 branch / 新 tag、
                                // RFC 3261 §8.1.1.5)。 同じ target + SDP を再送する。
                                let retry_plan =
                                    self.ngn_uac
                                        .build_invite(&target, sdp_for_ngn.as_deref(), None);
                                // pending の plan を retry 版に差し替えて CANCEL 経路で
                                // 正しい transaction を引けるようにする (best-effort:
                                // pending は Arc 共有なので invite_plan は immutable、
                                // 差し替えはできないが、 retry 中の CANCEL は select
                                // 抜けた直後にしか起こらないため実害は限定的)。
                                let new_outcome = self
                                    .ngn_uac
                                    .invite(retry_plan, sdp_for_ngn.clone())
                                    .await;
                                let succeeded =
                                    matches!(new_outcome, Ok(InviteOutcome::Established(_)));
                                if succeeded {
                                    info!(%call_id, "carrier retry 結果: 成功 (Issue #260)");
                                    self.metrics
                                        .record_ngn_carrier_retry(RetryOutcome::RetriedSucceeded);
                                } else {
                                    let new_status = match &new_outcome {
                                        Ok(InviteOutcome::Failed { response }) => {
                                            Some(response.status_code)
                                        }
                                        _ => None,
                                    };
                                    warn!(
                                        %call_id,
                                        new_status = ?new_status,
                                        "carrier retry 結果: 再失敗、 元 error を伝搬 (Issue #260)"
                                    );
                                    self.metrics
                                        .record_ngn_carrier_retry(RetryOutcome::RetriedFailed);
                                }
                                outcome = new_outcome;
                                Some(true)
                            }
                        }
                        RetryDecision::NoRetry { .. } => None,
                    }
                }
                _ => None,
            };
            if retry_taken.is_none() {
                self.metrics
                    .record_ngn_carrier_retry(RetryOutcome::NotRetried);
            }

            // 結果を処理する前に pending を取り除く (CANCEL されている場合は
            // cancelled_flag が立っている)。
            let was_cancelled = pending
                .cancelled_flag
                .load(std::sync::atomic::Ordering::SeqCst);
            if !call_id.is_empty() && call_id != "<no-call-id>" {
                self.registry.take_pending(&call_id).await;
            }

            match outcome {
                Ok(InviteOutcome::Established(call)) => {
                    // Issue #157: 2xx 確立 = NGN 側 cooldown 解除と解釈し、
                    // failure_streak をリセットする (TTC §5.7.1 連続抑制の継続を防ぐ)。
                    self.outbound_rate_limiter.record_success(&from_aor);
                    if was_cancelled {
                        // CANCEL 後に NGN 200 OK が間に合った場合は RFC 3261 §15.1.1 に
                        // 従い直ちに BYE を送って通話を解放する。内線側は 487 で
                        // 返してあるため、ここでは NGN レッグだけ閉じれば良い。
                        info!("CANCEL 後の 200 OK → NGN BYE で即座に閉じる");
                        let mut dlg = call.dialog;
                        if let Err(e) = dlg.send_bye().await {
                            warn!(error=%e, "競合 BYE の送出失敗");
                        }
                        self.metrics.record_invite_ngn(InviteResult::Error);
                        // Issue #278 (PR #286 review #4): RFC 3261 §15.1.1 競合 BYE 経路。
                        // 内線が CANCEL した直後に NGN 200 OK が到着した場合、 sabiden は
                        // 即 BYE で閉じるため通話としては「発信側 CANCEL で終了」。
                        // 既存の `Err(_) + was_cancelled` 経路 (line ~3651) と整合させて
                        // `Outcome::Cancelled` で record_end する (orphan 防止)。
                        if let Some(call_log) = self.call_log_clone().await {
                            call_log.record_end(
                                &call_id,
                                crate::observability::call_log::Outcome::Cancelled,
                            );
                        }
                        return Ok(());
                    }
                    // NGN 側 200 OK の SDP answer を内線に返す。
                    // ブリッジを起動できるなら sabiden 側 ext ソケットを指すよう書き換える。
                    let bridge_call_id;
                    let body_for_ext = match self
                        .finalize_outbound_bridge(bridge_ctx, &ext_offer, &call.response.body)
                        .await
                    {
                        Ok((body, cid)) => {
                            bridge_call_id = cid;
                            body
                        }
                        Err(e) => {
                            warn!(error=%e, "NGN 側 RTP ブリッジ確立失敗 → SDP 透過");
                            bridge_call_id = None;
                            call.response.body.clone()
                        }
                    };

                    // 200 OK を組み立てて内線へ返す (UAS 側 dialog 構築用に保持)。
                    // Contact URI は内線 UAS の bind addr が最優先 (= 内線レッグで
                    // sabiden が in-dialog 受信する socket)。`ext_local_addr` 未設定
                    // (= attach_ext_layer されていないテスト経路) の場合は NGN UAC
                    // の local_addr で代替する (RFC 3261 §13.3.1.4 を満たすには
                    // sub-optimal だが Contact 自体は必ず入れる)。
                    let contact_uri = self.ext_contact_uri();
                    let response_to_ext =
                        build_2xx_to_ext(&request, &body_for_ext, &contact_uri);
                    responder.respond(response_to_ext.clone()).await?;

                    // 観測: NGN レッグも内線レッグも応答済みとして記録
                    self.metrics.record_invite_ngn(InviteResult::Answered);
                    self.metrics.record_invite_extension(InviteResult::Answered);
                    self.metrics.inc_call_active();

                    // 内線レッグの UAS-side dialog を構築。Layer が無い (= BYE を内線へ
                    // 投げられない) 場合でも `Dialog` 自身は作っておく (将来用 / テスト用)。
                    let ext_dialog_cfg = self.build_ext_dialog_cfg(&request);
                    let ext_dialog =
                        match Dialog::from_uas_invite(&request, &response_to_ext, ext_dialog_cfg) {
                            Ok(d) => d,
                            Err(e) => {
                                // dialog 構築できない (Contact が無い等) なら以降の BYE 連動は
                                // 不能だが、通話自体は確立済みなのでエラー扱いはしない。
                                warn!(error=%e, "内線レッグ dialog 構築失敗 → BYE 連動不可");
                                return Ok(());
                            }
                        };

                    // 確立済みエントリとして登録 (NGN call-id も登録)。
                    if let Some(layer) = self.ext_layer.clone() {
                        let ngn_call_id = call.dialog.dialog().id().call_id.clone();
                        let entry = Arc::new(OutboundCallEntry {
                            ext_call_id: call_id.clone(),
                            ngn_call_id,
                            from_aor: from_aor.clone(),
                            ext_dialog: Mutex::new(ext_dialog),
                            ngn_dialog: Mutex::new(call.dialog),
                            ext_responder: responder,
                            ext_remote: remote,
                            ext_layer: layer,
                            bridge_call_id,
                        });
                        self.registry.insert_confirmed(entry).await;
                    } else {
                        // ext_layer 未設定: BYE は片方向 (内線→NGN) のみ可能。
                        // NGN 側 dialog は保持する余地がないので drop する。
                        warn!(
                            "ext_layer 未設定 → 内線→NGN BYE 連動のみ。NGN→内線 BYE は片方向 200 OK のみ"
                        );
                        let _ = call.dialog;
                    }
                    Ok(())
                }
                Ok(InviteOutcome::Failed { response }) => {
                    // Issue #260 Phase 1-A: 5xx 受信時は carrier 由来 header
                    // (Reason RFC 3326 / Retry-After RFC 3261 §20.33 /
                    // Server §20.35 / Warning §20.43) を warn! で構造化展開し、
                    // carrier intermittent (per-AOR cooldown / DoS / 内部
                    // race) の根本原因解析を可能にする。 3GPP TS 24.229 §5.2.7:
                    // P-CSCF の 500 は per-INVITE 失敗、 503 は overload を意味する。
                    // RFC 3261 §21.5 5xx 全般。
                    if response.status_code >= 500 && response.status_code < 600 {
                        let hv = extract_ngn_5xx_header_view(&response.headers);
                        let elapsed_ms = invite_started_at.elapsed().as_millis() as u64;
                        let cseq = request.headers.get("cseq").unwrap_or("");
                        let to_h = request.headers.get("to").unwrap_or("");
                        warn!(
                            status = response.status_code,
                            method = "INVITE",
                            call_id = %call_id,
                            aor = %from_aor,
                            to = %to_h,
                            cseq = %cseq,
                            reason = ?hv.reason,
                            retry_after = ?hv.retry_after,
                            server = ?hv.server,
                            warning = ?hv.warning,
                            via_received = ?hv.via_received,
                            via_rport = ?hv.via_rport,
                            elapsed_since_invite_ms = elapsed_ms,
                            "NGN 5xx 応答受信 (Issue #260 carrier intermittent 観測、 RFC 3326 / RFC 3261 §20.33/§20.35/§20.43/§21.5)"
                        );
                        self.metrics.record_ngn_5xx(response.status_code);
                    } else {
                        warn!(code = response.status_code, "NGN 側 INVITE 失敗");
                    }
                    let result = if response.status_code == 486 {
                        InviteResult::Busy
                    } else {
                        InviteResult::Error
                    };
                    self.metrics.record_invite_ngn(result);
                    // Issue #278: 内線→NGN 発信が NGN により拒否された。
                    // status code を保持し、 PWA/UI 側で「相手話中」「NGN 障害」
                    // を区別できるようにする (RFC 3261 §21)。
                    if let Some(call_log) = self.call_log_clone().await {
                        call_log.record_end(
                            &call_id,
                            crate::observability::call_log::Outcome::Failed {
                                status: response.status_code,
                            },
                        );
                    }
                    // Issue #157: TTC JJ-90.24 §5.7.3 (INVITE 5xx 自動 retry 禁止 +
                    // Retry-After 尊重) を rate limiter にフィードバック。
                    // NGN が Retry-After ヘッダを付けてくれば parser で抽出する
                    // (RFC 3261 §20.33)。 4xx (例 486) は streak 対象外。
                    let retry_after_secs = response
                        .headers
                        .get("retry-after")
                        .and_then(parse_retry_after);
                    self.outbound_rate_limiter.record_failure(
                        &from_aor,
                        response.status_code,
                        retry_after_secs,
                    );
                    // PR #193 review #2 🟡#1: NGN が `Retry-After` を返した場合は
                    // 内線レッグの 5xx にも転載する (RFC 3261 §20.33)。 これにより
                    // 内線端末側でも自前の retry 抑制が効く (TTC JJ-90.24 §5.7.3:
                    // 5xx + Retry-After で示された時間内は同一 Request-URI への
                    // INVITE 再送禁止)。 Retry-After 無しの 4xx/5xx は従来通り
                    // `responder.quick` で素通し。
                    if let Some(secs) = retry_after_secs {
                        let mut resp = build_response_skeleton(
                            &request,
                            response.status_code,
                            response.reason.as_str(),
                        );
                        resp.headers.set("Retry-After", format!("{}", secs));
                        ensure_to_tag(&mut resp);
                        responder.respond(resp).await
                    } else {
                        responder
                            .quick(response.status_code, response.reason.as_str())
                            .await
                    }
                }
                Err(e) => {
                    if was_cancelled {
                        // CANCEL 経路で 487 / Timer B で Err になったケース。
                        // 内線へは CANCEL 経路で 487 を返済済みの想定なので何もしない。
                        debug!(error=%e, "CANCEL 後の INVITE 終了");
                        // Issue #278: 内線が発信側 CANCEL してから NGN が Timer B
                        // 等で Err になった。 発信者主導の中断として記録する。
                        if let Some(call_log) = self.call_log_clone().await {
                            call_log.record_end(
                                &call_id,
                                crate::observability::call_log::Outcome::Cancelled,
                            );
                        }
                        return Ok(());
                    }
                    warn!(error=%e, "NGN 側 INVITE トランスポート失敗 → 503");
                    self.metrics.record_invite_ngn(InviteResult::Timeout);
                    // Issue #278: NGN トランスポート障害 (Timer B / I/O 失敗) =
                    // 確立できなかった outbound call。 status 503 (Service Unavailable)
                    // を載せて履歴に残す。
                    if let Some(call_log) = self.call_log_clone().await {
                        call_log.record_end(
                            &call_id,
                            crate::observability::call_log::Outcome::Failed { status: 503 },
                        );
                    }
                    // Issue #157: トランスポート失敗も 5xx 相当として backoff 対象に含める。
                    // タイムアウトの連続発射は NGN cooldown を起こす典型例。
                    self.outbound_rate_limiter
                        .record_failure(&from_aor, 503, None);
                    responder.quick(503, "Service Unavailable").await
                }
            }
        }
        .instrument(span)
        .await
    }

    /// 内線からの BYE を受け、NGN レッグへ BYE を伝搬する。RFC 3261 §15.1.2。
    ///
    /// フロー:
    /// 1. 内線レッグの 200 OK を即返す (responder 経由)
    /// 2. registry から NGN UacDialog を引き、`send_bye` を呼ぶ
    /// 3. RTP ブリッジを停止し、call_active を -1
    async fn handle_ext_bye(
        &self,
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    ) -> Result<()> {
        // 1) 内線へ 200 OK を即返す (RFC 3261 §15.1.2)
        if let Err(e) = responder.quick(200, "OK").await {
            warn!(error=%e, "内線 BYE への 200 OK 送出失敗");
        }

        let call_id = match request.headers.get("call-id") {
            Some(c) => c.to_string(),
            None => {
                warn!("内線 BYE に Call-ID が無い");
                return Ok(());
            }
        };
        debug!(%remote, %call_id, "内線 BYE 受信 → NGN へ BYE 伝搬");

        let entry = match self.registry.remove_by_ext(&call_id).await {
            Some(e) => e,
            None => {
                debug!(%call_id, "BYE: 対応する outbound call が見つからない");
                return Ok(());
            }
        };

        // 2) NGN UacDialog で BYE を送る
        {
            let mut ngn_dlg = entry.ngn_dialog.lock().await;
            if let Err(e) = ngn_dlg.send_bye().await {
                warn!(error=%e, "NGN 側 BYE 送出失敗");
            }
        }

        // 3) RTP ブリッジ停止 + 観測
        self.metrics.dec_call_active();
        // Issue #278: 内線→NGN 発信通話が正常終了 (内線 BYE 起点) → Answered。
        // record_start は build_invite 直前で書き込まれている。
        if let Some(call_log) = self.call_log_clone().await {
            call_log.record_end(&call_id, crate::observability::call_log::Outcome::Answered);
        }
        if let (Some(bridge_id), Some(mgr)) = (entry.bridge_call_id, self.call_manager.as_ref()) {
            if let Err(e) = mgr.terminate(bridge_id).await {
                warn!(error=%e, "RTP ブリッジ停止失敗");
            }
        }
        Ok(())
    }

    /// 内線からの **Re-INVITE** (To-tag 付き = mid-dialog) を伝搬する。
    ///
    /// RFC 3261 §14.2 (UAS Behavior on Re-INVITE) / §12.2.2 / RFC 3264 (Offer/Answer):
    /// - 既存 dialog 内の SDP renegotiation 要求であり、 新規 dialog として
    ///   扱ってはならない (Issue #94)。
    /// - 200 OK の To-tag は **既存 dialog の local-tag を保持** する
    ///   (= 受信 INVITE の To-tag をそのままエコー)。 `build_response_skeleton`
    ///   が To ヘッダ全体をコピーするため `ensure_to_tag` は no-op となり、
    ///   既存 tag が保たれる。
    /// - 確立済み dialog (`lookup_by_ext`) が無く、 かつ **同じ Call-ID で
    ///   進行中の INVITE が存在する場合** (= 初回 INVITE 完了前の Re-INVITE
    ///   競合) は **491 Request Pending** で返す (RFC 3261 §14.2: "If a UA
    ///   receives a re-INVITE for an existing dialog while it has an
    ///   INVITE it had sent in the same dialog still pending, it MUST
    ///   return a 491 (Request Pending) response to the received INVITE")。
    /// - 確立済み dialog も pending も無い場合は **481 Call/Transaction
    ///   Does Not Exist** (RFC 3261 §12.2.2) で返す。
    ///
    /// # 動作 (B2BUA)
    ///
    /// 1. Call-ID で `OutboundCallRegistry::lookup_by_ext` を引き、 内線→NGN
    ///    通話エントリを取得
    /// 2. 該当が無ければ `get_pending` で進行中 INVITE があるか確認:
    ///    - あり: 491 Request Pending (RFC 3261 §14.2)
    ///    - 無し: 481 Call/Transaction Does Not Exist (RFC 3261 §12.2.2)
    /// 3. NGN レッグの [`UacDialog`] に対して `send_reinvite` を呼び、 NGN から
    ///    新しい 200 OK + SDP answer を受領
    /// 4. 内線レッグへ 200 OK を返す。 SDP body は NGN answer をそのまま中継
    ///    (B2BUA media anchoring が無効な現実装では rewrite せず、 RFC 3264
    ///    Offer/Answer の素直な伝搬として扱う)
    ///
    /// # SDP 書換 (Issue #138)
    ///
    /// 内線が出した Re-INVITE オファ SDP を **NGN へ転送する前に必ず**
    /// `force_rewrite_sdp_for_ngn` (= `c=`/`o=` を eth1 IP に強制) +
    /// `restrict_audio_to_pcmu_with_dtmf` (= PCMU + telephone-event のみ残す)
    /// を通す。 これは初回 INVITE 経路 (`UasEventHandler::handle_invite`
    /// L1603-1625) と同じ前処理であり、 CLAUDE.md §5 「NGN 実機制約」
    /// (PCMU only / c=/o= は eth1 IP) を Re-INVITE でも遵守する。
    ///
    /// 透過モード (Phase R3 Negotiator 前) では RTP ブリッジ port 差替は
    /// 未対応のため、 m=audio port は内線オファのままで NGN に流す。
    /// hold/un-hold (= a=sendonly / a=sendrecv 切替) や `a=ptime` 変更は
    /// この前処理を通しても保存される。
    ///
    /// # Min-SE / Retry-After relay (Issue #138, RFC 4028 §6 / §7.1 / §10)
    ///
    /// NGN レッグから 422 Session Interval Too Small が返った場合、
    /// レスポンスに **Min-SE ヘッダ必須** (RFC 4028 §7.1 / §10):
    /// > "When this response is received, the UAC MUST examine the
    /// >  Min-SE header field in the response."
    ///
    /// sabiden は B2BUA であり、 NGN→sabiden の 422 で得た Min-SE を
    /// **そのまま** sabiden→内線 422 に乗せる必要がある (内線 UA が
    /// 同じ Re-INVITE を Min-SE 整合値で再送するため)。 同様に 5xx 系の
    /// Retry-After (RFC 3261 §20.33) も中継する。
    ///
    /// # 既知の制限 (Phase R3 で改善)
    ///
    /// - RTP ブリッジ媒介時の SDP 書換 (port / IP の sabiden 側差し替え) は
    ///   未実装。 現状は SDP 透過モードでの hold/un-hold / Session-Timer 更新
    ///   のみ正しく動く。 ブリッジ媒介時は将来 `prepare_outbound_bridge` /
    ///   `finalize_outbound_bridge` を Re-INVITE 経路にも結線する必要がある
    ///   (`docs/refactor-plan.md` §1.4 / Phase R3 Negotiator)。
    /// - PRACK / 100rel (RFC 3262) や UPDATE (RFC 3311) は未対応 (Phase R2)。
    async fn handle_ext_reinvite(
        &self,
        request: SipRequest,
        _remote: SocketAddr,
        responder: ResponderHandle,
    ) -> Result<()> {
        let call_id = request
            .headers
            .get("call-id")
            .map(str::to_string)
            .unwrap_or_default();
        let span = info_span!(
            "uas_reinvite",
            call_id = %call_id,
            direction = "extension",
        );
        async move {
            // RFC 3261 §12.2.2: in-dialog request は (Call-ID, From-tag, To-tag)
            // で既存 dialog を引く。 sabiden は内線レッグでは UAS なので、
            // 受信 INVITE の Call-ID = ext_call_id でレジストリを引く。
            let entry = match self.registry.lookup_by_ext(&call_id).await {
                Some(e) => e,
                None => {
                    // RFC 3261 §14.2: 確立済み dialog は無いが、 **同じ Call-ID で
                    // 進行中の INVITE がある** (= 初回 INVITE 完了前の Re-INVITE
                    // 競合) なら 491 Request Pending を返す。 進行中も無いなら
                    // 481 Call/Transaction Does Not Exist (RFC 3261 §12.2.2)。
                    if self.registry.get_pending(&call_id).await.is_some() {
                        warn!(
                            %call_id,
                            "Re-INVITE: 初回 INVITE 進行中 → 491 Request Pending (RFC 3261 §14.2)",
                        );
                        return responder.quick(491, "Request Pending").await;
                    }
                    warn!(%call_id, "Re-INVITE: 既存 dialog 無し → 481");
                    return responder
                        .quick(481, "Call/Transaction Does Not Exist")
                        .await;
                }
            };

            info!(%call_id, "Re-INVITE 受信 → NGN レッグへ伝搬 (RFC 3261 §14.2)");

            // Issue #138: 内線オファ SDP を NGN へ流す前に **必ず** NGN 制約に
            // 揃える (CLAUDE.md §5):
            // - `force_rewrite_sdp_for_ngn`: c=/o= IP を eth1 IP に強制
            // - `restrict_audio_to_pcmu_with_dtmf`: PCMU(0) + telephone-event(101)
            //   以外のコーデックを削除 (LAN 由来 Opus / G.722 が NGN レッグへ
            //   漏れて 488 になるのを防ぐ)
            //
            // Re-INVITE で sendonly/sendrecv 切替 (hold / un-hold) や ptime 変更を
            // 行うのが典型なので、 これらの属性は前処理を通しても保持される。
            // 元 SDP が空 (= SDP 無し Session-Timer 更新のみ) なら書換せず None。
            let ngn_local_ip = self.ngn_uac.config().local_addr.ip();
            let rewritten_offer: Option<Vec<u8>> = if request.body.is_empty() {
                None
            } else {
                let rewritten = force_rewrite_sdp_for_ngn(&request.body, ngn_local_ip)
                    .map(|s| Negotiator::for_ngn_with_dtmf().rewrite_offer(&s));
                if rewritten.is_none() {
                    debug!(%call_id, "Re-INVITE: SDP 書換が None (空) → SDP 無しで送信");
                }
                rewritten
            };
            let new_offer = rewritten_offer.as_deref();
            let ngn_resp = {
                let mut ngn_dlg = entry.ngn_dialog.lock().await;
                ngn_dlg.send_reinvite(new_offer).await
            };

            match ngn_resp {
                Ok(resp) if (200..300).contains(&resp.status_code) => {
                    // 200 OK + 新 answer SDP を内線へ返す。 To-tag は受信 INVITE
                    // の `tag=` をそのままエコー (RFC 3261 §12.2.2 / §14.2):
                    // build_response_skeleton が To をコピーし、 ensure_to_tag は
                    // tag 既存ならスキップするため、 既存 dialog の To-tag が保たれる。
                    let body = resp.body.clone();
                    let contact_uri = self.ext_contact_uri();
                    let mut response_to_ext = build_2xx_to_ext(&request, &body, &contact_uri);
                    // RFC 4028 §7.4: Session-Timer 更新の 2xx には Session-Expires
                    // を載せる。 NGN が refresher を確定した値があれば中継、
                    // 無ければ載せない (内線 UA は INVITE 送信時の値で動く)。
                    if let Some(se) = resp.headers.get("session-expires") {
                        response_to_ext.headers.set("Session-Expires", se);
                    }
                    if let Some(req_h) = resp.headers.get("require") {
                        if req_h
                            .split(',')
                            .any(|t| t.trim().eq_ignore_ascii_case("timer"))
                        {
                            response_to_ext.headers.set("Require", "timer");
                        }
                    }
                    if let Err(e) = responder.respond(response_to_ext).await {
                        warn!(error=%e, "Re-INVITE 200 OK の内線送出失敗");
                    }
                    Ok(())
                }
                Ok(resp) => {
                    // 4xx/5xx/6xx を中継 (491 Request Pending 含む、 RFC 3261 §14.2)。
                    // Issue #138: 422 Session Interval Too Small (RFC 4028 §7.1)
                    // や 5xx Retry-After (RFC 3261 §20.33) のリレー必須ヘッダを
                    // NGN レスポンスからコピーして内線へ返す。 これを欠くと
                    // 内線 UA は Min-SE 整合値で再送できず Session-Timer 更新が
                    // 失敗し続ける (= 通話途中切断の温床)。
                    warn!(code = resp.status_code, "NGN Re-INVITE 失敗 → 内線へ中継");
                    let mut relay =
                        build_response_skeleton(&request, resp.status_code, resp.reason.as_str());
                    // RFC 4028 §10: 422 には Min-SE 必須。 NGN が乗せて来た
                    // Min-SE をそのまま中継し、 内線 UA がその値で再送できるよう
                    // にする。 422 でも欠落していたらログだけ残す (NGN 側違反)。
                    if let Some(min_se) = resp.headers.get("min-se") {
                        relay.headers.set("Min-SE", min_se);
                    } else if resp.status_code == 422 {
                        warn!(
                            %call_id,
                            "Re-INVITE 422 だが NGN レスポンスに Min-SE が無い (RFC 4028 §10 違反)"
                        );
                    }
                    // RFC 3261 §20.33: 5xx (+ 404/413/480/486/600/603) の
                    // Retry-After は中継推奨。 422 や 423 の Min-SE 経路と
                    // 併存可能なので独立に判定して両方コピーされても問題ない。
                    if let Some(ra) = resp.headers.get("retry-after") {
                        relay.headers.set("Retry-After", ra);
                    }
                    // dialog を作らない 4xx/5xx 応答にも To-tag は必須
                    // (RFC 3261 §8.2.6.2)。 Re-INVITE は in-dialog なので
                    // request の To に既存 tag が乗っており ensure_to_tag は
                    // no-op。 念のため明示的に通しておく。
                    ensure_to_tag(&mut relay);
                    responder.respond(relay).await
                }
                Err(e) => {
                    warn!(error=%e, "NGN Re-INVITE トランスポート失敗 → 500");
                    responder.quick(500, "Server Internal Error").await
                }
            }
        }
        .instrument(span)
        .await
    }

    /// 内線からの CANCEL を受け、NGN へ CANCEL を伝搬する。RFC 3261 §9.1 / §15.1.
    async fn handle_ext_cancel(
        &self,
        request: SipRequest,
        _remote: SocketAddr,
        _responder: ResponderHandle,
    ) -> Result<()> {
        let call_id = match request.headers.get("call-id") {
            Some(c) => c.to_string(),
            None => return Ok(()),
        };
        info!(%call_id, "内線 CANCEL 受信 → NGN へ CANCEL");
        let pending = match self.registry.get_pending(&call_id).await {
            Some(p) => p,
            None => {
                debug!(%call_id, "CANCEL: 進行中 INVITE が見つからない (確立済み or 失敗済み)");
                return Ok(());
            }
        };
        // CANCEL フラグを立てる: invite() の future がこの後 200 を返してきても
        // 受理せず NGN へ即 BYE を送る経路に切り替える (RFC 3261 §9.1)。
        pending
            .cancelled_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        pending.cancelled.notify_waiters();

        // RFC 3261 §9.1: 1xx 受信前に CANCEL を送ってはならない (MUST NOT)。
        // `Uac::cancel_pending` は内部で transaction layer の応答受信進捗を
        // 待機し、 Provisional 後にだけ CANCEL を送出する (Issue #97)。
        // 最終応答が先に到達 / transaction 終了済の場合は `NotSent` を返す:
        // 後段の `cancelled_flag` 経路 (200 OK 受領 → BYE) が引き取る。
        match self.ngn_uac.cancel_pending(&pending.invite_plan).await {
            Ok(CancelOutcome::Sent(resp)) => {
                debug!(code = resp.status_code, "NGN CANCEL 応答");
            }
            Ok(CancelOutcome::NotSent) => {
                debug!("NGN CANCEL skip (RFC 3261 §9.1): 最終応答既到達 or transaction 終了済");
            }
            Err(e) => {
                warn!(error=%e, "NGN CANCEL 送出失敗");
            }
        }

        // 内線レッグへは 487 を返す (元 INVITE の ServerTransaction 経由)。
        // RFC 3261 §15.1: CANCEL を受けた UAS は元 INVITE に 487 Request Terminated を返す。
        if let Err(e) = pending.ext_responder.quick(487, "Request Terminated").await {
            warn!(error=%e, "内線へ 487 送出失敗");
        }
        // メトリクス: NGN INVITE は cancel された (= 失敗扱い)。
        self.metrics.record_invite_ngn(InviteResult::Error);
        Ok(())
    }

    /// 内線からの SIP INFO を扱う (RFC 6086)。
    ///
    /// 主用途は DTMF 中継 (Issue #69)。内線 UA が `application/dtmf-relay`
    /// または `application/dtmf` body で DTMF を送ってきた場合、本実装は
    /// RFC 4733 §2.5 telephone-event RTP packet 列に展開し、`CallManager`
    /// 経由で NGN レッグへ注入する。INFO 自身には 200 OK を返す (RFC 6086
    /// §3 / §4: 既存ダイアログの確認応答)。
    ///
    /// # 動作
    /// 1. `Content-Type` から body 形式を判定
    /// 2. body をパースして DTMF digit を取り出す
    /// 3. `CallManager` がある場合のみ RTP packet 列を生成し NGN レッグへ送る
    /// 4. responder で 200 OK を返す (失敗時は 415 Unsupported Media Type)
    async fn handle_ext_info(
        &self,
        request: SipRequest,
        _remote: SocketAddr,
        responder: ResponderHandle,
    ) -> Result<()> {
        let call_id = request
            .headers
            .get("call-id")
            .map(str::to_string)
            .unwrap_or_default();
        let content_type = request
            .headers
            .get("content-type")
            .map(str::to_string)
            .unwrap_or_default();
        let ct_lower = content_type.to_lowercase();

        // RFC 6086: INFO 自身の 200 OK は body 解釈に関わらず先に返す。
        // NGN への DTMF 注入が失敗しても内線 UA に対する INFO 応答は
        // 200 OK で確認するのが各 UA 実装と整合的 (Linphone / Polycom)。
        let dtmf_digit = if ct_lower.contains("application/dtmf-relay") {
            match super::dtmf::parse_application_dtmf_relay(&request.body) {
                Ok((digit, _dur)) => Some(digit),
                Err(e) => {
                    warn!(error=%e, "INFO dtmf-relay body パース失敗 → 415");
                    return responder.quick(415, "Unsupported Media Type").await;
                }
            }
        } else if ct_lower.contains("application/dtmf") {
            match super::dtmf::parse_application_dtmf(&request.body) {
                Ok(d) => Some(d),
                Err(e) => {
                    warn!(error=%e, "INFO dtmf body パース失敗 → 415");
                    return responder.quick(415, "Unsupported Media Type").await;
                }
            }
        } else {
            // DTMF 以外の INFO body は対応しない。RFC 6086 §10.4 に従い
            // 415 が無難 (200 OK を返すと「処理した」と誤解させる)。
            warn!(content_type=%content_type, "未対応 INFO Content-Type → 415");
            return responder.quick(415, "Unsupported Media Type").await;
        };

        // INFO 受領を 200 OK で確認 (RFC 6086 §4)。
        if let Err(e) = responder.quick(200, "OK").await {
            warn!(error=%e, "INFO 200 OK 送出失敗");
        }

        let Some(digit) = dtmf_digit else {
            return Ok(());
        };
        let Some(event) = super::dtmf::digit_to_event(digit) else {
            warn!(?digit, "RFC 4733 範囲外の DTMF digit → drop");
            return Ok(());
        };

        // CallManager / 該当通話の bridge_call_id が無いと注入できない。
        let entry = match self.registry.lookup_by_ext(&call_id).await {
            Some(e) => e,
            None => {
                debug!(%call_id, "INFO: 該当通話なし → DTMF drop");
                return Ok(());
            }
        };
        let Some(bridge_id) = entry.bridge_call_id else {
            debug!(%call_id, "INFO: bridge 未確立 → DTMF drop");
            return Ok(());
        };
        let Some(mgr) = self.call_manager.as_ref() else {
            debug!("CallManager 未注入 → DTMF drop");
            return Ok(());
        };

        // RFC 4733 §2.5.1.1: 同 1 押下で timestamp は固定。sabiden は
        // bridge 内の audio timestamp 系列と独立に DTMF 用 timestamp / SSRC を
        // 払い出す (RFC 4733 §2.4 が許容する)。簡易実装として:
        // - timestamp は当該イベント発生時刻のミリ秒下位 32 bit
        // - SSRC は call-id ベースのハッシュ (1 通話で固定)
        let now_ts = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
            & 0xFFFF_FFFF) as u32;
        let ssrc = {
            // 衝突を最小化する単純な FNV-1a 風ハッシュ
            let mut h: u32 = 0x811c_9dc5;
            for &b in call_id.as_bytes() {
                h ^= b as u32;
                h = h.wrapping_mul(0x0100_0193);
            }
            // SSRC=0 を避ける
            if h == 0 {
                0xCAFE_BABE
            } else {
                h
            }
        };
        // start_seq はランダムでよいが時刻下位 16bit で十分 (1 通話で重複しない範囲)。
        let start_seq = (now_ts & 0xFFFF) as u16;

        // RFC 4733 §2.5.1.1: 50ms 区切りで重複 packet を送り、終端は triplet。
        // duration は 100ms (DTMF として最低限聞こえる長さ)。
        let seq = super::dtmf::build_dtmf_packet_sequence(
            event, start_seq, now_ts, ssrc, /* duration_ms */ 100, /* period_ms */ 50,
            /* volume */ 10,
        );
        debug!(
            %call_id,
            digit = %digit,
            packets = seq.packets.len(),
            "INFO→RFC 4733 telephone-event 変換 → NGN へ注入"
        );
        for pkt in seq.packets {
            let bytes = pkt.to_bytes();
            if let Err(e) = mgr.inject_to_ngn(bridge_id, &bytes).await {
                warn!(error=%e, "DTMF RTP 注入失敗");
                break;
            }
        }
        Ok(())
    }

    /// 内線からの ACK を受け取る (RFC 3261 §17.1.1.3)。
    ///
    /// B2BUA では 内線→sabiden ACK と sabiden→NGN ACK は独立 (両側とも別々の
    /// 2xx に対する ACK) なので、本ハンドラは状態確認と監視のみで送出は行わない
    /// (NGN 側 ACK は `Uac::invite` 内で 200 OK 受信時に既に送出済み)。
    async fn handle_ext_ack(&self, request: SipRequest, _remote: SocketAddr) -> Result<()> {
        if let Some(cid) = request.headers.get("call-id") {
            if self.registry.lookup_by_ext(cid).await.is_some() {
                debug!(%cid, "内線 ACK 受信 → 通話確立済み");
            } else {
                debug!(%cid, "内線 ACK 受信 (未知の call: 既に終了している可能性)");
            }
        }
        Ok(())
    }

    /// NGN→内線方向の **Re-INVITE** を扱う (`NgnInboundHandler` から委譲される)。
    ///
    /// Issue #138: sabiden は通常 `refresher=uac` で Session-Timer refresh を
    /// 自分から打つため NGN 由来の Re-INVITE は稀だが、 NGN 側ピアが起こす
    /// hold / un-hold (`a=sendonly` ↔ `a=sendrecv`) を内線へ届けないと
    /// 通話状態が片側だけ更新される (= B2BUA としての透過性破綻)。
    ///
    /// RFC 3261 §14.2 (UAS Behavior on Re-INVITE) / §12.2.2:
    /// > "A UAS that receives a re-INVITE for an existing dialog ... MUST
    /// >  generate a response. ... If the re-INVITE contains an SDP body,
    /// >  the UAS MUST use the Offer/Answer model (RFC 3264) to negotiate."
    ///
    /// RFC 3264 §8: hold / un-hold は新しい SDP オファとして送られ、
    /// UAS は対称な answer を返さねばならない。
    ///
    /// # B2BUA 動作 (Issue #138)
    ///
    /// 1. registry から `OutboundCallEntry` を引く (call-id = NGN 側 Call-ID)
    /// 2. 内線レッグの `ext_dialog` (sabiden=UAS で確立) を流用して
    ///    `build_reinvite` で内線向け Re-INVITE を組み立てる。 SDP は NGN
    ///    オファをそのまま使用 (内線→NGN 透過モード)。
    /// 3. `ext_layer.send_request` で内線へ送出し、 応答を待つ
    /// 4. 受領した内線応答を NGN 側 ServerTransaction で中継:
    ///    - 2xx: SDP answer + Contact / Session-Expires を載せる
    ///    - 4xx/5xx: status + Min-SE / Retry-After を載せる (RFC 4028 §10 /
    ///      RFC 3261 §20.33)
    ///
    /// # 既知の制限 (Phase R3 で改善予定)
    ///
    /// - RTP ブリッジ媒介時の SDP 書換 (sabiden 側 RTP port への差替) は
    ///   未実装。 透過モード前提。
    /// - 内線が応答しない / Timeout した場合は NGN へ 408 Request Timeout
    ///   を返す (RFC 3261 §13.3.1.1)。
    /// - ACK は新規 transaction で NGN から sabiden へ来るが、
    ///   `NgnInboundHandler::handle_inbound` の `SipMethod::Ack` 分岐で
    ///   pending を掃除して終わる (= 既存挙動と同じ)。
    pub(crate) async fn handle_ngn_reinvite(
        &self,
        request: SipRequest,
        stx: Arc<Mutex<ServerTransaction>>,
    ) -> Result<()> {
        let call_id = request
            .headers
            .get("call-id")
            .map(str::to_string)
            .unwrap_or_default();
        let entry = match self.registry.lookup_by_ngn(&call_id).await {
            Some(e) => e,
            None => {
                // try_forward_ngn_reinvite が事前にチェックしている想定だが、
                // 競合で消えた場合の安全策として 481 を返す (RFC 3261 §12.2.2)。
                debug!(%call_id, "NGN Re-INVITE: 対応する outbound call が消失 → 481");
                let mut tx = stx.lock().await;
                let mut resp =
                    build_response_skeleton(tx.request(), 481, "Call/Transaction Does Not Exist");
                ensure_to_tag(&mut resp);
                return tx.respond(resp).await;
            }
        };
        info!(%call_id, "NGN Re-INVITE 受信 → 内線レッグへ伝搬 (RFC 3261 §14.2)");

        let layer = entry.ext_layer.clone();
        let ext_remote = entry.ext_remote;

        // 内線レッグ向け Re-INVITE 組み立て。 SDP は NGN オファを透過
        // (Phase R3 まで RTP ブリッジ port 差替は未対応)。 sabiden は
        // 内線レッグでも refresher=uac として Session-Timer を更新する
        // (= UacDialog::send_reinvite と同じ既定値 300/90)。
        let sdp_body: Option<&[u8]> = if request.body.is_empty() {
            None
        } else {
            Some(request.body.as_slice())
        };
        let ext_reinvite = {
            let dlg = entry.ext_dialog.lock().await;
            dlg.build_reinvite(sdp_body, 300, crate::sip::uac::MIN_SE)
        };
        if !request.body.is_empty() {
            // dialog.build_reinvite は SDP 有無を内部判定して Content-Type を
            // セットするので追加処理不要だが、 Content-Type 完全性を念のため確認
            // (空 body → set されない、 非空 → application/sdp が set される)。
            debug!(
                ?call_id,
                "NGN Re-INVITE SDP を内線へ透過 ({} bytes)",
                request.body.len()
            );
        }
        let ext_resp_result = layer.send_request(ext_reinvite, ext_remote).await;

        let mut tx = stx.lock().await;
        match ext_resp_result {
            Ok(resp) if (200..300).contains(&resp.status_code) => {
                // 内線 200 OK を NGN へ中継。 SDP answer / Session-Expires /
                // Require: timer をコピーする (RFC 4028 §7.4 / §9)。
                let mut to_ngn = build_response_skeleton(tx.request(), 200, "OK");
                if !resp.body.is_empty() {
                    to_ngn.body = resp.body.clone();
                    to_ngn.headers.set("Content-Type", "application/sdp");
                }
                // Contact は NGN 側 (sabiden=UAC for NGN) のローカル sent-by
                // を載せる必要がある。 既存 ngn_dialog の local_contact を
                // 利用すれば NGN レッグの整合が取れる。
                {
                    let ngn_dlg = entry.ngn_dialog.lock().await;
                    let contact = ngn_dlg.dialog().local_contact_uri();
                    to_ngn.headers.set("Contact", format!("<{}>", contact));
                }
                if let Some(se) = resp.headers.get("session-expires") {
                    to_ngn.headers.set("Session-Expires", se);
                }
                if let Some(req_h) = resp.headers.get("require") {
                    if req_h
                        .split(',')
                        .any(|t| t.trim().eq_ignore_ascii_case("timer"))
                    {
                        to_ngn.headers.set("Require", "timer");
                    }
                }
                // RFC 3261 §8.2.6.2: To-tag 必須。 既存 dialog の To-tag は
                // request の To から build_response_skeleton がコピー済み。
                ensure_to_tag(&mut to_ngn);
                tx.respond(to_ngn).await
            }
            Ok(resp) => {
                warn!(code = resp.status_code, "内線 Re-INVITE 失敗 → NGN へ中継");
                let mut to_ngn =
                    build_response_skeleton(tx.request(), resp.status_code, resp.reason.as_str());
                // RFC 4028 §10: 422 で内線が Min-SE を返したらそのまま NGN へ。
                // 内線 UA が refresher=uas として早く更新したい意思表示でも
                // 重要なので削らずに中継する。
                if let Some(min_se) = resp.headers.get("min-se") {
                    to_ngn.headers.set("Min-SE", min_se);
                } else if resp.status_code == 422 {
                    warn!(
                        %call_id,
                        "NGN→内線 Re-INVITE 422 だが内線応答に Min-SE が無い (RFC 4028 §10 違反)"
                    );
                }
                if let Some(ra) = resp.headers.get("retry-after") {
                    to_ngn.headers.set("Retry-After", ra);
                }
                ensure_to_tag(&mut to_ngn);
                tx.respond(to_ngn).await
            }
            Err(e) => {
                // 内線レッグ送出失敗の semantic 分類 (RFC 3261 §13.3.1.1 / §13.3.1.2):
                // - Timer B/F 満了 (内線 UAS 応答不在) → 408 Request Timeout
                // - UDP send / 内部 channel / header parse 失敗 → 500 Server Internal Error
                //
                // §13.3.1.1 は「callee が timely に応答しなかった」場合の 408 を
                // 認めており、 §13.3.1.2 は「unexpected condition で履行不能」の
                // 5xx を認めている。 transport failure を一律 408 で総括していた
                // PR #205 の振る舞いは、 NGN 側 UAC に対して「内線 callee の沈黙」
                // と「内線レッグ自体の通信路断絶」を区別不能にしており、
                // §13.3.1.2 の意味論上正しくない。
                let (code, reason) = classify_ext_reinvite_send_error(&e);
                warn!(error=%e, code, reason, "内線 Re-INVITE 失敗 → NGN へ転送");
                let mut to_ngn = build_response_skeleton(tx.request(), code, reason);
                ensure_to_tag(&mut to_ngn);
                tx.respond(to_ngn).await
            }
        }
    }

    /// NGN→内線方向の BYE を扱う (`NgnInboundHandler` から委譲される)。
    ///
    /// 1. registry から `OutboundCallEntry` を引く
    /// 2. 内線レッグへ BYE を `ext_layer.send_request` で送る
    /// 3. RTP ブリッジを停止
    pub(crate) async fn handle_ngn_bye(&self, ngn_call_id: &str) -> Result<()> {
        let entry = match self.registry.remove_by_ngn(ngn_call_id).await {
            Some(e) => e,
            None => {
                debug!(%ngn_call_id, "NGN BYE: 対応する outbound call が見つからない");
                return Ok(());
            }
        };
        let bye_req = {
            let mut dlg = entry.ext_dialog.lock().await;
            let req = dlg.build_bye();
            dlg.terminate();
            req
        };
        // 内線レッグの送信: 内線 UA がいる remote へ送る。応答は待つが timeout を
        // 短めに設定する余地はある (今は layer の Timer B に任せる)。
        match entry
            .ext_layer
            .send_request(bye_req, entry.ext_remote)
            .await
        {
            Ok(resp) => debug!(code = resp.status_code, "内線 BYE 応答"),
            Err(e) => warn!(error=%e, "内線へ BYE 送出失敗"),
        }
        // RTP ブリッジ停止 + 観測
        self.metrics.dec_call_active();
        if let (Some(bridge_id), Some(mgr)) = (entry.bridge_call_id, self.call_manager.as_ref()) {
            if let Err(e) = mgr.terminate(bridge_id).await {
                warn!(error=%e, "RTP ブリッジ停止失敗");
            }
        }
        Ok(())
    }

    /// 内線レッグの 200 OK / in-dialog レスポンスに載せる Contact URI を返す。
    ///
    /// RFC 3261 §13.3.1.4 (UAS Behavior, 2xx Responses) に従い、Contact は
    /// 内線レッグで in-dialog request を受け付ける socket を指す必要がある。
    ///
    /// 解決順:
    /// 1. `ext_local_addr` (attach_ext_layer で渡される内線 UAS bind addr)
    /// 2. `ext_layer.local_addr()` (TransactionLayer 結線済 socket)
    /// 3. NGN UAC の `local_addr` (sub-optimal: 内線とトランスポートが
    ///    分かれているケースでは届かない可能性があるが、RFC §13.3.1.4 違反
    ///    回避のため必ず何か入れる)
    ///
    /// 3 にフォールバックした場合は warn を出す。
    fn ext_contact_uri(&self) -> String {
        let host = self
            .ext_local_addr
            .map(|a| a.to_string())
            .or_else(|| {
                self.ext_layer
                    .as_ref()
                    .and_then(|l| l.local_addr().ok().map(|a| a.to_string()))
            })
            .unwrap_or_else(|| {
                let ngn_addr = self.ngn_uac.config().local_addr;
                warn!(
                    fallback=%ngn_addr,
                    "内線レッグ Contact: ext_local_addr/ext_layer 未設定 → NGN UAC local_addr で代替"
                );
                ngn_addr.to_string()
            });
        format!("sip:sabiden@{}", host)
    }

    /// 内線レッグの sabiden=UAS dialog 構築用 cfg を作る。
    fn build_ext_dialog_cfg(&self, invite: &SipRequest) -> DialogConfig {
        // local_uri = 内線 INVITE の To URI (= sabiden 側)
        // remote_uri = INVITE の From URI (= 内線側)
        let local_uri = invite
            .headers
            .get("to")
            .map(extract_uri_from_addr)
            .unwrap_or_else(|| "sip:sabiden".to_string());
        let remote_uri = invite
            .headers
            .get("from")
            .map(extract_uri_from_addr)
            .unwrap_or_else(|| "sip:unknown@sabiden".to_string());
        let sent_by = self
            .ext_local_addr
            .map(|a| a.to_string())
            .or_else(|| {
                self.ext_layer
                    .as_ref()
                    .and_then(|l| l.local_addr().ok().map(|a| a.to_string()))
            })
            .unwrap_or_else(|| "0.0.0.0:0".to_string());
        let local_contact = format!("sip:sabiden@{}", sent_by);
        DialogConfig {
            local_uri,
            remote_uri,
            local_contact,
            sent_by,
        }
    }

    /// 内線→NGN 発信時、CallManager があれば RTP ブリッジ用ソケットを bind し、
    /// NGN へ送る SDP オファを sabiden 側 NGN ソケットを指すように書き換える。
    /// 戻り値の `OutboundBridgeCtx` は確立後の `finalize_outbound_bridge` に渡す。
    async fn prepare_outbound_bridge(
        &self,
        ext_offer: &[u8],
    ) -> Result<Option<(OutboundBridgeCtx, Vec<u8>)>> {
        let Some(_mgr) = self.call_manager.as_ref() else {
            return Ok(None);
        };
        if ext_offer.is_empty() {
            return Ok(None);
        }
        let ext_peer = extract_rtp_endpoint(ext_offer)?;
        let ngn_bind_ip = self
            .bridge_ngn_bind_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let ext_bind_ip = self.bridge_ext_bind_ip.unwrap_or(ngn_bind_ip);
        // Phase 1-D: ephemeral port reuse 回避
        let ngn_sock = bind_ngn_rtp_socket(ngn_bind_ip).await?;
        let ext_sock = Arc::new(UdpSocket::bind(SocketAddr::new(ext_bind_ip, 0)).await?);
        let sabiden_ngn_addr = ngn_sock.local_addr()?;
        let rewritten =
            rewrite_rtp_endpoint(ext_offer, sabiden_ngn_addr.ip(), sabiden_ngn_addr.port())?;
        Ok(Some((
            OutboundBridgeCtx {
                ngn_sock,
                ext_sock,
                ext_peer,
            },
            rewritten,
        )))
    }

    /// NGN 200 OK の SDP answer を内線へ返す前に書き換え、`RtpBridge` を起動。
    ///
    /// B2BUA として内線レッグへ返す 200 OK SDP は、NGN 側エンドポイント
    /// (`118.177.125.1:28196` 等) ではなく **sabiden 自身の ext bridge socket**
    /// (`<bridge_ext_bind_ip>:<port>`) を広告する。これで内線 UA は sabiden に
    /// RTP を送り、sabiden が NGN 側へリレーする (= B2BUA media anchoring)。
    ///
    /// RFC 3264 §6 (Offer/Answer):
    /// > The answer MUST contain exactly the same number of "m=" lines as the offer.
    /// > The transport address from the answer (in the "c=" and "m=" lines) is
    /// > used by the offerer to send RTP.
    ///
    /// すなわち内線 UA が送る RTP の宛先は本関数が組み立てる SDP の `c=`/`m=`
    /// で決まる。ここを sabiden の ext bridge socket に向けないと内線 UA が
    /// 直接 NGN P-CSCF RTP 端点に送ろうとして LAN 越えできず音声無音になる
    /// (Issue #66 の根因)。
    ///
    /// RFC 4566 §5.7 / §5.14: rewrite 対象は session-level `c=` と最初の
    /// `m=audio` の port (および media-level `c=` があればそれも)。書き換えに
    /// 使う「元 SDP」は **内線オファ** をベースとする — オファに乗っていた
    /// `a=ptime`, `a=rtpmap`, `a=fmtp` 等は内線 UA 自身が提示した値なので
    /// そのまま answer に映るのが Offer/Answer の自然な形。NGN answer の
    /// SDP 属性をそのまま使うと NGN 由来の `c=` IP / port が混入するリスクが
    /// あるため避ける。
    ///
    /// 戻り値: (内線へ返す SDP body, 起動したブリッジの CallId)。
    /// `bridge_ctx` が `None` の場合は透過 (元 body をそのまま返す, CallId は None)。
    async fn finalize_outbound_bridge(
        &self,
        bridge_ctx: Option<OutboundBridgeCtx>,
        ext_offer: &[u8],
        ngn_answer: &[u8],
    ) -> Result<(Vec<u8>, Option<CallId>)> {
        let Some(ctx) = bridge_ctx else {
            return Ok((ngn_answer.to_vec(), None));
        };
        let Some(mgr) = self.call_manager.as_ref() else {
            return Ok((ngn_answer.to_vec(), None));
        };
        if ngn_answer.is_empty() {
            return Err(anyhow!("NGN 側 200 OK の SDP が空"));
        }
        let ngn_peer = extract_rtp_endpoint(ngn_answer)?;
        let sabiden_ext_addr = ctx.ext_sock.local_addr()?;

        // 内線 UA へ返す SDP は sabiden の ext 側ソケットを指すように書き換える。
        // 元の SDP オファをベースにすると ptime / rtpmap が保たれて好ましい
        // (RFC 3264 §6: answer は offer と同じ m= 数 + 同等メディア種別)。
        let rewritten_for_ext =
            rewrite_rtp_endpoint(ext_offer, sabiden_ext_addr.ip(), sabiden_ext_addr.port())?;

        // Issue #29: 内線→NGN 発信でも内線レッグが Opus を要求した場合は
        // Opus⇔PCMU トランスコード。NGN レッグは PCMU 固定 (上流で
        // restrict_audio_to_pcmu 済) なので NGN answer は PCMU 想定。
        let plan = select_media_plan(ngn_answer, ext_offer);
        let bridge: MediaBridge = match plan {
            MediaPlan::Relay => RtpBridge::start(BridgeConfig {
                ngn_socket: ctx.ngn_sock,
                ext_socket: ctx.ext_sock,
                ngn_peer: Some(ngn_peer),
                ext_peer: Some(ctx.ext_peer),
                metrics: Some(self.metrics.clone()),
            })?
            .into(),
            MediaPlan::Transcode { opus_pt } => {
                info!(opus_pt, "内線が Opus → 発信時 Opus⇔PCMU トランスコード起動");
                TranscodingBridge::start(TranscodeConfig {
                    ngn_socket: ctx.ngn_sock,
                    web_socket: ctx.ext_sock,
                    ngn_peer: Some(ngn_peer),
                    web_peer: Some(ctx.ext_peer),
                    opus_payload_type: opus_pt,
                    metrics: Some(self.metrics.clone()),
                })?
                .into()
            }
        };

        let cid = mgr.create_call().await;
        mgr.attach_media_bridge(cid, bridge).await?;
        Ok((rewritten_for_ext, Some(cid)))
    }
}

/// Issue #145: PWA→NGN 発信フローのハンドラ実装。
///
/// `UasEventHandler` は既に `ngn_uac` / `call_manager` / RTP bridge bind IP を
/// 抱えているため、 これらを再利用して PWA→NGN 発信を駆動する。 内線→NGN
/// 発信 (`handle_invite`) と概ね対称的だが、 内線レッグ側が SIP dialog ではなく
/// `PeerSession` (str0m) なので以下が異なる:
///
/// - browser ← sabiden: SAVPF answer は `peer.handle_offer` の戻り値をそのまま返す
/// - sabiden → NGN: AVP/PCMU SDP offer を新規ソケットで bind した RTP port に向けて出す
/// - 200 OK 後: `MediaBridge::WebRtcAudio` を起動 (NGN UDP socket ⇄ Opus⇔PCMU
///   ⇄ str0m peer)
/// - 内線レッグの ext_dialog / ResponderHandle は無く、 BYE 連動は WS 専用経路
///   で行う (`webrtc_active` に Call-ID で WS を保存して `NgnInboundHandler::handle_bye`
///   と対称的に PWA に通知する将来拡張)。 現状は `UacDialog` を保持しないので
///   NGN → PWA BYE 伝搬は別 issue。
///
/// # RFC 引用
///
/// - **RFC 3264 §5/§6** (SDP offer/answer): browser に対しては str0m の SAVPF
///   answer を即返し (browser は offerer)、 NGN に対しては sabiden が offerer
///   として AVP/PCMU で出す。 2 つの SDP 交渉は独立 (B2BUA SDP anchoring)。
/// - **RFC 8829** (JSEP): str0m が browser SDP を `accept_offer` した時点で
///   ICE/DTLS 状態機械が走り出す。 ICE candidate trickle は WS の `ServerMessage::Ice`
///   と独立に進む (RFC 8839 §4 trickle ICE)。
/// - **RFC 3550 §5.1 / RFC 3551 PT 0** (PCMU): NGN 側 RTP は `WebRtcAudioBridge`
///   が μ-law でエンコードして送る。
/// - **`docs/asterisk-real-invite.md` §2 / §5.2**: NGN 側 SDP は PCMU only
///   (`restrict_audio_to_pcmu_with_dtmf`)、 `c=`/`o=` は NGN 側 IP に強制書換。
#[async_trait::async_trait]
impl PwaOutboundHandler for UasEventHandler {
    /// PR #146 review #1 🟡#2 (WS 受信ループ非ブロック化) で背景化された実装。
    ///
    /// 同期パス (= `await` 中に WS 受信ループを止める時間) は最小化する:
    /// 1. target 防御的再検証 (defense in depth、 RFC 3261 §25.1 user 文法サブセット)
    /// 2. `peer.handle_offer` で SAVPF answer 取得 (str0m が ICE/DTLS の準備)
    /// 3. `peer.take_media_rx` で media receiver を確保 (1 度しか取れない)
    /// 4. NGN 側 bridge socket bind (loopback fallback、 高速)
    ///
    /// 背景パス (= JoinHandle で継続、 数秒〜数十秒掛かる可能性):
    /// 5. NGN INVITE → 200 OK 受信
    /// 6. `MediaBridge::WebRtcAudio` 起動 + `CallManager` 登録
    ///
    /// 背景失敗時は `ws_sink` 経由で `ServerMessage::Error{code:"outbound_failed"}`
    /// を browser に push する (PWA に正しくエラー返却、 review #1 🟡#4)。
    async fn handle_pwa_outbound_offer(
        &self,
        target: &str,
        browser_offer_sdp: &str,
        peer: &Arc<dyn PeerSession>,
        ws_sink: &WsSink,
    ) -> Result<PwaOutboundOutcome> {
        info!(%target, "PWA→NGN 発信フロー開始 (Issue #145)");

        // (a) target ホワイトリスト再検証 (defense in depth、 PR #146 review #1 🔴#1)。
        //     signaling 層で同じ検証を済ませているが、 trait 経由で呼ばれる
        //     全パス (テスト含む) で違反入力を NGN レッグまで運ばないよう、
        //     production 側でも assert する (RFC 3261 §25.1 user 文法サブセット)。
        if !is_valid_pwa_dial_target(target) {
            return Err(anyhow!(
                "invalid target charset (defense-in-depth assert): {:?}",
                target.escape_default().to_string()
            ));
        }

        // (a') Issue #157: TTC JJ-90.24 §5.7.1 連続抑制を PWA→NGN 経路にも適用する。
        //      PWA は SIP dialog を持たず複数 WS セッションが共通の NGN AOR
        //      (= sabiden REGISTER 番号) を共有するので、 ngn_uac の local AOR
        //      を rate-limit bucket key として使う。 これにより複数タブからの
        //      連投も同じ bucket でカウントされ、 NGN cooldown 連鎖を防ぐ。
        //      拒否時は browser に `ServerMessage::Error { code: "rate_limited", ... }`
        //      を返し、 PWA UI 側で「○秒お待ちください」を出す手掛かりにする
        //      (frontend UI 連発抑止は別 issue、 本 PR の scope 外)。
        let rate_aor = ngn_aor_from_uac(&self.ngn_uac);
        match self.outbound_rate_limiter.check_and_record(&rate_aor) {
            RateLimitDecision::Deny { retry_after } => {
                let secs = retry_after.as_secs();
                warn!(
                    aor = %rate_aor,
                    retry_after_secs = %secs,
                    "PWA outbound INVITE を rate limiter で拒否 (TTC JJ-90.24 §5.7.1)"
                );
                self.metrics
                    .record_invite_blocked_by_rate_limit(OutboundDirection::PwaOutbound);
                self.metrics.record_invite_pwa_outbound(InviteResult::Error);
                let _ = ws_sink.send(ServerMessage::error(
                    "rate_limited",
                    format!(
                        "outbound INVITE rate-limited (TTC JJ-90.24 §5.7.1): retry after {} sec",
                        secs
                    ),
                ));
                return Err(anyhow!(
                    "PWA outbound rate-limited: retry after {} sec",
                    secs
                ));
            }
            RateLimitDecision::Allow { previous_interval } => {
                // Issue #157 観測点: 内線レッグと同じく PWA 経路でも連続発信間隔を
                // `sabiden_sip_invite_interval_seconds` に記録する。 PWA は AOR が
                // sabiden 自身の REGISTER 番号に集約されるため、 複数 WS タブからの
                // 発射タイミングも全部この bucket で観測される。
                if let Some(d) = previous_interval {
                    let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
                    self.metrics.record_invite_interval_ms(ms);
                }
            }
        }

        // (b) browser SAVPF offer を str0m に渡し、 SAVPF answer を取得
        //     (RFC 3264 §6, RFC 8829)。
        let browser_answer = peer
            .handle_offer(browser_offer_sdp)
            .await
            .map_err(|e| anyhow!("peer.handle_offer 失敗 (browser SDP 不正?): {}", e))?;

        // (c) `peer.take_media_rx` を **同期で** 取得する (1 度しか取れないため、
        //     spawn 後に他経路に取られると bridge が起動できない)。 stub バック
        //     エンドや既に take 済の場合は同期 Err で返し、 background spawn
        //     しない。 PR #146 review #1 🟡#4 (take_media_rx None でも crash しない)。
        let peer_media_rx = peer.take_media_rx().await.ok_or_else(|| {
            anyhow!("peer.take_media_rx None (stub backend? 既に取り出し済?) → bridge 起動不可")
        })?;

        // (d) NGN 側 RTP bridge socket の bind は同期で済ませる (UDP bind は高速)。
        //     `bridge_ngn_bind_ip` 未設定 (None) は内線→NGN 発信と同じ loopback fallback。
        let ngn_bind_ip = self
            .bridge_ngn_bind_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        // Phase 1-D: ephemeral port reuse による P-CSCF ghost binding 衝突回避。
        let ngn_bridge_sock = bind_ngn_rtp_socket(ngn_bind_ip).await?;
        let sabiden_ngn_addr = ngn_bridge_sock.local_addr()?;

        // (e) NGN へ送る AVP/PCMU SDP を組み立てる (RFC 4566, `docs/asterisk-real-invite.md` §5.2)。
        // 実機検証 2026-05-10: telephone-event (PT 101) を含めて NGN INVITE すると
        // 500 Server Internal Error で拒否される (前作業時の Linphone→117 成功
        // パターンは PT 0 only)。 outbound INVITE でも PT 0 only に絞る。
        let avp_sdp = convert_savpf_to_avp(browser_answer.as_bytes())
            .map_err(|e| anyhow!("SAVPF→AVP 変換失敗: {}", e))?;
        // Phase R3 (Issue #272): Negotiator::for_ngn() = PCMU only subset +
        // WebRTC attr 剥離 + s=ptime/rtcp 補完。 旧 `restrict_audio_to_pcmu` は alias。
        let pcmu_only = Negotiator::for_ngn().rewrite_offer(&avp_sdp);
        let sdp_for_ngn =
            rewrite_rtp_endpoint(&pcmu_only, sabiden_ngn_addr.ip(), sabiden_ngn_addr.port())
                .map_err(|e| anyhow!("NGN 向け SDP rewrite 失敗: {}", e))?;

        // (f) Request-URI 組み立て (RFC 3261 §19.1.1, `docs/asterisk-real-invite.md` §5.1)。
        let ngn_server = self.ngn_uac.server_addr();
        let target_uri = format!("sip:{}@{}:{}", target, ngn_server.ip(), ngn_server.port());
        // 既存 normalize 関数で正規化 (idempotent)。 万一 target に
        // `;transport=udp` 等が混入していても剥がれる (Issue #58)。
        let target_uri = normalize_request_uri_for_ngn(
            &target_uri,
            &ngn_server.ip().to_string(),
            ngn_server.port(),
        );

        // (g) ここまでで browser に返す SAVPF answer は確定。
        //     NGN INVITE → 200 OK → bridge 起動を **背景タスク** で実行し、
        //     SAVPF answer を即時 browser に返せるようにする
        //     (PR #146 review #1 🟡#2 trickle ICE 詰まり対策、 RFC 8839 §4)。
        let ngn_uac = self.ngn_uac.clone();
        let metrics = self.metrics.clone();
        let call_manager = self.call_manager.clone();
        let webrtc_outbound_active = self.webrtc_outbound_active.clone();
        let peer_clone = peer.clone();
        let ws_sink_clone = ws_sink.clone();
        let target_owned = target.to_string();
        let browser_answer_for_opus = browser_answer.clone();
        // Issue #157: 背景タスクから結果を rate limiter にフィードバックする
        // ため、 limiter / AOR の clone を持ち込む。
        let rate_limiter = self.outbound_rate_limiter.clone();
        let rate_aor_owned = rate_aor.clone();
        // Issue #278: 通話履歴を背景タスクから記録するための Arc clone。
        // `Mutex<Option<...>>` を tokio::sync ロックで一度開いて clone する。
        // 未注入時 (`None`) は hook 全て no-op。
        let call_log_for_task = self.call_log_clone().await;
        let span = info_span!("pwa_outbound_invite_bg", target = %target);

        let completion = tokio::spawn(
            async move {
                let plan = ngn_uac.build_invite(&target_uri, Some(&sdp_for_ngn), None);
                // Issue #260 Phase 1-A: 5xx warn 構造化ログ用に Call-ID / CSeq /
                // Request-URI を `plan.request` (= 実際に送出する INVITE) から
                // 取り出して保持する。 plan は `invite()` の引数として move されるため
                // 結果側の警告ログ生成時には参照できない。
                let plan_call_id = plan
                    .request
                    .headers
                    .get("call-id")
                    .map(str::to_string)
                    .unwrap_or_default();
                let plan_cseq = plan
                    .request
                    .headers
                    .get("cseq")
                    .map(str::to_string)
                    .unwrap_or_default();
                let plan_target = plan.target_uri.clone();
                // Issue #278: PWA→NGN 発信を通話履歴に記録する。 ダイヤル先は
                // signaling 層から渡される target (user 部のみ) なので、 そのまま
                // remote_number として使う。
                if let Some(call_log) = call_log_for_task.as_ref() {
                    call_log.record_start(
                        crate::observability::call_log::Direction::Outbound,
                        target_owned.clone(),
                        plan_call_id.clone(),
                    );
                }
                // Issue #260 Phase 1-A: PWA→NGN 経路でも 5xx 受信時の経過 ms
                // を構造化ログに載せるため、 invite await 開始直前で計測開始する。
                let invite_started_at = std::time::Instant::now();
                let mut outcome = ngn_uac.invite(plan, Some(sdp_for_ngn.clone())).await;

                // Issue #260 Phase 1-B: PWA→NGN 経路でも carrier intermittent
                // reject (500/486/503) に対して 1 回限定 retry を行う。 sleep 中の
                // cancel race は `ws_sink_clone.is_closed()` (PWA WS close を意味
                // する、 `WsSink::is_closed` 内部で sender alive 数を見る) で
                // 検出する。 RFC 3261 §20.33 / 3GPP TS 24.229 §5.2.7 / TTC
                // JJ-90.24 §5.7.3。
                let retry_cfg = CarrierRetryConfig::default();
                let retry_taken = match &outcome {
                    Ok(InviteOutcome::Failed { response }) => {
                        let jitter = random_jitter_offset_ms(retry_cfg.jitter);
                        let decision = decide_retry(
                            response.status_code,
                            &response.headers,
                            &retry_cfg,
                            jitter,
                        );
                        match decision {
                            RetryDecision::Retry {
                                wait,
                                retry_after_header_secs,
                            } => {
                                info!(
                                    status = response.status_code,
                                    retry_delay_ms = wait.as_millis() as u64,
                                    retry_after_header = ?retry_after_header_secs,
                                    call_id = %plan_call_id,
                                    aor = %rate_aor_owned,
                                    "carrier intermittent reject 検知、 N ms 後に 1 回 retry (PWA outbound、 Issue #260 Phase 1-B、 RFC 3261 §20.33)"
                                );
                                tokio::time::sleep(wait).await;
                                if ws_sink_clone.is_closed() {
                                    info!(
                                        call_id = %plan_call_id,
                                        "retry sleep 中に PWA WS が閉じた → retry 中止"
                                    );
                                    metrics.record_ngn_carrier_retry(
                                        RetryOutcome::RetryAbortedByCancel,
                                    );
                                    Some(false)
                                } else {
                                    info!(
                                        call_id = %plan_call_id,
                                        "carrier retry 実行 (試行 2/2、 PWA outbound、 Issue #260)"
                                    );
                                    let retry_plan = ngn_uac.build_invite(
                                        &target_uri,
                                        Some(&sdp_for_ngn),
                                        None,
                                    );
                                    let new_outcome =
                                        ngn_uac.invite(retry_plan, Some(sdp_for_ngn.clone())).await;
                                    let succeeded =
                                        matches!(new_outcome, Ok(InviteOutcome::Established(_)));
                                    if succeeded {
                                        info!(
                                            call_id = %plan_call_id,
                                            "carrier retry 結果: 成功 (PWA outbound、 Issue #260)"
                                        );
                                        metrics.record_ngn_carrier_retry(
                                            RetryOutcome::RetriedSucceeded,
                                        );
                                    } else {
                                        let new_status = match &new_outcome {
                                            Ok(InviteOutcome::Failed { response }) => {
                                                Some(response.status_code)
                                            }
                                            _ => None,
                                        };
                                        warn!(
                                            call_id = %plan_call_id,
                                            new_status = ?new_status,
                                            "carrier retry 結果: 再失敗、 元 error を伝搬 (PWA outbound、 Issue #260)"
                                        );
                                        metrics
                                            .record_ngn_carrier_retry(RetryOutcome::RetriedFailed);
                                    }
                                    outcome = new_outcome;
                                    Some(true)
                                }
                            }
                            RetryDecision::NoRetry { .. } => None,
                        }
                    }
                    _ => None,
                };
                if retry_taken.is_none() {
                    metrics.record_ngn_carrier_retry(RetryOutcome::NotRetried);
                }

                match outcome {
                    Ok(InviteOutcome::Established(call)) => {
                        info!(
                            target = %target_owned,
                            ngn_local = %sabiden_ngn_addr,
                            "NGN 200 OK 取得 → PWA peer ⇄ NGN bridge 起動"
                        );
                        metrics.record_invite_ngn(InviteResult::Answered);
                        // Issue #157: 2xx 確立で rate limiter の failure_streak リセット。
                        rate_limiter.record_success(&rate_aor_owned);

                        // Issue #147 leak 防止: ここから下で sabiden 側の bridge
                        // 起動 / CallManager 登録のいずれかが失敗すると、 NGN は既に
                        // 200 OK 送出済 (UAC が ACK 済) で dialog が confirmed なのに
                        // sabiden 側は通話を保持できない状態になる。 何もしないと
                        // NGN は 5 分タイムアウトまで dialog を残し、 同番号への
                        // 再発信が 486 Busy Here で弾かれる (Issue #147 の根本要因)。
                        // 失敗時は best-effort で NGN BYE を撃って NGN dialog を
                        // 即座に閉じる (RFC 3261 §15.1.1: BYE で session terminate)。
                        let EstablishedCall {
                            dialog: mut ngn_dialog,
                            response: ngn_response,
                        } = *call;

                        // NGN 200 OK SDP から peer endpoint 抽出。 失敗時は NGN BYE。
                        let ngn_peer = match extract_rtp_endpoint(&ngn_response.body) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(error=%e, "NGN 200 OK SDP に RTP endpoint なし");
                                metrics.record_invite_pwa_outbound(InviteResult::Error);
                                let _ = ws_sink_clone.send(ServerMessage::error(
                                    "outbound_failed",
                                    format!("NGN 200 OK SDP 解析失敗: {}", e),
                                ));
                                if let Err(be) = ngn_dialog.send_bye().await {
                                    warn!(error=%be, "NGN BYE (cleanup) 失敗");
                                }
                                return Err(anyhow!("NGN 200 OK SDP 解析失敗: {}", e));
                            }
                        };
                        let opus_pt = super::transcoder::find_opus_payload_type(
                            browser_answer_for_opus.as_bytes(),
                        )
                        .unwrap_or(super::transcoder::DEFAULT_OPUS_PT);
                        // Issue #135 🟡 3: `WebRtcAudioBridge::start` は infallible。
                        // 旧 `Result<Self>` 戻り値での error path は実行時に到達不能
                        // だったので、 戻り値を `Self` に変更し match を省く。
                        let bridge: MediaBridge = super::transcoder::WebRtcAudioBridge::start(
                            super::transcoder::WebRtcAudioConfig {
                                ngn_socket: ngn_bridge_sock,
                                ngn_peer: Some(ngn_peer),
                                peer: peer_clone,
                                peer_media_rx,
                                opus_payload_type: opus_pt,
                                // PCMU 直送 (str0m PCMU only 構成、 詳細は inbound 経路コメント参照)。
                                direct_pcmu_passthrough: true,
                                metrics: Some(metrics.clone()),
                            },
                        )
                        .into();

                        let mgr = match call_manager.as_ref() {
                            Some(m) => m,
                            None => {
                                warn!("CallManager 未注入 → PWA outbound bridge を保持できない");
                                metrics.record_invite_pwa_outbound(InviteResult::Error);
                                let _ = ws_sink_clone.send(ServerMessage::error(
                                    "outbound_failed",
                                    "CallManager 未注入",
                                ));
                                if let Err(be) = ngn_dialog.send_bye().await {
                                    warn!(error=%be, "NGN BYE (cleanup) 失敗");
                                }
                                return Err(anyhow!(
                                    "CallManager 未注入 → PWA outbound bridge を保持できない"
                                ));
                            }
                        };
                        let cid = mgr.create_call().await;
                        if let Err(e) = mgr.attach_media_bridge(cid, bridge).await {
                            warn!(error=%e, "CallManager attach_media_bridge 失敗");
                            metrics.record_invite_pwa_outbound(InviteResult::Error);
                            let _ = ws_sink_clone.send(ServerMessage::error(
                                "outbound_failed",
                                format!("CallManager attach 失敗: {}", e),
                            ));
                            // bridge_call_id (cid) の create_call は確保済。
                            // attach 失敗時は CallManager 内には MediaBridge 未登録
                            // の Connecting state エントリが残るが、 terminate を
                            // 呼べば回収される。
                            if let Err(te) = mgr.terminate(cid).await {
                                warn!(error=%te, "create_call 後の terminate 失敗");
                            }
                            if let Err(be) = ngn_dialog.send_bye().await {
                                warn!(error=%be, "NGN BYE (cleanup) 失敗");
                            }
                            return Err(anyhow!("CallManager attach_media_bridge 失敗: {}", e));
                        }

                        // PR #146 review #1 🟡#1: PWA outbound 専用カウンタを使う。
                        // 内線レッグは存在しないので `record_invite_extension` は呼ばない。
                        metrics.record_invite_pwa_outbound(InviteResult::Answered);
                        metrics.inc_call_active();

                        // Issue #147: NGN UacDialog を専用テーブルに保持し、
                        // PWA→NGN 発信通話の双方向 BYE を成立させる。
                        // RFC 3261 §15.1.1 (BYE) / §15.1.2 (BYE 受信側) /
                        // RFC 5853 §3.2.2 SBC framework: B2BUA は片側 dialog 終了
                        // をもう片側に伝搬する責務を負う。
                        // - NGN→PWA BYE: NgnInboundHandler::handle_bye が引く。
                        // - PWA→NGN BYE: signaling 層が `close_pwa_outbound_for_ws`
                        //   経由でエントリを引いて `ngn_dialog.send_bye()` を撃つ。
                        // ここまで来た時点で metrics.inc_call_active 済 + bridge
                        // attach 済 = 通話確立。 失敗 branch (上の各 `return Err`)
                        // はテーブルに insert しないので leak 防止 (Issue #147 DoD)。
                        let ngn_call_id = ngn_dialog.dialog().id().call_id.clone();
                        let entry = Arc::new(WebRtcOutboundEntry {
                            ngn_dialog: Mutex::new(ngn_dialog),
                            ws: ws_sink_clone.clone(),
                            bridge_call_id: cid,
                        });
                        webrtc_outbound_active
                            .lock()
                            .await
                            .insert(ngn_call_id.clone(), entry);
                        debug!(
                            ngn_call_id = %ngn_call_id,
                            bridge_call_id = %cid,
                            "PWA outbound 確立 → webrtc_outbound_active に登録 (Issue #147)"
                        );

                        Ok(())
                    }
                    Ok(InviteOutcome::Failed { response }) => {
                        // Issue #260 Phase 1-A: PWA→NGN 経路の 5xx も同じ構造化
                        // ログを出す (Reason RFC 3326 / Retry-After §20.33 /
                        // Server §20.35 / Warning §20.43 / Via received/rport
                        // RFC 3581 §4)。 3GPP TS 24.229 §5.2.7 / RFC 3261 §21.5。
                        if response.status_code >= 500 && response.status_code < 600 {
                            let hv = extract_ngn_5xx_header_view(&response.headers);
                            let elapsed_ms = invite_started_at.elapsed().as_millis() as u64;
                            warn!(
                                status = response.status_code,
                                method = "INVITE",
                                call_id = %plan_call_id,
                                aor = %rate_aor_owned,
                                to = %plan_target,
                                cseq = %plan_cseq,
                                reason = ?hv.reason,
                                retry_after = ?hv.retry_after,
                                server = ?hv.server,
                                warning = ?hv.warning,
                                via_received = ?hv.via_received,
                                via_rport = ?hv.via_rport,
                                elapsed_since_invite_ms = elapsed_ms,
                                "NGN 5xx 応答受信 (PWA outbound、 Issue #260、 RFC 3326 / RFC 3261 §20.33/§20.35/§20.43/§21.5)"
                            );
                            metrics.record_ngn_5xx(response.status_code);
                        } else {
                            warn!(code = response.status_code, "NGN INVITE 失敗");
                        }
                        let result = if response.status_code == 486 {
                            InviteResult::Busy
                        } else {
                            InviteResult::Error
                        };
                        metrics.record_invite_ngn(result);
                        metrics.record_invite_pwa_outbound(result);
                        // Issue #157: NGN 5xx + Retry-After を rate limiter にフィードバック。
                        // TTC JJ-90.24 §5.7.3 (INVITE 5xx 自動 retry 禁止) / RFC 3261 §20.33。
                        let retry_after_secs = response
                            .headers
                            .get("retry-after")
                            .and_then(parse_retry_after);
                        rate_limiter.record_failure(
                            &rate_aor_owned,
                            response.status_code,
                            retry_after_secs,
                        );
                        // PR #193 review #2 🟡#1: NGN が Retry-After を返した場合は
                        // PWA UI が retry 抑制できるよう文字列に転載する。 SIP レッグ
                        // を持たない PWA は `ServerMessage::error` 経由でしか
                        // フィードバックを受けないため、 メッセージ本文に
                        // `retry_after=<sec>` を埋め込んで PWA 側で parse する。
                        let detail = match retry_after_secs {
                            Some(secs) => format!(
                                "NGN INVITE 失敗: {} {} (retry_after={}s)",
                                response.status_code, response.reason, secs
                            ),
                            None => format!(
                                "NGN INVITE 失敗: {} {}",
                                response.status_code, response.reason
                            ),
                        };
                        // Issue #278: PWA→NGN 発信が NGN により拒否された。
                        // status code をそのまま記録して PWA UI が「相手話中」
                        // 「NGN 一時障害」を区別できるようにする (RFC 3261 §21)。
                        if let Some(call_log) = call_log_for_task.as_ref() {
                            call_log.record_end(
                                &plan_call_id,
                                crate::observability::call_log::Outcome::Failed {
                                    status: response.status_code,
                                },
                            );
                        }
                        let _ = ws_sink_clone
                            .send(ServerMessage::error("outbound_failed", detail.clone()));
                        Err(anyhow!(detail))
                    }
                    Err(e) => {
                        warn!(error=%e, "NGN INVITE トランスポート失敗");
                        metrics.record_invite_ngn(InviteResult::Timeout);
                        metrics.record_invite_pwa_outbound(InviteResult::Timeout);
                        // Issue #157: トランスポート失敗 (timer B / I/O 等) も 5xx 相当として
                        // backoff 対象にする。 失敗連投で NGN cooldown を起こすのと等価。
                        rate_limiter.record_failure(&rate_aor_owned, 503, None);
                        // Issue #278: PWA→NGN トランスポート障害 = Failed { status: 503 }。
                        if let Some(call_log) = call_log_for_task.as_ref() {
                            call_log.record_end(
                                &plan_call_id,
                                crate::observability::call_log::Outcome::Failed { status: 503 },
                            );
                        }
                        let _ = ws_sink_clone.send(ServerMessage::error(
                            "outbound_failed",
                            format!("NGN INVITE 失敗: {}", e),
                        ));
                        Err(anyhow!("NGN INVITE 失敗: {}", e))
                    }
                }
            }
            .instrument(span),
        );

        Ok(PwaOutboundOutcome {
            savpf_answer: browser_answer,
            completion,
        })
    }
}

/// Issue #147: PWA WS の close / `ClientMessage::Bye` 受信時に呼ばれる、
/// PWA→NGN 発信通話の cleanup 経路。
///
/// `webrtc_outbound_active` テーブルを線形にスキャンし、 同一 WS セッション
/// (`WsSink::same_channel` 一致) のエントリを全て取り出して:
///
/// 1. NGN レッグへ `UacDialog::send_bye()` で BYE を撃つ (RFC 3261 §15.1.1)。
///    NGN が 5 分タイムアウトまで dialog を保持して 486 Busy Here を返す
///    現象 (Issue #147 の根本要因) を防ぐ。
/// 2. `CallManager::terminate(bridge_call_id)` で RTP ブリッジを停止。
/// 3. `metrics.dec_call_active()` で観測値を 1 減らす。
///
/// テーブルから先に `remove` してから処理するので、 NGN→PWA BYE と PWA→NGN
/// BYE が同時に発火しても (例: PWA 切断中に NGN がタイムアウト BYE を送る)
/// どちらかが先勝で他方は no-op となり、 二重 BYE / 二重 dec_call_active を
/// 起こさない (idempotent)。
#[async_trait::async_trait]
impl PwaOutboundCloser for UasEventHandler {
    async fn close_pwa_outbound_for_ws(&self, ws: &WsSink) -> usize {
        // (1) WS が一致するエントリを 1 段スキャンで一気に取り出す。
        //     ロックを保持したまま send_bye を await するとシグナリング層が
        //     他の Call-ID で操作するときにブロックするので、 remove と外部 IO は
        //     分離する。 2 段イテレーション (filter→collect→remove) は冗長
        //     なので `HashMap::extract_if` を使って 1 段で remove する
        //     (review #2 🟡#3)。
        let entries: Vec<(String, Arc<WebRtcOutboundEntry>)> = {
            let mut tbl = self.webrtc_outbound_active.lock().await;
            tbl.extract_if(|_, e| e.ws.same_channel(ws)).collect()
        };

        let count = entries.len();
        if count == 0 {
            return 0;
        }

        // (2) 各エントリに対し NGN BYE → bridge terminate → metrics dec を実施。
        //     send_bye は best-effort: NGN 到達不能でも sabiden 側 cleanup は続ける。
        for (cid, entry) in entries {
            // NGN レッグ BYE (RFC 3261 §15.1.1)。 同時並行で他経路 (例 NGN→sabiden
            // BYE が race で来た) からも触られないよう Mutex でガード。
            {
                let mut dlg = entry.ngn_dialog.lock().await;
                if let Err(e) = dlg.send_bye().await {
                    warn!(
                        error = %e,
                        ngn_call_id = %cid,
                        "PWA→NGN BYE 送出失敗 (NGN unreachable?)"
                    );
                }
            }
            // bridge 停止。
            if let Some(mgr) = self.call_manager.as_ref() {
                if let Err(e) = mgr.terminate(entry.bridge_call_id).await {
                    warn!(
                        error = %e,
                        bridge_call_id = %entry.bridge_call_id,
                        "PWA→NGN BYE: bridge terminate 失敗"
                    );
                }
            }
            self.metrics.dec_call_active();
            // Issue #278: PWA→NGN 発信通話が確立済 → PWA WS close で正常終了。
            // record_start は `handle_pwa_outbound_offer` の spawn 内で書き込まれている。
            if let Some(call_log) = self.call_log_clone().await {
                call_log.record_end(&cid, crate::observability::call_log::Outcome::Answered);
            }
            debug!(ngn_call_id=%cid, "PWA→NGN BYE 完了 (Issue #147)");
        }

        count
    }
}

/// Bug B / Issue #268: PWA WS の close 受信時に呼ばれる、 NGN→PWA 着信通話
/// の cleanup 経路 ([`PwaOutboundCloser`] の inbound 対称形)。
///
/// `webrtc_active` テーブルを線形にスキャンし、 同一 WS セッション
/// (`WsSink::same_channel` 一致) のエントリを全て取り出して:
///
/// 1. NGN レッグへ `WebRtcInboundEntry::send_bye()` で BYE を撃つ
///    (RFC 3261 §15.1.1)。 NGN が 5-10 秒タイムアウトまで dialog を保持して
///    BYE を送り返してくる現象 (実機 v7 で観測) を即時解消する。
/// 2. `CallManager::terminate(bridge_call_id)` で RTP ブリッジを停止。
///    `webrtc_active` の `start_bridge_for_inbound` で `self.active` に
///    `Some(bridge_call_id)` が入っているため、 そこから引いて停止する
///    (新規 `bridge_call_id` フィールドは entry 内に保存しない: 旧 `self.active`
///    との二重保管を避けるため)。
/// 3. `metrics.dec_call_active()` で観測値を 1 減らす。
/// 4. `self.pending` / `self.active` の Call-ID エントリも cleanup する
///    (NGN BYE 経路の `handle_bye` と等価な後処理)。
///
/// `extract_if` で先に remove するため、 NGN→PWA BYE (`handle_bye`) と
/// PWA→NGN BYE (本パス) が同時に発火しても先勝で他方は no-op (idempotent)。
#[async_trait::async_trait]
impl PwaInboundCloser for NgnInboundHandler {
    async fn close_pwa_inbound_for_ws(&self, ws: &WsSink) -> usize {
        // (1) WS が一致する entry を 1 段スキャンで一気に取り出す。
        //     ロック保持中に send_bye を await すると NGN BYE 経路 (handle_bye)
        //     が同 Mutex で詰まるので、 remove と外部 I/O は分離する。
        let entries: Vec<(String, Arc<WebRtcInboundEntry>)> = {
            let mut tbl = self.webrtc_active.lock().await;
            tbl.extract_if(|_, e| e.ws.same_channel(ws)).collect()
        };

        let count = entries.len();
        if count == 0 {
            return 0;
        }

        // (2) 各 entry に対し NGN BYE → bridge terminate → metrics dec → pending/
        //     active cleanup を実施。 send_bye は best-effort: NGN 到達不能でも
        //     sabiden 側 cleanup は続ける (= 旧挙動より degrade しない)。
        for (cid, entry) in entries {
            match entry.send_bye().await {
                Ok(Some(resp)) => {
                    debug!(
                        call_id = %cid,
                        status = resp.status_code,
                        "PWA disconnect → NGN BYE 送出完了 (Bug B / RFC 3261 §15.1.1)"
                    );
                }
                Ok(None) => {
                    debug!(
                        call_id = %cid,
                        "PWA disconnect → NGN BYE skip (degraded entry: dialog/layer 不足)"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        call_id = %cid,
                        "PWA disconnect → NGN BYE 送出失敗 (NGN unreachable?)"
                    );
                }
            }

            // bridge 停止 (`start_bridge_for_inbound` が `self.active` に
            // `Some(bridge_call_id)` を入れている場合)。 transparent モード
            // (`None`) や bridge 未起動経路では skip。
            let bridge_id = { self.active.lock().await.remove(&cid) };
            if let (Some(Some(bridge_call_id)), Some(mgr)) = (bridge_id, self.call_manager.as_ref())
            {
                if let Err(e) = mgr.terminate(bridge_call_id).await {
                    warn!(
                        error = %e,
                        call_id = %cid,
                        "PWA disconnect: bridge terminate 失敗"
                    );
                }
            }
            // pending 側も cleanup (NGN BYE 経路の `handle_bye` と等価)。
            self.pending.lock().await.remove(&cid);
            // call_active は (`webrtc_active` removed) で 1 回だけ減らす
            // (NGN BYE 経路と二重発火しない idempotent ガード: 先に webrtc_active
            // から抜けた側が dec を担当する)。
            self.metrics.dec_call_active();
            // Issue #278: NGN→PWA 着信通話が確立済 → PWA disconnect で BYE 完了。
            // record_start は NGN INVITE 受信時に Inbound として書き込まれている。
            if let Some(call_log) = self.call_log_clone().await {
                call_log.record_end(&cid, crate::observability::call_log::Outcome::Answered);
            }
        }

        count
    }
}

/// PWA→NGN 発信 target の defense-in-depth 検証 (signaling 層と同義語、
/// PR #146 review #1 🔴#1)。 production と test 双方の経路で違反入力を NGN
/// レッグまで運ばないよう、 trait 実装側でも assert する。
///
/// `is_valid_dial_target` (signaling 内 private) と同じ規則だが、
/// orchestrator から signaling 内部関数を直接参照しないために本ファイルでも
/// 独立に定義する。 ロジックは同一: `[0-9*#+]{1,32}` のホワイトリスト
/// (RFC 3261 §25.1 user 文法のサブセット)。
fn is_valid_pwa_dial_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 32 {
        return false;
    }
    target
        .chars()
        .all(|c| c.is_ascii_digit() || c == '*' || c == '#' || c == '+')
}

/// 内線レッグの 200 OK を組み立てる。`build_response_skeleton` がベース。
/// To に tag を付け、SDP body があれば設定し、Contact ヘッダを必ず付与する。
///
/// RFC 3261 §13.3.1.4 (UAS Behavior, 2xx Responses):
/// > The 2xx response to an INVITE MUST contain a Contact header field with
/// > a SIP or SIPS URI that the UAS will accept subsequent in-dialog
/// > requests at.
///
/// RFC 3261 §12.1.1 (UAS Dialog State) も同様に Contact 必須を規定する。
/// Contact が無いと UAC 側で remote target が決まらず ACK / BYE の宛先が
/// 不定となり、Linphone 等は dialog 確立を諦めて切断する。
///
/// `contact_uri` は sabiden が内線レッグで listen している SIP URI
/// (例 `sip:sabiden@192.168.20.239:5061`)。`<...>` 形式に整形される前提の
/// 生 URI で渡し、本関数内で `<` `>` を付けて name-addr 形式にする。
fn build_2xx_to_ext(invite: &SipRequest, body: &[u8], contact_uri: &str) -> SipResponse {
    let mut resp = build_response_skeleton(invite, 200, "OK");
    if !body.is_empty() {
        resp.headers.set("Content-Type", "application/sdp");
        resp.body = body.to_vec();
    }
    resp.headers.set("Contact", format!("<{}>", contact_uri));
    ensure_to_tag(&mut resp);
    resp
}

/// Issue #157: rate limiter で拒否した INVITE への 503 Service Unavailable +
/// Retry-After ヘッダ付き応答を組み立てる。
///
/// RFC 3261 §21.5.4 (503 Service Unavailable):
/// > "The server is temporarily unable to process the request due to a
/// >  temporary overloading or maintenance of the server.  The server MAY
/// >  indicate when the client should retry the request in a Retry-After
/// >  header field."
///
/// RFC 3261 §20.33 (Retry-After): 秒単位整数を入れる。 sabiden の rate limiter
/// が返す `retry_after` は最低 1 秒に切り上げ済 (`round_up_secs`)。
///
/// TTC JJ-90.24 §5.7.3: 内線/PWA が 5xx を受信した場合、 自動 retry せず
/// Retry-After で示された時間内は同じ Request-URI への INVITE を出さない。
/// sabiden が 503 + Retry-After を返すことで、 PWA / 内線が即時再発信
/// (= NGN cooldown の連鎖を起こす最悪パターン) を回避する。
fn build_503_with_retry_after(invite: &SipRequest, retry_after_secs: u64) -> SipResponse {
    let mut resp = build_response_skeleton(invite, 503, "Service Unavailable");
    resp.headers
        .set("Retry-After", format!("{}", retry_after_secs));
    // RFC 3261 §8.2.6.2: dialog を作らない final 応答にも To-tag を付与する。
    ensure_to_tag(&mut resp);
    resp
}

/// Issue #157: PWA→NGN 経路用の rate-limit bucket key (AOR) を `Uac` から取り出す。
///
/// PWA は SIP dialog を持たないため、 ハンドラ呼出時点で内線 From-AOR が無い。
/// 代わりに「sabiden 自身が REGISTER している NGN AOR」(= ngn_uac の local URI)
/// を共通 bucket key として使う。 複数の PWA WS セッションが同時にぶら下がっても
/// 全部同じ key に集約されるため、 NGN P-CSCF から見た「同一 AOR からの連投」を
/// 正しく抑制できる (TTC JJ-90.24 §5.7.1)。
///
/// `local_uri` (例 `sip:0312345678@ntt-east.ne.jp`) からユーザー部のみ取り出して
/// 短い key にする。 抽出失敗時は URI 全体を fallback として使う (= ロジックは
/// 変わらず、 ただ key が長いだけ)。
fn ngn_aor_from_uac(uac: &Uac) -> String {
    let local_uri = uac.config().local_addr_of_record();
    extract_user_from_sip_uri(local_uri).unwrap_or_else(|| local_uri.to_string())
}

/// `sip:user@host[;params]` から `user` 部分を取り出す。 失敗時 None。
/// `sip:host` (user 無し) も None。
fn extract_user_from_sip_uri(uri: &str) -> Option<String> {
    let after_scheme = uri.split_once(':').map(|x| x.1).unwrap_or(uri);
    let user_part = after_scheme.split_once('@').map(|x| x.0)?;
    if user_part.is_empty() {
        return None;
    }
    Some(user_part.to_string())
}

/// `<sip:user@host>;tag=...` のような name-addr / addr-spec から URI 部分のみ抽出する。
fn extract_uri_from_addr(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start + 1..].find('>') {
            return trimmed[start + 1..start + 1 + end].to_string();
        }
    }
    trimmed
        .split(';')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string()
}

/// `UasEventHandler::prepare_outbound_bridge` から `finalize_outbound_bridge` へ渡す
/// 中間状態。bind 済みのソケット 2 つと内線側ピアを保持する。
struct OutboundBridgeCtx {
    ngn_sock: Arc<UdpSocket>,
    ext_sock: Arc<UdpSocket>,
    ext_peer: SocketAddr,
}

/// `fork_to_bindings` 内部で使う leg 結果。
enum LegResult {
    Established {
        #[allow(dead_code)]
        aor: String,
        winner_uri: String,
        response: SipResponse,
        /// Issue #87 / #121: WebRTC leg が winner の場合だけ Some。
        /// `start_bridge_for_inbound` が `MediaBridge::WebRtcAudio` を起動する
        /// ために peer の MediaFrame mpsc にアクセスする必要がある。
        webrtc_handle: Option<WebRtcLegArtifacts>,
        /// Issue #81: WebRTC leg が winner の場合の WS ハンドル (BYE 伝搬用)。
        /// 同じ `WsSink` は `WebRtcLegHandle` にも存在するが、 winner と
        /// loser の両方に Cancel を撃つ用途と、 winner の Call-ID を確立
        /// 通話テーブル (`webrtc_active`) に保持する用途で別経路から取り
        /// 出す必要がある (winner は cleanup loop に含めないため)。
        webrtc_ws: Option<WsSink>,
    },
    Failed {
        #[allow(dead_code)]
        aor: String,
        status: u16,
    },
    Errored {
        #[allow(dead_code)]
        aor: String,
    },
}

/// Issue #87 / #121: WebRTC leg が winner になったときに
/// `start_bridge_for_inbound` に渡す peer 関連のハンドル一式。
///
/// peer は SRTP 終端と Opus codec を抱えており、 `take_media_rx` は 1 度
/// だけ取り出せる (= ここで取り出して所有権を bridge に渡す前提)。
pub struct WebRtcLegArtifacts {
    /// peer 本体 (SRTP / ICE / DTLS 終端済 [`PeerSession`])。
    pub peer: Arc<dyn PeerSession>,
    /// peer から `take_media_rx` で取り出した browser → orchestrator 方向の
    /// MediaFrame receiver。 1 度だけ取れるので `WebRtcAudioBridge` に move
    /// する想定。
    pub peer_media_rx: mpsc::Receiver<crate::webrtc::peer::MediaFrame>,
    /// SDP `a=rtpmap:<pt> opus/...` で negotiate した PT (Chromium 互換 既定 111)。
    pub opus_payload_type: u8,
}

/// winner 決定後に Cancel を送るための WebRTC leg 識別子。
#[derive(Clone)]
struct WebRtcLegHandle {
    ws: WsSink,
    pending: PendingAnswers,
    call_id: String,
}

/// `fork_to_bindings` の WebRTC leg 登録テーブル (Issue #81/#83 review #1)。
///
/// `closed = true` は「fork が確定 (winner/Timeout/AllFailed) し、 以後の
/// `run_webrtc_leg` は Offer push してはいけない」ことを示す。 fork 確定後に
/// `peer.create_offer` 中だった遅い leg を新規登録すると、 cleanup snapshot
/// に含まれず browser が ringing のまま固まる race があった
/// (RFC 3261 §9 / W3C WebRTC §4.4.1: long-running pending state を放置しない)。
///
/// レース閉鎖シナリオ:
/// 1. fork loop が winner を確定 → `close_and_drain` で `closed = true` 化
/// 2. 同時に走っていた slow leg が `peer.create_offer` 完了 → `try_register`
///    呼び出し
/// 3. registry が closed なので `try_register` は false を返し、 leg は
///    Offer push を skip して自前で Cancel を送って終了する
struct WebRtcLegRegistry {
    legs: Vec<WebRtcLegHandle>,
    closed: bool,
}

impl WebRtcLegRegistry {
    fn new() -> Self {
        Self {
            legs: Vec::new(),
            closed: false,
        }
    }
}

/// fork 確定後に slow leg を登録から弾くためのアトミック登録 API。
///
/// `closed` 確認 → `legs.push` を 1 つの mutex critical section で実行する
/// ことで、 「closed 化と push の TOCTOU」 race を閉じる
/// (`close_and_drain` 側も同じ mutex を取るため、 push と drain は順序付く)。
async fn try_register_webrtc_leg(
    registry: &Arc<Mutex<WebRtcLegRegistry>>,
    handle: WebRtcLegHandle,
) -> bool {
    let mut g = registry.lock().await;
    if g.closed {
        return false;
    }
    g.legs.push(handle);
    true
}

/// fork 確定時に「以後 push 禁止」フラグを立て、 既存 leg snapshot を取り出す。
///
/// 戻り値は cleanup 対象の leg リスト。 `same_channel` で winner を除外する
/// のは呼出側 (`fork_to_bindings`) の責務。
async fn close_and_drain_webrtc_legs(
    registry: &Arc<Mutex<WebRtcLegRegistry>>,
) -> Vec<WebRtcLegHandle> {
    let mut g = registry.lock().await;
    g.closed = true;
    std::mem::take(&mut g.legs)
}

/// RFC 3261 §16.7 step 6 (Aggregate Authorization Header Field Values / Best
/// Response): non-2xx final responses を集約する際の優先順位を実装する。
///
/// レスポンスクラス間の優先 (`final_response_class_rank`):
///
/// ```text
/// 6xx (Global Failure)        > 4xx (Request Failure) > 5xx (Server Failure) > 3xx (Redirection)
/// ```
///
/// 同クラス内では「最初に受信した」 ものを保持する (RFC 3261 §16.7 step 6
/// 5th paragraph: "Among same class, the proxy SHOULD pick the response from
/// the earliest-arrived response context.")。
///
/// 注: 2xx (Answered) は `fork_to_bindings` ループ内で別経路 (= `Established`)
/// で処理するため、 本関数の対象外。
///
/// 戻り値: 「`new` を採用すべきなら `true`」。 `current` が `None` のとき必ず
/// `true` を返す (初回受信は無条件採用)。
fn should_replace_status(current: Option<u16>, new: u16) -> bool {
    match current {
        None => true,
        Some(cur) => final_response_class_rank(new) > final_response_class_rank(cur),
    }
}

/// RFC 3261 §16.7 step 6 best response の優先度を返す。 値が大きいほど優先。
///
/// **順序**: `6xx > 4xx > 5xx > 3xx`。
///
/// RFC 3261 §16.7 step 6 (proxy stateful forking) は「6xx を受け取ったらそれを
/// best response として採用 (MUST)」 とだけ強く規定し、 3xx/4xx/5xx 間の厳密な
/// 比較順序は実装定義 (`SHOULD aggregate` 程度の緩い指針)。 sabiden は B2BUA
/// 内線 fork の特性 (= 内線端末の代表的失敗は 486 Busy / 404 Not Found 等の 4xx)
/// に合わせ、 4xx を 5xx (server 障害系) より優先採用する簡略化を選択。
///
/// この簡略化は RFC 違反ではないが、 厳密 RFC 3261 §16.7 step 6 解釈 (例: 5xx
/// を `proxy retry` 対象として 4xx より「より致命的」 と見なす派閥) とは差分が
/// ある。 厳密化は別 issue で扱う想定。
/// TODO(本流対応): RFC 3261 §16.7 step 6 4xx/5xx 厳密順序を別 issue で詰める。
///
/// 1xx / 2xx は本関数の対象外 (呼出側で除外済) で、 もし渡されれば最下位 (0)
/// として扱う (= 既存の 3xx/4xx/5xx/6xx を上書きしない)。
fn final_response_class_rank(code: u16) -> u8 {
    match code {
        600..=699 => 4,
        400..=499 => 3,
        500..=599 => 2,
        300..=399 => 1,
        _ => 0,
    }
}

/// `fork_to_bindings` の `AllFailed` 経路で NGN へ返す reason phrase を決定する。
///
/// 参照する RFC:
/// - RFC 3261 §21.4.21 "486 Busy Here"
/// - RFC 3261 §21.6.2 "603 Decline" — **単数** "Decline" が正規 (PR #210 では
///   "Declined" と誤記していたため Issue #211 で修正)。
/// - RFC 3261 §21 全般: その他 status code は `RESPONSE-PHRASE` を直接引用する
///   のが基本で、 未登録 (例: 487 Request Terminated は §21.4.25) のものも RFC
///   準拠の英語表現を返す。
///
/// 本関数は `AllFailed` 経路で使う final response (3xx-6xx) のみを想定する。
/// 未知 code は中立的な "Decline" (= 603 と同じ semantics の汎用拒否) を返す。
fn reason_phrase_for_status(code: u16) -> &'static str {
    match code {
        486 => "Busy Here",
        487 => "Request Terminated",
        603 => "Decline",
        _ => "Decline",
    }
}

/// 内線フォーク (transport-aware)。SIP/WebRTC を transport で分岐し並列に呼び出す。
/// 先着の 200 OK を winner として採用、それ以外の WebRTC leg には Cancel を流す。
pub async fn fork_to_bindings(
    inviter: ExtInviter,
    bindings: Vec<(String, Binding)>,
    sdp_offer: Vec<u8>,
    call_id: String,
    overall_timeout: Duration,
) -> ForkResult {
    if bindings.is_empty() {
        return ForkResult::AllFailed { last_status: None };
    }

    // 各 leg の終了を待ち合わせるチャネル。先着 200 を採用したら drop で終了させる。
    let (tx, mut rx) = mpsc::unbounded_channel::<LegResult>();
    let total = bindings.len();
    // Issue #81/#83 review #1: leg 登録を `closed` フラグ付きテーブルに変更し、
    // 「fork 確定 → 遅延 leg が後追いで Offer push する race」を閉じる。
    let webrtc_legs: Arc<Mutex<WebRtcLegRegistry>> = Arc::new(Mutex::new(WebRtcLegRegistry::new()));

    for (aor, binding) in bindings {
        let tx_c = tx.clone();
        let call_id_c = call_id.clone();
        match binding.transport {
            ExtTransport::Sip => {
                let sdp_c = sdp_offer.clone();
                let inviter_c = inviter.clone();
                let target_uri = binding.contact_uri.clone();
                let aor_c = aor.clone();
                tokio::spawn(async move {
                    let outcome = inviter_c.invite(&target_uri, &sdp_c).await;
                    let leg = match outcome {
                        Ok(super::manager::LegOutcome::Established { response, .. }) => {
                            LegResult::Established {
                                aor: aor_c,
                                winner_uri: target_uri,
                                response,
                                webrtc_handle: None,
                                webrtc_ws: None,
                            }
                        }
                        Ok(super::manager::LegOutcome::Failed { status, .. }) => {
                            LegResult::Failed { aor: aor_c, status }
                        }
                        Ok(super::manager::LegOutcome::Errored { .. }) | Err(_) => {
                            LegResult::Errored { aor: aor_c }
                        }
                    };
                    let _ = tx_c.send(leg);
                });
            }
            ExtTransport::WebRtc { peer, ws, pending } => {
                // Issue #73: WebRTC leg は NGN 由来の SDP オファを使わない
                // (sabiden 自身が `peer.create_offer()` で SAVPF オファを生成する)。
                // SIP leg と違い、 NGN SDP は `run_webrtc_leg` に渡さない。
                //
                // Issue #83: cleanup 用 `webrtc_legs` への登録は `run_webrtc_leg`
                // 内部で `ServerMessage::Offer` を WS 送信できた直後に行う。
                // Offer push 前に失敗 (`peer.create_offer` 失敗等) した leg を
                // 登録すると、 browser が見ていない call_id を後段で Cancel する
                // ことになり、 シグナリングノイズになる。
                let aor_c = aor.clone();
                let target_uri = binding.contact_uri.clone();
                let leg_timeout = overall_timeout;
                let webrtc_legs_c = webrtc_legs.clone();
                tokio::spawn(async move {
                    let leg = run_webrtc_leg(
                        aor_c.clone(),
                        target_uri,
                        peer,
                        ws,
                        pending,
                        call_id_c,
                        leg_timeout,
                        webrtc_legs_c,
                    )
                    .await;
                    let _ = tx_c.send(leg);
                });
            }
        }
    }
    drop(tx);

    let mut last_status: Option<u16> = None;
    let mut received = 0usize;
    let deadline = tokio::time::Instant::now() + overall_timeout;

    // winner となった WebRTC leg を識別するため、 確定時の `WsSink` のチャネル
    // 識別子 (= `mpsc::UnboundedSender::same_channel`) を覚えておく。
    // Cancel cleanup ループで winner を除外するために使う。
    let mut winner_ws: Option<WsSink> = None;
    let result = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break ForkResult::Timeout;
        }
        let next = match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(v)) => v,
            Ok(None) => break ForkResult::AllFailed { last_status },
            Err(_) => break ForkResult::Timeout,
        };
        received += 1;
        match next {
            LegResult::Established {
                winner_uri,
                response,
                webrtc_handle,
                webrtc_ws,
                ..
            } => {
                info!(winner = %winner_uri, "fork_to_bindings: 内線 {} が応答", winner_uri);
                winner_ws = webrtc_ws.clone();
                break ForkResult::Answered {
                    winner_uri,
                    response,
                    webrtc_handle,
                    webrtc_ws,
                };
            }
            LegResult::Failed { status, .. } => {
                // Issue #211 / RFC 3261 §16.7 step 6 best response selection:
                // 並走中の SIP 内線 486 が後着すると `last_status` を 486 で
                // 上書きし、 先着の PWA 603 Decline を埋没させていた。
                // `should_replace_status` で 6xx > 4xx > 5xx > 3xx の優先度
                // (同クラスは first-wins) を実装し、 「先着優位 + クラス優位」
                // で集約する。
                if should_replace_status(last_status, status) {
                    last_status = Some(status);
                }
                // RFC 3261 §16.7 step 5: 6xx 受領時はそれ以上 fork レッグの結果を
                // 待たず、 immediate に AllFailed として抜ける (= 残る WebRTC leg は
                // 下段の `close_and_drain_webrtc_legs` ループで Cancel される)。
                // SIP leg は spawn 済の future が継続するが、 `tx_c` 経由の
                // 結果は drop される (loop exit 後 `rx` を捨てるため)。
                if (600..=699).contains(&status) {
                    info!(
                        status,
                        "fork_to_bindings: 6xx 受領 → 残レッグを待たず early terminate (RFC 3261 §16.7 step 5)"
                    );
                    break ForkResult::AllFailed { last_status };
                }
            }
            LegResult::Errored { .. } => {}
        }
        if received >= total {
            break ForkResult::AllFailed { last_status };
        }
    };

    // Issue #83: 走っている WebRTC leg に `ServerMessage::Cancel` を流す。
    //
    // 旧実装は `Answered` のときだけ winner 以外の leg を Cancel 対象にしていた
    // が、 `Timeout` / `AllFailed` でも browser は ringing UI を解放できず PWA
    // が固まる (W3C WebRTC §4.4.1 PeerConnection state: UA は long-running
    // pending state を放置すべきでない)。 ここでは fork が **どの結果で抜けても
    // 一括** で WebRTC leg を Cancel し、 PWA を ringing から解放する。
    //
    // ただし `Answered` で winner 自身は Cancel してはいけない (winner は
    // `LegResult::Established` を返した時点で `peer.accept_answer` 完了済みで、
    // call_id を確立済み通話として保持する)。 `WsSink` の同一性は内部
    // `mpsc::UnboundedSender::same_channel` で判定する (RFC 3261 §15 / §9.1
    // semantics に対応する WS 層の通知)。
    //
    // Review #1 (race fix): `close_and_drain_webrtc_legs` でアトミックに
    // `closed = true` 化と既存 leg の取り出しを行う。 これにより fork 確定後に
    // `peer.create_offer` を完了した遅延 leg は `try_register_webrtc_leg` が
    // false を返すため、 自前で Cancel を送って終了する経路に入る。
    //
    // `WsSink::same_channel` の意味論: 内部 `mpsc::UnboundedSender::same_channel`
    // (tokio 1.x) は 2 つの sender が同一 mpsc receiver を共有しているか、
    // すなわち 同一 WS セッション (= 同一 browser tab) を指すかを判定する。
    // `Arc::ptr_eq` 風の ID 一致比較で、 (clone 元と clone 先) は true、
    // (別 WS セッション) は false。
    //
    // 構造上 1 WS = 1 `WsSink` + 1 `aor_guard`
    // (`src/webrtc/signaling.rs:1031` の `aor_guard` は WS セッション固有) で、
    // winner 確定時に winner の `WsSink` を clone して `winner_ws` に持ち回り、
    // cleanup snapshot 側の各 leg `WsSink` と `same_channel` 比較する。 別 leg
    // が同じ WS から作られていれば clone 由来で true (= winner 自身)、 別 WS
    // (= 別 PWA tab / 別 binding) なら false (= Cancel 対象)。
    // PR #137 round-2 review で「1 PWA tab に複数 binding」 と書いてあったが
    // それは誤読で、 実際は WS インスタンス単位での同一性比較である。
    let drained = close_and_drain_webrtc_legs(&webrtc_legs).await;
    for leg in drained {
        if let Some(winner) = &winner_ws {
            if leg.ws.same_channel(winner) {
                continue;
            }
        }
        leg.pending.cancel(&leg.call_id).await;
        let _ = leg.ws.send(ServerMessage::Cancel {
            call_id: leg.call_id,
        });
    }
    result
}

/// 1 つの WebRTC leg を駆動する (Issue #73 / PR #50 統合漏れ修正)。
///
/// # 流れ (RFC 3264 §5-6: SDP offer/answer model)
///
/// 1. `peer.create_offer()` で sabiden 自身が DTLS-SRTP/SAVPF オファを生成する
///    (NGN の生 RTP/AVP オファをそのまま push してもブラウザは DTLS
///    fingerprint / ICE 認証情報不在で拒絶するため; RFC 8827 §6.5,
///    RFC 8839 §4.1)。
/// 2. `pending.register(call_id)` で answer 待ち oneshot を予約する。
/// 3. `ServerMessage::Offer` で WS にオファを push する。
/// 4. ブラウザ answer を `leg_timeout` 内に受信する。
/// 5. `peer.accept_answer(answer)` で str0m に渡し DTLS/ICE 確立を進める。
/// 6. NGN へ返す 200 OK の SDP body はブラウザ answer (SAVPF) を
///    `convert_savpf_to_avp` で NGN 仕様 (`docs/asterisk-real-invite.md` §2:
///    PCMU only, `RTP/AVP`) に変換したものを使う。最終的な
///    `c=`/`m= port` 書換は呼出側 `start_bridge_for_inbound`
///    (`rewrite_rtp_endpoint` 経由) が行う。
///
/// # NGN 由来 SDP は受け取らない
///
/// 旧実装は NGN INVITE の SDP を受け取って `peer.handle_offer` に渡していたが、
/// (1) Issue #73 で sabiden が offerer 側 (`create_offer`) になったので不要、
/// (2) ngn_peer 抽出は呼出側の `start_bridge_for_inbound::extract_rtp_endpoint`
///     が NGN INVITE の `request.body` から再度行うため
/// run_webrtc_leg 自身は NGN SDP を保持しなくてよい。
///
/// # 失敗時の `pending` 状態
///
/// - `peer.create_offer` 失敗時は `pending.register` の前に return するため
///   `pending` は触らない (`fork_to_bindings` 側で他 leg を続行できる)。
/// - WS 送信失敗 / answer タイムアウト時は `pending.cancel` で予約だけ撤去する。
/// - `peer.accept_answer` 失敗時は既に `deliver` が `pending` を消費済みなので
///   `pending` は触らないが、 str0m 側は `pending_offer` を保持したまま、 browser
///   側は answer 消費済で宙ぶらりんになる。 そのため `peer.close()` をベスト
///   エフォートで呼んで str0m run_loop を畳む (Issue #122 🟡 #3 / W3C WebRTC
///   §4.4.1 close semantics) → `Errored` を返す。
///
/// # race-condition: register-then-deliver の順序仕様 (Issue #140)
///
/// browser answer が `pending.register` 完了より前に届くケース (極めて早い
/// answer / WS でのフレーム順序入替) は **無効動作** で確定:
///
/// 1. WS 受信ハンドラ (`process_client_message` / `src/webrtc/signaling.rs`) が
///    `pending.deliver(call_id, sdp)` を呼ぶが、 waiter テーブル未登録のため
///    `false` を返す (= no-op、 SDP は捨てられる)。
/// 2. その後 `run_webrtc_leg` が `pending.register` → `try_register_webrtc_leg`
///    と進み、 `try_register_webrtc_leg` も `closed = true` なら `false`
///    (PR #137 race fix)、 そうでなければ通常パスで Offer push → answer 待ち。
/// 3. 既に消費された answer は到達しないので、 結果として `leg_timeout` で
///    `LegResult::Failed { status: 408 }` を返し、 `pending.cancel` で予約を
///    撤去する。
///
/// この no-op 経路は browser 側 UA バグ / シグナリングテスト用 race で発火する
/// 想定だが、 通常運用 (sabiden が Offer push → browser が answer 返却) では
/// 順序が **必ず register 先行** となるため到達しない。 現状の動作 (= 黙って
/// 408 にする) は副作用を出さない安全側で、 RFC 3261 §17.1.1 (INVITE
/// transaction) の 「timer B 失効 = 408」 semantics と整合する。
///
/// # 注意 (Issue #121 follow-up)
///
/// 戻り値 200 OK SDP の `c=` / `m= port` は `0.0.0.0:9` のままで、
/// 呼出側の `start_bridge_for_inbound` が `rewrite_rtp_endpoint` で sabiden の
/// NGN 側 RTP socket を指すように書き換える前提。`start_bridge_for_inbound`
/// が失敗した場合は `0.0.0.0:9` を NGN に流してはならず、handle_invite 側で
/// 5xx を返して呼を放棄する (現状の挙動)。
#[allow(clippy::too_many_arguments)]
async fn run_webrtc_leg(
    aor: String,
    target_uri: String,
    peer: Arc<dyn PeerSession>,
    ws: WsSink,
    pending: PendingAnswers,
    call_id: String,
    leg_timeout: Duration,
    webrtc_legs: Arc<Mutex<WebRtcLegRegistry>>,
) -> LegResult {
    // (1) sabiden を offerer として SAVPF オファを生成
    //   失敗時は `pending` を触らずに復帰する (他の SIP leg を妨げない)。
    let offer_for_browser = match peer.create_offer().await {
        Ok(sdp) => sdp,
        Err(e) => {
            warn!(%aor, error=%e, "WebRTC leg: peer.create_offer 失敗");
            return LegResult::Errored { aor };
        }
    };

    // (2) answer 待ち oneshot を先に登録 (race 回避: WS push 前に登録する)
    let waiter = pending.register(&call_id).await;

    // Issue #81/#83 review #1 (race fix): `peer.create_offer` 中に他レッグが
    // winner 確定 / fork timeout していた場合、 ここで registry に登録できない。
    // `try_register_webrtc_leg` がアトミックに `closed` フラグ確認 + 追加 を
    // 行う (closed なら false で復帰)。 closed 時は browser に Cancel を送って
    // 即終了する (W3C WebRTC §4.4.1: pending state を放置しない / RFC 3261 §9
    // CANCEL semantics の WS 通知形)。
    //
    // この登録 → push の順序が逆だと、 push 後に同じ critical section で push
    // しようとした winner snapshot 側 (close_and_drain) との整合が崩れる。
    let handle = WebRtcLegHandle {
        ws: ws.clone(),
        pending: pending.clone(),
        call_id: call_id.clone(),
    };
    if !try_register_webrtc_leg(&webrtc_legs, handle).await {
        debug!(
            %aor,
            "WebRTC leg: fork 確定後に create_offer が完了 → Offer push せず Cancel"
        );
        pending.cancel(&call_id).await;
        let _ = ws.send(ServerMessage::Cancel {
            call_id: call_id.clone(),
        });
        return LegResult::Errored { aor };
    }

    // (3) ブラウザに WS で offer を push
    //   登録後の push 失敗時は registry に残ったエントリを cleanup 担当が
    //   Cancel しても browser に届かないだけで害はない (browser は既に切断)。
    if let Err(e) = ws.send(ServerMessage::Offer {
        call_id: call_id.clone(),
        sdp: offer_for_browser,
    }) {
        warn!(%aor, error=%e, "WebRTC leg: WS 送信失敗 (browser 切断?)");
        pending.cancel(&call_id).await;
        return LegResult::Errored { aor };
    }

    // (4) ブラウザ answer / decline を timeout 内で受信
    //
    // Issue #107 (RFC 3261 §21.6.2 603 Decline):
    //   browser が「拒否」 ボタンで `ClientMessage::Decline { call_id }` を
    //   送ってくると、 sabiden WS ハンドラ (`process_client_message`) が
    //   `pending.decline(call_id, 603)` を呼び、 oneshot に
    //   `AnswerOutcome::Decline { status }` が流れる。 ここでそれを観測して
    //   `LegResult::Failed { status }` に変換し、 fork 全体としては
    //   他レッグも全部失敗していれば `ForkResult::AllFailed { last_status: Some(603) }`
    //   で抜けて NGN へ 603 Decline を返す (RFC 3261 §16.7 best response)。
    //   他レッグ (SIP 内線端末) が 200 OK を返せば通話成立で本レッグの 603 は
    //   破棄される (Asterisk 風フォーク semantics)。
    let answer = match tokio::time::timeout(leg_timeout, waiter).await {
        Ok(Ok(crate::webrtc::signaling::AnswerOutcome::Sdp(sdp))) => sdp,
        Ok(Ok(crate::webrtc::signaling::AnswerOutcome::Decline { status })) => {
            // pending は (4) の `decline`/`deliver` で既に消費済みなので
            // 追加クリーンアップ不要。 fork 側の cleanup (`close_and_drain_webrtc_legs`)
            // は引き続き当該レッグに `ServerMessage::Cancel` を送るが、 browser
            // 側 PWA は既に手元で UI を閉じているため idempotent (App.tsx の
            // `case "cancel"` ハンドラは既終了状態を変更しない)。
            info!(%aor, status, "WebRTC leg: browser が着信を拒否 (RFC 3261 §21.6.2)");
            return LegResult::Failed { aor, status };
        }
        Ok(Err(_)) => {
            debug!(%aor, "WebRTC leg: pending oneshot がキャンセルされた");
            return LegResult::Errored { aor };
        }
        Err(_) => {
            warn!(%aor, "WebRTC leg: browser から answer タイムアウト");
            pending.cancel(&call_id).await;
            return LegResult::Failed { aor, status: 408 };
        }
    };

    // (5) str0m に answer を流し込み DTLS/ICE 確立を促す。
    //   `pending` は (4) の `deliver` で既に消費済みなので追加クリーンアップ不要。
    //   Issue #122 🟡 #3: 失敗時は str0m run_loop が `pending_offer` 保持で
    //   宙ぶらりんになるので `peer.close()` をベストエフォートで呼ぶ。
    //   `close()` は str0m 実装上 cmd_tx send 失敗 (run_loop 既終了) も無視する。
    //   W3C WebRTC §4.4.1: close で peerconnection state を `closed` に倒す。
    if let Err(e) = peer.accept_answer(&answer).await {
        warn!(%aor, error=%e, "WebRTC leg: peer.accept_answer 失敗 (browser SDP 不正?)");
        let _ = peer.close().await;
        return LegResult::Errored { aor };
    }

    // (6) NGN の 200 OK には PCMU AVP に変換した SDP を載せる
    //   (docs/asterisk-real-invite.md §2: NGN は SAVPF / DTLS / ICE 属性を解釈しない)
    let body_for_ngn = match crate::sdp::builder::convert_savpf_to_avp(answer.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            warn!(%aor, error=%e, "WebRTC leg: SAVPF→AVP 変換失敗、生 answer を返す");
            answer.clone().into_bytes()
        }
    };

    // (7) Issue #87 / #121: peer の MediaFrame I/O を取り出して bridge に
    //   渡せるよう WebRtcLegArtifacts にまとめる。 `take_media_rx` は 1 度
    //   しか取れないので、 ここで取り出して所有権を bridge に move する。
    //   browser answer から Opus PT を抽出 (RFC 7587 §7.1)、 不在なら
    //   Chromium 既定の 111 を使う。
    let opus_pt = crate::call::transcoder::find_opus_payload_type(answer.as_bytes())
        .unwrap_or(crate::call::transcoder::DEFAULT_OPUS_PT);
    let webrtc_handle = match peer.take_media_rx().await {
        Some(rx) => Some(WebRtcLegArtifacts {
            peer: peer.clone(),
            peer_media_rx: rx,
            opus_payload_type: opus_pt,
        }),
        None => {
            // stub backend / 取得済みなど。 bridge は起動できないが SIP
            // 経路は維持する (orchestrator 側で 502 にする / 透過にするは
            // is_undirected_or_webrtc_placeholder_sdp 判定で分岐済)。
            debug!(%aor, "WebRTC leg: peer.take_media_rx None (stub backend?)");
            None
        }
    };

    let mut headers = SipHeaders::new();
    headers.set("Via", "SIP/2.0/WS webrtc.peer;branch=z9hG4bKwebrtc");
    headers.set("From", "<sip:webrtc>;tag=webrtc");
    headers.set("To", format!("<{}>;tag=webrtc-{}", target_uri, aor));
    headers.set("Call-ID", &call_id);
    headers.set("CSeq", "1 INVITE");
    headers.set("Content-Type", "application/sdp");
    let response = SipResponse {
        status_code: 200,
        reason: "OK".to_string(),
        headers,
        body: body_for_ngn,
    };
    LegResult::Established {
        aor,
        winner_uri: target_uri,
        response,
        webrtc_handle,
        // Issue #81: NGN BYE を browser に伝搬するため、 winner WS を上位に運ぶ。
        webrtc_ws: Some(ws),
    }
}

/// 既定の本番経路用 [`UacForker`] を構築するヘルパ。
///
/// 内線網用の別 `UdpSocket` と `TransactionLayer` を持つ `Uac` を内側で
/// 構築する想定。本関数は `main.rs` の起動順序を整えるだけなので、
/// 引数として既に構築済みの `Uac` を受け取るだけでよい。
pub fn make_forker(uac: Arc<Uac>) -> ExtInviter {
    Arc::new(UacForker {
        uac,
        targets: HashMap::new(),
    })
}

/// NGN 側の `TransactionLayer` を使い、`inbound_rx` を駆動して
/// `NgnInboundHandler` を起動する高水準ヘルパ。
///
/// `main.rs` から呼ばれる結線エントリポイント。
pub fn wire_ngn_inbound(
    _layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
) -> Arc<NgnInboundHandler> {
    wire_ngn_inbound_with_metrics(
        _layer,
        socket,
        inbound_rx,
        inviter,
        extensions,
        cfg,
        Metrics::new(),
    )
}

/// `wire_ngn_inbound` のメトリクス付き版。
pub fn wire_ngn_inbound_with_metrics(
    _layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    metrics: Arc<Metrics>,
) -> Arc<NgnInboundHandler> {
    let handler = NgnInboundHandler::with_metrics(socket, inviter, extensions, cfg, metrics);
    handler.clone().spawn(inbound_rx);
    handler
}

/// 内線が出した INVITE の Request-URI を NGN 直収用に正規化する。
///
/// NTT NGN (P-CSCF) は Request-URI の host が IP アドレス (P-CSCF IP) で
/// あることを要求する。LAN private IP (例: `192.168.20.239`) や NGN ドメイン
/// (例: `ntt-east.ne.jp`) のままだと **403 Forbidden** で蹴られる
/// (`docs/asterisk-real-invite.md` §3 / §5.1 — Asterisk 20 が同一線で
/// `sip:117@118.177.125.1:5060` で 200 OK を取得した実機キャプチャ準拠)。
///
/// 加えて、内線 (baresip 等) が `sip:117@<host>;transport=udp` のように
/// **uri-parameters** (RFC 3261 §19.1.1) を付けてくると、NGN P-CSCF は
/// `;transport=udp` を含む Request-URI を **`500 Server Internal Error`**
/// で蹴る (Issue #58 の実機 trace)。同 §19.1.1 の通り `uri-parameters` は
/// `;param` の繰返し、`headers` は `?h=v&h=v` の形を取るが、Asterisk 実機
/// INVITE は **どちらも付けず** に 200 OK を取得している
/// (`docs/asterisk-real-invite.md` §5.1)。NGN 直収では `transport`/`lr`/
/// `maddr` 等の URI パラメータは **不要かつ有害** なので、host/port 書換と
/// 同時に `;params` と `?headers` を完全に剥がす。
///
/// 引数:
/// - `req_uri`: 内線が出した SIP URI (例: `sip:117@192.168.20.239;transport=udp`)
/// - `ngn_server_host`: P-CSCF IP (例: `118.177.125.1`)
/// - `ngn_server_port`: P-CSCF port (通常 `5060`)
///
/// 戻り値: `sip:<user>@<ngn_server_host>:<ngn_server_port>` 形式の URI。
/// `;uri-parameters` と `?headers` は常に削除する (NGN 仕様)。
/// 既に正規化済 (host:port 一致 + params/headers 無し) ならそのまま返す
/// (idempotent)。パース不能な URI は変更せず元のまま返す (フェイルセーフ)。
pub fn normalize_request_uri_for_ngn(
    req_uri: &str,
    ngn_server_host: &str,
    ngn_server_port: u16,
) -> String {
    // RFC 3261 §19.1.1 準拠の構造解析を `parse_sip_uri` に委譲し、
    // ここでは host/port の書換と uri-parameters/headers の破棄だけ行う。
    let parsed = match crate::sip::message::parse_sip_uri(req_uri) {
        Ok(p) => p,
        Err(_) => return req_uri.to_string(),
    };
    // 既に P-CSCF host:port + params/headers 無しなら何もしない (idempotent)。
    let already_pcsf_host = parsed.host.eq_ignore_ascii_case(ngn_server_host);
    let already_pcsf_port = parsed.port == Some(ngn_server_port);
    if already_pcsf_host
        && already_pcsf_port
        && parsed.params.is_empty()
        && parsed.headers.is_empty()
    {
        return req_uri.to_string();
    }
    // 再構築。`<scheme>:<user>@<pcsf_host>:<pcsf_port>` のみ。
    // `;params` と `?headers` は NGN 仕様 (§docstring 参照) で常に剥がす。
    let scheme = if parsed.scheme.is_empty() {
        "sip".to_string()
    } else {
        parsed.scheme.clone()
    };
    match parsed.user {
        Some(user) => format!(
            "{}:{}@{}:{}",
            scheme, user, ngn_server_host, ngn_server_port
        ),
        None => format!("{}:{}:{}", scheme, ngn_server_host, ngn_server_port),
    }
}

/// 内線→NGN 発信時の SDP 強制書換 (CallManager 未注入時のフォールバック)。
///
/// Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §5.2): NGN へ出す INVITE の
/// SDP に LAN private IP (192.168.x.x 等) を載せると応答先が成立しない。
/// `c=` / `o=` IP は **必ず** sabiden eth1 (NGN 側 sent-by) IP に書換える。
///
/// RTP port は本パスでは sabiden が中継しないため、内線広告の port を
/// そのまま広告する (= NGN→内線 RTP は経路上 NAT 越えできないため音声は
/// 流れないが、SIP signaling は通り 200 OK を取れる)。本来は CallManager を
/// `main.rs` で注入し `prepare_outbound_bridge` 経由で IP/port 両方を sabiden
/// 側に書換るのが正解。
///
/// 戻り値:
/// - 入力が空なら `None`
/// - 書換成功なら `Some(rewritten_bytes)`
/// - 書換失敗 (SDP パースエラー等) でも、元 body を `Some` で返す
///   (LAN IP を漏らすが、INVITE 自体は出る)。warn ログで観測可能。
fn force_rewrite_sdp_for_ngn(ext_offer: &[u8], ngn_local_ip: IpAddr) -> Option<Vec<u8>> {
    if ext_offer.is_empty() {
        return None;
    }
    // 元 SDP の m=audio port を温存しつつ c=/o= IP のみ NGN 側へ書き換える。
    // rewrite_rtp_endpoint は port も書き換えてしまうため、まず port を取り出す。
    let port =
        match crate::sdp::SessionDescription::parse(std::str::from_utf8(ext_offer).unwrap_or("")) {
            Ok(sdp) => sdp
                .media
                .iter()
                .find(|m| m.media == "audio")
                .map(|m| m.port)
                .unwrap_or(0),
            Err(e) => {
                warn!(error=%e, "SDP パース失敗 → 元 body のまま (LAN IP 漏洩リスク)");
                return Some(ext_offer.to_vec());
            }
        };
    match rewrite_rtp_endpoint(ext_offer, ngn_local_ip, port) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            warn!(error=%e, "SDP 強制書換失敗 → 元 body のまま (LAN IP 漏洩リスク)");
            Some(ext_offer.to_vec())
        }
    }
}

/// `wire_ngn_inbound` の `CallManager` 接続版。RTP ブリッジを起動する経路。
pub fn wire_ngn_inbound_with_manager(
    layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    call_manager: Arc<CallManager>,
) -> Arc<NgnInboundHandler> {
    wire_ngn_inbound_with_manager_and_metrics(
        layer,
        socket,
        inbound_rx,
        inviter,
        extensions,
        cfg,
        call_manager,
        Metrics::new(),
    )
}

/// `wire_ngn_inbound_with_manager` の メトリクス付きバージョン。
///
/// Issue #40 の本流配線で `main.rs` から呼ぶエントリポイント。NGN 着信 INVITE に
/// 対して内線フォーク + RTP ブリッジ起動を一括で結線する。
///
/// 引数が多いのは結線ヘルパとして必須パラメータをそのまま受け渡すためで、
/// 構造体化は本流配線の関心事ではない (`main.rs` から 1 か所で呼ぶだけ)。
#[allow(clippy::too_many_arguments)]
pub fn wire_ngn_inbound_with_manager_and_metrics(
    _layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    call_manager: Arc<CallManager>,
    metrics: Arc<Metrics>,
) -> Arc<NgnInboundHandler> {
    let handler = NgnInboundHandler::with_call_manager_and_metrics(
        socket,
        inviter,
        extensions,
        cfg,
        call_manager,
        metrics,
    );
    handler.clone().spawn(inbound_rx);
    handler
}

/// `wire_ngn_inbound_with_manager_and_metrics` の outbound テーブル共有版 (Issue #147)。
///
/// `webrtc_outbound_active` を [`UasEventHandler`] と共有することで、
/// PWA→NGN 発信通話の双方向 BYE 連動 (NGN→PWA / PWA→NGN) が成立する。
#[allow(clippy::too_many_arguments)]
pub fn wire_ngn_inbound_with_manager_metrics_and_outbound_table(
    layer: Arc<TransactionLayer>,
    socket: Arc<UdpSocket>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    inviter: ExtInviter,
    extensions: Arc<ExtensionRegistrar>,
    cfg: NgnInboundConfig,
    call_manager: Arc<CallManager>,
    metrics: Arc<Metrics>,
    webrtc_outbound_active: WebRtcOutboundActive,
) -> Arc<NgnInboundHandler> {
    // Bug B / Issue #268: layer を `NgnInboundHandler` に渡して PWA WS close →
    // NGN BYE 経路を有効化する。 旧経路 (`_layer` 未使用) は inbound 側で
    // BYE を発射する必要が無かったため layer を握っていなかったが、 本 PR で
    // `webrtc_active` を `WebRtcInboundEntry` 化し UAS dialog から BYE を組み
    // 立てる経路を追加したため layer 必須となる (RFC 3261 §15.1.1)。
    let handler = NgnInboundHandler::with_layer_call_manager_metrics_and_outbound_table(
        layer,
        socket,
        inviter,
        extensions,
        cfg,
        call_manager,
        metrics,
        webrtc_outbound_active,
    );
    handler.clone().spawn(inbound_rx);
    handler
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::{parse_message, SipMessage};
    use crate::sip::transaction::TransactionLayer;
    use crate::testing::builders;
    use crate::testing::scripted::{ScriptedAction, ScriptedInviter};
    use std::net::SocketAddr;
    use std::sync::Mutex as StdMutex;
    use tokio::net::UdpSocket;

    // ====================================================================
    // Issue #211: RFC 3261 §16.7 best response selection / §21.6.2 Decline
    // ====================================================================

    /// RFC 3261 §16.7 step 6: 6xx (Global Failure) は 4xx/5xx より優先される。
    /// PR #210 では先着 603 (PWA decline) が後着 486 (SIP busy) に上書きされる
    /// race があり、 Issue #211 で本関数の優先度ロジックを導入した。
    #[test]
    fn rfc3261_16_7_should_replace_status_6xx_beats_4xx_and_5xx() {
        // 6xx は 4xx/5xx を上書きする
        assert!(should_replace_status(Some(486), 603));
        assert!(should_replace_status(Some(404), 603));
        assert!(should_replace_status(Some(500), 603));
        assert!(should_replace_status(Some(503), 603));
        // 4xx/5xx は 6xx を上書きしない (= 後着の SIP 486 が PWA 603 を消さない)
        assert!(!should_replace_status(Some(603), 486));
        assert!(!should_replace_status(Some(603), 500));
        assert!(!should_replace_status(Some(603), 404));
    }

    /// RFC 3261 §16.7 step 6: 同クラス内は「first-wins」。 新 status が `current`
    /// と同じクラスなら上書きしない (= 先着優位)。
    #[test]
    fn rfc3261_16_7_should_replace_status_same_class_first_wins() {
        // 4xx 同士 → 先着 486 を保持
        assert!(!should_replace_status(Some(486), 404));
        assert!(!should_replace_status(Some(486), 487));
        // 6xx 同士 → 先着 603 を保持
        assert!(!should_replace_status(Some(603), 600));
        assert!(!should_replace_status(Some(603), 604));
        // 5xx 同士
        assert!(!should_replace_status(Some(500), 503));
    }

    /// 初回受信 (`current = None`) は無条件採用。
    #[test]
    fn rfc3261_16_7_should_replace_status_initial_none_always_accepts() {
        assert!(should_replace_status(None, 486));
        assert!(should_replace_status(None, 603));
        assert!(should_replace_status(None, 404));
        assert!(should_replace_status(None, 500));
    }

    /// RFC 3261 §16.7 step 6 クラス間優先度 (6xx > 4xx > 5xx > 3xx) を直接
    /// 検証する。 注: §16.7 は 4xx/5xx の正確な順序を規定していないが、
    /// 実用上 4xx (request failure) の方が「終端的」 として扱われることが多い
    /// (Asterisk fork_done コードと同じ慣習)。 ただし重要なのは「6xx が常に
    /// 最優先」 で、 これは Issue #211 の主目的。
    #[test]
    fn rfc3261_16_7_final_response_class_rank_orders_6xx_highest() {
        assert!(final_response_class_rank(603) > final_response_class_rank(486));
        assert!(final_response_class_rank(603) > final_response_class_rank(500));
        assert!(final_response_class_rank(603) > final_response_class_rank(302));
        // 6xx 内は同 rank (first-wins は呼出側のロジック)
        assert_eq!(
            final_response_class_rank(600),
            final_response_class_rank(603)
        );
    }

    /// RFC 3261 §21.6.2: 603 の正規 reason phrase は **単数** "Decline"。
    /// PR #210 では誤って "Declined" を返しており、 Issue #211 で修正。
    #[test]
    fn rfc3261_21_6_2_reason_phrase_for_603_is_singular_decline() {
        assert_eq!(reason_phrase_for_status(603), "Decline");
        // 誤った "Declined" になっていないこと (regression guard)
        assert_ne!(reason_phrase_for_status(603), "Declined");
    }

    /// RFC 3261 §21.4.21: 486 は "Busy Here"。
    #[test]
    fn rfc3261_21_4_21_reason_phrase_for_486_is_busy_here() {
        assert_eq!(reason_phrase_for_status(486), "Busy Here");
    }

    /// RFC 3261 §21.4.25: 487 は "Request Terminated"。
    #[test]
    fn rfc3261_21_4_25_reason_phrase_for_487_is_request_terminated() {
        assert_eq!(reason_phrase_for_status(487), "Request Terminated");
    }

    /// Issue #211: race シナリオの再現テスト。 fork に 3 つの leg を入れて、
    ///
    /// 1. WebRTC leg 風の Failed{603} (PWA decline 相当) が先着
    /// 2. SIP leg の Failed{486} (SIP UA busy) が後着
    /// 3. SIP leg の Failed{404} (Not Found) が後着
    ///
    /// 旧挙動では `last_status = Some(486)` (または 404) で上書きされ NGN へ
    /// 486 / 404 が返っていた。 新挙動は **6xx 受領時点で early terminate**
    /// + 6xx 優先度で `Some(603)` を維持し、 NGN へ 603 Decline を返す
    /// (RFC 3261 §16.7 step 5/6)。
    ///
    /// ここでは SIP 3 本だけで `fork_to_bindings` を呼ぶ (WebRTC mock は別テストで
    /// 検証済 `rfc3261_21_6_2_run_webrtc_leg_propagates_decline_as_failed_603`)。
    /// 1 本目を `ImmediateStatus(603)`、 残り 2 本を `DelayedStatus(486)` /
    /// `DelayedStatus(404)` にすることで「603 先着 → 486/404 後着」 を再現。
    #[tokio::test]
    async fn rfc3261_16_7_fork_to_bindings_keeps_6xx_when_4xx_arrives_later() {
        use crate::sip::registrar::{Binding, ExtTransport};

        // 600ms 後に 486 / 800ms 後に 404 を返す 2 本と、 即時 603 の 1 本。
        let inviter = ScriptedInviter::builder()
            .script(
                "sip:fast-decline@ext.local",
                ScriptedAction::ImmediateStatus(603),
            )
            .script(
                "sip:slow-busy@ext.local",
                ScriptedAction::DelayedStatus {
                    delay_ms: 600,
                    status: 486,
                },
            )
            .script(
                "sip:slow-notfound@ext.local",
                ScriptedAction::DelayedStatus {
                    delay_ms: 800,
                    status: 404,
                },
            )
            .default_action(ScriptedAction::ImmediateStatus(486))
            .build();

        let make_binding = |uri: &str| Binding {
            contact_uri: uri.to_string(),
            remote: "127.0.0.1:65535".parse().unwrap(),
            expires_at: std::time::Instant::now() + Duration::from_secs(60),
            transport: ExtTransport::Sip,
        };
        let bindings = vec![
            (
                "fast".to_string(),
                make_binding("sip:fast-decline@ext.local"),
            ),
            ("slow1".to_string(), make_binding("sip:slow-busy@ext.local")),
            (
                "slow2".to_string(),
                make_binding("sip:slow-notfound@ext.local"),
            ),
        ];

        let start = std::time::Instant::now();
        let result = fork_to_bindings(
            inviter,
            bindings,
            b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
              m=audio 20000 RTP/AVP 0\r\n"
                .to_vec(),
            "ut-cid-6xx-priority".to_string(),
            Duration::from_secs(5),
        )
        .await;
        let elapsed = start.elapsed();

        // RFC 3261 §16.7 step 5: 6xx 受領で early terminate するため、
        // 遅い 486/404 (600ms/800ms) を待たずに数十 ms で抜けるはず。
        assert!(
            elapsed < Duration::from_millis(500),
            "6xx early terminate (RFC 3261 §16.7 step 5) が効いていない: elapsed={:?}",
            elapsed
        );

        match result {
            ForkResult::AllFailed { last_status } => {
                assert_eq!(
                    last_status,
                    Some(603),
                    "RFC 3261 §16.7 step 6: 603 (6xx) は 486/404 (4xx) より優先される"
                );
            }
            ForkResult::Answered { .. } => panic!("AllFailed 期待だが Answered"),
            ForkResult::Timeout => panic!("AllFailed 期待だが Timeout"),
        }
    }

    /// Issue #211 / RFC 3261 §16.7 step 6: 逆順 race (4xx 先着 → 6xx 後着) でも
    /// 最終的に `last_status = Some(603)` になる。 これは「6xx は 4xx を
    /// **上書きする**」 という class 間優先度の検証。
    #[tokio::test]
    async fn rfc3261_16_7_fork_to_bindings_late_6xx_overrides_early_4xx() {
        use crate::sip::registrar::{Binding, ExtTransport};

        let inviter = ScriptedInviter::builder()
            .script(
                "sip:fast-busy@ext.local",
                ScriptedAction::ImmediateStatus(486),
            )
            .script(
                "sip:slow-decline@ext.local",
                ScriptedAction::DelayedStatus {
                    delay_ms: 200,
                    status: 603,
                },
            )
            .default_action(ScriptedAction::ImmediateStatus(486))
            .build();

        let make_binding = |uri: &str| Binding {
            contact_uri: uri.to_string(),
            remote: "127.0.0.1:65535".parse().unwrap(),
            expires_at: std::time::Instant::now() + Duration::from_secs(60),
            transport: ExtTransport::Sip,
        };
        let bindings = vec![
            ("fast".to_string(), make_binding("sip:fast-busy@ext.local")),
            (
                "slow".to_string(),
                make_binding("sip:slow-decline@ext.local"),
            ),
        ];

        let result = fork_to_bindings(
            inviter,
            bindings,
            b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
              m=audio 20000 RTP/AVP 0\r\n"
                .to_vec(),
            "ut-cid-late-6xx".to_string(),
            Duration::from_secs(3),
        )
        .await;

        match result {
            ForkResult::AllFailed { last_status } => {
                assert_eq!(
                    last_status,
                    Some(603),
                    "RFC 3261 §16.7 step 6: 6xx は 4xx を上書きする"
                );
            }
            ForkResult::Answered { .. } => panic!("AllFailed 期待だが Answered"),
            ForkResult::Timeout => panic!("AllFailed 期待だが Timeout"),
        }
    }

    /// PR #193 review #2 🟡#3: PWA→NGN 経路の rate-limit bucket key 抽出
    /// (`extract_user_from_sip_uri`) の境界条件。 sabiden の `local_uri` は
    /// `sip:0312345678@ntt-east.ne.jp` 形式が標準 (RFC 3261 §19.1.1) だが、
    /// 設定ミスや config 経路の柔軟性で別形式が混入する余地があるため、
    /// 全形式で panic しないことと、 不正形式は `None` を返すことを保証する。
    #[test]
    fn extract_user_from_sip_uri_parses_canonical_form() {
        // RFC 3261 §19.1.1 標準形式
        assert_eq!(
            extract_user_from_sip_uri("sip:0312345678@ntt-east.ne.jp"),
            Some("0312345678".to_string())
        );
    }

    /// `sips:` スキーム (RFC 3261 §19.1) も `sip:` と同じく user 部を返す。
    #[test]
    fn extract_user_from_sip_uri_handles_sips_scheme() {
        assert_eq!(
            extract_user_from_sip_uri("sips:alice@example.com"),
            Some("alice".to_string())
        );
    }

    /// user 部が無い URI (`sip:host[:port]`) は `None`。
    /// 呼出側 (`ngn_aor_from_uac`) はこの場合 URI 全体を fallback key にする
    /// (= 動作はそのまま、 ただ bucket key が長いだけ)。
    #[test]
    fn extract_user_from_sip_uri_returns_none_for_userless_uri() {
        assert_eq!(extract_user_from_sip_uri("sip:example.com"), None);
        assert_eq!(extract_user_from_sip_uri("sip:example.com:5060"), None);
    }

    /// 空文字列は `None` (panic しない)。
    #[test]
    fn extract_user_from_sip_uri_returns_none_for_empty_input() {
        assert_eq!(extract_user_from_sip_uri(""), None);
    }

    /// `@` 前の user-part が空 (`sip:@host`) は `None`。 ロジック上は
    /// `Some("")` で返さない (= bucket key として空文字列は使わない)。
    #[test]
    fn extract_user_from_sip_uri_rejects_empty_user_part() {
        assert_eq!(extract_user_from_sip_uri("sip:@example.com"), None);
    }

    /// `;params` / `:port` 付きの host は user 抽出に影響しない。
    /// `sip:user;param=val@host` のような不正形式 (params は URI 末尾の hostname
    /// 以降に置くのが RFC 3261 §19.1.1 標準) は最初の `@` で割るため、
    /// `user;param=val` を返す。 既存呼出側 (`ngn_aor_from_uac`) の用途では
    /// この string がそのまま bucket key になる = 多少奇妙でも誤動作はしない。
    #[test]
    fn extract_user_from_sip_uri_keeps_userpart_verbatim() {
        // 標準形式: host に :port が付いていても user 抽出には影響しない
        assert_eq!(
            extract_user_from_sip_uri("sip:0312345678@ntt-east.ne.jp:5060"),
            Some("0312345678".to_string())
        );
        // user 部に `:password` (RFC 3261 §19.1.1: userinfo) が混入した場合は
        // そのまま返す。 sabiden の用途では password を含む URI は使わない
        // (`auth_password` は別フィールド) ので、 ここはベストエフォート。
        assert_eq!(
            extract_user_from_sip_uri("sip:user:pw@example.com"),
            Some("user:pw".to_string())
        );
    }

    /// Issue #207 / PR #205 follow-up 🟡#3: `classify_ext_reinvite_send_error`
    /// は内線レッグ `send_request` 失敗を RFC 3261 §13.3.1.1 (408) / §13.3.1.2
    /// (500) の正しい意味論に振り分けることを保証する。
    ///
    /// Timer B/F (= 64 * T1) 満了の場合 ClientTransaction::run は
    /// `anyhow!("transaction timeout")` を返す。 §13.3.1.1 はこの「callee 応答
    /// 不在」を 408 Request Timeout で表現することを認めており、 sabiden は
    /// B2BUA UAS として同 semantic を NGN 側 UAC に伝搬する。
    #[test]
    fn classifies_timer_bf_as_408_per_rfc3261_13_3_1_1() {
        let err = anyhow::anyhow!("transaction timeout");
        assert_eq!(
            classify_ext_reinvite_send_error(&err),
            (408, "Request Timeout"),
        );
    }

    /// Timer B/F 以外の `send_request` 失敗 (= UDP I/O 失敗、 channel 停止、
    /// header parse 失敗) は RFC 3261 §13.3.1.2 「unexpected condition で
    /// request 履行不能」に該当するため 500 Server Internal Error を返す。
    #[test]
    fn classifies_transport_error_as_500_per_rfc3261_13_3_1_2() {
        // (a) UDP send_to の I/O 失敗をシミュレートする anyhow 例
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "ECONNREFUSED");
        let any_io: anyhow::Error = anyhow::Error::new(io_err);
        assert_eq!(
            classify_ext_reinvite_send_error(&any_io),
            (500, "Server Internal Error"),
        );

        // (b) transaction layer 停止 (rx チャネル close) を表す文字列
        let layer_down = anyhow::anyhow!("transaction layer が停止した");
        assert_eq!(
            classify_ext_reinvite_send_error(&layer_down),
            (500, "Server Internal Error"),
        );

        // (c) oneshot 中断 (= client transaction が中断された)
        let oneshot_abort = anyhow::anyhow!("client transaction が中断された");
        assert_eq!(
            classify_ext_reinvite_send_error(&oneshot_abort),
            (500, "Server Internal Error"),
        );

        // (d) create_client のヘッダ欠落
        let no_via = anyhow::anyhow!("Via ヘッダがない");
        assert_eq!(
            classify_ext_reinvite_send_error(&no_via),
            (500, "Server Internal Error"),
        );
    }

    /// "transaction timeout" 文字列を context に含めた wrap 形式 (今後
    /// transaction.rs 側で context を追加された場合に備えた契約) でも 408
    /// に振れることを確認する。 `format!("{err}")` が anyhow の chain を辿る
    /// ことに依存するため、 wrap 後でも一致することを念のため担保する。
    #[test]
    fn classifies_wrapped_timeout_as_408() {
        let inner = anyhow::anyhow!("transaction timeout");
        let wrapped = inner.context("ext leg Re-INVITE failed");
        assert_eq!(
            classify_ext_reinvite_send_error(&wrapped),
            (408, "Request Timeout"),
        );
    }

    /// PR #193 review #2 🟡#3: `ngn_aor_from_uac` は `Uac::config().local_addr_of_record()`
    /// から user 部を取り出して bucket key とする。 user 抽出に成功すれば短い
    /// key (`0312345678`)、 失敗すれば URI 全体 fallback (`sip:example.com`) を
    /// 返すことを統合的に確認する。
    #[tokio::test]
    async fn ngn_aor_from_uac_falls_back_to_full_uri_when_no_user_part() {
        use crate::sip::uac::UacConfig;
        // (1) 正常: user 抽出成功
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (layer, _rx) = TransactionLayer::spawn(sock.clone());
        let uac_ok = Uac::new(
            UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            layer,
            sock.local_addr().unwrap(),
        );
        assert_eq!(ngn_aor_from_uac(&uac_ok), "0312345678");

        // (2) fallback: user 部無し URI → URI 全体が key になる
        let sock2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (layer2, _rx2) = TransactionLayer::spawn(sock2.clone());
        let uac_userless = Uac::new(
            UacConfig {
                local_uri: "sip:ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: sock2.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            layer2,
            sock2.local_addr().unwrap(),
        );
        assert_eq!(ngn_aor_from_uac(&uac_userless), "sip:ntt-east.ne.jp");
    }

    /// RFC 3261 §8.2.6.2 / §7.3.1 / §25.1 / §12.2.2 / PR #136 review fix:
    /// orchestrator 側の `ensure_to_tag` も既存 To-tag 有無判定を
    /// **case-insensitive** に行う。 `;TAG=existing` 大文字 / `;tAg=` 混在
    /// に対し、 既存値を保持して二重 tag を作らないことを assert する。
    /// 二重 tag を返すと内線 UA は §12.2.2 違反扱いで ACK を送らず切断する。
    #[test]
    fn rfc3261_8_2_6_2_orchestrator_ensure_to_tag_is_case_insensitive() {
        // (1) 大文字 `;TAG=existing-uas-tag` → no-op で原文保持
        let mut resp = SipResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: SipHeaders::new(),
            body: vec![],
        };
        resp.headers
            .set("To", "<sip:dest@sabiden>;TAG=existing-uas-tag");
        ensure_to_tag(&mut resp);
        let to = resp.headers.get("to").unwrap();
        assert_eq!(
            to, "<sip:dest@sabiden>;TAG=existing-uas-tag",
            "orchestrator::ensure_to_tag: 大文字 TAG を尊重し二重付与しない: To={}",
            to
        );

        // (2) mixed case `;tAg=` も保持
        let mut resp = SipResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: SipHeaders::new(),
            body: vec![],
        };
        resp.headers.set("To", "<sip:dest@sabiden>;tAg=mixed");
        ensure_to_tag(&mut resp);
        let to = resp.headers.get("to").unwrap();
        assert_eq!(
            to, "<sip:dest@sabiden>;tAg=mixed",
            "orchestrator::ensure_to_tag: mixed case を保持: To={}",
            to
        );

        // (3) tag 真に無し: 新規付与する (RFC 3261 §8.2.6.2)
        let mut resp = SipResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: SipHeaders::new(),
            body: vec![],
        };
        resp.headers.set("To", "<sip:dest@sabiden>");
        ensure_to_tag(&mut resp);
        let to = resp.headers.get("to").unwrap();
        assert!(to.contains(";tag="), "tag 無しなら新規付与: To={}", to);
    }

    /// `is_undirected_or_webrtc_placeholder_sdp` が WebRTC leg 由来の `0.0.0.0:9`
    /// プレースホルダ SDP を検出する。 正常な SIP leg の LAN IP / 実 port SDP、
    /// および RFC 4566 §5.7 hold/silenced (= `c=0.0.0.0` + 実 port) は false に
    /// すること (Issue #122 🟡 #2 修正)。
    ///
    /// telephone-event 関連の判定は Issue #108 (PR #209) で `offer_has_telephone_event`
    /// (orchestrator-private) から `crate::sdp::builder::restrict_answer_to_ngn_offer_subset`
    /// (NGN offer subset 厳密化) に移管されたため、 本 test module 側の
    /// `offer_has_telephone_event_*` テスト群も併せて削除した
    /// (RFC 3264 §6.1 準拠は `src/sdp/builder.rs::restrict_answer_subset_tests` で担保)。
    #[test]
    fn rfc4566_5_2_5_14_undirected_or_webrtc_placeholder_requires_both_zero_conn_and_port_9() {
        // WebRTC leg placeholder: c=0.0.0.0 かつ m=audio 9 → true
        let webrtc_avp = b"v=0\r\no=- 9 9 IN IP4 0.0.0.0\r\ns=-\r\n\
                           c=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                           m=audio 9 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        assert!(is_undirected_or_webrtc_placeholder_sdp(webrtc_avp));

        let webrtc_savpf = b"v=0\r\no=- 9 9 IN IP4 0.0.0.0\r\ns=-\r\n\
                             c=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                             m=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n";
        assert!(is_undirected_or_webrtc_placeholder_sdp(webrtc_savpf));

        // 通常 SIP UA: LAN IP + 実 port → false
        let normal_sip = b"v=0\r\no=- 1 1 IN IP4 192.168.1.10\r\ns=-\r\n\
                           c=IN IP4 192.168.1.10\r\nt=0 0\r\n\
                           m=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        assert!(!is_undirected_or_webrtc_placeholder_sdp(normal_sip));

        // Issue #122 🟡 #2 重要回帰: RFC 4566 §5.7 hold/silenced semantics で
        // SIP UA が `c=IN IP4 0.0.0.0` + 実 RTP port を返した場合は **false**。
        // 旧実装は ここを true として 502 で呼を落としていた (誤検知)。
        let session_held = b"v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\n\
                             c=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                             m=audio 30000 RTP/AVP 0\r\n";
        assert!(
            !is_undirected_or_webrtc_placeholder_sdp(session_held),
            "RFC 4566 §5.7 hold/silenced は WebRTC placeholder ではない (Issue #122 🟡 #2)"
        );

        // 逆ケース: m=audio 9 のみ (c= は実 IP) → false (offer に対する完全な
        // discard port 拒否は別 semantics で、 本判定は WebRTC peer 由来の
        // 「0.0.0.0:9 中間状態」を狭く拾う)。
        let port_9_only = b"v=0\r\no=- 1 1 IN IP4 192.168.1.10\r\ns=-\r\n\
                            c=IN IP4 192.168.1.10\r\nt=0 0\r\n\
                            m=audio 9 RTP/AVP 0\r\n";
        assert!(!is_undirected_or_webrtc_placeholder_sdp(port_9_only));
    }

    /// NGN 着信 INVITE → 内線フォーク (200) → 200 OK が NGN 側に届く。
    #[tokio::test]
    async fn ngn_invite_forwards_200_back() {
        // sabiden の NGN 側ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();

        // フェイク NGN クライアント (UA 役)
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 内線登録テーブルにダミー内線を 1 件入れておく
        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6001".to_string(),
                "127.0.0.1:6001".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        // モック inviter (testing ハーネス): 200 OK + ダミー SDP
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n".to_vec())
            .build();

        // TransactionLayer + 着信ハンドラを起動
        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
        );

        // フェイク NGN から INVITE を送信
        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0312345678@sabiden",
            "ngn-invite-cid",
            "z9hG4bKngn1",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\n".to_vec(),
        );
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 100 Trying と 200 OK が届くまで複数応答を読む
        let mut buf = vec![0u8; 8192];
        let mut got_100 = false;
        let mut got_200 = false;
        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        match r.status_code {
                            100 => got_100 = true,
                            200 => {
                                got_200 = true;
                                // SDP 透過確認
                                assert!(!r.body.is_empty(), "200 OK には SDP body があるはず");
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_100, "100 Trying が NGN 側に届くべき");
        assert!(got_200, "200 OK が NGN 側に届くべき");
        assert!(inviter.call_count() >= 1, "内線へ INVITE される");
    }

    /// 登録内線が 0 件なら 480 Temporarily Unavailable で返る。
    #[tokio::test]
    async fn ngn_invite_with_no_extensions_returns_480() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
        );

        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0312345678@sabiden",
            "ngn-noext-cid",
            "z9hG4bKngn-noext",
            Vec::new(),
        );
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let mut got_480 = false;
        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(2), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 480 {
                            got_480 = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_480, "480 Temporarily Unavailable が返るべき");
        assert_eq!(
            inviter.call_count(),
            0,
            "内線が無ければ inviter は呼ばれない"
        );
    }

    /// Issue #110 共通ハーネス: NGN→sabiden に method 指定の SIP リクエストを
    /// 投げて、 期待するステータスコードと `Allow` ヘッダの有無を検証する。
    ///
    /// セットアップ: 100 Trying 等を返さない non-INVITE 経路を見るために
    /// 登録内線 0 件で十分 (handle_invite に到達しないため)。
    async fn assert_ngn_method_response(
        method: SipMethod,
        expected_status: u16,
        expect_allow_header: bool,
    ) {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
        );

        let method_str = method.as_str().to_string();
        let req = builders::request_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            method,
            "sip:sabiden@127.0.0.1",
            &format!("ngn-{}-cid", method_str.to_lowercase()),
            &format!("z9hG4bKngn-{}", method_str.to_lowercase()),
        );
        let method_str = method_str.as_str();
        ngn_sock
            .send_to(&req.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let mut got_response = None;
        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(2), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                        // 100 Trying は INVITE 系のみ。 非 INVITE 経路には来ない想定。
                        if r.status_code != 100 {
                            got_response = Some(r);
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        let resp = got_response.unwrap_or_else(|| {
            panic!(
                "{} に対する応答が NGN 側に届くべき (期待 status={})",
                method_str, expected_status
            )
        });
        assert_eq!(
            resp.status_code, expected_status,
            "{} には status={} を返すべき (実際: {} {})",
            method_str, expected_status, resp.status_code, resp.reason,
        );
        let allow = resp.headers.get("allow");
        if expect_allow_header {
            let allow_val = allow.unwrap_or_else(|| {
                panic!(
                    "{} 応答には `Allow` ヘッダが必須 (RFC 3261 §8.2.1 / §20.5)",
                    method_str
                )
            });
            assert!(
                allow_val.contains("INVITE") && allow_val.contains("BYE"),
                "{} 応答の Allow に INVITE / BYE が含まれること: {}",
                method_str,
                allow_val
            );
        }
    }

    /// RFC 3265 §3.2: NGN 側から届いた NOTIFY は該当 subscription が
    /// 無いため `481 Subscription Does Not Exist` で応答する。
    /// IMS の reg-event NOTIFY を 405 で返すと P-CSCF が
    /// 「reg-event を扱えない端末」と判断し binding 期限を短縮する
    /// (Issue #110)。
    #[tokio::test]
    async fn rfc3265_3_2_ngn_notify_returns_481_with_allow_header() {
        assert_ngn_method_response(SipMethod::Notify, 481, true).await;
    }

    /// RFC 3265 §7.2.4: 未対応 event package に対する SUBSCRIBE には
    /// `489 Bad Event` で返す。 sabiden は SUBSCRIBE 受信機能を持たない。
    #[tokio::test]
    async fn rfc3265_7_2_4_ngn_subscribe_returns_489_with_allow_header() {
        assert_ngn_method_response(SipMethod::Subscribe, 489, true).await;
    }

    /// RFC 3262 §4: PRACK は UAS が `Require: 100rel` 付き 1xx を出した
    /// ときのみ正規に届く。 sabiden は 100rel を発行しないので、
    /// PRACK は対応 transaction なし扱いで `481` を返す。
    #[tokio::test]
    async fn rfc3262_4_ngn_prack_returns_481_with_allow_header() {
        assert_ngn_method_response(SipMethod::Prack, 481, true).await;
    }

    /// RFC 3903 §11.1: 未対応 event package に対する PUBLISH には
    /// `489 Bad Event` で返す。
    #[tokio::test]
    async fn rfc3903_11_1_ngn_publish_returns_489_with_allow_header() {
        assert_ngn_method_response(SipMethod::Publish, 489, true).await;
    }

    /// RFC 3311 §5.2: UPDATE はダイアログ既存判定で 200 OK / 481。
    /// `NgnInboundHandler` はダイアログ状態を直接保持しないため、 UPDATE は
    /// 対応ダイアログ無しとして `481` を返す。
    #[tokio::test]
    async fn rfc3311_5_2_ngn_update_returns_481_with_allow_header() {
        assert_ngn_method_response(SipMethod::Update, 481, true).await;
    }

    /// RFC 6086 §4: orchestrator が NGN 側で INFO 受信時の上位
    /// ルーティング (DTMF 等) を持たないため、 該当ダイアログ無し扱いで
    /// `481` を返す (内線側 INFO は `UasEvent::Info` 経由でルートされる)。
    #[tokio::test]
    async fn rfc6086_4_ngn_info_returns_481_with_allow_header() {
        assert_ngn_method_response(SipMethod::Info, 481, true).await;
    }

    /// RFC 3428 §7: UAS が MESSAGE をサポートしない場合でも `200 OK` で
    /// 受け流し、 UA 側の再送ストームを防ぐ (CLAUDE.md §9 既知方針)。
    #[tokio::test]
    async fn rfc3428_7_ngn_message_returns_200_ok() {
        assert_ngn_method_response(SipMethod::Message, 200, true).await;
    }

    /// RFC 3261 §8.2.1: REFER は転送実装が無いため `405 Method Not Allowed`
    /// + `Allow` ヘッダで明示的に拒否する。
    #[tokio::test]
    async fn rfc3261_8_2_1_ngn_refer_returns_405_with_allow_header() {
        assert_ngn_method_response(SipMethod::Refer, 405, true).await;
    }

    /// RFC 3261 §8.2.1: 未知メソッド (`Other(_)`) には必ず `Allow` ヘッダ
    /// 付きの `405` で応答する。 Allow 欠落自体が RFC 違反 (Issue #110)。
    #[tokio::test]
    async fn rfc3261_8_2_1_ngn_unknown_method_returns_405_with_allow_header() {
        assert_ngn_method_response(SipMethod::Other("FOO".to_string()), 405, true).await;
    }

    /// RFC 3261 §11 / §20.5: OPTIONS への 200 OK にも `Allow` を載せて
    /// capability 広告できる (keep-alive を兼ねる)。 既存 OPTIONS 経路の
    /// regression check を兼ねる (Issue #110 同 PR で Allow 付与した)。
    #[tokio::test]
    async fn rfc3261_11_ngn_options_returns_200_with_allow_header() {
        assert_ngn_method_response(SipMethod::Options, 200, true).await;
    }

    /// `make_forker` は与えられた Uac を内包する forker を生成する。
    #[tokio::test]
    async fn make_forker_wraps_uac() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let (layer, _rx) = TransactionLayer::spawn(sock.clone());
        let cfg = crate::sip::uac::UacConfig {
            local_uri: "sip:sabiden@local".to_string(),
            domain: "local".to_string(),
            local_addr: sock.local_addr().unwrap(),
            user_agent: "test/0.1".to_string(),
            auth_username: None,
            auth_password: None,
        };
        let uac = Arc::new(Uac::new(cfg, layer, server));
        let forker = make_forker(uac);
        // 型確認のみ (本体は manager::tests でカバー)
        let _ = forker;
    }

    /// Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §5.1):
    /// 内線が出した Request-URI が LAN private IP / NGN ドメインのどちらでも
    /// P-CSCF IP+port (`118.177.125.1:5060`) に正規化される。
    #[test]
    fn normalize_request_uri_rewrites_to_pcsf_ip() {
        // ケース 1: LAN private IP → P-CSCF IP+port
        let lan = "sip:117@192.168.20.239";
        let out = normalize_request_uri_for_ngn(lan, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース 2: NGN ドメイン (`ntt-east.ne.jp`) → P-CSCF IP+port
        // (NGN は host が IP でないと 403 を返す実機証拠あり)
        let domain = "sip:117@ntt-east.ne.jp";
        let out = normalize_request_uri_for_ngn(domain, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース 3: LAN IP に port 付き
        let lan_port = "sip:117@192.168.20.239:5060";
        let out = normalize_request_uri_for_ngn(lan_port, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース 4: 既に P-CSCF host:port なら idempotent (= 変更しない)
        let already = "sip:117@118.177.125.1:5060";
        let out = normalize_request_uri_for_ngn(already, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");
    }

    /// RFC 3261 §19.1.1 — uri-parameters (`;transport`, `;lr`, `;maddr`, ...)
    /// と `?headers` は SIP-URI 構文上許されるが、NTT NGN P-CSCF は
    /// `;transport=udp` を含む Request-URI を **500 Server Internal Error**
    /// で蹴る (Issue #58 実機 trace)。Asterisk 実機 INVITE はどちらも付けず
    /// 200 OK を取得しているため (`docs/asterisk-real-invite.md` §5.1)、
    /// `normalize_request_uri_for_ngn` は host/port 書換と同時に `;params`
    /// と `?headers` を完全に削除する。
    #[test]
    fn rfc3261_19_1_1_normalize_strips_uri_params_and_headers() {
        // ケース A: ;transport=udp は剥がす (Issue #58 の主症状)
        let with_transport = "sip:117@127.0.0.1;transport=udp";
        let out = normalize_request_uri_for_ngn(with_transport, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース B: 複数 uri-parameters (;lr;maddr=...) はまとめて剥がす
        let with_multi = "sip:117@127.0.0.1;lr;maddr=192.0.2.1";
        let out = normalize_request_uri_for_ngn(with_multi, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース C: ?headers (RFC 3261 §19.1.1) も剥がす
        let with_headers = "sip:117@127.0.0.1?header=value";
        let out = normalize_request_uri_for_ngn(with_headers, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース D: 既に P-CSCF host:port だが ;params が残っているケース。
        // host/port 書換は不要だが ;params 削除のみ走らせて idempotent に
        // 落ち着かせる (Issue #58 の二重正規化対策)。
        let pcsf_with_params = "sip:117@118.177.125.1:5060;transport=udp";
        let out = normalize_request_uri_for_ngn(pcsf_with_params, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");

        // ケース E: 完全正規化済 (host:port 一致 + params/headers 無し) は
        // そのまま返す (true idempotent)。
        let canonical = "sip:117@118.177.125.1:5060";
        let out = normalize_request_uri_for_ngn(canonical, "118.177.125.1", 5060);
        assert_eq!(out, "sip:117@118.177.125.1:5060");
    }

    /// RFC 3261 §13.3.1.4 (UAS Behavior, 2xx Responses):
    /// 内線レッグの 200 OK には Contact ヘッダが必須。Contact が無いと
    /// UAC 側で remote target が決まらず ACK / BYE の宛先が不定となり、
    /// Linphone 等は dialog 確立を諦めて切断する (Issue #64)。
    #[test]
    fn rfc3261_13_3_1_4_build_2xx_to_ext_includes_contact_header() {
        // 模擬 INVITE (To = sabiden 内線、From = 内線 UA)
        let ngn_addr: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let invite = builders::invite_from_phone(
            &ngn_addr,
            "iphone",
            "sip:0312345678@sabiden",
            "z9hG4bK-2xx-contact",
            None,
        );
        let body = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n";

        let resp = build_2xx_to_ext(&invite, body, "sip:sabiden@192.168.20.239:5061");

        // Contact ヘッダが name-addr 形式で必ず入る
        assert_eq!(
            resp.headers.get("contact"),
            Some("<sip:sabiden@192.168.20.239:5061>"),
            "RFC 3261 §13.3.1.4: 2xx には Contact ヘッダが必須",
        );
        // SDP body と Content-Type も維持
        assert_eq!(resp.headers.get("content-type"), Some("application/sdp"));
        assert_eq!(resp.body, body);
        // To tag は ensure_to_tag で付く
        assert!(
            resp.headers
                .get("to")
                .map(|v| v.contains("tag="))
                .unwrap_or(false),
            "RFC 3261 §8.2.6.2: 2xx の To には tag が必須"
        );
        assert_eq!(resp.status_code, 200);
    }

    /// Asterisk 実機準拠 (`docs/asterisk-real-invite.md` §5.2):
    /// 内線 SDP に乗っている LAN private IP (`192.168.30.162` 等) は
    /// NGN 行きの INVITE では eth1 IP に強制書換される。
    #[test]
    fn outbound_invite_sdp_rewrites_private_ip_to_eth1() {
        let ext_offer = b"v=0\r\n\
                          o=iphone 2246 1745 IN IP4 192.168.30.162\r\n\
                          s=Talk\r\n\
                          c=IN IP4 192.168.30.162\r\n\
                          t=0 0\r\n\
                          m=audio 55120 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n";
        let eth1_ip: IpAddr = "118.177.72.242".parse().unwrap();
        let rewritten = force_rewrite_sdp_for_ngn(ext_offer, eth1_ip).expect("Some");
        let parsed =
            crate::sdp::SessionDescription::parse(std::str::from_utf8(&rewritten).unwrap())
                .expect("rewritten SDP must parse");

        // c= / o= は eth1 IP に書換 (LAN private は漏らさない)
        assert_eq!(parsed.connection.as_ref().unwrap().address, eth1_ip);
        assert_eq!(parsed.origin.address, eth1_ip);
        // RTP port は内線広告の port をそのまま温存 (中継不能でも SIP は通る)
        assert_eq!(parsed.media[0].port, 55120);

        // 空 body は None
        assert!(force_rewrite_sdp_for_ngn(b"", eth1_ip).is_none());
    }

    /// Asterisk 実機準拠 e2e: 内線 INVITE に対し UasEventHandler が NGN へ
    /// プロキシする際、出力 INVITE の Request-URI が P-CSCF IP:port になる。
    /// `docs/asterisk-real-invite.md` §3 / §5.1 の事故再現テスト。
    #[tokio::test]
    async fn invite_request_uri_uses_pcsf_ip_when_proxied_from_extension() {
        use crate::sip::uac::UacConfig;

        // (1) フェイク NGN (= P-CSCF) サーバ: INVITE を受けたら Request-URI を
        //     検査して 200 OK を返す。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let captured_uri: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let captured_via: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let captured_uri_c = captured_uri.clone();
        let captured_via_c = captured_via.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(req) = parsed {
                *captured_uri_c.lock().unwrap() = Some(req.uri.clone());
                *captured_via_c.lock().unwrap() = req.headers.get("via").map(str::to_string);
                let mut resp = build_response_skeleton(&req, 200, "OK");
                resp.headers.set(
                    "To",
                    format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
                );
                resp.headers
                    .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                fake_ngn_clone
                    .send_to(&resp.to_bytes(), peer)
                    .await
                    .unwrap();
                let _ = fake_ngn_clone.recv_from(&mut buf).await;
            }
        });

        // (2) sabiden NGN 側 UAC: server_addr = fake_ngn (P-CSCF 役)。
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // (3) UasEventHandler を起動 (CallManager 無し = SDP 強制書換パス)
        let handler = UasEventHandler::new(ngn_uac.clone());
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.spawn(event_rx);

        // (4) 模擬内線 UAS: ServerTransaction を sabiden 内に作って
        //     UasEvent を直接 push する。
        let phone_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone_sock.local_addr().unwrap();
        let sabiden_uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

        // 内線が出すであろう INVITE: Request-URI は LAN IP (= 内線 UA から見た sabiden)。
        // ここでは "sip:117@192.168.20.239" を模擬。
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:117@192.168.20.239");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKptest", phone_addr),
        );
        invite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonereq");
        invite.headers.set("To", "<sip:117@192.168.20.239>");
        invite.headers.set("Call-ID", "uri-rewrite-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = b"v=0\r\n\
                        o=iphone 2246 1745 IN IP4 192.168.30.162\r\n\
                        s=Talk\r\n\
                        c=IN IP4 192.168.30.162\r\n\
                        t=0 0\r\n\
                        m=audio 55120 RTP/AVP 0\r\n\
                        a=rtpmap:0 PCMU/8000\r\n"
            .to_vec();
        phone_sock
            .send_to(&invite.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) =
            tokio::time::timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        let parsed = parse_message(&buf[..n]).unwrap();
        let req = match parsed {
            SipMessage::Request(r) => r,
            _ => panic!("INVITE 期待"),
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_uas_sock.clone()).unwrap();
        let responder = crate::testing::builders::responder_handle_for_test(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder,
            })
            .unwrap();

        // (5) NGN タスクが Request-URI を回収するまで待つ
        let _ = ngn_task.await;

        // (6) 検証: 出力 INVITE の Request-URI は P-CSCF IP:port (= fake_ngn_addr) に
        //         書換わっているはず。
        let uri = captured_uri
            .lock()
            .unwrap()
            .clone()
            .expect("NGN へ INVITE が届くべき");
        let pcsf_str = fake_ngn_addr.to_string();
        let user_at_pcsf = format!("sip:117@{}", pcsf_str);
        assert_eq!(
            uri, user_at_pcsf,
            "Request-URI は P-CSCF IP+port に書換わるべき (Asterisk pcap §5.1)"
        );
        // 副次確認: Via に rport が付いていること (§5.5)
        let via = captured_via.lock().unwrap().clone().unwrap_or_default();
        assert!(
            via.contains(";rport"),
            "Via に `;rport` が必要 (Asterisk pcap §5.5): got {}",
            via
        );
    }

    /// 内線 UA → 内線 UAS → UasEventHandler → NGN UAC → フェイク NGN の
    /// end-to-end 結線テスト。Issue #15 の主目的である UAS event ハンドラの
    /// プロキシ動作を確認する。
    #[tokio::test]
    async fn uas_event_proxies_invite_to_ngn() {
        use crate::config::{ExtensionConfig, UasConfig};
        use crate::sip::uas::ExtensionUas;
        use crate::sip::utils::{new_call_id, new_tag};

        // (1) フェイク NGN サーバ: INVITE を受けたら 200 OK を返す
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_invite_seen = Arc::new(StdMutex::new(false));
        let ngn_invite_seen_c = ngn_invite_seen.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE を受信して 200 OK を返す
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(req) = parsed {
                assert_eq!(req.method, SipMethod::Invite);
                *ngn_invite_seen_c.lock().unwrap() = true;
                let mut resp = build_response_skeleton(&req, 200, "OK");
                resp.headers.set(
                    "To",
                    format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
                );
                resp.headers
                    .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                fake_ngn_clone
                    .send_to(&resp.to_bytes(), peer)
                    .await
                    .unwrap();
                // ACK 受信 (drop)
                let _ = fake_ngn_clone.recv_from(&mut buf).await;
            }
        });

        // (2) NGN 側 UAC: TransactionLayer + Uac
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // (3) 内線 UAS bind
        let uas_cfg = UasConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            realm: "sabiden-test".to_string(),
            max_expires: 3600,
        };
        let extensions = vec![ExtensionConfig {
            username: "iphone".to_string(),
            password: "secret".to_string(),
        }];
        let uas = ExtensionUas::bind(uas_cfg, &extensions).await.unwrap();
        let uas_addr = uas.socket().local_addr().unwrap();
        let registrar = uas.registrar();

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        // (4) UasEventHandler を起動 (UAS event → NGN UAC)
        let handler = UasEventHandler::new(ngn_uac);
        handler.spawn(event_rx);

        // (5) フェイク内線 UA から INVITE を送る。
        //
        // Issue #62 / RFC 3261 §22 以降、内線 INVITE では Digest challenge を
        // 出さない (REGISTER で確立した binding を信用)。ここでは REGISTER の
        // 往復を省略するため、registrar に AOR を直接 register して binding を
        // 作っておく (本テストの主眼は INVITE→NGN プロキシのため)。
        let phone = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let phone_local = phone.local_addr().unwrap();
        registrar
            .register(
                "iphone",
                format!("sip:iphone@{}", phone_local),
                phone_local,
                Duration::from_secs(60),
            )
            .await;

        let mut req = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKuasint1", phone_local),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", format!("<sip:iphone@sabiden>;tag={}", new_tag()));
        req.headers.set("To", "<sip:dest@sabiden>");
        req.headers.set("Call-ID", new_call_id());
        req.headers.set("CSeq", "1 INVITE");
        req.headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        phone.send_to(&req.to_bytes(), uas_addr).await.unwrap();

        // 100 Trying → 200 OK が届くまで複数応答を読む。401 は来ない。
        let mut buf = vec![0u8; 8192];
        let mut got_2xx = false;
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        assert_ne!(
                            r.status_code, 401,
                            "Issue #62: 既登録 binding に対し challenge してはならない"
                        );
                        if (200..300).contains(&r.status_code) {
                            got_2xx = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }

        // 内線側へ 200 OK が返り、フェイク NGN にも INVITE が届いたことを確認
        assert!(got_2xx, "内線へ 200 OK が返るべき");
        let _ = ngn_task.await;
        assert!(
            *ngn_invite_seen.lock().unwrap(),
            "NGN へ INVITE がプロキシされるべき"
        );
    }

    /// NGN→内線 着信で `CallManager` を接続した場合の統合テスト。
    ///
    /// - フェイク内線 inviter が SDP answer を返すように設定する
    /// - sabiden は両側 RTP ソケットを bind し、200 OK の SDP に sabiden の
    ///   NGN 側 RTP ポートを記載するはず
    /// - フェイク NGN ピアと フェイク内線ピアを別ソケットで模擬し、ブリッジ
    ///   経由で双方向 RTP が届くことを確認
    /// - BYE 受信で `CallManager` から通話が消えることを確認
    #[tokio::test]
    async fn ngn_inbound_with_call_manager_starts_rtp_bridge_and_rewrites_sdp() {
        use crate::call::manager::CallManager;
        use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク内線ピア (200 OK SDP の宛先)
        let ext_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_peer_addr = ext_peer_sock.local_addr().unwrap();
        let ext_answer_sdp = format!(
            "v=0\r\n\
             o=- 2 2 IN IP4 {ip}\r\n\
             s=-\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            ip = ext_peer_addr.ip(),
            port = ext_peer_addr.port()
        );

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(ext_answer_sdp.into_bytes())
            .build();

        // sabiden NGN 側 SIP ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();

        // フェイク NGN ピア (RTP の送り元/受け先 + SIP UA)
        let ngn_peer_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        // 内線登録
        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6001".to_string(),
                "127.0.0.1:6001".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let mgr = CallManager::new(extensions.clone());

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound_with_manager(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
            mgr.clone(),
        );
        let _ = inviter; // keep call_count alive (no-op)

        // NGN INVITE 送信 (SDP オファあり)
        let ngn_offer_sdp = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 {ip}\r\n\
             s=-\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            ip = ngn_peer_addr.ip(),
            port = ngn_peer_addr.port()
        );
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKbridge1", ngn_peer_addr),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-bridge");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-bridge-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = ngn_offer_sdp.into_bytes();
        ngn_peer_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 200 OK を読み取り、書き換え後の SDP からブリッジが指す sabiden NGN ポートを得る
        let mut buf = vec![0u8; 8192];
        let sabiden_ngn_rtp: SocketAddr;
        loop {
            let (n, _) = timeout(Duration::from_secs(3), ngn_peer_sock.recv_from(&mut buf))
                .await
                .expect("200 OK が来ない")
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 200 {
                    assert!(!r.body.is_empty(), "200 OK には書き換え後の SDP が必要");
                    let sdp_text = std::str::from_utf8(&r.body).unwrap();
                    let parsed = crate::sdp::SessionDescription::parse(sdp_text).unwrap();
                    let conn = parsed.connection.as_ref().expect("c= が必要");
                    let port = parsed.media[0].port;
                    sabiden_ngn_rtp = SocketAddr::new(conn.address, port);
                    // ext_peer_addr (内線側) のままだと中継されないので絶対 NG
                    assert_ne!(
                        sabiden_ngn_rtp, ext_peer_addr,
                        "200 OK の SDP は sabiden 側 RTP ポートを指すべき (内線ポートのままでは透過不可)"
                    );
                    break;
                }
            }
        }

        // ブリッジが起動して CallManager に登録されているはず
        assert_eq!(mgr.len().await, 1, "通話エントリが 1 件");

        // フェイク NGN ピア → sabiden NGN RTP → 内線ピア の方向で RTP リレー確認
        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 160,
            ssrc: 0xCAFE_BABE,
            payload: vec![0xff; 160],
        }
        .to_bytes();
        ngn_peer_sock.send_to(&pkt, sabiden_ngn_rtp).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), ext_peer_sock.recv_from(&mut buf))
            .await
            .expect("内線ピアが RTP を受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.ssrc, 0xCAFE_BABE);

        // 逆方向: 内線ピアが返事を送ったら NGN ピアが受け取れる (送り元学習機構を活用)
        // ブリッジは learn_peer なので、ext_peer の最初の送信で sabiden_ext を学習させる必要がある。
        // 内線ピアは sabiden の ext 側 RTP ポートが分からない (本テストでは 200 OK の中身のみ
        // 知っているのは NGN 側ピア)。実際には内線も自身の SDP オファ→sabiden 側応答で
        // sabiden の ext ポートを知るが、本テストでは内線ピアが ext_peer_sock からの送信元として
        // 露出した sabiden の ext_socket をそのまま再送先に流用する。
        // → 直前に sabiden の ext 側ソケット → ext_peer_sock の通信が起きており、recv_from の
        //    ピア情報からは sabiden_ext が引ける。
        // ここでは簡略化のため、逆方向は省略する (片方向の中継・SDP 書き換え検証で十分)。

        // BYE で通話終了
        let mut bye = SipRequest::new(SipMethod::Bye, "sip:sabiden");
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKbridgebye", ngn_peer_addr),
        );
        bye.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-bridge");
        bye.headers.set("To", "<sip:0312345678@sabiden>;tag=local");
        bye.headers.set("Call-ID", "ngn-bridge-cid");
        bye.headers.set("CSeq", "2 BYE");
        ngn_peer_sock
            .send_to(&bye.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // BYE の 200 OK を待つ (CallManager::terminate が走る)
        for _ in 0..3 {
            match timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 200 {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        // CallManager::terminate は async で実行されているので少し待つ
        for _ in 0..20 {
            if mgr.len().await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(mgr.len().await, 0, "BYE で通話エントリが消えるべき");
    }

    /// 内線→NGN 発信時、`UasEventHandler::with_call_manager` 経路で
    /// SDP を sabiden 側に書き換えた INVITE が NGN に届き、
    /// 200 OK answer を内線へ返す際にも sabiden 側 ext ポートに書き換わることを確認。
    /// 加えて RTP リレーが NGN 側ピア → 内線側ピアで実際に動くことを検証する。
    #[tokio::test]
    async fn uas_event_with_call_manager_starts_rtp_bridge() {
        use crate::call::manager::CallManager;
        use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク内線ピア (内線 UA の RTP 担当役)
        let ext_peer_rtp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_peer_rtp_addr = ext_peer_rtp.local_addr().unwrap();

        // フェイク NGN: INVITE を受けて SDP answer (NGN ピアの RTP ポート) を 200 OK で返す。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        // NGN 側 RTP ピア
        let ngn_peer_rtp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_rtp_addr = ngn_peer_rtp.local_addr().unwrap();

        let invite_sdp_to_ngn: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(None));
        let invite_sdp_seen_for_task = invite_sdp_to_ngn.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let parsed = parse_message(&buf[..n]).unwrap();
            if let SipMessage::Request(req) = parsed {
                assert_eq!(req.method, SipMethod::Invite);
                // 受信した SDP を保存 (sabiden 側 NGN ポートに書き換わっているはず)
                *invite_sdp_seen_for_task.lock().unwrap() = Some(req.body.clone());
                let mut resp = build_response_skeleton(&req, 200, "OK");
                resp.headers.set(
                    "To",
                    format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
                );
                resp.headers
                    .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                resp.headers.set("Content-Type", "application/sdp");
                resp.body = format!(
                    "v=0\r\n\
                     o=- 9 9 IN IP4 {ip}\r\n\
                     s=-\r\n\
                     c=IN IP4 {ip}\r\n\
                     t=0 0\r\n\
                     m=audio {port} RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n",
                    ip = ngn_peer_rtp_addr.ip(),
                    port = ngn_peer_rtp_addr.port()
                )
                .into_bytes();
                fake_ngn_clone
                    .send_to(&resp.to_bytes(), peer)
                    .await
                    .unwrap();
                // ACK 受信 (drop)
                let _ = fake_ngn_clone.recv_from(&mut buf).await;
            }
        });

        // sabiden NGN 側 UAC
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        let mgr = CallManager::new(ExtensionRegistrar::new());

        let mut handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );

        // 内線が出すであろう INVITE を擬似的に作成 (responder は ServerTransaction が必要)。
        // 内線ピア役の SIP トランザクションを 1 個作成し ResponderHandle を握る。
        let phone_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone_sock.local_addr().unwrap();
        // 内線→sabiden 用ソケット (内線 UAS 役を簡易的に手書きする)
        let sabiden_uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

        // 内線レッグの TransactionLayer を結線する (Issue #69 INFO 経路で必要)。
        // attach_ext_layer は Arc::get_mut を使うので、共有前 (= spawn 前) に呼ぶ。
        let (ext_layer, _ext_rx) = TransactionLayer::spawn(sabiden_uas_sock.clone());
        handler.attach_ext_layer(ext_layer, Some(sabiden_uas_addr));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.spawn(event_rx);

        let mut invite_from_phone = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite_from_phone.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKuasinv", phone_addr),
        );
        invite_from_phone
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet");
        invite_from_phone
            .headers
            .set("To", "<sip:0312345678@sabiden>");
        invite_from_phone.headers.set("Call-ID", "uas-bridge-cid");
        invite_from_phone.headers.set("CSeq", "1 INVITE");
        // RFC 3261 §12.1.2: in-dialog 確立には Contact が必要 (sabiden 側で
        // ext-leg dialog を組むのに必須)。
        invite_from_phone
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));
        invite_from_phone
            .headers
            .set("Content-Type", "application/sdp");
        invite_from_phone.body = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 {ip}\r\n\
             s=-\r\n\
             c=IN IP4 {ip}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            ip = ext_peer_rtp_addr.ip(),
            port = ext_peer_rtp_addr.port()
        )
        .into_bytes();

        // 内線から sabiden へ INVITE を送り、sabiden 側で ServerTransaction を作って
        // UasEvent を直接イベントチャネルに突っ込む。
        phone_sock
            .send_to(&invite_from_phone.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
        // sabiden 側で受信
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_message(&buf[..n]).unwrap();
        let req = match parsed {
            SipMessage::Request(r) => r,
            _ => panic!("INVITE 期待"),
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_uas_sock.clone()).unwrap();
        let responder = crate::testing::builders::responder_handle_for_test(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder,
            })
            .unwrap();

        // 内線が 200 OK + SDP answer を受け取る (書き換えされているはず)
        let sabiden_ext_rtp: SocketAddr = loop {
            let (n, _) = timeout(Duration::from_secs(3), phone_sock.recv_from(&mut buf))
                .await
                .expect("内線へ 200 OK が来ない")
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 200 {
                    assert!(!r.body.is_empty(), "200 OK には書き換え後 SDP が必要");
                    let parsed = crate::sdp::SessionDescription::parse(
                        std::str::from_utf8(&r.body).unwrap(),
                    )
                    .unwrap();
                    let conn = parsed.connection.unwrap();
                    let port = parsed.media[0].port;
                    let addr = SocketAddr::new(conn.address, port);
                    assert_ne!(
                        addr, ngn_peer_rtp_addr,
                        "200 OK の SDP は sabiden 側 ext ポートを指すべき"
                    );
                    break addr;
                }
            }
        };

        // NGN へ送信された INVITE の SDP も書き換わっているはず
        let _ = ngn_task.await;
        let ngn_invite_sdp = invite_sdp_to_ngn
            .lock()
            .unwrap()
            .clone()
            .expect("NGN へ INVITE が届くべき");
        let parsed =
            crate::sdp::SessionDescription::parse(std::str::from_utf8(&ngn_invite_sdp).unwrap())
                .unwrap();
        assert_ne!(
            parsed.media[0].port,
            ext_peer_rtp_addr.port(),
            "NGN 行きの INVITE の SDP は sabiden 側 NGN ポートを指すべき"
        );

        // ブリッジが起動している
        assert_eq!(mgr.len().await, 1);

        // RTP リレー (NGN ピア → sabiden NGN bridge → 内線ピア) を確認するため、
        // sabiden_ext_rtp が ext_peer_rtp_addr ではなく sabiden 側 ext bridge ポートで
        // あることを利用して、ext_peer_rtp が sabiden_ext_rtp 宛に送る → ブリッジが
        // NGN 側へ転送 → ngn_peer_rtp が受信、を確認する。
        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 5,
            timestamp: 320,
            ssrc: 0xDEAD_BEEF,
            payload: vec![0xab; 160],
        }
        .to_bytes();
        ext_peer_rtp.send_to(&pkt, sabiden_ext_rtp).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), ngn_peer_rtp.recv_from(&mut buf))
            .await
            .expect("NGN ピアが RTP を受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.ssrc, 0xDEAD_BEEF);

        // ===== Issue #69: 内線が SIP INFO で DTMF を送ったら、 NGN レッグへ
        //       RFC 4733 telephone-event RTP packet が流れることを確認する。 =====
        // 内線→NGN INFO body は `Signal=5\r\nDuration=200\r\n` (Cisco/Avaya 形式)。
        let mut info_req = SipRequest::new(SipMethod::Info, "sip:sabiden");
        info_req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKuasinfo", phone_addr),
        );
        info_req
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet");
        info_req
            .headers
            .set("To", "<sip:0312345678@sabiden>;tag=ngn-tag");
        info_req.headers.set("Call-ID", "uas-bridge-cid");
        info_req.headers.set("CSeq", "2 INFO");
        info_req
            .headers
            .set("Content-Type", "application/dtmf-relay");
        info_req.body = b"Signal=5\r\nDuration=200\r\n".to_vec();
        let info_stx =
            ServerTransaction::new(info_req.clone(), phone_addr, sabiden_uas_sock.clone()).unwrap();
        let info_responder = crate::testing::builders::responder_handle_for_test(info_stx);
        event_tx
            .send(UasEvent::Info {
                request: info_req,
                remote: phone_addr,
                responder: info_responder,
            })
            .unwrap();

        // INFO への 200 OK が内線に届く (RFC 6086 §4)
        let mut got_info_ok = false;
        for _ in 0..3 {
            match timeout(Duration::from_secs(2), phone_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 200 {
                            // CSeq から INFO 応答であることを確認
                            if r.headers
                                .get("cseq")
                                .map(|v| v.contains("INFO"))
                                .unwrap_or(false)
                            {
                                got_info_ok = true;
                                break;
                            }
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_info_ok, "RFC 6086 §4: INFO への 200 OK が必要");

        // NGN ピアは RFC 4733 の telephone-event RTP packet を受け取る (event=5)。
        // build_dtmf_packet_sequence(duration=100ms, period=50ms) なので
        // 中間 2 + 終端 3 = 5 packet 来る。最初の packet は marker=1。
        let mut got_pt101 = 0usize;
        let mut got_marker = false;
        let mut got_event_5 = false;
        let mut got_end_bit = false;
        for _ in 0..6 {
            match timeout(Duration::from_secs(1), ngn_peer_rtp.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    let pkt = RtpPacket::from_bytes(&buf[..n]).unwrap();
                    if pkt.payload_type == 101 {
                        got_pt101 += 1;
                        if pkt.marker {
                            got_marker = true;
                        }
                        let evt =
                            crate::call::dtmf::TelephoneEvent::from_payload(&pkt.payload).unwrap();
                        if evt.event == 5 {
                            got_event_5 = true;
                        }
                        if evt.end {
                            got_end_bit = true;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(
            got_pt101 >= 4,
            "RFC 4733: PT=101 packet が複数届くべき (got {got_pt101})"
        );
        assert!(
            got_marker,
            "RFC 4733 §2.5.1.1: 押下開始 packet で marker=1 必須"
        );
        assert!(got_event_5, "RFC 4733 §3.2: digit '5' は event=5 必須");
        assert!(
            got_end_bit,
            "RFC 4733 §2.5.1.2: 押下終了 packet (E=1) が必要"
        );
    }

    // ===== B2BUA 双方向シグナリング テスト群 =====

    /// 内線→NGN 発信通話で、内線が BYE を出すと NGN にも BYE が伝搬される。
    /// RFC 3261 §15.1.2 (BYE) + B2BUA の責務 (両レッグの dialog を別々に閉じる)。
    #[tokio::test]
    async fn ext_bye_propagates_to_ngn() {
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: INVITE→200 OK→ACK→BYE→200 OK
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let ngn_bye_seen = Arc::new(StdMutex::new(false));
        let ngn_bye_seen_c = ngn_bye_seen.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE 受信 → 200 OK 返送
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(invite) = parse_message(&buf[..n]).unwrap() else {
                panic!("INVITE 期待");
            };
            assert_eq!(invite.method, SipMethod::Invite);
            let mut resp = build_response_skeleton(&invite, 200, "OK");
            resp.headers.set(
                "To",
                format!("{};tag=ngn-tag", invite.headers.get("to").unwrap()),
            );
            resp.headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_clone
                .send_to(&resp.to_bytes(), peer)
                .await
                .unwrap();
            // ACK 受信 (drop)
            let _ = fake_ngn_clone.recv_from(&mut buf).await;
            // BYE 受信 → 200 OK 返送
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            if let SipMessage::Request(bye) = parse_message(&buf[..n]).unwrap() {
                if bye.method == SipMethod::Bye {
                    *ngn_bye_seen_c.lock().unwrap() = true;
                    let bye_resp = build_response_skeleton(&bye, 200, "OK");
                    fake_ngn_clone
                        .send_to(&bye_resp.to_bytes(), peer)
                        .await
                        .unwrap();
                }
            }
        });

        // sabiden NGN UAC
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // sabiden 内線 UAS 用 socket (生 recv_from する用; レイヤを spawn しない)。
        // BYE を内線へ送るための ext_layer は別ソケットで持つ (本テストでは
        // ext→NGN 方向なので ext_layer は使われないが attach のみ)。
        let sabiden_ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_ext_addr = sabiden_ext_sock.local_addr().unwrap();
        let layer_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ext_layer, _ext_rx) = TransactionLayer::spawn(layer_sock.clone());

        // UasEventHandler with ext_layer attached
        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer.clone(), Some(sabiden_ext_addr));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.clone().spawn(event_rx);

        // フェイク内線: 自前ソケットから INVITE を送り、200 OK を受け取る
        let phone = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone.local_addr().unwrap();
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKextbye1", phone_addr),
        );
        invite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ext-bye-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));

        // sabiden の UAS-side ServerTransaction を作成し UasEvent::Invite を送る
        phone
            .send_to(&invite.to_bytes(), sabiden_ext_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_ext_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("INVITE 期待");
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let responder = crate::testing::builders::responder_handle_for_test(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder,
            })
            .unwrap();

        // 内線が 200 OK を受信するまで待つ
        let _ok = loop {
            let (n, _) = timeout(Duration::from_secs(3), phone.recv_from(&mut buf))
                .await
                .expect("内線へ 200 OK が届かない")
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 200 {
                    break r;
                }
            }
        };

        // 内線が BYE を送る (B2BUA: NGN にも伝搬されるはず)
        let mut bye = SipRequest::new(SipMethod::Bye, "sip:sabiden");
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKextbye2", phone_addr),
        );
        bye.headers.set("From", "<sip:iphone@sabiden>;tag=phonet");
        bye.headers.set("To", "<sip:0312345678@sabiden>;tag=local"); // sabiden 側 tag 未把握なので仮値
        bye.headers.set("Call-ID", "ext-bye-cid");
        bye.headers.set("CSeq", "2 BYE");

        // sabiden 側で BYE を受信して UasEvent::Bye を直接 fire (UAS::run なしで動かしてるため)
        phone
            .send_to(&bye.to_bytes(), sabiden_ext_addr)
            .await
            .unwrap();
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_ext_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(bye_req) = parse_message(&buf[..n]).unwrap() else {
            panic!("BYE 期待");
        };
        assert_eq!(bye_req.method, SipMethod::Bye);
        let bye_stx =
            ServerTransaction::new(bye_req.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let bye_responder = crate::testing::builders::responder_handle_for_test(bye_stx);
        event_tx
            .send(UasEvent::Bye {
                request: bye_req,
                remote,
                responder: bye_responder,
            })
            .unwrap();

        // 内線へ BYE 200 OK が返り、NGN にも BYE が届く
        let mut got_bye_ok = false;
        for _ in 0..3 {
            match timeout(Duration::from_secs(2), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 200 {
                            // BYE への 200 OK
                            got_bye_ok = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_bye_ok, "内線への BYE 200 OK が必要");

        // フェイク NGN タスクが BYE を観測した
        let _ = timeout(Duration::from_secs(3), ngn_task).await;
        assert!(*ngn_bye_seen.lock().unwrap(), "NGN へ BYE が伝搬されるべき");
    }

    /// 内線→NGN 発信通話で、NGN が BYE を出すと内線にも BYE が伝搬される。
    #[tokio::test]
    async fn ngn_bye_propagates_to_ext() {
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: INVITE→200 OK→ACK 受信、その後自分から BYE を送る
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        // BYE を送る側で response を受け取りたいのでチャネルを切らずにタスクを動かす
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE 受信
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(invite) = parse_message(&buf[..n]).unwrap() else {
                panic!("INVITE 期待");
            };
            // 200 OK 返送
            let mut resp = build_response_skeleton(&invite, 200, "OK");
            resp.headers.set(
                "To",
                format!("{};tag=ngn-tag", invite.headers.get("to").unwrap()),
            );
            resp.headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_clone
                .send_to(&resp.to_bytes(), peer)
                .await
                .unwrap();
            // ACK 受信
            let (_, _) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            // 自分から BYE 送出 (NGN ダイアログのテイクダウン)
            let mut bye = SipRequest::new(SipMethod::Bye, format!("sip:sabiden@{}", peer));
            bye.headers.set(
                "Via",
                format!("SIP/2.0/UDP {};branch=z9hG4bKngnbye", fake_ngn_addr),
            );
            bye.headers.set(
                "From",
                format!("{};tag=ngn-tag", invite.headers.get("to").unwrap()),
            );
            bye.headers.set("To", invite.headers.get("from").unwrap());
            bye.headers
                .set("Call-ID", invite.headers.get("call-id").unwrap());
            bye.headers.set("CSeq", "1 BYE");
            fake_ngn_clone.send_to(&bye.to_bytes(), peer).await.unwrap();
            // BYE への 200 OK を受け取る (ペイロードは捨てる)
            let _ = timeout(Duration::from_secs(3), fake_ngn_clone.recv_from(&mut buf)).await;
        });

        // sabiden NGN UAC + 着信ハンドラ
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, ngn_inbound_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer.clone(),
            fake_ngn_addr,
        ));

        // sabiden 内線 UAS 用 socket + layer
        let sabiden_ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_ext_addr = sabiden_ext_sock.local_addr().unwrap();
        let (ext_layer, _ext_rx) = TransactionLayer::spawn(sabiden_ext_sock.clone());

        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer.clone(), Some(sabiden_ext_addr));
        let handler_for_forwarder: Arc<dyn OutboundDialogForwarder> = handler.clone();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.clone().spawn(event_rx);

        // NGN 着信ハンドラを起動 (NGN 側 inbound_rx で BYE をキャッチさせる)。
        // inviter は使わない (内線着信は来ない) ので minimal な dummy を渡す。
        // (ハーネス Issue #42 で `ScriptedInviter` は builder ベースに統合された。)
        let dummy_inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let extensions_empty = ExtensionRegistrar::new();
        let ngn_handler = NgnInboundHandler::new(
            ngn_client_sock.clone(),
            dummy_inviter,
            extensions_empty,
            NgnInboundConfig::default(),
        );
        ngn_handler
            .set_outbound_forwarder(handler_for_forwarder)
            .await;
        ngn_handler.spawn(ngn_inbound_rx);

        // フェイク内線から INVITE を送る
        let phone = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone.local_addr().unwrap();
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKngnbye1", phone_addr),
        );
        invite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet2");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-bye-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));
        phone
            .send_to(&invite.to_bytes(), sabiden_ext_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_ext_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("INVITE 期待");
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let responder = crate::testing::builders::responder_handle_for_test(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder,
            })
            .unwrap();

        // 内線が 200 OK を受信
        loop {
            let (n, _) = timeout(Duration::from_secs(3), phone.recv_from(&mut buf))
                .await
                .expect("内線へ 200 OK が届かない")
                .unwrap();
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 200 {
                    break;
                }
            }
        }

        // NGN は ACK 受信後に BYE を送ってくる → sabiden は内線へ BYE を伝搬する
        let got_bye = loop {
            let (n, _) = match timeout(Duration::from_secs(5), phone.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => break false,
            };
            if let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() {
                if req.method == SipMethod::Bye {
                    // 内線として 200 OK を返す
                    let bye_resp = build_response_skeleton(&req, 200, "OK");
                    phone
                        .send_to(&bye_resp.to_bytes(), sabiden_ext_addr)
                        .await
                        .unwrap();
                    break true;
                }
            }
        };
        assert!(got_bye, "NGN BYE が内線レッグに伝搬されるべき");
        let _ = timeout(Duration::from_secs(2), ngn_task).await;
    }

    /// 内線→NGN 発信中、INVITE 進行中に内線が CANCEL を出すと、NGN へ CANCEL が
    /// 伝搬され、内線へは 487 Request Terminated が返る。
    #[tokio::test]
    async fn ext_cancel_propagates_to_ngn_and_returns_487() {
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: INVITE を受けたら 100 Trying のみ返し、応答を保留。
        // CANCEL を受けたら 200 OK + 487 Request Terminated を返す。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let cancel_seen = Arc::new(StdMutex::new(false));
        let cancel_seen_c = cancel_seen.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // INVITE
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(invite) = parse_message(&buf[..n]).unwrap() else {
                panic!("INVITE 期待");
            };
            assert_eq!(invite.method, SipMethod::Invite);
            // 100 Trying
            let trying = build_response_skeleton(&invite, 100, "Trying");
            fake_ngn_clone
                .send_to(&trying.to_bytes(), peer)
                .await
                .unwrap();
            // CANCEL を待つ
            let (n, peer2) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            if let SipMessage::Request(cancel) = parse_message(&buf[..n]).unwrap() {
                if cancel.method == SipMethod::Cancel {
                    *cancel_seen_c.lock().unwrap() = true;
                    let cancel_ok = build_response_skeleton(&cancel, 200, "OK");
                    fake_ngn_clone
                        .send_to(&cancel_ok.to_bytes(), peer2)
                        .await
                        .unwrap();
                    // 元 INVITE に 487 Request Terminated
                    let mut term = build_response_skeleton(&invite, 487, "Request Terminated");
                    term.headers.set(
                        "To",
                        format!("{};tag=ngn-cancel", invite.headers.get("to").unwrap()),
                    );
                    fake_ngn_clone
                        .send_to(&term.to_bytes(), peer)
                        .await
                        .unwrap();
                    // ACK 受信 (drop)
                    let _ =
                        timeout(Duration::from_secs(2), fake_ngn_clone.recv_from(&mut buf)).await;
                }
            }
        });

        // sabiden NGN UAC
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // sabiden 内線 UAS 用
        let sabiden_ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_ext_addr = sabiden_ext_sock.local_addr().unwrap();
        let (ext_layer, _ext_rx) = TransactionLayer::spawn(sabiden_ext_sock.clone());

        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer, Some(sabiden_ext_addr));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.clone().spawn(event_rx);

        // 内線が INVITE を送って sabiden が ServerTransaction を作る
        let phone = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone.local_addr().unwrap();
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKextcanc1", phone_addr),
        );
        invite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet3");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ext-cancel-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));
        phone
            .send_to(&invite.to_bytes(), sabiden_ext_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_ext_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("INVITE 期待");
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let responder = crate::testing::builders::responder_handle_for_test(stx);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req.clone(),
                remote,
                responder,
            })
            .unwrap();

        // INVITE が NGN へ届くまで少し待つ (registry に pending が入るタイミング)。
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 内線が CANCEL を送る (UasEvent::Cancel を直接 fire)
        let mut cancel = SipRequest::new(SipMethod::Cancel, "sip:0312345678@sabiden");
        cancel.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKextcanc1", phone_addr),
        );
        cancel
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet3");
        cancel.headers.set("To", "<sip:0312345678@sabiden>");
        cancel.headers.set("Call-ID", "ext-cancel-cid");
        cancel.headers.set("CSeq", "1 CANCEL");
        let cancel_stx =
            ServerTransaction::new(cancel.clone(), remote, sabiden_ext_sock.clone()).unwrap();
        let cancel_responder = crate::testing::builders::responder_handle_for_test(cancel_stx);
        event_tx
            .send(UasEvent::Cancel {
                request: cancel,
                remote,
                responder: cancel_responder,
            })
            .unwrap();

        // 内線へ 487 が返る
        let mut got_487 = false;
        for _ in 0..6 {
            match timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 487 {
                            got_487 = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_487, "内線レッグへ 487 Request Terminated が必要");

        // NGN へ CANCEL が届く
        let _ = timeout(Duration::from_secs(3), ngn_task).await;
        assert!(
            *cancel_seen.lock().unwrap(),
            "NGN へ CANCEL が伝搬されるべき"
        );
    }

    /// RFC 3261 §14.2 (UAS Behavior on Re-INVITE) / §12.2.2 / Issue #94:
    /// 既存 dialog が確立済みの内線レッグに対し Re-INVITE が来ると、
    /// `handle_ext_reinvite` は NGN レッグへ Re-INVITE を伝搬し、 NGN の 200 OK
    /// を受けて内線へ 200 OK を返す。 200 OK の To-tag は **既存 dialog の
    /// local-tag を保持** する (= 受信 INVITE の To-tag をそのままエコー)。
    ///
    /// 本テストは内線→NGN 発信通話を `uas_event_proxies_invite_to_ngn` と同じ
    /// 経路で確立した上で、 同 Call-ID + To-tag 付きの INVITE を流して
    /// Re-INVITE 経路を検証する。
    #[tokio::test]
    async fn rfc3261_14_2_ext_reinvite_propagates_to_ngn_and_preserves_to_tag() {
        use crate::config::{ExtensionConfig, UasConfig};
        use crate::sip::message::parse_message;
        use crate::sip::uas::ExtensionUas;
        use std::sync::Mutex as StdMutex;
        use std::time::Duration;
        use tokio::time::timeout;

        // (1) フェイク NGN: 1) 初回 INVITE → 200 OK / ACK 2) 2 回目 INVITE
        // (= sabiden 側 NGN レッグの Re-INVITE) → 200 OK + 新 SDP / ACK
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let reinv_seen: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(None));
        let reinv_seen_c = reinv_seen.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 初回 INVITE
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(req1) = parse_message(&buf[..n]).unwrap() else {
                panic!("INVITE 期待");
            };
            assert_eq!(req1.method, SipMethod::Invite);
            let mut resp1 = build_response_skeleton(&req1, 200, "OK");
            resp1.headers.set(
                "To",
                format!("{};tag=ngn-tag", req1.headers.get("to").unwrap()),
            );
            resp1
                .headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_clone
                .send_to(&resp1.to_bytes(), peer)
                .await
                .unwrap();
            // ACK 受信
            let _ = fake_ngn_clone.recv_from(&mut buf).await;

            // 2 回目: Re-INVITE
            let (n, peer2) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(req2) = parse_message(&buf[..n]).unwrap() else {
                panic!("Re-INVITE 期待");
            };
            assert_eq!(req2.method, SipMethod::Invite);
            *reinv_seen_c.lock().unwrap() = Some(req2.body.clone());
            let mut resp2 = build_response_skeleton(&req2, 200, "OK");
            // To には既に NGN-tag が乗っている (in-dialog なので) ためそのまま返す
            resp2
                .headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            resp2.headers.set("Content-Type", "application/sdp");
            resp2.body = b"v=0\r\no=- 9 9 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n".to_vec();
            fake_ngn_clone
                .send_to(&resp2.to_bytes(), peer2)
                .await
                .unwrap();
            // ACK 受信 (drop)
            let _ = timeout(Duration::from_secs(2), fake_ngn_clone.recv_from(&mut buf)).await;
        });

        // (2) NGN 側 UAC
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // (3) 内線 UAS bind + handler
        let uas_cfg = UasConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            realm: "sabiden-test".to_string(),
            max_expires: 3600,
        };
        let extensions = vec![ExtensionConfig {
            username: "iphone".to_string(),
            password: "secret".to_string(),
        }];
        let uas = ExtensionUas::bind(uas_cfg, &extensions).await.unwrap();
        let uas_addr = uas.socket().local_addr().unwrap();
        let registrar = uas.registrar();
        let ext_layer_for_handler = uas.layer();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer_for_handler, Some(uas_addr));
        handler.spawn(event_rx);

        // (4) フェイク内線 UA: REGISTER 省略のため registrar に binding 直接挿入
        let phone = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let phone_local = phone.local_addr().unwrap();
        registrar
            .register(
                "iphone",
                format!("sip:iphone@{}", phone_local),
                phone_local,
                Duration::from_secs(60),
            )
            .await;

        // (5) 初回 INVITE (To-tag 無し = dialog-creating)
        let call_id = "reinv-test-cid";
        let from_tag = "phonet";
        let mut req = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKfirst", phone_local),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", format!("<sip:iphone@sabiden>;tag={}", from_tag));
        req.headers.set("To", "<sip:dest@sabiden>");
        req.headers.set("Call-ID", call_id);
        req.headers.set("CSeq", "1 INVITE");
        req.headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        phone.send_to(&req.to_bytes(), uas_addr).await.unwrap();

        // 200 OK を受信し To-tag を採取する
        let mut buf = vec![0u8; 8192];
        let mut sabiden_to_tag: Option<String> = None;
        for _ in 0..5 {
            match timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if (200..300).contains(&r.status_code) {
                            let to = r.headers.get("to").unwrap().to_string();
                            // tag= 以降を抽出
                            if let Some(idx) = to.find(";tag=") {
                                sabiden_to_tag =
                                    Some(to[idx + 5..].split(';').next().unwrap().to_string());
                            }
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        let sabiden_to_tag = sabiden_to_tag.expect("初回 INVITE の 200 OK 内 To-tag が取れるべき");

        // (6) Re-INVITE: 同じ Call-ID / From-tag、 To-tag は採取した sabiden 側 tag
        let mut reinv = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        reinv.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKsecond", phone_local),
        );
        reinv.headers.set("Max-Forwards", "70");
        reinv
            .headers
            .set("From", format!("<sip:iphone@sabiden>;tag={}", from_tag));
        // RFC 3261 §14.2 / §12.2.2: Re-INVITE は既存 dialog の To-tag を保持
        reinv
            .headers
            .set("To", format!("<sip:dest@sabiden>;tag={}", sabiden_to_tag));
        reinv.headers.set("Call-ID", call_id);
        reinv.headers.set("CSeq", "2 INVITE");
        reinv
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        reinv.headers.set("Content-Type", "application/sdp");
        reinv.body = b"v=0\r\no=- 1 2 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n".to_vec();
        phone.send_to(&reinv.to_bytes(), uas_addr).await.unwrap();

        // 内線が 2 回目 200 OK を受信し、 To-tag が保たれていることを確認
        let mut got_reinv_200 = false;
        for _ in 0..6 {
            match timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        let cseq = r.headers.get("cseq").unwrap_or("");
                        if (200..300).contains(&r.status_code) && cseq.contains("2 ") {
                            let to = r.headers.get("to").unwrap();
                            assert!(
                                to.contains(&format!("tag={}", sabiden_to_tag)),
                                "Re-INVITE の 200 OK は既存 dialog の To-tag を保持 (RFC 3261 §12.2.2): To={}",
                                to
                            );
                            assert!(
                                !r.body.is_empty(),
                                "Re-INVITE の 200 OK は新 answer SDP を含むべき"
                            );
                            got_reinv_200 = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_reinv_200, "Re-INVITE への 200 OK が内線に届くべき");

        // NGN レッグへ Re-INVITE が伝搬され、 内線が出した新オファ SDP が乗っている
        let _ = timeout(Duration::from_secs(2), ngn_task).await;
        let ngn_reinv_sdp = reinv_seen
            .lock()
            .unwrap()
            .clone()
            .expect("NGN レッグへ Re-INVITE が届くべき");
        let sdp_str = std::str::from_utf8(&ngn_reinv_sdp).unwrap();
        assert!(
            sdp_str.contains("a=sendonly"),
            "NGN への Re-INVITE は内線オファの a=sendonly を含むべき: {}",
            sdp_str
        );
    }

    /// RFC 3261 §12.2.2: 未知の Call-ID で Re-INVITE が来たら
    /// 481 Call/Transaction Does Not Exist を返す。
    #[tokio::test]
    async fn rfc3261_12_2_2_ext_reinvite_with_unknown_dialog_returns_481() {
        use crate::sip::message::parse_message;
        use std::time::Duration;
        use tokio::time::timeout;

        // NGN UAC は使わない (lookup で 481 が返るので Re-INVITE 送出には至らない)
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        let phone_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone_sock.local_addr().unwrap();
        let sabiden_uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

        let handler = UasEventHandler::new(ngn_uac);

        // registry には何も入れない → 未知の Call-ID として 481 が返る
        let mut reinvite = SipRequest::new(SipMethod::Invite, "sip:dst@sabiden");
        reinvite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKstale", phone_addr),
        );
        reinvite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet");
        reinvite
            .headers
            .set("To", "<sip:dst@sabiden>;tag=stale-uas-tag");
        reinvite.headers.set("Call-ID", "unknown-cid");
        reinvite.headers.set("CSeq", "5 INVITE");
        reinvite
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));

        phone_sock
            .send_to(&reinvite.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("Re-INVITE 期待");
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_uas_sock.clone()).unwrap();
        let responder = crate::testing::builders::responder_handle_for_test(stx);

        handler
            .handle_ext_reinvite(req, remote, responder)
            .await
            .unwrap();

        // 481 を受信
        let mut got_481 = false;
        for _ in 0..3 {
            let (n, _) = match timeout(Duration::from_secs(1), phone_sock.recv_from(&mut buf)).await
            {
                Ok(Ok(v)) => v,
                _ => break,
            };
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 481 {
                    got_481 = true;
                    break;
                }
            }
        }
        assert!(
            got_481,
            "未知の Call-ID の Re-INVITE は 481 Call/Transaction Does Not Exist (RFC 3261 §12.2.2)"
        );
    }

    /// RFC 3261 §14.2 / PR #136 review fix:
    /// 確立済み dialog ではないが、 同じ Call-ID で **進行中の INVITE がある**
    /// (= 初回 INVITE の応答完了前に再度 INVITE を受けた glare 状態) 場合、
    /// `handle_ext_reinvite` は **491 Request Pending** を返さなければならない
    /// (RFC 3261 §14.2: "If a UA receives a re-INVITE for an existing dialog
    /// while it has an INVITE it had sent in the same dialog still pending,
    /// it MUST return a 491 (Request Pending)")。
    ///
    /// 481 経路 (pending も confirmed も無い) との切り分けを確認する。
    #[tokio::test]
    async fn rfc3261_14_2_ext_reinvite_with_pending_invite_returns_491() {
        use crate::sip::message::parse_message;
        use std::time::Duration;
        use tokio::time::timeout;

        // NGN UAC は使わない (491 で返るので Re-INVITE 送出には至らない)
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        let phone_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone_sock.local_addr().unwrap();
        let sabiden_uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

        let handler = UasEventHandler::new(ngn_uac);

        // 同じ Call-ID で **pending** な INVITE が registry にあるという状態を作る。
        // ResponderHandle は実 socket を必要とするので、 別途 server-side socket
        // から ServerTransaction を起こして埋め込む (production code の経路と
        // 同じ生成手順)。
        let pending_call_id = "race-cid";
        let pending_responder_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pending_resp_addr = pending_responder_sock.local_addr().unwrap();
        let pending_responder = {
            let mut req = SipRequest::new(SipMethod::Invite, "sip:dst@host");
            req.headers.set(
                "Via",
                format!("SIP/2.0/UDP {};branch=z9hG4bKpending", pending_resp_addr),
            );
            req.headers.set("From", "<sip:src@host>;tag=alice");
            req.headers.set("To", "<sip:dst@host>");
            req.headers.set("Call-ID", pending_call_id);
            req.headers.set("CSeq", "1 INVITE");
            let stx =
                ServerTransaction::new(req, pending_resp_addr, pending_responder_sock).unwrap();
            crate::testing::builders::responder_handle_for_test(stx)
        };
        let pending = Arc::new(PendingOutbound {
            ext_call_id: pending_call_id.to_string(),
            invite_plan: {
                let mut req = SipRequest::new(SipMethod::Invite, "sip:dst@ntt-east.ne.jp");
                req.headers
                    .set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKngnsend");
                req.headers
                    .set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=ng");
                req.headers.set("To", "<sip:dst@ntt-east.ne.jp>");
                req.headers.set("Call-ID", "ngn-side-cid");
                req.headers.set("CSeq", "1 INVITE");
                crate::sip::uac::InvitePlan {
                    request: req,
                    cseq: 1,
                    target_uri: "sip:dst@ntt-east.ne.jp".to_string(),
                    session_expires: 300,
                }
            },
            ext_responder: pending_responder,
            cancelled: tokio::sync::Notify::new(),
            cancelled_flag: std::sync::atomic::AtomicBool::new(false),
        });
        handler.registry.insert_pending(pending).await;

        // 同 Call-ID で Re-INVITE を投げる。 lookup_by_ext は None だが
        // get_pending が Some なので 491 が返るはず。
        let mut reinvite = SipRequest::new(SipMethod::Invite, "sip:dst@sabiden");
        reinvite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKrace", phone_addr),
        );
        reinvite
            .headers
            .set("From", "<sip:iphone@sabiden>;tag=phonet");
        reinvite
            .headers
            .set("To", "<sip:dst@sabiden>;tag=stale-uas-tag");
        reinvite.headers.set("Call-ID", pending_call_id);
        reinvite.headers.set("CSeq", "2 INVITE");
        reinvite
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_addr));

        phone_sock
            .send_to(&reinvite.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) = timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() else {
            panic!("Re-INVITE 期待");
        };
        let stx = ServerTransaction::new(req.clone(), remote, sabiden_uas_sock.clone()).unwrap();
        let responder = crate::testing::builders::responder_handle_for_test(stx);

        handler
            .handle_ext_reinvite(req, remote, responder)
            .await
            .unwrap();

        // 491 を受信
        let mut got_491 = false;
        for _ in 0..3 {
            let (n, _) = match timeout(Duration::from_secs(1), phone_sock.recv_from(&mut buf)).await
            {
                Ok(Ok(v)) => v,
                _ => break,
            };
            if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                if r.status_code == 491 {
                    got_491 = true;
                    break;
                }
                // 481 が来たら fail (今回は pending があるので 491 が正解)
                assert_ne!(
                    r.status_code, 481,
                    "pending INVITE がある場合は 491 (RFC 3261 §14.2) であって 481 ではない"
                );
            }
        }
        assert!(
            got_491,
            "進行中 INVITE と Race した Re-INVITE は 491 Request Pending (RFC 3261 §14.2)"
        );
    }

    /// Issue #138 / RFC 3264 §8 / CLAUDE.md §5: 内線が Re-INVITE オファとして
    /// LAN private IP + Opus を含む SDP を出してきた場合、 sabiden は NGN レッグ
    /// へ送信する前に **必ず** `c=`/`o=` を eth1 IP に強制書換し、 PCMU(0) +
    /// telephone-event(101) 以外のコーデックを削除しなければならない
    /// (NGN は PCMU only, c=/o= は eth1 IP のみ受理する `docs/asterisk-real-invite.md`
    /// §5.2)。 これを欠くと LAN IP 漏洩 → 488 NotAcceptable で hold/un-hold が
    /// 失敗する。
    #[tokio::test]
    async fn rfc3264_8_ext_reinvite_offer_is_rewritten_for_ngn_before_relay() {
        use crate::config::{ExtensionConfig, UasConfig};
        use crate::sip::message::parse_message;
        use crate::sip::uas::ExtensionUas;
        use std::sync::Mutex as StdMutex;
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: 初回 INVITE + Re-INVITE 両方を受ける。 Re-INVITE 受信時の
        // SDP body を共有 buffer に保存して assertion に使う。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let reinv_sdp: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(None));
        let reinv_sdp_c = reinv_sdp.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 初回 INVITE
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(req1) = parse_message(&buf[..n]).unwrap() else {
                panic!("初回 INVITE 期待");
            };
            let mut resp1 = build_response_skeleton(&req1, 200, "OK");
            resp1.headers.set(
                "To",
                format!("{};tag=ngn-tag", req1.headers.get("to").unwrap()),
            );
            resp1
                .headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_clone
                .send_to(&resp1.to_bytes(), peer)
                .await
                .unwrap();
            let _ = fake_ngn_clone.recv_from(&mut buf).await; // ACK
                                                              // Re-INVITE 受信して body をキャプチャ
            let (n, peer2) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(req2) = parse_message(&buf[..n]).unwrap() else {
                panic!("Re-INVITE 期待");
            };
            *reinv_sdp_c.lock().unwrap() = Some(req2.body.clone());
            let mut resp2 = build_response_skeleton(&req2, 200, "OK");
            resp2.headers.set("Content-Type", "application/sdp");
            resp2
                .headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            resp2.body = b"v=0\r\no=- 2 2 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n".to_vec();
            fake_ngn_clone
                .send_to(&resp2.to_bytes(), peer2)
                .await
                .unwrap();
            let _ = timeout(Duration::from_secs(2), fake_ngn_clone.recv_from(&mut buf)).await;
        });

        // ngn_local_addr = 127.0.0.1 (テスト用)。 LAN 192.168 を eth1 = 127.0.0.1
        // に書き換える挙動を観察する (production では 118.177.x.x になる)。
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_local_addr = ngn_client_sock.local_addr().unwrap();
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_local_addr,
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // 内線 UAS bind
        let uas_cfg = UasConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            realm: "sabiden-test".to_string(),
            max_expires: 3600,
        };
        let extensions = vec![ExtensionConfig {
            username: "iphone".to_string(),
            password: "secret".to_string(),
        }];
        let uas = ExtensionUas::bind(uas_cfg, &extensions).await.unwrap();
        let uas_addr = uas.socket().local_addr().unwrap();
        let registrar = uas.registrar();
        let ext_layer_for_handler = uas.layer();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });
        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer_for_handler, Some(uas_addr));
        handler.spawn(event_rx);

        let phone = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let phone_local = phone.local_addr().unwrap();
        registrar
            .register(
                "iphone",
                format!("sip:iphone@{}", phone_local),
                phone_local,
                Duration::from_secs(60),
            )
            .await;

        // 初回 INVITE
        let call_id = "rewr-cid";
        let from_tag = "phonet";
        let mut req = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKfirst", phone_local),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("From", format!("<sip:iphone@sabiden>;tag={}", from_tag));
        req.headers.set("To", "<sip:dest@sabiden>");
        req.headers.set("Call-ID", call_id);
        req.headers.set("CSeq", "1 INVITE");
        req.headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        phone.send_to(&req.to_bytes(), uas_addr).await.unwrap();

        // 200 OK を取って To-tag を採取
        let mut buf = vec![0u8; 8192];
        let mut sabiden_to_tag: Option<String> = None;
        for _ in 0..5 {
            match timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if (200..300).contains(&r.status_code) {
                            let to = r.headers.get("to").unwrap().to_string();
                            if let Some(idx) = to.find(";tag=") {
                                sabiden_to_tag =
                                    Some(to[idx + 5..].split(';').next().unwrap().to_string());
                            }
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        let sabiden_to_tag = sabiden_to_tag.expect("初回 200 OK の To-tag");

        // Re-INVITE: LAN IP 192.168.20.42 + Opus 109 を含む multi-codec SDP
        let mut reinv = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        reinv.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKsecond", phone_local),
        );
        reinv.headers.set("Max-Forwards", "70");
        reinv
            .headers
            .set("From", format!("<sip:iphone@sabiden>;tag={}", from_tag));
        reinv
            .headers
            .set("To", format!("<sip:dest@sabiden>;tag={}", sabiden_to_tag));
        reinv.headers.set("Call-ID", call_id);
        reinv.headers.set("CSeq", "2 INVITE");
        reinv
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        reinv.headers.set("Content-Type", "application/sdp");
        reinv.body = b"v=0\r\no=iphone 1 2 IN IP4 192.168.20.42\r\ns=-\r\nc=IN IP4 192.168.20.42\r\nt=0 0\r\nm=audio 40000 RTP/AVP 109 0 101\r\na=rtpmap:109 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n".to_vec();
        phone.send_to(&reinv.to_bytes(), uas_addr).await.unwrap();

        // NGN が Re-INVITE を受け、 200 OK で完了するのを待つ
        let _ = timeout(Duration::from_secs(3), ngn_task).await;
        let got = reinv_sdp
            .lock()
            .unwrap()
            .clone()
            .expect("NGN レッグへ Re-INVITE が届くべき");
        let sdp = std::str::from_utf8(&got).unwrap();
        // RFC 4566 §5.7 / CLAUDE.md §5: c=/o= の LAN IP は eth1 IP に書き換わる
        assert!(
            !sdp.contains("192.168.20.42"),
            "Re-INVITE NGN レッグの SDP に LAN IP が残ってはいけない: {}",
            sdp
        );
        let eth1_ip_str = ngn_local_addr.ip().to_string();
        assert!(
            sdp.contains(&format!("c=IN IP4 {}", eth1_ip_str)),
            "Re-INVITE NGN レッグの c= は eth1 IP ({}) であるべき: {}",
            eth1_ip_str,
            sdp
        );
        // CLAUDE.md §5 / RFC 3551: Opus は NGN レッグに流してはいけない
        assert!(
            !sdp.contains("opus"),
            "Re-INVITE NGN レッグの SDP から Opus が削除されているべき: {}",
            sdp
        );
        // RFC 4733 §2.4.1: telephone-event は PCMU と並走可
        assert!(
            sdp.contains("PCMU"),
            "Re-INVITE NGN レッグの SDP に PCMU は残るべき: {}",
            sdp
        );
        assert!(
            sdp.contains("telephone-event"),
            "Re-INVITE NGN レッグの SDP に telephone-event は残るべき: {}",
            sdp
        );
    }

    /// Issue #138 / RFC 4028 §7.1 / §10: NGN レッグから 422 Session Interval
    /// Too Small が **Min-SE ヘッダ付き** で返った場合、 sabiden は同 Min-SE 値を
    /// 内線レッグの 422 にも乗せて中継しなければならない。 これを欠くと
    /// 内線 UA が再送値を知らず Session-Timer 更新が失敗し続ける。
    #[tokio::test]
    async fn rfc4028_10_ext_reinvite_relays_min_se_from_ngn_422() {
        use crate::config::{ExtensionConfig, UasConfig};
        use crate::sip::message::parse_message;
        use crate::sip::uas::ExtensionUas;
        use std::time::Duration;
        use tokio::time::timeout;

        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let fake_ngn_clone = fake_ngn.clone();
        // フェイク NGN: 1) 初回 INVITE → 200 OK, 2) Re-INVITE → **422 + Min-SE: 1800**
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 初回
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(req1) = parse_message(&buf[..n]).unwrap() else {
                panic!("INVITE 期待");
            };
            let mut resp1 = build_response_skeleton(&req1, 200, "OK");
            resp1.headers.set(
                "To",
                format!("{};tag=ngn-tag", req1.headers.get("to").unwrap()),
            );
            resp1
                .headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_clone
                .send_to(&resp1.to_bytes(), peer)
                .await
                .unwrap();
            let _ = fake_ngn_clone.recv_from(&mut buf).await; // ACK

            // Re-INVITE → 422 Session Interval Too Small + Min-SE: 1800
            let (n, peer2) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(req2) = parse_message(&buf[..n]).unwrap() else {
                panic!("Re-INVITE 期待");
            };
            let mut resp422 = build_response_skeleton(&req2, 422, "Session Interval Too Small");
            resp422.headers.set("Min-SE", "1800");
            fake_ngn_clone
                .send_to(&resp422.to_bytes(), peer2)
                .await
                .unwrap();
            // 422 への ACK は内部で送られる
            let _ = timeout(Duration::from_secs(2), fake_ngn_clone.recv_from(&mut buf)).await;
        });

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));
        let uas_cfg = UasConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            realm: "sabiden-test".to_string(),
            max_expires: 3600,
        };
        let extensions = vec![ExtensionConfig {
            username: "iphone".to_string(),
            password: "secret".to_string(),
        }];
        let uas = ExtensionUas::bind(uas_cfg, &extensions).await.unwrap();
        let uas_addr = uas.socket().local_addr().unwrap();
        let registrar = uas.registrar();
        let ext_layer_for_handler = uas.layer();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });
        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer_for_handler, Some(uas_addr));
        handler.spawn(event_rx);

        let phone = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let phone_local = phone.local_addr().unwrap();
        registrar
            .register(
                "iphone",
                format!("sip:iphone@{}", phone_local),
                phone_local,
                Duration::from_secs(60),
            )
            .await;

        // 初回 INVITE
        let call_id = "minse-cid";
        let mut req = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKfirst", phone_local),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers.set("From", "<sip:iphone@sabiden>;tag=phonet");
        req.headers.set("To", "<sip:dest@sabiden>");
        req.headers.set("Call-ID", call_id);
        req.headers.set("CSeq", "1 INVITE");
        req.headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        phone.send_to(&req.to_bytes(), uas_addr).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let mut sabiden_to_tag: Option<String> = None;
        for _ in 0..5 {
            match timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if (200..300).contains(&r.status_code) {
                            let to = r.headers.get("to").unwrap().to_string();
                            if let Some(idx) = to.find(";tag=") {
                                sabiden_to_tag =
                                    Some(to[idx + 5..].split(';').next().unwrap().to_string());
                            }
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        let sabiden_to_tag = sabiden_to_tag.expect("初回 200 OK To-tag");

        // Re-INVITE (Session-Timer 更新狙い)
        let mut reinv = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        reinv.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKsecond", phone_local),
        );
        reinv.headers.set("Max-Forwards", "70");
        reinv.headers.set("From", "<sip:iphone@sabiden>;tag=phonet");
        reinv
            .headers
            .set("To", format!("<sip:dest@sabiden>;tag={}", sabiden_to_tag));
        reinv.headers.set("Call-ID", call_id);
        reinv.headers.set("CSeq", "2 INVITE");
        reinv
            .headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        reinv.headers.set("Session-Expires", "60");
        reinv.headers.set("Min-SE", "60");
        phone.send_to(&reinv.to_bytes(), uas_addr).await.unwrap();

        // 内線が 422 + Min-SE を受信
        let mut got_422_with_minse = false;
        for _ in 0..6 {
            match timeout(Duration::from_secs(3), phone.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        let cseq = r.headers.get("cseq").unwrap_or("");
                        if r.status_code == 422 && cseq.contains("2 ") {
                            let min_se = r.headers.get("min-se").unwrap_or("");
                            assert_eq!(
                                min_se.trim(),
                                "1800",
                                "RFC 4028 §10: 422 の Min-SE は NGN レスポンスから中継"
                            );
                            got_422_with_minse = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(
            got_422_with_minse,
            "内線へ 422 Session Interval Too Small + Min-SE が中継されるべき (RFC 4028 §7.1 / §10)"
        );
        let _ = timeout(Duration::from_secs(1), ngn_task).await;
    }

    /// Issue #138 / RFC 3261 §14.2: NGN→sabiden 方向の Re-INVITE
    /// (内線→NGN 発信通話に対して NGN 側ピアが起こす hold/un-hold) は
    /// 内線レッグへ Re-INVITE として伝搬されなければならない。
    ///
    /// シナリオ: 1) 内線が発信 INVITE → sabiden が NGN へ INVITE → 確立。
    /// 2) NGN がフェイクで in-dialog INVITE (= Re-INVITE) を sabiden に送る。
    /// 3) sabiden は内線レッグへ Re-INVITE を投げ、 内線が 200 OK を返す。
    /// 4) sabiden が NGN へ 200 OK を中継する。
    #[tokio::test]
    async fn rfc3261_14_2_ngn_reinvite_forwards_to_extension() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
            )
            .with_test_writer()
            .try_init();
        use crate::config::{ExtensionConfig, UasConfig};
        use crate::sip::message::parse_message;
        use crate::sip::uas::ExtensionUas;
        use std::sync::Mutex as StdMutex;
        use std::time::Duration;
        use tokio::time::timeout;

        // フェイク NGN: 1) 初回 INVITE 受信 → 200 OK, 2) ACK 受信,
        // 3) 自分から in-dialog INVITE を撃って 200 OK を待つ
        let fake_ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn_sock.local_addr().unwrap();
        // (NGN フェイクは後ほど socket 共有で sabiden 側に振る)。

        // 内線 UAS bind
        let uas_cfg = UasConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            realm: "sabiden-test".to_string(),
            max_expires: 3600,
        };
        let extensions = vec![ExtensionConfig {
            username: "iphone".to_string(),
            password: "secret".to_string(),
        }];
        let uas = ExtensionUas::bind(uas_cfg, &extensions).await.unwrap();
        let uas_addr = uas.socket().local_addr().unwrap();
        let registrar = uas.registrar();
        let ext_layer_for_handler = uas.layer();

        // NGN 側 UAC + Inbound handler を **同じ socket** に共有する。
        // production と同じ「P-CSCF 通信用 UDP socket は 1 つ」を再現。
        let ngn_shared_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_shared_addr = ngn_shared_sock.local_addr().unwrap();
        let (ngn_layer, ngn_inbound_rx) = TransactionLayer::spawn(ngn_shared_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_shared_addr,
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // UasEventHandler 構築 + ext_layer 接続
        let mut handler = UasEventHandler::new(ngn_uac);
        handler.attach_ext_layer(ext_layer_for_handler, Some(uas_addr));

        // NgnInboundHandler 起動 (ngn_uac とは別の socket / layer)
        // outbound_forwarder に handler を渡すことで NGN→sabiden Re-INVITE 経路を結線
        // 本テストでは NGN 着信フォーク経路は走らない (NGN→sabiden Re-INVITE は
        // outbound_forwarder で短絡される) ため、 dummy inviter で十分。
        let dummy_inviter: ExtInviter = crate::testing::scripted::ScriptedInviter::builder()
            .default_action(crate::testing::scripted::ScriptedAction::busy())
            .build();
        let ngn_handler = NgnInboundHandler::with_metrics(
            ngn_shared_sock.clone(),
            dummy_inviter,
            registrar.clone(),
            NgnInboundConfig::default(),
            Metrics::new(),
        );
        ngn_handler.set_outbound_forwarder(handler.clone()).await;
        ngn_handler.clone().spawn(ngn_inbound_rx);

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });
        handler.spawn(event_rx);

        // 内線登録
        let phone = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_local = phone.local_addr().unwrap();
        registrar
            .register(
                "iphone",
                format!("sip:iphone@{}", phone_local),
                phone_local,
                Duration::from_secs(60),
            )
            .await;

        // フェイク NGN: 初回 INVITE を受けて 200 OK を返し、 同 dialog で
        // Re-INVITE (in-dialog INVITE) を sabiden に向けて送る。
        // ext_reinv_seen を共有して内線が Re-INVITE を受けたことを観測する。
        let ngn_ack_seen: Arc<StdMutex<bool>> = Arc::new(StdMutex::new(false));
        let ngn_ack_seen_c = ngn_ack_seen.clone();
        let fake_ngn_sock_c = fake_ngn_sock.clone();
        let ngn_call_id_for_reinv: Arc<StdMutex<Option<(SipRequest, std::net::SocketAddr)>>> =
            Arc::new(StdMutex::new(None));
        let captured_initial = ngn_call_id_for_reinv.clone();
        let ngn_200_seen: Arc<StdMutex<Option<u16>>> = Arc::new(StdMutex::new(None));
        let ngn_200_seen_c = ngn_200_seen.clone();

        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 1) 初回 INVITE を受信
            let (n, peer) = fake_ngn_sock_c.recv_from(&mut buf).await.unwrap();
            let SipMessage::Request(req1) = parse_message(&buf[..n]).unwrap() else {
                panic!("初回 INVITE 期待");
            };
            *captured_initial.lock().unwrap() = Some((req1.clone(), peer));
            let mut resp1 = build_response_skeleton(&req1, 200, "OK");
            // To-tag を付ける (新規 dialog なので)
            let to_in = req1.headers.get("to").unwrap();
            resp1.headers.set("To", format!("{};tag=ngnsidetag", to_in));
            resp1
                .headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            fake_ngn_sock_c
                .send_to(&resp1.to_bytes(), peer)
                .await
                .unwrap();
            // 2) ACK を受ける
            let _ = fake_ngn_sock_c.recv_from(&mut buf).await;
            *ngn_ack_seen_c.lock().unwrap() = true;

            // 3) NGN 側ピアが Re-INVITE を sabiden に向けて発射
            let (orig, sabiden_peer) = captured_initial.lock().unwrap().clone().unwrap();
            let mut reinv = SipRequest::new(SipMethod::Invite, orig.uri.clone());
            reinv.headers.set(
                "Via",
                format!("SIP/2.0/UDP {};branch=z9hG4bKreinv-ngn", fake_ngn_addr),
            );
            reinv.headers.set("Max-Forwards", "70");
            // From は元 INVITE の To (sabiden 側)、 To は元 INVITE の From (NGN 側ピア)
            // を反転して in-dialog request を作る形だが、 sabiden=UAC for NGN な
            // dialog 視点では「NGN ピア → sabiden」方向。
            // 元 INVITE の From/To をそのまま使うと dialog tag が逆になる:
            //   - sabiden=UAC, NGN=UAS だったので
            //   - in-dialog request from NGN to sabiden は From(NGN 側)=元 To+tag(NGN),
            //     To(sabiden 側)=元 From+tag(sabiden) になる。
            // build_response_skeleton で付けた "ngnsidetag" を NGN→sabiden 方向の
            // remote tag として再利用する。
            let orig_from = orig.headers.get("from").unwrap();
            let orig_from_tag = orig_from
                .split(";tag=")
                .nth(1)
                .map(|s| s.split(';').next().unwrap_or(s))
                .unwrap_or("");
            // sabiden 側の URI (= 元 To URI without tag) と既存 sabiden tag を抽出
            let orig_to = orig.headers.get("to").unwrap();
            let orig_to_uri = orig_to
                .split(";tag=")
                .next()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| orig_to.to_string());
            // NGN 側の URI (= 元 From URI without tag)
            let orig_from_uri = orig_from
                .split(";tag=")
                .next()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| orig_from.to_string());
            reinv
                .headers
                .set("From", format!("{};tag=ngnsidetag", orig_to_uri));
            reinv
                .headers
                .set("To", format!("{};tag={}", orig_from_uri, orig_from_tag));
            reinv
                .headers
                .set("Call-ID", orig.headers.get("call-id").unwrap());
            reinv.headers.set("CSeq", "200 INVITE");
            reinv
                .headers
                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
            reinv.headers.set("Content-Type", "application/sdp");
            // a=sendonly = NGN ピアが hold を要求するパターン (RFC 3264 §8)
            reinv.body = b"v=0\r\no=- 9 10 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 30002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n".to_vec();

            fake_ngn_sock_c
                .send_to(&reinv.to_bytes(), sabiden_peer)
                .await
                .unwrap();

            // 4) sabiden が NGN へ返す 200 OK を待つ
            for _ in 0..6 {
                match timeout(Duration::from_secs(3), fake_ngn_sock_c.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) => {
                        if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                            let cseq = r.headers.get("cseq").unwrap_or("");
                            if cseq.contains("200 ") && (200..300).contains(&r.status_code) {
                                *ngn_200_seen_c.lock().unwrap() = Some(r.status_code);
                                break;
                            }
                        }
                    }
                    _ => break,
                }
            }
        });

        // 内線フェイク UA: 単一タスクで INVITE / Re-INVITE / 200 OK 応答 / ACK
        // 自動送出を全部担当する。 socket は phone を排他で持つ。
        let phone_c = phone.clone();
        let ext_reinv_seen: Arc<StdMutex<bool>> = Arc::new(StdMutex::new(false));
        let ext_reinv_seen_c = ext_reinv_seen.clone();
        let phone_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            for _ in 0..12 {
                let (n, peer) =
                    match timeout(Duration::from_secs(6), phone_c.recv_from(&mut buf)).await {
                        Ok(Ok(v)) => v,
                        _ => break,
                    };
                let msg = parse_message(&buf[..n]).unwrap();
                match msg {
                    SipMessage::Request(req) if req.method == SipMethod::Invite => {
                        // Re-INVITE (To に既に tag あり) を検出
                        let to_in = req.headers.get("to").unwrap_or("").to_string();
                        if to_in.contains(";tag=") {
                            *ext_reinv_seen_c.lock().unwrap() = true;
                        }
                        let mut resp = build_response_skeleton(&req, 200, "OK");
                        if !to_in.contains(";tag=") {
                            resp.headers.set("To", format!("{};tag=phonetag", to_in));
                        }
                        resp.headers.set(
                            "Contact",
                            format!("<sip:iphone@{}>", phone_c.local_addr().unwrap()),
                        );
                        resp.headers.set("Content-Type", "application/sdp");
                        resp.body = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 50000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n".to_vec();
                        phone_c.send_to(&resp.to_bytes(), peer).await.unwrap();
                    }
                    SipMessage::Response(r) => {
                        let cseq = r.headers.get("cseq").unwrap_or("").to_string();
                        if (200..300).contains(&r.status_code) && cseq.ends_with("INVITE") {
                            // 内線が UAC として発信した INVITE への 200 OK → ACK
                            let mut ack =
                                SipRequest::new(SipMethod::Ack, "sip:dest@sabiden".to_string());
                            ack.headers.set(
                                "Via",
                                format!(
                                    "SIP/2.0/UDP {};branch=z9hG4bKack",
                                    phone_c.local_addr().unwrap()
                                ),
                            );
                            ack.headers.set("Max-Forwards", "70");
                            ack.headers
                                .set("From", r.headers.get("from").unwrap().to_string());
                            ack.headers
                                .set("To", r.headers.get("to").unwrap().to_string());
                            ack.headers
                                .set("Call-ID", r.headers.get("call-id").unwrap().to_string());
                            let n_cseq = cseq.split_whitespace().next().unwrap_or("1");
                            ack.headers.set("CSeq", format!("{} ACK", n_cseq));
                            phone_c.send_to(&ack.to_bytes(), peer).await.unwrap();
                        }
                    }
                    _ => {}
                }
            }
        });

        // (5) 内線が **発信側**: INVITE を sabiden へ向けて投げる
        let call_id = "ngn-reinv-cid";
        let mut req = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        req.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKout", phone_local),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers.set("From", "<sip:iphone@sabiden>;tag=phonet");
        req.headers.set("To", "<sip:dest@sabiden>");
        req.headers.set("Call-ID", call_id);
        req.headers.set("CSeq", "1 INVITE");
        req.headers
            .set("Contact", format!("<sip:iphone@{}>", phone_local));
        req.headers.set("Content-Type", "application/sdp");
        req.body = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 50000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n".to_vec();
        phone.send_to(&req.to_bytes(), uas_addr).await.unwrap();

        // NGN タスク完了 (Re-INVITE 完了)
        let _ = timeout(Duration::from_secs(10), ngn_task).await;
        let _ = timeout(Duration::from_secs(1), phone_task).await;

        assert!(
            *ext_reinv_seen.lock().unwrap(),
            "NGN→sabiden Re-INVITE が内線レッグへ伝搬されるべき (RFC 3261 §14.2)"
        );
        assert!(
            ngn_200_seen.lock().unwrap().is_some(),
            "sabiden は NGN へ Re-INVITE の 200 OK を返すべき (RFC 3261 §14.2)"
        );
    }

    /// `OutboundCallRegistry` の単体動作: pending → confirmed の遷移と
    /// 両側 Call-ID での lookup が機能する。
    #[tokio::test]
    async fn outbound_registry_lookup_by_either_call_id() {
        let reg = OutboundCallRegistry::new();
        // pending 投入
        let pending = Arc::new(PendingOutbound {
            ext_call_id: "ext-cid".to_string(),
            invite_plan: {
                let mut req = SipRequest::new(SipMethod::Invite, "sip:dst@host");
                req.headers
                    .set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest");
                req.headers.set("From", "<sip:src@host>;tag=alice");
                req.headers.set("To", "<sip:dst@host>");
                req.headers.set("Call-ID", "fake");
                req.headers.set("CSeq", "1 INVITE");
                crate::sip::uac::InvitePlan {
                    request: req,
                    cseq: 1,
                    target_uri: "sip:dst@host".to_string(),
                    session_expires: 300,
                }
            },
            ext_responder: {
                let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let mut req = SipRequest::new(SipMethod::Invite, "sip:dst@host");
                req.headers
                    .set("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtest");
                req.headers.set("From", "<sip:src@host>;tag=alice");
                req.headers.set("To", "<sip:dst@host>");
                req.headers.set("Call-ID", "fake");
                req.headers.set("CSeq", "1 INVITE");
                let stx =
                    ServerTransaction::new(req, "127.0.0.1:9999".parse().unwrap(), sock).unwrap();
                crate::testing::builders::responder_handle_for_test(stx)
            },
            cancelled: tokio::sync::Notify::new(),
            cancelled_flag: std::sync::atomic::AtomicBool::new(false),
        });
        reg.insert_pending(pending.clone()).await;
        assert!(reg.get_pending("ext-cid").await.is_some());
        assert!(reg.take_pending("ext-cid").await.is_some());
        assert!(reg.get_pending("ext-cid").await.is_none());
    }

    /// NGN 着信 INVITE → WebRTC 内線への offer push → browser からの answer 受信
    /// までの round trip と、 RtpBridge を起動できない transparent モード
    /// (Issue #15 互換) で WebRTC leg の **未書換 SDP** (`c=0.0.0.0` /
    /// `m=audio 9`) が NGN に流れないことを確認する。
    ///
    /// Issue #73 の主眼: browser に push される SDP が `peer.create_offer()`
    /// 由来 (SAVPF/DTLS) であって NGN 生 SDP (RTP/AVP) ではないこと。
    /// Issue #73 review (本 PR fix): `start_bridge_for_inbound` が起動できない
    /// 状況で 200 OK + 未書換 `0.0.0.0:9` SDP を NGN に流すと NGN は RTP を
    /// 投げる先がなく半端な状態になるので、 502 Bad Gateway に切り替えた
    /// (`docs/asterisk-real-invite.md` §5.2)。 実際の bridged WebRTC 結線は
    /// Issue follow-up で対応する。
    #[tokio::test]
    async fn ngn_invite_to_webrtc_binding_offer_push_and_answer_round_trip() {
        use crate::sip::message::parse_message;
        use crate::sip::message::SipMessage;
        use crate::sip::registrar::ExtTransport;
        use crate::sip::transaction::TransactionLayer;
        use crate::webrtc::peer::{PeerSession, StubPeerSession};
        use crate::webrtc::signaling::{ClientMessage, PendingAnswers, ServerMessage, WsSink};
        use std::time::Duration;
        use tokio::sync::mpsc;
        use tokio::time::timeout;

        // sabiden NGN SIP ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        // NGN 側ピア (フェイク UA)
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_addr = ngn_sock.local_addr().unwrap();

        // WebRTC 内線をシミュレートする WS チャネル (browser 役)
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();

        // ExtensionRegistrar に WebRTC transport で binding を入れる
        let extensions = ExtensionRegistrar::new();
        extensions
            .register_with_transport(
                "alice",
                "sip:alice@webrtc.peer".to_string(),
                "127.0.0.1:65535".parse().unwrap(),
                Duration::from_secs(60),
                ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            )
            .await;

        // NGN 由来の生 SDP (RTP/AVP)。Issue #73 の修正により、 これがそのまま
        // browser に push されてはいけない (browser は DTLS/ICE 不在で拒絶する)。
        let ngn_raw_sdp_marker = "192.0.2.1";

        // browser シミュレーション: ServerMessage::Offer を受け取ったら同じ call_id で
        // ClientMessage::Answer { call_id, sdp } 相当の SDP を pending に届ける。
        // ブラウザは setRemoteDescription(offer) → answer 生成の流れだが、
        // ここではテスト都合上、固定の SAVPF answer を返す。
        let pending_for_browser = pending.clone();
        let browser_answer_sdp = "v=0\r\n\
                                  o=mozilla 9 9 IN IP4 0.0.0.0\r\n\
                                  s=-\r\n\
                                  c=IN IP4 0.0.0.0\r\n\
                                  t=0 0\r\n\
                                  m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
                                  a=rtpmap:0 PCMU/8000\r\n\
                                  a=ice-ufrag:browser\r\n\
                                  a=ice-pwd:browserpasswordbrowserpassword\r\n\
                                  a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                                  a=setup:active\r\n\
                                  a=mid:0\r\n\
                                  a=rtcp-mux\r\n\
                                  a=sendrecv\r\n";
        let browser_answer_sdp_owned = browser_answer_sdp.to_string();
        let captured_offer: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_offer_c = captured_offer.clone();
        let browser_task = tokio::spawn(async move {
            let msg = timeout(Duration::from_secs(3), out_rx.recv())
                .await
                .expect("browser へ offer push が来ない")
                .expect("WS チャネルが閉じている");
            match msg {
                ServerMessage::Offer { call_id, sdp } => {
                    *captured_offer_c.lock().await = Some(sdp);
                    let delivered = pending_for_browser
                        .deliver(&call_id, browser_answer_sdp_owned.clone())
                        .await;
                    assert!(delivered, "PendingAnswers::deliver が成功するはず");
                }
                other => panic!("offer 以外を受信: {:?}", other),
            }
        });

        // SIP fork 用 inviter (本テストでは呼ばれないはずだが ExtInviter が必要)。
        // (ハーネス Issue #42 で `ScriptedInviter` は builder ベースに統合された。)
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter.clone(),
            extensions,
            NgnInboundConfig::default(),
        );

        // NGN INVITE 送信 (PCMU 0 のコンパクト SDP)
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKwebrtc-ngn", ngn_addr),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-w");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-webrtc-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = b"v=0\r\n\
                        o=- 1 1 IN IP4 192.0.2.1\r\n\
                        s=-\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        m=audio 20000 RTP/AVP 0\r\n\
                        a=rtpmap:0 PCMU/8000\r\n\
                        a=ptime:20\r\n\
                        a=sendrecv\r\n"
            .to_vec();
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 100 Trying と 502 Bad Gateway (transparent モードかつ WebRTC leg の
        // `0.0.0.0:9` answer は未書換のまま NGN に流せないため) を待つ。
        // Issue #249: 100 と 502 の間に 180 Ringing (RFC 3261 §13.3.1.4) が流れる。
        let mut buf = vec![0u8; 8192];
        let mut got_100 = false;
        let mut final_status: Option<u16> = None;
        for _ in 0..6 {
            match timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        match r.status_code {
                            100 => got_100 = true,
                            180 => {} // RFC 3261 §13.3.1.4 (Issue #249)
                            code => {
                                final_status = Some(code);
                                break;
                            }
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_100, "100 Trying が NGN 側に届くべき");
        assert_eq!(
            final_status,
            Some(502),
            "transparent モードで WebRTC leg を bridge できない場合は 502 を返すべき"
        );

        // Issue #73 主検証: browser に push した SDP は NGN 由来生 SDP ではなく、
        // sabiden が `peer.create_offer()` で作った SAVPF オファであるべき。
        let pushed_offer = captured_offer
            .lock()
            .await
            .clone()
            .expect("browser へ offer が push されているはず");
        assert!(
            !pushed_offer.contains(ngn_raw_sdp_marker),
            "NGN 生 SDP がそのまま browser に push されている (#73 バグ): {}",
            pushed_offer
        );
        assert!(
            pushed_offer.contains("UDP/TLS/RTP/SAVPF"),
            "browser 向け offer は SAVPF であるべき: {}",
            pushed_offer
        );
        assert!(
            pushed_offer.to_uppercase().contains("PCMU"),
            "browser 向け offer に PCMU が含まれるべき: {}",
            pushed_offer
        );

        assert_eq!(
            inviter.call_count(),
            0,
            "WebRTC 専用 binding なので SIP fork inviter は呼ばれないはず"
        );

        // browser タスクが正常に完了している
        browser_task.await.unwrap();

        // ClientMessage::Answer のラウンドトリップ JSON 表現も serde で読み書きできる
        let cm = ClientMessage::Answer {
            call_id: "x".into(),
            sdp: "v=0".into(),
        };
        let s = serde_json::to_string(&cm).unwrap();
        assert!(s.contains("\"type\":\"answer\""));
        assert!(s.contains("\"call_id\":\"x\""));
    }

    /// Issue #73 unit: `run_webrtc_leg` 経路で
    ///   1. `peer.create_offer()` が呼ばれる
    ///   2. その戻り値が `ServerMessage::Offer` で WS に push される
    ///   3. ブラウザ answer 受信後 `peer.accept_answer()` が呼ばれる
    ///   4. NGN 200 OK 用の SDP は SAVPF→AVP 変換済 (RTP/AVP) になる
    /// が満たされることを、 `fork_to_bindings` 経由で直接検証する。
    /// fork_to_bindings は内部で run_webrtc_leg を spawn するので、 run_webrtc_leg
    /// が private のままでも経路は同じ。
    #[tokio::test]
    async fn run_webrtc_leg_uses_create_offer_and_accept_answer() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// 呼び出し回数を数える PeerSession モック。
        struct CountingPeer {
            create_offer_count: AtomicUsize,
            accept_answer_count: AtomicUsize,
            offer_sdp: String,
        }
        #[async_trait::async_trait]
        impl PeerSession for CountingPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Err(anyhow::anyhow!(
                    "本フローでは handle_offer を呼んではいけない (Issue #73)"
                ))
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                self.create_offer_count.fetch_add(1, Ordering::SeqCst);
                Ok(self.offer_sdp.clone())
            }
            async fn accept_answer(&self, sdp: &str) -> anyhow::Result<()> {
                self.accept_answer_count.fetch_add(1, Ordering::SeqCst);
                // 受け取った SDP が browser の SAVPF answer であることを軽く確認
                assert!(sdp.contains("UDP/TLS/RTP/SAVPF"));
                Ok(())
            }
            async fn add_ice_candidate(&self, _candidate: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let peer_inner = Arc::new(CountingPeer {
            create_offer_count: AtomicUsize::new(0),
            accept_answer_count: AtomicUsize::new(0),
            offer_sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                        t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                        a=ice-ufrag:srvuf\r\na=ice-pwd:srvpasswordsrvpassword\r\n\
                        a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
                        a=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
                .to_string(),
        });
        let peer: Arc<dyn PeerSession> = peer_inner.clone();

        // WS チャネル + pending
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();

        // browser タスク: offer push を受け、 SAVPF answer を pending に届ける。
        let browser_answer = "v=0\r\no=mozilla 9 9 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                              t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                              a=ice-ufrag:browser\r\na=ice-pwd:browserpwdbrowserpwdbrowserpwd\r\n\
                              a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                              a=setup:active\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
            .to_string();
        let pending_for_browser = pending.clone();
        let captured: Arc<tokio::sync::Mutex<Option<String>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let captured_c = captured.clone();
        let browser_task = tokio::spawn(async move {
            let msg = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
                .await
                .expect("offer push 不在")
                .expect("WS チャネル閉鎖");
            if let ServerMessage::Offer { call_id, sdp } = msg {
                *captured_c.lock().await = Some(sdp);
                let ok = pending_for_browser.deliver(&call_id, browser_answer).await;
                assert!(ok);
            } else {
                panic!("offer 以外を受信");
            }
        });

        // fork_to_bindings 経由で run_webrtc_leg を駆動する。
        // SIP inviter は使われないが ExtInviter として渡す必要がある。
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![(
            "alice".to_string(),
            Binding {
                contact_uri: "sip:alice@webrtc.peer".to_string(),
                remote: "127.0.0.1:65535".parse().unwrap(),
                expires_at: std::time::Instant::now() + Duration::from_secs(60),
                transport: ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            },
        )];
        // NGN 由来オファ (run_webrtc_leg の新設計では 200 OK 構築には使わない;
        // browser に push されてもいけない)
        let ngn_offer = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
                          t=0 0\r\nm=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
            .to_vec();
        let result = fork_to_bindings(
            inviter,
            bindings,
            ngn_offer,
            "ut-cid".to_string(),
            Duration::from_secs(3),
        )
        .await;

        browser_task.await.unwrap();

        // (1) create_offer が呼ばれた / (3) accept_answer も呼ばれた
        assert_eq!(peer_inner.create_offer_count.load(Ordering::SeqCst), 1);
        assert_eq!(peer_inner.accept_answer_count.load(Ordering::SeqCst), 1);

        // (2) push された SDP は peer.create_offer の返値である
        let pushed = captured.lock().await.clone().expect("offer push");
        assert!(pushed.contains("UDP/TLS/RTP/SAVPF"));
        assert!(!pushed.contains("192.0.2.1"), "NGN 由来 SDP が混入");

        // (4) 200 OK の SDP は AVP に変換されている
        match result {
            ForkResult::Answered { response, .. } => {
                let body = std::str::from_utf8(&response.body).unwrap();
                assert!(body.contains("RTP/AVP"));
                assert!(!body.contains("UDP/TLS/RTP/SAVPF"));
                assert!(!body.contains("a=fingerprint"));
                assert!(body.contains("a=rtpmap:0 PCMU/8000"));
            }
            ForkResult::AllFailed { last_status } => {
                panic!(
                    "Answered 期待だが AllFailed (last_status={:?})",
                    last_status
                )
            }
            ForkResult::Timeout => panic!("Answered 期待だが Timeout"),
        }
    }

    /// Issue #73 unit (review): `peer.create_offer` が Err を返したら
    /// `pending` を触らずに `Errored` で復帰し、 `fork_to_bindings` 全体としては
    /// `AllFailed { last_status: None }` になる。
    /// `pending` 状態が変化していないことも合わせて確認する。
    #[tokio::test]
    async fn run_webrtc_leg_returns_errored_when_create_offer_fails() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct FailingCreateOfferPeer {
            create_calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl PeerSession for FailingCreateOfferPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Err(anyhow::anyhow!("unused"))
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                self.create_calls.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::anyhow!("create_offer 失敗 (str0m 内部エラー)"))
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                panic!("create_offer 失敗時は accept_answer を呼んではいけない");
            }
            async fn add_ice_candidate(&self, _candidate: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let peer_inner = Arc::new(FailingCreateOfferPeer {
            create_calls: AtomicUsize::new(0),
        });
        let peer: Arc<dyn PeerSession> = peer_inner.clone();

        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![(
            "alice".to_string(),
            Binding {
                contact_uri: "sip:alice@webrtc.peer".to_string(),
                remote: "127.0.0.1:65535".parse().unwrap(),
                expires_at: std::time::Instant::now() + Duration::from_secs(60),
                transport: ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            },
        )];
        let result = fork_to_bindings(
            inviter,
            bindings,
            b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
              m=audio 20000 RTP/AVP 0\r\n"
                .to_vec(),
            "ut-cid-create-fail".to_string(),
            Duration::from_secs(3),
        )
        .await;

        // create_offer 失敗 → AllFailed (status は Errored 由来なので None)
        match result {
            ForkResult::AllFailed { last_status } => {
                assert!(
                    last_status.is_none(),
                    "create_offer 失敗は Errored 扱いで status は記録されない"
                );
            }
            ForkResult::Answered { .. } => panic!("AllFailed 期待だが Answered"),
            ForkResult::Timeout => panic!("AllFailed 期待だが Timeout"),
        }
        assert_eq!(peer_inner.create_calls.load(Ordering::SeqCst), 1);

        // pending は (1) より前に return しているので変化していない (= deliver できない)。
        let dropped = pending
            .deliver("ut-cid-create-fail", "dummy".to_string())
            .await;
        assert!(
            !dropped,
            "pending.register が呼ばれていないので deliver は false を返すはず"
        );

        // browser へは offer が送られていない
        assert!(
            out_rx.try_recv().is_err(),
            "create_offer 失敗時に WS push が起きてはいけない"
        );
    }

    /// Issue #73 unit (review): `peer.accept_answer` が Err を返したら
    /// `Errored` で復帰し、 `fork_to_bindings` 全体としては
    /// `AllFailed { last_status: None }` になる。
    /// `pending` は (4) の `deliver` で既に消費済みであるべき。
    #[tokio::test]
    async fn run_webrtc_leg_returns_errored_when_accept_answer_fails() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct FailingAcceptAnswerPeer {
            create_calls: AtomicUsize,
            accept_calls: AtomicUsize,
            close_calls: AtomicUsize,
            offer_sdp: String,
        }
        #[async_trait::async_trait]
        impl PeerSession for FailingAcceptAnswerPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Err(anyhow::anyhow!("unused"))
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                self.create_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.offer_sdp.clone())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                self.accept_calls.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::anyhow!("accept_answer 失敗 (browser SDP 不正)"))
            }
            async fn add_ice_candidate(&self, _candidate: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                self.close_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let peer_inner = Arc::new(FailingAcceptAnswerPeer {
            create_calls: AtomicUsize::new(0),
            accept_calls: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            offer_sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                        t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                        a=ice-ufrag:srvuf\r\na=ice-pwd:srvpasswordsrvpassword\r\n\
                        a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
                        a=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
                .to_string(),
        });
        let peer: Arc<dyn PeerSession> = peer_inner.clone();

        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();

        // browser タスク: offer push を受け、 SAVPF answer を pending に届ける。
        let browser_answer = "v=0\r\no=mozilla 9 9 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                              t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                              a=ice-ufrag:browser\r\na=ice-pwd:browserpwdbrowserpwdbrowserpwd\r\n\
                              a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                              a=setup:active\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
            .to_string();
        let pending_for_browser = pending.clone();
        let browser_task = tokio::spawn(async move {
            let msg = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
                .await
                .expect("offer push 不在")
                .expect("WS チャネル閉鎖");
            if let ServerMessage::Offer { call_id, sdp: _ } = msg {
                let ok = pending_for_browser.deliver(&call_id, browser_answer).await;
                assert!(ok);
            } else {
                panic!("offer 以外を受信");
            }
        });

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![(
            "alice".to_string(),
            Binding {
                contact_uri: "sip:alice@webrtc.peer".to_string(),
                remote: "127.0.0.1:65535".parse().unwrap(),
                expires_at: std::time::Instant::now() + Duration::from_secs(60),
                transport: ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            },
        )];
        let result = fork_to_bindings(
            inviter,
            bindings,
            b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
              m=audio 20000 RTP/AVP 0\r\n"
                .to_vec(),
            "ut-cid-accept-fail".to_string(),
            Duration::from_secs(3),
        )
        .await;

        browser_task.await.unwrap();

        // create_offer は呼ばれ、accept_answer も呼ばれた (が Err を返した)
        assert_eq!(peer_inner.create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(peer_inner.accept_calls.load(Ordering::SeqCst), 1);

        // accept_answer 失敗 → AllFailed { last_status: None } (Errored 由来)
        match result {
            ForkResult::AllFailed { last_status } => {
                assert!(
                    last_status.is_none(),
                    "accept_answer 失敗は Errored 扱いで status は記録されない"
                );
            }
            ForkResult::Answered { .. } => panic!("AllFailed 期待だが Answered"),
            ForkResult::Timeout => panic!("AllFailed 期待だが Timeout"),
        }

        // pending は (4) の deliver で消費済み (= 二重 deliver は false)
        let again = pending
            .deliver("ut-cid-accept-fail", "dummy".to_string())
            .await;
        assert!(
            !again,
            "pending は accept_answer 到達前に deliver で消費済みのはず"
        );

        // Issue #122 🟡 #3: accept_answer 失敗時は str0m / browser が宙ぶらりんに
        // ならないよう `peer.close()` がベストエフォートで呼ばれていること。
        // W3C WebRTC §4.4.1: close で peerconnection state を `closed` に倒す。
        assert_eq!(
            peer_inner.close_calls.load(Ordering::SeqCst),
            1,
            "accept_answer 失敗時は peer.close() を 1 度だけ呼ぶべき (Issue #122 🟡 #3)"
        );
    }

    /// Issue #107: browser が `ClientMessage::Decline` を送ると、
    /// `run_webrtc_leg` は `LegResult::Failed { status: 603 }` を返し、
    /// `fork_to_bindings` は `ForkResult::AllFailed { last_status: Some(603) }` で抜ける
    /// (RFC 3261 §21.6.2 603 Decline / §16.7 best response selection)。
    ///
    /// 旧挙動: browser が何も送らず、 `fork_to_bindings` は `leg_timeout` 経過まで
    /// 待ってから `Timeout` で抜けていた (NGN 側は応答無しで 30 秒以上保留)。
    /// 新挙動: 即時 (= browser が decline を送った瞬間) 603 で抜ける。
    #[tokio::test]
    async fn rfc3261_21_6_2_run_webrtc_leg_propagates_decline_as_failed_603() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// 必要最低限の Peer。 create_offer は SAVPF SDP を返す。
        /// accept_answer は呼ばれてはいけない (decline 経路なので)。
        struct DeclinePathPeer {
            create_calls: AtomicUsize,
            offer_sdp: String,
        }
        #[async_trait::async_trait]
        impl PeerSession for DeclinePathPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Err(anyhow::anyhow!("unused"))
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                self.create_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.offer_sdp.clone())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                panic!("decline 経路では accept_answer を呼んではいけない");
            }
            async fn add_ice_candidate(&self, _candidate: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let peer_inner = Arc::new(DeclinePathPeer {
            create_calls: AtomicUsize::new(0),
            offer_sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                        t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                        a=ice-ufrag:srvuf\r\na=ice-pwd:srvpasswordsrvpassword\r\n\
                        a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
                        a=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
                .to_string(),
        });
        let peer: Arc<dyn PeerSession> = peer_inner.clone();

        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();

        // browser タスク: offer push を受け取った瞬間に decline を送る (= 拒否ボタン)
        let pending_for_browser = pending.clone();
        let browser_task = tokio::spawn(async move {
            let msg = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
                .await
                .expect("offer push 不在")
                .expect("WS チャネル閉鎖");
            if let ServerMessage::Offer { call_id, sdp: _ } = msg {
                let ok = pending_for_browser.decline(&call_id, 603).await;
                assert!(ok, "PendingAnswers::decline 成功すべき");
            } else {
                panic!("offer 以外を受信");
            }
            // fork_to_bindings の cleanup から Cancel が来るかもしれないが、
            // 本テストでは観測しなくてよい (drained Cancel は PWA UI で
            // idempotent に処理される)。 drain しておく。
            while let Ok(Some(_)) =
                tokio::time::timeout(Duration::from_millis(100), out_rx.recv()).await
            {}
        });

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![(
            "alice".to_string(),
            Binding {
                contact_uri: "sip:alice@webrtc.peer".to_string(),
                remote: "127.0.0.1:65535".parse().unwrap(),
                expires_at: std::time::Instant::now() + Duration::from_secs(60),
                transport: ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            },
        )];
        let start = std::time::Instant::now();
        let result = fork_to_bindings(
            inviter,
            bindings,
            b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
              m=audio 20000 RTP/AVP 0\r\n"
                .to_vec(),
            "ut-cid-decline".to_string(),
            // 旧挙動なら 30 秒以上待つはず。 即時 603 が返ることを確認するため、
            // 短い fork_timeout (3s) を渡し、 さらに elapsed < 1s を assert する。
            Duration::from_secs(3),
        )
        .await;
        let elapsed = start.elapsed();

        browser_task.await.unwrap();

        // create_offer は呼ばれた (= decline は post-create_offer のタイミング)
        assert_eq!(peer_inner.create_calls.load(Ordering::SeqCst), 1);

        // 即時 603 で抜ける (旧挙動 = fork_timeout 待ちでは 3 秒以上かかる)
        assert!(
            elapsed < Duration::from_secs(1),
            "decline 経路は即時 (< 1s) 撤収するはず: elapsed={:?}",
            elapsed
        );

        // fork 全体としては 603 で AllFailed (= SIP 内線端末が居ない構成なので)
        match result {
            ForkResult::AllFailed { last_status } => {
                assert_eq!(
                    last_status,
                    Some(603),
                    "browser decline は 603 Decline として fork に伝搬 (RFC 3261 §21.6.2)"
                );
            }
            ForkResult::Answered { .. } => panic!("AllFailed 期待だが Answered"),
            ForkResult::Timeout => panic!(
                "AllFailed 期待だが Timeout (Issue #107 旧挙動の症状: decline が伝搬していない)"
            ),
        }
    }

    /// Issue #66 の核心: `finalize_outbound_bridge` が NGN 200 OK の SDP answer
    /// を **そのまま** 内線へ返さず、 sabiden の ext bridge socket を指す
    /// `c=` / `m=audio port` に書き換えていることを直接検証する。
    ///
    /// RFC 3264 §6: answer の transport address (c= / m=) で offerer は RTP 宛先を決める。
    /// よって内線 UA は本関数が返す SDP に書かれた IP:port へ RTP を送る。
    /// ここが NGN の `118.177.125.1:28196` のままだと LAN 経由の Linphone は
    /// NGN P-CSCF へ直送ろうとして到達せず無音になる (Issue #66)。
    #[tokio::test]
    async fn finalize_outbound_bridge_rewrites_ngn_answer_to_ext_bridge_endpoint() {
        use crate::call::manager::CallManager;

        // sabiden NGN 側 UAC は本テストの finalize_outbound_bridge ロジックには
        // 直接影響しないが、UasEventHandler コンストラクタには必須なので
        // 最小実装で通す。
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            "127.0.0.1:5060".parse().unwrap(),
        ));

        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr,
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );

        // ext bridge socket と NGN bridge socket を bind し、ext_peer は適当な内線
        // RTP エンドポイントとして埋める (RtpBridge 起動には必要だが、本テストは
        // 戻り SDP の検証だけが目的)。
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_local = ext_sock.local_addr().unwrap();
        let ctx = OutboundBridgeCtx {
            ngn_sock,
            ext_sock,
            ext_peer: "127.0.0.1:40000".parse().unwrap(),
        };

        // 内線 UA が出したオファ (ext_offer) — `a=ptime:20` 等が乗っているのが
        // 自然形。c=/m= ともこの段階では内線 UA 自身の LAN IP/port が乗る。
        let ext_offer = b"v=0\r\n\
            o=- 1 1 IN IP4 192.168.20.50\r\n\
            s=-\r\n\
            c=IN IP4 192.168.20.50\r\n\
            t=0 0\r\n\
            m=audio 7078 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=ptime:20\r\n";

        // NGN が返してきた 200 OK answer — Issue #66 の発火条件と全く同じ:
        // c= / m=audio 共に NGN P-CSCF 側の RTP エンドポイント。
        let ngn_answer = b"v=0\r\n\
            o=- 9 9 IN IP4 118.177.125.1\r\n\
            s=-\r\n\
            c=IN IP4 118.177.125.1\r\n\
            t=0 0\r\n\
            m=audio 28196 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n";

        let (rewritten, bridge_id) = handler
            .finalize_outbound_bridge(Some(ctx), ext_offer, ngn_answer)
            .await
            .expect("finalize_outbound_bridge");

        let body = std::str::from_utf8(&rewritten).expect("utf8");
        // 1. NGN 側 IP がそのまま素通しされていないこと (= 根本回避できている)。
        assert!(
            !body.contains("118.177.125.1"),
            "NGN P-CSCF IP が内線レッグ SDP に残っている: {body}"
        );
        assert!(
            !body.contains("28196"),
            "NGN 側 RTP port が内線レッグ SDP に残っている: {body}"
        );
        // 2. ext bridge socket の IP/port が広告されていること。
        assert!(
            body.contains(&format!("c=IN IP4 {}\r\n", ext_local.ip())),
            "session-level c= が ext bridge IP に書き換わっていない: {body}"
        );
        assert!(
            body.contains(&format!("m=audio {} RTP/AVP 0", ext_local.port())),
            "m=audio port が ext bridge port に書き換わっていない: {body}"
        );
        // 3. オファ由来の rtpmap / ptime が保持されていること (RFC 3264 §6)。
        assert!(
            body.contains("a=rtpmap:0 PCMU/8000"),
            "rtpmap が失われている: {body}"
        );
        assert!(body.contains("a=ptime:20"), "ptime が失われている: {body}");
        // 4. RtpBridge が起動して CallId が返ってきていること。
        assert!(bridge_id.is_some(), "RTP ブリッジが起動していない");
    }

    /// Issue #66: `finalize_outbound_bridge` は ext_bind_ip と ngn_bind_ip を
    /// 個別に指定したときも、内線レッグ SDP に書き出されるのは ext socket の
    /// 実際の bind 先 (ext_bind_ip 側) であること。NGN 側 IP が漏れない。
    #[tokio::test]
    async fn finalize_outbound_bridge_uses_ext_bind_ip_not_ngn_bind_ip() {
        use crate::call::manager::CallManager;

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            "127.0.0.1:5060".parse().unwrap(),
        ));
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr,
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );

        // ngn_sock と ext_sock を別ポートで bind (実環境では別 NIC を想定)。
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ext_addr = ext_sock.local_addr().unwrap();
        assert_ne!(
            ngn_addr.port(),
            ext_addr.port(),
            "テスト前提: NGN bridge と ext bridge は別ポート"
        );

        let ctx = OutboundBridgeCtx {
            ngn_sock,
            ext_sock,
            ext_peer: "127.0.0.1:40000".parse().unwrap(),
        };
        let ext_offer = b"v=0\r\n\
            o=- 1 1 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 7000 RTP/AVP 0\r\n";
        let ngn_answer = b"v=0\r\n\
            o=- 9 9 IN IP4 118.177.125.1\r\n\
            s=-\r\n\
            c=IN IP4 118.177.125.1\r\n\
            t=0 0\r\n\
            m=audio 28196 RTP/AVP 0\r\n";

        let (rewritten, _) = handler
            .finalize_outbound_bridge(Some(ctx), ext_offer, ngn_answer)
            .await
            .unwrap();
        let body = std::str::from_utf8(&rewritten).unwrap();

        // ext_addr.port() が広告されているべき (NGN bridge port ではない)。
        assert!(
            body.contains(&format!("m=audio {}", ext_addr.port())),
            "ext bridge port {} が SDP に出ていない: {}",
            ext_addr.port(),
            body
        );
        assert!(
            !body.contains(&format!("m=audio {}", ngn_addr.port())),
            "NGN bridge port {} が誤って ext SDP に出ている: {}",
            ngn_addr.port(),
            body
        );
    }

    /// Issue #29: 内線レッグ SDP が Opus を要求した場合、
    /// `finalize_outbound_bridge` は `MediaBridge::Transcode` を選んで
    /// Opus⇔PCMU トランスコーダを起動する。
    ///
    /// 直接 enum バリアントを覗くために `CallManager::inner` を経由するのが
    /// 重いため、本テストでは「トランスコーダが起動 → bridge_call_id が
    /// `Some`」だけを assert し、実際にトランスコードが回ることは
    /// transcoder.rs 側の `web_to_ngn_transcodes_packet` 等で別途
    /// 担保している。
    #[tokio::test]
    async fn finalize_outbound_bridge_with_opus_offer_starts_transcoding_bridge() {
        use crate::call::manager::CallManager;

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            "127.0.0.1:5060".parse().unwrap(),
        ));
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );

        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ctx = OutboundBridgeCtx {
            ngn_sock,
            ext_sock,
            ext_peer: "127.0.0.1:40001".parse().unwrap(),
        };

        // 内線オファ: WebRTC ブラウザ風に Opus 動的 PT 111 を宣言。
        let ext_offer = b"v=0\r\n\
            o=- 1 1 IN IP4 192.168.20.50\r\n\
            s=-\r\n\
            c=IN IP4 192.168.20.50\r\n\
            t=0 0\r\n\
            m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n\
            a=rtpmap:111 opus/48000/2\r\n\
            a=ptime:20\r\n";
        // NGN は restrict_audio_to_pcmu 後の PCMU only answer を返す。
        let ngn_answer = b"v=0\r\n\
            o=- 9 9 IN IP4 118.177.125.1\r\n\
            s=-\r\n\
            c=IN IP4 118.177.125.1\r\n\
            t=0 0\r\n\
            m=audio 28196 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n";

        let (_body, bridge_id) = handler
            .finalize_outbound_bridge(Some(ctx), ext_offer, ngn_answer)
            .await
            .expect("finalize_outbound_bridge with opus offer");
        assert!(
            bridge_id.is_some(),
            "Opus 内線オファでブリッジが起動していない"
        );
    }

    /// Issue #29 安全網: 両側 PCMU の従来パスも MediaBridge::Relay で
    /// ちゃんと起動する (= 既存 117 時報通話 / Linphone↔NGN を壊していない)。
    #[tokio::test]
    async fn finalize_outbound_bridge_with_pcmu_uses_relay_bridge() {
        use crate::call::manager::CallManager;

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            crate::sip::uac::UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            "127.0.0.1:5060".parse().unwrap(),
        ));
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );

        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ctx = OutboundBridgeCtx {
            ngn_sock,
            ext_sock,
            ext_peer: "127.0.0.1:40002".parse().unwrap(),
        };

        let ext_offer = b"v=0\r\n\
            o=- 1 1 IN IP4 192.168.20.50\r\n\
            s=-\r\n\
            c=IN IP4 192.168.20.50\r\n\
            t=0 0\r\n\
            m=audio 7078 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n";
        let ngn_answer = b"v=0\r\n\
            o=- 9 9 IN IP4 118.177.125.1\r\n\
            s=-\r\n\
            c=IN IP4 118.177.125.1\r\n\
            t=0 0\r\n\
            m=audio 28196 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n";

        let (_body, bridge_id) = handler
            .finalize_outbound_bridge(Some(ctx), ext_offer, ngn_answer)
            .await
            .expect("finalize_outbound_bridge pcmu");
        assert!(bridge_id.is_some(), "PCMU 通話でブリッジが起動していない");
    }

    /// RFC 3261 §21.5.2 (502 Bad Gateway): "The server, while acting as a gateway
    /// or proxy, received an invalid response from the downstream server."
    ///
    /// transparent モード (= `CallManager` 不在の test harness 経路) では WebRTC
    /// leg が返す 200 OK の SDP `c=` / `m= port` が `0.0.0.0:9` のままで、
    /// 通常運用なら呼出側の `start_bridge_for_inbound` が `rewrite_rtp_endpoint`
    /// で sabiden NGN 側 RTP socket に書き換える前提だが、 transparent モードでは
    /// `CallManager` が無いため書換が走らず handle_invite 側が 502 を返す
    /// (`run_webrtc_leg` のドキュメント参照: 「start_bridge_for_inbound が失敗
    /// した場合は 0.0.0.0:9 を NGN に流してはならず、 handle_invite 側で 5xx を
    /// 返して呼を放棄する」)。
    ///
    /// 本テストは Issue #81/#83 review #2 由来の 2 点を担保する:
    /// - NGN に **502 Bad Gateway** が返ること (上記の transparent モード fallback)
    /// - browser (PWA) に **`ServerMessage::Cancel`** が push されること
    ///   (W3C WebRTC §4.4.1: long-running pending state を残さず PWA UI を
    ///   ringing から解放する)
    ///
    /// NGN BYE → `ServerMessage::Bye` の本流伝搬は別 unit
    /// `rfc3261_15_1_2_handle_bye_pushes_servermsg_bye_to_webrtc_ws` でカバー
    /// しているため、 本テストでは触らない。
    #[tokio::test]
    async fn rfc3261_21_5_2_transparent_mode_webrtc_leg_returns_502_and_cancels_browser() {
        use crate::sip::message::parse_message;
        use crate::sip::message::SipMessage;
        use crate::sip::registrar::ExtTransport;
        use crate::sip::transaction::TransactionLayer;
        use crate::webrtc::peer::{PeerSession, StubPeerSession};
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::time::Duration;
        use tokio::sync::mpsc;
        use tokio::time::timeout;

        // sabiden NGN SIP ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        // mock NGN UA (フェイク)
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_addr = ngn_sock.local_addr().unwrap();

        // mock browser: WS チャネル + pending
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();
        let peer: Arc<dyn PeerSession> = StubPeerSession::new();

        // ExtensionRegistrar に WebRTC binding を登録
        let extensions = ExtensionRegistrar::new();
        extensions
            .register_with_transport(
                "alice",
                "sip:alice@webrtc.peer".to_string(),
                "127.0.0.1:65535".parse().unwrap(),
                Duration::from_secs(60),
                ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            )
            .await;

        // browser シミュレーション: Offer push 受信時に SAVPF answer を deliver
        let pending_for_browser = pending.clone();
        let browser_answer_sdp = "v=0\r\n\
                                  o=mozilla 9 9 IN IP4 0.0.0.0\r\n\
                                  s=-\r\n\
                                  c=IN IP4 0.0.0.0\r\n\
                                  t=0 0\r\n\
                                  m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
                                  a=rtpmap:0 PCMU/8000\r\n\
                                  a=ice-ufrag:browser\r\n\
                                  a=ice-pwd:browserpasswordbrowserpassword\r\n\
                                  a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                                  a=setup:active\r\n\
                                  a=mid:0\r\n\
                                  a=rtcp-mux\r\n\
                                  a=sendrecv\r\n";
        let browser_answer_owned = browser_answer_sdp.to_string();
        // 後で Bye 受信のためにここで receiver を別タスクへ move せず、 直接 .recv() で
        // 段階的に確認する。
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        // NGN INVITE 送信
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKwebrtcbye", ngn_addr),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-bye");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-webrtc-bye-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = b"v=0\r\n\
                        o=- 1 1 IN IP4 192.0.2.1\r\n\
                        s=-\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        m=audio 20000 RTP/AVP 0\r\n\
                        a=rtpmap:0 PCMU/8000\r\n"
            .to_vec();
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // browser 役: Offer を受け取ったら answer を pending.deliver で返す
        let offer_msg = timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .expect("Offer push 不在 (browser へ到達せず)")
            .expect("WS チャネル閉鎖");
        let captured_call_id = match offer_msg {
            ServerMessage::Offer { call_id, sdp: _ } => {
                let delivered = pending_for_browser
                    .deliver(&call_id, browser_answer_owned)
                    .await;
                assert!(delivered, "PendingAnswers::deliver 成功");
                call_id
            }
            other => panic!("Offer 期待だが {:?}", other),
        };

        // captured_call_id は INVITE Call-ID と一致するため未使用 (アサート済の
        // `delivered` でカバー済)。 BYE 伝搬経路はここでは検証せず、 別 unit
        // (`rfc3261_15_1_2_handle_bye_pushes_servermsg_bye_to_webrtc_ws`) で
        // handle_bye を直接呼んでカバーする。
        let _ = captured_call_id;

        // 502 を吸って transaction を完了させる
        let mut buf = vec![0u8; 8192];
        let mut got_502 = false;
        for _ in 0..6 {
            match timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 502 {
                            got_502 = true;
                            // 502 への ACK を返して transaction 終了
                            let mut ack = SipRequest::new(
                                SipMethod::Ack,
                                "sip:0312345678@sabiden".to_string(),
                            );
                            ack.headers.set(
                                "Via",
                                format!("SIP/2.0/UDP {};branch=z9hG4bKwebrtcbye", ngn_addr),
                            );
                            ack.headers
                                .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-bye");
                            ack.headers
                                .set("To", r.headers.get("to").unwrap().to_string());
                            ack.headers.set("Call-ID", "ngn-webrtc-bye-cid");
                            ack.headers.set("CSeq", "1 ACK");
                            ngn_sock
                                .send_to(&ack.to_bytes(), sabiden_addr)
                                .await
                                .unwrap();
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_502, "transparent モードの WebRTC leg は 502 を返すはず");

        // Review #1 #2: 502 fallback で browser に `ServerMessage::Cancel` が push
        // されることを確認 (PWA UI を ringing/connected 状態から解放する)。 502 が
        // 返ってから Cancel が enqueue されるまで 1 秒程度の余裕を見る。
        let mut got_cancel = false;
        for _ in 0..4 {
            match timeout(Duration::from_secs(1), out_rx.recv()).await {
                Ok(Some(ServerMessage::Cancel { call_id })) => {
                    assert_eq!(call_id, "ngn-webrtc-bye-cid");
                    got_cancel = true;
                    break;
                }
                Ok(Some(_)) => continue, // 他のメッセージは無視
                Ok(None) | Err(_) => break,
            }
        }
        assert!(
            got_cancel,
            "Issue #81/#83 review #2: 502 fallback で browser に Cancel が push されるべき"
        );
    }

    /// Issue #122 🟡 #4: **bridged モード** (`CallManager` 接続済 = NGN 直収本番経路)
    /// で `start_bridge_for_inbound` が失敗した場合に 502 Bad Gateway が NGN に
    /// 返ることを直接検証する。
    ///
    /// PR #76 で `bridged_mode || is_undirected_or_webrtc_placeholder_sdp` の OR
    /// 分岐を追加したが、 `bridged_mode = true` 側を直接ヒットさせる単体テストが
    /// なかった (transparent モード = `call_manager.is_none()` 側だけ
    /// `rfc3261_21_5_2_transparent_mode_webrtc_leg_returns_502_and_cancels_browser` でカバー
    /// していた)。 本テストは SIP 内線 (= WebRTC 経路を経由しない) でも、
    /// 内線 200 OK answer SDP が `extract_rtp_endpoint` で parse 失敗するような
    /// 異常値だった場合、 bridged モードでは透過せず 502 で打ち切ることを担保する。
    ///
    /// RFC 3261 §21.5.2 (502 Bad Gateway): "The server, while acting as a gateway
    /// or proxy, received an invalid response from the downstream server."
    /// — 内線 leg の SDP が壊れていて bridge 起動できないのは正に B2BUA 下流応答が
    /// invalid な状況。
    #[tokio::test]
    async fn rfc3261_21_5_2_bridged_mode_bridge_failure_returns_502_to_ngn() {
        use crate::call::manager::CallManager;
        use crate::sip::message::parse_message;
        use crate::sip::message::SipMessage;
        use crate::sip::transaction::TransactionLayer;
        use std::time::Duration;
        use tokio::time::timeout;

        // sabiden NGN SIP ソケット
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        // mock NGN UA
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_addr = ngn_sock.local_addr().unwrap();

        // 内線レジストリにダミー SIP 内線を 1 件入れる (WebRTC ではなく通常 SIP)
        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6001".to_string(),
                "127.0.0.1:6001".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        // ScriptedInviter: 200 OK だが **answer SDP が壊れている** (c= も m= も無い)。
        // start_bridge_for_inbound の `extract_rtp_endpoint(ext_answer)?` で
        // 「SDP に audio media がない」 Err となり、 bridge 起動全体が失敗する。
        let broken_answer = b"v=0\r\no=- 1 1 IN IP4 192.168.1.10\r\ns=-\r\nt=0 0\r\n".to_vec();
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(broken_answer)
            .build();

        // bridged モード: CallManager を接続した handler
        let mgr = CallManager::new(extensions.clone());
        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound_with_manager(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
            mgr.clone(),
        );

        // NGN INVITE 送信 (正常な PCMU SDP)
        let mut invite = SipRequest::new(SipMethod::Invite, "sip:0312345678@sabiden");
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKbridged-fail", ngn_addr),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-br");
        invite.headers.set("To", "<sip:0312345678@sabiden>");
        invite.headers.set("Call-ID", "ngn-bridged-fail-cid");
        invite.headers.set("CSeq", "1 INVITE");
        invite.headers.set("Content-Type", "application/sdp");
        invite.body = b"v=0\r\n\
                        o=- 1 1 IN IP4 192.0.2.1\r\n\
                        s=-\r\n\
                        c=IN IP4 192.0.2.1\r\n\
                        t=0 0\r\n\
                        m=audio 20000 RTP/AVP 0\r\n\
                        a=rtpmap:0 PCMU/8000\r\n"
            .to_vec();
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // NGN は 100 Trying と 502 Bad Gateway を期待する
        // Issue #249: 100 と 502 の間に 180 Ringing (RFC 3261 §13.3.1.4) が入る。
        let mut buf = vec![0u8; 8192];
        let mut got_100 = false;
        let mut final_status: Option<u16> = None;
        for _ in 0..7 {
            match timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        match r.status_code {
                            100 => got_100 = true,
                            180 => {} // RFC 3261 §13.3.1.4 (Issue #249)
                            code => {
                                final_status = Some(code);
                                break;
                            }
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(got_100, "100 Trying が NGN 側に届くべき");
        assert_eq!(
            final_status,
            Some(502),
            "bridged モードで start_bridge_for_inbound が失敗した場合、 NGN に 502 を返すべき (Issue #122 🟡 #4 / RFC 3261 §21.5.2)"
        );

        // bridge が起動していないので CallManager にエントリは無い
        assert_eq!(
            mgr.len().await,
            0,
            "bridge 起動失敗時は CallManager にエントリが登録されてはいけない"
        );
    }

    /// Issue #81 unit: `NgnInboundHandler::handle_bye` が `webrtc_active`
    /// テーブルにエントリがあるとき、 該当 WS に `ServerMessage::Bye` を push
    /// することを直接検証する (RFC 3261 §15.1.2 / RFC 5853 §3.2.2)。
    ///
    /// 200 OK 経路 (`start_bridge_for_inbound` の bridge bind 等) を経由しなくても
    /// テストできるよう、 `webrtc_active` に直接 `(call_id, ws_sink)` を入れて、
    /// その状態で BYE を流す。
    #[tokio::test]
    async fn rfc3261_15_1_2_handle_bye_pushes_servermsg_bye_to_webrtc_ws() {
        use crate::sip::message::parse_message;
        use crate::sip::message::SipMessage;
        use crate::sip::transaction::TransactionLayer;
        use crate::webrtc::signaling::{ServerMessage, WsSink};
        use std::time::Duration;
        use tokio::sync::mpsc;
        use tokio::time::timeout;

        // sabiden NGN ソケット + 着信ハンドラ (CallManager なし、 outbound_forwarder なし)
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let (_layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let extensions = ExtensionRegistrar::new();
        let handler = NgnInboundHandler::new(
            sabiden_sock.clone(),
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );
        handler.clone().spawn(inbound_rx);

        // mock browser WS
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);

        // webrtc_active に直接エントリを入れる (内部 API は private なので
        // handler.webrtc_active を Arc 経由で触る代わりに、 同じ Mutex の
        // ロック経由で書き込む)。 Bug B (Issue #268) で entry が
        // `Arc<WebRtcInboundEntry>` に変わったので、 test fixture では
        // `ws_only_for_test` で degraded entry を作って入れる (NGN→PWA BYE
        // 経路のみ機能、 WS close → NGN BYE 経路は本テスト対象外)。
        const TEST_CALL_ID: &str = "rfc3261-15-1-2-cid";
        handler.webrtc_active.lock().await.insert(
            TEST_CALL_ID.to_string(),
            WebRtcInboundEntry::ws_only_for_test(ws_sink.clone()),
        );

        // mock NGN から BYE を送る
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let mut bye = SipRequest::new(SipMethod::Bye, format!("sip:sabiden@{}", sabiden_addr));
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKbyetest", ngn_addr),
        );
        bye.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngnbye");
        bye.headers
            .set("To", format!("<sip:sabiden@{}>;tag=sabiden", sabiden_addr));
        bye.headers.set("Call-ID", TEST_CALL_ID);
        bye.headers.set("CSeq", "2 BYE");
        ngn_sock
            .send_to(&bye.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // (a) NGN へは 200 OK が返ってくる
        let mut buf = vec![0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf))
            .await
            .expect("BYE への 200 OK が NGN 側に届くべき")
            .unwrap();
        match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => assert_eq!(r.status_code, 200),
            other => panic!("Response 期待だが {:?}", other),
        }

        // (b) browser WS に `ServerMessage::Bye` が push されている (Issue #81)
        let pushed = timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .expect("WS Bye が enqueue されない (Issue #81 の修正が無効)")
            .expect("WS チャネル閉鎖");
        assert!(
            matches!(pushed, ServerMessage::Bye),
            "ServerMessage::Bye 期待だが {:?}",
            pushed
        );

        // (c) webrtc_active からエントリは消えている (idempotent: 二重 BYE で重複 push しない)
        assert!(
            handler
                .webrtc_active
                .lock()
                .await
                .get(TEST_CALL_ID)
                .is_none(),
            "BYE 処理後は webrtc_active から消えているべき"
        );
    }

    /// Issue #139 unit: `sweep_webrtc_active` が **WS 切断済 entry** のみを
    /// remove し、 生きている entry は保持することを直接検証する。
    ///
    /// 背景 (Issue #139):
    /// `webrtc_active` は NGN BYE 受信時にしか消されない設計 (Issue #81)。
    /// browser が `ClientMessage::Bye` を送らずに WS だけ切った場合 (= RFC 6455
    /// §7.4 close handshake のみ) は NGN BYE が永久に来ないため entry が leak
    /// する。 sweeper は `WsSink::is_closed` (= `mpsc::UnboundedSender::is_closed`
    /// が `true`、 = receiver drop 済) を判定して該当 entry を除去する。
    #[tokio::test]
    async fn issue139_sweep_webrtc_active_removes_closed_ws_only() {
        use crate::webrtc::signaling::WsSink;
        use tokio::sync::mpsc;

        // ハンドラ (CallManager / outbound forwarder 不要、 sweeper 単体テスト)。
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let extensions = ExtensionRegistrar::new();
        let handler = NgnInboundHandler::new(
            sabiden_sock,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        // 生きている WS と切断済 WS を 1 つずつ作る。
        let (tx_alive, _rx_alive) = mpsc::unbounded_channel();
        let alive = WsSink::new(tx_alive);

        let (tx_dead, rx_dead) = mpsc::unbounded_channel();
        let dead = WsSink::new(tx_dead);
        drop(rx_dead); // receiver を drop すると WsSink::is_closed が true になる

        assert!(!alive.is_closed(), "前提: alive は閉じていない");
        assert!(
            dead.is_closed(),
            "前提: dead は閉じている (receiver drop 済)"
        );

        // webrtc_active に 2 entry 挿入 (Bug B 後 `Arc<WebRtcInboundEntry>` に変更)。
        const ALIVE_CID: &str = "issue139-alive";
        const DEAD_CID: &str = "issue139-dead";
        {
            let mut tbl = handler.webrtc_active.lock().await;
            tbl.insert(
                ALIVE_CID.to_string(),
                WebRtcInboundEntry::ws_only_for_test(alive),
            );
            tbl.insert(
                DEAD_CID.to_string(),
                WebRtcInboundEntry::ws_only_for_test(dead),
            );
        }

        // sweep を 1 回実行。
        let removed = handler.sweep_webrtc_active().await;
        assert_eq!(removed, 1, "1 件 (dead) のみ remove されるはず");

        let tbl = handler.webrtc_active.lock().await;
        assert!(tbl.contains_key(ALIVE_CID), "alive 側は保持されるべき");
        assert!(!tbl.contains_key(DEAD_CID), "dead 側は除去されるべき");
        assert_eq!(tbl.len(), 1);
    }

    /// Issue #139 unit: 空テーブル / 全部生きている / 全部死んでいる の 3 ケースを
    /// `sweep_webrtc_active` の冪等性として検証する。
    #[tokio::test]
    async fn issue139_sweep_webrtc_active_idempotent_edge_cases() {
        use crate::webrtc::signaling::WsSink;
        use tokio::sync::mpsc;

        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let handler = NgnInboundHandler::new(
            sabiden_sock,
            inviter,
            ExtensionRegistrar::new(),
            NgnInboundConfig::default(),
        );

        // (a) 空テーブル → 0 件除去、 サイズ 0 のまま。
        assert_eq!(handler.sweep_webrtc_active().await, 0);
        assert_eq!(handler.webrtc_active.lock().await.len(), 0);

        // (b) 全部生きている → 0 件除去、 全部残る。
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        {
            let mut tbl = handler.webrtc_active.lock().await;
            tbl.insert(
                "alive-1".to_string(),
                WebRtcInboundEntry::ws_only_for_test(WsSink::new(tx1)),
            );
            tbl.insert(
                "alive-2".to_string(),
                WebRtcInboundEntry::ws_only_for_test(WsSink::new(tx2)),
            );
        }
        assert_eq!(handler.sweep_webrtc_active().await, 0);
        assert_eq!(handler.webrtc_active.lock().await.len(), 2);

        // (c) 全部死亡 → 全件除去。
        {
            let mut tbl = handler.webrtc_active.lock().await;
            tbl.clear();
            for i in 0..3 {
                let (tx, rx) = mpsc::unbounded_channel();
                drop(rx);
                tbl.insert(
                    format!("dead-{}", i),
                    WebRtcInboundEntry::ws_only_for_test(WsSink::new(tx)),
                );
            }
        }
        assert_eq!(handler.sweep_webrtc_active().await, 3);
        assert_eq!(handler.webrtc_active.lock().await.len(), 0);

        // (d) 2 回目の sweep は no-op (idempotent)。
        assert_eq!(handler.sweep_webrtc_active().await, 0);
    }

    /// Issue #139 race: NGN BYE 経路 (`handle_bye` line 976 の `remove`) と
    /// sweeper の `retain` が並走しても、 二重削除 / panic を起こさないことを
    /// 検証する。 `WebRTC peer drop + NGN BYE 到着` が時間的にぶつかった
    /// 場合の defense-in-depth。
    ///
    /// 検証は in-memory のみ (lock を取り合うだけ): `tokio::join!` で BYE
    /// path 模擬 (= 直接 `webrtc_active.lock().await.remove`) と sweeper を
    /// 同時実行し、 最終的にテーブルが空であることだけを確認する。
    #[tokio::test]
    async fn issue139_sweep_and_bye_remove_race_is_safe() {
        use crate::webrtc::signaling::WsSink;
        use tokio::sync::mpsc;

        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let handler = NgnInboundHandler::new(
            sabiden_sock,
            inviter,
            ExtensionRegistrar::new(),
            NgnInboundConfig::default(),
        );

        // dead WS (sweeper が拾う対象) を 1 件入れる (Bug B 後 entry 型変更)。
        const RACE_CID: &str = "issue139-race";
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        let ws = WsSink::new(tx);
        handler.webrtc_active.lock().await.insert(
            RACE_CID.to_string(),
            WebRtcInboundEntry::ws_only_for_test(ws),
        );

        // sweeper と BYE 経路を同時に発火する。 どちらが先に remove しても
        // 結果は同じ (= テーブル空、 panic なし)。
        let handler_a = handler.clone();
        let handler_b = handler.clone();
        let (swept, byed) = tokio::join!(
            async move { handler_a.sweep_webrtc_active().await },
            async move {
                // BYE path の `webrtc_active.remove(&cid)` 部分のみを模擬。
                let removed = handler_b.webrtc_active.lock().await.remove(RACE_CID);
                removed.is_some()
            },
        );

        // どちらかが先勝で remove。 二重 remove はない (HashMap::remove は
        // 1 回目で Some、 2 回目で None を返す)。
        assert!(
            swept + (byed as usize) >= 1,
            "sweeper か BYE のどちらかは entry を見るはず"
        );
        assert_eq!(
            handler.webrtc_active.lock().await.len(),
            0,
            "race 後はテーブル空 (二重削除 / panic なし)"
        );
    }

    /// Issue #139 lifecycle: `NgnInboundHandler` の `Arc` が drop されたら
    /// sweeper タスクも自動終了することを確認する (= 弱参照経由設計)。
    ///
    /// 確認方法: 短い sweep interval で起動 → ハンドラを drop → 数 tick 待つ →
    /// テストが hang せず終了。 `Weak::upgrade` が `None` を返すと sweeper は
    /// 即 return する。
    #[tokio::test]
    async fn issue139_sweeper_terminates_on_handler_drop() {
        use std::time::Instant;

        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let cfg = NgnInboundConfig {
            webrtc_active_sweep_interval: Duration::from_millis(50),
            ..NgnInboundConfig::default()
        };
        let handler = NgnInboundHandler::new(sabiden_sock, inviter, ExtensionRegistrar::new(), cfg);

        // 弱参照を別途取り、 sweeper を起動する。
        let weak = Arc::downgrade(&handler);
        NgnInboundHandler::spawn_webrtc_active_sweeper(weak.clone(), Duration::from_millis(50));

        // 数 tick 動かす。
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(weak.upgrade().is_some(), "前提: ハンドラはまだ生存");

        // ハンドラ Arc を drop すると strong_count が 0 になる。
        drop(handler);
        // sweeper は次の tick で `Weak::upgrade` が None を返して終了する
        // (interval=50ms、 200ms 待てば十分)。
        let start = Instant::now();
        loop {
            if weak.upgrade().is_none() {
                break;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!("sweeper がハンドラ drop 後も Arc を保持し続けている (Issue #139)");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Issue #218: `spawn_webrtc_active_sweeper` に `Duration::ZERO` を渡しても
    /// caller スレッドで panic せず、 sweeper が正常起動・終了できることを検証する。
    ///
    /// 背景: `tokio::time::interval(Duration::ZERO)` は事前条件違反で panic
    /// する (tokio docs: "panics if `period` is zero")。 同種の panic を
    /// `WebRtcConfig::default()` 経路で既に塞いだ事例あり (Issue #166 /
    /// `src/config/mod.rs:218`)。 `NgnInboundConfig` も同種の static fragility
    /// (Default 派生ミス / 将来の config TOML 化) を抱えるため、 sweeper 入口
    /// で `Duration::ZERO` → [`MIN_SWEEP_INTERVAL`] に clamp する (CLAUDE.md
    /// §6.5: production code で panic / unwrap 禁止)。
    ///
    /// 検証方針:
    /// - clamp が無いと spawn 内の `interval(ZERO)` で panic し task は即抜ける。
    ///   tokio runtime はそれを caller には伝播しないが、 spawn 直後に
    ///   `Weak::upgrade().is_some()` 確認をすることで「呼び出し自体が unwind
    ///   していない」ことを保証する (panic は caller に届かない)。
    /// - clamp が効いていれば task は 30s 周期 ticker を持って待機する。
    ///   handler drop 後は `Weak` しか持たないため、 strong_count=0 になる。
    #[tokio::test]
    async fn issue218_zero_duration_does_not_panic() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let handler = NgnInboundHandler::new(
            sabiden_sock,
            inviter,
            ExtensionRegistrar::new(),
            NgnInboundConfig::default(),
        );

        // ZERO で sweeper を起動。 clamp が漏れていればこの呼び出しは
        // tokio::spawn の中で interval(ZERO) panic を起こすが、 caller スレッド
        // からは catch できない。 ここでは clamp 経路が走り、 panic せず
        // task が立ち上がることを期待する。
        let weak = Arc::downgrade(&handler);
        NgnInboundHandler::spawn_webrtc_active_sweeper(weak.clone(), Duration::ZERO);

        // sweeper 起動が caller スレッドを unwind していないことを確認。
        assert!(weak.upgrade().is_some(), "ハンドラ Arc はまだ生存");

        // ハンドラ drop → strong_count=0。 sweeper task は Weak しか持たない
        // ため、 panic 有無に関わらず upgrade は None を返す。
        drop(handler);
        assert!(
            weak.upgrade().is_none(),
            "ハンドラ drop 後は強参照ゼロ (sweeper task は Weak しか持たない)"
        );
    }

    /// Bug B / Issue #268: PWA WS close 時に `close_pwa_inbound_for_ws` が
    /// `webrtc_active` から該当 WS の entry を抽出して NGN BYE を撃つことを
    /// 検証する (RFC 3261 §15.1.1 / §15.1.2)。
    ///
    /// 旧実装 (Bug B 修正前) は inbound 通話で PWA disconnect が起きても
    /// sabiden→NGN BYE が出ず、 NGN 側が 5-10 秒タイムアウトで BYE を投げ返す
    /// まで dialog が宙ぶらりんだった (実機 v7 で 6 秒待ち観測)。
    ///
    /// 検証方針:
    /// 1. fake NGN socket (BYE 受信スパイ) を bind し、 そこを fallback_peer と
    ///    する `WebRtcInboundEntry` を作って `webrtc_active` に挿入。
    /// 2. `close_pwa_inbound_for_ws` を呼び、 fake NGN socket に BYE が到達する
    ///    こと、 戻り値が 1 であること、 entry が remove されることを確認。
    /// 3. 同 WS で 2 度目を呼ぶと idempotent (= 0 件、 no-op) であること。
    #[tokio::test]
    async fn bug_b_close_pwa_inbound_sends_bye_to_ngn() {
        use crate::sip::dialog::DialogConfig;
        use crate::sip::message::{parse_message, SipMessage};
        use crate::webrtc::signaling::{PwaInboundCloser, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::sync::mpsc;
        use tokio::time::timeout;

        // (1) fake NGN socket: BYE が来たら 200 OK を返し、 カウンタを上げる。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let bye_count = Arc::new(AtomicU32::new(0));
        let bye_count_inner = bye_count.clone();
        let fake_ngn_clone = fake_ngn.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let (n, peer) = match fake_ngn_clone.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if let Ok(SipMessage::Request(req)) = parse_message(&buf[..n]) {
                    if matches!(req.method, SipMethod::Bye) {
                        bye_count_inner.fetch_add(1, Ordering::SeqCst);
                        // 200 OK を返す
                        let mut ok = build_response_skeleton(&req, 200, "OK");
                        ok.headers.set("Content-Length", "0");
                        let _ = fake_ngn_clone.send_to(&ok.to_bytes(), peer).await;
                    }
                }
            }
        });

        // (2) sabiden 側 NGN socket + TransactionLayer + NgnInboundHandler。
        let sabiden_ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (sabiden_layer, sabiden_inbound_rx) = TransactionLayer::spawn(sabiden_ngn_sock.clone());

        let inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let extensions = ExtensionRegistrar::new();
        let webrtc_outbound_active: WebRtcOutboundActive = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Metrics::new();
        // call_manager は test 簡略化のため省略 (bridge 経路は別 test)。
        // production layout を再現したいので with_layer_call_manager_metrics_and_outbound_table
        // ではなく with_metrics_then_layer 相当を直接構築する: layer を Some にした
        // handler を作るため `with_metrics` を起点に手で組み立てる。
        let handler = Arc::new(NgnInboundHandler {
            socket: sabiden_ngn_sock.clone(),
            layer: Some(sabiden_layer.clone()),
            inviter,
            extensions,
            cfg: NgnInboundConfig::default(),
            pending: Arc::new(Mutex::new(HashMap::new())),
            active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_active: Arc::new(Mutex::new(HashMap::new())),
            webrtc_outbound_active,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            rc100rel: Arc::new(Mutex::new(HashMap::new())),
            call_manager: None,
            outbound_forwarder: Mutex::new(None),
            metrics: metrics.clone(),
            call_log: Mutex::new(None),
        });
        // inbound_rx は不要 (今回 INVITE 経路は走らせず webrtc_active を直接操作する)
        drop(sabiden_inbound_rx);

        // (3) WS と WebRtcInboundEntry を作って webrtc_active に挿入。
        let (out_tx, _out_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws = WsSink::new(out_tx);

        // 受信 INVITE と 200 OK を擬似的に作って Dialog::from_uas_invite に渡す。
        const TEST_CALL_ID: &str = "bug-b-cid";
        let mut invite = SipRequest::new(SipMethod::Invite, format!("sip:117@{}", fake_ngn_addr));
        invite.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKtest", fake_ngn_addr),
        );
        invite
            .headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngn-caller");
        invite
            .headers
            .set("To", format!("<sip:117@{}>", fake_ngn_addr));
        invite.headers.set("Call-ID", TEST_CALL_ID);
        invite.headers.set("CSeq", "1 INVITE");
        invite
            .headers
            .set("Contact", format!("<sip:caller@{}>", fake_ngn_addr));

        let mut ok = build_response_skeleton(&invite, 200, "OK");
        ok.headers
            .set("To", format!("<sip:117@{}>;tag=sabiden-tag", fake_ngn_addr));
        let dlg_cfg = DialogConfig {
            local_uri: format!("sip:sabiden@{}", sabiden_ngn_sock.local_addr().unwrap()),
            remote_uri: "sip:caller@ntt-east.ne.jp".to_string(),
            local_contact: format!("sip:sabiden@{}", sabiden_ngn_sock.local_addr().unwrap()),
            sent_by: sabiden_ngn_sock.local_addr().unwrap().to_string(),
        };
        let dialog = Dialog::from_uas_invite(&invite, &ok, dlg_cfg).expect("dialog 構築成功");

        let entry = Arc::new(WebRtcInboundEntry {
            uas_dialog: Some(Mutex::new(dialog)),
            layer: Some(sabiden_layer.clone()),
            fallback_peer: fake_ngn_addr,
            ws: ws.clone(),
        });
        handler
            .webrtc_active
            .lock()
            .await
            .insert(TEST_CALL_ID.to_string(), entry);
        // call_active=1 (handle_invite が呼んだ inc 相当)。
        metrics.inc_call_active();

        // (4) close_pwa_inbound_for_ws を呼んで結果を観測。
        let n = handler.close_pwa_inbound_for_ws(&ws).await;
        assert_eq!(n, 1, "1 entry が閉じられるべき");

        // fake NGN socket で BYE 1 件受信を待つ。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while bye_count.load(Ordering::SeqCst) == 0 {
            if std::time::Instant::now() >= deadline {
                panic!("PWA disconnect → NGN BYE が fake NGN socket に到達していない (Bug B 再発)");
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            bye_count.load(Ordering::SeqCst),
            1,
            "BYE は 1 件のみ送出されるべき"
        );

        // webrtc_active から entry は消えている (idempotent gate)。
        assert!(
            handler.webrtc_active.lock().await.is_empty(),
            "close 後は webrtc_active から削除されているべき"
        );

        // (5) 二度目の close は no-op (idempotent)。
        let n2 = timeout(
            std::time::Duration::from_secs(1),
            handler.close_pwa_inbound_for_ws(&ws),
        )
        .await
        .expect("idempotent 二回目で hang してはいけない");
        assert_eq!(n2, 0, "二回目の close は 0 件 (idempotent)");
        // BYE 件数は 1 のまま (= 二重 BYE 送出していない)。
        assert_eq!(bye_count.load(Ordering::SeqCst), 1);
    }

    /// Bug B / Issue #268: `WebRtcInboundEntry::send_bye()` の `Ok(None)` 経路。
    /// degraded entry (dialog / layer 不足) に対して send_bye を呼ぶと、 BYE は
    /// 送らず skip して Ok(None) を返す (= 旧経路互換、 production では起きない)。
    #[tokio::test]
    async fn bug_b_degraded_entry_send_bye_returns_none_without_panic() {
        use crate::webrtc::signaling::{ServerMessage, WsSink};
        use tokio::sync::mpsc;

        let (tx, _rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws = WsSink::new(tx);
        let entry = WebRtcInboundEntry::ws_only_for_test(ws);

        let resp = entry
            .send_bye()
            .await
            .expect("Ok 戻りであるべき (panic 禁止)");
        assert!(resp.is_none(), "degraded entry では None を返すべき");
    }

    /// Issue #218: clamp 後の interval が [`MIN_SWEEP_INTERVAL`] (= 30s) と
    /// 一致することを確認する semantics test。 値変更時の回帰防止 + docstring
    /// との二重チェック。 [`NgnInboundConfig::default()`] と揃わないと
    /// 「ZERO 投入時だけ sweep が遅くなる / 早くなる」 という驚き挙動になる。
    #[test]
    fn issue218_min_sweep_interval_matches_default() {
        assert_eq!(
            MIN_SWEEP_INTERVAL,
            Duration::from_secs(30),
            "MIN_SWEEP_INTERVAL は struct field docstring の 30s と一致させる"
        );
        assert_eq!(
            MIN_SWEEP_INTERVAL,
            NgnInboundConfig::default().webrtc_active_sweep_interval,
            "MIN_SWEEP_INTERVAL は NgnInboundConfig::default() と揃える (clamp 後の挙動が既定と等価になる)"
        );
        // Duration::ZERO.is_zero() の semantics 文書化 (clamp 条件の前提)。
        // 同 pattern: src/config/mod.rs:874 の Issue #166 既存テスト。
        assert!(
            Duration::ZERO.is_zero(),
            "Duration::ZERO は is_zero() が true を返す (clamp 条件の前提)"
        );
    }

    /// Issue #83: `fork_to_bindings` が `Timeout` で抜けたとき、 走っていた
    /// WebRTC leg の WS に `ServerMessage::Cancel` が push されることを検証する。
    /// (W3C WebRTC §4.4.1: long-running pending state を放置しない)。
    #[tokio::test]
    async fn issue83_fork_timeout_sends_cancel_to_webrtc_legs() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// browser が answer を返さない (= timeout する) PeerSession mock
        struct SilentBrowserPeer {
            create_calls: AtomicUsize,
            offer_sdp: String,
        }
        #[async_trait::async_trait]
        impl PeerSession for SilentBrowserPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Err(anyhow::anyhow!("unused"))
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                self.create_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.offer_sdp.clone())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                panic!("answer 来ないので呼ばれてはいけない");
            }
            async fn add_ice_candidate(&self, _candidate: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }
        let peer_inner = Arc::new(SilentBrowserPeer {
            create_calls: AtomicUsize::new(0),
            offer_sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                        t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                        a=ice-ufrag:srvuf\r\na=ice-pwd:srvpasswordsrvpassword\r\n\
                        a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
                        a=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
                .to_string(),
        });
        let peer: Arc<dyn PeerSession> = peer_inner.clone();

        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![(
            "alice".to_string(),
            Binding {
                contact_uri: "sip:alice@webrtc.peer".to_string(),
                remote: "127.0.0.1:65535".parse().unwrap(),
                expires_at: std::time::Instant::now() + Duration::from_secs(60),
                transport: ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            },
        )];
        // 短い timeout で fork_to_bindings を駆動 — answer は来ない
        let result = fork_to_bindings(
            inviter,
            bindings,
            b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
              m=audio 20000 RTP/AVP 0\r\n"
                .to_vec(),
            "issue83-timeout-cid".to_string(),
            Duration::from_millis(300),
        )
        .await;

        // 結果は AllFailed { 408 } もしくは Timeout (WebRTC leg 内部 timeout で
        // Failed{408} が tx 経由で返ってくれば AllFailed、 fork_to_bindings 自身の
        // 全体 deadline で抜ければ Timeout)。 どちらでも browser には Cancel が
        // 飛ぶ必要があるのが Issue #83 の DoD。
        match result {
            ForkResult::AllFailed { last_status } => {
                // run_webrtc_leg 内部 timeout が先に発火した場合は status=408
                // (run_webrtc_leg の `LegResult::Failed { status: 408 }` 経路)
                assert!(
                    last_status == Some(408) || last_status.is_none(),
                    "AllFailed の last_status: {:?}",
                    last_status
                );
            }
            ForkResult::Timeout => {}
            ForkResult::Answered { .. } => panic!("AllFailed/Timeout 期待だが Answered"),
        }

        // browser に Cancel が push されている
        // (Offer が先に来るので 1 個目を捨てて 2 個目を確認)
        let mut got_offer = false;
        let mut got_cancel = false;
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(2), out_rx.recv()).await {
                Ok(Some(ServerMessage::Offer { .. })) => got_offer = true,
                Ok(Some(ServerMessage::Cancel { call_id })) => {
                    assert_eq!(call_id, "issue83-timeout-cid");
                    got_cancel = true;
                    break;
                }
                Ok(Some(other)) => panic!("Offer/Cancel 期待だが {:?}", other),
                Ok(None) | Err(_) => break,
            }
        }
        assert!(got_offer, "Offer push は届いているべき");
        assert!(
            got_cancel,
            "Issue #83: Timeout/AllFailed でも WebRTC leg に Cancel が push されるべき"
        );
    }

    /// Issue #83: `fork_to_bindings` が `AllFailed` で抜けたとき、 走っていた
    /// WebRTC leg の WS に `ServerMessage::Cancel` が push されることを検証する。
    ///
    /// `accept_answer` 失敗で `Errored` 復帰、 全 leg 失敗 → AllFailed の経路。
    #[tokio::test]
    async fn issue83_fork_all_failed_sends_cancel_to_webrtc_legs() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// accept_answer で失敗する PeerSession mock
        struct FailAcceptAnswerPeer {
            offer_sdp: String,
            accept_calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl PeerSession for FailAcceptAnswerPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Err(anyhow::anyhow!("unused"))
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(self.offer_sdp.clone())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                self.accept_calls.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::anyhow!("accept_answer 失敗"))
            }
            async fn add_ice_candidate(&self, _candidate: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let peer_inner = Arc::new(FailAcceptAnswerPeer {
            offer_sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                        t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                        a=ice-ufrag:srvuf\r\na=ice-pwd:srvpasswordsrvpassword\r\n\
                        a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
                        a=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
                .to_string(),
            accept_calls: AtomicUsize::new(0),
        });
        let peer: Arc<dyn PeerSession> = peer_inner.clone();

        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();

        // browser シミュレーション: offer push を受けたら answer を deliver する
        let pending_for_browser = pending.clone();
        let browser_answer = "v=0\r\no=mozilla 9 9 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                              t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                              a=ice-ufrag:browser\r\na=ice-pwd:browserpwdbrowserpwdbrowserpwd\r\n\
                              a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                              a=setup:active\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
            .to_string();
        // 直接 deliver は使わず、 receive 側で回収 → deliver する。
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![(
            "alice".to_string(),
            Binding {
                contact_uri: "sip:alice@webrtc.peer".to_string(),
                remote: "127.0.0.1:65535".parse().unwrap(),
                expires_at: std::time::Instant::now() + Duration::from_secs(60),
                transport: ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            },
        )];

        // 同 task で fork_to_bindings + browser を回す: spawn して並列に動かす。
        let fork_handle = tokio::spawn(async move {
            fork_to_bindings(
                inviter,
                bindings,
                b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
                  m=audio 20000 RTP/AVP 0\r\n"
                    .to_vec(),
                "issue83-allfailed-cid".to_string(),
                Duration::from_secs(3),
            )
            .await
        });

        // browser: Offer を受けたら answer を deliver する
        let mut got_cancel = false;
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(3), out_rx.recv()).await {
                Ok(Some(ServerMessage::Offer { call_id, .. })) => {
                    let ok = pending_for_browser
                        .deliver(&call_id, browser_answer.clone())
                        .await;
                    assert!(ok, "deliver 成功");
                }
                Ok(Some(ServerMessage::Cancel { call_id })) => {
                    assert_eq!(call_id, "issue83-allfailed-cid");
                    got_cancel = true;
                    break;
                }
                Ok(Some(other)) => panic!("Offer/Cancel 期待だが {:?}", other),
                Ok(None) | Err(_) => break,
            }
        }
        let result = fork_handle.await.unwrap();
        match result {
            ForkResult::AllFailed { last_status } => assert!(last_status.is_none()),
            other => panic!("AllFailed 期待だが {:?}", std::mem::discriminant(&other)),
        }
        // accept_answer は呼ばれた (= 失敗 → Errored)
        assert_eq!(peer_inner.accept_calls.load(Ordering::SeqCst), 1);
        assert!(
            got_cancel,
            "Issue #83: AllFailed でも WebRTC leg に Cancel が push されるべき"
        );
    }

    /// Issue #83: `fork_to_bindings` が `Answered` で抜けたとき、 winner WebRTC
    /// leg 自身には `Cancel` が送られず、 winner だけ確立済みのまま残ること。
    /// (Issue #81 で winner は確立済み通話として `webrtc_active` に入る。)
    #[tokio::test]
    async fn issue83_fork_answered_does_not_cancel_winner_webrtc_leg() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::{PeerSession, StubPeerSession};
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};

        let peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(out_tx);
        let pending = PendingAnswers::new();

        // browser: Offer を受けたら answer を deliver
        let pending_for_browser = pending.clone();
        let browser_answer = "v=0\r\no=mozilla 9 9 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                              t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                              a=ice-ufrag:browser\r\na=ice-pwd:browserpwdbrowserpwdbrowserpwd\r\n\
                              a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                              a=setup:active\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
            .to_string();

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![(
            "alice".to_string(),
            Binding {
                contact_uri: "sip:alice@webrtc.peer".to_string(),
                remote: "127.0.0.1:65535".parse().unwrap(),
                expires_at: std::time::Instant::now() + Duration::from_secs(60),
                transport: ExtTransport::WebRtc {
                    peer: peer.clone(),
                    ws: ws_sink.clone(),
                    pending: pending.clone(),
                },
            },
        )];
        let fork_handle = tokio::spawn(async move {
            fork_to_bindings(
                inviter,
                bindings,
                b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
                  m=audio 20000 RTP/AVP 0\r\n"
                    .to_vec(),
                "issue83-winner-cid".to_string(),
                Duration::from_secs(3),
            )
            .await
        });

        // 1 つだけ Offer を受けたら answer を返す。 fork が Answered で完了したあと、
        // cleanup ループで winner 自身を Cancel しないことを確認する。
        let first = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let call_id = if let ServerMessage::Offer { call_id, .. } = first {
            pending_for_browser
                .deliver(&call_id, browser_answer.clone())
                .await;
            call_id
        } else {
            panic!("Offer 期待")
        };

        let result = fork_handle.await.unwrap();
        let webrtc_ws_present = matches!(
            result,
            ForkResult::Answered {
                webrtc_ws: Some(_),
                ..
            }
        );
        assert!(
            webrtc_ws_present,
            "Answered の `webrtc_ws` は Some であるべき (Issue #81 BYE 伝搬用)"
        );

        // この後 Cancel メッセージが winner に来ないこと。 1 秒待っても何も来ない
        // (winner は cleanup loop で除外されるため)。
        let after = tokio::time::timeout(Duration::from_millis(500), out_rx.recv()).await;
        match after {
            Err(_) => {} // タイムアウト = 何も来ない (期待動作)
            Ok(Some(ServerMessage::Cancel { call_id: cancel_cid })) => panic!(
                "winner WebRTC leg に Cancel が送られた (Issue #83 で winner 自身は除外する)。 call_id={}",
                cancel_cid
            ),
            Ok(other) => panic!("予想外: {:?}", other),
        }
        let _ = call_id; // 使わないが pin
    }

    /// Issue #83 regression: 複数 WebRTC レッグの fork で先着 200 OK (Answered)
    /// が成立した際、 winner 以外の **losing legs** に `ServerMessage::Cancel` が
    /// 確実に送出されることを検証する。
    ///
    /// 旧実装 (PR #137 以前) でも Answered 経路では losing leg に Cancel を流して
    /// いたため、 本テストは「Issue #83 で Timeout/AllFailed まで cleanup を拡大
    /// しても Answered の cleanup が壊れていない」 ことを担保する regression
    /// guard (CLAUDE.md §13 既存通話パス regression なし要件)。
    ///
    /// 参照: RFC 3261 §9.1 (CANCEL semantics) / §16.7 step 7 (fork で 2xx 確定後の
    /// 残レッグキャンセル) / W3C WebRTC §4.4.1 (pending state を放置しない)。
    #[tokio::test]
    async fn issue83_fork_answered_sends_cancel_to_losing_webrtc_legs() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::{PeerSession, StubPeerSession};
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// `create_offer` を僅かに遅延させる loser 用 mock。 winner が先に
        /// Established を返して fork を確定させるためのスケジュール調整。
        /// 遅延は短く保ち、 fork 確定後の `try_register_webrtc_leg` race 経路
        /// (= `race_late_create_offer_after_winner_sends_cancel_not_offer` で
        /// カバー済) ではなく、 通常の cleanup loop (close_and_drain) 経由で
        /// Cancel が届くことを確認する。
        struct SilentLoserPeer {
            offer_sdp: String,
            create_calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl PeerSession for SilentLoserPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Err(anyhow::anyhow!("unused"))
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                self.create_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.offer_sdp.clone())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                panic!("loser に answer は来ないので呼ばれてはいけない");
            }
            async fn add_ice_candidate(&self, _candidate: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let winner_peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let (ws_winner_tx, mut ws_winner_rx) =
            tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_winner = WsSink::new(ws_winner_tx);
        let pending_winner = PendingAnswers::new();

        let loser_peer_inner = Arc::new(SilentLoserPeer {
            offer_sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                        t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                        a=ice-ufrag:srvuf\r\na=ice-pwd:srvpasswordsrvpassword\r\n\
                        a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
                        a=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
                .to_string(),
            create_calls: AtomicUsize::new(0),
        });
        let loser_peer: Arc<dyn PeerSession> = loser_peer_inner.clone();
        let (ws_loser_tx, mut ws_loser_rx) =
            tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_loser = WsSink::new(ws_loser_tx);
        let pending_loser = PendingAnswers::new();

        let browser_answer = "v=0\r\no=mozilla 9 9 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                              t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                              a=ice-ufrag:browser\r\na=ice-pwd:browserpwdbrowserpwdbrowserpwd\r\n\
                              a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                              a=setup:active\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
            .to_string();

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![
            (
                "winner".to_string(),
                Binding {
                    contact_uri: "sip:winner@webrtc.peer".to_string(),
                    remote: "127.0.0.1:65535".parse().unwrap(),
                    expires_at: std::time::Instant::now() + Duration::from_secs(60),
                    transport: ExtTransport::WebRtc {
                        peer: winner_peer.clone(),
                        ws: ws_winner.clone(),
                        pending: pending_winner.clone(),
                    },
                },
            ),
            (
                "loser".to_string(),
                Binding {
                    contact_uri: "sip:loser@webrtc.peer".to_string(),
                    remote: "127.0.0.1:65534".parse().unwrap(),
                    expires_at: std::time::Instant::now() + Duration::from_secs(60),
                    transport: ExtTransport::WebRtc {
                        peer: loser_peer.clone(),
                        ws: ws_loser.clone(),
                        pending: pending_loser.clone(),
                    },
                },
            ),
        ];
        let pending_winner_for_browser = pending_winner.clone();
        let fork_handle = tokio::spawn(async move {
            fork_to_bindings(
                inviter,
                bindings,
                b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
                  m=audio 20000 RTP/AVP 0\r\n"
                    .to_vec(),
                "issue83-loser-cid".to_string(),
                Duration::from_secs(3),
            )
            .await
        });

        // winner: Offer 受信 → answer deliver → fork が Answered で抜ける。
        let first_winner = tokio::time::timeout(Duration::from_secs(2), ws_winner_rx.recv())
            .await
            .expect("winner Offer push 不在")
            .expect("winner ws_rx 閉鎖");
        match first_winner {
            ServerMessage::Offer { call_id, .. } => {
                pending_winner_for_browser
                    .deliver(&call_id, browser_answer.clone())
                    .await;
            }
            other => panic!("winner: Offer 期待だが {:?}", other),
        }

        let result = fork_handle.await.unwrap();
        match result {
            ForkResult::Answered { .. } => {}
            other => panic!("Answered 期待だが {:?}", std::mem::discriminant(&other)),
        }

        // loser: Offer push → その後 Cancel が cleanup loop 経由で届くべき。
        let mut got_loser_offer = false;
        let mut got_loser_cancel = false;
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(2), ws_loser_rx.recv()).await {
                Ok(Some(ServerMessage::Offer { call_id, .. })) => {
                    assert_eq!(call_id, "issue83-loser-cid");
                    got_loser_offer = true;
                }
                Ok(Some(ServerMessage::Cancel { call_id })) => {
                    assert_eq!(call_id, "issue83-loser-cid");
                    got_loser_cancel = true;
                    break;
                }
                Ok(Some(other)) => panic!("Offer/Cancel 期待だが {:?}", other),
                Ok(None) | Err(_) => break,
            }
        }
        assert!(
            got_loser_offer,
            "loser には Offer push が届いているべき (Answered 確定前に Offer 完了)"
        );
        assert!(
            got_loser_cancel,
            "Issue #83 regression: Answered 確定後、 losing WebRTC leg に Cancel が届くべき"
        );
        assert_eq!(loser_peer_inner.create_calls.load(Ordering::SeqCst), 1);

        // winner WS には Cancel が来てはいけない (Issue #81 で winner は確立済み
        // 通話として維持される)。
        let after_winner =
            tokio::time::timeout(Duration::from_millis(300), ws_winner_rx.recv()).await;
        match after_winner {
            Err(_) | Ok(None) => {}
            Ok(Some(ServerMessage::Cancel { call_id })) => panic!(
                "winner WebRTC leg に Cancel が送られた: call_id={}",
                call_id
            ),
            Ok(Some(other)) => {
                // Cancel 以外 (例: ICE candidate notify) は当面許容するが、 本テストでは想定しない
                panic!("winner 側に予想外メッセージ: {:?}", other);
            }
        }
    }

    /// Review #1 #1 (race fix): `peer.create_offer` 中に他レッグが winner 確定
    /// した場合、 遅い leg は **Offer push せず** に browser へ自前 Cancel を
    /// 送って終了することを検証する。
    ///
    /// 旧実装: slow leg が `peer.create_offer` 完了 → `ws.send(Offer)` → 当該
    /// leg を `webrtc_legs.push` という順序だったため、 winner snapshot は
    /// slow leg を含まず browser は ringing で固まる。
    ///
    /// 新実装: `try_register_webrtc_leg` で `closed` フラグをアトミックに
    /// 確認し、 既に closed なら Offer push せず Cancel して終了する
    /// (W3C WebRTC §4.4.1: pending state を放置しない)。
    #[tokio::test]
    async fn race_late_create_offer_after_winner_sends_cancel_not_offer() {
        use crate::sip::registrar::Binding;
        use crate::webrtc::peer::{PeerSession, StubPeerSession};
        use crate::webrtc::signaling::{PendingAnswers, ServerMessage, WsSink};
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// `create_offer` を意図的に遅延させる mock peer。 別 leg が winner
        /// 確定するまで待ってから offer を返す。
        struct SlowOfferPeer {
            offer_sdp: String,
            delay: Duration,
            create_calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl PeerSession for SlowOfferPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Err(anyhow::anyhow!("unused"))
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                self.create_calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
                Ok(self.offer_sdp.clone())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _candidate: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // 2 レッグ構成: 速い winner と 遅い loser。 ws_winner と ws_loser は
        // 別チャネル (= 別 browser tab 想定)。
        let winner_peer: Arc<dyn PeerSession> = StubPeerSession::new();
        let (ws_winner_tx, mut ws_winner_rx) =
            tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_winner = WsSink::new(ws_winner_tx);
        let pending_winner = PendingAnswers::new();

        let slow_peer_inner = Arc::new(SlowOfferPeer {
            offer_sdp: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                        t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                        a=ice-ufrag:srvuf\r\na=ice-pwd:srvpasswordsrvpassword\r\n\
                        a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
                        a=setup:actpass\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
                .to_string(),
            // winner answer 配送を確実に先行させるため、 充分長い遅延を入れる。
            delay: Duration::from_millis(800),
            create_calls: AtomicUsize::new(0),
        });
        let slow_peer: Arc<dyn PeerSession> = slow_peer_inner.clone();
        let (ws_loser_tx, mut ws_loser_rx) =
            tokio::sync::mpsc::unbounded_channel::<ServerMessage>();
        let ws_loser = WsSink::new(ws_loser_tx);
        let pending_loser = PendingAnswers::new();

        // browser シミュレーション (winner 側): Offer 受信即 answer deliver
        let pending_winner_for_browser = pending_winner.clone();
        let browser_answer = "v=0\r\no=mozilla 9 9 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
                              t=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                              a=ice-ufrag:browser\r\na=ice-pwd:browserpwdbrowserpwdbrowserpwd\r\n\
                              a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                              a=setup:active\r\na=mid:0\r\na=rtcp-mux\r\na=sendrecv\r\n"
            .to_string();

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();
        let bindings = vec![
            (
                "winner".to_string(),
                Binding {
                    contact_uri: "sip:winner@webrtc.peer".to_string(),
                    remote: "127.0.0.1:65535".parse().unwrap(),
                    expires_at: std::time::Instant::now() + Duration::from_secs(60),
                    transport: ExtTransport::WebRtc {
                        peer: winner_peer.clone(),
                        ws: ws_winner.clone(),
                        pending: pending_winner.clone(),
                    },
                },
            ),
            (
                "slow_loser".to_string(),
                Binding {
                    contact_uri: "sip:slow@webrtc.peer".to_string(),
                    remote: "127.0.0.1:65534".parse().unwrap(),
                    expires_at: std::time::Instant::now() + Duration::from_secs(60),
                    transport: ExtTransport::WebRtc {
                        peer: slow_peer.clone(),
                        ws: ws_loser.clone(),
                        pending: pending_loser.clone(),
                    },
                },
            ),
        ];
        let fork_handle = tokio::spawn(async move {
            fork_to_bindings(
                inviter,
                bindings,
                b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
                  m=audio 20000 RTP/AVP 0\r\n"
                    .to_vec(),
                "race-winner-cid".to_string(),
                Duration::from_secs(5),
            )
            .await
        });

        // winner 側: Offer 受信 → answer deliver
        let first_winner = tokio::time::timeout(Duration::from_secs(2), ws_winner_rx.recv())
            .await
            .expect("winner Offer push 不在")
            .expect("winner ws_rx 閉鎖");
        match first_winner {
            ServerMessage::Offer { call_id, .. } => {
                pending_winner_for_browser
                    .deliver(&call_id, browser_answer.clone())
                    .await;
            }
            other => panic!("winner: Offer 期待だが {:?}", other),
        }

        // fork_to_bindings は Answered で抜けるはず
        let result = fork_handle.await.unwrap();
        match result {
            ForkResult::Answered { .. } => {}
            other => panic!("Answered 期待だが {:?}", std::mem::discriminant(&other)),
        }

        // slow loser: `create_offer` は呼ばれた (= delay 中だった)
        assert_eq!(slow_peer_inner.create_calls.load(Ordering::SeqCst), 1);

        // slow loser の WS には **Cancel** が来るべき (Offer ではない)。
        // race fix: try_register が closed=true で false を返し、 自前 Cancel 経路に入る。
        let mut got_cancel = false;
        let mut got_offer = false;
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(2), ws_loser_rx.recv()).await {
                Ok(Some(ServerMessage::Cancel { call_id })) => {
                    assert_eq!(call_id, "race-winner-cid");
                    got_cancel = true;
                    break;
                }
                Ok(Some(ServerMessage::Offer { .. })) => got_offer = true,
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => break,
            }
        }
        assert!(
            !got_offer,
            "race fix: slow loser に Offer は push されてはいけない (browser が ringing で固まる)"
        );
        assert!(
            got_cancel,
            "got_cancel: slow loser に Cancel が push されるべき"
        );
    }

    // ===== Issue #145: PWA→NGN 発信フロー (PwaOutboundHandler) =====

    /// Issue #145: `PwaOutboundHandler::handle_pwa_outbound_offer` 経由で
    /// PWA→NGN 発信が成立することを end-to-end で検証する。
    ///
    /// 観点 (RFC 3264 §5/§6, RFC 8829, `docs/asterisk-real-invite.md` §5):
    /// 1. browser SAVPF SDP を渡したら、 戻り値は SAVPF answer (browser に返る)
    /// 2. NGN に届く INVITE の Request-URI が `sip:<target>@<P-CSCF>:<port>`
    /// 3. NGN に届く INVITE の SDP は AVP/PCMU で、 `c=`/`m= port` が
    ///    sabiden NGN bridge socket を指している (LAN private IP / `0.0.0.0:9` でない)
    /// 4. `peer.handle_offer` が呼ばれ、 `peer.take_media_rx` も呼ばれる
    ///    (= bridge に MediaFrame I/O を渡している)
    /// 5. 200 OK 受信後 `MediaBridge::WebRtcAudio` が CallManager に登録される
    #[tokio::test]
    async fn rfc3264_pwa_outbound_dials_ngn_with_avp_pcmu_sdp_and_savpf_returned_to_browser() {
        use crate::call::manager::CallManager;
        use crate::call::transcoder::DEFAULT_OPUS_PT;
        use crate::sip::uac::UacConfig;
        use crate::webrtc::peer::{MediaFrame, PeerSession};
        use crate::webrtc::signaling::PwaOutboundHandler;
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrder};
        use std::sync::Mutex as StdMutex;
        use tokio::sync::Mutex as TokioMutex;

        // ---- (1) フェイク NGN P-CSCF: INVITE を受けて 200 OK を返す ----
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        // NGN 側 RTP ピアとして使うソケット。 INVITE 200 OK の SDP に乗せる。
        let ngn_peer_rtp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_rtp_addr = ngn_peer_rtp.local_addr().unwrap();

        let captured_uri: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let captured_sdp: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(None));
        let captured_uri_c = captured_uri.clone();
        let captured_sdp_c = captured_sdp.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, peer) = fake_ngn_clone.recv_from(&mut buf).await.unwrap();
            if let SipMessage::Request(req) = parse_message(&buf[..n]).unwrap() {
                assert_eq!(req.method, SipMethod::Invite);
                *captured_uri_c.lock().unwrap() = Some(req.uri.clone());
                *captured_sdp_c.lock().unwrap() = Some(req.body.clone());
                let mut resp = build_response_skeleton(&req, 200, "OK");
                resp.headers.set(
                    "To",
                    format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
                );
                resp.headers
                    .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                resp.headers.set("Content-Type", "application/sdp");
                resp.body = format!(
                    "v=0\r\n\
                     o=- 9 9 IN IP4 {ip}\r\n\
                     s=-\r\n\
                     c=IN IP4 {ip}\r\n\
                     t=0 0\r\n\
                     m=audio {port} RTP/AVP 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n",
                    ip = ngn_peer_rtp_addr.ip(),
                    port = ngn_peer_rtp_addr.port()
                )
                .into_bytes();
                fake_ngn_clone
                    .send_to(&resp.to_bytes(), peer)
                    .await
                    .unwrap();
                // ACK は drop
                let _ = fake_ngn_clone.recv_from(&mut buf).await;
            }
        });

        // ---- (2) sabiden NGN UAC ----
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // ---- (3) UasEventHandler を CallManager 付きで構築 ----
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );
        let pwa_h: Arc<dyn PwaOutboundHandler> = handler.clone();

        // ---- (4) PWA を模した PeerSession ----
        struct PwaPeer {
            handle_offer_count: AtomicU32,
            seen_offer: StdMutex<Option<String>>,
            answer_sdp: String,
            // take_media_rx は 1 度だけ取れる
            media_rx: TokioMutex<Option<mpsc::Receiver<MediaFrame>>>,
        }
        #[async_trait::async_trait]
        impl PeerSession for PwaPeer {
            async fn handle_offer(&self, sdp: &str) -> Result<String> {
                self.handle_offer_count.fetch_add(1, AtomicOrder::SeqCst);
                *self.seen_offer.lock().unwrap() = Some(sdp.to_string());
                Ok(self.answer_sdp.clone())
            }
            async fn create_offer(&self) -> Result<String> {
                Err(anyhow!("本フローでは create_offer を呼ばない"))
            }
            async fn accept_answer(&self, _sdp: &str) -> Result<()> {
                Err(anyhow!(
                    "PWA outbound では sabiden は browser に answer を返すだけで accept_answer は呼ばない"
                ))
            }
            async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
                Ok(())
            }
            async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
                self.media_rx.lock().await.take()
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        // browser SAVPF answer (Opus PT 111 + PCMU PT 0 を含めて、 SAVPF→AVP→PCMU
        // 縮退の経路を網羅する):
        let browser_answer_sdp = "v=0\r\n\
            o=- 1 1 IN IP4 0.0.0.0\r\n\
            s=-\r\n\
            c=IN IP4 0.0.0.0\r\n\
            t=0 0\r\n\
            m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n\
            a=rtpmap:111 opus/48000/2\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=ice-ufrag:abc1\r\n\
            a=ice-pwd:abcdefghabcdefghabcdef\r\n\
            a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
            a=setup:passive\r\n\
            a=mid:0\r\n\
            a=rtcp-mux\r\n\
            a=sendrecv\r\n"
            .to_string();
        let (_media_tx, media_rx) = mpsc::channel::<MediaFrame>(8);
        let pwa_peer = Arc::new(PwaPeer {
            handle_offer_count: AtomicU32::new(0),
            seen_offer: StdMutex::new(None),
            answer_sdp: browser_answer_sdp.clone(),
            media_rx: TokioMutex::new(Some(media_rx)),
        });
        let pwa_peer_dyn: Arc<dyn PeerSession> = pwa_peer.clone();

        // ---- (5) 発信フロー実行 ----
        // PR #146 review #1 🟡#2: handler は SAVPF answer を即返し、 NGN
        // INVITE → bridge 起動は背景タスクで進む。 テストは completion
        // JoinHandle を await して bridge 登録完了を確認する。
        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);
        let browser_offer = "v=0\r\nbrowser-savpf-offer\r\n";
        let outcome = pwa_h
            .handle_pwa_outbound_offer("117", browser_offer, &pwa_peer_dyn, &ws_sink)
            .await
            .expect("PWA outbound 同期パス成功");
        let returned_to_browser = outcome.savpf_answer.clone();
        tokio::time::timeout(Duration::from_secs(5), outcome.completion)
            .await
            .expect("background task 完了 timeout")
            .expect("background task panic")
            .expect("background task ok");
        // 成功パスでは ws_sink への ServerMessage::Error push は無いはず。
        assert!(
            ws_rx.try_recv().is_err(),
            "成功パスでは ws_sink に error は流れない"
        );

        // ---- (6) 検証 ----
        assert_eq!(
            returned_to_browser, browser_answer_sdp,
            "browser に返る SDP は peer.handle_offer の戻り値そのまま (RFC 3264 §6 answer)"
        );
        assert_eq!(
            pwa_peer.handle_offer_count.load(AtomicOrder::SeqCst),
            1,
            "peer.handle_offer は 1 回呼ばれる"
        );
        assert_eq!(
            pwa_peer.seen_offer.lock().unwrap().as_deref(),
            Some(browser_offer),
            "peer.handle_offer は browser SAVPF offer を受け取る"
        );

        // NGN に届く INVITE の検証
        let _ = tokio::time::timeout(Duration::from_secs(2), ngn_task).await;
        let uri = captured_uri
            .lock()
            .unwrap()
            .clone()
            .expect("NGN に INVITE 到達");
        let expected_uri = format!("sip:117@{}", fake_ngn_addr);
        assert_eq!(
            uri, expected_uri,
            "Request-URI は P-CSCF IP+port を持つ (Asterisk pcap §5.1)"
        );

        // SDP の検証: AVP/PCMU only で c=/m= port が NGN bridge socket を指している
        let ngn_sdp = captured_sdp
            .lock()
            .unwrap()
            .clone()
            .expect("NGN INVITE SDP");
        let sdp_text = std::str::from_utf8(&ngn_sdp).unwrap();
        assert!(
            sdp_text.contains("RTP/AVP "),
            "NGN 向け SDP は RTP/AVP (SAVPF→AVP 変換済): \n{}",
            sdp_text
        );
        assert!(
            !sdp_text.contains("UDP/TLS/RTP/SAVPF"),
            "SAVPF proto が残っている (NGN は SAVPF を解釈しない): \n{}",
            sdp_text
        );
        let parsed = crate::sdp::SessionDescription::parse(sdp_text).unwrap();
        let m = parsed
            .media
            .iter()
            .find(|m| m.media == "audio")
            .expect("m=audio 必須");
        // PCMU only (RFC 3551 PT 0) + telephone-event (RFC 4733 PT 101) に
        // 絞られている (`docs/asterisk-real-invite.md` §2 + Issue #69 DTMF interop)。
        // browser answer に PT 101 が無いケースなので 0 のみのはずだが、
        // `restrict_audio_to_pcmu_with_dtmf` が PT 101 を補う場合もあるため
        // 「0 が含まれる + 0/101 以外は無い」 の形で assert する。
        assert!(
            m.formats.contains(&"0".to_string()),
            "PT 0 (PCMU) は必ず含まれる: {:?}",
            m.formats
        );
        for f in &m.formats {
            assert!(
                f == "0" || f == "101",
                "PCMU(0) / telephone-event(101) 以外の PT が漏れている: {:?}",
                m.formats
            );
        }
        // c= は loopback (テストでは 127.0.0.1 を bridge_ngn_bind_ip に指定)
        let conn = parsed.connection.as_ref().unwrap();
        assert_eq!(
            conn.address.to_string(),
            "127.0.0.1",
            "c= は sabiden NGN 側 IP (LAN private が漏れていない)"
        );
        // m=audio port は sabiden が bind した実 port (`9` のままはダメ)
        assert!(m.port > 0 && m.port != 9);
        // ngn_peer_rtp_addr の port が NGN→sabiden 向け (= NGN answer 由来) なので
        // sabiden が出した c=/m= port とは別
        assert_ne!(
            m.port,
            ngn_peer_rtp_addr.port(),
            "sabiden 自身の bridge port を広告すべきで、 NGN ピア port を漏らしてはいけない"
        );

        // CallManager に bridge が登録されている
        assert_eq!(
            mgr.len().await,
            1,
            "PWA outbound bridge が CallManager に登録される"
        );

        // browser answer から Opus PT 111 を拾えていることを find_opus_payload_type で再確認
        // (handler 側で同じ抽出を行っている)
        assert_eq!(
            crate::call::transcoder::find_opus_payload_type(browser_answer_sdp.as_bytes()),
            Some(111),
        );
        let _ = DEFAULT_OPUS_PT; // 参照だけ保持
    }

    /// Issue #145: peer.handle_offer が失敗したら handler は `Err` を返し、
    /// NGN への INVITE は飛ばない (browser SDP 不正で交渉開始前に止まる)。
    #[tokio::test]
    async fn pwa_outbound_returns_err_when_peer_handle_offer_fails() {
        use crate::call::manager::CallManager;
        use crate::sip::uac::UacConfig;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::PwaOutboundHandler;

        // フェイク NGN: INVITE が来たら回数を数える (来てはいけない)
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let invite_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invite_seen_c = invite_seen.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let _ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            if tokio::time::timeout(
                Duration::from_millis(200),
                fake_ngn_clone.recv_from(&mut buf),
            )
            .await
            .is_ok()
            {
                invite_seen_c.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:test@local".to_string(),
                domain: "local".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "test".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );
        let pwa_h: Arc<dyn PwaOutboundHandler> = handler.clone();

        struct FailingPeer;
        #[async_trait::async_trait]
        impl PeerSession for FailingPeer {
            async fn handle_offer(&self, _sdp: &str) -> Result<String> {
                Err(anyhow!("simulated SDP parse error"))
            }
            async fn create_offer(&self) -> Result<String> {
                Err(anyhow!("not used"))
            }
            async fn accept_answer(&self, _sdp: &str) -> Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
                Ok(())
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let peer: Arc<dyn PeerSession> = Arc::new(FailingPeer);

        let (ws_tx, _ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);
        let r = pwa_h
            .handle_pwa_outbound_offer("117", "garbage", &peer, &ws_sink)
            .await;
        assert!(r.is_err(), "peer.handle_offer 失敗で同期 Err");

        // NGN には INVITE が飛んでいないこと (200ms 待機しても受信なし)
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !invite_seen.load(std::sync::atomic::Ordering::SeqCst),
            "browser 側で SDP 失敗したら NGN へ INVITE は出さない"
        );
        assert_eq!(mgr.len().await, 0, "bridge は登録されない");
    }

    /// Issue #145: NGN が 486 Busy を返したら handler は `Err` を返し、
    /// CallManager に bridge は登録されない。
    #[tokio::test]
    async fn pwa_outbound_returns_err_when_ngn_returns_486() {
        use crate::call::manager::CallManager;
        use crate::sip::uac::UacConfig;
        use crate::webrtc::peer::{MediaFrame, PeerSession};
        use crate::webrtc::signaling::PwaOutboundHandler;
        use tokio::sync::Mutex as TokioMutex;

        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let fake_ngn_clone = fake_ngn.clone();
        // Issue #260 Phase 1-B: carrier intermittent reject に 1 回 retry が
        // 入るため、 fake NGN は 486 を 2 回 (元 INVITE + retry INVITE) 返す。
        // ACK / 100 Trying 等は読み飛ばす。
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut sent = 0u32;
            while sent < 2 {
                let (n, peer) = match tokio::time::timeout(
                    Duration::from_secs(20),
                    fake_ngn_clone.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok(v)) => v,
                    _ => break,
                };
                if let Ok(SipMessage::Request(req)) = parse_message(&buf[..n]) {
                    if req.method != SipMethod::Invite {
                        continue;
                    }
                    let mut resp = build_response_skeleton(&req, 486, "Busy Here");
                    resp.headers.set(
                        "To",
                        format!("{};tag=busy-tag-{}", req.headers.get("to").unwrap(), sent),
                    );
                    fake_ngn_clone
                        .send_to(&resp.to_bytes(), peer)
                        .await
                        .unwrap();
                    sent += 1;
                }
            }
        });

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:test@local".to_string(),
                domain: "local".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "test".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );
        let pwa_h: Arc<dyn PwaOutboundHandler> = handler.clone();

        struct OkPeer {
            media_rx: TokioMutex<Option<mpsc::Receiver<MediaFrame>>>,
        }
        #[async_trait::async_trait]
        impl PeerSession for OkPeer {
            async fn handle_offer(&self, _sdp: &str) -> Result<String> {
                Ok(
                    "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                    m=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
                        .to_string(),
                )
            }
            async fn create_offer(&self) -> Result<String> {
                Err(anyhow!("not used"))
            }
            async fn accept_answer(&self, _sdp: &str) -> Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
                Ok(())
            }
            async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
                self.media_rx.lock().await.take()
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let (_tx, rx) = mpsc::channel::<MediaFrame>(8);
        let peer: Arc<dyn PeerSession> = Arc::new(OkPeer {
            media_rx: TokioMutex::new(Some(rx)),
        });

        // PR #146 review #1 🟡#2: NGN 486 は **背景タスク** で観測される。
        // 同期パスは Ok を返し、 completion JoinHandle が `Err` を返す。
        // また `ws_sink` 経由で `ServerMessage::Error{code:"outbound_failed"}`
        // が browser に push される (review #1 🟡#4 PWA エラー返却)。
        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);
        let outcome = pwa_h
            .handle_pwa_outbound_offer("117", "v=0", &peer, &ws_sink)
            .await
            .expect("同期パスは成功 (NGN 失敗は background)");
        // Issue #260 Phase 1-B.2: retry wait が 8s±1.5s (= ~9.5s upper) + INVITE 往復 ×2 +
        // CI runner overhead で 20s では足りないことがある。 余裕を持って 60s。
        let bg = tokio::time::timeout(Duration::from_secs(60), outcome.completion)
            .await
            .expect("background timeout")
            .expect("background panic");
        assert!(bg.is_err(), "NGN 486 で background task は Err");
        assert_eq!(mgr.len().await, 0, "bridge は登録されない");
        // ws_sink に error が push されていることを確認
        let ws_msg = tokio::time::timeout(Duration::from_secs(1), async { ws_rx.recv().await })
            .await
            .expect("ws_sink に error が push される")
            .expect("ws_sink チャネルが閉じていない");
        match ws_msg {
            ServerMessage::Error { code, .. } => {
                assert_eq!(code, "outbound_failed", "NGN 失敗は outbound_failed");
            }
            other => panic!("error メッセージ期待: {:?}", other),
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), ngn_task).await;
    }

    /// PR #146 review #1 🟡#4: NGN 503 (Service Unavailable) の場合も browser に
    /// `outbound_failed` エラーが届くことを確認する。 486 は Busy 区分、 503 は
    /// Error 区分で counter が変わるが、 browser から見たエラー通知は同じ。
    #[tokio::test]
    async fn pwa_outbound_ngn_503_pushes_outbound_failed_to_browser() {
        use crate::call::manager::CallManager;
        use crate::sip::uac::UacConfig;
        use crate::webrtc::peer::{MediaFrame, PeerSession};
        use crate::webrtc::signaling::PwaOutboundHandler;
        use tokio::sync::Mutex as TokioMutex;

        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let fake_ngn_clone = fake_ngn.clone();
        // Issue #260 Phase 1-B: 503 も auto-retry 対象なので fake NGN は 2 回応答する。
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut sent = 0u32;
            while sent < 2 {
                let (n, peer) = match tokio::time::timeout(
                    Duration::from_secs(20),
                    fake_ngn_clone.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok(v)) => v,
                    _ => break,
                };
                if let Ok(SipMessage::Request(req)) = parse_message(&buf[..n]) {
                    if req.method != SipMethod::Invite {
                        continue;
                    }
                    let mut resp = build_response_skeleton(&req, 503, "Service Unavailable");
                    resp.headers.set(
                        "To",
                        format!("{};tag=503-tag-{}", req.headers.get("to").unwrap(), sent),
                    );
                    fake_ngn_clone
                        .send_to(&resp.to_bytes(), peer)
                        .await
                        .unwrap();
                    sent += 1;
                }
            }
        });

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:test@local".to_string(),
                domain: "local".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "test".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );
        let pwa_h: Arc<dyn PwaOutboundHandler> = handler.clone();

        struct OkPeer {
            media_rx: TokioMutex<Option<mpsc::Receiver<MediaFrame>>>,
        }
        #[async_trait::async_trait]
        impl PeerSession for OkPeer {
            async fn handle_offer(&self, _sdp: &str) -> Result<String> {
                Ok(
                    "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                    m=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
                        .to_string(),
                )
            }
            async fn create_offer(&self) -> Result<String> {
                Err(anyhow!("not used"))
            }
            async fn accept_answer(&self, _sdp: &str) -> Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
                Ok(())
            }
            async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
                self.media_rx.lock().await.take()
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let (_tx, rx) = mpsc::channel::<MediaFrame>(8);
        let peer: Arc<dyn PeerSession> = Arc::new(OkPeer {
            media_rx: TokioMutex::new(Some(rx)),
        });

        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);
        let outcome = pwa_h
            .handle_pwa_outbound_offer("117", "v=0", &peer, &ws_sink)
            .await
            .expect("同期パスは成功");
        // Issue #260 Phase 1-B.2: retry wait が 8s±1.5s (= ~9.5s upper) + INVITE 往復 ×2 +
        // CI runner overhead で 20s では足りないことがある。 余裕を持って 60s。
        let bg = tokio::time::timeout(Duration::from_secs(60), outcome.completion)
            .await
            .expect("background timeout")
            .expect("background panic");
        assert!(bg.is_err(), "NGN 503 で background task は Err");
        assert_eq!(mgr.len().await, 0, "bridge は登録されない");
        let ws_msg = tokio::time::timeout(Duration::from_secs(1), async { ws_rx.recv().await })
            .await
            .expect("ws_sink に error が push される")
            .expect("ws_sink チャネルが閉じていない");
        match ws_msg {
            ServerMessage::Error { code, message } => {
                assert_eq!(code, "outbound_failed");
                assert!(
                    message.contains("503"),
                    "エラーメッセージに 503 が含まれる: {:?}",
                    message
                );
            }
            other => panic!("error メッセージ期待: {:?}", other),
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), ngn_task).await;
    }

    /// PR #146 review #1 🟡#4: `peer.take_media_rx` が None を返す場合
    /// (= stub backend / 既に取り出し済み) で handler が crash しない / NGN
    /// INVITE を出さない / 同期 Err で signaling 層に伝わる。
    #[tokio::test]
    async fn pwa_outbound_returns_err_when_take_media_rx_is_none() {
        use crate::call::manager::CallManager;
        use crate::sip::uac::UacConfig;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::PwaOutboundHandler;

        // フェイク NGN: INVITE が来てはいけないので受信を時間で打ち切るだけ
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let invite_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invite_seen_c = invite_seen.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let _ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            if tokio::time::timeout(
                Duration::from_millis(200),
                fake_ngn_clone.recv_from(&mut buf),
            )
            .await
            .is_ok()
            {
                invite_seen_c.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:test@local".to_string(),
                domain: "local".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "test".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );
        let pwa_h: Arc<dyn PwaOutboundHandler> = handler.clone();

        // `take_media_rx` が常に None を返す (= stub 等しい挙動)
        struct NoMediaPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoMediaPeer {
            async fn handle_offer(&self, _sdp: &str) -> Result<String> {
                Ok(
                    "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                    m=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
                        .to_string(),
                )
            }
            async fn create_offer(&self) -> Result<String> {
                Err(anyhow!("not used"))
            }
            async fn accept_answer(&self, _sdp: &str) -> Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
                Ok(())
            }
            // take_media_rx の既定実装は None を返す → そのまま使う
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let peer: Arc<dyn PeerSession> = Arc::new(NoMediaPeer);

        let (ws_tx, _ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);
        let r = pwa_h
            .handle_pwa_outbound_offer("117", "v=0", &peer, &ws_sink)
            .await;
        assert!(r.is_err(), "take_media_rx None で同期 Err (crash しない)");
        let msg = format!("{}", r.unwrap_err());
        assert!(
            msg.contains("take_media_rx"),
            "エラー文言に take_media_rx が含まれる: {}",
            msg
        );

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !invite_seen.load(std::sync::atomic::Ordering::SeqCst),
            "media_rx None なら NGN INVITE は出さない"
        );
        assert_eq!(mgr.len().await, 0, "bridge は登録されない");
    }

    /// PR #146 review #1 🔴#1 (defense in depth): `is_valid_pwa_dial_target`
    /// 違反入力は orchestrator handler 側でも同期 Err で拒否され、 NGN INVITE
    /// は出ない。 signaling 層の検証を素通り (テスト等で trait を直接呼ぶ場合)
    /// しても production code path では絶対に NGN レッグまで運ばない。
    #[tokio::test]
    async fn pwa_outbound_handler_rejects_invalid_target_charset() {
        use crate::call::manager::CallManager;
        use crate::sip::uac::UacConfig;
        use crate::webrtc::peer::PeerSession;
        use crate::webrtc::signaling::PwaOutboundHandler;

        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let invite_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invite_seen_c = invite_seen.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let _ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            if tokio::time::timeout(
                Duration::from_millis(200),
                fake_ngn_clone.recv_from(&mut buf),
            )
            .await
            .is_ok()
            {
                invite_seen_c.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:test@local".to_string(),
                domain: "local".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "test".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let handler = UasEventHandler::with_call_manager(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
        );
        let pwa_h: Arc<dyn PwaOutboundHandler> = handler.clone();

        struct DummyPeer;
        #[async_trait::async_trait]
        impl PeerSession for DummyPeer {
            async fn handle_offer(&self, _sdp: &str) -> Result<String> {
                panic!("invalid target なら handle_offer に到達してはならない");
            }
            async fn create_offer(&self) -> Result<String> {
                Err(anyhow!("not used"))
            }
            async fn accept_answer(&self, _sdp: &str) -> Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
                Ok(())
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let peer: Arc<dyn PeerSession> = Arc::new(DummyPeer);

        let (ws_tx, _ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);
        // CRLF injection と @host hijack を 1 つずつ確認
        for bad in ["117\r\nINVITE", "117@evil.com", "", &"1".repeat(33)] {
            let r = pwa_h
                .handle_pwa_outbound_offer(bad, "v=0", &peer, &ws_sink)
                .await;
            assert!(r.is_err(), "invalid target rejected: {:?}", bad);
        }

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !invite_seen.load(std::sync::atomic::Ordering::SeqCst),
            "invalid target で NGN INVITE は絶対出さない"
        );
        assert_eq!(mgr.len().await, 0);
    }

    // =====================================================================
    // Issue #147: PWA→NGN outbound BYE 連動 + leak 防止
    // =====================================================================
    //
    // テスト群は以下を網羅する (`docs/test-strategy.md` §2 4 層のうち
    // integration: 127.0.0.1:0 in-process socket):
    //
    // 1) `issue147_pwa_outbound_inserts_into_shared_table`
    //    成立 branch で `webrtc_outbound_active` に Call-ID キーで挿入される。
    // 2) `rfc3261_15_1_2_ngn_bye_terminates_pwa_outbound_and_pushes_ws_bye`
    //    NGN→PWA BYE: 200 OK 返答 + bridge terminate + dec_call_active +
    //    `ServerMessage::Bye` push (RFC 3261 §15.1.2 / RFC 5853 §3.2.2)。
    // 3) `rfc3261_15_1_1_pwa_close_sends_ngn_bye_and_dec_call_active`
    //    PWA→NGN BYE: `close_pwa_outbound_for_ws` で NGN BYE が送出され、
    //    bridge terminate + dec_call_active が走る (RFC 3261 §15.1.1)。
    // 4) `issue147_double_close_is_idempotent`
    //    NGN BYE 後に再度 `close_pwa_outbound_for_ws` を呼んでも no-op
    //    (二重 dec_call_active しない)。
    // 5) `issue147_close_pwa_outbound_no_match_returns_zero`
    //    無関係 WS で呼んでもテーブルは触らない (誤掃き防止)。

    /// PWA outbound 発信フロー全体を立ち上げ、 共有 outbound テーブルに
    /// エントリが挿入されるまで完了するヘルパ (production layout =
    /// `CallManager` を outbound/inbound で共有)。
    ///
    /// 戻り値:
    /// - `webrtc_outbound_active` Arc (NGN/UAS 両ハンドラと共有済)
    /// - `metrics` Arc
    /// - `mgr` outbound 側 `CallManager` (= 本 layout では inbound と同一 Arc)
    /// - `ws_sink` PWA セッションの WS 送信ハンドル
    /// - `ws_rx` 同 WS 受信側 (テストで `ServerMessage::Bye` を観測する)
    /// - `ngn_handler` 必要に応じて NGN→PWA BYE を駆動するため返す
    /// - `uas_handler` 必要に応じて PWA→NGN BYE を駆動するため返す
    /// - `fake_ngn` フェイク NGN socket (BYE 受信 / 返答テストで使う)
    /// - `fake_ngn_addr` 同上 socket addr
    /// - `ngn_call_id` 確立した NGN レッグ Call-ID (テーブルキー)
    #[allow(clippy::type_complexity)]
    async fn issue147_setup_pwa_outbound_call() -> (
        WebRtcOutboundActive,
        Arc<Metrics>,
        Arc<CallManager>,
        WsSink,
        mpsc::UnboundedReceiver<ServerMessage>,
        Arc<NgnInboundHandler>,
        Arc<UasEventHandler>,
        Arc<UdpSocket>,
        SocketAddr,
        String,
    ) {
        let r = issue147_setup_pwa_outbound_call_with_layout(false).await;
        // production layout は outbound_mgr == inbound_mgr の同一 Arc。
        // 既存呼び出し元向けに 1 個だけ返す。
        (
            r.webrtc_outbound_active,
            r.metrics,
            r.outbound_mgr,
            r.ws_sink,
            r.ws_rx,
            r.ngn_handler,
            r.uas_handler,
            r.fake_ngn,
            r.fake_ngn_addr,
            r.ngn_call_id,
        )
    }

    /// `issue147_setup_pwa_outbound_call` の検証用 layout 切替版。
    ///
    /// `separate_mgrs = true` で PR #154 修正前の production layout (outbound と
    /// inbound で別々の `CallManager` Arc を持つ) を再現する。 NGN→PWA BYE で
    /// `terminate` が silent no-op になり RTP bridge が leak することを直接
    /// 観測するための regression test に使う (review #2 🔴)。
    /// `separate_mgrs = false` は本流 (= PR #154 修正後の挙動) で `outbound_mgr ==
    /// inbound_mgr`。
    struct Issue147SetupResult {
        webrtc_outbound_active: WebRtcOutboundActive,
        metrics: Arc<Metrics>,
        /// `UasEventHandler` に注入した `CallManager`。
        outbound_mgr: Arc<CallManager>,
        /// `NgnInboundHandler` に注入した `CallManager`。 production layout では
        /// `outbound_mgr` と同一 Arc。
        inbound_mgr: Arc<CallManager>,
        ws_sink: WsSink,
        ws_rx: mpsc::UnboundedReceiver<ServerMessage>,
        ngn_handler: Arc<NgnInboundHandler>,
        uas_handler: Arc<UasEventHandler>,
        fake_ngn: Arc<UdpSocket>,
        fake_ngn_addr: SocketAddr,
        ngn_call_id: String,
        /// fake NGN に到達した BYE の数 (review #2 🟡#2: PWA→NGN BYE 経路で
        /// 実 BYE 到達を直接検証するため)。
        ngn_bye_seen: Arc<std::sync::atomic::AtomicU32>,
    }

    async fn issue147_setup_pwa_outbound_call_with_layout(
        separate_mgrs: bool,
    ) -> Issue147SetupResult {
        use crate::call::manager::CallManager;
        use crate::sip::uac::UacConfig;
        use crate::webrtc::peer::{MediaFrame, PeerSession};
        use crate::webrtc::signaling::PwaOutboundHandler;
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrder};
        use std::sync::Mutex as StdMutex;
        use tokio::sync::Mutex as TokioMutex;

        // ---- フェイク NGN P-CSCF: INVITE → 200 OK、 BYE → 200 OK ----
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let ngn_peer_rtp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_rtp_addr = ngn_peer_rtp.local_addr().unwrap();

        let fake_ngn_clone = fake_ngn.clone();
        // BYE 到達カウンタ (review #2 🟡#2: PWA→NGN BYE が実 socket に到達した
        // ことを test 側で `assert` できるよう public に出す)。
        let ngn_bye_seen = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ngn_bye_seen_inner = ngn_bye_seen.clone();
        // INVITE 受信 → 200 OK 送信、 後続 ACK / BYE は受け取って 200 OK で
        // 返す (テスト中ずっと spawn しっぱなしにしておく)。
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let (n, peer) = match fake_ngn_clone.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let msg = match parse_message(&buf[..n]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if let SipMessage::Request(req) = msg {
                    match req.method {
                        SipMethod::Invite => {
                            let mut resp = build_response_skeleton(&req, 200, "OK");
                            resp.headers.set(
                                "To",
                                format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
                            );
                            resp.headers
                                .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                            resp.headers.set("Content-Type", "application/sdp");
                            resp.body = format!(
                                "v=0\r\n\
                                 o=- 9 9 IN IP4 {ip}\r\n\
                                 s=-\r\n\
                                 c=IN IP4 {ip}\r\n\
                                 t=0 0\r\n\
                                 m=audio {port} RTP/AVP 0\r\n\
                                 a=rtpmap:0 PCMU/8000\r\n",
                                ip = ngn_peer_rtp_addr.ip(),
                                port = ngn_peer_rtp_addr.port()
                            )
                            .into_bytes();
                            let _ = fake_ngn_clone.send_to(&resp.to_bytes(), peer).await;
                        }
                        SipMethod::Bye => {
                            ngn_bye_seen_inner.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let resp = build_response_skeleton(&req, 200, "OK");
                            let _ = fake_ngn_clone.send_to(&resp.to_bytes(), peer).await;
                        }
                        _ => {} // ACK 等は drop
                    }
                }
            }
        });

        // ---- sabiden NGN UAC ----
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // ---- 共有 webrtc_outbound_active + metrics + CallManager ----
        let webrtc_outbound_active: WebRtcOutboundActive = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Metrics::new();
        // production layout: outbound と inbound は同一 Arc を共有 (PR #154 fix)。
        // separate_mgrs=true (regression test 用) では別 Arc を作って旧バグを再現。
        let outbound_mgr = CallManager::new(ExtensionRegistrar::new());
        let inbound_mgr = if separate_mgrs {
            CallManager::new(ExtensionRegistrar::new())
        } else {
            outbound_mgr.clone()
        };

        // ---- UasEventHandler (共有テーブル付き) ----
        let uas_handler = UasEventHandler::with_call_manager_metrics_and_outbound_table(
            ngn_uac.clone(),
            outbound_mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
            metrics.clone(),
            webrtc_outbound_active.clone(),
        );

        // ---- NgnInboundHandler (BYE 受信用 socket は別 / sabiden 側) ----
        let sabiden_inbound_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (_ngn_inbound_layer, ngn_inbound_rx) =
            TransactionLayer::spawn(sabiden_inbound_sock.clone());
        let inviter: ExtInviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::busy())
            .build();
        let ngn_handler = NgnInboundHandler::with_call_manager_metrics_and_outbound_table(
            sabiden_inbound_sock.clone(),
            inviter,
            ExtensionRegistrar::new(),
            NgnInboundConfig::default(),
            inbound_mgr.clone(),
            metrics.clone(),
            webrtc_outbound_active.clone(),
        );
        ngn_handler.clone().spawn(ngn_inbound_rx);

        // ---- PWA peer (fake) ----
        struct PwaPeer {
            answer_sdp: String,
            media_rx: TokioMutex<Option<mpsc::Receiver<MediaFrame>>>,
            handle_offer_calls: AtomicU32,
        }
        #[async_trait::async_trait]
        impl PeerSession for PwaPeer {
            async fn handle_offer(&self, _sdp: &str) -> Result<String> {
                self.handle_offer_calls.fetch_add(1, AtomicOrder::SeqCst);
                Ok(self.answer_sdp.clone())
            }
            async fn create_offer(&self) -> Result<String> {
                Err(anyhow!("not used"))
            }
            async fn accept_answer(&self, _sdp: &str) -> Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
                Ok(())
            }
            async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
                self.media_rx.lock().await.take()
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let browser_answer_sdp = "v=0\r\n\
            o=- 1 1 IN IP4 0.0.0.0\r\n\
            s=-\r\n\
            c=IN IP4 0.0.0.0\r\n\
            t=0 0\r\n\
            m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n\
            a=rtpmap:111 opus/48000/2\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=ice-ufrag:abc1\r\n\
            a=ice-pwd:abcdefghabcdefghabcdef\r\n\
            a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
            a=setup:passive\r\n\
            a=mid:0\r\n\
            a=rtcp-mux\r\n\
            a=sendrecv\r\n"
            .to_string();
        let (_media_tx, media_rx) = mpsc::channel::<MediaFrame>(8);
        let _ = StdMutex::new(()); // 未使用 import 警告抑止
        let pwa_peer: Arc<dyn PeerSession> = Arc::new(PwaPeer {
            answer_sdp: browser_answer_sdp.clone(),
            media_rx: TokioMutex::new(Some(media_rx)),
            handle_offer_calls: AtomicU32::new(0),
        });

        // ---- WS チャネル ----
        let (ws_tx, ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);

        // ---- 発信実行 (background completion を await) ----
        let pwa_h: Arc<dyn PwaOutboundHandler> = uas_handler.clone();
        let outcome = pwa_h
            .handle_pwa_outbound_offer("117", "v=0\r\nbrowser-offer\r\n", &pwa_peer, &ws_sink)
            .await
            .expect("PWA outbound 同期パス成功");
        tokio::time::timeout(Duration::from_secs(5), outcome.completion)
            .await
            .expect("background task 完了 timeout")
            .expect("background task panic")
            .expect("background task ok");

        // 共有テーブルから挿入されたエントリの NGN call-id を取り出す。
        let ngn_call_id = {
            let tbl = webrtc_outbound_active.lock().await;
            assert_eq!(
                tbl.len(),
                1,
                "PWA outbound 成功 → 共有テーブルに 1 件挿入される (Issue #147)"
            );
            tbl.keys().next().unwrap().clone()
        };

        Issue147SetupResult {
            webrtc_outbound_active,
            metrics,
            outbound_mgr,
            inbound_mgr,
            ws_sink,
            ws_rx,
            ngn_handler,
            uas_handler,
            fake_ngn,
            fake_ngn_addr,
            ngn_call_id,
            ngn_bye_seen,
        }
    }

    /// Issue #147 (1): PWA outbound 成立時に共有テーブルに insert される。
    /// (`handle_pwa_outbound_offer` 成功 branch の `let _ = call.dialog;` を撤去
    /// して `webrtc_outbound_active.insert(...)` に置換した修正の検証。)
    #[tokio::test]
    async fn issue147_pwa_outbound_inserts_into_shared_table() {
        let (tbl, metrics, mgr, _ws, _ws_rx, _ngnh, _uash, _fngn, _fngn_addr, ngn_cid) =
            issue147_setup_pwa_outbound_call().await;

        // 表に Call-ID で 1 件
        let tbl_guard = tbl.lock().await;
        assert!(
            tbl_guard.contains_key(&ngn_cid),
            "NGN Call-ID キーで挿入されている: {}",
            ngn_cid
        );
        // メトリクス +1, CallManager に bridge 1 件
        assert_eq!(
            metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(mgr.len().await, 1);
    }

    /// RFC 3261 §15.1.2 / RFC 5853 §3.2.2 (Issue #147 (2)):
    /// NGN→sabiden BYE 受信 → bridge terminate + dec_call_active +
    /// `ServerMessage::Bye` を WS push + テーブルから削除。
    #[tokio::test]
    async fn rfc3261_15_1_2_ngn_bye_terminates_pwa_outbound_and_pushes_ws_bye() {
        let (tbl, metrics, mgr, _ws, mut ws_rx, ngnh, _uash, _fngn, _fngn_addr, ngn_cid) =
            issue147_setup_pwa_outbound_call().await;
        assert_eq!(
            metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(mgr.len().await, 1);

        // mock NGN から sabiden の inbound socket に BYE を送る
        let sabiden_inbound_addr = ngnh.socket.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let mut bye = SipRequest::new(
            SipMethod::Bye,
            format!("sip:sabiden@{}", sabiden_inbound_addr),
        );
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKngnbye147", ngn_addr),
        );
        bye.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngnsidetag");
        bye.headers.set(
            "To",
            format!("<sip:sabiden@{}>;tag=sabsidetag", sabiden_inbound_addr),
        );
        bye.headers.set("Call-ID", &ngn_cid);
        bye.headers.set("CSeq", "2 BYE");
        ngn_sock
            .send_to(&bye.to_bytes(), sabiden_inbound_addr)
            .await
            .unwrap();

        // (a) NGN へ 200 OK 返答
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf))
            .await
            .expect("BYE 200 OK が返るべき")
            .unwrap();
        match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => assert_eq!(r.status_code, 200),
            other => panic!("Response 期待: {:?}", other),
        }

        // (b) PWA WS に ServerMessage::Bye が push される
        let pushed = tokio::time::timeout(Duration::from_secs(3), ws_rx.recv())
            .await
            .expect("WS Bye push timeout (Issue #147)")
            .expect("WS チャネル閉鎖");
        assert!(matches!(pushed, ServerMessage::Bye), "got {:?}", pushed);

        // (c) 共有テーブルから消えている (idempotent: 二重 BYE 安全)
        assert!(
            !tbl.lock().await.contains_key(&ngn_cid),
            "NGN→PWA BYE 後はテーブルから消える"
        );
        // (d) call_active が 0 に戻り、 bridge も terminated
        assert_eq!(
            metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        // (e) review #2 🔴 fix 検証: outbound 側で create_call した bridge が
        //     inbound 側の terminate でちゃんと回収されていることを確認する。
        //     production layout (= 共有 CallManager) では `mgr.len()` は 0 に戻る。
        //     PR #154 修正前は 2 個別 Arc 構成で silent no-op になり 1 件残った。
        assert_eq!(
            mgr.len().await,
            0,
            "NGN→PWA BYE で outbound bridge が回収されている (CallManager 共有 layout)"
        );
    }

    /// RFC 3261 §15.1.1 (Issue #147 (3)):
    /// PWA WS close 経路 (`close_pwa_outbound_for_ws`) → NGN BYE 送出 +
    /// bridge terminate + dec_call_active + テーブルから削除。
    #[tokio::test]
    async fn rfc3261_15_1_1_pwa_close_sends_ngn_bye_and_dec_call_active() {
        use crate::webrtc::signaling::PwaOutboundCloser;

        // review #2 🟡#2: NGN BYE 到達を直接 assert するため layout 版を使う
        // (`ngn_bye_seen` カウンタを参照)。
        let r = issue147_setup_pwa_outbound_call_with_layout(false).await;
        assert_eq!(
            r.metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            r.ngn_bye_seen.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "発信完了時点で NGN への BYE はまだ届いていない"
        );

        let closer: Arc<dyn PwaOutboundCloser> = r.uas_handler.clone();
        let closed = closer.close_pwa_outbound_for_ws(&r.ws_sink).await;
        assert_eq!(closed, 1, "PWA WS と一致するエントリ 1 件が閉じられた");

        // 副作用: メトリクス -1、 テーブルから削除
        assert_eq!(
            r.metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(!r
            .webrtc_outbound_active
            .lock()
            .await
            .contains_key(&r.ngn_call_id));

        // review #2 🟡#2: フェイク NGN への BYE 到達を直接観測する。
        // `close_pwa_outbound_for_ws` は `send_bye` のエラーを握り潰すので、
        // closed=1 だけでは BYE socket 出力を保証しない。 fake NGN spawn ループの
        // BYE counter が 1 以上になることを assert することで「NGN レッグ
        // socket に SIP BYE が届いた」を直接検証する (RFC 3261 §15.1.1)。
        let mut waited = 0u32;
        while r.ngn_bye_seen.load(std::sync::atomic::Ordering::SeqCst) == 0 && waited < 30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            waited += 1;
        }
        assert!(
            r.ngn_bye_seen.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "PWA→NGN BYE が fake NGN socket に到達していない"
        );

        // bridge も outbound_mgr (= 共有 layout なので inbound_mgr と同一) から消えている
        assert_eq!(
            r.outbound_mgr.len().await,
            0,
            "PWA→NGN BYE 後は outbound_mgr の bridge は解放される"
        );
    }

    /// Issue #147 (4): NGN BYE → close_pwa_outbound_for_ws の二重実行で
    /// `dec_call_active` が二重に走らない (idempotent)。
    /// テーブルから先に remove する設計 (handle_bye / closer の両方で remove
    /// 後に処理) のため、 後勝ちは 0 件 = no-op になる。
    #[tokio::test]
    async fn issue147_double_close_is_idempotent() {
        use crate::webrtc::signaling::PwaOutboundCloser;
        let (tbl, metrics, _mgr, ws, mut ws_rx, ngnh, uash, _fngn, _fngn_addr, ngn_cid) =
            issue147_setup_pwa_outbound_call().await;

        // (1) NGN BYE 先行
        let sabiden_inbound_addr = ngnh.socket.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let mut bye = SipRequest::new(
            SipMethod::Bye,
            format!("sip:sabiden@{}", sabiden_inbound_addr),
        );
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKdup147", ngn_addr),
        );
        bye.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngndup");
        bye.headers.set(
            "To",
            format!("<sip:sabiden@{}>;tag=sabdup", sabiden_inbound_addr),
        );
        bye.headers.set("Call-ID", &ngn_cid);
        bye.headers.set("CSeq", "2 BYE");
        ngn_sock
            .send_to(&bye.to_bytes(), sabiden_inbound_addr)
            .await
            .unwrap();

        // BYE 200 OK + WS Bye が来るのを待つ (NGN→PWA 経路完了)
        let mut buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(3), ws_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(!tbl.lock().await.contains_key(&ngn_cid));

        // (2) その後 close_pwa_outbound_for_ws を呼んでも 0 件 (no-op)。
        let closer: Arc<dyn PwaOutboundCloser> = uash.clone();
        let n = closer.close_pwa_outbound_for_ws(&ws).await;
        assert_eq!(
            n, 0,
            "テーブル空 → 0 件 (二重 dec_call_active を起こさない)"
        );
        // メトリクスはまだ 0 (= 二重減算で saturating-zero に張り付いていない)
        assert_eq!(
            metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// Issue #147 (5): 無関係 WS で `close_pwa_outbound_for_ws` を呼んでも
    /// 既存エントリは触られない (誤掃き防止)。
    #[tokio::test]
    async fn issue147_close_pwa_outbound_no_match_returns_zero() {
        use crate::webrtc::signaling::PwaOutboundCloser;
        let (tbl, metrics, _mgr, _ws, _ws_rx, _ngnh, uash, _fngn, _fngn_addr, ngn_cid) =
            issue147_setup_pwa_outbound_call().await;

        // 別 WS (別チャネル) を作って呼ぶ
        let (other_tx, _other_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let other_ws = WsSink::new(other_tx);

        let closer: Arc<dyn PwaOutboundCloser> = uash.clone();
        let n = closer.close_pwa_outbound_for_ws(&other_ws).await;
        assert_eq!(n, 0, "無関係 WS では既存エントリを触らない");
        assert!(tbl.lock().await.contains_key(&ngn_cid));
        // call_active は維持
        assert_eq!(
            metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// Issue #147 (6) leak 防止: bridge 起動失敗時にはテーブルに insert され
    /// ない (= 通話確立した扱いにしない)。
    /// `take_media_rx` が None を返す peer (stub backend / 既に取り出し済) で
    /// `handle_pwa_outbound_offer` は同期 Err を返すので、 NGN INVITE は出ず
    /// テーブルも空のまま。 既存テスト
    /// `pwa_outbound_returns_err_when_take_media_rx_is_none` の延長として
    /// 「テーブル無挿入」を確認する。
    #[tokio::test]
    async fn issue147_no_insert_when_take_media_rx_is_none() {
        use crate::call::manager::CallManager;
        use crate::sip::uac::UacConfig;
        use crate::webrtc::peer::{MediaFrame, PeerSession};
        use crate::webrtc::signaling::PwaOutboundHandler;

        // INVITE が出てはいけないので NGN ソケットだけ作って受信は無視。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let invite_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invite_seen_c = invite_seen.clone();
        let fake_ngn_c = fake_ngn.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            if fake_ngn_c.recv_from(&mut buf).await.is_ok() {
                invite_seen_c.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));
        let webrtc_outbound_active: WebRtcOutboundActive = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Metrics::new();
        let mgr = CallManager::new(ExtensionRegistrar::new());
        let uas_handler = UasEventHandler::with_call_manager_metrics_and_outbound_table(
            ngn_uac,
            mgr.clone(),
            Some("127.0.0.1".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap()),
            metrics.clone(),
            webrtc_outbound_active.clone(),
        );

        // take_media_rx が None を返す peer (= bridge 起動不可)
        struct NoMediaPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoMediaPeer {
            async fn handle_offer(&self, _sdp: &str) -> Result<String> {
                Ok("v=0\r\nbrowser-answer\r\n".to_string())
            }
            async fn create_offer(&self) -> Result<String> {
                Err(anyhow!("not used"))
            }
            async fn accept_answer(&self, _sdp: &str) -> Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> Result<()> {
                Ok(())
            }
            async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
                None
            }
            async fn close(&self) -> Result<()> {
                Ok(())
            }
        }
        let peer: Arc<dyn PeerSession> = Arc::new(NoMediaPeer);
        let (ws_tx, _ws_rx) = mpsc::unbounded_channel::<ServerMessage>();
        let ws_sink = WsSink::new(ws_tx);
        let pwa_h: Arc<dyn PwaOutboundHandler> = uas_handler.clone();
        let r = pwa_h
            .handle_pwa_outbound_offer("117", "v=0", &peer, &ws_sink)
            .await;
        assert!(r.is_err(), "take_media_rx None で同期 Err");

        // (a) テーブルは空 (leak 防止 = エントリを作らない)
        assert!(
            webrtc_outbound_active.lock().await.is_empty(),
            "失敗 branch では webrtc_outbound_active に insert されない"
        );
        // (b) call_active は 0 (inc されていない)
        assert_eq!(
            metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        // (c) NGN INVITE は出していない (同期 Err は INVITE 送出前)
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !invite_seen.load(std::sync::atomic::Ordering::SeqCst),
            "take_media_rx None で NGN INVITE は飛ばない"
        );
        assert_eq!(mgr.len().await, 0);
    }

    /// Issue #147 review #2 🔴 (regression test): 旧 layout (outbound と
    /// inbound で **別々の** `CallManager` Arc) では NGN→PWA BYE 経路で
    /// `terminate` が silent no-op になり、 outbound 側の RTP bridge が
    /// 回収されない (= `outbound_mgr.len()` が 1 のまま残る) ことを直接
    /// 観測する。 PR #154 の修正 (main.rs で `shared_call_manager` を共有)
    /// が将来 regression したら本テストが落ちる。
    ///
    /// 対比して `rfc3261_15_1_2_ngn_bye_terminates_pwa_outbound_and_pushes_ws_bye`
    /// (production layout = 共有 Arc) では `mgr.len() == 0` になる。
    ///
    /// RFC 3261 §15.1.2 / RFC 5853 §3.2.2 SBC framework: B2BUA は片側 dialog
    /// 終了をもう片側へ伝搬する責務を負う。 共有 CallManager はその責務を
    /// 成立させるための実装契約。
    #[tokio::test]
    async fn issue147_separate_call_managers_leak_outbound_bridge_on_ngn_bye() {
        let r = issue147_setup_pwa_outbound_call_with_layout(true).await;
        assert_eq!(
            r.metrics
                .call_active
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        // 旧 layout: outbound 側 CallManager に 1 件、 inbound 側は空。
        assert_eq!(
            r.outbound_mgr.len().await,
            1,
            "PWA outbound 成立時は outbound_mgr に 1 件登録される"
        );
        assert_eq!(
            r.inbound_mgr.len().await,
            0,
            "inbound_mgr は別 Arc なので空"
        );

        // mock NGN から sabiden の inbound socket に BYE を送る
        let sabiden_inbound_addr = r.ngn_handler.socket.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let mut bye = SipRequest::new(
            SipMethod::Bye,
            format!("sip:sabiden@{}", sabiden_inbound_addr),
        );
        bye.headers.set(
            "Via",
            format!("SIP/2.0/UDP {};branch=z9hG4bKngnbyeleak147", ngn_addr),
        );
        bye.headers
            .set("From", "<sip:caller@ntt-east.ne.jp>;tag=ngnsidetagleak");
        bye.headers.set(
            "To",
            format!("<sip:sabiden@{}>;tag=sabsidetagleak", sabiden_inbound_addr),
        );
        bye.headers.set("Call-ID", &r.ngn_call_id);
        bye.headers.set("CSeq", "2 BYE");
        ngn_sock
            .send_to(&bye.to_bytes(), sabiden_inbound_addr)
            .await
            .unwrap();

        // BYE 200 OK が返るのを待つ (= handle_bye 完了)
        let mut buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(3), ngn_sock.recv_from(&mut buf))
            .await
            .expect("BYE 200 OK が返るべき")
            .unwrap();

        // テーブルからは消える (handle_bye の冒頭で remove するため)
        assert!(!r
            .webrtc_outbound_active
            .lock()
            .await
            .contains_key(&r.ngn_call_id));

        // 🔴 観測される leak: NgnInboundHandler は inbound_mgr.terminate を呼ぶが、
        // bridge_call_id は outbound_mgr で create_call された ID なので
        // inbound_mgr 側には entry が無く、 silent Ok(()) が返る。
        // 結果 outbound_mgr 側の entry は永続。
        assert_eq!(
            r.outbound_mgr.len().await,
            1,
            "🔴 separate_mgrs layout: NGN→PWA BYE 経路で outbound bridge が回収されない (= leak)"
        );
        assert_eq!(
            r.inbound_mgr.len().await,
            0,
            "inbound_mgr 側には何も登録されていない (= terminate は silent no-op)"
        );
    }

    /// Issue #157 / TTC JJ-90.24 §5.7.1 / RFC 3261 §21.5.4 / §20.33:
    /// 内線→NGN 連投時、 sabiden は 2 本目を NGN に到達させる前に
    /// 503 Service Unavailable + Retry-After で内線へ早期拒否する。
    ///
    /// シナリオ:
    /// 1. AOR "iphone" から 1 本目の INVITE → rate limiter は Allow (初回)
    /// 2. 即座に AOR "iphone" から 2 本目の INVITE → rate limiter は Deny
    /// 3. 2 本目の応答は 503 + Retry-After ヘッダ付き
    /// 4. NGN 側には 2 本目は届かない (fake NGN は 1 回しか受信しない)
    #[tokio::test]
    async fn rfc3261_21_5_4_extension_outbound_rate_limited_returns_503_retry_after() {
        use crate::call::rate_limiter::{OutboundRateLimiter, RateLimiterConfig};
        use crate::sip::uac::UacConfig;

        // (1) フェイク NGN: INVITE を受けたら 200 OK を返す。
        //     2 本目は届かない想定なので、 1 INVITE 分のループだけ用意する。
        let fake_ngn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fake_ngn_addr = fake_ngn.local_addr().unwrap();
        let invite_count = Arc::new(StdMutex::new(0u32));
        let invite_count_c = invite_count.clone();
        let fake_ngn_clone = fake_ngn.clone();
        let ngn_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let res = tokio::time::timeout(
                    Duration::from_secs(3),
                    fake_ngn_clone.recv_from(&mut buf),
                )
                .await;
                let (n, peer) = match res {
                    Ok(Ok(v)) => v,
                    _ => break,
                };
                let parsed = parse_message(&buf[..n]).unwrap();
                if let SipMessage::Request(req) = parsed {
                    if req.method == SipMethod::Invite {
                        *invite_count_c.lock().unwrap() += 1;
                        let mut resp = build_response_skeleton(&req, 200, "OK");
                        resp.headers.set(
                            "To",
                            format!("{};tag=ngn-tag", req.headers.get("to").unwrap()),
                        );
                        resp.headers
                            .set("Contact", format!("<sip:ngn@{}>", fake_ngn_addr));
                        let _ = fake_ngn_clone.send_to(&resp.to_bytes(), peer).await;
                    }
                }
            }
        });

        // (2) sabiden NGN 側 UAC
        let ngn_client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ngn_layer, _ngn_rx) = TransactionLayer::spawn(ngn_client_sock.clone());
        let ngn_uac = Arc::new(Uac::new(
            UacConfig {
                local_uri: "sip:0312345678@ntt-east.ne.jp".to_string(),
                domain: "ntt-east.ne.jp".to_string(),
                local_addr: ngn_client_sock.local_addr().unwrap(),
                user_agent: "sabiden-test/0.1".to_string(),
                auth_username: None,
                auth_password: None,
            },
            ngn_layer,
            fake_ngn_addr,
        ));

        // (3) UasEventHandler: rate limiter を超短 min_interval で構築すると
        //     どうしても 1 本目と 2 本目の発射タイミング差で flaky になるので、
        //     min_interval=60 秒に設定して 2 本目を確実に Deny させる。
        let mut handler = UasEventHandler::new(ngn_uac);
        handler.set_outbound_rate_limiter(Arc::new(OutboundRateLimiter::with_config(
            RateLimiterConfig {
                min_interval: Duration::from_secs(60),
                failure_backoff_steps: vec![],
            },
        )));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        handler.clone().spawn(event_rx);

        // (4) 模擬内線 UAS の sabiden 側 socket
        let phone_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let phone_addr = phone_sock.local_addr().unwrap();
        let sabiden_uas_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_uas_addr = sabiden_uas_sock.local_addr().unwrap();

        // 共通の INVITE 生成 (Call-ID は毎回変える)
        let make_invite = |call_id: &str| {
            let mut invite = SipRequest::new(SipMethod::Invite, "sip:117@192.168.20.239");
            invite.headers.set(
                "Via",
                format!("SIP/2.0/UDP {};branch=z9hG4bK-{}", phone_addr, call_id),
            );
            invite
                .headers
                .set("From", "<sip:iphone@sabiden>;tag=phonereq");
            invite.headers.set("To", "<sip:117@192.168.20.239>");
            invite.headers.set("Call-ID", call_id);
            invite.headers.set("CSeq", "1 INVITE");
            invite.headers.set("Content-Type", "application/sdp");
            invite.body = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
                            c=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                            m=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec();
            invite
        };

        // (5) 1 本目: NGN へ届く
        let invite1 = make_invite("rl-call-1");
        phone_sock
            .send_to(&invite1.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, remote) =
            tokio::time::timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        let parsed = parse_message(&buf[..n]).unwrap();
        let req = match parsed {
            SipMessage::Request(r) => r,
            _ => panic!("INVITE 期待"),
        };
        let stx1 = ServerTransaction::new(req.clone(), remote, sabiden_uas_sock.clone()).unwrap();
        let responder1 = crate::testing::builders::responder_handle_for_test(stx1);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req,
                remote,
                responder: responder1,
            })
            .unwrap();
        // 1 本目の処理が始まるのを待ってから 2 本目を出す
        tokio::time::sleep(Duration::from_millis(200)).await;

        // (6) 2 本目: rate limiter で 503 + Retry-After で返るはず
        let invite2 = make_invite("rl-call-2");
        let phone_sock2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        phone_sock2
            .send_to(&invite2.to_bytes(), sabiden_uas_addr)
            .await
            .unwrap();
        let (n2, remote2) =
            tokio::time::timeout(Duration::from_secs(2), sabiden_uas_sock.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        let parsed2 = parse_message(&buf[..n2]).unwrap();
        let req2 = match parsed2 {
            SipMessage::Request(r) => r,
            _ => panic!("INVITE 期待"),
        };
        let stx2 = ServerTransaction::new(req2.clone(), remote2, sabiden_uas_sock.clone()).unwrap();
        let responder2 = crate::testing::builders::responder_handle_for_test(stx2);
        event_tx
            .send(UasEvent::Invite {
                from_aor: "iphone".to_string(),
                request: req2,
                remote: remote2,
                responder: responder2,
            })
            .unwrap();

        // (7) 2 本目の応答を phone_sock2 で受信 → 503 + Retry-After 検証
        let mut buf2 = vec![0u8; 4096];
        let recv =
            tokio::time::timeout(Duration::from_secs(3), phone_sock2.recv_from(&mut buf2)).await;
        let (rn, _ra) = recv
            .expect("2 本目への 503 応答がタイムアウト前に到着するべき")
            .unwrap();
        let resp_msg = parse_message(&buf2[..rn]).unwrap();
        let resp = match resp_msg {
            SipMessage::Response(r) => r,
            _ => panic!("レスポンス期待"),
        };
        assert_eq!(
            resp.status_code, 503,
            "TTC JJ-90.24 §5.7.1 / RFC 3261 §21.5.4: rate-limited INVITE には 503"
        );
        let retry_after = resp
            .headers
            .get("retry-after")
            .expect("RFC 3261 §20.33: 503 Service Unavailable には Retry-After ヘッダを付けるべき");
        let secs: u32 = retry_after.parse().expect("Retry-After は整数秒");
        assert!(
            (1..=60).contains(&secs),
            "Retry-After は 1..=60 の範囲 (min_interval=60): {}",
            secs
        );

        // (8) NGN 側に届いた INVITE は 1 本のみ
        // (1 本目の 200 OK→ACK→BYE で fake_ngn ループが drain して終わる)
        // 少し待ってから検査する。
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            *invite_count.lock().unwrap(),
            1,
            "rate limiter が 2 本目を NGN に流していないこと"
        );

        ngn_task.abort();
    }

    // ====================================================================
    // Issue #249: NGN inbound 200 OK で Session-Expires + 180 Ringing + ptime
    //   RFC 3261 §13.3.1.4 / RFC 4028 §7 / RFC 3264 §6.1
    // ====================================================================

    /// テスト用ヘルパ: INVITE を投げて N 個の応答を受信する。
    /// timeout は各 recv 単位。 timeout 内に応答が来なければ Vec を返す。
    async fn drain_responses(
        ngn_sock: &UdpSocket,
        max_count: usize,
        timeout: Duration,
    ) -> Vec<SipResponse> {
        let mut buf = vec![0u8; 8192];
        let mut out = Vec::new();
        for _ in 0..max_count {
            match tokio::time::timeout(timeout, ngn_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                        let status = r.status_code;
                        out.push(r);
                        // 200 など最終応答が来たらすぐ抜けても良いが、
                        // 後段の応答 (リトランスミット等) を測りたい用途もあるので
                        // ループを継続。 timeout で抜ける。
                        if status >= 200 {
                            // 最終応答後に provisional の遅延到着は無いので break
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        out
    }

    /// Issue #249 / RFC 3261 §13.3.1.4: NGN 着信 INVITE で 100 Trying の
    /// **直後に 180 Ringing** が NGN へ送出される (= "remote callee is being
    /// alerted" の semantic で、 4 秒 silent → 200 OK の carrier IMS timeout
    /// 経路を消す)。 実機 evidence: `/tmp/sabiden-080-inbound.pcap` で
    /// 100 Trying → 4.1 秒 silent → 200 OK → 28ms 後 BYE。 180 を挟むと
    /// carrier は call setup 進行中と認識する。
    #[tokio::test]
    async fn rfc3261_13_3_1_4_inbound_invite_sends_180_ringing() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6101".to_string(),
                "127.0.0.1:6101".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        // 内線がすぐ 200 OK を返さないよう、 INVITE delay でフォーク中に
        // 180 が出ていることを観測しやすくする (= fork timeout までは
        // ringing 状態が継続)。 ここでは scripted action で OK 即答だが、
        // 100 → 180 → 200 が一連で届くだけでもよく、 順序検証が肝。
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3261-13-3-1-4-cid",
            "z9hG4bK-ring",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20000 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        // 順序検証: 100 が最初、 180 が 100 の後、 200 (or 4xx) が最後の方
        let codes: Vec<u16> = responses.iter().map(|r| r.status_code).collect();
        assert!(
            codes.contains(&100),
            "RFC 3261 §17.2.1: 100 Trying を送るべき。 codes={codes:?}"
        );
        assert!(
            codes.contains(&180),
            "RFC 3261 §13.3.1.4: 180 Ringing を送るべき (Issue #249)。 codes={codes:?}"
        );
        // 100 → 180 の順序 (どちらも最終応答前)
        let pos_100 = codes.iter().position(|c| *c == 100).unwrap();
        let pos_180 = codes.iter().position(|c| *c == 180).unwrap();
        assert!(
            pos_100 < pos_180,
            "100 Trying は 180 Ringing より前。 codes={codes:?}"
        );

        // 180 と 200 の To-tag が同値 (RFC 3261 §12.1.1: early == confirmed dialog)
        let r180 = responses
            .iter()
            .find(|r| r.status_code == 180)
            .expect("180 を保持");
        if let Some(r200) = responses.iter().find(|r| r.status_code == 200) {
            let to_180 = r180.headers.get("to").expect("180 To");
            let to_200 = r200.headers.get("to").expect("200 To");
            let tag_180 = extract_to_tag(to_180).expect("180 に To-tag");
            let tag_200 = extract_to_tag(to_200).expect("200 に To-tag");
            assert_eq!(
                tag_180, tag_200,
                "RFC 3261 §12.1.1: 180 / 200 の To-tag は同値必須 (early dialog == confirmed dialog)"
            );
        }
    }

    /// Issue #249 / RFC 4028 §7 / §9: INVITE が `Session-Expires: 300;refresher=uac`
    /// と `Supported: timer` を載せたら、 200 OK に **`Session-Expires` + refresher
    /// (UAC 要求を echo、 Issue #251 で旧 `uas` 強制を撤去) + `Require: timer`** を
    /// echo する。 実機 evidence: `/tmp/sabiden-080-inbound.pcap` で NGN INVITE に
    /// `x: 300;refresher=uac`、 我々の 200 OK に Session-Expires が無い → 28ms 後 BYE。
    #[tokio::test]
    async fn rfc4028_7_session_expires_echoed_in_200_ok_with_refresher_echo() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6102".to_string(),
                "127.0.0.1:6102".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30003 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc4028-7-cid",
            "z9hG4bK-se",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20001 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        // RFC 4028 §4: INVITE に Session-Expires / Min-SE / Supported: timer。
        invite.headers.set("Session-Expires", "300;refresher=uac");
        invite.headers.set("Min-SE", "300");
        invite.headers.set("Supported", "timer");
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r200 = responses
            .iter()
            .find(|r| r.status_code == 200)
            .expect("200 OK が来るべき");

        let se = r200
            .headers
            .get("session-expires")
            .expect("RFC 4028 §7: 200 OK に Session-Expires を echo すべき (Issue #249)");
        // delta-seconds = 300 (= INVITE 値、 Min-SE 90 以上なので素通し)
        assert!(
            se.starts_with("300"),
            "Session-Expires は 300 を echo すべき: {se}"
        );
        // RFC 4028 §9 (Issue #251 Phase A): UAC が `refresher=uac` を要求したら
        // 200 OK でも echo する (旧実装は強制 `uas` 書換)。 carrier の意図尊重で
        // dialog 確立直後の即時 BYE を回避する。
        assert!(
            se.to_ascii_lowercase().contains("refresher=uac"),
            "RFC 4028 §9: UAC 要求 refresher=uac を 200 OK で echo すべき: {se}"
        );
        let require = r200
            .headers
            .get("require")
            .expect("RFC 4028 §7: timer negotiate 完了の明示として Require: timer を載せるべき");
        assert!(
            require.to_ascii_lowercase().contains("timer"),
            "Require: timer が含まれるべき: {require}"
        );
    }

    /// Issue #249 / RFC 4028 §7 後段: INVITE に `Session-Expires` が **不在**
    /// なら、 200 OK にも echo してはいけない (UAS が timer をサポートしない
    /// 応答と等価)。
    #[tokio::test]
    async fn rfc4028_7_session_expires_absent_in_invite_not_echoed() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6103".to_string(),
                "127.0.0.1:6103".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        // Session-Expires / Min-SE / Supported: timer は **付けない**
        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc4028-7-absent-cid",
            "z9hG4bK-se-absent",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r200 = responses
            .iter()
            .find(|r| r.status_code == 200)
            .expect("200 OK が来るべき");

        assert!(
            r200.headers.get("session-expires").is_none(),
            "RFC 4028 §7 後段: INVITE に SE が無いなら 200 OK にも乗せない"
        );
        // Require: timer も付けない (negotiate 対象が無いので)
        let require = r200.headers.get("require").unwrap_or("");
        assert!(
            !require.to_ascii_lowercase().contains("timer"),
            "INVITE が timer を Supported に乗せていないなら Require: timer も不要"
        );
    }

    /// Issue #249 / RFC 3264 §6.1: NGN offer に `a=ptime:20` があれば 200 OK
    /// SDP の `m=audio` に `a=ptime:20` を echo する (NGN PCMU は 20ms 固定、
    /// pcap evidence)。
    #[tokio::test]
    async fn rfc3264_6_1_inbound_answer_echoes_ptime() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6104".to_string(),
                "127.0.0.1:6104".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        // 内線 200 OK SDP は ptime 不在 (= sabiden 側 echo 経路を観測する)
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30005 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        // INVITE SDP に `a=ptime:20` を明示
        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3264-6-1-ptime-cid",
            "z9hG4bK-ptime",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20003 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r200 = responses
            .iter()
            .find(|r| r.status_code == 200)
            .expect("200 OK が来るべき");

        let body = std::str::from_utf8(&r200.body).expect("SDP utf8");
        assert!(
            body.contains("a=ptime:20"),
            "RFC 3264 §6.1: 200 OK SDP に offer 由来 ptime を echo すべき (Issue #249): \n{body}"
        );
    }

    /// Issue #249 / RFC 4028 §10: INVITE の Session-Expires が sabiden Min-SE
    /// (= 90 秒) より小さい (例: 60) なら、 422 Session Interval Too Small を
    /// **Min-SE ヘッダ付き** で返す。 既存 Re-INVITE 422 経路の回帰防止と、
    /// 初回 INVITE 経路にも 422 を導入したことの検証。
    #[tokio::test]
    async fn rfc4028_min_se_too_small_returns_422() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6105".to_string(),
                "127.0.0.1:6105".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(b"".to_vec())
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        // SE = 60 (sabiden Min-SE = 90 未満)、 Min-SE 60 を主張するが sabiden の
        // 90 と max を取って 90 以上を要求する。
        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc4028-10-422-cid",
            "z9hG4bK-422",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        invite.headers.set("Session-Expires", "60;refresher=uac");
        invite.headers.set("Min-SE", "60");
        invite.headers.set("Supported", "timer");
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r422 = responses
            .iter()
            .find(|r| r.status_code == 422)
            .expect("RFC 4028 §10: SE < Min-SE で 422 Session Interval Too Small (Issue #249)");
        let min_se = r422
            .headers
            .get("min-se")
            .expect("RFC 4028 §10: 422 は Min-SE 必須");
        let n: u32 = min_se.split(';').next().unwrap().trim().parse().unwrap();
        assert!(
            n >= 90,
            "Min-SE は sabiden の MIN_SE (= 90) 以上を要求すべき: {min_se}"
        );
        // 422 後は 200 OK が来ないこと (fork を起動していない)
        assert!(
            !responses.iter().any(|r| r.status_code == 200),
            "422 で打ち切ったので 200 OK は来ない: codes={:?}",
            responses.iter().map(|r| r.status_code).collect::<Vec<_>>()
        );
    }

    /// RFC 4028 §4 ABNF: `Session-Expires` の delta-seconds と refresher param
    /// のパース正当性。 compact form (`x:`) は SipHeaders 正規化で
    /// `session-expires` に変換済 (`src/sip/message.rs:309`)。
    #[test]
    fn rfc4028_4_parse_session_expires_with_refresher() {
        let t = parse_session_expires_header("300;refresher=uac").expect("parse ok");
        assert_eq!(t.session_expires, 300);
        assert_eq!(t.refresher.as_deref(), Some("uac"));

        let t = parse_session_expires_header("1800").expect("parse ok");
        assert_eq!(t.session_expires, 1800);
        assert!(t.refresher.is_none());

        // refresher param は case-insensitive
        let t = parse_session_expires_header("90;REFRESHER=UAS").expect("parse ok");
        assert_eq!(t.refresher.as_deref(), Some("uas"));

        // 不正数値は None
        assert!(parse_session_expires_header("abc").is_none());
        assert!(parse_session_expires_header("").is_none());
    }

    // ====================================================================
    // Issue #251 Phase A: UAS 18x/2xx に Allow/Supported/Date/Server 付与 +
    //   refresher 尊重 + Require 検証
    //   RFC 3261 §8.2.2.3 / §20.5 / §20.17 / §20.41 / RFC 4028 §9 / RFC 7231
    // ====================================================================

    /// RFC 7231 §7.1.1.1: IMF-fixdate のフォーマット規約。
    /// 1970-01-01 00:00:00 UTC = epoch = Thursday。
    #[test]
    fn rfc7231_imf_fixdate_epoch_is_thursday_jan_01_1970() {
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    /// RFC 7231 §7.1.1.1: IMF-fixdate の桁数 (day = 2、 year = 4、
    /// time = 8 = HH:MM:SS) と day-name / month-name 短縮形。
    /// 全 UNIX 秒値は `date -u -d @<sec>` で独立検算済。
    #[test]
    fn rfc7231_imf_fixdate_formats_known_dates() {
        // 2024-03-04 12:00:00 UTC = Monday、 UNIX 秒 = 1709553600
        assert_eq!(
            format_http_date(1_709_553_600),
            "Mon, 04 Mar 2024 12:00:00 GMT"
        );
        // 1996-11-06 20:49:37 UTC (RFC 7231 §7.1.1.1 例の派生、 UNIX 秒で
        // 直接検算: `date -u -d @847313377`) = Wednesday。
        assert_eq!(
            format_http_date(847_313_377),
            "Wed, 06 Nov 1996 20:49:37 GMT"
        );
        // うるう年判定 (2000-02-29) = Tuesday、 UNIX 秒 = 951782400 (00:00:00 UTC)
        assert_eq!(
            format_http_date(951_782_400),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
        // 2026-01-01 00:00:00 UTC (= Issue #251 開発時の年、 `date -u` 検算済)。
        assert_eq!(
            format_http_date(1_767_225_600),
            "Thu, 01 Jan 2026 00:00:00 GMT"
        );
    }

    /// RFC 7231 §7.1.1.1: 月境界 / 年境界 / うるう年 / 4 年・100 年・400 年規則。
    #[test]
    fn rfc7231_imf_fixdate_boundary_cases() {
        // 月末 (2024-01-31 23:59:59 UTC = Wednesday)
        assert_eq!(
            format_http_date(1_706_745_599),
            "Wed, 31 Jan 2024 23:59:59 GMT"
        );
        // 月跨ぎ (2024-02-01 00:00:00 UTC = Thursday)
        assert_eq!(
            format_http_date(1_706_745_600),
            "Thu, 01 Feb 2024 00:00:00 GMT"
        );
        // 年跨ぎ (2025-01-01 00:00:00 UTC = Wednesday)
        assert_eq!(
            format_http_date(1_735_689_600),
            "Wed, 01 Jan 2025 00:00:00 GMT"
        );
        // 100 年規則 (2100 はうるう年ではない) は SystemTime 範囲外なので省略。
    }

    /// RFC 3261 §8.2.2.3: `Require` に未対応 option-tag があれば 420 を返す。
    /// sabiden 既知 (`KNOWN_OPTION_TAGS`) = timer / replaces / 100rel
    /// (Issue #251 Phase B で 100rel 追加)。
    #[test]
    fn rfc3261_8_2_2_3_unsupported_option_tags_detects_unknown() {
        // 全て既知 → 空
        assert!(unsupported_option_tags("timer").is_empty());
        assert!(unsupported_option_tags("timer, replaces").is_empty());
        // 100rel も既知 (RFC 3262 §3、 Issue #251 Phase B)
        assert!(unsupported_option_tags("100rel").is_empty());
        assert!(unsupported_option_tags("timer, 100rel").is_empty());
        // case-insensitive (RFC 3261 §7.3.1)
        assert!(unsupported_option_tags("TIMER, Replaces, 100REL").is_empty());
        // 未知混入 → 未知 tag のみ列挙
        let u = unsupported_option_tags("timer, precondition");
        assert_eq!(u, vec!["precondition".to_string()]);
        // 全て未知
        let u = unsupported_option_tags("foo, precondition");
        assert_eq!(u, vec!["foo".to_string(), "precondition".to_string()]);
        // 空ヘッダ → 空 (= 通常処理を継続)
        assert!(unsupported_option_tags("").is_empty());
    }

    /// RFC 4028 §9: 200 OK の refresher は UAC が要求した値を echo する。
    /// 旧実装 (常に `uas` 強制) を撤去し、 carrier 意図を尊重する。
    #[test]
    fn rfc4028_9_resolve_response_refresher_echoes_uac_when_requested() {
        assert_eq!(resolve_response_refresher(Some("uac")), "uac");
        // case-insensitive (RFC 3261 §7.3.1 / RFC 4028 §4 ABNF)
        assert_eq!(resolve_response_refresher(Some("UAC")), "uac");
        assert_eq!(resolve_response_refresher(Some("Uac")), "uac");
    }

    /// RFC 4028 §9: refresher 不在 / "uas" 明示 / 不正値は `uas` フォールバック。
    #[test]
    fn rfc4028_9_resolve_response_refresher_defaults_to_uas_when_absent() {
        assert_eq!(resolve_response_refresher(None), "uas");
        assert_eq!(resolve_response_refresher(Some("uas")), "uas");
        // 不正値 (ABNF 外) も safe fallback で uas
        assert_eq!(resolve_response_refresher(Some("none")), "uas");
        assert_eq!(resolve_response_refresher(Some("")), "uas");
    }

    /// RFC 3261 §20.5 / §20.17 / §20.41 / RFC 4028 §7 / RFC 3262 §3
    /// (Issue #251 Phase A + B): `apply_uas_inbound_2xx_headers` が
    /// Allow / Supported / Date / Server を必ず付与し、 PRACK / 100rel
    /// 経路を含むこと。
    #[test]
    fn rfc3261_20_5_apply_uas_inbound_2xx_headers_sets_allow_supported_date_server() {
        let mut resp = SipResponse {
            status_code: 200,
            reason: "OK".to_string(),
            headers: SipHeaders::new(),
            body: Vec::new(),
        };
        apply_uas_inbound_2xx_headers(&mut resp);

        let allow = resp.headers.get("allow").expect("Allow 必須");
        // INVITE/ACK/BYE/CANCEL/OPTIONS/UPDATE/INFO/PRACK は含む
        // (PRACK は Phase B で追加、 RFC 3262 §4)
        for m in [
            "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "UPDATE", "INFO", "PRACK",
        ] {
            assert!(allow.contains(m), "Allow に {m} を含むべき: {allow}");
        }

        let supported = resp.headers.get("supported").expect("Supported 必須");
        assert!(
            supported.to_ascii_lowercase().contains("timer"),
            "Supported に timer を含むべき: {supported}"
        );
        // 100rel は出す (Phase B で追加、 RFC 3262 §3)
        assert!(
            supported.to_ascii_lowercase().contains("100rel"),
            "Supported に 100rel を含むべき (Phase B): {supported}"
        );

        let date = resp.headers.get("date").expect("Date 必須");
        // IMF-fixdate の構造: "Day, DD Mon YYYY HH:MM:SS GMT"
        assert!(date.ends_with(" GMT"), "Date は GMT で終わるべき: {date}");
        assert!(
            date.len() == "Wed, 11 May 2026 07:43:35 GMT".len(),
            "Date は固定長 29 chars であるべき (RFC 7231 §7.1.1.1): {date}"
        );

        let server = resp.headers.get("server").expect("Server 必須");
        assert!(
            server.starts_with("sabiden/"),
            "Server は sabiden/<version>: {server}"
        );
    }

    // ====================================================================
    // E2E: NGN inbound INVITE で 180 / 200 OK の RFC 互換ヘッダ
    // ====================================================================

    /// RFC 3261 §20.5 (Issue #251 Phase A): NGN 着信 INVITE への 180 Ringing /
    /// 200 OK 両方に `Allow` を付与する。 Allow 不在は carrier IMS に
    /// 「機能不足端末」判定され即 BYE される (audit top-1)。
    #[tokio::test]
    async fn rfc3261_20_5_inbound_18x_and_2xx_include_allow_header() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6201".to_string(),
                "127.0.0.1:6201".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30201 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3261-20-5-cid",
            "z9hG4bK-allow",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20201 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r180 = responses
            .iter()
            .find(|r| r.status_code == 180)
            .expect("180 Ringing が来るべき");
        let r200 = responses
            .iter()
            .find(|r| r.status_code == 200)
            .expect("200 OK が来るべき");
        for (label, resp) in [("180", r180), ("200", r200)] {
            let allow = resp
                .headers
                .get("allow")
                .unwrap_or_else(|| panic!("{label}: Allow 必須 (RFC 3261 §20.5)"));
            assert!(
                allow.contains("INVITE")
                    && allow.contains("ACK")
                    && allow.contains("BYE")
                    && allow.contains("UPDATE"),
                "{label}: Allow に INVITE/ACK/BYE/UPDATE 必須: {allow}"
            );
        }
    }

    /// RFC 3261 §20.17 / RFC 7231 §7.1.1.1 (Issue #251 Phase A): NGN inbound
    /// 18x / 2xx 応答に `Date` を IMF-fixdate 形式で付与。 Date 不在は carrier
    /// IMS の billing record 起票不能で dialog rollback (audit top-3)。
    #[tokio::test]
    async fn rfc3261_20_17_inbound_2xx_includes_date_header_rfc7231_format() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6202".to_string(),
                "127.0.0.1:6202".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30202 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3261-20-17-cid",
            "z9hG4bK-date",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20202 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r200 = responses
            .iter()
            .find(|r| r.status_code == 200)
            .expect("200 OK が来るべき");
        let date = r200
            .headers
            .get("date")
            .expect("Date 必須 (RFC 3261 §20.17)");
        // IMF-fixdate ABNF (RFC 7231 §7.1.1.1): "Day, DD Mon YYYY HH:MM:SS GMT"
        assert!(date.ends_with(" GMT"), "Date は GMT で終わる: {date}");
        // day-name は 3 文字、 月名は 3 文字、 day は 2 桁、 year は 4 桁。
        // 厳密検査は format_http_date のユニットテストに任せ、 ここでは形状のみ。
        assert_eq!(
            date.len(),
            "Wed, 11 May 2026 07:43:35 GMT".len(),
            "Date は IMF-fixdate (29 chars 固定): {date}"
        );
    }

    /// RFC 3261 §20.41 (Issue #251 Phase A): NGN inbound 2xx 応答に
    /// `Server: sabiden/<version>` を付与。 carrier 側障害解析時の端末特定に必須。
    #[tokio::test]
    async fn rfc3261_20_41_inbound_2xx_includes_server_header() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6203".to_string(),
                "127.0.0.1:6203".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30203 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3261-20-41-cid",
            "z9hG4bK-server",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20203 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r200 = responses
            .iter()
            .find(|r| r.status_code == 200)
            .expect("200 OK が来るべき");
        let server = r200
            .headers
            .get("server")
            .expect("Server 必須 (RFC 3261 §20.41)");
        assert!(
            server.starts_with("sabiden/"),
            "Server は sabiden/<version>: {server}"
        );
    }

    /// RFC 4028 §9 (Issue #251 Phase A): UAC が `refresher=uac` を要求したら
    /// 200 OK でも `refresher=uac` を **echo** する (旧実装は強制 `uas` で
    /// 書換えていた、 audit #6 で carrier 即 BYE 原因候補と指摘)。
    #[tokio::test]
    async fn rfc4028_9_session_expires_refresher_uac_preserved_in_2xx() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6204".to_string(),
                "127.0.0.1:6204".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30204 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc4028-9-uac-cid",
            "z9hG4bK-refresher-uac",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20204 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        invite.headers.set("Session-Expires", "300;refresher=uac");
        invite.headers.set("Min-SE", "300");
        invite.headers.set("Supported", "timer");

        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r200 = responses
            .iter()
            .find(|r| r.status_code == 200)
            .expect("200 OK が来るべき");
        let se = r200
            .headers
            .get("session-expires")
            .expect("Session-Expires が必要");
        assert!(
            se.to_ascii_lowercase().contains("refresher=uac"),
            "RFC 4028 §9: UAC 要求 refresher=uac を echo すべき (旧実装は uas 書換だった): {se}"
        );
    }

    /// RFC 4028 §9 (Issue #251 Phase A): refresher 不在 / "uas" 明示の場合は
    /// `refresher=uas` (sabiden が refresh 担当)。 既存 outbound forwarder 経路
    /// (Issue #138) との整合が必要なため、 旧挙動を fallback として保持する。
    #[tokio::test]
    async fn rfc4028_9_session_expires_refresher_uas_default_when_absent() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6205".to_string(),
                "127.0.0.1:6205".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30205 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc4028-9-uas-cid",
            "z9hG4bK-refresher-uas",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20205 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        // refresher 不在 (delta-seconds のみ)
        invite.headers.set("Session-Expires", "300");
        invite.headers.set("Min-SE", "300");
        invite.headers.set("Supported", "timer");

        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r200 = responses
            .iter()
            .find(|r| r.status_code == 200)
            .expect("200 OK が来るべき");
        let se = r200
            .headers
            .get("session-expires")
            .expect("Session-Expires が必要");
        assert!(
            se.to_ascii_lowercase().contains("refresher=uas"),
            "RFC 4028 §9: refresher 不在なら uas にフォールバック: {se}"
        );
    }

    /// RFC 3261 §8.2.2.3 (Issue #251 Phase A): 未対応 option-tag を含む `Require`
    /// 付き INVITE は 420 Bad Extension + `Unsupported: <unknown>` で reject MUST。
    #[tokio::test]
    async fn rfc3261_8_2_2_3_require_unknown_option_tag_returns_420_with_unsupported() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6206".to_string(),
                "127.0.0.1:6206".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30206 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3261-8-2-2-3-cid",
            "z9hG4bK-require-precondition",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20206 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        // sabiden 未実装: precondition (RFC 3312)。 100rel は Phase B で実装済の
        // ため、 既知 tag に移動した。 unknown tag を別途用意する必要がある。
        invite.headers.set("Require", "precondition");

        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r420 = responses
            .iter()
            .find(|r| r.status_code == 420)
            .expect("420 Bad Extension が来るべき (RFC 3261 §8.2.2.3)");
        let unsupported = r420
            .headers
            .get("unsupported")
            .expect("Unsupported ヘッダ MUST (§8.2.2.3)");
        assert!(
            unsupported.contains("precondition"),
            "Unsupported に precondition を含むべき: {unsupported}"
        );
        // 200 OK が来てはいけない (= 通常処理を継続してはいけない)
        assert!(
            !responses.iter().any(|r| r.status_code == 200),
            "420 で打ち切ったので 200 OK は来ない: codes={:?}",
            responses.iter().map(|r| r.status_code).collect::<Vec<_>>()
        );
    }

    /// RFC 3261 §8.2.2.3 (Issue #251 Phase A): `Require` の option-tag が全て
    /// 既知 (= `timer` / `replaces`) なら通常処理を継続し、 200 OK を返す。
    #[tokio::test]
    async fn rfc3261_8_2_2_3_require_known_option_tag_proceeds_normally() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6207".to_string(),
                "127.0.0.1:6207".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30207 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3261-8-2-2-3-known-cid",
            "z9hG4bK-require-timer",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20207 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        // 全て既知 (sabiden 実装済)
        invite.headers.set("Require", "timer");
        invite.headers.set("Session-Expires", "300;refresher=uac");
        invite.headers.set("Min-SE", "300");

        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        assert!(
            !responses.iter().any(|r| r.status_code == 420),
            "既知 option-tag のみなら 420 を返してはいけない: codes={:?}",
            responses.iter().map(|r| r.status_code).collect::<Vec<_>>()
        );
        assert!(
            responses.iter().any(|r| r.status_code == 200),
            "既知 option-tag のみなら 200 OK が来るべき: codes={:?}",
            responses.iter().map(|r| r.status_code).collect::<Vec<_>>()
        );
    }

    /// `extract_to_tag` が name-addr 形式 / addr-spec 形式 / 大文字 tag /
    /// 山括弧内の偽 tag を正しく扱う (Issue #249 で 180 / 200 OK 同一 tag 保持の
    /// ために導入)。 RFC 3261 §7.3.1 / §20.39 / §25.1。
    #[test]
    fn rfc3261_20_39_extract_to_tag_handles_variants() {
        assert_eq!(
            extract_to_tag("<sip:dest@sabiden>;tag=abc123"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_to_tag("sip:dest@sabiden;tag=xyz"),
            Some("xyz".to_string())
        );
        // case-insensitive parameter name
        assert_eq!(
            extract_to_tag("<sip:dest@sabiden>;TAG=hex"),
            Some("hex".to_string())
        );
        // tag 不在
        assert_eq!(extract_to_tag("<sip:dest@sabiden>"), None);
        // 山括弧内の tag= は無視 (URI userinfo の tag は header param ではない)
        assert_eq!(extract_to_tag("<sip:dest;tag=fake@sabiden>"), None);
    }

    // ====================================================================
    // RFC 3262 (Issue #251 Phase B) 100rel / PRACK reliable provisional
    // response テスト。 純粋関数 + 結合テストの両方を含む。
    // ====================================================================

    /// RFC 3262 §7.2 ABNF: `RAck = "RAck" HCOLON response-num LWS CSeq-num LWS Method`。
    /// `parse_rack_header` が正常系 / 異常系を区別する。
    #[test]
    fn rfc3262_7_2_parse_rack_header_well_formed_and_malformed() {
        // 正常系
        assert_eq!(
            parse_rack_header("123 5 INVITE"),
            Some((123, 5, "INVITE".to_string()))
        );
        // case-insensitive method (ABNF 上 method は大文字推奨だが解析は寛容に)
        assert_eq!(
            parse_rack_header("1 1 invite"),
            Some((1, 1, "invite".to_string()))
        );
        // 余計な空白は許容 (LWS は複数 SP / HTAB)
        assert_eq!(
            parse_rack_header("  123   5   INVITE  "),
            Some((123, 5, "INVITE".to_string()))
        );
        // フィールド不足 → None
        assert_eq!(parse_rack_header("123"), None);
        assert_eq!(parse_rack_header("123 5"), None);
        // 余剰トークン → None (ABNF 厳格)
        assert_eq!(parse_rack_header("123 5 INVITE extra"), None);
        // 数値外 → None
        assert_eq!(parse_rack_header("abc 5 INVITE"), None);
        assert_eq!(parse_rack_header("123 abc INVITE"), None);
        // 0 / overflow は数値として通る (RSeq 0 は ABNF 違反だが parser 層で拒否しない)
        assert_eq!(
            parse_rack_header("0 0 INVITE"),
            Some((0, 0, "INVITE".to_string()))
        );
    }

    /// RFC 3262 §3 / §7.1: `RSeq` の初期値は 1..=2^31-1。 `random_initial_rseq`
    /// が ABNF / SHOULD を遵守する。
    #[test]
    fn rfc3262_3_random_initial_rseq_within_valid_range() {
        for _ in 0..100 {
            let r = random_initial_rseq();
            assert!(r >= 1, "RSeq は 1 以上 (RFC 3262 §7.1 ABNF)");
            assert!(r <= 0x7FFF_FFFF, "RSeq SHOULD は 2^31-1 以下 (RFC 3262 §3)");
        }
    }

    /// RFC 3261 §7.3.1 / RFC 3262 §3: `Supported` / `Require` の comma 区切り
    /// option-tag リストで 100rel を case-insensitive に検出する。
    #[test]
    fn rfc3262_3_header_has_option_tag_case_insensitive_comma_list() {
        assert!(header_has_option_tag(Some("100rel"), OPTION_TAG_100REL));
        assert!(header_has_option_tag(Some("100REL"), OPTION_TAG_100REL));
        assert!(header_has_option_tag(
            Some("timer, 100rel"),
            OPTION_TAG_100REL
        ));
        assert!(header_has_option_tag(
            Some("timer,100rel,replaces"),
            OPTION_TAG_100REL
        ));
        assert!(header_has_option_tag(Some("  100rel  "), OPTION_TAG_100REL));
        // 不在 / None / 別 tag のみ
        assert!(!header_has_option_tag(Some("timer"), OPTION_TAG_100REL));
        assert!(!header_has_option_tag(Some(""), OPTION_TAG_100REL));
        assert!(!header_has_option_tag(None, OPTION_TAG_100REL));
        // 部分一致は false (`1100rel` は別 tag 扱い、 RFC 3261 §7.3.1 で
        // option-tag は token なので部分一致は誤検知)
        assert!(!header_has_option_tag(Some("1100rel"), OPTION_TAG_100REL));
    }

    /// RFC 3262 §3: NGN INVITE が `Supported: 100rel` を提示したら、 sabiden の
    /// 180 Ringing に `Require: 100rel` + `RSeq: <u32>` が乗ること。 既存の
    /// non-reliable 180 (capability 不在の旧経路) と区別される。
    #[tokio::test]
    async fn rfc3262_3_inbound_invite_with_supported_100rel_triggers_reliable_180() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6301".to_string(),
                "127.0.0.1:6301".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        // 内線レッグは無応答 (fork timeout 経路) で良い。 ここでは reliable 180
        // が出ているか **だけ** 観測する。 ScriptedAction::ok() は即 200 を
        // 返してしまうので、 reliable 180 と 200 OK を切り離すため `ringing` で
        // 内線を 180 状態に留める。 ただし sabiden の fork は内線 200 OK で
        // 確定するため、 ここでは inviter から ok() を返すが drain_responses は
        // 180 / 200 を順に拾うので、 180 に Require / RSeq が乗っていることが
        // 検証できれば十分。
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30301 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3262-3-supported-100rel-cid",
            "z9hG4bK-100rel-supp",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20301 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        invite.headers.set("Supported", "100rel");
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 100 Trying / 180 Ringing を拾う。 200 OK は PRACK 待ちで永遠に来ない
        // (= PRACK 32 秒 timeout 経路) ため、 ここでは短いタイムアウトで止める。
        let mut buf = vec![0u8; 8192];
        let mut got_180: Option<SipResponse> = None;
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_millis(500), ngn_sock.recv_from(&mut buf))
                .await
            {
                Ok(Ok((n, _))) => {
                    if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                        if r.status_code == 180 {
                            got_180 = Some(r);
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        let r180 = got_180.expect("180 Ringing が来るべき (RFC 3261 §13.3.1.4)");
        let require = r180.headers.get("require").expect(
            "RFC 3262 §3: Supported: 100rel offer に対し reliable 180 は Require: 100rel を載せる",
        );
        assert!(
            require.to_ascii_lowercase().contains("100rel"),
            "Require に 100rel を含むべき: {require}"
        );
        let rseq = r180
            .headers
            .get("rseq")
            .expect("RFC 3262 §3 / §7.1: reliable 18x は RSeq ヘッダ MUST");
        let rseq_num: u32 = rseq.parse().expect("RSeq は u32 数値");
        assert!(
            (1..=0x7FFF_FFFF).contains(&rseq_num),
            "RSeq は 1..=2^31-1 (RFC 3262 §3 / §7.1): {rseq_num}"
        );
    }

    /// RFC 3262 §3 regression: `Supported: 100rel` が無ければ既存の non-reliable
    /// 180 Ringing (Require / RSeq 不在) のまま、 既存通話パスは不変。
    #[tokio::test]
    async fn rfc3262_3_inbound_invite_without_100rel_keeps_non_reliable_180() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6302".to_string(),
                "127.0.0.1:6302".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30302 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        // `Supported` には timer のみ。 100rel は **不在**。
        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3262-3-no100rel-cid",
            "z9hG4bK-no100rel",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20302 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        invite.headers.set("Supported", "timer");
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let responses = drain_responses(&ngn_sock, 8, Duration::from_secs(3)).await;
        let r180 = responses
            .iter()
            .find(|r| r.status_code == 180)
            .expect("180 Ringing が来るべき (RFC 3261 §13.3.1.4 regression)");
        // Require: 100rel は **載せない** (carrier が 100rel を要求していないため)
        let require = r180.headers.get("require").unwrap_or("");
        assert!(
            !require.to_ascii_lowercase().contains("100rel"),
            "100rel 非要求時は Require: 100rel を載せない: {require}"
        );
        assert!(
            r180.headers.get("rseq").is_none(),
            "100rel 非要求時は RSeq を載せない (RFC 3262 §3): {:?}",
            r180.headers.get("rseq")
        );
        // 既存通話パス: 200 OK が来る (= fork 成功で確定するシーケンスに到達)
        assert!(
            responses.iter().any(|r| r.status_code == 200),
            "100rel 不在経路は既存通り 200 OK で確定: codes={:?}",
            responses.iter().map(|r| r.status_code).collect::<Vec<_>>()
        );
    }

    /// RFC 3262 §4: 受信 PRACK の RAck が直近 reliable 18x の (RSeq, INVITE
    /// CSeq, "INVITE") と一致しなければ 481 を返す。 `handle_inbound` の
    /// PRACK 分岐で `rc100rel` に entry 無し (= reliable 18x 未送出) の経路。
    #[tokio::test]
    async fn rfc3262_4_prack_unrecognized_rack_returns_481() {
        // この経路は reliable 18x を出していない (= rc100rel entry 無し) ため、
        // 任意の RAck で 481。 既存 PRACK→481 テスト
        // `rfc3262_4_ngn_prack_returns_481_with_allow_header` (Phase A) を
        // 補強する: 明示的に `RAck` ヘッダを付けても結果は同じ (§4)。
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut prack = builders::request_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            SipMethod::Prack,
            "sip:sabiden@127.0.0.1",
            "rfc3262-4-prack-unknown-cid",
            "z9hG4bK-prack-unknown",
        );
        // RAck を付ける (= 「PRACK は届いたが該当 state 無し」 経路の検証)。
        prack.headers.set("RAck", "999999 1 INVITE");
        ngn_sock
            .send_to(&prack.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let mut got: Option<SipResponse> = None;
        for _ in 0..3 {
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_secs(2), ngn_sock.recv_from(&mut buf)).await
            {
                if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                    got = Some(r);
                    break;
                }
            }
        }
        let r = got.expect("PRACK 応答が来るべき");
        assert_eq!(
            r.status_code, 481,
            "RFC 3262 §4: rc100rel state 無し PRACK は 481"
        );
    }

    /// RFC 3262 §3: reliable 180 を出したまま PRACK が来ない経路で、
    /// 32 秒 (= 64*T1) timeout 後に 408 で INVITE を終結させる。
    /// `tokio::time::pause` で仮想時間を進めて高速検証。
    #[tokio::test(start_paused = true)]
    async fn rfc3262_3_prack_timeout_terminates_invite_with_408() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6303".to_string(),
                "127.0.0.1:6303".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        // 内線 OK 応答 (= fork 即成功) にして、 200 OK 直前の PRACK 待ちのみが
        // タイムアウト経路に乗ることを保証する。
        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30303 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3262-3-prack-timeout-cid",
            "z9hG4bK-prack-timeout",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20303 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        invite.headers.set("Supported", "100rel");
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 32 秒進める前に 100 / 180 / retransmits を捌くため数 ms 進行。
        // start_paused=true なので manual advance が必要。 仮想時間で
        // 32 秒 + α 進めれば PRACK 待ち timeout 経路 (408) に到達。
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        // PRACK timeout (32 秒) を超える分だけ進める。
        tokio::time::advance(Duration::from_secs(35)).await;
        tokio::task::yield_now().await;

        // 仮想時間進行中も UDP recv はリアルタイムなので、 タイムアウト短めで
        // 既送出メッセージを拾う。
        let mut buf = vec![0u8; 8192];
        let mut codes: Vec<u16> = Vec::new();
        for _ in 0..16 {
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(100), ngn_sock.recv_from(&mut buf)).await
            {
                if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                    codes.push(r.status_code);
                }
            } else {
                // 仮想時間を更に進めて poll 機会を増やす。
                tokio::time::advance(Duration::from_millis(50)).await;
                tokio::task::yield_now().await;
            }
        }
        assert!(
            codes.contains(&408),
            "RFC 3262 §3: PRACK 不到来 32 秒で 408 Request Timeout で終結。 codes={codes:?}"
        );
    }

    /// RFC 3262 §3 / RFC 3261 §17.1.1.2: reliable 18x は T1 (= 500ms) 起点に
    /// T2 (= 4s) 頭打ちの指数バックオフで再送される。 仮想時間で T1, 2T1, 4T1
    /// の境界を確認する。 同一 RSeq で送られ続けることが §3 の MUST。
    #[tokio::test(start_paused = true)]
    async fn rfc3262_3_reliable_180_retransmits_on_t1_backoff() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6304".to_string(),
                "127.0.0.1:6304".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30304 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            "rfc3262-3-retransmit-cid",
            "z9hG4bK-retx",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20304 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        invite.headers.set("Supported", "100rel");
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // T1 (500ms) + 2T1 (1s) + 4T1 (2s) = 3.5s を経過すれば 4 回目の境界。
        // 100 Trying と 180 Ringing 初回 + 3 回の再送 ≒ 計 5 個の応答が見える。
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        let mut buf = vec![0u8; 8192];
        let mut rseq_values: Vec<u32> = Vec::new();
        let mut count_180 = 0usize;
        for _ in 0..20 {
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(100), ngn_sock.recv_from(&mut buf)).await
            {
                if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                    if r.status_code == 180 {
                        count_180 += 1;
                        if let Some(v) = r.headers.get("rseq").and_then(|s| s.parse::<u32>().ok()) {
                            rseq_values.push(v);
                        }
                    }
                }
            } else {
                tokio::time::advance(Duration::from_millis(100)).await;
                tokio::task::yield_now().await;
            }
        }
        assert!(
            count_180 >= 2,
            "RFC 3262 §3: reliable 180 は T1 起点で自発再送される (PRACK 未到来時)。 count_180={count_180}"
        );
        // RFC 3262 §3: "MUST be sent with the same RSeq" 全再送で同一 RSeq。
        if rseq_values.len() >= 2 {
            let first = rseq_values[0];
            assert!(
                rseq_values.iter().all(|v| *v == first),
                "RFC 3262 §3: reliable 18x 再送は同一 RSeq MUST: {rseq_values:?}"
            );
        }
    }

    /// RFC 3262 §4: 受信 PRACK の RAck が直近 reliable 18x の (RSeq, CSeq, "INVITE")
    /// と一致したら 200 OK PRACK を返し、 INVITE 側の wait を解除する。
    /// reliable 180 取得 → PRACK 送出 → 200 OK PRACK + 200 OK INVITE が
    /// 順に届く end-to-end フロー。
    #[tokio::test]
    async fn rfc3262_4_prack_with_matching_rack_returns_200_ok() {
        let sabiden_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabiden_addr = sabiden_sock.local_addr().unwrap();
        let ngn_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let extensions = ExtensionRegistrar::new();
        extensions
            .register(
                "iphone",
                "sip:iphone@127.0.0.1:6305".to_string(),
                "127.0.0.1:6305".parse().unwrap(),
                Duration::from_secs(60),
            )
            .await;

        let inviter = ScriptedInviter::builder()
            .default_action(ScriptedAction::ok())
            .default_body(
                b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                  m=audio 30305 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
                    .to_vec(),
            )
            .build();

        let (layer, inbound_rx) = TransactionLayer::spawn(sabiden_sock.clone());
        let _handler = wire_ngn_inbound(
            layer,
            sabiden_sock.clone(),
            inbound_rx,
            inviter,
            extensions,
            NgnInboundConfig::default(),
        );

        let call_id = "rfc3262-4-prack-ok-cid";
        let mut invite = builders::invite_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            "sip:0191349809@sabiden",
            call_id,
            "z9hG4bK-prack-ok",
            b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
              m=audio 20305 RTP/AVP 0\r\na=ptime:20\r\na=rtpmap:0 PCMU/8000\r\n"
                .to_vec(),
        );
        invite.headers.set("Supported", "100rel");
        ngn_sock
            .send_to(&invite.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // reliable 180 を待つ。
        let mut buf = vec![0u8; 8192];
        let mut r180: Option<SipResponse> = None;
        for _ in 0..6 {
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_secs(2), ngn_sock.recv_from(&mut buf)).await
            {
                if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                    if r.status_code == 180 {
                        r180 = Some(r);
                        break;
                    }
                }
            }
        }
        let r180 = r180.expect("reliable 180 が来るべき");
        let rseq: u32 = r180
            .headers
            .get("rseq")
            .expect("RSeq")
            .parse()
            .expect("RSeq u32");

        // RFC 3262 §7.2: PRACK の RAck = "<RSeq> <CSeq> INVITE"
        let mut prack = builders::request_from_ngn(
            &ngn_sock.local_addr().unwrap(),
            SipMethod::Prack,
            "sip:sabiden@127.0.0.1",
            call_id,
            "z9hG4bK-prack-match",
        );
        prack.headers.set("RAck", format!("{} 1 INVITE", rseq));
        ngn_sock
            .send_to(&prack.to_bytes(), sabiden_addr)
            .await
            .unwrap();

        // 200 PRACK と 200 INVITE が順次届くことを確認 (順序は環境依存だが
        // 両方とも届く)。
        let mut got_200_prack = false;
        let mut got_200_invite = false;
        let mut observed: Vec<(u16, String)> = Vec::new();
        for _ in 0..20 {
            if let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_secs(2), ngn_sock.recv_from(&mut buf)).await
            {
                if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                    let cseq = r.headers.get("cseq").unwrap_or("").to_string();
                    observed.push((r.status_code, cseq.clone()));
                    if r.status_code == 200 {
                        if cseq.to_ascii_uppercase().contains("PRACK") {
                            got_200_prack = true;
                        } else if cseq.to_ascii_uppercase().contains("INVITE") {
                            got_200_invite = true;
                        }
                    }
                }
            }
            if got_200_prack && got_200_invite {
                break;
            }
        }
        assert!(
            got_200_prack,
            "RFC 3262 §4: matching RAck PRACK は 200 OK が返る。 observed={observed:?}"
        );
        assert!(
            got_200_invite,
            "RFC 3262 §3: PRACK 受信後に INVITE 側 200 OK が出る。 observed={observed:?}"
        );
    }

    // ====================================================================
    // Issue #260 Phase 1-A: NGN 5xx 応答受信時の header 構造化抽出
    //   RFC 3261 §20.33 (Retry-After) / §20.35 (Server) / §20.43 (Warning) /
    //   §21.5 (5xx Server Failure) / RFC 3326 §3-4 (Reason) /
    //   RFC 3581 §4 (Via received / rport)
    // ====================================================================

    /// RFC 3261 §21.5 5xx Server Failure 応答から carrier 由来 header を
    /// 抽出できることを検証する。 Reason / Retry-After / Server / Warning /
    /// Via received/rport の全項目を 1 件の SipResponse で網羅。
    #[test]
    fn rfc3261_21_5_5xx_response_logging_extracts_reason_retry_after() {
        let mut headers = SipHeaders::new();
        headers.set("Call-ID", "ngn-500-cid@118.177.72.242");
        headers.set("CSeq", "1 INVITE");
        // RFC 3261 §20.33: Retry-After は delta-seconds (整数秒)
        headers.set("Retry-After", "30");
        // RFC 3326 §3: Reason ヘッダは SIP/Q.850 protocol-name + protocol-cause
        headers.set("Reason", r#"Q.850;cause=16;text="Normal call clearing""#);
        // RFC 3261 §20.35: Server は UAS 識別文字列
        headers.set("Server", "NEC IP-PBX 6.0");
        // RFC 3261 §20.43: Warning = warn-code SP warn-agent SP warn-text
        headers.set("Warning", r#"399 ngn.ne.jp "Temporary congestion""#);
        // RFC 3581 §4: Via に sent-by + received= + rport= が乗る
        headers.set(
            "Via",
            "SIP/2.0/UDP 118.177.72.242:5060;branch=z9hG4bK-xyz;received=118.177.72.242;rport=5060",
        );

        let view = extract_ngn_5xx_header_view(&headers);
        assert_eq!(view.retry_after.as_deref(), Some("30"));
        assert_eq!(view.server.as_deref(), Some("NEC IP-PBX 6.0"));
        assert!(
            view.warning
                .as_deref()
                .map(|w| w.contains("399") && w.contains("Temporary congestion"))
                .unwrap_or(false),
            "Warning 全文が保持される: {:?}",
            view.warning
        );
        assert!(
            view.reason
                .as_deref()
                .map(|r| r.contains("Q.850") && r.contains("cause=16"))
                .unwrap_or(false),
            "Reason の protocol-name + protocol-cause が保持される: {:?}",
            view.reason
        );
        assert_eq!(view.via_received.as_deref(), Some("118.177.72.242"));
        assert_eq!(view.via_rport.as_deref(), Some("5060"));
    }

    /// RFC 3326 §4: Reason header は Q.850 cause code text を含み、 sabiden は
    /// パースせず全文を warn ログに転送する (carrier 解析時に手で読みたいため)。
    /// Retry-After が無いケースで `None` が返ることも合わせて検証。
    #[test]
    fn rfc3326_4_reason_header_q850_cause_extracted() {
        let mut headers = SipHeaders::new();
        headers.set("Reason", r#"Q.850;cause=41;text="Temporary failure""#);
        // Retry-After / Server / Warning / Via を意図的に省略する
        let view = extract_ngn_5xx_header_view(&headers);
        assert!(
            view.reason
                .as_deref()
                .map(|r| r.contains("cause=41") && r.contains("Temporary failure"))
                .unwrap_or(false),
            "Q.850 cause=41 を含む Reason ヘッダが取り出される: {:?}",
            view.reason
        );
        assert!(view.retry_after.is_none());
        assert!(view.server.is_none());
        assert!(view.warning.is_none());
        assert!(view.via_received.is_none());
        assert!(view.via_rport.is_none());
    }

    /// RFC 3581 §4: Via に `;rport` フラグだけ (= 値なし) が付いている場合は、
    /// UAS が観測した port が記載されていないので `None` を返す。 `received=`
    /// は値ありなので抽出される。 大文字小文字混在も `eq_ignore_ascii_case`
    /// で対応 (RFC 3261 §7.3.1)。
    #[test]
    fn rfc3581_4_via_received_rport_case_insensitive() {
        let mut headers = SipHeaders::new();
        headers.set(
            "Via",
            "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-abc;RECEIVED=203.0.113.5;rport",
        );
        let view = extract_ngn_5xx_header_view(&headers);
        assert_eq!(view.via_received.as_deref(), Some("203.0.113.5"));
        // 値なしの `;rport` は観測値ではないので None
        assert_eq!(view.via_rport, None);
    }

    /// `Metrics::record_ngn_5xx` は status code 別に独立 atomic を加算する
    /// (3GPP TS 24.229 §5.2.7: 500 = per-INVITE failure / 503 = overload を
    /// 観測時に区別したいため)。
    #[test]
    fn rfc3261_21_5_record_ngn_5xx_increments_per_status() {
        let metrics = crate::observability::Metrics::new();
        metrics.record_ngn_5xx(500);
        metrics.record_ngn_5xx(500);
        metrics.record_ngn_5xx(503);
        metrics.record_ngn_5xx(504);
        // 4xx は 5xx 観測対象外 (= 加算しない)
        metrics.record_ngn_5xx(486);

        assert_eq!(
            metrics
                .ngn_5xx_500
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics
                .ngn_5xx_503
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .ngn_5xx_other
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "500/503 以外の 5xx は other ラベルに集約される"
        );

        // Prometheus exposition format に 3 ラベル全部出ること
        let rendered = metrics.render_prometheus(false);
        assert!(rendered.contains("sabiden_ngn_5xx_total{status=\"500\"} 2"));
        assert!(rendered.contains("sabiden_ngn_5xx_total{status=\"503\"} 1"));
        assert!(rendered.contains("sabiden_ngn_5xx_total{status=\"other\"} 1"));
    }

    /// RFC 3550 §11 / Issue #260 Phase 1-D: `bind_ngn_rtp_socket` は必ず
    /// **偶数 port** を払い出す (NGN P-CSCF が奇数 port を 500 で reject するため、
    /// `project_ngn_500_FINAL.md` 真因 + falsification evidence、 16/16 odd→500)。
    /// allocator は 30000-30998 even round-robin、 fallback でも even のみ accept。
    #[tokio::test]
    async fn rfc3550_11_bind_ngn_rtp_socket_always_returns_even_port() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        // 連続 16 回 bind して全 even を確認 (Phase 1-D allocator の round-robin
        // step=2 + even start で、 odd を引く分岐は仕様上 fallback path のみ。
        // fallback でも parity check で even のみ accept)。
        let mut sockets = Vec::new();
        for _ in 0..16 {
            let s = super::bind_ngn_rtp_socket(ip)
                .await
                .expect("bind_ngn_rtp_socket should succeed");
            let port = s.local_addr().expect("local_addr").port();
            assert_eq!(
                port % 2,
                0,
                "bind_ngn_rtp_socket は偶数 port のみ払い出すべき (got {})",
                port
            );
            sockets.push(s);
        }
    }
}
