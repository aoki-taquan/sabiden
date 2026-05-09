//! 通話制御 (Call Manager)
//!
//! NGN 側 UAC (`sip::uac::Uac`) と内線 UAS (`sip::uas::ExtensionUas`) の
//! 二つのレッグを束ね、Asterisk 風のフォーク着信と RTP リレーを行う層。
//!
//! - 着信 (NGN → 内線): NGN から受信した INVITE を登録済み全内線へ
//!   並列に発信し、最初に 200 OK を返した内線で確立、他は CANCEL する。
//! - 発信 (内線 → NGN): 内線から `UasEvent::Invite` を受け取り、UAC で
//!   NGN にプロキシする。
//! - RTP リレー: 確立後、両レッグの SDP からピア address/port を抽出して
//!   `RtpBridge` を起動する (G.711 μ-law をそのままコピー転送)。
//!
//! Phase 1 の責務に絞り、トランスコードは Phase 3 (Issue #6 系) で実装する。

pub mod bridge;
pub mod codec_pipeline;
pub mod dtmf;
pub mod manager;
pub mod orchestrator;
pub mod transcoder;

// Issue #42: ハーネスを使った E2E テスト。`#[cfg(test)]` でゲートしているため
// production ビルドには含まれない。
#[cfg(test)]
mod e2e_harness_tests;

// Issue #45: NGN→内線 着信フロー専用 E2E テスト。
// `NgnInboundHandler` の round-trip / 失敗パターン (480 / 408 / NGN CANCEL race) を
// docs/architecture.md §4.2 / §5.7 のシーケンスに沿って網羅する。
#[cfg(test)]
mod inbound_e2e_tests;

use std::sync::atomic::{AtomicU64, Ordering};

/// 通話の状態 (RFC 3261 §13 + 内部状態)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// 通話オブジェクト生成直後。INVITE 未送信 / 未受信。
    Idle,
    /// INVITE 送信済みで 1xx (Ringing) 受信中、または 200 OK 待ち。
    Ringing,
    /// 双方が 200 OK / ACK を交換し RTP ブリッジが確立した状態。
    Connected,
    /// BYE / CANCEL / タイムアウト等で解放済み。
    Terminated,
}

/// プロセス内で一意な通話 ID。テスト容易性のため単調増加カウンタを使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallId(pub u64);

impl CallId {
    /// プロセス内で重複しない新規 ID を発行する。
    pub fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

impl std::fmt::Display for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "call-{}", self.0)
    }
}
