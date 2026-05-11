//! E2E SIP testbed: NGN P-CSCF + 内線 UA mock を tokio 内で立ち上げ、
//! sabiden の **通話シーケンス全体** (INVITE → 100 → 180 → 200 → ACK → BYE)
//! を 1 test で検証する harness。
//!
//! # 設計
//!
//! このテストクレートは sabiden の production 型 (`ServerTransaction` /
//! `UAS` / `Uac` 等) を **mock しない** (CLAUDE.md §6.3 違反防止)。
//! 代わりに `tokio::net::UdpSocket` レベルで生 SIP を読み書きする最小
//! 実装で carrier (NGN P-CSCF) と内線 UA を模擬する。
//!
//! sabiden 側は `wire_ngn_inbound` で `NgnInboundHandler` を直接 spawn する
//! (= main.rs と同じ高水準ヘルパ)。 これによりテストは sabiden の
//! 「実 socket 経由で INVITE を受け取り、 内線レッグへ fork し、 200 OK を
//! NGN へ返す」 全経路を駆動する。
//!
//! # モジュール構成
//!
//! - [`mock_ngn_carrier`]: NTT NGN P-CSCF 模擬 (Asterisk pcap 由来の特徴
//!   ヘッダ付き INVITE 注入、 100/180/200 受領、 ACK/BYE 送出)。
//! - [`mock_extension_ua`]: 内線 UA 模擬 (PWA-like)。 REGISTER で sabiden の
//!   `ExtensionRegistrar` に bind を登録、 sabiden が fork してきた INVITE
//!   を UDP で受信し、 200 OK + SDP answer を返す。
//! - [`leg_inviter`]: テスト用 [`crate::call::manager::LegInviter`] 実装。
//!   `mock_extension_ua` の UDP socket addr に INVITE を生 UDP で送り、
//!   200 OK を待って [`crate::call::manager::LegOutcome::Established`] を返す。
//! - [`sabiden_harness`]: sabiden を in-process に組み立てるエントリ。
//! - [`scenarios`]: 初期 4 件の test シナリオ (RFC 3261 §13 / RFC 4028 / RFC 3264)。
//!
//! # RFC 参照
//!
//! - RFC 3261 §13: INVITE-initiated Session
//! - RFC 3261 §17.2.1: INVITE Server Transaction (100 Trying)
//! - RFC 3261 §13.3.1.4: 2xx Response, Contact target refresh
//! - RFC 3261 §12.1.1: Dialog ID = (Call-ID, From-tag, To-tag)
//! - RFC 4028 §7 / §10: Session Timers, Min-SE / Session-Expires echo
//! - RFC 3264 §6.1: Offer/Answer (answer は offer の subset)

#![allow(dead_code)] // 各シナリオで段階的に使うため未使用ヘルパは許容

pub mod leg_inviter;
pub mod mock_extension_ua;
pub mod mock_ngn_carrier;
pub mod sabiden_harness;
pub mod scenarios;
