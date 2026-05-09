//! sabiden ライブラリエントリポイント。
//!
//! バイナリ (`sabiden`) と並んで、ベンチマーク・統合テスト・将来の埋め込み用途で
//! 各モジュールを公開する。Phase 1 段階では公開 API を絞る (内部実装の差し替え
//! 自由度を確保)。
//!
//! 既存コードはバイナリ専用で `pub` を意識せず書かれているため、リントを
//! ライブラリビルドでも一律緩和する (TODO: モジュール毎に絞る)。

#![allow(clippy::len_without_is_empty)]

pub mod call;
pub mod config;
pub mod dhcp;
pub mod health;
pub mod observability;
pub mod rtp;
pub mod sdp;
pub mod sip;
pub mod webrtc;

// Issue #42: テスト共通ハーネス。`#[cfg(test)]` でゲートしているため
// production ビルドには含まれない。
#[cfg(test)]
pub mod testing;
