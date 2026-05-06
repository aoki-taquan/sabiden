//! オーディオコーデック層 (G.711 / Opus) と関連ユーティリティ
//!
//! WebRTC ↔ NGN ブリッジの要点:
//! - WebRTC 側は Opus 48 kHz / mono が標準 (RFC 7587 §3)
//! - NGN 側は G.711 μ-law 8 kHz (RFC 3551 §4.5.14)
//! - 双方向で 8 kHz ⇔ 48 kHz リサンプル + Opus encode/decode + μ-law encode/decode
//!
//! 本モジュールでは [`AudioFrame`] を中間表現とし、各コーデック・リサンプラが
//! `i16 PCM` (mono) を受け渡す。サンプルレート情報は明示的に持たせ、誤接続を防ぐ。

pub mod opus;
pub mod resample;

/// PCM フレームの中間表現 (mono / i16)。
///
/// 設計意図: コーデック層と RTP 層の間で「何 Hz の何サンプル」かを取り違えると
/// 静寂や倍速音になりやすい。型に sample_rate を持たせ、変換関数は明示的に
/// 入出力レートを宣言する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    pub sample_rate: u32,
    pub samples: Vec<i16>,
}

impl AudioFrame {
    pub fn new(sample_rate: u32, samples: Vec<i16>) -> Self {
        Self {
            sample_rate,
            samples,
        }
    }

    /// 20ms 分のサンプル数 (rate * 0.02)。
    pub fn frame_len_20ms(rate: u32) -> usize {
        (rate as usize * 20) / 1000
    }
}
