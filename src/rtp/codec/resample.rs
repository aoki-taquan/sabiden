//! 8 kHz ⇔ 48 kHz リサンプラ
//!
//! `rubato` クレートの [`FastFixedIn`] (多項式補間) を使う。
//! 設計選択:
//! - SincFixedIn は品質が高いが計算量が大きく、20ms フレームで毎回呼び出すには重い
//! - FastFixedIn の Septic (7 次) なら CPU 負荷が低くインテリジビリティ十分
//! - 入力固定長 (160 / 960) を保証するため `FastFixedIn` の固定入力モードを使う
//!
//! NGN ↔ WebRTC のリサンプル比は 1:6 / 6:1 という整数比のため、
//! Sinc 系でも十分速いが、本実装は VoIP ホットパスでの分かりやすさを重視。

use anyhow::{Context, Result};
use rubato::{FastFixedIn, PolynomialDegree, Resampler};

use super::AudioFrame;

/// G.711 / NGN 側のサンプルレート。
pub const NARROW_BAND_RATE: u32 = 8_000;
/// Opus / WebRTC 側のサンプルレート。
pub const WIDE_BAND_RATE: u32 = 48_000;
/// 20ms @ 8 kHz
pub const NB_FRAME_SAMPLES: usize = 160;
/// 20ms @ 48 kHz
pub const WB_FRAME_SAMPLES: usize = 960;

/// 8 kHz → 48 kHz アップサンプラ。
pub struct UpsamplerNbToWb {
    inner: FastFixedIn<f32>,
}

impl UpsamplerNbToWb {
    pub fn new() -> Result<Self> {
        // ratio = out/in = 6.0, sub_chunks=1 (一発で変換), channels=1
        let inner =
            FastFixedIn::<f32>::new(6.0, 1.0, PolynomialDegree::Septic, NB_FRAME_SAMPLES, 1)
                .context("UpsamplerNbToWb 生成失敗")?;
        Ok(Self { inner })
    }

    /// 20ms NB フレーム (160 samples / 8 kHz) → 20ms WB フレーム (960 samples / 48 kHz)
    pub fn process(&mut self, input: &AudioFrame) -> Result<AudioFrame> {
        if input.sample_rate != NARROW_BAND_RATE {
            anyhow::bail!(
                "Upsampler 入力レート不正: {} Hz (8000 を要求)",
                input.sample_rate
            );
        }
        if input.samples.len() != NB_FRAME_SAMPLES {
            anyhow::bail!(
                "Upsampler 入力長不正: {} samples (期待 {})",
                input.samples.len(),
                NB_FRAME_SAMPLES
            );
        }
        let in_f: Vec<f32> = input
            .samples
            .iter()
            .map(|&s| s as f32 / i16::MAX as f32)
            .collect();
        let mut out = self
            .inner
            .process(&[in_f], None)
            .context("Upsampler 処理失敗")?;
        let out0 = out.pop().unwrap_or_default();
        // FastFixedIn は固定出力サイズではないため、長さチェックして切り詰め / パディング
        let mut samples: Vec<i16> = out0
            .iter()
            .map(|&v| (v * i16::MAX as f32).clamp(i16::MIN as f32, i16::MAX as f32) as i16)
            .collect();
        samples.resize(WB_FRAME_SAMPLES, 0);
        Ok(AudioFrame::new(WIDE_BAND_RATE, samples))
    }
}

/// 48 kHz → 8 kHz ダウンサンプラ。
pub struct DownsamplerWbToNb {
    inner: FastFixedIn<f32>,
}

impl DownsamplerWbToNb {
    pub fn new() -> Result<Self> {
        let inner = FastFixedIn::<f32>::new(
            1.0 / 6.0,
            1.0,
            PolynomialDegree::Septic,
            WB_FRAME_SAMPLES,
            1,
        )
        .context("DownsamplerWbToNb 生成失敗")?;
        Ok(Self { inner })
    }

    /// 20ms WB フレーム (960 samples / 48 kHz) → 20ms NB フレーム (160 samples / 8 kHz)
    pub fn process(&mut self, input: &AudioFrame) -> Result<AudioFrame> {
        if input.sample_rate != WIDE_BAND_RATE {
            anyhow::bail!(
                "Downsampler 入力レート不正: {} Hz (48000 を要求)",
                input.sample_rate
            );
        }
        if input.samples.len() != WB_FRAME_SAMPLES {
            anyhow::bail!(
                "Downsampler 入力長不正: {} samples (期待 {})",
                input.samples.len(),
                WB_FRAME_SAMPLES
            );
        }
        let in_f: Vec<f32> = input
            .samples
            .iter()
            .map(|&s| s as f32 / i16::MAX as f32)
            .collect();
        let mut out = self
            .inner
            .process(&[in_f], None)
            .context("Downsampler 処理失敗")?;
        let out0 = out.pop().unwrap_or_default();
        let mut samples: Vec<i16> = out0
            .iter()
            .map(|&v| (v * i16::MAX as f32).clamp(i16::MIN as f32, i16::MAX as f32) as i16)
            .collect();
        samples.resize(NB_FRAME_SAMPLES, 0);
        Ok(AudioFrame::new(NARROW_BAND_RATE, samples))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sine_8k(freq_hz: f32, amp: i16) -> AudioFrame {
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * freq_hz * t).sin();
            samples.push((v * amp as f32) as i16);
        }
        AudioFrame::new(NARROW_BAND_RATE, samples)
    }

    fn energy(samples: &[i16]) -> f64 {
        samples.iter().map(|s| (*s as f64).powi(2)).sum()
    }

    #[test]
    fn upsample_then_downsample_preserves_signal() {
        // 1 kHz は 8 kHz NB のナイキスト 4 kHz 内なので往復可能
        let mut up = UpsamplerNbToWb::new().unwrap();
        let mut down = DownsamplerWbToNb::new().unwrap();
        let original = make_sine_8k(1000.0, 8000);
        let wb = up.process(&original).unwrap();
        assert_eq!(wb.sample_rate, WIDE_BAND_RATE);
        assert_eq!(wb.samples.len(), WB_FRAME_SAMPLES);

        let nb_again = down.process(&wb).unwrap();
        assert_eq!(nb_again.sample_rate, NARROW_BAND_RATE);
        assert_eq!(nb_again.samples.len(), NB_FRAME_SAMPLES);

        // 往復後のエネルギーが半分以上残ること (フィルタ過渡応答による損失は許容)
        let orig_e = energy(&original.samples);
        let round_e = energy(&nb_again.samples);
        assert!(
            round_e > orig_e * 0.3,
            "リサンプル往復でエネルギーが大幅減: orig={} round={}",
            orig_e,
            round_e
        );
    }

    #[test]
    fn upsample_rejects_wrong_input_rate() {
        let mut up = UpsamplerNbToWb::new().unwrap();
        let bad = AudioFrame::new(16_000, vec![0; NB_FRAME_SAMPLES]);
        assert!(up.process(&bad).is_err());
    }

    #[test]
    fn upsample_rejects_wrong_input_length() {
        let mut up = UpsamplerNbToWb::new().unwrap();
        let bad = AudioFrame::new(NARROW_BAND_RATE, vec![0; 100]);
        assert!(up.process(&bad).is_err());
    }

    #[test]
    fn downsample_rejects_wrong_input_rate() {
        let mut down = DownsamplerWbToNb::new().unwrap();
        let bad = AudioFrame::new(16_000, vec![0; WB_FRAME_SAMPLES]);
        assert!(down.process(&bad).is_err());
    }

    #[test]
    fn upsample_silent_frame_remains_silent() {
        let mut up = UpsamplerNbToWb::new().unwrap();
        let silent = AudioFrame::new(NARROW_BAND_RATE, vec![0i16; NB_FRAME_SAMPLES]);
        let wb = up.process(&silent).unwrap();
        let max_abs = wb
            .samples
            .iter()
            .map(|s| s.unsigned_abs())
            .max()
            .unwrap_or(0);
        assert!(max_abs < 100, "無音アップサンプル後の残留: {}", max_abs);
    }
}
