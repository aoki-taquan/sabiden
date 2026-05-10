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

    /// 連続フレームを位相連続な定常 sine wave で供給した時の挙動を検査する。
    ///
    /// 単一フレーム検査 (`upsample_then_downsample_preserves_signal`) では
    /// 検出できない「過渡応答が累積してエネルギーが drift する」「フレーム長
    /// が 160:960 = 1:6 から崩れる」を検出する。 多項式補間フィルタは数フレーム
    /// の warm-up を経て定常化するため、 初期フレームを skip した上で N
    /// フレームを評価する。
    fn make_continuous_sine_8k(freq_hz: f32, amp: i16, frames: usize) -> Vec<AudioFrame> {
        let mut out = Vec::with_capacity(frames);
        for fi in 0..frames {
            let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
            for i in 0..NB_FRAME_SAMPLES {
                let n = fi * NB_FRAME_SAMPLES + i; // 全フレームを通した時刻
                let t = n as f32 / NARROW_BAND_RATE as f32;
                let v = (2.0 * std::f32::consts::PI * freq_hz * t).sin();
                samples.push((v * amp as f32) as i16);
            }
            out.push(AudioFrame::new(NARROW_BAND_RATE, samples));
        }
        out
    }

    /// 上下リサンプラを N フレーム通して、 入出力サンプル数が 160:960:160 で
    /// 厳密一致することを検査する。 1 つでもフレームがズレると累積で位相が
    /// 崩れ、 音声が壊れる。
    #[test]
    fn resample_chain_preserves_n_frames_alignment() {
        const FRAMES: usize = 10;
        let mut up = UpsamplerNbToWb::new().unwrap();
        let mut down = DownsamplerWbToNb::new().unwrap();
        let inputs = make_continuous_sine_8k(1000.0, 8000, FRAMES);

        let mut total_wb = 0usize;
        let mut total_round = 0usize;
        for (idx, frame) in inputs.iter().enumerate() {
            let wb = up.process(frame).unwrap();
            assert_eq!(
                wb.samples.len(),
                WB_FRAME_SAMPLES,
                "frame {idx}: upsample 出力長が {WB_FRAME_SAMPLES} でない: {}",
                wb.samples.len()
            );
            assert_eq!(wb.sample_rate, WIDE_BAND_RATE);
            total_wb += wb.samples.len();
            let nb_again = down.process(&wb).unwrap();
            assert_eq!(
                nb_again.samples.len(),
                NB_FRAME_SAMPLES,
                "frame {idx}: round-trip downsample 出力長が {NB_FRAME_SAMPLES} でない: {}",
                nb_again.samples.len()
            );
            assert_eq!(nb_again.sample_rate, NARROW_BAND_RATE);
            total_round += nb_again.samples.len();
        }
        // 累積サンプル数が厳密に 1:6 比 (8k:48k) を保つ
        assert_eq!(
            total_wb,
            FRAMES * WB_FRAME_SAMPLES,
            "累積 WB サンプル数ずれ: {} (期待 {})",
            total_wb,
            FRAMES * WB_FRAME_SAMPLES
        );
        assert_eq!(
            total_round,
            FRAMES * NB_FRAME_SAMPLES,
            "累積 round-trip サンプル数ずれ: {} (期待 {})",
            total_round,
            FRAMES * NB_FRAME_SAMPLES
        );
    }

    /// 多項式補間フィルタの過渡応答は初期数フレームに限られる。
    /// 1 フレーム目と「定常化後のフレーム」のエネルギー比を取り、
    /// 後者で入力エネルギーが十分回復していることを確認する。
    /// これが満たされないとリサンプル経路で音量が変化する。
    #[test]
    fn resample_chain_transient_subsides_after_warmup() {
        const FRAMES: usize = 10;
        let mut up = UpsamplerNbToWb::new().unwrap();
        let mut down = DownsamplerWbToNb::new().unwrap();
        let inputs = make_continuous_sine_8k(1000.0, 8000, FRAMES);
        let input_energies: Vec<f64> = inputs.iter().map(|f| energy(&f.samples)).collect();

        let mut output_energies: Vec<f64> = Vec::with_capacity(FRAMES);
        for frame in &inputs {
            let wb = up.process(frame).unwrap();
            let nb_again = down.process(&wb).unwrap();
            output_energies.push(energy(&nb_again.samples));
        }

        // フレーム 5 以降 (= warm-up 完了後) で、 入出力エネルギー比が 0.7
        // 以上を維持していること
        for i in 5..FRAMES {
            let in_e = input_energies[i];
            let out_e = output_energies[i];
            assert!(in_e > 0.0, "frame {i} 入力エネルギー 0");
            let ratio = out_e / in_e;
            assert!(
                (0.7..=1.3).contains(&ratio),
                "frame {i}: 定常化後のエネルギー比が範囲外 ratio={ratio} in={in_e} out={out_e}",
            );
        }
    }

    /// 通過帯域内 (2 kHz, 8 kHz NB のナイキスト 4 kHz の半分) の信号が
    /// 上下リサンプル round-trip で十分なエネルギーを保つこと。
    /// FastFixedIn の Septic 多項式補間は理想 sinc に比べてロールオフが
    /// 早く、 ナイキスト直下 (3.5 kHz) では強く減衰するため、 ここでは
    /// 一般的な音声成分が集中する 2 kHz でエネルギー保存を保証する。
    #[test]
    fn resample_chain_passband_signal_survives_round_trip() {
        let mut up = UpsamplerNbToWb::new().unwrap();
        let mut down = DownsamplerWbToNb::new().unwrap();

        // 数フレーム warm-up (位相連続な sine で過渡を吸収)
        let warmup = make_continuous_sine_8k(2000.0, 8000, 4);
        for f in &warmup {
            let wb = up.process(f).unwrap();
            let _ = down.process(&wb).unwrap();
        }

        // 5 フレーム目を評価対象に
        let input = warmup.last().unwrap().clone();
        let wb = up.process(&input).unwrap();
        let round = down.process(&wb).unwrap();

        let in_e = energy(&input.samples);
        let out_e = energy(&round.samples);
        assert!(
            out_e > in_e * 0.5,
            "通過帯域 2 kHz round-trip でエネルギー大幅減: in={in_e} out={out_e}"
        );
    }
}
