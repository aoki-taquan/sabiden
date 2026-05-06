//! Opus エンコーダ / デコーダ (RFC 6716, RFC 7587)
//!
//! `opus` クレート (libopus FFI) を薄くラップする。WebRTC 互換のため:
//! - サンプルレート 48 kHz
//! - チャネル mono (NGN 側 G.711 が mono のため)
//! - フレーム長 20ms (= 960 samples @ 48 kHz)
//! - 既定ビットレート 24 kbps (`OPUS_AUTO` でも良いが固定で安定動作)
//! - VOIP application を選択 (低レイテンシ・音声特化)
//!
//! Opus は VBR や DTX (silence suppression) を有効にできるが、トランスコード
//! 経路では「相手 (NGN G.711) が DTX を理解しない」ため DTX は OFF。CBR で
//! ジッタを抑える。

use anyhow::{Context, Result};
use opus::{Application, Channels, Decoder, Encoder};

use super::AudioFrame;

/// WebRTC が要求する標準 Opus サンプルレート (RFC 7587 §4.2)。
pub const OPUS_SAMPLE_RATE: u32 = 48_000;
/// 20ms フレーム = 960 サンプル @ 48 kHz。
pub const OPUS_FRAME_SAMPLES: usize = (OPUS_SAMPLE_RATE as usize * 20) / 1000;
/// VoIP 既定ビットレート。WebRTC 実装でも近い値を用いる。
pub const OPUS_DEFAULT_BITRATE: i32 = 24_000;
/// libopus 推奨の出力バッファ最大サイズ (4000 bytes)。
const OPUS_MAX_PACKET: usize = 4000;

/// Opus エンコーダ (mono / 48 kHz / 20ms フレーム)。
pub struct OpusEncoder {
    encoder: Encoder,
}

impl OpusEncoder {
    /// 既定設定 (VoIP application, 24 kbps CBR, DTX オフ) で生成する。
    pub fn new() -> Result<Self> {
        Self::with_bitrate(OPUS_DEFAULT_BITRATE)
    }

    /// ビットレートを指定して生成する。
    pub fn with_bitrate(bitrate_bps: i32) -> Result<Self> {
        let mut encoder = Encoder::new(OPUS_SAMPLE_RATE, Channels::Mono, Application::Voip)
            .context("Opus エンコーダ生成失敗")?;
        // RFC 7587 §6.1: WebRTC とのインタオペでは CBR 推奨
        encoder
            .set_bitrate(opus::Bitrate::Bits(bitrate_bps))
            .context("Opus ビットレート設定失敗")?;
        Ok(Self { encoder })
    }

    /// 1 フレーム (20ms / 960 samples @ 48 kHz, mono) をエンコードして
    /// Opus パケットを返す。
    pub fn encode(&mut self, frame: &AudioFrame) -> Result<Vec<u8>> {
        if frame.sample_rate != OPUS_SAMPLE_RATE {
            anyhow::bail!(
                "Opus エンコード入力レート不正: {} Hz (48000 を要求)",
                frame.sample_rate
            );
        }
        if frame.samples.len() != OPUS_FRAME_SAMPLES {
            anyhow::bail!(
                "Opus フレーム長不正: {} samples (期待 {})",
                frame.samples.len(),
                OPUS_FRAME_SAMPLES
            );
        }
        let mut out = vec![0u8; OPUS_MAX_PACKET];
        let n = self
            .encoder
            .encode(&frame.samples, &mut out)
            .context("Opus エンコード失敗")?;
        out.truncate(n);
        Ok(out)
    }
}

/// Opus デコーダ (mono / 48 kHz)。
pub struct OpusDecoder {
    decoder: Decoder,
}

impl OpusDecoder {
    pub fn new() -> Result<Self> {
        let decoder =
            Decoder::new(OPUS_SAMPLE_RATE, Channels::Mono).context("Opus デコーダ生成失敗")?;
        Ok(Self { decoder })
    }

    /// Opus パケットを 1 つデコードして 20ms PCM (48 kHz mono) を返す。
    ///
    /// `packet` が空の場合は PLC (パケットロスコンシールメント) を行う
    /// (FEC なし、`fec=false`)。
    pub fn decode(&mut self, packet: &[u8]) -> Result<AudioFrame> {
        let mut samples = vec![0i16; OPUS_FRAME_SAMPLES];
        let n = self
            .decoder
            .decode(packet, &mut samples, false)
            .context("Opus デコード失敗")?;
        samples.truncate(n);
        Ok(AudioFrame::new(OPUS_SAMPLE_RATE, samples))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sine_48k_20ms(freq_hz: f32, amplitude: i16) -> AudioFrame {
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * freq_hz * t).sin();
            samples.push((v * amplitude as f32) as i16);
        }
        AudioFrame::new(OPUS_SAMPLE_RATE, samples)
    }

    #[test]
    fn encode_decode_roundtrip_produces_audible_signal() {
        // 1 kHz サイン波 → エンコード → デコード で同程度のエネルギーが残るか
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();
        let original = sine_48k_20ms(1000.0, 8000);

        let packet = enc.encode(&original).unwrap();
        assert!(
            packet.len() >= 5 && packet.len() < OPUS_MAX_PACKET,
            "Opus パケット長が異常: {}",
            packet.len()
        );
        let decoded = dec.decode(&packet).unwrap();
        assert_eq!(decoded.sample_rate, OPUS_SAMPLE_RATE);
        assert_eq!(decoded.samples.len(), OPUS_FRAME_SAMPLES);

        // エネルギー比 (lossy だが 1/4 以上は残るはず)
        let orig_energy: f64 = original.samples.iter().map(|s| (*s as f64).powi(2)).sum();
        let dec_energy: f64 = decoded.samples.iter().map(|s| (*s as f64).powi(2)).sum();
        assert!(
            dec_energy > orig_energy / 4.0,
            "デコード信号のエネルギーが小さすぎる: orig={} dec={}",
            orig_energy,
            dec_energy
        );
    }

    #[test]
    fn encode_rejects_wrong_sample_rate() {
        let mut enc = OpusEncoder::new().unwrap();
        let bad = AudioFrame::new(8000, vec![0; 160]);
        assert!(enc.encode(&bad).is_err());
    }

    #[test]
    fn encode_rejects_wrong_frame_length() {
        let mut enc = OpusEncoder::new().unwrap();
        let bad = AudioFrame::new(OPUS_SAMPLE_RATE, vec![0; 100]);
        assert!(enc.encode(&bad).is_err());
    }

    #[test]
    fn decode_silence_produces_silent_frame() {
        // Opus エンコードした無音 → デコード で正しく 20ms 無音が出る
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();
        let silent = AudioFrame::new(OPUS_SAMPLE_RATE, vec![0i16; OPUS_FRAME_SAMPLES]);
        let pkt = enc.encode(&silent).unwrap();
        let out = dec.decode(&pkt).unwrap();
        assert_eq!(out.samples.len(), OPUS_FRAME_SAMPLES);
        // 量子化雑音は許容: 平均絶対値が小さければ良い
        let avg_abs = out
            .samples
            .iter()
            .map(|s| s.unsigned_abs() as u32)
            .sum::<u32>()
            / out.samples.len() as u32;
        assert!(avg_abs < 200, "無音フレームの残留振幅が大きい: {}", avg_abs);
    }

    #[test]
    fn custom_bitrate_works() {
        let mut enc_low = OpusEncoder::with_bitrate(8_000).unwrap();
        let mut enc_high = OpusEncoder::with_bitrate(64_000).unwrap();
        let signal = sine_48k_20ms(1000.0, 8000);
        let p_low = enc_low.encode(&signal).unwrap();
        let p_high = enc_high.encode(&signal).unwrap();
        // 高ビットレートのパケットの方が概ね大きい
        assert!(
            p_high.len() >= p_low.len(),
            "ビットレート差がパケット長に反映されていない (low={}, high={})",
            p_low.len(),
            p_high.len()
        );
    }
}
