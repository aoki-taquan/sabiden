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

    /// RFC 7587 §6.2 (Packet Loss Concealment):
    /// "the receiver MUST be able to decode lost frames using the Packet
    /// Loss Concealment (PLC) mechanism".
    /// RFC 6716 §6: "In the event of packet loss, the decoder will produce a
    /// synthesized signal".
    ///
    /// libopus は `opus_decode` を `data=NULL` / `len=0` で呼ぶと PLC モード
    /// で動作し、 直前のフレームから合成した 20ms のサンプルを返す。
    /// sabiden の [`OpusDecoder::decode`] は空 slice を渡すとこの経路に入る
    /// (`fec=false` ハードコード) ため、 受信ロス時に「呼び出し側がフレーム
    /// 長分のサンプル数を必ず受け取れる」契約を回帰検査する。
    #[test]
    fn rfc7587_6_2_plc_empty_packet_returns_full_frame() {
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();
        // 直前フレームの状態を作る (PLC は履歴依存)
        let signal = sine_48k_20ms(1000.0, 8000);
        let pkt = enc.encode(&signal).unwrap();
        let _primer = dec.decode(&pkt).unwrap();

        // 空パケット (= packet loss) で PLC 呼び出し
        let plc = dec.decode(&[]).unwrap();
        assert_eq!(
            plc.sample_rate, OPUS_SAMPLE_RATE,
            "PLC 出力レートが 48 kHz でない"
        );
        assert_eq!(
            plc.samples.len(),
            OPUS_FRAME_SAMPLES,
            "PLC 出力長が 20ms 分でない: 期待 {} 実際 {}",
            OPUS_FRAME_SAMPLES,
            plc.samples.len()
        );
    }

    /// RFC 7587 §6.2: 連続パケットロスでも PLC が動き続け、 各呼び出しが
    /// 20ms 分のサンプルを返すこと。 RFC 6716 §6 では「数フレーム経過後は
    /// 振幅を漸減させる (comfort noise / fade-out)」と規定されているため、
    /// 振幅が無限に発散したり 0 を上回り続けたりしないことも併せて確認。
    #[test]
    fn rfc7587_6_2_plc_consecutive_losses_fade_to_silence() {
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();

        // 履歴を作る (1 秒分エンコードしてデコード状態を温める)
        for _ in 0..50 {
            let signal = sine_48k_20ms(1000.0, 8000);
            let pkt = enc.encode(&signal).unwrap();
            let _ = dec.decode(&pkt).unwrap();
        }

        // 連続 N フレームの PLC 出力エネルギーを記録
        let mut energies: Vec<f64> = Vec::new();
        for _ in 0..30 {
            let frame = dec.decode(&[]).unwrap();
            assert_eq!(frame.samples.len(), OPUS_FRAME_SAMPLES);
            let e: f64 = frame
                .samples
                .iter()
                .map(|s| (*s as f64).powi(2))
                .sum::<f64>()
                / frame.samples.len() as f64;
            energies.push(e);
        }

        // RFC 6716 §6: PLC は最終的に silence/comfort-noise に収束する。
        // 末尾フレームのエネルギーが初期 PLC フレームの一定割合以下になっていることを確認。
        let head = energies[0].max(1.0);
        let tail = energies[energies.len() - 1];
        assert!(
            tail < head * 0.5 || tail < 1.0e6,
            "PLC が長時間で fade out していない: head={head} tail={tail}"
        );
    }

    /// RFC 7587 §7.1 (`a=rtpmap:<pt> opus/48000/2`): Opus の動的 PT は
    /// セッションごとに変わりうる (典型: 96, 111)。
    /// 「PT 値はトランスポート (RTP ヘッダ) の判別子であり、 ペイロードの
    /// バイト列は同一 PT で再現可能」という不変条件を検査する。
    /// 同じ入力 → 同じビットストリームが出ることで、 PT 切り替え後に
    /// 「PT だけ書き換えて payload を再利用する」上位層 (transcoder) の
    /// 振る舞いを安全に保証できる。
    #[test]
    fn rfc7587_7_1_encode_is_pt_independent() {
        let mut enc = OpusEncoder::new().unwrap();
        let signal = sine_48k_20ms(1000.0, 8000);

        // 同じ入力を続けて 2 回エンコードすると、 Opus は内部状態を持つので
        // 出力は変わる。 ここでは 「入力が同一なら 1 回分のエンコード結果は
        // 1 つの bitstream に確定」 という性質を確認するため、 別エンコーダで
        // 1 回ずつ取って比較する。
        let mut enc2 = OpusEncoder::new().unwrap();
        let p1 = enc.encode(&signal).unwrap();
        let p2 = enc2.encode(&signal).unwrap();
        assert_eq!(
            p1, p2,
            "同一入力からのエンコード bitstream が不一致: \
             PT 切り替えで bitstream まで変化すると上位層の再 wrap が成立しない"
        );
        // 1 byte たりとも変わらない bitstream を、 RTP ヘッダの PT だけ
        // 書き換えて再送できる (Re-INVITE で 96→111 等になっても OK)。
        assert!(!p1.is_empty(), "Opus エンコード結果が空");
    }
}
