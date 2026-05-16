//! RIFF/WAVE (linear 16-bit PCM mono 8 kHz) writer — Issue #288
//!
//! Microsoft RIFF/WAVE 仕様 ("Multimedia Programming Interface and Data
//! Specifications 1.0", 1991-08) に従い、 G.711 μ-law から decode した linear
//! PCM s16le サンプル列を WAV ファイルに dump する最小実装。
//!
//! # WAV layout (本実装が書く形)
//!
//! ```text
//!   offset  size  field          value (sabiden 留守録)
//!   ─────────────────────────────────────────────────────────
//!     0      4    "RIFF"         magic (FOURCC)
//!     4      4    chunk_size     filesize - 8 (リアル時刻に書く)
//!     8      4    "WAVE"         format
//!    12      4    "fmt "         subchunk1 id (note trailing space)
//!    16      4    subchunk1_size 16  (PCM = 16 byte fmt subchunk)
//!    20      2    audio_format   1  (PCM 線形 16-bit、 not μ-law)
//!    22      2    num_channels   1  (mono)
//!    24      4    sample_rate    8000  (RFC 3551 §4.5.14 / NGN PCMU)
//!    28      4    byte_rate      16000  (= sample_rate * channels * bits/8)
//!    32      2    block_align    2  (= channels * bits/8)
//!    34      2    bits_per_sample 16
//!    36      4    "data"         subchunk2 id
//!    40      4    subchunk2_size data_bytes  (= num_samples * 2)
//!    44      ..   pcm samples (s16le)
//! ```
//!
//! `chunk_size` (offset 4) と `subchunk2_size` (offset 40) は **finalize 時に
//! 書き戻す** ため、 [`WavWriter::create`] は header をプレースホルダで書き、
//! 録音終了時 [`WavWriter::finalize`] で正しい値で seek + write を行う。
//!
//! # なぜ μ-law を直接 WAVE_FORMAT_MULAW (=7) で書かないか
//!
//! RIFF/WAVE は μ-law (`WAVE_FORMAT_MULAW = 0x0007`) を仕様上サポートするが、
//! PWA / モバイル ブラウザの `<audio>` 要素は環境によって μ-law を decode
//! できないことがある (Firefox は ALAW/MULAW を WAV ヘッダ経由では再生不可、
//! Chrome は OK)。 PR では「PWA から再生」が DoD のため、 互換性最高の
//! **linear PCM 16-bit** に decode して書く方針 (8 kHz × 16 bit ≒ 16 KB/s で
//! ファイル size も実用範囲)。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt, SeekFrom};

/// RIFF/WAVE header bytes 長 (`data` chunk のサンプル開始位置 = 44)。
pub const WAV_HEADER_LEN: u64 = 44;

/// 留守録 WAV のサンプリングレート (PCMU 由来、 RFC 3551 §4.5.14)。
pub const WAV_SAMPLE_RATE: u32 = 8_000;

/// 留守録 WAV のチャネル数。 NGN PCMU は mono 固定。
pub const WAV_CHANNELS: u16 = 1;

/// 留守録 WAV の bits per sample。 linear PCM 16-bit。
pub const WAV_BITS_PER_SAMPLE: u16 = 16;

/// RIFF/WAVE 出力 stream。 sample (i16 mono 8 kHz) を逐次追記し、
/// `finalize` で header の size フィールドを書き戻す。
pub struct WavWriter {
    path: PathBuf,
    file: File,
    data_bytes: u32,
    finalized: bool,
}

impl WavWriter {
    /// 新規 WAV ファイルを作成する。 既存ファイルは truncate される。
    /// header はプレースホルダ (`chunk_size=0` / `subchunk2_size=0`) で書く。
    pub async fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::create(&path)
            .await
            .with_context(|| format!("WAV ファイル作成失敗: {:?}", path))?;
        let header = make_header_placeholder();
        file.write_all(&header)
            .await
            .with_context(|| format!("WAV header 書込失敗: {:?}", path))?;
        Ok(Self {
            path,
            file,
            data_bytes: 0,
            finalized: false,
        })
    }

    /// PCM サンプル列を末尾に追記する (s16le)。 サンプル数 × 2 byte を消費。
    pub async fn write_samples(&mut self, samples: &[i16]) -> Result<()> {
        if samples.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::with_capacity(samples.len() * 2);
        for s in samples {
            buf.extend_from_slice(&s.to_le_bytes());
        }
        self.file
            .write_all(&buf)
            .await
            .with_context(|| format!("WAV データ書込失敗: {:?}", self.path))?;
        // u32 飽和: WAV は 32-bit size header なので 4 GiB が上限。
        // 留守録上限 60 秒の場合 60 × 16 KB ≒ 1 MB なので実害なし。
        let added = samples.len() as u64 * 2;
        self.data_bytes = self.data_bytes.saturating_add(added as u32);
        Ok(())
    }

    /// header の `chunk_size` と `subchunk2_size` を書き戻して flush する。
    /// 二重呼び出しは no-op。
    pub async fn finalize(&mut self) -> Result<()> {
        if self.finalized {
            return Ok(());
        }
        // RIFF chunk_size (offset 4) = filesize - 8 = 36 + data_bytes
        let riff_size: u32 = 36u32.saturating_add(self.data_bytes);
        self.file
            .seek(SeekFrom::Start(4))
            .await
            .with_context(|| "WAV header seek (riff size) 失敗".to_string())?;
        self.file
            .write_all(&riff_size.to_le_bytes())
            .await
            .with_context(|| "WAV header write (riff size) 失敗".to_string())?;
        // data subchunk_size (offset 40) = data_bytes
        self.file
            .seek(SeekFrom::Start(40))
            .await
            .with_context(|| "WAV header seek (data size) 失敗".to_string())?;
        self.file
            .write_all(&self.data_bytes.to_le_bytes())
            .await
            .with_context(|| "WAV header write (data size) 失敗".to_string())?;
        self.file.flush().await.ok();
        self.finalized = true;
        Ok(())
    }

    /// 現在までに書いた data byte 数 (sample 数 × 2)。
    pub fn data_bytes(&self) -> u32 {
        self.data_bytes
    }
}

/// 44 byte の RIFF/WAVE header をプレースホルダ (size = 0) で組み立てる。
///
/// `finalize` で offset 4 と offset 40 を書き換える。
fn make_header_placeholder() -> [u8; 44] {
    let mut h = [0u8; 44];
    h[0..4].copy_from_slice(b"RIFF");
    // h[4..8] = chunk_size (placeholder 0)
    h[8..12].copy_from_slice(b"WAVE");
    h[12..16].copy_from_slice(b"fmt ");
    // subchunk1_size = 16 (PCM)
    h[16..20].copy_from_slice(&16u32.to_le_bytes());
    // audio_format = 1 (PCM linear)
    h[20..22].copy_from_slice(&1u16.to_le_bytes());
    // num_channels
    h[22..24].copy_from_slice(&WAV_CHANNELS.to_le_bytes());
    // sample_rate
    h[24..28].copy_from_slice(&WAV_SAMPLE_RATE.to_le_bytes());
    // byte_rate = sample_rate * channels * bits/8
    let byte_rate = WAV_SAMPLE_RATE * WAV_CHANNELS as u32 * (WAV_BITS_PER_SAMPLE as u32) / 8;
    h[28..32].copy_from_slice(&byte_rate.to_le_bytes());
    // block_align = channels * bits/8
    let block_align = WAV_CHANNELS * WAV_BITS_PER_SAMPLE / 8;
    h[32..34].copy_from_slice(&block_align.to_le_bytes());
    // bits_per_sample
    h[34..36].copy_from_slice(&WAV_BITS_PER_SAMPLE.to_le_bytes());
    h[36..40].copy_from_slice(b"data");
    // h[40..44] = subchunk2_size (placeholder 0)
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::UNIX_EPOCH;

    fn tmp_wav() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("sabiden-wav-test-{pid}-{nanos}-{n}.wav"))
    }

    /// header placeholder 44 byte が正しい layout で組み立つ。
    #[test]
    fn header_placeholder_layout_matches_riff_wave_spec() {
        let h = make_header_placeholder();
        assert_eq!(&h[0..4], b"RIFF");
        assert_eq!(&h[8..12], b"WAVE");
        assert_eq!(&h[12..16], b"fmt ");
        assert_eq!(u32::from_le_bytes([h[16], h[17], h[18], h[19]]), 16);
        assert_eq!(u16::from_le_bytes([h[20], h[21]]), 1);
        assert_eq!(u16::from_le_bytes([h[22], h[23]]), 1);
        assert_eq!(u32::from_le_bytes([h[24], h[25], h[26], h[27]]), 8000);
        assert_eq!(u32::from_le_bytes([h[28], h[29], h[30], h[31]]), 16000);
        assert_eq!(u16::from_le_bytes([h[32], h[33]]), 2);
        assert_eq!(u16::from_le_bytes([h[34], h[35]]), 16);
        assert_eq!(&h[36..40], b"data");
    }

    /// `create` → `write_samples` → `finalize` の sequence で chunk_size と
    /// data_size が正しく埋まる。
    #[tokio::test]
    async fn create_write_finalize_writes_correct_sizes() {
        let path = tmp_wav();
        let mut w = WavWriter::create(&path).await.expect("create");
        let samples: Vec<i16> = (0..1000).map(|i| i as i16).collect();
        w.write_samples(&samples).await.expect("write");
        w.finalize().await.expect("finalize");
        drop(w);

        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes.len(), 44 + 2000, "header + 1000 sample × 2 byte");
        let chunk_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(chunk_size, 36 + 2000);
        let data_size = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        assert_eq!(data_size, 2000);
        // sample 値が s16le で並んでいる。
        let s0 = i16::from_le_bytes([bytes[44], bytes[45]]);
        let s1 = i16::from_le_bytes([bytes[46], bytes[47]]);
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);

        std::fs::remove_file(path).ok();
    }

    /// `finalize` を 2 回呼んでも 1 回目と結果が変わらない (idempotent)。
    #[tokio::test]
    async fn finalize_is_idempotent() {
        let path = tmp_wav();
        let mut w = WavWriter::create(&path).await.expect("create");
        w.write_samples(&[1, 2, 3]).await.expect("write");
        w.finalize().await.expect("first finalize");
        w.finalize().await.expect("second finalize no-op");
        drop(w);
        let bytes = std::fs::read(&path).expect("read");
        let data_size = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        assert_eq!(data_size, 6);
        std::fs::remove_file(path).ok();
    }

    /// 空 (sample 0 件) でも valid な WAV になる。
    #[tokio::test]
    async fn empty_recording_produces_zero_data_chunk() {
        let path = tmp_wav();
        let mut w = WavWriter::create(&path).await.expect("create");
        w.finalize().await.expect("finalize");
        drop(w);
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes.len(), 44);
        let data_size = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        assert_eq!(data_size, 0);
        std::fs::remove_file(path).ok();
    }
}
