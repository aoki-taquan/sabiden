//! AI 文字起こし (transcription) サブシステム — Issue #300
//!
//! Voicemail (Issue #288) / Recording (Issue #296) で保存した WAV ファイル
//! (RIFF/WAVE linear PCM 16-bit / mono / 8 kHz、 RFC 3551 §4.5.14 PCMU 由来)
//! を AI ASR (Whisper API / faster-whisper 等) に投げて文字起こしを生成し、
//! sidecar `.txt` として WAV と並べて保存する仕組み。
//!
//! 本 Issue (#300) は **stub レベル** で trait + StubTranscriber + 統合 hooks
//! + REST endpoint のみを用意し、 実 ASR backend 実装 (OpenAI Whisper API /
//! faster-whisper ローカル推論) は別 Issue で wire-up する。 既定設定は
//! `[transcription] enabled = false` で完全な後方互換 (transcript は生成
//! されず `.txt` も書かれない)。
//!
//! # 設計要点
//!
//! - **Trait abstraction**: [`Transcriber`] trait を `Send + Sync` で定義し、
//!   `dyn Transcriber` を `Arc<dyn Transcriber>` で持ち回す。 production 実装
//!   ([`StubTranscriber`]) と将来の [Whisper API / faster-whisper backend] を
//!   同じ Arc で取り回せる (CLAUDE.md §6.3 production-side test hook 禁止に
//!   準拠し、 trait は production 型を mock せず最小実装で書く)。
//! - **WAV 仕様前提**: 入力は RFC 3551 §4.5.14 PCMU を [`crate::rtp::decode_ulaw`]
//!   で linear PCM 16-bit にデコードした **RIFF/WAVE (mono / 8 kHz)** だけを
//!   想定。 ヘッダ format code = 1 (PCM)、 sample rate 8000 Hz、 16-bit / sample、
//!   1 channel (`src/call/voicemail/wav.rs::WavWriter` 出力仕様)。 将来 backend
//!   が別 sample rate を要求する場合は呼出側でリサンプリングする (本 Issue
//!   scope 外)。
//! - **エラー方針**: production code で `panic!` / `unwrap` / `expect` 禁止
//!   (CLAUDE.md §6.5)。 失敗は [`anyhow::Result`] で返し、 finalize 経路は
//!   transcript 失敗を warn ログに落とすだけで音声本体 (WAV) は保護する
//!   (= transcript 失敗で WAV が消える事故を防ぐ)。
//! - **Sidecar `.txt` 仕様**: WAV と同じディレクトリ・同じ basename で
//!   拡張子だけ `.txt` に置換 (`<id>.txt`)。 UTF-8、 改行は LF。 `model` /
//!   `language` 等の付随メタデータは将来 sidecar JSON へ拡張する余地を残し、
//!   本 PR では text 本体だけ書く (PWA で読みやすい形)。
//! - **無効化挙動**: `[transcription] enabled = false` (既定) の場合は
//!   [`TranscriptionConfig::is_enabled`] が false を返し、 voicemail /
//!   recording finalize hook 側で何も実行されない (= I/O ゼロ、 既存挙動と
//!   完全互換)。
//!
//! # 結線先
//!
//! - `src/call/voicemail/mod.rs::run_recording_loop` の WAV finalize 直後
//!   (= sidecar JSON 書込前) に [`Transcriber::transcribe`] を呼んで `.txt`
//!   を書く。 transcript 失敗は warn のみで recording 本体は保護する。
//! - `src/call/recording.rs::run_recording_loop` も同様。
//! - `src/health/mod.rs` に `GET /api/voicemail/{id}/transcript` /
//!   `GET /api/recording/{id}/transcript` を追加。 transcript 不在は 404。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// transcript sidecar の拡張子。 WAV と同じ basename + `.txt` で保存する。
pub const TRANSCRIPT_EXT: &str = "txt";

/// transcription backend が返す結果。
///
/// `text` は UTF-8 (改行は LF) の自然文。 `model` は backend 識別子
/// (例: `"stub"` / `"whisper-1"` / `"faster-whisper-base"`)、 `language` は
/// ISO 639-1 2 文字コード (`"ja"` / `"en"` 等)、 検出不能なら `None`。
/// `duration_ms` は backend が要した処理時間 (= レイテンシ観測用)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranscriptionResult {
    /// 文字起こしされた本文 (UTF-8、 改行は LF)。
    pub text: String,
    /// 検出言語 (ISO 639-1)。 backend が検出しない / 失敗時は `None`。
    pub language: Option<String>,
    /// transcribe 処理時間 (ミリ秒)。 backend 内部計測。
    pub duration_ms: u64,
    /// backend 識別子 (例: `"stub"` / `"whisper-1"`)。
    pub model: String,
}

/// WAV ファイルから transcript を生成する抽象。
///
/// stub 実装 ([`StubTranscriber`]) と将来の Whisper API / faster-whisper
/// 実装が同じ trait に乗る (`Arc<dyn Transcriber>` で voicemail / recording
/// に渡す)。
///
/// # 非同期化について
///
/// 現状は同期 `transcribe`。 stub は I/O ゼロでコストゼロ、 production
/// backend (HTTP API 呼出) は実装時に async 版を別途生やす想定 (例:
/// `async fn transcribe_async` を default impl 無しで追加し、 stub は同期
/// 結果をそのまま返す)。 本 Issue では sync API のみで finalize hook を
/// 結線する。
pub trait Transcriber: Send + Sync {
    /// 指定 WAV ファイルを文字起こしして結果を返す。
    ///
    /// 入力は voicemail / recording が保存した RIFF/WAVE (mono / 8 kHz /
    /// linear PCM 16-bit、 RFC 3551 §4.5.14 PCMU 由来) を想定。
    /// 失敗時 (ファイル不在 / backend エラー) は `Err` で返し、 呼出側は
    /// warn ログに落として音声本体は保護する責務を持つ。
    fn transcribe(&self, wav_path: &Path) -> Result<TranscriptionResult>;
}

/// 実 ASR backend が未配線の状況用の no-op 実装。
///
/// 常に「(transcription unavailable - configure backend)」 という固定文字列
/// を返し、 `language` は `None`、 `duration_ms = 0`、 `model = "stub"`。
/// この placeholder text は PWA UI 側で「未対応」 と表示するための sentinel
/// として扱う想定 (将来 Whisper API backend が `model = "whisper-1"` 等を
/// 返すようになれば、 PWA は model 値で「実 ASR で書き起こされた」 ことを
/// 判別できる)。
///
/// # 既知の制約
///
/// `transcribe` は WAV ファイルの実体検査も読込も行わない (stub なので
/// 中身を見ない設計)。 つまり「WAV が存在しない / 壊れている」 ことを
/// 検出する責務は呼出側 (voicemail / recording finalize 経路) が持つ。
/// 実 backend を差し替えた時点で「WAV を実際に読んで失敗したら Err」
/// という挙動に切り替わる前提。
#[derive(Debug, Default, Clone, Copy)]
pub struct StubTranscriber;

impl StubTranscriber {
    /// stub が返す固定 placeholder text。 PWA UI で「未対応」 表示用に
    /// `model = "stub"` とセットで判別される。
    pub const PLACEHOLDER_TEXT: &'static str = "(transcription unavailable - configure backend)";

    /// stub 識別子 (`TranscriptionResult.model`)。
    pub const MODEL_ID: &'static str = "stub";
}

impl Transcriber for StubTranscriber {
    fn transcribe(&self, _wav_path: &Path) -> Result<TranscriptionResult> {
        Ok(TranscriptionResult {
            text: Self::PLACEHOLDER_TEXT.to_string(),
            language: None,
            duration_ms: 0,
            model: Self::MODEL_ID.to_string(),
        })
    }
}

/// `[transcription]` セクション (TOML)。
///
/// 既定 `enabled = false` (= 完全に既存挙動)、 `backend = "stub"` で
/// [`StubTranscriber`] を選択する。 将来の backend 識別子:
///
/// - `"stub"` (本 PR / 既定): [`StubTranscriber`] (placeholder text のみ)
/// - `"whisper-api"` (Issue 未着手): OpenAI Whisper API (`api_key_env`、
///   `base_url` を別途読む想定)
/// - `"faster-whisper"` (Issue 未着手): ローカル ggml 推論 (`model_path`)
///
/// 不明な `backend` 値は起動時 `build_transcriber` で `Err` にして fail-fast
/// する (= 設定ミスを即座に検出)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionConfig {
    /// 文字起こし機能の有効化フラグ。 既定 `false` (= transcript 生成
    /// しない、 sidecar `.txt` も書かれない)。 backend が `"stub"` のままでも
    /// `enabled = true` にすれば placeholder text の `.txt` が生成される
    /// (動作確認 / wiring 検証用)。
    #[serde(default)]
    pub enabled: bool,
    /// 文字起こし backend 識別子。 既定 `"stub"`。
    #[serde(default = "default_backend")]
    pub backend: String,
    /// (将来) Whisper API の API key を取り出す環境変数名。 本 PR では
    /// 値の取り込みのみ (未使用)。
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// (将来) ローカル推論の model ファイルパス。 本 PR では未使用。
    #[serde(default)]
    pub model_path: Option<PathBuf>,
}

impl Default for TranscriptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_backend(),
            api_key_env: None,
            model_path: None,
        }
    }
}

impl TranscriptionConfig {
    /// 機能が有効か (= finalize hook で実際に transcribe するか) を返す。
    /// `enabled = false` なら trait dispatch すら行わない (I/O ゼロ)。
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

fn default_backend() -> String {
    "stub".to_string()
}

/// 設定値から `Arc<dyn Transcriber>` を組み立てる。
///
/// - `backend = "stub"`: [`StubTranscriber`] を返す。
/// - その他: 本 PR では未対応で `Err` を返す (fail-fast、 設定ミス即検出)。
///   将来 Whisper API / faster-whisper backend を追加した際にここを拡張する。
pub fn build_transcriber(cfg: &TranscriptionConfig) -> Result<std::sync::Arc<dyn Transcriber>> {
    match cfg.backend.as_str() {
        "stub" => Ok(std::sync::Arc::new(StubTranscriber)),
        other => Err(anyhow::anyhow!(
            "unsupported transcription backend {:?} (Issue #300 では \"stub\" のみ wire 済)",
            other
        )),
    }
}

/// `<wav_path 拡張子>` を `.txt` に置換した sidecar transcript path を返す。
///
/// 例: `/var/lib/sabiden/voicemail/abc.wav` → `/var/lib/sabiden/voicemail/abc.txt`。
/// `wav_path` が拡張子を持たない場合は `.txt` を末尾に付与する。
pub fn transcript_path_for(wav_path: &Path) -> PathBuf {
    wav_path.with_extension(TRANSCRIPT_EXT)
}

/// transcript 本文を sidecar `.txt` に書き出す (UTF-8、 改行は LF を保証)。
///
/// 既存ファイルがあれば上書きする (= 再録音時に古い transcript を残さない)。
/// 失敗は `Err` で返し、 呼出側 (voicemail / recording finalize) は warn
/// ログに落として音声本体は保護する。
pub async fn write_transcript(wav_path: &Path, result: &TranscriptionResult) -> Result<PathBuf> {
    let txt_path = transcript_path_for(wav_path);
    // UTF-8 で書く。 本文末尾に余分な改行は付けない (PWA UI が直接表示)。
    let bytes = result.text.as_bytes();
    tokio::fs::write(&txt_path, bytes)
        .await
        .with_context(|| format!("write transcript: {:?}", txt_path))?;
    Ok(txt_path)
}

/// sidecar `.txt` から transcript 本文を読み出す (REST endpoint 用)。
/// 存在しなければ `Ok(None)` (404 用)、 I/O 失敗は `Err` で返す。
pub async fn read_transcript(wav_path: &Path) -> Result<Option<String>> {
    let txt_path = transcript_path_for(wav_path);
    if !txt_path.exists() {
        return Ok(None);
    }
    let bytes = tokio::fs::read(&txt_path)
        .await
        .with_context(|| format!("read transcript: {:?}", txt_path))?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("transcript not utf-8: {:?}", txt_path))?;
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::UNIX_EPOCH;

    fn tempdir() -> TempDir {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("sabiden-tr-test-{pid}-{nanos}-{n}"));
        std::fs::create_dir_all(&path).expect("mkdir");
        TempDir(path)
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Issue #300 DoD: StubTranscriber は固定 placeholder text + model="stub" を返す。
    /// 実 ASR backend が未配線の状況で、 finalize hook が安全に呼び出せる
    /// (= placeholder transcript が `.txt` に書かれる、 既存音声本体には影響なし)
    /// ことを保証する単体テスト。
    #[test]
    fn stub_transcriber_returns_placeholder_text_with_stub_model_id() {
        let stub = StubTranscriber;
        let result = stub
            .transcribe(Path::new("/nonexistent/dummy.wav"))
            .expect("stub never fails");
        assert_eq!(result.text, StubTranscriber::PLACEHOLDER_TEXT);
        assert_eq!(result.model, StubTranscriber::MODEL_ID);
        assert!(result.language.is_none());
        assert_eq!(result.duration_ms, 0);
    }

    /// `Send + Sync` であることを type-check 時に強制 (`Arc<dyn Transcriber>`
    /// で voicemail / recording に渡せる前提)。
    #[test]
    fn stub_transcriber_is_send_sync_via_dyn_trait_object() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StubTranscriber>();
        // dyn trait 経由でも Send+Sync が保たれる。
        let _arc: std::sync::Arc<dyn Transcriber> = std::sync::Arc::new(StubTranscriber);
    }

    /// `TranscriptionConfig::default()` は `enabled = false` / `backend = "stub"`。
    /// 設定省略時に何も起きない (= 完全な後方互換) ことを保証する。
    #[test]
    fn default_config_is_disabled_with_stub_backend() {
        let cfg = TranscriptionConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.backend, "stub");
        assert!(cfg.api_key_env.is_none());
        assert!(cfg.model_path.is_none());
    }

    /// `build_transcriber` は `backend = "stub"` で `StubTranscriber` を返す。
    /// transcribe を 1 回呼んで placeholder text であることを確認 (= 結線確認)。
    #[test]
    fn build_transcriber_returns_stub_for_stub_backend() {
        let cfg = TranscriptionConfig::default();
        let transcriber = build_transcriber(&cfg).expect("build stub");
        let result = transcriber
            .transcribe(Path::new("/dummy.wav"))
            .expect("stub never fails");
        assert_eq!(result.model, "stub");
    }

    /// `build_transcriber` は未対応 backend で fail-fast (= 設定ミス即検出)。
    /// `Arc<dyn Transcriber>` は Debug 実装が無いため `expect_err` は使えず、
    /// match 経由でエラー本体を取り出す。
    #[test]
    fn build_transcriber_fails_for_unsupported_backend() {
        let cfg = TranscriptionConfig {
            enabled: true,
            backend: "whisper-api".to_string(),
            ..TranscriptionConfig::default()
        };
        let err = match build_transcriber(&cfg) {
            Ok(_) => panic!("expected error for unsupported backend"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("whisper-api"),
            "error must mention backend name: {msg}"
        );
    }

    /// `transcript_path_for` は WAV path の拡張子を `.txt` に置換する。
    #[test]
    fn transcript_path_for_replaces_wav_extension_with_txt() {
        let p = transcript_path_for(Path::new("/foo/bar/abc.wav"));
        assert_eq!(p, PathBuf::from("/foo/bar/abc.txt"));
        let p2 = transcript_path_for(Path::new("/x/y/noext"));
        assert_eq!(p2, PathBuf::from("/x/y/noext.txt"));
    }

    /// `write_transcript` → `read_transcript` の round-trip (UTF-8 / 日本語含む)。
    #[tokio::test]
    async fn write_then_read_transcript_roundtrip_with_utf8_jp_text() {
        let dir = tempdir();
        let wav = dir.path().join("call-1.wav");
        // dummy WAV (中身は空でも write_transcript 自体は WAV を読まない)
        std::fs::write(&wav, b"RIFF").unwrap();
        let result = TranscriptionResult {
            text: "もしもし、 留守録テストです。".to_string(),
            language: Some("ja".to_string()),
            duration_ms: 42,
            model: "stub".to_string(),
        };
        let txt = write_transcript(&wav, &result).await.expect("write");
        assert_eq!(txt, dir.path().join("call-1.txt"));
        let read = read_transcript(&wav).await.expect("read").expect("Some");
        assert_eq!(read, "もしもし、 留守録テストです。");
    }

    /// `read_transcript` は sidecar 不在で `Ok(None)` (404 用)。
    #[tokio::test]
    async fn read_transcript_returns_none_for_missing_sidecar() {
        let dir = tempdir();
        let wav = dir.path().join("absent.wav");
        let out = read_transcript(&wav).await.expect("ok none");
        assert!(out.is_none());
    }

    /// TOML パース: 既定省略でも default が入る。 backend を上書きできる。
    #[test]
    fn toml_parses_transcription_section_with_overrides() {
        let toml_str = r#"
enabled = true
backend = "whisper-api"
api_key_env = "OPENAI_API_KEY"
"#;
        let cfg: TranscriptionConfig = toml::from_str(toml_str).expect("parse");
        assert!(cfg.enabled);
        assert_eq!(cfg.backend, "whisper-api");
        assert_eq!(cfg.api_key_env.as_deref(), Some("OPENAI_API_KEY"));
        assert!(cfg.model_path.is_none());
    }
}
