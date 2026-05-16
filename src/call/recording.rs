//! Active call recording (PWA-triggered) — Issue #296
//!
//! PWA UI で「録音開始」/「録音停止」 ボタンを押した際、 sabiden が active
//! call の RTP ストリーム (PCMU 8 kHz mono) を WAV ファイルへ dump する機構。
//!
//! 留守録 (`src/call/voicemail/`、 Issue #288) は **不在着信時の自動録音**
//! だが、 本モジュールは **通話確立中に PWA からのトリガで開始/停止する**
//! 点が違う。 RTP→WAV 変換ロジックは voicemail と同じ仕組み (`WavWriter`)
//! を再利用するため、 wav 層の機能変更は伴わない。
//!
//! # 設計要点
//!
//! - **コーデック制約 (CLAUDE.md §5)**: NGN レッグは PCMU 8 kHz mono
//!   (RFC 3551 §4.5.14, PT=0) のみ。 本モジュールは PCMU 固定で動作し、
//!   PCMA / G.722 / Opus / telephone-event 等は recorder 側で silent drop。
//! - **bridge tap 経由**: 通話確立後の双方向 RTP は [`super::bridge::RtpBridge`]
//!   等が forward しているため、 録音は「bridge が観測した RTP packet」 を
//!   `mpsc::Receiver<RtpPacket>` 経由で受け取る。 これにより既存 RTP リレー
//!   パスへの介入を最小化し (= 既存 117 通話パスの regression リスクを下げ)、
//!   recorder と bridge の責務を分離できる。
//! - **WAV 仕様**: 留守録と同じ Microsoft RIFF/WAVE (linear PCM 16-bit /
//!   mono / 8000 Hz)。 [`super::voicemail::WavWriter`] をそのまま再利用する。
//! - **副ファイル (sidecar)**: 1 録音につき `<id>.wav` と `<id>.json` を保存。
//!   JSON には `recording_id` / `call_id` / `remote_number` / `started_at_unix_ms`
//!   / `duration_ms` を入れる (= [`RecordingFile`])。
//! - **最大録音時間**: [`RecordingConfig::max_duration_secs`] で打ち切る
//!   (デフォルト 600 秒)。 タイマー超過で recorder task が WAV finalize して
//!   終了する (留守録より長め: 顧客対応の証跡用途を想定)。
//! - **二重 start 防止**: 同一 `call_id` に対する 2 重 [`CallRecorder::start`]
//!   は [`RecordingError::AlreadyRecording`] で拒否する。
//!
//! # 既存 voicemail との関係
//!
//! voicemail module の [`super::voicemail::WavWriter`] は **logic 変更なし**
//! で再利用する (Issue #296 制約)。 active recording 専用の差分は本ファイル
//! 内に閉じ込め、 voicemail 関数の signature は触らない。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::rtp::{decode_ulaw, RtpPacket, PAYLOAD_TYPE_ULAW};
use crate::webrtc::signaling::{
    PwaRecordHandler, RecordingControlError, RecordingStartedInfo, RecordingStoppedInfo,
};

use super::voicemail::{sanitize_id, WavWriter};

/// recording ファイル拡張子 (留守録と同じ FOURCC 文字列を使うが、 保存先
/// ディレクトリは別)。
pub const RECORDING_EXT_WAV: &str = "wav";
pub const RECORDING_EXT_META: &str = "json";

/// 1 録音分のメタデータ (sidecar JSON で永続化)。 voicemail と異なり
/// `recording_id` (= ファイル名) と `call_id` を分けて保持する。 同一 call
/// 中に start/stop を複数回繰り返すことを許容するため、 `recording_id` は
/// 単調増加カウンタ + nanos で組み立てる。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordingFile {
    /// 録音 ID (ファイル名にも使う一意識別子)。
    pub recording_id: String,
    /// 録音対象通話の SIP Call-ID。
    pub call_id: String,
    /// 相手電話番号 (発信先 / 発信元)。 NGN inbound では carrier IMS が
    /// anonymous 化する場合がある (memory: `project_ngn_inbound_caller_id_stripped`)。
    pub remote_number: String,
    /// 録音開始時刻 (UNIX epoch ミリ秒)。
    pub started_at_unix_ms: u64,
    /// 録音長さ (ミリ秒)。
    pub duration_ms: u64,
}

impl RecordingFile {
    /// `<storage_dir>/<recording_id>.wav` を組み立てる。
    pub fn audio_path(&self, storage_dir: &Path) -> PathBuf {
        storage_dir.join(format!(
            "{}.{}",
            sanitize_id(&self.recording_id),
            RECORDING_EXT_WAV
        ))
    }

    /// `<storage_dir>/<recording_id>.json` を組み立てる。
    pub fn meta_path(&self, storage_dir: &Path) -> PathBuf {
        storage_dir.join(format!(
            "{}.{}",
            sanitize_id(&self.recording_id),
            RECORDING_EXT_META
        ))
    }
}

/// active call recording の設定 (`[recording]` セクション)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingConfig {
    /// 有効化フラグ。 既定 `false` (= 録音機能 OFF、 完全に既存挙動)。
    #[serde(default)]
    pub enabled: bool,
    /// 録音ファイル保存先。 voicemail とは別ディレクトリ。 既定
    /// `/tmp/sabiden-recording`。
    #[serde(default = "default_storage_dir")]
    pub storage_dir: PathBuf,
    /// 最大録音長 (秒)。 0 は実質無制限 (推奨しない、 既定 600 秒)。
    /// voicemail の 60 秒より長め: SOHO 顧客対応 / 会議メモを想定。
    #[serde(default = "default_max_duration_secs")]
    pub max_duration_secs: u64,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage_dir: default_storage_dir(),
            max_duration_secs: default_max_duration_secs(),
        }
    }
}

impl RecordingConfig {
    /// `max_duration_secs` を [`Duration`] にする。 0 は実上限 (u64::MAX/2 秒)
    /// として扱う ([`super::voicemail::VoicemailConfig::max_duration`] と同じ
    /// 規約)。
    pub fn max_duration(&self) -> Duration {
        if self.max_duration_secs == 0 {
            Duration::from_secs(u64::MAX / 2)
        } else {
            Duration::from_secs(self.max_duration_secs)
        }
    }
}

fn default_storage_dir() -> PathBuf {
    PathBuf::from("/tmp/sabiden-recording")
}

fn default_max_duration_secs() -> u64 {
    600
}

/// recording 操作の失敗種別。 signaling 層は本 enum を観測して
/// `ServerMessage::Error` の `code` 文字列にマップする。
#[derive(Debug)]
pub enum RecordingError {
    /// 同一 `call_id` で既に録音が走っている (= 二重 start)。
    AlreadyRecording { call_id: String },
    /// 録音 task の準備 (storage_dir 作成 / WAV file create) に失敗。
    Setup { reason: String },
    /// `call_id` に対応する録音が見つからない (= stop 対象なし)。
    NotFound { call_id: String },
}

impl std::fmt::Display for RecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordingError::AlreadyRecording { call_id } => {
                write!(f, "already recording call_id={}", call_id)
            }
            RecordingError::Setup { reason } => write!(f, "recording setup failed: {}", reason),
            RecordingError::NotFound { call_id } => {
                write!(f, "no active recording for call_id={}", call_id)
            }
        }
    }
}

impl std::error::Error for RecordingError {}

/// recording task への handle。 [`CallRecorder::start`] が返す。
///
/// - [`RecordingHandle::stop`]: 録音停止 (notify、 idempotent)。
/// - [`RecordingHandle::join`]: 録音 task の完了を await して結果を取り出す。
/// - `Drop`: stop_signal を発火して task は速やかに finalize する。
pub struct RecordingHandle {
    recording_id: String,
    started_at_unix_ms: u64,
    stop_signal: Arc<Notify>,
    join: Option<JoinHandle<Result<RecordingFile>>>,
}

impl RecordingHandle {
    /// この録音の ID。 PWA に push する `ServerMessage::RecordingStarted` で使う。
    pub fn recording_id(&self) -> &str {
        &self.recording_id
    }

    /// 録音開始時刻 (UNIX epoch ms)。
    pub fn started_at_unix_ms(&self) -> u64 {
        self.started_at_unix_ms
    }

    /// 録音を停止する (idempotent)。 task は WAV を finalize してから終了する。
    pub fn stop(&self) {
        self.stop_signal.notify_waiters();
    }

    /// 録音 task の完了を await して結果を取り出す (1 度だけ呼べる)。
    pub async fn join(mut self) -> Result<RecordingFile> {
        let handle = self
            .join
            .take()
            .ok_or_else(|| anyhow::anyhow!("RecordingHandle::join already taken"))?;
        match handle.await {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("recording task join error: {e}")),
        }
    }
}

impl Drop for RecordingHandle {
    fn drop(&mut self) {
        // task が走り続けないように notify する (idempotent)。
        self.stop_signal.notify_waiters();
    }
}

/// recording 入力チャネルへ packet を流すための送信側 handle。 bridge tap が
/// 観測した RTP packet を `try_send` で流す。 channel 容量を超えると drop
/// される (back pressure: 録音は best-effort で、 通話品質より低優先)。
#[derive(Clone, Debug)]
pub struct RecordingSender {
    tx: mpsc::Sender<RtpPacket>,
}

impl RecordingSender {
    /// RTP packet 1 つを recorder 側に渡す。 channel が満杯なら drop して
    /// `Ok(false)` を返す。 receiver 側が閉じていれば `Err`。
    pub fn try_send(&self, pkt: RtpPacket) -> Result<bool, mpsc::error::TrySendError<RtpPacket>> {
        match self.tx.try_send(pkt) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(e @ mpsc::error::TrySendError::Closed(_)) => Err(e),
        }
    }

    /// receiver が drop 済みかチェック (= 録音 task が既に終了)。
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// active call recording の中心オブジェクト。 同時複数 call の録音 task を
/// 管理する。
///
/// ライフサイクル:
///
/// 1. PWA `ClientMessage::RecordStart { call_id }` 受信 →
///    [`CallRecorder::start`] で task spawn + [`RecordingHandle`] 取得。
/// 2. orchestrator は得た [`RecordingSender`] を bridge tap に登録し、
///    bridge が観測する RTP packet を流す。
/// 3. PWA `ClientMessage::RecordStop { call_id }` 受信 →
///    [`CallRecorder::stop`] で stop_signal 発火 + handle 引き取り + join。
/// 4. 結果 [`RecordingFile`] が permanent 化 (WAV + sidecar JSON) され、
///    PWA は `GET /api/recording/list` で確認できる。
pub struct CallRecorder {
    storage_dir: PathBuf,
    max_duration: Duration,
    /// `call_id` → 録音 sender + handle のテーブル。 同一 call で重複 start
    /// すると [`RecordingError::AlreadyRecording`] を返す。
    active: Arc<Mutex<std::collections::HashMap<String, ActiveEntry>>>,
}

struct ActiveEntry {
    sender: RecordingSender,
    handle: RecordingHandle,
}

impl CallRecorder {
    /// 新規 recorder を構築する。 `storage_dir` が存在しなければ create する。
    pub async fn new(storage_dir: PathBuf, max_duration: Duration) -> Result<Self> {
        fs::create_dir_all(&storage_dir)
            .await
            .with_context(|| format!("recording storage_dir 作成失敗: {:?}", storage_dir))?;
        Ok(Self {
            storage_dir,
            max_duration,
            active: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// 設定から構築する。 `cfg.enabled` の真偽は呼出側 (orchestrator / main)
    /// が判定する責務。 ここでは「設定値を recorder に embed」 のみ行う。
    pub async fn from_config(cfg: &RecordingConfig) -> Result<Self> {
        Self::new(cfg.storage_dir.clone(), cfg.max_duration()).await
    }

    /// 保存先ディレクトリ。
    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    /// `call_id` に対する録音を開始する。 戻り値は (sender, recording_id,
    /// started_at_unix_ms)。
    ///
    /// orchestrator は得た [`RecordingSender`] を bridge tap (将来 PR で
    /// 実装される `RtpBridge::attach_tap` 等) に登録し、 forward 中の RTP
    /// packet を流す。 channel 容量超過の packet は silent drop される。
    ///
    /// 同一 `call_id` で既に録音中なら [`RecordingError::AlreadyRecording`]
    /// を返す (二重 start 防止)。
    pub async fn start(
        &self,
        call_id: &str,
        remote_number: &str,
    ) -> Result<(RecordingSender, String, u64), RecordingError> {
        // 二重 start 防止: 既に同一 call_id の entry があれば即座に拒否。
        // start/stop を排他するために active table の lock を確保したまま
        // sender の作成・spawn まで一気に行う。
        let mut tbl = self.active.lock().await;
        if tbl.contains_key(call_id) {
            return Err(RecordingError::AlreadyRecording {
                call_id: call_id.to_string(),
            });
        }

        let recording_id = next_recording_id(call_id);
        let started_at = SystemTime::now();
        let started_at_unix_ms = started_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // mpsc 容量: 録音は best-effort なので背圧で通話品質を落とさない
        // よう、 余裕を持たせた (256 packet = 約 5 秒分の PCMU 20ms packet)。
        // 超えたら try_send が Full を返し、 sender 側で silent drop。
        let (tx, rx) = mpsc::channel::<RtpPacket>(256);

        let safe_id = sanitize_id(&recording_id);
        let wav_path = self.storage_dir.join(format!("{safe_id}.wav"));
        let meta_path = self.storage_dir.join(format!("{safe_id}.json"));

        // WAV を先に作成しておくと recorder task の起動失敗を即座に把握できる。
        let writer = WavWriter::create(&wav_path)
            .await
            .map_err(|e| RecordingError::Setup {
                reason: format!("WAV 作成失敗 {:?}: {}", wav_path, e),
            })?;

        let stop_signal = Arc::new(Notify::new());
        let stop_clone = stop_signal.clone();
        let recording_id_clone = recording_id.clone();
        let call_id_clone = call_id.to_string();
        let remote_clone = remote_number.to_string();
        let max_duration = self.max_duration;

        let join = tokio::spawn(async move {
            run_recording_loop(
                writer,
                rx,
                stop_clone,
                max_duration,
                recording_id_clone,
                call_id_clone,
                remote_clone,
                started_at_unix_ms,
                meta_path,
            )
            .await
        });

        let sender = RecordingSender { tx };
        let handle = RecordingHandle {
            recording_id: recording_id.clone(),
            started_at_unix_ms,
            stop_signal,
            join: Some(join),
        };

        tbl.insert(
            call_id.to_string(),
            ActiveEntry {
                sender: sender.clone(),
                handle,
            },
        );
        info!(
            %call_id,
            %recording_id,
            "active call recording 開始 (Issue #296)"
        );
        Ok((sender, recording_id, started_at_unix_ms))
    }

    /// `call_id` の録音を停止する。 戻り値は finalize 済の
    /// [`RecordingFile`] (= duration_ms 確定)。 該当無しは
    /// [`RecordingError::NotFound`]。
    pub async fn stop(&self, call_id: &str) -> Result<RecordingFile, RecordingError> {
        let entry = {
            let mut tbl = self.active.lock().await;
            tbl.remove(call_id)
        };
        let Some(entry) = entry else {
            return Err(RecordingError::NotFound {
                call_id: call_id.to_string(),
            });
        };
        let ActiveEntry { sender, handle } = entry;
        // sender を先に drop して receiver loop の `recv()` を None で抜けさせる
        // (stop_signal 経由でも抜けられるが、 sender drop の方が race が無い)。
        drop(sender);
        handle.stop();
        handle.join().await.map_err(|e| RecordingError::Setup {
            reason: format!("recording task join error: {}", e),
        })
    }

    /// 録音中の `call_id` に対する sender を引く (= bridge から RTP を流す
    /// 用)。 該当無しは `None`。
    pub async fn sender_for(&self, call_id: &str) -> Option<RecordingSender> {
        let tbl = self.active.lock().await;
        tbl.get(call_id).map(|e| e.sender.clone())
    }

    /// 録音中の `call_id` 一覧 (テスト・観測用)。
    pub async fn active_call_ids(&self) -> Vec<String> {
        let tbl = self.active.lock().await;
        tbl.keys().cloned().collect()
    }

    /// 保存済 recording 一覧を新しい順 (`started_at_unix_ms` 降順) で返す。
    pub async fn list(&self) -> Result<Vec<RecordingFile>> {
        load_list(&self.storage_dir).await
    }

    /// 指定 ID の recording を 1 件読み出す。
    pub async fn get(&self, id: &str) -> Result<Option<(RecordingFile, PathBuf)>> {
        let safe_id = sanitize_id(id);
        let meta_path = self
            .storage_dir
            .join(format!("{safe_id}.{RECORDING_EXT_META}"));
        let wav_path = self
            .storage_dir
            .join(format!("{safe_id}.{RECORDING_EXT_WAV}"));
        if !meta_path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&meta_path).await?;
        let meta: RecordingFile = serde_json::from_slice(&bytes)?;
        Ok(Some((meta, wav_path)))
    }

    /// 指定 ID の recording を削除 (WAV + JSON 両方)。 存在しなければ
    /// `Ok(false)` を返す (404 用)。
    pub async fn delete(&self, id: &str) -> Result<bool> {
        let safe_id = sanitize_id(id);
        let meta_path = self
            .storage_dir
            .join(format!("{safe_id}.{RECORDING_EXT_META}"));
        let wav_path = self
            .storage_dir
            .join(format!("{safe_id}.{RECORDING_EXT_WAV}"));
        let mut found = false;
        if meta_path.exists() {
            fs::remove_file(&meta_path).await.ok();
            found = true;
        }
        if wav_path.exists() {
            fs::remove_file(&wav_path).await.ok();
            found = true;
        }
        Ok(found)
    }

    /// テスト用: `RtpPacket` 列を直接 WAV に書き出す (recorder task を bypass)。
    ///
    /// unit test で mpsc チャネルを bypass して「与えた packet 群 → WAV
    /// bytes」 を検証するための pure-fn 入口。 voicemail の
    /// `record_from_packets` と同じ役割。
    pub async fn record_from_packets(
        &self,
        call_id: &str,
        remote_number: &str,
        packets: &[RtpPacket],
    ) -> Result<RecordingFile> {
        let started_at = SystemTime::now();
        let started_at_unix_ms = started_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let recording_id = next_recording_id(call_id);
        let safe_id = sanitize_id(&recording_id);
        let wav_path = self.storage_dir.join(format!("{safe_id}.wav"));
        let meta_path = self.storage_dir.join(format!("{safe_id}.json"));

        let mut writer = WavWriter::create(&wav_path).await?;
        let mut total_samples: u64 = 0;
        for pkt in packets {
            if pkt.payload_type != PAYLOAD_TYPE_ULAW {
                continue;
            }
            let pcm: Vec<i16> = pkt.payload.iter().map(|b| decode_ulaw(*b)).collect();
            writer.write_samples(&pcm).await?;
            total_samples += pcm.len() as u64;
        }
        writer.finalize().await?;

        let duration_ms = total_samples * 1000 / (crate::rtp::packet::SAMPLE_RATE as u64).max(1);
        let meta = RecordingFile {
            recording_id,
            call_id: call_id.to_string(),
            remote_number: remote_number.to_string(),
            started_at_unix_ms,
            duration_ms,
        };
        let json = serde_json::to_vec_pretty(&meta)?;
        let mut meta_file = fs::File::create(&meta_path).await?;
        meta_file.write_all(&json).await?;
        meta_file.flush().await.ok();
        Ok(meta)
    }
}

/// 録音ループ本体 (task 内で動く)。
///
/// 終了条件:
/// 1. `stop_signal` notify 受信 (= PWA RecordStop / drop)
/// 2. `max_duration` 経過
/// 3. mpsc `rx.recv()` が `None` を返す (= 全 sender drop = call 終了)
#[allow(clippy::too_many_arguments)]
async fn run_recording_loop(
    mut writer: WavWriter,
    mut rx: mpsc::Receiver<RtpPacket>,
    stop_signal: Arc<Notify>,
    max_duration: Duration,
    recording_id: String,
    call_id: String,
    remote_number: String,
    started_at_unix_ms: u64,
    meta_path: PathBuf,
) -> Result<RecordingFile> {
    let mut total_samples: u64 = 0;
    let deadline = tokio::time::sleep(max_duration);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = stop_signal.notified() => {
                debug!(%recording_id, %call_id, "recording stop_signal 受信 → finalize");
                break;
            }
            _ = &mut deadline => {
                info!(
                    %recording_id,
                    %call_id,
                    max_duration_secs = max_duration.as_secs(),
                    "recording max_duration 経過 → finalize (Issue #296)"
                );
                break;
            }
            maybe_pkt = rx.recv() => {
                match maybe_pkt {
                    Some(pkt) => {
                        if pkt.payload_type != PAYLOAD_TYPE_ULAW {
                            // PCMA / G.722 / Opus / telephone-event 等は無視。
                            // CLAUDE.md §5 + RFC 3551 §4.5.14。
                            continue;
                        }
                        let pcm: Vec<i16> = pkt.payload.iter().map(|b| decode_ulaw(*b)).collect();
                        if let Err(e) = writer.write_samples(&pcm).await {
                            warn!(%recording_id, error=%e, "recording: WAV write error → finalize");
                            break;
                        }
                        total_samples += pcm.len() as u64;
                    }
                    None => {
                        // 全 sender が drop された (= bridge 側 tap が外れた = call 終了)。
                        debug!(%recording_id, %call_id, "recording: sender 全 drop → finalize");
                        break;
                    }
                }
            }
        }
    }

    writer
        .finalize()
        .await
        .with_context(|| format!("WAV finalize 失敗 (recording_id={})", recording_id))?;

    let duration_ms = total_samples * 1000 / (crate::rtp::packet::SAMPLE_RATE as u64).max(1);
    let meta = RecordingFile {
        recording_id: recording_id.clone(),
        call_id,
        remote_number,
        started_at_unix_ms,
        duration_ms,
    };

    let json = serde_json::to_vec_pretty(&meta)
        .with_context(|| "recording metadata serialize 失敗".to_string())?;
    let mut meta_file = fs::File::create(&meta_path)
        .await
        .with_context(|| format!("recording metadata 作成失敗: {:?}", meta_path))?;
    meta_file
        .write_all(&json)
        .await
        .with_context(|| format!("recording metadata 書込失敗: {:?}", meta_path))?;
    meta_file.flush().await.ok();

    info!(
        recording_id = %meta.recording_id,
        call_id = %meta.call_id,
        duration_ms,
        "recording finalize 完了 (Issue #296)"
    );
    Ok(meta)
}

/// `<call_id_sanitized>-<unix_ms>-<seq>` の形式で新規 recording_id を生成する。
/// 同一 call_id で start/stop を複数回繰り返しても衝突しない (seq でカウント)。
fn next_recording_id(call_id: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    format!("{}-{}-{}", sanitize_id(call_id), ms, n)
}

/// 既存の recording 一覧を `started_at_unix_ms` 降順で取得する。
async fn load_list(storage_dir: &Path) -> Result<Vec<RecordingFile>> {
    if !storage_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = fs::read_dir(storage_dir).await?;
    let mut out: Vec<RecordingFile> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let is_json = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.eq_ignore_ascii_case(RECORDING_EXT_META))
            .unwrap_or(false);
        if !is_json {
            continue;
        }
        match fs::read(&path).await {
            Ok(bytes) => match serde_json::from_slice::<RecordingFile>(&bytes) {
                Ok(meta) => out.push(meta),
                Err(e) => warn!(?path, error=%e, "recording metadata parse 失敗 → skip"),
            },
            Err(e) => warn!(?path, error=%e, "recording metadata read 失敗 → skip"),
        }
    }
    out.sort_by_key(|m| std::cmp::Reverse(m.started_at_unix_ms));
    Ok(out)
}

/// PWA WS `ClientMessage::RecordStart` / `RecordStop` を [`CallRecorder`] に
/// 取り次ぐ [`PwaRecordHandler`] 実装 (Issue #296)。
///
/// `SignalingState::with_pwa_record` に注入することで、 signaling 層が
/// `recording_unavailable` を返さずに本ハンドラへ dispatch される。 リモート
/// 番号 (PSTN E.164) は PWA からは見えないため、 `remote_number` プレースホルダ
/// を sidecar JSON に書き出し、 PWA UI / `/api/recording/list` 表示時に
/// 別経路 (call-log) で補完する想定。
///
/// このハンドラは「recording 専用、 stop 経路で `RecordingControlError::UnknownCallId`
/// を返さないと PWA が無限待ちになる」 ため、 `CallRecorder::stop` の
/// `NotFound` を `UnknownCallId` に、 `AlreadyRecording` を `AlreadyRecording`
/// にそれぞれ map する (`recording.rs::RecordingError` → signaling
/// `RecordingControlError` の単純変換)。
pub struct PwaRecordHandlerImpl {
    recorder: Arc<CallRecorder>,
}

impl PwaRecordHandlerImpl {
    /// `Arc<CallRecorder>` から新しいハンドラを作る。 同じ recorder を
    /// `HealthState::with_recording` と共有することで、 開始した録音が即座に
    /// `GET /api/recording/list` で見えるようになる (Issue #296)。
    pub fn new(recorder: Arc<CallRecorder>) -> Arc<Self> {
        Arc::new(Self { recorder })
    }
}

/// PWA が知らないリモート番号 (PSTN E.164) のプレースホルダ。 signaling 層は
/// `call_id` だけを送り、 着信元 / 発信先番号は別経路 (call-log) でしか
/// 観測できないため、 sidecar JSON にはこの sentinel を入れる。
const RECORDING_REMOTE_UNKNOWN: &str = "unknown";

#[async_trait::async_trait]
impl PwaRecordHandler for PwaRecordHandlerImpl {
    async fn start_recording(
        &self,
        call_id: &str,
    ) -> Result<RecordingStartedInfo, RecordingControlError> {
        match self.recorder.start(call_id, RECORDING_REMOTE_UNKNOWN).await {
            Ok((_sender, recording_id, started_at_unix_ms)) => Ok(RecordingStartedInfo {
                recording_id,
                started_at_unix_ms,
            }),
            Err(RecordingError::AlreadyRecording { .. }) => {
                Err(RecordingControlError::AlreadyRecording)
            }
            Err(RecordingError::Setup { reason }) => {
                Err(RecordingControlError::Internal { reason })
            }
            // `start` は NotFound を返さないので発生しないが、 enum を網羅。
            Err(RecordingError::NotFound { call_id }) => Err(RecordingControlError::Internal {
                reason: format!("unexpected NotFound on start: call_id={call_id}"),
            }),
        }
    }

    async fn stop_recording(
        &self,
        call_id: &str,
    ) -> Result<RecordingStoppedInfo, RecordingControlError> {
        match self.recorder.stop(call_id).await {
            Ok(file) => Ok(RecordingStoppedInfo {
                recording_id: file.recording_id,
                duration_ms: file.duration_ms,
            }),
            Err(RecordingError::NotFound { .. }) => Err(RecordingControlError::UnknownCallId),
            Err(RecordingError::AlreadyRecording { .. }) => {
                // stop で AlreadyRecording は出ない (`active` table から remove
                // した直後に同 call_id の handle を join するため)。 念のため
                // Internal にマップして panic 回避。
                Err(RecordingControlError::Internal {
                    reason: "unexpected AlreadyRecording on stop".to_string(),
                })
            }
            Err(RecordingError::Setup { reason }) => {
                Err(RecordingControlError::Internal { reason })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::{encode_ulaw, RtpPacket, PAYLOAD_TYPE_ULAW};

    /// テスト用 tempdir ヘルパ (voicemail と同じ pattern)。
    fn tempdir() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("sabiden-rec-test-{pid}-{nanos}-{n}"));
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

    fn pcmu_packet(seq: u16, samples: usize) -> RtpPacket {
        RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: seq == 0,
            sequence: seq,
            timestamp: seq as u32 * samples as u32,
            ssrc: 0xCAFE_BABE,
            payload: vec![encode_ulaw(1000); samples],
        }
    }

    /// DoD ケース 1 (正常 start → packet 流入 → stop → WAV 生成):
    /// PWA RecordStart → bridge tap が PCMU packet を流す → PWA RecordStop で
    /// finalize → WAV が RIFF/WAVE 仕様 (linear PCM 16-bit / mono / 8 kHz) で
    /// 出力される (RFC 3551 §4.5.14 PCMU + RIFF/WAVE spec)。
    #[tokio::test]
    async fn rfc3551_4_5_14_start_packets_stop_produces_valid_wav() {
        let tmp = tempdir();
        let recorder = CallRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");

        let (sender, recording_id, _started_ms) = recorder
            .start("call-abc", "0312345678")
            .await
            .expect("start");
        assert!(!recording_id.is_empty());

        // 10 packet × 160 sample (= 200 ms @ 8 kHz PCMU 20ms ptime) を流す。
        for i in 0..10u16 {
            let res = sender.try_send(pcmu_packet(i, 160)).expect("send");
            assert!(res, "channel が満杯で drop された (=容量 256 想定外)");
        }

        // recorder task が packet を消費する時間を与える (mpsc + spawn は
        // 即座に反映されないため、 少し待ってから stop する)。
        tokio::time::sleep(Duration::from_millis(50)).await;

        let meta = recorder.stop("call-abc").await.expect("stop");
        assert_eq!(meta.call_id, "call-abc");
        assert_eq!(meta.remote_number, "0312345678");
        assert_eq!(meta.recording_id, recording_id);
        // 10 packet × 160 sample / 8000 Hz = 200 ms。 multi-task scheduling で
        // packet が間に合わず少なく書かれる可能性は許容 (>=150ms)。
        assert!(
            meta.duration_ms >= 150 && meta.duration_ms <= 250,
            "duration_ms ({}) は 150..=250 を期待",
            meta.duration_ms
        );

        // WAV が RIFF/WAVE 仕様で書かれている。
        let wav_bytes = std::fs::read(meta.audio_path(tmp.path())).expect("read wav");
        assert_eq!(&wav_bytes[0..4], b"RIFF");
        assert_eq!(&wav_bytes[8..12], b"WAVE");
        assert_eq!(&wav_bytes[12..16], b"fmt ");
        let fmt_code = u16::from_le_bytes([wav_bytes[20], wav_bytes[21]]);
        let channels = u16::from_le_bytes([wav_bytes[22], wav_bytes[23]]);
        let rate = u32::from_le_bytes([wav_bytes[24], wav_bytes[25], wav_bytes[26], wav_bytes[27]]);
        let bits = u16::from_le_bytes([wav_bytes[34], wav_bytes[35]]);
        assert_eq!(fmt_code, 1);
        assert_eq!(channels, 1);
        assert_eq!(rate, 8000);
        assert_eq!(bits, 16);

        // sidecar JSON が読み戻せる。
        let listed = recorder.list().await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].recording_id, recording_id);
    }

    /// DoD ケース 2 (max_duration 到達 → 自動 finalize):
    /// stop を呼ばなくても `max_duration` 経過で WAV が finalize され、
    /// orchestrator は handle.join で結果を受け取れる。
    ///
    /// RFC 3551 §4.5.14 PCMU + 留守録 `VoicemailRecorder` の `max_duration`
    /// 規約 (issue #288) を recording にも引き継ぐ。
    #[tokio::test]
    async fn max_duration_elapsed_finalizes_without_explicit_stop() {
        let tmp = tempdir();
        // max_duration = 100ms で short-circuit を促す (テスト時間短縮)。
        let recorder = CallRecorder::new(tmp.path().to_path_buf(), Duration::from_millis(100))
            .await
            .expect("new");

        let (sender, _rid, _) = recorder
            .start("call-short", "0312345678")
            .await
            .expect("start");
        // 1 packet 流して deadline を超えるまで待つ。
        sender.try_send(pcmu_packet(0, 160)).expect("send");

        // 200 ms 待って max_duration の 100ms を確実に超える。
        tokio::time::sleep(Duration::from_millis(200)).await;

        // recorder task は max_duration で finalize 済のはず。 list で見える。
        let listed = recorder.list().await.expect("list");
        assert_eq!(listed.len(), 1, "max_duration finalize 後の sidecar が無い");
        let meta = &listed[0];
        assert_eq!(meta.call_id, "call-short");
        assert!(
            meta.duration_ms <= 250,
            "duration_ms ({}) は max_duration 100ms +α に収まるはず",
            meta.duration_ms
        );

        // ただし active table には entry が残っているので stop も呼べる
        // (NotFound にはならない、 task は join 可能)。
        let res = recorder.stop("call-short").await;
        assert!(res.is_ok(), "max_duration 後でも stop で join できる");
    }

    /// DoD ケース 3 (録音中 BYE で stop 経由でも単体で停止できる):
    /// 通話 BYE を検知した orchestrator は `recorder.stop(call_id)` を呼ぶ。
    /// 録音は中断されて finalize する (= 通話切断時の自動 cleanup)。
    ///
    /// RFC 3261 §15.1.1 (BYE) + RFC 5853 §3.2.2 (B2BUA 片側 dialog 終了
    /// 伝搬) の派生: B2BUA は片側 BYE 受領で active 状態の付随リソース
    /// (= recording) を cleanup する。
    #[tokio::test]
    async fn rfc3261_15_1_1_bye_during_recording_finalizes_via_stop() {
        let tmp = tempdir();
        let recorder = CallRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");

        let (sender, _rid, _) = recorder
            .start("call-bye", "0312345678")
            .await
            .expect("start");

        // 5 packet 流す (= 100 ms 分)。
        for i in 0..5u16 {
            sender.try_send(pcmu_packet(i, 160)).expect("send");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // NGN BYE 受信を模して orchestrator が stop を呼ぶ。
        let meta = recorder.stop("call-bye").await.expect("stop");
        assert_eq!(meta.call_id, "call-bye");
        // BYE 即時 stop なので duration は <=150ms (timing margin 込み)。
        assert!(
            meta.duration_ms <= 150,
            "BYE 即時 stop の duration_ms ({}) は 150ms 以下を期待",
            meta.duration_ms
        );

        // active table から消えている。
        let ids = recorder.active_call_ids().await;
        assert!(ids.is_empty(), "stop 後の active table は空のはず");

        // 二重 stop は NotFound。
        let err = recorder.stop("call-bye").await.expect_err("double stop");
        assert!(matches!(err, RecordingError::NotFound { .. }));
    }

    /// DoD ケース 4 (二重 start エラー):
    /// 同一 call_id に対し 2 回 start を呼ぶと AlreadyRecording で拒否される。
    /// PWA UI のダブルクリック等で発生しうる race を防ぐ (二重録音は file
    /// race + sidecar JSON 上書き競合の原因)。
    #[tokio::test]
    async fn double_start_for_same_call_id_returns_already_recording_error() {
        let tmp = tempdir();
        let recorder = CallRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");

        let (_sender, _rid, _) = recorder
            .start("call-dup", "0312345678")
            .await
            .expect("first start");

        let err = recorder
            .start("call-dup", "0312345678")
            .await
            .expect_err("second start should fail");
        match err {
            RecordingError::AlreadyRecording { call_id } => {
                assert_eq!(call_id, "call-dup");
            }
            other => panic!("expected AlreadyRecording, got {:?}", other),
        }

        // 後始末: stop して entry を消し、 後続テストに影響しないように。
        let _ = recorder.stop("call-dup").await;
    }

    /// PCMU 以外の payload は silent drop される (CLAUDE.md §5 NGN は PCMU
    /// only + RFC 3551 §4.5.14)。
    #[tokio::test]
    async fn rfc3551_non_pcmu_payloads_are_skipped() {
        let tmp = tempdir();
        let recorder = CallRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");

        let packets = vec![
            RtpPacket {
                payload_type: 8, // PCMA
                marker: false,
                sequence: 1,
                timestamp: 0,
                ssrc: 0,
                payload: vec![0u8; 160],
            },
            RtpPacket {
                payload_type: 101, // telephone-event
                marker: false,
                sequence: 2,
                timestamp: 160,
                ssrc: 0,
                payload: vec![0u8; 4],
            },
        ];
        let meta = recorder
            .record_from_packets("call-skip", "anon", &packets)
            .await
            .expect("record");
        assert_eq!(meta.duration_ms, 0);
    }

    /// list は started_at_unix_ms 降順 (= 新しい順)。
    #[tokio::test]
    async fn list_returns_newest_first() {
        let tmp = tempdir();
        let recorder = CallRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");
        let p = vec![pcmu_packet(0, 160)];

        let mut older = recorder
            .record_from_packets("call-old", "a", &p)
            .await
            .expect("record");
        older.started_at_unix_ms = 1000;
        let json = serde_json::to_vec(&older).unwrap();
        std::fs::write(older.meta_path(tmp.path()), json).unwrap();

        let mut newer = recorder
            .record_from_packets("call-new", "b", &p)
            .await
            .expect("record");
        newer.started_at_unix_ms = 2000;
        let json = serde_json::to_vec(&newer).unwrap();
        std::fs::write(newer.meta_path(tmp.path()), json).unwrap();

        let list = recorder.list().await.expect("list");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].started_at_unix_ms, 2000);
        assert_eq!(list[1].started_at_unix_ms, 1000);
    }

    /// delete は WAV + JSON 両方を削除する。 二重 delete は false。
    #[tokio::test]
    async fn delete_removes_both_wav_and_json() {
        let tmp = tempdir();
        let recorder = CallRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");
        let p = vec![pcmu_packet(0, 160)];
        let meta = recorder
            .record_from_packets("call-victim", "anon", &p)
            .await
            .expect("record");

        assert!(meta.audio_path(tmp.path()).exists());
        assert!(meta.meta_path(tmp.path()).exists());

        let removed = recorder.delete(&meta.recording_id).await.expect("delete");
        assert!(removed);
        assert!(!meta.audio_path(tmp.path()).exists());
        assert!(!meta.meta_path(tmp.path()).exists());

        let removed2 = recorder.delete(&meta.recording_id).await.expect("delete2");
        assert!(!removed2);
    }

    /// 設定駆動 (`enabled = false` 既定 → recording disable):
    /// `RecordingConfig::default()` は disabled で、 main / orchestrator は
    /// recorder を生成しないため active call 中の挙動は完全に既存通り
    /// (Issue #296 後方互換 DoD)。
    #[test]
    fn default_config_is_disabled() {
        let cfg = RecordingConfig::default();
        assert!(!cfg.enabled, "default は disabled");
        assert!(
            cfg.storage_dir.ends_with("sabiden-recording"),
            "default storage_dir は /tmp/sabiden-recording"
        );
        assert_eq!(cfg.max_duration_secs, 600);
    }

    /// max_duration_secs = 0 は実上限として大きい値を返す
    /// (voicemail と同じ規約、 `Duration::ZERO` panic 回避)。
    #[test]
    fn max_duration_zero_means_practically_unlimited() {
        let cfg = RecordingConfig {
            enabled: true,
            storage_dir: PathBuf::from("/tmp/x"),
            max_duration_secs: 0,
        };
        // u64::MAX / 2 秒 ≒ 数十億年。
        assert!(cfg.max_duration() > Duration::from_secs(60 * 60 * 24 * 365));
    }

    /// next_recording_id は同 call_id でも seq でユニークになる
    /// (= 同一通話で start/stop を複数回繰り返しても file 衝突しない)。
    #[test]
    fn next_recording_id_is_unique_per_call_for_repeated_start() {
        let a = next_recording_id("call-x");
        let b = next_recording_id("call-x");
        assert_ne!(a, b);
        assert!(a.starts_with("call-x-"));
        assert!(b.starts_with("call-x-"));
    }

    /// Issue #296 integration: PWA WS `ClientMessage::RecordStart` を
    /// `PwaRecordHandlerImpl::start_recording` 経由で受けると、
    /// `RecordingStartedInfo` が返り、 後段の `stop_recording` で
    /// `RecordingStoppedInfo` (= duration_ms 確定) が返る。 二重 start は
    /// `AlreadyRecording`、 未知 call_id の stop は `UnknownCallId`。
    ///
    /// RFC 3261 §15.1.1 BYE → recorder.stop の対称形 (signaling 層の
    /// `ClientMessage::RecordStop` が PWA UI からの明示停止、 BYE 経由の
    /// orchestrator cleanup は同じ `CallRecorder::stop` を呼ぶため、 本テスト
    /// で PwaRecordHandlerImpl→CallRecorder→sidecar JSON finalize の経路を
    /// カバーする)。
    #[tokio::test]
    async fn rfc3261_15_1_1_pwa_record_handler_start_stop_finalizes_via_callrecorder() {
        let tmp = tempdir();
        // 短い max_duration はテスト時間を縛る保険 (Notify::notify_waiters
        // race を deadline で確実に解消する。 詳細は
        // `rfc5853_3_2_2_bye_path_directly_stops_recording_without_pwa_signaling`
        // のコメント参照)。 stop_recording 経路では `Arc<CallRecorder>` 外に
        // sender は無いため race は起きないが、 念のため短めに設定する。
        let recorder = Arc::new(
            CallRecorder::new(tmp.path().to_path_buf(), Duration::from_millis(200))
                .await
                .expect("new"),
        );
        let handler: Arc<dyn PwaRecordHandler> = PwaRecordHandlerImpl::new(recorder.clone());

        // PWA RecordStart → handler.start_recording → RecordingStartedInfo
        let started = handler
            .start_recording("call-pwa-1")
            .await
            .expect("start_recording");
        assert!(!started.recording_id.is_empty());
        assert!(started.started_at_unix_ms > 0);

        // 二重 start → AlreadyRecording (RecordingControlError マップ確認)
        let double = handler.start_recording("call-pwa-1").await;
        assert!(
            matches!(double, Err(RecordingControlError::AlreadyRecording)),
            "double start should map to AlreadyRecording, got {:?}",
            double.as_ref().err()
        );

        // PWA RecordStop → handler.stop_recording → RecordingStoppedInfo
        let stopped = handler
            .stop_recording("call-pwa-1")
            .await
            .expect("stop_recording");
        assert_eq!(stopped.recording_id, started.recording_id);

        // sidecar JSON が `/api/recording/list` で見える状態になっている。
        let listed = recorder.list().await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].recording_id, started.recording_id);

        // 未知 call_id の stop → UnknownCallId
        let err = handler
            .stop_recording("call-unknown")
            .await
            .expect_err("unknown stop");
        assert!(
            matches!(err, RecordingControlError::UnknownCallId),
            "unknown stop should map to UnknownCallId, got {err:?}"
        );
    }

    /// Issue #296 integration (BYE 経路の cleanup):
    /// signaling 層からではなく orchestrator (BYE handler) が
    /// `CallRecorder::stop` を直接呼ぶ経路でも recording が finalize される。
    ///
    /// RFC 5853 §3.2.2 B2BUA は片側 dialog 終了 (NGN BYE / PWA→NGN BYE) で
    /// 付随リソース (= recording) を自動 cleanup する責務がある。 BYE handler
    /// は recorder.stop を呼んで WAV finalize させる。 `NotFound` は録音中で
    /// ない call_id (= 通常の BYE) を意味するので silent OK 扱い。
    ///
    /// NOTE: テスト内で test scope の `sender` を `stop` より前に明示 drop
    /// するのは、 `RecordingHandle::stop` の `Notify::notify_waiters` が
    /// 「現在 waiter が居なければ通知を落とす」 仕様 (tokio doc) で race する
    /// ためのテストハーネス側対処。 production 配線 (`UasEventHandler` /
    /// `NgnInboundHandler` の recording_recorder hook) では sender は recorder
    /// 内部の `ActiveEntry` しか持たないので、 `stop` の冒頭で remove + drop
    /// した時点で task は `rx.recv()` が None を返して即 finalize する (race
    /// しない)。 短い max_duration はテスト時間を縛る保険でもある。
    #[tokio::test]
    async fn rfc5853_3_2_2_bye_path_directly_stops_recording_without_pwa_signaling() {
        let tmp = tempdir();
        let recorder = Arc::new(
            CallRecorder::new(tmp.path().to_path_buf(), Duration::from_millis(200))
                .await
                .expect("new"),
        );

        // PWA RecordStart で recorder 内に active entry を作る (handler を経由
        // しないテストでも CallRecorder::start を直接呼ぶ)。
        let (sender, recording_id, _) = recorder
            .start("call-bye-cleanup", "0312345678")
            .await
            .expect("start");
        // テスト scope の sender を drop して、 `recorder.stop` 内の sender
        // drop と合わせて全 sender drop → task の `rx.recv()` が即 `None` を
        // 返す状態にする (= notify_waiters race を回避、 production 経路と
        // 同じ「sender が active table 外に居ない」 状況を模擬)。
        drop(sender);

        // BYE 経路を模して orchestrator が recorder.stop を呼ぶ。 PWA WS
        // からの `ClientMessage::RecordStop` ではなく、 NGN/内線 BYE 受信時に
        // 自動 cleanup する経路 (RFC 5853 §3.2.2)。
        let meta = recorder
            .stop("call-bye-cleanup")
            .await
            .expect("bye-path stop");
        assert_eq!(meta.recording_id, recording_id);

        // 録音されていない call_id の stop は NotFound (orchestrator は
        // silent ignore する想定)。
        let err = recorder
            .stop("never-recorded")
            .await
            .expect_err("not found");
        assert!(matches!(err, RecordingError::NotFound { .. }));

        // sidecar JSON が `/api/recording/list` で見える。
        let listed = recorder.list().await.expect("list");
        assert_eq!(listed.len(), 1);
    }
}
