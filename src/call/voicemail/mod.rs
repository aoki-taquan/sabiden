//! 留守録 (Voicemail) サブシステム — Issue #288
//!
//! NGN 着信で全 fork (内線 / PWA) が応答に失敗した場合、 sabiden 自身が UAS と
//! して 200 OK を返し、 NGN から流入する RTP 音声 (G.711 μ-law) を WAV ファイル
//! に保存して PWA から再生 / 削除可能にする。
//!
//! # 設計要点
//!
//! - **コーデック制約 (CLAUDE.md §5)**: NGN レッグは PCMU 8 kHz mono (RFC 3551
//!   §4.5.14, PT=0) のみ。 Opus / PCMA / G.722 は NGN レッグでは流れないため、
//!   本モジュールは PCMU 固定で動作する。 RTP packet からは payload (8-bit
//!   μ-law 符号化) を取り出し、 [`crate::rtp::decode_ulaw`] で linear PCM 16-bit
//!   に decode してから WAV ([`WavWriter`]) に書き込む。
//! - **WAV 仕様 (Microsoft RIFF/WAVE)**: PCM 線形 16-bit、 mono、 8000 Hz。
//!   header は [`WavWriter::write_header`] が `RIFF` / `WAVE` / `fmt ` / `data`
//!   chunks を書く (詳細は `wav` サブモジュール docstring 参照)。
//! - **副ファイル (sidecar)**: 1 通話につき `<id>.wav` と `<id>.json` を保存。
//!   JSON には `call_id` / `remote_number` / `recorded_at_unix_ms` / `duration_ms`
//!   を入れる (= [`VoicemailFile`])。 これにより `GET /api/voicemail/list` は
//!   ディレクトリを scan して JSON を返すだけで済む。
//! - **最大録音時間**: [`VoicemailConfig.max_duration`] で打ち切る (デフォルト
//!   60 秒)。 タイマー超過で recorder task が終了し、 呼出側 (orchestrator) は
//!   NGN へ BYE を送って通話を閉じる。
//! - **テスト容易性**: [`VoicemailRecorder::record_from_packets`] を分離し、
//!   `&[RtpPacket]` を直接食わせて WAV を吐く API を持つ。 unit test では
//!   `UdpSocket` を bind せず純粋関数的に検証できる (`src/call/voicemail.rs`
//!   末尾の `tests` モジュール)。
//!
//! # 触らない設計
//!
//! - 既存 [`super::bridge::RtpBridge`] / [`super::transcoder::TranscodingBridge`]
//!   は通話成立後の **bidirectional bridge** であり、 留守録は **inbound-only
//!   sink** なので別経路で扱う。 大規模 refactor を避けるため voicemail 専用
//!   recv loop を持つ。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::rtp::{decode_ulaw, RECV_BUF_SIZE};

pub mod wav;

pub use wav::WavWriter;

/// 留守録ファイル拡張子。 WAV 本体 + JSON サイドカー。
pub const VOICEMAIL_EXT_WAV: &str = "wav";
pub const VOICEMAIL_EXT_META: &str = "json";

/// 1 通話分の留守録ファイル metadata (sidecar JSON で永続化する)。
///
/// `GET /api/voicemail/list` はこの構造体配列をそのまま JSON で返す。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoicemailFile {
    /// SIP Call-ID (recorder 起動時の固定識別子)。 ファイル名にも使う。
    pub call_id: String,
    /// SIP `From` ヘッダの user 部 (発信者番号)。 NGN inbound では carrier
    /// IMS が anonymous 化することがある (memory: `project_ngn_inbound_caller_id_stripped`)。
    pub remote_number: String,
    /// 録音開始時刻 (UNIX epoch ミリ秒)。 `SystemTime` を直接 serialize
    /// できない (`std` の Serialize 実装は存在しない) ため u64 で保持。
    pub recorded_at_unix_ms: u64,
    /// 録音長さ (ミリ秒)。 RTP packet 数 × 20ms (PCMU の典型 ptime)。
    pub duration_ms: u64,
}

impl VoicemailFile {
    /// `<storage_dir>/<call_id>.wav` を組み立てる。
    pub fn audio_path(&self, storage_dir: &Path) -> PathBuf {
        storage_dir.join(format!(
            "{}.{}",
            sanitize_id(&self.call_id),
            VOICEMAIL_EXT_WAV
        ))
    }

    /// `<storage_dir>/<call_id>.json` を組み立てる。
    pub fn meta_path(&self, storage_dir: &Path) -> PathBuf {
        storage_dir.join(format!(
            "{}.{}",
            sanitize_id(&self.call_id),
            VOICEMAIL_EXT_META
        ))
    }
}

/// 留守録の設定 (`[voicemail]` セクション)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoicemailConfig {
    /// 有効化フラグ。 既定 `false` (= 留守録機能 OFF)。
    #[serde(default)]
    pub enabled: bool,
    /// 録音ファイル保存先。 既定 `/tmp/sabiden-voicemail`。
    #[serde(default = "default_storage_dir")]
    pub storage_dir: PathBuf,
    /// 最大録音長 (秒)。 0 は無制限 (推奨しない、 既定 60 秒)。
    #[serde(default = "default_max_duration_secs")]
    pub max_duration_secs: u64,
}

impl Default for VoicemailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage_dir: default_storage_dir(),
            max_duration_secs: default_max_duration_secs(),
        }
    }
}

impl VoicemailConfig {
    /// `max_duration_secs` を [`Duration`] にする。 0 は実質「max u64 秒」
    /// (= 18 京年) として扱い、 タイマー側は実上限を別途敷く想定。
    pub fn max_duration(&self) -> Duration {
        if self.max_duration_secs == 0 {
            Duration::from_secs(u64::MAX / 2)
        } else {
            Duration::from_secs(self.max_duration_secs)
        }
    }
}

fn default_storage_dir() -> PathBuf {
    PathBuf::from("/tmp/sabiden-voicemail")
}

fn default_max_duration_secs() -> u64 {
    60
}

/// 留守録 recorder。 UDP socket を 1 つ受け取り、 受信 RTP packet を WAV に
/// dump する task を spawn する。
///
/// ライフサイクル:
///
/// 1. orchestrator が NGN 着信 fork all-fail を検出 →
///    [`VoicemailRecorder::start`] で task spawn。
/// 2. recorder task は `UdpSocket::recv_from` をループし、 受信 datagram を
///    `RtpPacket::from_bytes` で parse、 PCMU payload を [`decode_ulaw`] で
///    linear PCM に変換して WAV file に書き込む。
/// 3. `max_duration` で打ち切り、 もしくは [`VoicemailRecorder::stop`]
///    (= orchestrator 側で NGN BYE 受信時) で task は WAV finalize 後に終了。
/// 4. 結果 [`VoicemailFile`] は JSON sidecar と共に永続化される。
pub struct VoicemailRecorder {
    storage_dir: PathBuf,
    max_duration: Duration,
    /// Issue #300: WAV finalize 直後に呼ぶ AI 文字起こし backend (option)。
    /// `None` (= 既定) の場合は transcript 生成しない (`.txt` も書かれない)、
    /// 完全な既存挙動 (Issue #288 当時の動作と同一)。
    transcriber: Option<Arc<dyn crate::observability::transcription::Transcriber>>,
}

impl std::fmt::Debug for VoicemailRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoicemailRecorder")
            .field("storage_dir", &self.storage_dir)
            .field("max_duration", &self.max_duration)
            .field("transcriber", &self.transcriber.is_some())
            .finish()
    }
}

impl VoicemailRecorder {
    /// 新規 recorder を構築する。 `storage_dir` が存在しなければ create する。
    pub async fn new(storage_dir: PathBuf, max_duration: Duration) -> Result<Self> {
        fs::create_dir_all(&storage_dir)
            .await
            .with_context(|| format!("voicemail storage_dir 作成失敗: {:?}", storage_dir))?;
        Ok(Self {
            storage_dir,
            max_duration,
            transcriber: None,
        })
    }

    /// 設定から構築する。 `cfg.enabled` の真偽は呼出側 (orchestrator) が判定
    /// する責務。 ここでは「設定値を recorder に embed」 のみ行う。
    pub async fn from_config(cfg: &VoicemailConfig) -> Result<Self> {
        Self::new(cfg.storage_dir.clone(), cfg.max_duration()).await
    }

    /// Issue #300: WAV finalize 直後に呼ぶ AI 文字起こし backend を attach する
    /// (builder 風)。 `None` のままなら transcript 生成しない (= 既存挙動)。
    /// orchestrator / main が `[transcription] enabled = true` のときに
    /// `Arc<dyn Transcriber>` を組み立てて差し込む。
    pub fn with_transcriber(
        mut self,
        transcriber: Arc<dyn crate::observability::transcription::Transcriber>,
    ) -> Self {
        self.transcriber = Some(transcriber);
        self
    }

    /// 保存先ディレクトリ。
    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    /// 録音タスクを spawn する。 `socket` の I/O 所有権は recorder に移譲され、
    /// `stop_signal` を notify するか `max_duration` 経過まで RTP 受信を続ける。
    ///
    /// 戻り値 [`VoicemailHandle`] は `await` 可能で、 録音完了時に
    /// [`VoicemailFile`] (永続化済 metadata) を返す。
    pub fn start(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        call_id: String,
        remote_number: String,
    ) -> VoicemailHandle {
        let stop_signal = Arc::new(Notify::new());
        let stop_clone = stop_signal.clone();
        let recorder = self.clone();
        let join = tokio::spawn(async move {
            recorder
                .run_recording_loop(socket, call_id, remote_number, stop_clone)
                .await
        });
        VoicemailHandle {
            stop_signal,
            join: Some(join),
        }
    }

    /// 録音ループ本体。
    async fn run_recording_loop(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        call_id: String,
        remote_number: String,
        stop_signal: Arc<Notify>,
    ) -> Result<VoicemailFile> {
        let recorded_at = SystemTime::now();
        let recorded_at_unix_ms = recorded_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let safe_id = sanitize_id(&call_id);
        let wav_path = self.storage_dir.join(format!("{safe_id}.wav"));
        let meta_path = self.storage_dir.join(format!("{safe_id}.json"));

        let mut writer = WavWriter::create(&wav_path)
            .await
            .with_context(|| format!("WAV 作成失敗: {:?}", wav_path))?;

        info!(
            %call_id,
            %remote_number,
            path = %wav_path.display(),
            max_duration_secs = self.max_duration.as_secs(),
            "留守録開始 (Issue #288)"
        );

        let mut buf = vec![0u8; RECV_BUF_SIZE];
        let mut total_samples: u64 = 0;
        let deadline = tokio::time::sleep(self.max_duration);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = stop_signal.notified() => {
                    debug!(%call_id, "留守録 stop signal 受信 → finalize");
                    break;
                }
                _ = &mut deadline => {
                    debug!(%call_id, "留守録 max_duration 経過 → finalize");
                    break;
                }
                recv = socket.recv_from(&mut buf) => {
                    let (n, _from) = match recv {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(%call_id, error=%e, "留守録: recv_from error → finalize");
                            break;
                        }
                    };
                    if let Some(samples_added) = consume_rtp_datagram(&buf[..n], &mut writer)
                        .await
                        .unwrap_or_else(|e| {
                            warn!(%call_id, error=%e, "留守録: RTP parse / write error (skip)");
                            None
                        })
                    {
                        total_samples += samples_added as u64;
                    }
                }
            }
        }

        // WAV を finalize する (RIFF/WAVE の size フィールドを埋める)。
        writer
            .finalize()
            .await
            .with_context(|| format!("WAV finalize 失敗: {:?}", wav_path))?;

        // Issue #300: WAV finalize 直後に AI 文字起こし stub を呼んで sidecar
        // `.txt` を書く。 transcriber 未設定 (= 既定 disabled) なら no-op。
        // 失敗は warn ログのみで音声本体は保護する (RFC 4566 / RIFF WAVE 仕様
        // を持つ `wav.rs` 出力には触らない)。
        run_transcription_hook(self.transcriber.as_ref(), &wav_path, &call_id).await;

        // 録音長 = サンプル数 / 8000 Hz (PCMU 8kHz 想定)。
        let duration_ms = total_samples * 1000 / (crate::rtp::packet::SAMPLE_RATE as u64).max(1);

        let meta = VoicemailFile {
            call_id: call_id.clone(),
            remote_number,
            recorded_at_unix_ms,
            duration_ms,
        };

        // sidecar JSON を書く (`load_list` 側で読み戻す)。
        let json = serde_json::to_vec_pretty(&meta)
            .with_context(|| "voicemail metadata serialize 失敗".to_string())?;
        let mut meta_file = fs::File::create(&meta_path)
            .await
            .with_context(|| format!("voicemail metadata 作成失敗: {:?}", meta_path))?;
        meta_file
            .write_all(&json)
            .await
            .with_context(|| format!("voicemail metadata 書込失敗: {:?}", meta_path))?;
        meta_file.flush().await.ok();

        info!(
            call_id = %meta.call_id,
            duration_ms,
            "留守録 finalize 完了"
        );
        Ok(meta)
    }

    /// 保存済 voicemail 一覧を新しい順 (`recorded_at_unix_ms` 降順) で返す。
    pub async fn list(&self) -> Result<Vec<VoicemailFile>> {
        load_list(&self.storage_dir).await
    }

    /// 指定 ID の voicemail を 1 件読み出す。
    pub async fn get(&self, id: &str) -> Result<Option<(VoicemailFile, PathBuf)>> {
        let safe_id = sanitize_id(id);
        let meta_path = self
            .storage_dir
            .join(format!("{safe_id}.{VOICEMAIL_EXT_META}"));
        let wav_path = self
            .storage_dir
            .join(format!("{safe_id}.{VOICEMAIL_EXT_WAV}"));
        if !meta_path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&meta_path).await?;
        let meta: VoicemailFile = serde_json::from_slice(&bytes)?;
        Ok(Some((meta, wav_path)))
    }

    /// 指定 ID の voicemail を削除する (WAV + JSON + Issue #300 transcript `.txt`)。
    /// 存在しなければ `Ok(false)` を返す (404 用)。 transcript の有無は
    /// `found` の判定には影響させない (主資源 = WAV/JSON が無ければ 404)。
    pub async fn delete(&self, id: &str) -> Result<bool> {
        let safe_id = sanitize_id(id);
        let meta_path = self
            .storage_dir
            .join(format!("{safe_id}.{VOICEMAIL_EXT_META}"));
        let wav_path = self
            .storage_dir
            .join(format!("{safe_id}.{VOICEMAIL_EXT_WAV}"));
        let mut found = false;
        if meta_path.exists() {
            fs::remove_file(&meta_path).await.ok();
            found = true;
        }
        if wav_path.exists() {
            fs::remove_file(&wav_path).await.ok();
            found = true;
        }
        // Issue #300: sidecar transcript `.txt` も削除。 単独欠如は found
        // フラグには影響させない (= 主資源不在で 404、 transcript-only でも残骸を残さない)。
        let txt_path = crate::observability::transcription::transcript_path_for(&wav_path);
        if txt_path.exists() {
            fs::remove_file(&txt_path).await.ok();
        }
        Ok(found)
    }

    /// テスト用: `RtpPacket` 列を直接 WAV に書き出す (recv loop を bypass)。
    ///
    /// unit test で UDP socket を使わずに「与えた packet 群 → WAV bytes」を
    /// 検証するための pure-fn 入口。
    pub async fn record_from_packets(
        &self,
        call_id: &str,
        remote_number: &str,
        packets: &[crate::rtp::RtpPacket],
    ) -> Result<VoicemailFile> {
        let recorded_at = SystemTime::now();
        let recorded_at_unix_ms = recorded_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let safe_id = sanitize_id(call_id);
        let wav_path = self.storage_dir.join(format!("{safe_id}.wav"));
        let meta_path = self.storage_dir.join(format!("{safe_id}.json"));

        let mut writer = WavWriter::create(&wav_path).await?;
        let mut total_samples: u64 = 0;
        for pkt in packets {
            if pkt.payload_type != crate::rtp::PAYLOAD_TYPE_ULAW {
                continue;
            }
            let pcm: Vec<i16> = pkt.payload.iter().map(|b| decode_ulaw(*b)).collect();
            writer.write_samples(&pcm).await?;
            total_samples += pcm.len() as u64;
        }
        writer.finalize().await?;

        // Issue #300: 同期版 finalize でも transcript hook を呼ぶ (unit test
        // 経路でも transcript 生成を検証可能にするため)。 transcriber 未設定なら
        // no-op、 失敗は warn ログのみで recorded WAV は保護する。
        run_transcription_hook(self.transcriber.as_ref(), &wav_path, call_id).await;

        let duration_ms = total_samples * 1000 / (crate::rtp::packet::SAMPLE_RATE as u64).max(1);
        let meta = VoicemailFile {
            call_id: call_id.to_string(),
            remote_number: remote_number.to_string(),
            recorded_at_unix_ms,
            duration_ms,
        };
        let json = serde_json::to_vec_pretty(&meta)?;
        let mut meta_file = fs::File::create(&meta_path).await?;
        meta_file.write_all(&json).await?;
        meta_file.flush().await.ok();
        Ok(meta)
    }
}

/// 録音タスクへの handle。 drop すると stop_signal が flame して task は
/// 速やかに finalize する。
pub struct VoicemailHandle {
    stop_signal: Arc<Notify>,
    join: Option<JoinHandle<Result<VoicemailFile>>>,
}

impl VoicemailHandle {
    /// 録音を停止する (orchestrator 側で NGN BYE 受信時に呼ぶ)。
    pub fn stop(&self) {
        self.stop_signal.notify_waiters();
    }

    /// 録音 task の完了を await して結果を取り出す。
    pub async fn join(mut self) -> Result<VoicemailFile> {
        let handle = self
            .join
            .take()
            .ok_or_else(|| anyhow!("VoicemailHandle::join already taken"))?;
        match handle.await {
            Ok(r) => r,
            Err(e) => Err(anyhow!("voicemail task join error: {e}")),
        }
    }
}

impl Drop for VoicemailHandle {
    fn drop(&mut self) {
        // 明示停止されていなくても task は max_duration で抜ける。
        // ここでは notify を撃って早期 finalize を促す (idempotent)。
        self.stop_signal.notify_waiters();
    }
}

/// 1 datagram を RTP として parse し、 PCMU payload を WAV writer に流す。
/// 戻り値は「書き込んだサンプル数 (= μ-law byte 数)」 / 非 PCMU は `None`。
async fn consume_rtp_datagram(data: &[u8], writer: &mut WavWriter) -> Result<Option<usize>> {
    let pkt = crate::rtp::RtpPacket::from_bytes(data)?;
    if pkt.payload_type != crate::rtp::PAYLOAD_TYPE_ULAW {
        return Ok(None);
    }
    let pcm: Vec<i16> = pkt.payload.iter().map(|b| decode_ulaw(*b)).collect();
    let len = pcm.len();
    writer.write_samples(&pcm).await?;
    Ok(Some(len))
}

/// 既存の voicemail 一覧を `recorded_at_unix_ms` 降順で取得する。
async fn load_list(storage_dir: &Path) -> Result<Vec<VoicemailFile>> {
    if !storage_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = fs::read_dir(storage_dir).await?;
    let mut out: Vec<VoicemailFile> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let is_json = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.eq_ignore_ascii_case(VOICEMAIL_EXT_META))
            .unwrap_or(false);
        if !is_json {
            continue;
        }
        match fs::read(&path).await {
            Ok(bytes) => match serde_json::from_slice::<VoicemailFile>(&bytes) {
                Ok(meta) => out.push(meta),
                Err(e) => warn!(?path, error=%e, "voicemail metadata parse 失敗 → skip"),
            },
            Err(e) => warn!(?path, error=%e, "voicemail metadata read 失敗 → skip"),
        }
    }
    out.sort_by_key(|m| std::cmp::Reverse(m.recorded_at_unix_ms));
    Ok(out)
}

/// Issue #300: WAV finalize 直後に呼ぶ transcript hook。 transcriber が
/// `None` (= 既定 disabled) なら何もしない (I/O ゼロ、 完全な既存挙動)。
/// 失敗は warn ログのみで音声本体 (WAV) は保護する: transcript stub の失敗
/// で留守録 (= UX 上の主機能) が消える事故を防ぐ防御層。
///
/// `transcriber.transcribe` は同期 API (Issue #300 stub) のため `spawn_blocking`
/// で blocking pool に逃がす必要は無い (stub は I/O ゼロ即時 return)。
/// 将来 HTTP backend を生やしたら trait 自体を async 化する想定。
async fn run_transcription_hook(
    transcriber: Option<&Arc<dyn crate::observability::transcription::Transcriber>>,
    wav_path: &Path,
    call_id: &str,
) {
    let Some(transcriber) = transcriber else {
        return;
    };
    match transcriber.transcribe(wav_path) {
        Ok(result) => {
            match crate::observability::transcription::write_transcript(wav_path, &result).await {
                Ok(txt_path) => {
                    debug!(
                        %call_id,
                        path = %txt_path.display(),
                        model = %result.model,
                        "voicemail transcript 書込 (Issue #300)"
                    );
                }
                Err(e) => {
                    warn!(%call_id, error=%e, "voicemail transcript 書込失敗 (Issue #300、 WAV は保護)");
                }
            }
        }
        Err(e) => {
            warn!(%call_id, error=%e, "voicemail transcribe 失敗 (Issue #300、 WAV は保護)");
        }
    }
}

/// 安全な path component に正規化する。 `..` / `/` / null / 制御文字を弾く。
/// 留守録 ID は SIP Call-ID 由来で任意文字を含み得るため、 directory traversal
/// 攻撃 (`GET /api/voicemail/..%2Fetc%2Fpasswd/audio`) を防ぐ目的で sanitize する。
pub fn sanitize_id(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            // Leading '.' (= hidden file) や '..' を弾く: '.' 単独は許容するが、
            // 結果が '.' / '..' になる場合は後段で `safe` プレースホルダで置換。
            s.push(c);
        } else {
            s.push('_');
        }
    }
    if s.is_empty() || s == "." || s == ".." {
        return "_".to_string();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::transcription::{
        transcript_path_for, StubTranscriber, Transcriber, TranscriptionResult,
    };
    use crate::rtp::{encode_ulaw, RtpPacket, PAYLOAD_TYPE_ULAW};

    /// Issue #288 DoD: 5 秒分の RTP packet 群 → WAV ファイル生成 + メタ JSON。
    /// 録音 5 秒なので RTP は 20 ms × 250 = 250 packet、 各 packet 160 サンプル
    /// (PCMU 8kHz @ 20ms = 160 byte payload、 RFC 3551 §4.5.14)。
    #[tokio::test]
    async fn rfc3551_4_5_14_record_5sec_packets_produces_wav_with_correct_riff_header() {
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");
        let packets: Vec<RtpPacket> = (0..250)
            .map(|i| RtpPacket {
                payload_type: PAYLOAD_TYPE_ULAW,
                marker: i == 0,
                sequence: 1000 + i,
                timestamp: i as u32 * 160,
                ssrc: 0xCAFE_BABE,
                payload: vec![encode_ulaw(1000); 160],
            })
            .collect();

        let meta = recorder
            .record_from_packets("call-test-5s", "0312345678", &packets)
            .await
            .expect("record");

        assert_eq!(meta.call_id, "call-test-5s");
        assert_eq!(meta.remote_number, "0312345678");
        // 250 packet × 160 samples = 40_000 samples / 8000 Hz = 5_000 ms
        assert_eq!(meta.duration_ms, 5_000);

        // WAV ファイルが書かれていて、 RIFF header が正しいことを確認。
        let wav_bytes = std::fs::read(meta.audio_path(tmp.path())).expect("read wav");
        assert!(wav_bytes.len() > 44, "WAV body 不足");
        assert_eq!(&wav_bytes[0..4], b"RIFF", "RIFF magic");
        assert_eq!(&wav_bytes[8..12], b"WAVE", "WAVE magic");
        assert_eq!(&wav_bytes[12..16], b"fmt ", "fmt chunk");
        // PCM (format code 1)、 mono (1 channel)、 8000 Hz、 16-bit。
        let fmt_code = u16::from_le_bytes([wav_bytes[20], wav_bytes[21]]);
        let channels = u16::from_le_bytes([wav_bytes[22], wav_bytes[23]]);
        let rate = u32::from_le_bytes([wav_bytes[24], wav_bytes[25], wav_bytes[26], wav_bytes[27]]);
        let bits = u16::from_le_bytes([wav_bytes[34], wav_bytes[35]]);
        assert_eq!(fmt_code, 1, "PCM format code");
        assert_eq!(channels, 1, "mono");
        assert_eq!(rate, 8000, "8 kHz");
        assert_eq!(bits, 16, "16-bit linear PCM");
        // data chunk size = 40_000 samples × 2 byte = 80_000 byte
        let data_size =
            u32::from_le_bytes([wav_bytes[40], wav_bytes[41], wav_bytes[42], wav_bytes[43]]);
        assert_eq!(data_size, 80_000);
    }

    /// PCMU 以外の payload type (PT=8 PCMA / PT=101 telephone-event 等) は無視
    /// される (RFC 3551 §4.5.14 + CLAUDE.md §5 NGN は PCMU only)。
    #[tokio::test]
    async fn rfc3551_non_pcmu_payloads_are_skipped() {
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
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
            .record_from_packets("skip-test", "anon", &packets)
            .await
            .expect("record");
        assert_eq!(meta.duration_ms, 0, "全 packet skip されるので 0 ms");
        let wav_bytes = std::fs::read(meta.audio_path(tmp.path())).expect("read wav");
        let data_size =
            u32::from_le_bytes([wav_bytes[40], wav_bytes[41], wav_bytes[42], wav_bytes[43]]);
        assert_eq!(data_size, 0);
    }

    /// PCMU decode が non-zero 信号で動くことを波形 sample で確認する
    /// (`decode_ulaw(encode_ulaw(s))` ≒ s、 RFC 3551 §4.5.14 quantization 誤差内)。
    #[tokio::test]
    async fn pcmu_decode_roundtrip_within_quantization_error() {
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");
        // 8 kHz / 1 kHz sine wave (1 周期 = 8 サンプル) を 1 packet 分。
        let samples: Vec<i16> = (0..160)
            .map(|i| {
                let t = (i as f32) / 8000.0;
                let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin();
                (v * 8000.0) as i16
            })
            .collect();
        let packet = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: true,
            sequence: 1,
            timestamp: 0,
            ssrc: 0,
            payload: samples.iter().map(|s| encode_ulaw(*s)).collect(),
        };
        let meta = recorder
            .record_from_packets("sine-1k", "0312345678", &[packet])
            .await
            .expect("record");
        let wav_bytes = std::fs::read(meta.audio_path(tmp.path())).expect("read wav");
        // data chunk size = 160 × 2 byte
        let data_size =
            u32::from_le_bytes([wav_bytes[40], wav_bytes[41], wav_bytes[42], wav_bytes[43]]);
        assert_eq!(data_size, 320);
        // 最初のサンプル (= 入力 s=0 付近) は decode 値も 0 近傍。
        let s0 = i16::from_le_bytes([wav_bytes[44], wav_bytes[45]]);
        assert!(s0.abs() < 200, "near-zero sample drift: {s0}");
    }

    /// `list` は新しい順 (recorded_at_unix_ms 降順)。
    #[tokio::test]
    async fn list_returns_newest_first() {
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");
        let p = vec![RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 0,
            ssrc: 0,
            payload: vec![encode_ulaw(0); 160],
        }];

        // 録音 ID と recorded_at を別々の値で 2 件登録。 sleep は要らないが
        // tokio Time 上 1ms 進めて recorded_at_unix_ms の単調性を担保する。
        let mut older = recorder
            .record_from_packets("old", "a", &p)
            .await
            .expect("record");
        // sidecar JSON を直接書き換えて時刻差を作る (テスト容易性)。
        older.recorded_at_unix_ms = 1000;
        let json = serde_json::to_vec(&older).unwrap();
        std::fs::write(older.meta_path(tmp.path()), json).unwrap();

        let mut newer = recorder
            .record_from_packets("new", "b", &p)
            .await
            .expect("record");
        newer.recorded_at_unix_ms = 2000;
        let json = serde_json::to_vec(&newer).unwrap();
        std::fs::write(newer.meta_path(tmp.path()), json).unwrap();

        let list = recorder.list().await.expect("list");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].call_id, "new");
        assert_eq!(list[1].call_id, "old");
    }

    /// `delete` で WAV + JSON 両方が消える。 存在しない ID は false。
    #[tokio::test]
    async fn delete_removes_both_wav_and_json() {
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");
        let p = vec![RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 0,
            ssrc: 0,
            payload: vec![encode_ulaw(0); 160],
        }];
        let meta = recorder
            .record_from_packets("victim", "anon", &p)
            .await
            .expect("record");
        assert!(meta.audio_path(tmp.path()).exists());
        assert!(meta.meta_path(tmp.path()).exists());

        let removed = recorder.delete("victim").await.expect("delete");
        assert!(removed);
        assert!(!meta.audio_path(tmp.path()).exists());
        assert!(!meta.meta_path(tmp.path()).exists());

        // 同じ ID をもう一度 delete → false (404 用)。
        let removed2 = recorder.delete("victim").await.expect("delete2");
        assert!(!removed2);
    }

    /// `sanitize_id` は directory traversal を防ぐ。
    /// `/` / `\` 等は `_` に置換され、 単独 `.` / `..` は `_` に置換される。
    /// 結果文字列に `..` の subsequence が残っても、 `/` が無いので
    /// `storage_dir.join(safe_id)` が parent dir を脱出できない (path
    /// component が 1 つのみ)。
    #[test]
    fn sanitize_id_blocks_path_traversal() {
        assert_eq!(sanitize_id(".."), "_");
        assert_eq!(sanitize_id("."), "_");
        // `/` は全部 `_` に変換される (=> 1 component に閉じ込められる)
        assert_eq!(sanitize_id("../etc/passwd"), ".._etc_passwd");
        assert_eq!(sanitize_id("good-id_123.call"), "good-id_123.call");
        assert_eq!(sanitize_id(""), "_");
        assert_eq!(sanitize_id("a/b"), "a_b");
        // バックスラッシュ / NUL / 制御文字も `_` に。
        assert_eq!(sanitize_id("a\\b"), "a_b");
        assert_eq!(sanitize_id("a\0b"), "a_b");
    }

    /// UDP socket 経由の end-to-end: bind した socket に loopback で RTP を撃ち
    /// 込み、 録音停止で WAV file が生成されることを検証する。
    #[tokio::test]
    async fn rfc3550_record_loop_writes_received_rtp_to_wav() {
        let tmp = tempdir();
        let recorder = Arc::new(
            VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(2))
                .await
                .expect("new"),
        );
        let listen = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let listen_addr = listen.local_addr().expect("addr");
        let handle =
            recorder
                .clone()
                .start(listen, "udp-test".to_string(), "0312345678".to_string());

        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");
        for i in 0..10u16 {
            let pkt = RtpPacket {
                payload_type: PAYLOAD_TYPE_ULAW,
                marker: i == 0,
                sequence: 1000 + i,
                timestamp: i as u32 * 160,
                ssrc: 0xCAFE,
                payload: vec![encode_ulaw(1000); 160],
            };
            sender
                .send_to(&pkt.to_bytes(), listen_addr)
                .await
                .expect("send");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // 受信完了を保証してから stop。
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.stop();
        let meta = handle.join().await.expect("join");
        assert_eq!(meta.call_id, "udp-test");
        // 10 packet × 160 samples = 1600 samples / 8000 Hz = 200 ms
        assert!(
            meta.duration_ms >= 100 && meta.duration_ms <= 250,
            "duration_ms ({}) は 100..=250 を期待",
            meta.duration_ms
        );
        let wav_bytes = std::fs::read(meta.audio_path(tmp.path())).expect("read wav");
        assert_eq!(&wav_bytes[0..4], b"RIFF");
        assert_eq!(&wav_bytes[8..12], b"WAVE");
    }

    /// Issue #300: voicemail finalize 経路で transcriber が attach されている
    /// ときに sidecar `.txt` が生成され、 placeholder text が書かれていること。
    /// 主資源 (WAV / JSON) も従来通り生成されていることを併せて確認する
    /// (= transcription 失敗で音声本体が消えない、 finalize hook が後方互換)。
    #[tokio::test]
    async fn issue_300_voicemail_finalize_writes_stub_transcript_sidecar_txt() {
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new")
            .with_transcriber(Arc::new(StubTranscriber));
        let packets = vec![RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: true,
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
            payload: vec![encode_ulaw(0); 160],
        }];
        let meta = recorder
            .record_from_packets("call-tr-vm", "0312345678", &packets)
            .await
            .expect("record");

        // 主資源 WAV + JSON は従来通り存在する。
        let wav_path = meta.audio_path(tmp.path());
        let meta_path = meta.meta_path(tmp.path());
        assert!(wav_path.exists(), "WAV must exist after finalize");
        assert!(meta_path.exists(), "JSON sidecar must exist after finalize");

        // Issue #300 transcript `.txt` が WAV と同じ basename で生成される。
        let txt_path = transcript_path_for(&wav_path);
        assert!(
            txt_path.exists(),
            "transcript `.txt` must be written by finalize hook: {:?}",
            txt_path
        );
        let txt = std::fs::read_to_string(&txt_path).expect("read txt");
        assert_eq!(txt, StubTranscriber::PLACEHOLDER_TEXT);
    }

    /// Issue #300: transcriber 未 attach (= 既定 disabled) なら `.txt` は
    /// **書かれない** (完全な後方互換、 Issue #288 当時の挙動と同一)。
    #[tokio::test]
    async fn issue_300_voicemail_without_transcriber_does_not_write_txt() {
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new");
        let packets = vec![RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: true,
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
            payload: vec![encode_ulaw(0); 160],
        }];
        let meta = recorder
            .record_from_packets("call-no-tr", "0312345678", &packets)
            .await
            .expect("record");
        let wav_path = meta.audio_path(tmp.path());
        assert!(wav_path.exists());
        let txt_path = transcript_path_for(&wav_path);
        assert!(
            !txt_path.exists(),
            "transcript `.txt` must NOT be written when transcriber is None"
        );
    }

    /// Issue #300: transcribe が `Err` を返しても WAV / JSON 本体は保護される
    /// (= warn のみで finalize 完了)。 production code の panic 禁止を満たす。
    #[tokio::test]
    async fn issue_300_voicemail_transcriber_failure_preserves_wav_and_json() {
        struct FailingTranscriber;
        impl Transcriber for FailingTranscriber {
            fn transcribe(&self, _: &Path) -> Result<TranscriptionResult> {
                Err(anyhow::anyhow!("synthetic failure"))
            }
        }
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new")
            .with_transcriber(Arc::new(FailingTranscriber));
        let packets = vec![RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: true,
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
            payload: vec![encode_ulaw(0); 160],
        }];
        let meta = recorder
            .record_from_packets("call-tr-fail", "0312345678", &packets)
            .await
            .expect("record (should succeed despite transcriber failure)");
        let wav_path = meta.audio_path(tmp.path());
        let meta_path = meta.meta_path(tmp.path());
        assert!(wav_path.exists(), "WAV must survive transcriber failure");
        assert!(meta_path.exists(), "JSON must survive transcriber failure");
        // transcript は書かれていない (失敗時は no `.txt`)
        let txt_path = transcript_path_for(&wav_path);
        assert!(
            !txt_path.exists(),
            "transcript `.txt` must NOT exist when transcribe fails"
        );
    }

    /// Issue #300: `delete` は sidecar transcript `.txt` も削除する。
    #[tokio::test]
    async fn issue_300_voicemail_delete_removes_sidecar_transcript_txt() {
        let tmp = tempdir();
        let recorder = VoicemailRecorder::new(tmp.path().to_path_buf(), Duration::from_secs(60))
            .await
            .expect("new")
            .with_transcriber(Arc::new(StubTranscriber));
        let packets = vec![RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: true,
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
            payload: vec![encode_ulaw(0); 160],
        }];
        let meta = recorder
            .record_from_packets("call-del", "0312345678", &packets)
            .await
            .expect("record");
        let wav_path = meta.audio_path(tmp.path());
        let txt_path = transcript_path_for(&wav_path);
        assert!(txt_path.exists());
        let removed = recorder.delete("call-del").await.expect("delete");
        assert!(removed);
        assert!(!wav_path.exists());
        assert!(!txt_path.exists(), "transcript must be deleted with WAV");
    }

    /// テスト用 tempdir ヘルパ (`tempfile` crate を引かないため自前)。
    fn tempdir() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("sabiden-vm-test-{pid}-{nanos}-{n}"));
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
}
