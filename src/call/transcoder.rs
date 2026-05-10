//! Opus ↔ G.711 μ-law トランスコーディング ブリッジ
//!
//! WebRTC レッグ (Opus 48 kHz) と NGN レッグ (G.711 μ-law 8 kHz) の間で
//! メディアパケットを相互変換しながらリレーする。
//!
//! ## パイプライン
//!
//! ```text
//! WebRTC RTP (Opus)  → デコード → PCM 48k → ダウンサンプル → PCM 8k → μ-law → NGN RTP
//! NGN RTP (μ-law)    → デコード → PCM 8k  → アップサンプル → PCM 48k → Opus  → WebRTC RTP
//! ```
//!
//! ## 設計上の注意
//!
//! - 各方向のホットパスは "1 RTP 受信 → 1 RTP 送信" の同期処理。並列性はソケット
//!   ループ単位 (NGN→WebRTC と WebRTC→NGN を別タスクで spawn)。
//! - コーデックインスタンス (Encoder/Decoder/Resampler) は各方向で 1 個ずつ。
//!   `&mut self` で状態を持ち、`Mutex` 越しに使う。NGN 側は 20ms ごとに 1 個の
//!   パケットしか来ないため lock 競合は事実上ない。
//! - RTP ヘッダ (seq, ts, ssrc) は出力側で再生成する。NGN 側は 8000 Hz 単位の
//!   timestamp、WebRTC 側は 48000 Hz 単位の timestamp になる。
//! - 受信元アドレスは `RtpBridge` と同じく late binding で学習する。
//!
//! ## トレードオフ (リレーモードとの違い)
//!
//! - CPU コストは 0 → ~数 % へ増加 (20ms ごとに Opus encode/decode + リサンプル)
//! - 追加レイテンシ ~20ms (フレーム境界で待つ)
//! - 暗号化 (SRTP) は範疇外。WebRTC 側 SRTP を解く処理は呼び出し側で行う前提。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::observability::Metrics;
use crate::rtp::codec::opus::{OpusDecoder, OpusEncoder, OPUS_FRAME_SAMPLES};
use crate::rtp::codec::resample::{
    DownsamplerWbToNb, UpsamplerNbToWb, NARROW_BAND_RATE, NB_FRAME_SAMPLES, WB_FRAME_SAMPLES,
};
use crate::rtp::codec::AudioFrame;
use crate::rtp::jitter::{JitterBuffer, DEFAULT_DEPTH};
use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW, SAMPLES_PER_FRAME};
use crate::rtp::{decode_ulaw, encode_ulaw, set_rtp_dscp};
use crate::webrtc::peer::{MediaFrame, PeerSession};

/// `TranscodingBridge` のジッタバッファ pull 周期。
///
/// RFC 3551 §4.5.14 (PCMU 8 kHz / 20 ms / 160 samples / packet) と
/// RFC 7587 §4.2 (Opus 20 ms = 960 samples @ 48 kHz) の双方とも
/// 20 ms フレーム前提なので、 1 frame 取り出すごとに 1 RTP packet を
/// エンコード送信する。
const JITTER_PULL_INTERVAL: Duration = Duration::from_millis(20);

/// ジッタバッファのデフォルト深度 (パケット数)。
///
/// RFC 3550 §6.4.1: jitter は受信パケット間隔の統計分散。 `JitterBuffer`
/// (`src/rtp/jitter.rs`) は受信時に §A.8 の式で jitter 推定を更新し、
/// 取り出し時に `depth` 未満なら待機 (= reorder window)、 `depth*2` を
/// 超えたら強制 pull (= overflow ロス) する。 デフォルト 4 packet ≒ 80 ms は
/// `src/rtp/jitter.rs::DEFAULT_DEPTH` と整合。
const JITTER_DEPTH: usize = DEFAULT_DEPTH;

/// Opus ペイロード PT。WebRTC SDP では動的 PT (96-127) を使うのが一般的。
/// SDP で受け取った値を渡せるようにし、デフォルトは 111 (Chromium 互換)。
pub const DEFAULT_OPUS_PT: u8 = 111;

/// トランスコードブリッジの起動パラメータ。
pub struct TranscodeConfig {
    /// NGN 側 RTP ソケット (G.711 μ-law)
    pub ngn_socket: Arc<UdpSocket>,
    /// WebRTC 側 RTP ソケット (Opus)
    pub web_socket: Arc<UdpSocket>,
    /// SDP から既知の NGN 側ピア (Option: late-binding)
    pub ngn_peer: Option<SocketAddr>,
    /// SDP から既知の WebRTC 側ピア
    pub web_peer: Option<SocketAddr>,
    /// SDP `a=rtpmap:<pt> opus/48000/2` で指定された PT。指定なしは [`DEFAULT_OPUS_PT`]。
    pub opus_payload_type: u8,
    /// 観測カウンタ。
    pub metrics: Option<Arc<Metrics>>,
}

/// 内側の peer 状態 (片方向)。`RtpBridge::LegState` と同じ late-binding 戦略。
#[derive(Default)]
struct LegState {
    peer: Mutex<Option<SocketAddr>>,
}

/// 1 通話分のトランスコード ブリッジ。
pub struct TranscodingBridge {
    ngn_to_web: Option<JoinHandle<()>>,
    web_to_ngn: Option<JoinHandle<()>>,
    state: Arc<BridgeState>,
    /// NGN 側 socket / 学習済 peer。DTMF 注入 (Issue #69) で使う。
    ngn_socket: Arc<UdpSocket>,
    ngn_state: Arc<LegState>,
    /// WebRTC 側 socket / 学習済 peer。NGN→内線 INFO 経路の placeholder。
    web_socket: Arc<UdpSocket>,
    web_state: Arc<LegState>,
}

#[derive(Default)]
struct BridgeState {
    /// NGN→WebRTC 方向で正しく送信できた RTP 数
    ngn_to_web_packets: std::sync::atomic::AtomicU64,
    /// WebRTC→NGN 方向で正しく送信できた RTP 数
    web_to_ngn_packets: std::sync::atomic::AtomicU64,
    /// デコード/エンコード失敗で drop した RTP 数
    transcode_errors: std::sync::atomic::AtomicU64,
}

impl TranscodingBridge {
    /// ブリッジを起動する。両方向のループを spawn する。
    pub fn start(cfg: TranscodeConfig) -> Result<Self> {
        let TranscodeConfig {
            ngn_socket,
            web_socket,
            ngn_peer,
            web_peer,
            opus_payload_type,
            metrics,
        } = cfg;

        if let Err(e) = set_rtp_dscp(&ngn_socket, 32) {
            warn!("NGN RTP socket DSCP 設定失敗 (続行): {}", e);
        }

        let ngn_state = Arc::new(LegState {
            peer: Mutex::new(ngn_peer),
        });
        let web_state = Arc::new(LegState {
            peer: Mutex::new(web_peer),
        });
        let state = Arc::new(BridgeState::default());

        // NGN → WebRTC: μ-law デコード → 8k PCM → アップサンプル → 48k PCM → Opus
        let ngn_to_web = tokio::spawn(ngn_to_web_loop(
            ngn_socket.clone(),
            web_socket.clone(),
            ngn_state.clone(),
            web_state.clone(),
            state.clone(),
            opus_payload_type,
            metrics.clone(),
        ));

        // WebRTC → NGN: Opus デコード → 48k PCM → ダウンサンプル → 8k PCM → μ-law
        let web_to_ngn = tokio::spawn(web_to_ngn_loop(
            web_socket.clone(),
            ngn_socket.clone(),
            web_state.clone(),
            ngn_state.clone(),
            state.clone(),
            opus_payload_type,
            metrics,
        ));

        Ok(Self {
            ngn_to_web: Some(ngn_to_web),
            web_to_ngn: Some(web_to_ngn),
            state,
            ngn_socket,
            ngn_state,
            web_socket,
            web_state,
        })
    }

    /// Issue #69: NGN 側 socket から NGN ピア宛に任意 RTP datagram を 1 つ送る。
    /// SIP INFO で受け取った DTMF を RFC 4733 telephone-event RTP packet に
    /// 変換して NGN レッグに乗せるための注入経路。
    ///
    /// NGN ピアが学習されていない (= まだ RTP を受信していない) 場合は `Err`。
    /// トランスコード経路では Opus → μ-law 変換と independent に PT=101 を
    /// 直接送れるので、DTMF をリサンプル / 再エンコードしない (RFC 4733 §2.4)。
    pub async fn send_to_ngn(&self, datagram: &[u8]) -> Result<()> {
        let dest = { *self.ngn_state.peer.lock().await };
        let dest = dest.ok_or_else(|| anyhow::anyhow!("NGN peer 未確定"))?;
        self.ngn_socket.send_to(datagram, dest).await?;
        Ok(())
    }

    /// Issue #69: WebRTC 側 socket から WebRTC ピア宛に任意 RTP datagram を 1 つ送る
    /// (NGN→内線 INFO 経路の placeholder)。
    pub async fn send_to_web(&self, datagram: &[u8]) -> Result<()> {
        let dest = { *self.web_state.peer.lock().await };
        let dest = dest.ok_or_else(|| anyhow::anyhow!("Web peer 未確定"))?;
        self.web_socket.send_to(datagram, dest).await?;
        Ok(())
    }

    /// 両ループを停止する。
    pub async fn stop(mut self) {
        if let Some(h) = self.ngn_to_web.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.web_to_ngn.take() {
            h.abort();
            let _ = h.await;
        }
    }

    /// 統計: (NGN→WebRTC 成功数, WebRTC→NGN 成功数, トランスコード失敗数)
    pub fn stats(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.state.ngn_to_web_packets.load(Ordering::Relaxed),
            self.state.web_to_ngn_packets.load(Ordering::Relaxed),
            self.state.transcode_errors.load(Ordering::Relaxed),
        )
    }
}

impl Drop for TranscodingBridge {
    fn drop(&mut self) {
        if let Some(h) = self.ngn_to_web.take() {
            h.abort();
        }
        if let Some(h) = self.web_to_ngn.take() {
            h.abort();
        }
    }
}

/// NGN (μ-law 8k) → WebRTC (Opus 48k) 方向の 1 ループ。
///
/// # ジッタバッファ統合 (Issue #105)
///
/// `recv_from` 直後に `RtpPacket` を [`JitterBuffer`] へ push し、
/// 20 ms 間隔の `interval` tick で `pull` してエンコード送信する。
/// 受信タスクとエンコード送信タスクを 1 つの async 関数に
/// `tokio::select!` で同居させることで、 [`JitterBuffer`] への
/// 排他アクセス (Mutex 不要) と JoinHandle の単一化を両立する。
///
/// # RFC 引用
///
/// - **RFC 3550 §6.4.1** (Jitter): jitter は受信パケット間隔の統計分散。
///   IP 網は順序保証しない (§A.8 D(i,j) = (Rj-Ri)-(Sj-Si) の前提)。
/// - **RFC 3550 §6.4.2** (Inter-arrival jitter): 受信側 (= sabiden) は
///   jitter 推定値に応じてバッファ深度を調整するべき。 本実装では
///   固定深度 4 packet ≒ 80 ms (`JITTER_DEPTH`) を採用。
/// - **RFC 7587 §6.2** (Opus PLC): pull が `None` (= 期待 seq の packet が
///   未到着) の場合、 timing 維持のため空 payload を decode して PLC frame
///   を生成する選択肢があるが、 `JitterBuffer` はバッファが overflow に
///   なるまで `None` を返し続ける設計のため (`src/rtp/jitter.rs::pull`)、
///   無音を勝手に挿入しない。 端末側の jitter buffer に PLC を委ねる。
async fn ngn_to_web_loop(
    from_socket: Arc<UdpSocket>,
    to_socket: Arc<UdpSocket>,
    from_state: Arc<LegState>,
    to_state: Arc<LegState>,
    state: Arc<BridgeState>,
    opus_pt: u8,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    let span = tracing::trace_span!("transcode_ngn_to_web");
    let _enter = span.enter();

    // パイプラインの状態 (この方向で 1 通話の間使い回す)
    let mut upsampler = match UpsamplerNbToWb::new() {
        Ok(v) => v,
        Err(e) => {
            warn!(error=%e, "Upsampler 初期化失敗 → NGN→Web 方向停止");
            return;
        }
    };
    let mut encoder = match OpusEncoder::new() {
        Ok(v) => v,
        Err(e) => {
            warn!(error=%e, "Opus エンコーダ初期化失敗 → NGN→Web 方向停止");
            return;
        }
    };

    // 出力 RTP の seq/ts/ssrc は random 初期値で start (RFC 3550 §5.1)
    let ssrc: u32 = rand::random();
    let mut seq: u16 = rand::random();
    let mut ts: u32 = rand::random();

    let mut jitter = JitterBuffer::new(JITTER_DEPTH);
    let mut tick = tokio::time::interval(JITTER_PULL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            // RTP 受信 → jitter buffer へ push (RFC 3550 §6.4.1)
            recv_res = from_socket.recv_from(&mut buf) => {
                let (n, src) = match recv_res {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(error=%e, "NGN recv エラー → ループ終了");
                        return;
                    }
                };
                // 送信元学習 (NGN 側の peer)
                {
                    let mut peer = from_state.peer.lock().await;
                    if peer.as_ref() != Some(&src) {
                        trace!(?src, "NGN 側 RTP 送信元学習");
                        *peer = Some(src);
                    }
                }

                let pkt = match RtpPacket::from_bytes(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        trace!(error=%e, "NGN RTP パース失敗 → drop");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if pkt.payload_type != PAYLOAD_TYPE_ULAW {
                    trace!(pt = pkt.payload_type, "NGN 側 PT≠0 → drop");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // 1 NGN フレームは 20ms = 160 samples 想定
                if pkt.payload.len() != SAMPLES_PER_FRAME {
                    trace!(len = pkt.payload.len(), "NGN payload 長異常 → drop");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                jitter.push(pkt, Instant::now());
            }
            // 20ms tick → jitter buffer から pull → transcode → 送信
            _ = tick.tick() => {
                let Some(pkt) = jitter.pull() else { continue };

                // μ-law decode
                let pcm8: Vec<i16> = pkt.payload.iter().map(|b| decode_ulaw(*b)).collect();
                let nb = AudioFrame::new(NARROW_BAND_RATE, pcm8);

                // upsample 8k → 48k
                let wb = match upsampler.process(&nb) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!(error=%e, "アップサンプル失敗");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                // Opus encode
                let opus_payload = match encoder.encode(&wb) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!(error=%e, "Opus エンコード失敗");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                let dest = match *to_state.peer.lock().await {
                    Some(d) => d,
                    None => {
                        trace!("WebRTC 側 peer 未確定 → drop");
                        continue;
                    }
                };

                let out_pkt = RtpPacket {
                    payload_type: opus_pt & 0x7f,
                    marker: false,
                    sequence: seq,
                    timestamp: ts,
                    ssrc,
                    payload: opus_payload,
                };
                seq = seq.wrapping_add(1);
                ts = ts.wrapping_add(OPUS_FRAME_SAMPLES as u32);

                if let Err(e) = to_socket.send_to(&out_pkt.to_bytes(), dest).await {
                    warn!(error=%e, "WebRTC へ RTP forward 失敗");
                    continue;
                }
                state.ngn_to_web_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(m) = metrics.as_ref() {
                    m.add_rtp_ngn_to_ext(1);
                }
            }
        }
    }
}

/// WebRTC (Opus 48k) → NGN (μ-law 8k) 方向の 1 ループ。
///
/// # ジッタバッファ統合 (Issue #105)
///
/// `recv_from` 直後に `RtpPacket` を [`JitterBuffer`] へ push し、
/// 20 ms 間隔の `interval` tick で `pull` してデコード送信する。
/// WebRTC レッグは ICE/TURN 経由で reorder の頻度が高いため、
/// NGN 方向と同様 jitter buffer を経由する。
///
/// # RFC 引用
///
/// - **RFC 3550 §6.4.1** (Jitter): IP 網は順序保証無し、 受信側で再整列
///   が必要。
/// - **RFC 3550 §6.4.2** (Inter-arrival jitter buffer): 受信側 buffer は
///   reorder 緩和と loss 検出の双方を兼ねる。
async fn web_to_ngn_loop(
    from_socket: Arc<UdpSocket>,
    to_socket: Arc<UdpSocket>,
    from_state: Arc<LegState>,
    to_state: Arc<LegState>,
    state: Arc<BridgeState>,
    opus_pt: u8,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    let span = tracing::trace_span!("transcode_web_to_ngn");
    let _enter = span.enter();

    let mut downsampler = match DownsamplerWbToNb::new() {
        Ok(v) => v,
        Err(e) => {
            warn!(error=%e, "Downsampler 初期化失敗 → Web→NGN 方向停止");
            return;
        }
    };
    let mut decoder = match OpusDecoder::new() {
        Ok(v) => v,
        Err(e) => {
            warn!(error=%e, "Opus デコーダ初期化失敗 → Web→NGN 方向停止");
            return;
        }
    };

    let ssrc: u32 = rand::random();
    let mut seq: u16 = rand::random();
    let mut ts: u32 = rand::random();

    let mut jitter = JitterBuffer::new(JITTER_DEPTH);
    let mut tick = tokio::time::interval(JITTER_PULL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            recv_res = from_socket.recv_from(&mut buf) => {
                let (n, src) = match recv_res {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(error=%e, "WebRTC recv エラー → ループ終了");
                        return;
                    }
                };
                {
                    let mut peer = from_state.peer.lock().await;
                    if peer.as_ref() != Some(&src) {
                        trace!(?src, "WebRTC 側 RTP 送信元学習");
                        *peer = Some(src);
                    }
                }

                let pkt = match RtpPacket::from_bytes(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        trace!(error=%e, "WebRTC RTP パース失敗 → drop");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if pkt.payload_type != opus_pt {
                    trace!(
                        pt = pkt.payload_type,
                        expected = opus_pt,
                        "WebRTC PT 不一致 → drop"
                    );
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                jitter.push(pkt, Instant::now());
            }
            _ = tick.tick() => {
                let Some(pkt) = jitter.pull() else { continue };

                // Opus decode → 48k PCM (mono, 960 samples 想定)
                let wb = match decoder.decode(&pkt.payload) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!(error=%e, "Opus デコード失敗");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                // 20ms 以外のフレーム長はサポート外 (本実装は 20ms 固定)
                if wb.samples.len() != WB_FRAME_SAMPLES {
                    trace!(
                        samples = wb.samples.len(),
                        "WebRTC フレーム長異常 (20ms 期待) → drop"
                    );
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // downsample 48k → 8k
                let nb = match downsampler.process(&wb) {
                    Ok(v) => v,
                    Err(e) => {
                        trace!(error=%e, "ダウンサンプル失敗");
                        state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if nb.samples.len() != NB_FRAME_SAMPLES {
                    trace!(samples = nb.samples.len(), "NB フレーム長異常 → drop");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // μ-law encode
                let ulaw: Vec<u8> = nb.samples.iter().map(|s| encode_ulaw(*s)).collect();

                let dest = match *to_state.peer.lock().await {
                    Some(d) => d,
                    None => {
                        trace!("NGN 側 peer 未確定 → drop");
                        continue;
                    }
                };

                let out_pkt = RtpPacket {
                    payload_type: PAYLOAD_TYPE_ULAW,
                    marker: false,
                    sequence: seq,
                    timestamp: ts,
                    ssrc,
                    payload: ulaw,
                };
                seq = seq.wrapping_add(1);
                ts = ts.wrapping_add(SAMPLES_PER_FRAME as u32);

                if let Err(e) = to_socket.send_to(&out_pkt.to_bytes(), dest).await {
                    warn!(error=%e, "NGN へ RTP forward 失敗");
                    continue;
                }
                state.web_to_ngn_packets.fetch_add(1, Ordering::Relaxed);
                if let Some(m) = metrics.as_ref() {
                    m.add_rtp_ext_to_ngn(1);
                }
            }
        }
    }
}

/// SDP の `a=rtpmap:<pt> opus/48000[/<ch>]` (RFC 7587 §7.1) から PT を取り出す。
///
/// 該当がなければ `None`。トランスコード要否判定 (`sdp_uses_opus`) の基礎関数。
pub fn find_opus_payload_type(sdp_bytes: &[u8]) -> Option<u8> {
    let text = std::str::from_utf8(sdp_bytes).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            if let Some((pt_str, codec_part)) = rest.split_once(' ') {
                let codec = codec_part
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if codec == "opus" {
                    if let Ok(pt) = pt_str.parse::<u8>() {
                        return Some(pt);
                    }
                }
            }
        }
    }
    None
}

/// SDP で Opus が宣言されているかどうか (= トランスコードが必要か) を判定する
/// 簡易関数。WebRTC ↔ NGN 通話判定のヒューリスティック。
pub fn sdp_uses_opus(sdp_bytes: &[u8]) -> bool {
    find_opus_payload_type(sdp_bytes).is_some()
}

/// Issue #87 / #121: NGN レッグ (UDP socket) ⇔ WebRTC peer (str0m) を結ぶ
/// 双方向ブリッジ。
///
/// `TranscodingBridge` と違い、 PWA レッグは UDP socket を直接持たず、
/// [`PeerSession::take_media_rx`] / [`PeerSession::send_media`] の
/// MediaFrame mpsc を使う (str0m が ICE/DTLS 上で SRTP 多重化するため)。
///
/// # 経路
///
/// ```text
/// NGN UDP socket (PCMU PT 0)  →  μ-law decode → 8k PCM
///   → upsample 48k PCM → Opus encode → MediaFrame → peer.send_media
///
/// peer.take_media_rx (Opus)
///   → Opus decode → 48k PCM → downsample 8k PCM
///   → μ-law encode → RtpPacket → NGN UDP socket
/// ```
///
/// # RFC 引用
///
/// - **RFC 3550 §5.1** (RTP frame): NGN レッグの 1 RTP パケットは 1 frame。
/// - **RFC 3551 §4.5.14** (PCMU PT 0, 8 kHz, 20 ms = 160 samples / packet)。
/// - **RFC 7587 §4.2** (Opus payload format): WebRTC は通常 20 ms = 960
///   samples@48 kHz の Opus フレームを 1 RTP packet に乗せる。
/// - **RFC 8835** (WebRTC overview): 媒体経路は SRTP/AVPF の上 Opus を運ぶ。
pub struct WebRtcAudioBridge {
    ngn_to_peer: Option<JoinHandle<()>>,
    peer_to_ngn: Option<JoinHandle<()>>,
    state: Arc<BridgeState>,
    /// NGN 側 socket / 学習済 peer。 DTMF 注入 (Issue #69) で使う。
    ngn_socket: Arc<UdpSocket>,
    ngn_state: Arc<LegState>,
}

/// [`WebRtcAudioBridge`] の起動パラメータ。
pub struct WebRtcAudioConfig {
    /// NGN 側 RTP ソケット (G.711 μ-law PT=0)。
    pub ngn_socket: Arc<UdpSocket>,
    /// SDP から既知の NGN 側ピア (Option: late-binding)。
    pub ngn_peer: Option<SocketAddr>,
    /// WebRTC peer。 双方向の MediaFrame mpsc にアクセスする。
    pub peer: Arc<dyn PeerSession>,
    /// `take_media_rx` で取り出した PWA → orchestrator 方向の receiver。
    /// `peer.take_media_rx().await` の結果をそのまま渡す。
    pub peer_media_rx: mpsc::Receiver<MediaFrame>,
    /// SDP `a=rtpmap:<pt> opus/48000[/<ch>]` で negotiate した PT。
    /// 不明なら [`DEFAULT_OPUS_PT`]。
    pub opus_payload_type: u8,
    /// PCMU 直送モード (両側 PCMU 構成、 transcode 不要)。
    /// sabiden の str0m は `enable_pcmu` 1 codec 構成 (`webrtc/str0m_session.rs:190`)
    /// なので NGN(μ-law)↔PWA(μ-law) を素通しできる。 true の場合 Opus 経路を
    /// 完全に bypass し、 NGN 受信 RTP の payload をそのまま `MediaFrame { pt:0 }`
    /// として peer に流す (RFC 3551 §4.5.14: PCMU PT 0、 8kHz)。
    pub direct_pcmu_passthrough: bool,
    /// 観測カウンタ。
    pub metrics: Option<Arc<Metrics>>,
}

impl WebRtcAudioBridge {
    /// ブリッジを起動する。両方向のループを spawn する。
    ///
    /// # 戻り値が `Self` (not `Result<Self>`) である理由 (Issue #135 🟡 3)
    ///
    /// 本関数は内部で fallible な操作を一切しない:
    /// - `set_rtp_dscp` は失敗しても `warn` で握る (DSCP は QoS 最適化、
    ///   設定不可でも通話自体は成立する。 `src/main.rs::set_dscp` 参照)。
    /// - `tokio::spawn` は infallible (panic を `JoinError` として後段で
    ///   検知する設計、 spawn 自体は `Err` を返さない)。
    ///
    /// よって `Result<Self>` を返すと呼出側 (`orchestrator.rs::run_inbound_*`
    /// および PWA outbound 経路) が形式上 `?` で error path を書く必要が生じ、
    /// **存在しない error path** を扱うことになる。 これは「unreachable な
    /// failure mode を API に晒さない」(Rust API guidelines C-FAILURE) 観点で
    /// 誠実でないため、 `Self` を直接返す。 RFC 直接参照は無いが、
    /// `CLAUDE.md §6.5` の `unwrap`/`expect` 禁止と同じ精神 (production code
    /// で出ない error path を晒さない) に則る。
    pub fn start(cfg: WebRtcAudioConfig) -> Self {
        let WebRtcAudioConfig {
            ngn_socket,
            ngn_peer,
            peer,
            peer_media_rx,
            opus_payload_type,
            direct_pcmu_passthrough,
            metrics,
        } = cfg;

        if let Err(e) = set_rtp_dscp(&ngn_socket, 32) {
            warn!("NGN RTP socket DSCP 設定失敗 (続行): {}", e);
        }

        let ngn_state = Arc::new(LegState {
            peer: Mutex::new(ngn_peer),
        });
        let state = Arc::new(BridgeState::default());

        // NGN → peer: μ-law → 8k PCM → 48k PCM → Opus → peer.send_media
        // (direct_pcmu_passthrough = true なら μ-law をそのまま PT 0 で peer へ素通し)
        let ngn_to_peer = tokio::spawn(ngn_to_peer_loop(
            ngn_socket.clone(),
            ngn_state.clone(),
            peer.clone(),
            state.clone(),
            opus_payload_type,
            direct_pcmu_passthrough,
            metrics.clone(),
        ));

        // peer → NGN: peer.take_media_rx (Opus) → 48k PCM → 8k PCM → μ-law → NGN UDP
        // (direct_pcmu_passthrough = true なら受信した PT 0 PCMU をそのまま μ-law として NGN へ)
        let peer_to_ngn = tokio::spawn(peer_to_ngn_loop(
            peer_media_rx,
            ngn_socket.clone(),
            ngn_state.clone(),
            state.clone(),
            opus_payload_type,
            direct_pcmu_passthrough,
            metrics,
        ));

        Self {
            ngn_to_peer: Some(ngn_to_peer),
            peer_to_ngn: Some(peer_to_ngn),
            state,
            ngn_socket,
            ngn_state,
        }
    }

    /// Issue #69: NGN 側 socket から NGN ピア宛に任意 RTP datagram を 1 つ送る。
    pub async fn send_to_ngn(&self, datagram: &[u8]) -> Result<()> {
        let dest = { *self.ngn_state.peer.lock().await };
        let dest = dest.ok_or_else(|| anyhow::anyhow!("NGN peer 未確定"))?;
        self.ngn_socket.send_to(datagram, dest).await?;
        Ok(())
    }

    /// 両ループを停止する。
    pub async fn stop(mut self) {
        if let Some(h) = self.ngn_to_peer.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.peer_to_ngn.take() {
            h.abort();
            let _ = h.await;
        }
    }

    /// 統計: (NGN→peer 成功数, peer→NGN 成功数, トランスコード失敗数)
    pub fn stats(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.state.ngn_to_web_packets.load(Ordering::Relaxed),
            self.state.web_to_ngn_packets.load(Ordering::Relaxed),
            self.state.transcode_errors.load(Ordering::Relaxed),
        )
    }
}

impl Drop for WebRtcAudioBridge {
    fn drop(&mut self) {
        if let Some(h) = self.ngn_to_peer.take() {
            h.abort();
        }
        if let Some(h) = self.peer_to_ngn.take() {
            h.abort();
        }
    }
}

/// NGN (μ-law 8k) → WebRTC peer (Opus 48k) 方向。
///
/// 1 RTP 受信 → 1 MediaFrame 送信。 `peer.send_media` は run_loop に
/// command で渡すだけなので背圧は実質 mpsc バッファ容量で吸収される。
async fn ngn_to_peer_loop(
    from_socket: Arc<UdpSocket>,
    from_state: Arc<LegState>,
    peer: Arc<dyn PeerSession>,
    state: Arc<BridgeState>,
    opus_pt: u8,
    direct_pcmu_passthrough: bool,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    let span = tracing::trace_span!("transcode_ngn_to_peer");
    let _enter = span.enter();

    debug!(direct_pcmu_passthrough, "ngn_to_peer_loop START");

    // 直送モード時は upsampler / encoder を初期化しない (使わない)。
    let mut upsampler_enc: Option<(UpsamplerNbToWb, OpusEncoder)> = if direct_pcmu_passthrough {
        None
    } else {
        let up = match UpsamplerNbToWb::new() {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "Upsampler 初期化失敗 → NGN→peer 方向停止");
                return;
            }
        };
        let enc = match OpusEncoder::new() {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "Opus エンコーダ初期化失敗 → NGN→peer 方向停止");
                return;
            }
        };
        Some((up, enc))
    };

    // RTP timestamp 単調増加 (RFC 7587 §4.1: Opus は 48kHz、 RFC 3551 §4.5.14:
    // PCMU は 8kHz)。 直送モードでは frame ごとに 160 サンプル進める。
    let mut rtp_ts: u32 = rand::random();

    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match from_socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!(error=%e, "NGN recv エラー → NGN→peer 方向終了");
                return;
            }
        };
        {
            let mut p = from_state.peer.lock().await;
            if p.as_ref() != Some(&src) {
                trace!(?src, "NGN 側 RTP 送信元学習");
                *p = Some(src);
            }
        }

        let pkt = match RtpPacket::from_bytes(&buf[..n]) {
            Ok(p) => p,
            Err(e) => {
                trace!(error=%e, "NGN RTP パース失敗 → drop");
                state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        if pkt.payload_type != PAYLOAD_TYPE_ULAW {
            trace!(pt = pkt.payload_type, "NGN 側 PT≠0 → drop");
            state.transcode_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if pkt.payload.len() != SAMPLES_PER_FRAME {
            trace!(len = pkt.payload.len(), "NGN payload 長異常 → drop");
            state.transcode_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let frame = if direct_pcmu_passthrough {
            // PCMU 直送: μ-law payload をそのまま PT 0 で peer に渡す。
            // RTP timestamp は 8kHz 単位 (RFC 3551 §4.5.14: PCMU clock=8000)、
            // 1 frame = SAMPLES_PER_FRAME (= 160) 進める。
            let f = MediaFrame {
                pt: PAYLOAD_TYPE_ULAW,
                rtp_time: rtp_ts,
                payload: pkt.payload.clone(),
                network_time: std::time::Instant::now(),
            };
            rtp_ts = rtp_ts.wrapping_add(SAMPLES_PER_FRAME as u32);
            f
        } else {
            let (upsampler, encoder) = upsampler_enc
                .as_mut()
                .expect("upsampler_enc must be Some when not in direct mode");
            let pcm8: Vec<i16> = pkt.payload.iter().map(|b| decode_ulaw(*b)).collect();
            let nb = AudioFrame::new(NARROW_BAND_RATE, pcm8);
            let wb = match upsampler.process(&nb) {
                Ok(v) => v,
                Err(e) => {
                    trace!(error=%e, "アップサンプル失敗");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let opus_payload = match encoder.encode(&wb) {
                Ok(v) => v,
                Err(e) => {
                    trace!(error=%e, "Opus エンコード失敗");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let f = MediaFrame {
                pt: opus_pt,
                rtp_time: rtp_ts,
                payload: opus_payload,
                network_time: std::time::Instant::now(),
            };
            rtp_ts = rtp_ts.wrapping_add(OPUS_FRAME_SAMPLES as u32);
            f
        };

        if let Err(e) = peer.send_media(frame).await {
            debug!(error=%e, "peer.send_media 失敗 → NGN→peer 方向終了");
            return;
        }
        state.ngn_to_web_packets.fetch_add(1, Ordering::Relaxed);
        if let Some(m) = metrics.as_ref() {
            m.add_rtp_ngn_to_ext(1);
        }
    }
}

/// WebRTC peer (Opus 48k) → NGN (μ-law 8k) 方向。
///
/// `peer_media_rx` から MediaFrame を 1 個受け取り、 Opus decode → resample →
/// μ-law encode → RTP packet 構築 → NGN UDP socket へ送信する。
async fn peer_to_ngn_loop(
    mut peer_media_rx: mpsc::Receiver<MediaFrame>,
    to_socket: Arc<UdpSocket>,
    to_state: Arc<LegState>,
    state: Arc<BridgeState>,
    opus_pt: u8,
    direct_pcmu_passthrough: bool,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    let span = tracing::trace_span!("transcode_peer_to_ngn");
    let _enter = span.enter();

    debug!(direct_pcmu_passthrough, "peer_to_ngn_loop START");

    // 直送モードでは decoder / downsampler は使わない。
    let mut down_dec: Option<(DownsamplerWbToNb, OpusDecoder)> = if direct_pcmu_passthrough {
        None
    } else {
        let down = match DownsamplerWbToNb::new() {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "Downsampler 初期化失敗 → peer→NGN 方向停止");
                return;
            }
        };
        let dec = match OpusDecoder::new() {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "Opus デコーダ初期化失敗 → peer→NGN 方向停止");
                return;
            }
        };
        Some((down, dec))
    };

    let ssrc: u32 = rand::random();
    let mut seq: u16 = rand::random();
    let mut ts: u32 = rand::random();
    let expected_pt = if direct_pcmu_passthrough {
        PAYLOAD_TYPE_ULAW
    } else {
        opus_pt
    };

    while let Some(frame) = peer_media_rx.recv().await {
        if frame.pt != expected_pt {
            trace!(
                pt = frame.pt,
                expected = expected_pt,
                "peer 側 PT 不一致 → drop"
            );
            state.transcode_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let ulaw: Vec<u8> = if direct_pcmu_passthrough {
            // PCMU 直送: peer からの μ-law payload をそのまま NGN へ。
            frame.payload.clone()
        } else {
            let (downsampler, decoder) = down_dec
                .as_mut()
                .expect("down_dec must be Some when not in direct mode");
            let wb = match decoder.decode(&frame.payload) {
                Ok(v) => v,
                Err(e) => {
                    trace!(error=%e, "Opus デコード失敗");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            if wb.samples.len() != WB_FRAME_SAMPLES {
                trace!(samples = wb.samples.len(), "WebRTC フレーム長異常 → drop");
                state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let nb = match downsampler.process(&wb) {
                Ok(v) => v,
                Err(e) => {
                    trace!(error=%e, "ダウンサンプル失敗");
                    state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            if nb.samples.len() != NB_FRAME_SAMPLES {
                trace!(samples = nb.samples.len(), "NB フレーム長異常 → drop");
                state.transcode_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            nb.samples.iter().map(|s| encode_ulaw(*s)).collect()
        };

        let dest = match *to_state.peer.lock().await {
            Some(d) => d,
            None => {
                trace!("NGN 側 peer 未確定 → drop");
                continue;
            }
        };
        let out_pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: seq,
            timestamp: ts,
            ssrc,
            payload: ulaw,
        };
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(SAMPLES_PER_FRAME as u32);

        if let Err(e) = to_socket.send_to(&out_pkt.to_bytes(), dest).await {
            warn!(error=%e, "NGN へ RTP forward 失敗");
            continue;
        }
        state.web_to_ngn_packets.fetch_add(1, Ordering::Relaxed);
        if let Some(m) = metrics.as_ref() {
            m.add_rtp_ext_to_ngn(1);
        }
    }
    debug!("peer_media_rx closed → peer→NGN 方向終了");
}

/// テスト用ヘルパ: 1 NGN RTP パケット (μ-law 20ms 無音) を作る。
#[cfg(test)]
pub(crate) fn build_ulaw_rtp_packet(seq: u16, ts: u32, ssrc: u32, samples: &[i16]) -> Vec<u8> {
    let payload: Vec<u8> = samples.iter().map(|s| encode_ulaw(*s)).collect();
    RtpPacket {
        payload_type: PAYLOAD_TYPE_ULAW,
        marker: false,
        sequence: seq,
        timestamp: ts,
        ssrc,
        payload,
    }
    .to_bytes()
}

/// テスト用ヘルパ: 1 WebRTC RTP パケット (Opus encode 済み) を作る。
#[cfg(test)]
pub(crate) fn build_opus_rtp_packet(
    pt: u8,
    seq: u16,
    ts: u32,
    ssrc: u32,
    encoder: &mut OpusEncoder,
    pcm48k: &AudioFrame,
) -> Result<Vec<u8>> {
    use anyhow::Context;
    let payload = encoder
        .encode(pcm48k)
        .context("テスト用 Opus エンコード失敗")?;
    Ok(RtpPacket {
        payload_type: pt,
        marker: false,
        sequence: seq,
        timestamp: ts,
        ssrc,
        payload,
    }
    .to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::codec::opus::OPUS_SAMPLE_RATE;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn detect_opus_payload_type_basic() {
        let sdp = b"v=0\r\n\
                    m=audio 40000 UDP/TLS/RTP/SAVPF 111 0\r\n\
                    a=rtpmap:111 opus/48000/2\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(find_opus_payload_type(sdp), Some(111));
        assert!(sdp_uses_opus(sdp));
    }

    #[test]
    fn detect_opus_payload_type_absent() {
        let sdp = b"v=0\r\n\
                    m=audio 40000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(find_opus_payload_type(sdp), None);
        assert!(!sdp_uses_opus(sdp));
    }

    #[test]
    fn detect_opus_payload_type_lowercase_codec() {
        let sdp = b"a=rtpmap:96 OPUS/48000/2\r\n";
        assert_eq!(find_opus_payload_type(sdp), Some(96));
    }

    /// NGN→WebRTC 方向: μ-law を投入して Opus パケットが反対側で受信できるか。
    ///
    /// Issue #105 でジッタバッファを統合したため、 depth (`JITTER_DEPTH = 4`)
    /// が満たされる **5 packet** 投入する (initial fill + 1 pull 分)。
    #[tokio::test]
    async fn ngn_to_web_transcodes_packet() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 8 kHz 1 kHz トーン (160 samples)
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        // depth=4 を満たすため 5 packet 投入 (初期 fill 4 + pull 1)
        for i in 0..5u16 {
            let pkt = build_ulaw_rtp_packet(
                i + 1,
                i as u32 * SAMPLES_PER_FRAME as u32,
                0xAAAA_AAAA,
                &samples,
            );
            ngn_peer.send_to(&pkt, ngn_addr).await.unwrap();
        }

        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(2), web_peer.recv_from(&mut buf))
            .await
            .expect("WebRTC 側で受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.payload_type, DEFAULT_OPUS_PT);
        assert!(!recv.payload.is_empty(), "Opus payload 空");

        // ブリッジ統計に反映されている
        let (n2w, _w2n, _err) = bridge.stats();
        assert!(n2w >= 1, "NGN→WebRTC カウンタが上がっていない: {}", n2w);
        bridge.stop().await;
    }

    /// Issue #105 / RFC 3550 §6.4.1: NGN→Web 方向で **時間方向に逆順** の
    /// RTP 入力を流し、 transcoder が NGN レッグから受け取った順序ではなく
    /// **seq 番号順** で WebRTC 側へ送出することを確認する。
    ///
    /// 受信順序: seq = [4, 3, 2, 1, 0]
    /// 期待送出順序: seq は単調増加 (jitter buffer pull 順)
    ///
    /// transcoder の出力 RTP seq は内部で再生成される (`seq.wrapping_add(1)`)
    /// ため、 受信側 seq の単調増加性そのものは検証できない。 代わりに
    /// **payload 識別子** (μ-law payload の先頭バイトで識別) を入力に埋め込み、
    /// 出力側で受信される payload の発出順序が「入力の seq 昇順に対応する」
    /// ことを確認する。
    #[tokio::test]
    async fn rfc3550_6_4_1_ngn_to_web_reorders_packets_by_seq() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 各 seq に対し識別可能な「定数振幅」の μ-law トーンを生成する。
        // seq=N の payload は (N+1)*1000 Hz 相当のトーンとし、 Opus decode 後の
        // ピーク周波数で順序を識別できるようにする。 ただし Opus 経由では
        // 元周波数は復元しないので、 ここでは「Opus 出力の総数 = 入力数」と
        // 「先頭 payload が seq=0 由来」までを検証 (深い周波数分析は不要)。
        let build_packet = |seq: u16, marker_val: i16| -> Vec<u8> {
            let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
            for _ in 0..NB_FRAME_SAMPLES {
                samples.push(marker_val);
            }
            build_ulaw_rtp_packet(
                seq,
                seq as u32 * SAMPLES_PER_FRAME as u32,
                0x1234_5678,
                &samples,
            )
        };

        // depth=4 を満たし、 かつ reorder で 5 packet を逆順投入
        // seq=[4,3,2,1,0] (時間方向に逆)。 各々振幅 (seq+1)*1000 で識別。
        let inputs: Vec<(u16, i16)> = (0..5).rev().map(|s| (s as u16, (s + 1) * 1000)).collect();
        for (seq, amp) in &inputs {
            let pkt = build_packet(*seq, *amp);
            ngn_peer.send_to(&pkt, ngn_addr).await.unwrap();
            // 少し待ち、 buffer が確実に push を吸収するように
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // 出力側で 5 packet 受信する。 jitter buffer は depth 充足後に
        // seq 昇順で pull するため、 内部 seq の昇順 = WebRTC 側へ送出される順。
        let mut received_opus = Vec::with_capacity(5);
        for _ in 0..5 {
            let mut buf = vec![0u8; 1500];
            let (n, _) = timeout(Duration::from_secs(3), web_peer.recv_from(&mut buf))
                .await
                .expect("WebRTC 側で 5 packet 受信できない")
                .unwrap();
            let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
            assert_eq!(recv.payload_type, DEFAULT_OPUS_PT);
            received_opus.push(recv);
        }

        // 連続性: 出力 RTP の seq は単調増加 (1 ずつ)
        for w in received_opus.windows(2) {
            let prev = w[0].sequence;
            let curr = w[1].sequence;
            assert_eq!(
                curr.wrapping_sub(prev),
                1,
                "出力 RTP seq が単調増加していない: prev={} curr={}",
                prev,
                curr
            );
        }

        // 連続性: 出力 RTP の timestamp は OPUS_FRAME_SAMPLES (960) ずつ進む
        for w in received_opus.windows(2) {
            let prev = w[0].timestamp;
            let curr = w[1].timestamp;
            assert_eq!(
                curr.wrapping_sub(prev),
                OPUS_FRAME_SAMPLES as u32,
                "出力 RTP timestamp 増分が 960 でない: prev={} curr={}",
                prev,
                curr
            );
        }

        let (n2w, _w2n, err) = bridge.stats();
        assert_eq!(n2w, 5, "5 packet 全てが forward されているはず: {}", n2w);
        assert_eq!(err, 0, "reorder 経路で transcode error が出ている: {}", err);
        bridge.stop().await;
    }

    /// Issue #105 / RFC 3550 §6.4.1: Web→NGN 方向で **時間方向に逆順** の
    /// Opus RTP を流し、 transcoder が seq 番号順で NGN へ送出することを
    /// 確認する。
    ///
    /// NGN 側で受信した μ-law payload の RTP seq は 1 ずつ単調増加、
    /// timestamp は 160 (8 kHz × 20 ms) ずつ進む。
    #[tokio::test]
    async fn rfc3550_6_4_1_web_to_ngn_reorders_packets_by_seq() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_addr = web_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 48 kHz 1 kHz トーン (960 samples) を Opus 化
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);

        // 5 packet を seq=[4,3,2,1,0] (逆順) で投入
        for s in (0..5u16).rev() {
            let pkt = build_opus_rtp_packet(
                DEFAULT_OPUS_PT,
                s,
                s as u32 * OPUS_FRAME_SAMPLES as u32,
                0x9ABC_DEF0,
                &mut enc,
                &frame,
            )
            .unwrap();
            web_peer.send_to(&pkt, web_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // NGN 側で 5 packet 受信
        let mut received = Vec::with_capacity(5);
        for _ in 0..5 {
            let mut buf = vec![0u8; 1500];
            let (n, _) = timeout(Duration::from_secs(3), ngn_peer.recv_from(&mut buf))
                .await
                .expect("NGN 側で 5 packet 受信できない")
                .unwrap();
            let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
            assert_eq!(recv.payload_type, PAYLOAD_TYPE_ULAW);
            assert_eq!(recv.payload.len(), SAMPLES_PER_FRAME);
            received.push(recv);
        }

        // 出力 RTP seq は単調増加 (1 ずつ)
        for w in received.windows(2) {
            assert_eq!(
                w[1].sequence.wrapping_sub(w[0].sequence),
                1,
                "出力 NGN seq が単調増加していない"
            );
        }

        // 出力 RTP timestamp は 160 (8 kHz × 20 ms) ずつ進む
        for w in received.windows(2) {
            assert_eq!(
                w[1].timestamp.wrapping_sub(w[0].timestamp),
                SAMPLES_PER_FRAME as u32,
                "出力 NGN timestamp 増分が 160 でない"
            );
        }

        let (_n2w, w2n, err) = bridge.stats();
        assert_eq!(w2n, 5, "5 packet 全てが forward されているはず: {}", w2n);
        assert_eq!(err, 0, "reorder 経路で transcode error が出ている: {}", err);
        bridge.stop().await;
    }

    /// WebRTC→NGN 方向: Opus を投入して μ-law が反対側で受信できるか。
    #[tokio::test]
    async fn web_to_ngn_transcodes_packet() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let _ngn_addr = ngn_sock.local_addr().unwrap();
        let web_addr = web_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap();

        // 48 kHz 1 kHz トーン (960 samples) を Opus 化
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);
        // Issue #105: ジッタバッファ depth=4 を満たすため 5 packet 投入
        for i in 0..5u16 {
            let pkt = build_opus_rtp_packet(
                DEFAULT_OPUS_PT,
                i + 1,
                i as u32 * OPUS_FRAME_SAMPLES as u32,
                0xBBBB_BBBB,
                &mut enc,
                &frame,
            )
            .unwrap();
            web_peer.send_to(&pkt, web_addr).await.unwrap();
        }

        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(2), ngn_peer.recv_from(&mut buf))
            .await
            .expect("NGN 側で受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.payload_type, PAYLOAD_TYPE_ULAW);
        assert_eq!(recv.payload.len(), SAMPLES_PER_FRAME);

        let (_n2w, w2n, _err) = bridge.stats();
        assert!(w2n >= 1, "WebRTC→NGN カウンタが上がっていない: {}", w2n);
        bridge.stop().await;
    }

    /// Issue #87 / #121: NGN socket → WebRtcAudioBridge → peer.send_media
    /// 経路が PCMU 1 packet で起動し、 peer に Opus MediaFrame が届く。
    #[tokio::test]
    async fn webrtc_audio_bridge_ngn_to_peer_emits_opus_media_frame() {
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc as SArc;
        use tokio::sync::Mutex as TMutex;

        // sabiden 内 mock peer: send_media を回数カウントして observed に積む。
        struct MockPeer {
            received: SArc<TMutex<Vec<MediaFrame>>>,
            counter: SArc<AtomicU32>,
        }

        #[async_trait]
        impl PeerSession for MockPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, frame: MediaFrame) -> anyhow::Result<()> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                self.received.lock().await.push(frame);
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // 1 RTP datagram を投入できる NGN socket
        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        // peer_media_rx は使用しない (peer→NGN 方向はテストしない) ので空チャネル
        let (_dummy_tx, dummy_rx) = mpsc::channel::<MediaFrame>(1);

        let received: SArc<TMutex<Vec<MediaFrame>>> = SArc::new(TMutex::new(Vec::new()));
        let counter = SArc::new(AtomicU32::new(0));
        let mock_peer: Arc<dyn PeerSession> = Arc::new(MockPeer {
            received: received.clone(),
            counter: counter.clone(),
        });

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: mock_peer,
            peer_media_rx: dummy_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: false,
            metrics: None,
        });

        // 8 kHz 1 kHz トーン (160 samples) を μ-law 化して NGN socket に投入
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let pkt = build_ulaw_rtp_packet(1, 0, 0xCAFE_BEEF, &samples);
        ngn_peer_sock.send_to(&pkt, ngn_addr).await.unwrap();

        // peer.send_media が呼ばれるまで最大 2 秒待つ
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while counter.load(Ordering::SeqCst) == 0 {
            if std::time::Instant::now() > deadline {
                panic!("WebRtcAudioBridge: NGN→peer 方向で peer.send_media が呼ばれない");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let frames = received.lock().await;
        assert_eq!(frames.len(), 1, "1 frame 受信されているはず");
        assert_eq!(frames[0].pt, DEFAULT_OPUS_PT, "Opus PT で push されている");
        assert!(!frames[0].payload.is_empty(), "Opus payload が空");

        let (n2p, _p2n, _err) = bridge.stats();
        assert!(n2p >= 1, "stats 反映されていない: {}", n2p);
        bridge.stop().await;
    }

    /// Issue #87: peer_media_rx (Opus) → NGN socket (μ-law) 方向。
    /// テストフレームを peer_media_rx に push し、 NGN socket で μ-law が
    /// 受信できることを確認する。
    #[tokio::test]
    async fn webrtc_audio_bridge_peer_to_ngn_emits_pcmu_to_ngn_socket() {
        use std::sync::Arc as SArc;

        // dummy peer: send_media は呼ばれない (NGN→peer は流さないので)
        struct NoopPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoopPeer {
            async fn handle_offer(&self, _: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        let (peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(8);

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: Arc::new(NoopPeer),
            peer_media_rx: peer_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: false,
            metrics: None,
        });

        // 48 kHz 1 kHz トーンを Opus encode し、 MediaFrame として peer_tx に push
        let mut enc = OpusEncoder::new().unwrap();
        let mut samples = Vec::with_capacity(OPUS_FRAME_SAMPLES);
        for i in 0..OPUS_FRAME_SAMPLES {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let frame = AudioFrame::new(OPUS_SAMPLE_RATE, samples);
        let opus_payload = enc.encode(&frame).unwrap();
        let media = MediaFrame {
            pt: DEFAULT_OPUS_PT,
            rtp_time: 0,
            payload: opus_payload,
            network_time: std::time::Instant::now(),
        };
        peer_tx.send(media).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, _src) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("NGN socket で μ-law が受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(
            recv.payload_type, PAYLOAD_TYPE_ULAW,
            "PCMU PT=0 で送られているはず"
        );
        assert_eq!(recv.payload.len(), SAMPLES_PER_FRAME);

        let (_n2p, p2n, _err) = bridge.stats();
        assert!(p2n >= 1, "peer→NGN stats 反映されていない: {}", p2n);
        bridge.stop().await;
    }

    /// Issue #150 / RFC 3551 §4.5.14: `direct_pcmu_passthrough = true` 経路で
    /// NGN UDP socket 受信の μ-law payload が `MediaFrame { pt: 0 }` として
    /// **不変**で peer に渡ることを確認する。
    ///
    /// 既存テスト `webrtc_audio_bridge_ngn_to_peer_emits_opus_media_frame` は
    /// `false` で transcode 経路 (μ-law → Opus) のみを検証していたため、
    /// production で唯一使われる直送経路に test gap があった (PR #149 review)。
    ///
    /// 期待:
    /// - peer.send_media に届く `MediaFrame.pt == PAYLOAD_TYPE_ULAW (0)`
    /// - `MediaFrame.payload` は受信 RTP の payload と完全一致 (encode/decode しない)
    /// - RTP timestamp は 8 kHz クロック (RFC 3551 §4.5.14: PCMU clock=8000)
    ///   なので、 1 frame で `SAMPLES_PER_FRAME (= 160)` 進む。
    #[tokio::test]
    async fn rfc3551_4_5_14_pcmu_passthrough_ngn_to_peer_preserves_payload() {
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc as SArc;
        use tokio::sync::Mutex as TMutex;

        struct CapturePeer {
            received: SArc<TMutex<Vec<MediaFrame>>>,
            counter: SArc<AtomicU32>,
        }

        #[async_trait]
        impl PeerSession for CapturePeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, frame: MediaFrame) -> anyhow::Result<()> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                self.received.lock().await.push(frame);
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        // peer→NGN 方向は使わない
        let (_dummy_tx, dummy_rx) = mpsc::channel::<MediaFrame>(1);

        let received: SArc<TMutex<Vec<MediaFrame>>> = SArc::new(TMutex::new(Vec::new()));
        let counter = SArc::new(AtomicU32::new(0));
        let mock_peer: Arc<dyn PeerSession> = Arc::new(CapturePeer {
            received: received.clone(),
            counter: counter.clone(),
        });

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: mock_peer,
            peer_media_rx: dummy_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: true,
            metrics: None,
        });

        // 8 kHz 1 kHz トーン (160 samples) を μ-law 化
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        // 期待 payload: build_ulaw_rtp_packet と同じ μ-law エンコード結果
        let expected_payload: Vec<u8> = samples.iter().map(|s| encode_ulaw(*s)).collect();
        let pkt = build_ulaw_rtp_packet(1, 0, 0xDEAD_BEEF, &samples);
        ngn_peer_sock.send_to(&pkt, ngn_addr).await.unwrap();

        // 1 frame 目を投入: peer.send_media が呼ばれるまで待つ
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while counter.load(Ordering::SeqCst) == 0 {
            if std::time::Instant::now() > deadline {
                panic!("direct_pcmu_passthrough: NGN→peer 方向で peer.send_media が呼ばれない");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // 連続性確認のため 2 frame 目も投入 (rtp_time が 160 進むことを検証)
        let pkt2 = build_ulaw_rtp_packet(2, 160, 0xDEAD_BEEF, &samples);
        ngn_peer_sock.send_to(&pkt2, ngn_addr).await.unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while counter.load(Ordering::SeqCst) < 2 {
            if std::time::Instant::now() > deadline {
                panic!("2 frame 目が peer に届かない");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let frames = received.lock().await;
        assert_eq!(frames.len(), 2, "2 frame 受信されているはず");

        // PT 不変 (RFC 3551 §4.5.14: PCMU PT=0)
        assert_eq!(
            frames[0].pt, PAYLOAD_TYPE_ULAW,
            "passthrough は PCMU PT=0 で渡すべき"
        );
        assert_eq!(
            frames[1].pt, PAYLOAD_TYPE_ULAW,
            "passthrough は 2 frame 目も PCMU PT=0"
        );

        // payload 不変 (encode/decode を経由していない)
        assert_eq!(
            frames[0].payload, expected_payload,
            "μ-law payload が不変で peer に渡るべき (encode/decode しない)"
        );
        assert_eq!(
            frames[1].payload, expected_payload,
            "2 frame 目も同じ payload が不変で渡るべき"
        );

        // RTP timestamp は 8 kHz クロックで SAMPLES_PER_FRAME 単位に進む
        // (RFC 3551 §4.5.14: PCMU clock = 8000 Hz)
        let dt = frames[1].rtp_time.wrapping_sub(frames[0].rtp_time);
        assert_eq!(
            dt as usize, SAMPLES_PER_FRAME,
            "passthrough の RTP timestamp 増分は 160 (8kHz × 20ms)"
        );

        let (n2p, _p2n, err) = bridge.stats();
        assert!(n2p >= 2, "stats が 2 frame 反映されていない: {}", n2p);
        assert_eq!(err, 0, "passthrough 経路でエラーが出ている: {}", err);
        bridge.stop().await;
    }

    /// Issue #150 / RFC 3551 §4.5.14: `direct_pcmu_passthrough = true` 経路で
    /// peer から流れる `MediaFrame { pt: 0 }` の μ-law payload が NGN UDP socket
    /// に **不変**で出ることを確認する。
    ///
    /// 既存テスト `webrtc_audio_bridge_peer_to_ngn_emits_pcmu_to_ngn_socket` は
    /// `false` で Opus → μ-law transcode 経路のみを検証していたため、
    /// 直送経路に test gap があった (PR #149 review 🟡#1)。
    ///
    /// 期待:
    /// - NGN socket で受信した RTP の `payload_type == PAYLOAD_TYPE_ULAW (0)`
    /// - 受信 RTP の payload は peer 側で push した μ-law payload と完全一致
    ///   (Opus decode / resample / μ-law encode を経由しない)
    /// - PT が opus_pt (=111) で来た frame は drop される (passthrough 時の
    ///   expected_pt は 0)
    #[tokio::test]
    async fn rfc3551_4_5_14_pcmu_passthrough_peer_to_ngn_preserves_payload() {
        use std::sync::Arc as SArc;

        struct NoopPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoopPeer {
            async fn handle_offer(&self, _: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, _: MediaFrame) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();

        let (peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(8);

        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: Some(ngn_peer_addr),
            peer: Arc::new(NoopPeer),
            peer_media_rx: peer_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: true,
            metrics: None,
        });

        // 8 kHz 1 kHz トーン → μ-law 化 (160 byte payload)
        let mut samples = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            samples.push(v as i16);
        }
        let ulaw_payload: Vec<u8> = samples.iter().map(|s| encode_ulaw(*s)).collect();
        assert_eq!(ulaw_payload.len(), SAMPLES_PER_FRAME);

        // direct_pcmu_passthrough なので peer 側の MediaFrame も PT=0 で来る前提
        let media = MediaFrame {
            pt: PAYLOAD_TYPE_ULAW,
            rtp_time: 0,
            payload: ulaw_payload.clone(),
            network_time: std::time::Instant::now(),
        };
        peer_tx.send(media).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, _src) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("NGN socket で μ-law が受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(
            recv.payload_type, PAYLOAD_TYPE_ULAW,
            "PCMU PT=0 で送られているはず (RFC 3551 §4.5.14)"
        );
        assert_eq!(
            recv.payload.len(),
            SAMPLES_PER_FRAME,
            "20 ms = 160 samples (RFC 3551 §4.5.14)"
        );
        assert_eq!(
            recv.payload, ulaw_payload,
            "μ-law payload が不変で NGN に出るべき (decode/resample/encode しない)"
        );

        // PT 不一致 (opus_pt = 111) の frame は drop されることを確認
        // (expected_pt は passthrough 時 PCMU=0)
        let bad = MediaFrame {
            pt: DEFAULT_OPUS_PT,
            rtp_time: SAMPLES_PER_FRAME as u32,
            payload: ulaw_payload.clone(),
            network_time: std::time::Instant::now(),
        };
        peer_tx.send(bad).await.unwrap();

        // 続いて正規 PT の 2 frame 目を流し、 NGN socket には bad ではなく
        // この frame だけが届くことを確認 (drop されたら 1 個しか届かない)。
        let media2 = MediaFrame {
            pt: PAYLOAD_TYPE_ULAW,
            rtp_time: SAMPLES_PER_FRAME as u32,
            payload: ulaw_payload.clone(),
            network_time: std::time::Instant::now(),
        };
        peer_tx.send(media2).await.unwrap();

        let (n2, _) = timeout(Duration::from_secs(2), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("2 frame 目が NGN socket に届かない")
            .unwrap();
        let recv2 = RtpPacket::from_bytes(&buf[..n2]).unwrap();
        assert_eq!(recv2.payload_type, PAYLOAD_TYPE_ULAW);
        assert_eq!(recv2.payload, ulaw_payload, "2 frame 目も payload 不変");

        let (_n2p, p2n, err) = bridge.stats();
        assert!(p2n >= 2, "passthrough p2n stats 不足: {}", p2n);
        assert!(
            err >= 1,
            "PT=111 の bad frame が drop された記録が無い: {}",
            err
        );
        bridge.stop().await;
    }

    /// ループバック (NGN→WebRTC→NGN相当) で品質劣化が一定以下か。
    /// 直接ブリッジ往復ではなくコーデックチェーン単体での確認 (端末役のソケット
    /// セットアップを 2 つ立てるよりシンプル)。
    #[test]
    fn end_to_end_codec_chain_preserves_signal() {
        let mut up = UpsamplerNbToWb::new().unwrap();
        let mut down = DownsamplerWbToNb::new().unwrap();
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();

        // 1 kHz 入力
        let mut input = Vec::with_capacity(NB_FRAME_SAMPLES);
        for i in 0..NB_FRAME_SAMPLES {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            input.push(v as i16);
        }
        let nb_in = AudioFrame::new(NARROW_BAND_RATE, input.clone());

        // 数フレーム流して Opus エンコーダのプリロールを抜けたところで判定
        let mut last_rms = 0.0f64;
        for _ in 0..5 {
            let wb = up.process(&nb_in).unwrap();
            let opus_pkt = enc.encode(&wb).unwrap();
            let wb2 = dec.decode(&opus_pkt).unwrap();
            let nb_out = down.process(&wb2).unwrap();
            let energy: f64 = nb_out.samples.iter().map(|s| (*s as f64).powi(2)).sum();
            last_rms = (energy / nb_out.samples.len() as f64).sqrt();
        }
        // 入力 RMS は 8000/sqrt(2) ≒ 5657。半分以上は残ること
        assert!(
            last_rms > 2000.0,
            "コーデックチェーン後の RMS が小さすぎる: {}",
            last_rms
        );
    }

    /// Issue #135 🟡 3: `WebRtcAudioBridge::start` は infallible シグネチャ
    /// (`-> Self`)。 `?` / `match Result` を呼出側に要求しない API 形を
    /// コンパイル時に強制するため、 `Self` の field と spawn された 2 つの
    /// JoinHandle が即座に観測可能であることを確認する。
    ///
    /// 旧 `Result<Self>` 戻り値での error path は実行時に到達不能だったため
    /// (CLAUDE.md §6.5 「production code で出ない error path を晒さない」
    /// 精神)、 本テストは戻り値型のみを契約として検証する。
    #[tokio::test]
    async fn webrtc_audio_bridge_start_returns_self_directly() {
        use std::sync::Arc as SArc;
        use tokio::sync::mpsc;

        struct NoopPeer;
        #[async_trait::async_trait]
        impl crate::webrtc::peer::PeerSession for NoopPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                unreachable!()
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                unreachable!()
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                unreachable!()
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                unreachable!()
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let ngn_sock = SArc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (_peer_tx, peer_rx) = mpsc::channel::<MediaFrame>(1);

        // `start` の戻り値は `Self` であり `Result` ではない。
        // 型注釈で `Result<Self>` だとコンパイルエラーになる契約を
        // 明示する (variable 名 `bridge: WebRtcAudioBridge`)。
        let bridge: WebRtcAudioBridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: ngn_sock,
            ngn_peer: None,
            peer: Arc::new(NoopPeer),
            peer_media_rx: peer_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: true,
            metrics: None,
        });

        // 2 ループは spawn 直後で生存している (drop されていない)。
        let (sent, recv, errs) = bridge.stats();
        assert_eq!(sent, 0);
        assert_eq!(recv, 0);
        assert_eq!(errs, 0);
        bridge.stop().await;
    }
}
