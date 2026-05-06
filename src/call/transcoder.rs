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

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::observability::Metrics;
use crate::rtp::codec::opus::{OpusDecoder, OpusEncoder, OPUS_FRAME_SAMPLES};
use crate::rtp::codec::resample::{
    DownsamplerWbToNb, UpsamplerNbToWb, NARROW_BAND_RATE, NB_FRAME_SAMPLES, WB_FRAME_SAMPLES,
};
use crate::rtp::codec::AudioFrame;
use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW, SAMPLES_PER_FRAME};
use crate::rtp::{decode_ulaw, encode_ulaw, set_rtp_dscp};

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
            web_socket,
            ngn_socket,
            web_state,
            ngn_state,
            state.clone(),
            opus_payload_type,
            metrics,
        ));

        Ok(Self {
            ngn_to_web: Some(ngn_to_web),
            web_to_ngn: Some(web_to_ngn),
            state,
        })
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

    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match from_socket.recv_from(&mut buf).await {
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

/// WebRTC (Opus 48k) → NGN (μ-law 8k) 方向の 1 ループ。
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

    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match from_socket.recv_from(&mut buf).await {
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
        let pkt = build_ulaw_rtp_packet(1, 0, 0xAAAA_AAAA, &samples);
        ngn_peer.send_to(&pkt, ngn_addr).await.unwrap();

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
        let pkt =
            build_opus_rtp_packet(DEFAULT_OPUS_PT, 1, 0, 0xBBBB_BBBB, &mut enc, &frame).unwrap();
        web_peer.send_to(&pkt, web_addr).await.unwrap();

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
}
