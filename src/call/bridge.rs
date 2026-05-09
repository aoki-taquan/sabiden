//! RTP リレー (Phase 1)
//!
//! NGN レッグと内線レッグの 2 つの UDP ソケットを繋ぎ、受信した RTP/RTCP
//! パケットをそのまま反対側へ転送する。両側とも G.711 μ-law (PT=0) を
//! 想定するためトランスコードは行わない (Phase 3 で対応)。
//!
//! 設計上の注意:
//! - NGN ⇔ 内線の両側とも `tokio::net::UdpSocket` を別個に bind し、
//!   sabiden が「RTP プロキシ」として両方のピアに対面する。
//! - 受信元 (`peer`) は最初の RTP 到着で確定する (RFC 3550 §5 のように
//!   late binding する。SDP の宣言ポートと実際の送信元ポートが異なる
//!   ケースに頑健)。
//! - DSCP は `rtp::set_rtp_dscp` で 32 を設定する (NGN 要件)。
//!
//! 1 通話 1 [`RtpBridge`] が 2 つのソケット ループを spawn し、`stop()`
//! を呼ぶか `Drop` で停止する。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use super::transcoder::TranscodingBridge;
use crate::observability::Metrics;
use crate::rtp::set_rtp_dscp;

/// NGN レッグと内線レッグの SDP に応じて、純リレーまたはトランスコードの
/// どちらかで動く統一ブリッジハンドル (Issue #29)。
///
/// `RtpBridge` (両側 PCMU 想定) と `TranscodingBridge` (Opus↔PCMU) を
/// 1 つの型に閉じ込め、`CallManager::attach_bridge` 経由で 1 通話に
/// 1 つだけ持たせるための薄いアダプタ。
///
/// # 既存パスの保持
///
/// - 両側 PCMU の場合は必ず [`MediaBridge::Relay`] を選び、`RtpBridge` の
///   ホットパスをそのまま使う (= 既存の Linphone↔NGN / 117 時報通話の
///   挙動と完全一致)。
/// - WebRTC レッグ (Opus) ↔ NGN レッグ (PCMU) のときのみ
///   [`MediaBridge::Transcode`] を選び、Opus encode/decode + 8k↔48k
///   リサンプルを噛ませる。
pub enum MediaBridge {
    /// 純リレー (G.711 μ-law をそのまま転送)。
    Relay(RtpBridge),
    /// Opus ⇔ G.711 トランスコード (RFC 7587 ↔ RFC 3551)。
    Transcode(TranscodingBridge),
}

impl MediaBridge {
    /// 両ループを停止する。`RtpBridge::stop` / `TranscodingBridge::stop`
    /// と同等。
    pub async fn stop(self) {
        match self {
            MediaBridge::Relay(b) => b.stop().await,
            MediaBridge::Transcode(b) => b.stop().await,
        }
    }

    /// 観測用統計。`(NGN→ext, ext→NGN)` のパケット数を返す。
    /// トランスコード時は `(NGN→Web, Web→NGN)` を同じ意味で返す
    /// (B2BUA 観点では NGN レッグ⇔ 内線レッグ の単純な 2 方向)。
    pub fn stats(&self) -> (u64, u64) {
        match self {
            MediaBridge::Relay(b) => b.stats(),
            MediaBridge::Transcode(b) => {
                let (n2w, w2n, _err) = b.stats();
                (n2w, w2n)
            }
        }
    }

    /// Issue #69: NGN レッグ socket から NGN ピア宛に任意 RTP datagram を 1 つ
    /// 注入する。SIP INFO で受け取った DTMF を RFC 4733 telephone-event RTP
    /// packet に変換して NGN レッグへ流す用途。
    ///
    /// `MediaBridge::Relay` (両側 PCMU) でも `MediaBridge::Transcode` (Opus⇔PCMU)
    /// でも同じ NGN socket / NGN peer を使うので、変種に関わらず同一インタフェース
    /// で扱える。
    pub async fn send_to_ngn(&self, datagram: &[u8]) -> Result<()> {
        match self {
            MediaBridge::Relay(b) => b.send_to_ngn(datagram).await,
            MediaBridge::Transcode(b) => b.send_to_ngn(datagram).await,
        }
    }

    /// Issue #69: 内線レッグ socket から内線ピア宛に任意 RTP datagram を 1 つ
    /// 注入する (NGN→内線 INFO 経路の placeholder)。
    pub async fn send_to_ext(&self, datagram: &[u8]) -> Result<()> {
        match self {
            MediaBridge::Relay(b) => b.send_to_ext(datagram).await,
            MediaBridge::Transcode(b) => b.send_to_web(datagram).await,
        }
    }
}

impl From<RtpBridge> for MediaBridge {
    fn from(b: RtpBridge) -> Self {
        MediaBridge::Relay(b)
    }
}

impl From<TranscodingBridge> for MediaBridge {
    fn from(b: TranscodingBridge) -> Self {
        MediaBridge::Transcode(b)
    }
}

/// 1 つのリレー方向 (片側ソケット → 反対側) を表す共有状態。
///
/// `peer` は最初の受信時に確定する (`OnceCell` 的な使い方)。SDP から
/// 宣言された値を初期値として渡しても良いし、空のままでも late-binding
/// で動く。
#[derive(Default)]
struct LegState {
    peer: Mutex<Option<SocketAddr>>,
}

/// 1 通話分の RTP ブリッジ。
///
/// 2 ソケット (NGN 側 / 内線側) を所有し、それぞれの受信ループを
/// 並列に走らせる。どちらかのループが終了する (= ソケットが閉じる)
/// と他方も `abort` する。
pub struct RtpBridge {
    ngn_handle: Option<JoinHandle<()>>,
    ext_handle: Option<JoinHandle<()>>,
    /// 内側状態: 統計・peer など。`stop` 後でもアクセスできるよう保持する。
    state: Arc<BridgeState>,
    /// NGN 側 socket / 学習済 peer。DTMF 注入 (Issue #69) で使う。
    ngn_socket: Arc<UdpSocket>,
    ngn_state: Arc<LegState>,
    /// 内線側 socket / 学習済 peer。NGN→内線 INFO 経路の DTMF 注入で使う。
    ext_socket: Arc<UdpSocket>,
    ext_state: Arc<LegState>,
}

#[derive(Default)]
struct BridgeState {
    forwarded_to_ext: std::sync::atomic::AtomicU64,
    forwarded_to_ngn: std::sync::atomic::AtomicU64,
}

/// ブリッジの生成パラメータ。
pub struct BridgeConfig {
    /// NGN 側 RTP を受け取る・送り返すソケット。
    pub ngn_socket: Arc<UdpSocket>,
    /// 内線側 RTP を受け取る・送り返すソケット。
    pub ext_socket: Arc<UdpSocket>,
    /// SDP から判明している NGN 側 RTP ピア (`Option`: 不明なら最初の受信で確定)。
    pub ngn_peer: Option<SocketAddr>,
    /// SDP から判明している内線側 RTP ピア。
    pub ext_peer: Option<SocketAddr>,
    /// プロセス全体で共有する観測カウンタ。`None` なら計測なし。
    pub metrics: Option<Arc<Metrics>>,
}

impl RtpBridge {
    /// ブリッジを起動する。即座に両側で受信ループが動き出す。
    pub fn start(cfg: BridgeConfig) -> Result<Self> {
        let BridgeConfig {
            ngn_socket,
            ext_socket,
            ngn_peer,
            ext_peer,
            metrics,
        } = cfg;

        // NGN 要件: RTP ソケットに DSCP 32 を立てる。失敗しても致命的ではない
        // (Linux 以外ではオフ) ので警告のみ。
        if let Err(e) = set_rtp_dscp(&ngn_socket, 32) {
            warn!("NGN RTP socket DSCP 設定失敗 (続行): {}", e);
        }
        if let Err(e) = set_rtp_dscp(&ext_socket, 32) {
            warn!("内線 RTP socket DSCP 設定失敗 (続行): {}", e);
        }

        let ngn_state = Arc::new(LegState {
            peer: Mutex::new(ngn_peer),
        });
        let ext_state = Arc::new(LegState {
            peer: Mutex::new(ext_peer),
        });
        let state = Arc::new(BridgeState::default());

        // NGN -> 内線 方向: NGN socket から受信し、ext socket で ext peer 宛に送る
        let ngn_handle = tokio::spawn(forward_loop(
            "NGN→ext",
            ngn_socket.clone(),
            ext_socket.clone(),
            ngn_state.clone(), // 受信側 (peer 確定対象)
            ext_state.clone(), // 送信先
            state.clone(),
            true,
            metrics.clone(),
        ));

        // 内線 -> NGN 方向
        let ext_handle = tokio::spawn(forward_loop(
            "ext→NGN",
            ext_socket.clone(),
            ngn_socket.clone(),
            ext_state.clone(),
            ngn_state.clone(),
            state.clone(),
            false,
            metrics,
        ));

        Ok(Self {
            ngn_handle: Some(ngn_handle),
            ext_handle: Some(ext_handle),
            state,
            ngn_socket,
            ngn_state,
            ext_socket,
            ext_state,
        })
    }

    /// NGN 側ソケットから NGN ピアへ任意の RTP datagram を 1 つ送る。
    ///
    /// Issue #69 (DTMF interop): 内線が SIP INFO で送ってきた DTMF を
    /// RFC 4733 telephone-event RTP packet に変換して NGN レッグに乗せる用途。
    /// NGN ピアが学習されていない (= まだ RTP を受信していない) 場合は
    /// `Err` を返し、呼び出し側でバッファリング or drop する。
    ///
    /// 通常の音声 RTP は `forward_loop` がそのまま転送するので本メソッド
    /// 経由で送る必要はない。本メソッドは「外部から bridge に新規 RTP を
    /// 注入する」用途専用。
    pub async fn send_to_ngn(&self, datagram: &[u8]) -> Result<()> {
        let dest = { *self.ngn_state.peer.lock().await };
        let dest = dest.ok_or_else(|| anyhow::anyhow!("NGN peer 未確定"))?;
        self.ngn_socket.send_to(datagram, dest).await?;
        Ok(())
    }

    /// 内線側ソケットから内線ピアへ任意の RTP datagram を 1 つ送る。
    ///
    /// Issue #69: NGN レッグから来た RFC 4733 telephone-event を、内線 UA が
    /// INFO 派の場合に SIP INFO へ変換するのではなく、PT=101 をそのまま
    /// 内線レッグに流すケースで使う (本実装では bridge がそもそも PT=101 を
    /// 透過するため、本メソッドは将来 NGN→内線 で INFO→RFC 4733 変換が
    /// 必要になった時用の placeholder)。
    pub async fn send_to_ext(&self, datagram: &[u8]) -> Result<()> {
        let dest = { *self.ext_state.peer.lock().await };
        let dest = dest.ok_or_else(|| anyhow::anyhow!("ext peer 未確定"))?;
        self.ext_socket.send_to(datagram, dest).await?;
        Ok(())
    }

    /// 両ループを停止して JoinHandle を待ち合わせる。
    pub async fn stop(mut self) {
        if let Some(h) = self.ngn_handle.take() {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self.ext_handle.take() {
            h.abort();
            let _ = h.await;
        }
    }

    /// 統計: NGN→内線 / 内線→NGN の転送パケット数。
    pub fn stats(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.state.forwarded_to_ext.load(Ordering::Relaxed),
            self.state.forwarded_to_ngn.load(Ordering::Relaxed),
        )
    }
}

impl Drop for RtpBridge {
    fn drop(&mut self) {
        if let Some(h) = self.ngn_handle.take() {
            h.abort();
        }
        if let Some(h) = self.ext_handle.take() {
            h.abort();
        }
    }
}

/// 1 方向の受信→転送ループ。
///
/// `from_state.peer` は受信したパケットの送信元で update され、`to_state.peer`
/// に書き込み先を求める。`to_state.peer` が None なら destination 未知のため
/// 黙って drop する (相手側ループで peer が判明し次第転送が始まる)。
#[allow(clippy::too_many_arguments)]
async fn forward_loop(
    direction: &'static str,
    from_socket: Arc<UdpSocket>,
    to_socket: Arc<UdpSocket>,
    from_state: Arc<LegState>,
    to_state: Arc<LegState>,
    state: Arc<BridgeState>,
    increment_to_ext: bool,
    metrics: Option<Arc<Metrics>>,
) {
    use std::sync::atomic::Ordering;
    // RTP ホットパスは hot loop だが、`tracing::Span` の発行は最初の 1 回のみ。
    let span = tracing::trace_span!("rtp_bridge", direction);
    let _enter = span.enter();
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match from_socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!(direction, error=%e, "RTP recv エラー → ループ終了");
                return;
            }
        };
        // 送信元を学習: 既に SDP から既知の peer が登録されていてもポート
        // が違う可能性がある (NAT 後ろでなくても UA 実装差で起こる)。
        // 受信元が変わったら更新する。
        {
            let mut peer = from_state.peer.lock().await;
            if peer.as_ref() != Some(&src) {
                trace!(direction, ?src, "RTP 送信元学習");
                *peer = Some(src);
            }
        }

        let dest = { *to_state.peer.lock().await };
        let Some(dest) = dest else {
            trace!(direction, "対向 peer 未確定 → drop");
            continue;
        };

        if let Err(e) = to_socket.send_to(&buf[..n], dest).await {
            warn!(direction, error=%e, "RTP forward 失敗");
            continue;
        }
        if increment_to_ext {
            state.forwarded_to_ext.fetch_add(1, Ordering::Relaxed);
            if let Some(m) = metrics.as_ref() {
                m.add_rtp_ngn_to_ext(1);
            }
        } else {
            state.forwarded_to_ngn.fetch_add(1, Ordering::Relaxed);
            if let Some(m) = metrics.as_ref() {
                m.add_rtp_ext_to_ngn(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
    use std::time::Duration;
    use tokio::time::timeout;

    /// 双方向の RTP リレーが NGN ⇔ 内線で機能することを確認する。
    /// 模擬 NGN ピアと模擬内線ピアの 2 ソケットを bind し、ブリッジを
    /// 起動して片方から送ったパケットがもう片方で受信できるかを見る。
    #[tokio::test]
    async fn bridges_rtp_in_both_directions() {
        // ブリッジ自身が持つ NGN 側 / 内線側 ソケット
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ext_addr = ext_sock.local_addr().unwrap();

        // 模擬ピア (NGN 側エンドポイント役 と 内線 UA 役)
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();
        let ext_peer_addr = ext_peer_sock.local_addr().unwrap();

        let bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ngn_sock,
            ext_socket: ext_sock,
            ngn_peer: Some(ngn_peer_addr),
            ext_peer: Some(ext_peer_addr),
            metrics: None,
        })
        .unwrap();

        // NGN ピア → ブリッジ NGN 側 → 内線ピア
        let pkt1 = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 160,
            ssrc: 0x1111_1111,
            payload: vec![0xff; 160],
        }
        .to_bytes();
        ngn_peer_sock.send_to(&pkt1, ngn_addr).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let (n, _src) = timeout(Duration::from_secs(1), ext_peer_sock.recv_from(&mut buf))
            .await
            .expect("内線側で受信できない")
            .unwrap();
        let recv1 = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv1.ssrc, 0x1111_1111);

        // 内線ピア → ブリッジ内線側 → NGN ピア
        let pkt2 = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 2,
            timestamp: 320,
            ssrc: 0x2222_2222,
            payload: vec![0xee; 160],
        }
        .to_bytes();
        ext_peer_sock.send_to(&pkt2, ext_addr).await.unwrap();
        let (n, _src) = timeout(Duration::from_secs(1), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("NGN 側で受信できない")
            .unwrap();
        let recv2 = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv2.ssrc, 0x2222_2222);

        let (to_ext, to_ngn) = bridge.stats();
        assert!(to_ext >= 1 && to_ngn >= 1);
        bridge.stop().await;
    }

    /// Issue #66: PCMU (RFC 3551 PT 0) パケットを双方向で 5 個ずつ流して、
    /// 1 個も落とさず NGN ⇔ 内線で順序通りに届くことを smoke test する。
    /// peer は SDP で既知 (`Some(...)`) のシナリオ — Issue #66 の本流経路で
    /// `prepare_outbound_bridge` / `finalize_outbound_bridge` が SDP の
    /// `c=`/`m=audio` から peer を抽出してブリッジに渡す前提と一致する。
    #[tokio::test]
    async fn rtp_bridge_forwards_pcmu_packets_in_both_directions() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ext_addr = ext_sock.local_addr().unwrap();

        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();
        let ext_peer_addr = ext_peer_sock.local_addr().unwrap();

        let bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ngn_sock,
            ext_socket: ext_sock,
            ngn_peer: Some(ngn_peer_addr),
            ext_peer: Some(ext_peer_addr),
            metrics: None,
        })
        .unwrap();

        const N: u16 = 5;

        // NGN → ext: 5 パケット (G.711 μ-law / PT=0、20ms フレーム = 160 sample)
        for i in 0..N {
            let pkt = RtpPacket {
                payload_type: PAYLOAD_TYPE_ULAW,
                marker: false,
                sequence: 100 + i,
                timestamp: 160 * u32::from(i),
                ssrc: 0xAAAA_0000,
                payload: vec![0xff; 160],
            }
            .to_bytes();
            ngn_peer_sock.send_to(&pkt, ngn_addr).await.unwrap();
        }
        let mut buf = vec![0u8; 1500];
        for i in 0..N {
            let (n, _src) = timeout(Duration::from_secs(1), ext_peer_sock.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("NGN→ext PCMU #{i} を受信できない"))
                .unwrap();
            let pkt = RtpPacket::from_bytes(&buf[..n]).unwrap();
            assert_eq!(pkt.payload_type, PAYLOAD_TYPE_ULAW);
            assert_eq!(pkt.sequence, 100 + i);
            assert_eq!(pkt.ssrc, 0xAAAA_0000);
        }

        // ext → NGN: 5 パケット
        for i in 0..N {
            let pkt = RtpPacket {
                payload_type: PAYLOAD_TYPE_ULAW,
                marker: false,
                sequence: 200 + i,
                timestamp: 160 * u32::from(i),
                ssrc: 0xBBBB_0000,
                payload: vec![0xee; 160],
            }
            .to_bytes();
            ext_peer_sock.send_to(&pkt, ext_addr).await.unwrap();
        }
        for i in 0..N {
            let (n, _src) = timeout(Duration::from_secs(1), ngn_peer_sock.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("ext→NGN PCMU #{i} を受信できない"))
                .unwrap();
            let pkt = RtpPacket::from_bytes(&buf[..n]).unwrap();
            assert_eq!(pkt.payload_type, PAYLOAD_TYPE_ULAW);
            assert_eq!(pkt.sequence, 200 + i);
            assert_eq!(pkt.ssrc, 0xBBBB_0000);
        }

        let (to_ext, to_ngn) = bridge.stats();
        assert_eq!(to_ext, u64::from(N), "NGN→ext のリレー総数が一致しない");
        assert_eq!(to_ngn, u64::from(N), "ext→NGN のリレー総数が一致しない");

        bridge.stop().await;
    }

    /// Issue #29: MediaBridge::Relay で wrap した RtpBridge が PCMU パケットを
    /// 双方向に流す (= 既存パスをそのまま使えること)。
    #[tokio::test]
    async fn media_bridge_relay_variant_forwards_pcmu_unchanged() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();
        let ext_peer_addr = ext_peer_sock.local_addr().unwrap();

        let bridge: MediaBridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ngn_sock,
            ext_socket: ext_sock,
            ngn_peer: Some(ngn_peer_addr),
            ext_peer: Some(ext_peer_addr),
            metrics: None,
        })
        .unwrap()
        .into();

        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 7,
            timestamp: 160,
            ssrc: 0xC0DE_FACE,
            payload: vec![0x55; 160],
        }
        .to_bytes();
        ngn_peer_sock.send_to(&pkt, ngn_addr).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(1), ext_peer_sock.recv_from(&mut buf))
            .await
            .expect("Relay ブランチでもパケットが届くべき")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.payload_type, PAYLOAD_TYPE_ULAW);
        assert_eq!(recv.ssrc, 0xC0DE_FACE);
        let (to_ext, _to_ngn) = bridge.stats();
        assert!(to_ext >= 1);
        bridge.stop().await;
    }

    /// Issue #29: MediaBridge::Transcode が NGN→ext (μ-law→Opus) と
    /// ext→NGN (Opus→μ-law) の両方向を 1 オブジェクトで stop できる。
    /// 入出力 PT は SDP の rtpmap で指定された値を使う。
    #[tokio::test]
    async fn media_bridge_transcode_variant_handles_both_directions() {
        use crate::call::transcoder::{
            build_opus_rtp_packet, build_ulaw_rtp_packet, TranscodeConfig, TranscodingBridge,
            DEFAULT_OPUS_PT,
        };
        use crate::rtp::codec::opus::{OpusEncoder, OPUS_FRAME_SAMPLES, OPUS_SAMPLE_RATE};
        use crate::rtp::codec::resample::{NARROW_BAND_RATE, NB_FRAME_SAMPLES};
        use crate::rtp::codec::AudioFrame;
        use crate::rtp::packet::SAMPLES_PER_FRAME;

        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let web_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let web_addr = web_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let web_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer.local_addr().unwrap();
        let web_peer_addr = web_peer.local_addr().unwrap();

        let bridge: MediaBridge = TranscodingBridge::start(TranscodeConfig {
            ngn_socket: ngn_sock,
            web_socket: web_sock,
            ngn_peer: Some(ngn_peer_addr),
            web_peer: Some(web_peer_addr),
            opus_payload_type: DEFAULT_OPUS_PT,
            metrics: None,
        })
        .unwrap()
        .into();

        // NGN→WebRTC: μ-law (160 サンプル無音) を投入 → Opus が出てくる。
        let silence_nb = vec![0i16; NB_FRAME_SAMPLES];
        let pkt_ulaw = build_ulaw_rtp_packet(1, 0, 0xAAAA_AAAA, &silence_nb);
        ngn_peer.send_to(&pkt_ulaw, ngn_addr).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(2), web_peer.recv_from(&mut buf))
            .await
            .expect("Transcode 経由で Opus が届かない")
            .unwrap();
        let received_opus = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(received_opus.payload_type, DEFAULT_OPUS_PT);
        assert!(!received_opus.payload.is_empty());

        // WebRTC→NGN: Opus (48k 無音) を投入 → μ-law 160 サンプルが出てくる。
        let mut enc = OpusEncoder::new().unwrap();
        let silence_wb = AudioFrame::new(OPUS_SAMPLE_RATE, vec![0i16; OPUS_FRAME_SAMPLES]);
        let pkt_opus =
            build_opus_rtp_packet(DEFAULT_OPUS_PT, 1, 0, 0xBBBB_BBBB, &mut enc, &silence_wb)
                .unwrap();
        // RTP のホットパスの順序保証のため、念のためサンプルレート明示
        let _ = NARROW_BAND_RATE;
        web_peer.send_to(&pkt_opus, web_addr).await.unwrap();
        let (n2, _) = timeout(Duration::from_secs(2), ngn_peer.recv_from(&mut buf))
            .await
            .expect("Transcode 経由で μ-law が届かない")
            .unwrap();
        let received_ulaw = RtpPacket::from_bytes(&buf[..n2]).unwrap();
        assert_eq!(received_ulaw.payload_type, PAYLOAD_TYPE_ULAW);
        assert_eq!(received_ulaw.payload.len(), SAMPLES_PER_FRAME);

        // MediaBridge 経由でも統計が読めること。
        let (to_ext, to_ngn) = bridge.stats();
        assert!(to_ext >= 1, "NGN→Web 統計 = {}", to_ext);
        assert!(to_ngn >= 1, "Web→NGN 統計 = {}", to_ngn);
        let _ = web_peer_addr;

        // MediaBridge::stop で両ループがちゃんと畳まれる。
        bridge.stop().await;
    }

    /// Issue #69: `send_to_ngn` は NGN 側 socket を使って NGN ピア宛に
    /// 任意 RTP datagram を 1 つ送れる。学習済 peer が無い場合は Err。
    #[tokio::test]
    async fn rfc4733_send_to_ngn_injects_dtmf_packet() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();
        let ext_peer_addr = ext_peer_sock.local_addr().unwrap();

        let bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ngn_sock,
            ext_socket: ext_sock,
            ngn_peer: Some(ngn_peer_addr),
            ext_peer: Some(ext_peer_addr),
            metrics: None,
        })
        .unwrap();

        // RFC 4733 telephone-event RTP packet を NGN レッグへ注入する。
        let dtmf_pkt = RtpPacket {
            payload_type: 101, // telephone-event
            marker: true,
            sequence: 5000,
            timestamp: 100000,
            ssrc: 0xDEAD_BEEF,
            payload: vec![1, 0x0a, 0x03, 0x20], // event=1, vol=10, dur=800
        }
        .to_bytes();
        bridge.send_to_ngn(&dtmf_pkt).await.expect("send_to_ngn");

        let mut buf = vec![0u8; 1500];
        let (n, _src) = timeout(Duration::from_secs(1), ngn_peer_sock.recv_from(&mut buf))
            .await
            .expect("NGN ピアで DTMF が受信できない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.payload_type, 101);
        assert_eq!(recv.sequence, 5000);
        assert_eq!(recv.payload, vec![1, 0x0a, 0x03, 0x20]);
        let _ = ext_peer_sock;
        let _ = ext_peer_addr;

        bridge.stop().await;
    }

    /// Issue #69: PT=101 telephone-event RTP packet も `forward_loop` で
    /// 透過される (内線→NGN 方向、SDP に PT=101 が乗っている前提)。
    /// PCMU と並走しても整合性が保たれる。
    #[tokio::test]
    async fn rfc4733_telephone_event_pt_101_forwards_transparently() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_addr = ext_sock.local_addr().unwrap();

        let ngn_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ngn_peer_addr = ngn_peer_sock.local_addr().unwrap();
        let ext_peer_addr = ext_peer_sock.local_addr().unwrap();

        let bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ngn_sock,
            ext_socket: ext_sock,
            ngn_peer: Some(ngn_peer_addr),
            ext_peer: Some(ext_peer_addr),
            metrics: None,
        })
        .unwrap();

        // ext→NGN: 1) PCMU (PT=0) を 1 個、2) telephone-event (PT=101) を 1 個。
        let pcmu = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 0,
            ssrc: 0xCAFE,
            payload: vec![0xff; 160],
        }
        .to_bytes();
        let dtmf = RtpPacket {
            payload_type: 101,
            marker: true,
            sequence: 2,
            timestamp: 160,
            ssrc: 0xCAFE,
            payload: vec![3, 0x80 | 10, 0x03, 0x20], // event=3, end=1
        }
        .to_bytes();
        ext_peer_sock.send_to(&pcmu, ext_addr).await.unwrap();
        ext_peer_sock.send_to(&dtmf, ext_addr).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let mut got_pcmu = false;
        let mut got_dtmf = false;
        for _ in 0..2 {
            let (n, _src) = timeout(Duration::from_secs(1), ngn_peer_sock.recv_from(&mut buf))
                .await
                .expect("forward 待機 timeout")
                .unwrap();
            let pkt = RtpPacket::from_bytes(&buf[..n]).unwrap();
            match pkt.payload_type {
                PAYLOAD_TYPE_ULAW => got_pcmu = true,
                101 => got_dtmf = true,
                other => panic!("予期しない PT={other}"),
            }
        }
        assert!(
            got_pcmu && got_dtmf,
            "PT=0 と PT=101 の両方が forward されるべき"
        );
        let _ = ext_peer_addr;

        bridge.stop().await;
    }

    /// SDP で peer が分からなくても、最初の受信で学習して以降は転送できる。
    #[tokio::test]
    async fn learns_peer_from_first_packet() {
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_addr = ngn_sock.local_addr().unwrap();
        let ext_addr = ext_sock.local_addr().unwrap();

        let ngn_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ngn_sock,
            ext_socket: ext_sock,
            ngn_peer: None,
            ext_peer: None,
            metrics: None,
        })
        .unwrap();

        // 内線→ブリッジ→NGN 方向は ngn_peer 未確定なので最初の 1 つは drop される。
        // 先に NGN 側からトリガを打って ngn_peer を学習させる。
        let warm = vec![0x80u8, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]; // 最低限の RTP ヘッダ
        ngn_peer.send_to(&warm, ngn_addr).await.unwrap();
        // ext_peer 未学習なので NGN→ext は drop されるが NGN 側 peer は確定する。
        tokio::time::sleep(Duration::from_millis(20)).await;

        // 内線側からも 1 発打って ext_peer を学習させる
        ext_peer.send_to(&warm, ext_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // 以降は両側学習済み: NGN→ext と ext→NGN の双方が通る
        let pkt_ngn = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 10,
            timestamp: 0,
            ssrc: 0xAAAA_BBBB,
            payload: vec![0; 160],
        }
        .to_bytes();
        ngn_peer.send_to(&pkt_ngn, ngn_addr).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(Duration::from_secs(1), ext_peer.recv_from(&mut buf))
            .await
            .expect("学習後の転送がない")
            .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.ssrc, 0xAAAA_BBBB);

        bridge.stop().await;
    }
}
