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

use crate::rtp::set_rtp_dscp;

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
}

impl RtpBridge {
    /// ブリッジを起動する。即座に両側で受信ループが動き出す。
    pub fn start(cfg: BridgeConfig) -> Result<Self> {
        let BridgeConfig {
            ngn_socket,
            ext_socket,
            ngn_peer,
            ext_peer,
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
        ));

        // 内線 -> NGN 方向
        let ext_handle = tokio::spawn(forward_loop(
            "ext→NGN",
            ext_socket,
            ngn_socket,
            ext_state,
            ngn_state,
            state.clone(),
            false,
        ));

        Ok(Self {
            ngn_handle: Some(ngn_handle),
            ext_handle: Some(ext_handle),
            state,
        })
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
async fn forward_loop(
    direction: &'static str,
    from_socket: Arc<UdpSocket>,
    to_socket: Arc<UdpSocket>,
    from_state: Arc<LegState>,
    to_state: Arc<LegState>,
    state: Arc<BridgeState>,
    increment_to_ext: bool,
) {
    use std::sync::atomic::Ordering;
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
        } else {
            state.forwarded_to_ngn.fetch_add(1, Ordering::Relaxed);
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
