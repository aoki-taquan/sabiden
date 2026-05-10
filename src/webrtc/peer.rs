//! WebRTC PeerConnection の抽象化と最小実装
//!
//! 本モジュールは「ブラウザの WebRTC SDP オファを受け取り、RTP メディアを
//! 内線レッグに橋渡しする」インタフェースを定義する。
//!
//! # 採用方針 (Issue #23)
//!
//! Issue では `webrtc-rs` ないし `str0m` を推奨しているが、両クレートを
//! sabiden に直接ロードすると依存ツリーが ~70+ クレート増え、CI ビルド
//! 時間と外部攻撃面が膨らむ。そこで本 PR では以下の段階的な構造を採用する。
//!
//! 1. [`PeerSession`] トレイトで PeerConnection の最小操作を定義
//! 2. [`StubPeerSession`] で SDP answer 生成と ICE 交換のテスト用 stub を提供
//! 3. 実 ICE/DTLS-SRTP/Opus を扱う `webrtc-rs` バックエンドは別 PR で
//!    `webrtc-backend` feature flag として後付けできる構造にする。
//!
//! このアプローチにより、シグナリング層・認証層・Call Manager 統合は
//! 本 PR で完結し、メディア層の実装は Issue #25 (Opus 並行作業) と協調
//! しながら段階導入できる。
//!
//! # SDP answer 生成
//!
//! Stub では以下の最小限の処理を行う:
//! - offer の `m=audio` 行から PT (payload type) を抽出
//! - 同 PT の SDP answer を生成 (a=rtpmap は OPUS/48000/2 を想定)
//! - bundle / rtcp-mux はそのまま透過
//! - DTLS fingerprint は固定 (ICE のみ通って終端は将来実装)
//!
//! 実運用で本 stub を使うとブラウザは ICE/DTLS で失敗するが、シグナリング
//! 経路 (auth → register → offer/answer/ice → bye) は実装通りに動く。

use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

use crate::sdp::SessionDescription;

/// PeerConnection から取り出す / 押し込む音声フレーム 1 個。
///
/// RFC 3550 §5.1 (RTP) の 1 packet に対応する depayload 済みフレーム。
/// RFC 7587 (Opus payload format) で WebRTC は通常 20 ms = 960 samples@48kHz の
/// Opus フレームを 1 RTP packet に乗せる。 本構造は RTP ヘッダを直接持たず、
/// `pt` (payload type) と `rtp_time` (RTP timestamp / メディア時刻) と
/// `payload` (codec が解釈するペイロード本体) のみを保持する。
///
/// [`PeerSession::send_media`] / [`PeerSession::take_media_rx`] で
/// orchestrator ↔ str0m の間を流れる単位になる。
#[derive(Debug, Clone)]
pub struct MediaFrame {
    /// SDP の `a=rtpmap:<pt>` で negotiate した payload type。
    pub pt: u8,
    /// RTP timestamp (sample count, codec のサンプリングレート単位)。
    pub rtp_time: u32,
    /// codec ペイロード本体 (Opus フレーム、 μ-law サンプル列等)。
    pub payload: Vec<u8>,
    /// 受信時の wall-clock。 送信側 (orchestrator → str0m) では
    /// `Instant::now()` を入れる。 RFC 3550 §6.4.1 SR 算出に使う。
    pub network_time: Instant,
}

/// WebRTC PeerConnection の最小インタフェース。
///
/// 実バックエンド (`webrtc-rs` / `str0m`) でも本 trait を満たせば
/// シグナリング層から差し替え可能。
#[async_trait]
pub trait PeerSession: Send + Sync {
    /// ブラウザからの SDP offer を処理して answer を返す
    /// (RFC 3264 §5: answerer flow)。
    ///
    /// PWA→sabiden→NGN の発信フロー (内線オファ→SAVPF answer) で使う。
    async fn handle_offer(&self, sdp: &str) -> Result<String>;

    /// sabiden が offerer となって SDP オファを生成する
    /// (RFC 3264 §5: offerer flow)。
    ///
    /// NGN→PWA の **着信** フローで sabiden 自身が DTLS-SRTP/SAVPF オファを
    /// 作り、ブラウザに WS で push する用途。NGN の生 SDP (RTP/AVP) を
    /// そのままブラウザに渡しても、ブラウザは DTLS fingerprint / ICE 認証情報
    /// 不在で setRemoteDescription を拒絶するため、sabiden 側で SAVPF オファを
    /// 組み直す必要がある (Issue #73 / `docs/asterisk-real-invite.md` §5.2)。
    async fn create_offer(&self) -> Result<String>;

    /// `create_offer` で出したオファに対するブラウザの SDP answer を受理する
    /// (RFC 3264 §6: answerer の応答を offerer 側で適用)。
    ///
    /// str0m バックエンドでは `accept_answer` が DTLS-SRTP / ICE の確立を
    /// 進める。stub バックエンドは形式チェックだけ行う。
    async fn accept_answer(&self, sdp: &str) -> Result<()>;

    /// ICE candidate を 1 つ追加する (RFC 8445 §5.1.1: trickle ICE)。
    async fn add_ice_candidate(&self, candidate: &str) -> Result<()>;

    /// ローカル ICE candidate (a=candidate ラインのテキスト) のストリームを
    /// 取り出す。trickle ICE で WS シグナリングに流すために使う。
    ///
    /// stub バックエンドは候補を生成しない (None を返す)。
    /// str0m バックエンドはバインドした UDP ソケットの host candidate を
    /// 1 つ送出する。`public_ip` 設定があればそれを反映した形式になる。
    ///
    /// 戻り値が `None` の場合、シグナリング層は trickle 配信をスキップする。
    async fn take_local_candidates(&self) -> Option<mpsc::Receiver<String>> {
        None
    }

    /// ブラウザから受信したメディアフレーム ([`MediaFrame`]) のストリームを
    /// 1 度だけ取り出す (RFC 8835 §3: WebRTC media plane)。
    ///
    /// str0m バックエンドでは run_loop の `Event::MediaData` から 1 frame ずつ
    /// 流れる。 本 receiver を取り出した orchestrator は通常
    /// [`crate::call::bridge::MediaBridge::WebRtcAudio`] にパイプし、
    /// Opus → PCMU トランスコードして NGN レッグへ転送する。
    ///
    /// stub バックエンドは `None` を返す (実 codec を持たない)。
    /// 取り出しは **1 度だけ**。 2 度目以降は `None`。
    async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
        None
    }

    /// orchestrator から peer に音声フレームを送り込む (NGN → ブラウザ方向)。
    ///
    /// str0m バックエンドでは run_loop に command として渡し、
    /// `Rtc::writer(mid).write(pt, wallclock, rtp_time, payload)` 経由で
    /// SRTP 化して UDP へ送出する (RFC 8827: WebRTC は SRTP 必須)。
    /// 呼出側は Opus 化済みペイロードを渡す (PT は negotiate 済みの値)。
    ///
    /// stub バックエンドは即 `Ok(())` を返す (no-op、 テスト用)。
    /// peer がまだ Connected していない場合 (DTLS 確立前) は drop されるが
    /// `Ok(())` を返す (`Rtc::writer().write` の挙動に追従)。
    async fn send_media(&self, _frame: MediaFrame) -> Result<()> {
        Ok(())
    }

    /// セッションをクローズする。
    async fn close(&self) -> Result<()>;
}

/// テスト/開発用の stub PeerSession。
///
/// 実 ICE/DTLS は終端しないが、ブラウザに返す SDP answer を offer から
/// 機械的に組み立てる。本 PR ではこの stub をデフォルトにし、別 PR で
/// `webrtc-rs` 実装に差し替える。
pub struct StubPeerSession {
    inner: Mutex<StubInner>,
}

struct StubInner {
    /// 受信した ICE candidate 文字列 (テスト用)
    candidates: Vec<String>,
    closed: bool,
}

impl Default for StubPeerSession {
    fn default() -> Self {
        Self {
            inner: Mutex::new(StubInner {
                candidates: Vec::new(),
                closed: false,
            }),
        }
    }
}

impl StubPeerSession {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// テスト用: 蓄積された ICE candidate のスナップショット。
    pub async fn candidates(&self) -> Vec<String> {
        self.inner.lock().await.candidates.clone()
    }

    /// テスト用: クローズ済みか。
    pub async fn is_closed(&self) -> bool {
        self.inner.lock().await.closed
    }
}

#[async_trait]
impl PeerSession for StubPeerSession {
    async fn handle_offer(&self, sdp: &str) -> Result<String> {
        let answer = build_minimal_answer(sdp)?;
        debug!(
            answer_len = answer.len(),
            "stub PeerSession: SDP answer 生成"
        );
        Ok(answer)
    }

    async fn create_offer(&self) -> Result<String> {
        // Stub では実 DTLS / ICE を持たないので、形式上 SAVPF / PCMU PT 0 を
        // 含む最小 SDP を返す。テストはこの戻り値が NGN の生 SDP と区別できれば
        // 十分。実バックエンド (str0m) では `Str0mPeerSession::create_offer` が
        // 実フィンガプリント / ICE 認証情報入りで返す。
        let offer = "v=0\r\n\
                     o=- 0 0 IN IP4 0.0.0.0\r\n\
                     s=-\r\n\
                     c=IN IP4 0.0.0.0\r\n\
                     t=0 0\r\n\
                     m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n\
                     a=sendrecv\r\n"
            .to_string();
        Ok(offer)
    }

    async fn accept_answer(&self, sdp: &str) -> Result<()> {
        // Stub は SDP の形式だけ確認し、実 ICE/DTLS の遷移はしない。
        // パース不能なら Err、`m=audio` 不在は Err。
        let parsed = SessionDescription::parse(sdp)?;
        if !parsed.media.iter().any(|m| m.media == "audio") {
            return Err(anyhow!("answer に m=audio がない"));
        }
        Ok(())
    }

    async fn add_ice_candidate(&self, candidate: &str) -> Result<()> {
        let mut g = self.inner.lock().await;
        if g.closed {
            return Err(anyhow!("PeerSession は閉じている"));
        }
        g.candidates.push(candidate.to_string());
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.inner.lock().await.closed = true;
        Ok(())
    }
}

/// SDP offer から最小限の answer を組み立てる。
///
/// 本実装は ICE/DTLS を実装しないため、ブラウザ側でハンドシェイクは失敗
/// する。ただし JSON シグナリングのフォーマット検証としては有効で、
/// `m=audio <port> <proto> <pt>` を mirror して `a=recvonly` を付ける。
///
/// 実バックエンドが導入されたら本関数は廃止し、PeerConnection から
/// 生成した answer を返すよう差し替える。
pub fn build_minimal_answer(offer: &str) -> Result<String> {
    let parsed = SessionDescription::parse(offer)?;
    let m = parsed
        .media
        .iter()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow!("offer に m=audio がない"))?;
    let pt = m
        .formats
        .first()
        .ok_or_else(|| anyhow!("m= に payload type がない"))?;
    // 透過モード: 同じ PT を返し、connection は 0.0.0.0 (peerless)。
    let answer = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 0.0.0.0\r\n\
         s=-\r\n\
         c=IN IP4 0.0.0.0\r\n\
         t=0 0\r\n\
         m=audio 0 {proto} {pt}\r\n\
         a=rtpmap:{pt} OPUS/48000/2\r\n\
         a=recvonly\r\n",
        proto = m.protocol,
        pt = pt
    );
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_offer() -> String {
        "v=0\r\n\
         o=- 1 1 IN IP4 192.0.2.1\r\n\
         s=-\r\n\
         c=IN IP4 192.0.2.1\r\n\
         t=0 0\r\n\
         m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n\
         a=rtpmap:111 OPUS/48000/2\r\n\
         a=sendrecv\r\n"
            .to_string()
    }

    #[tokio::test]
    async fn stub_peer_round_trip() {
        let p = StubPeerSession::new();
        let answer = p.handle_offer(&sample_offer()).await.unwrap();
        assert!(answer.contains("m=audio 0 UDP/TLS/RTP/SAVPF 111"));
        assert!(answer.contains("a=rtpmap:111 OPUS/48000/2"));
        assert!(answer.contains("a=recvonly"));
    }

    #[tokio::test]
    async fn stub_peer_collects_ice_candidates() {
        let p = StubPeerSession::new();
        p.add_ice_candidate("candidate:1 1 udp 1 1.2.3.4 3478 typ host")
            .await
            .unwrap();
        assert_eq!(p.candidates().await.len(), 1);
    }

    #[tokio::test]
    async fn stub_peer_close_blocks_ice() {
        let p = StubPeerSession::new();
        p.close().await.unwrap();
        assert!(p.is_closed().await);
        assert!(p
            .add_ice_candidate("candidate:x 1 udp 1 1.1.1.1 1 typ host")
            .await
            .is_err());
    }

    #[test]
    fn build_answer_rejects_offer_without_audio() {
        let bad = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\n";
        assert!(build_minimal_answer(bad).is_err());
    }

    /// Issue #73: `create_offer` は SAVPF / PCMU を含む SDP を返す
    /// (RFC 3264 §5: offerer flow)。NGN の生 RTP/AVP SDP と区別可能であること。
    #[tokio::test]
    async fn stub_create_offer_returns_savpf_pcmu() {
        let p = StubPeerSession::new();
        let offer = p.create_offer().await.unwrap();
        assert!(
            offer.contains("UDP/TLS/RTP/SAVPF"),
            "offer に SAVPF proto がない: {}",
            offer
        );
        assert!(offer.contains("a=rtpmap:0 PCMU/8000"));
        // NGN AVP SDP にはない proto なので、生 NGN SDP と取り違えない
        assert!(!offer.contains("RTP/AVP "), "AVP proto が混入: {}", offer);
    }

    /// Issue #73: `accept_answer` は形式上 m=audio を含む SDP のみ受理。
    #[tokio::test]
    async fn stub_accept_answer_requires_audio_m_line() {
        let p = StubPeerSession::new();
        let ok_sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
                      m=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n";
        p.accept_answer(ok_sdp).await.expect("受理");
        let bad = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n";
        assert!(p.accept_answer(bad).await.is_err());
    }
}
