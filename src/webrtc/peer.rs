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
/// # answer 側の rtpmap (Issue #80)
///
/// RFC 3264 §6 (Generating the Answer): answer の各 fmt は offer の対応
/// する fmt と意味的に一致する codec を表さなければならない。 RFC 4566 §6
/// (rtpmap) は「静的に割り当てられた PT (RFC 3551 §6) の rtpmap を書く
/// 場合、 encoding 名は RFC 3551 で登録された名前と一致しなければならない
/// (MUST)」と定める。 したがって本関数は以下の方針で answer の rtpmap を
/// 生成する:
///
/// 1. 静的 PT (RFC 3551 §6 Table 4 / 5): canonical な名前と clock rate を
///    返す。 例: PT=0 → `PCMU/8000`、 PT=8 → `PCMA/8000`。
/// 2. 動的 PT (96..=127): offer の同 PT 行の rtpmap を引き継ぐ。
///    offer に rtpmap が無いと codec が定義できないのでエラー。
/// 3. 静的だが未対応な PT: rtpmap 行を出さない (RFC 4566 §6 「静的 PT は
///    rtpmap 必須ではない」)。
pub fn build_minimal_answer(offer: &str) -> Result<String> {
    let parsed = SessionDescription::parse(offer)?;
    let m = parsed
        .media
        .iter()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow!("offer に m=audio がない"))?;
    let pt_str = m
        .formats
        .first()
        .ok_or_else(|| anyhow!("m= に payload type がない"))?;
    let pt: u8 = pt_str
        .parse()
        .map_err(|_| anyhow!("payload type が数値でない: {}", pt_str))?;

    let rtpmap_line = rtpmap_for_answer(&parsed, m, pt)?;

    // 透過モード: 同じ PT を返し、connection は 0.0.0.0 (peerless)。
    let answer = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 0.0.0.0\r\n\
         s=-\r\n\
         c=IN IP4 0.0.0.0\r\n\
         t=0 0\r\n\
         m=audio 0 {proto} {pt}\r\n\
         {rtpmap}\
         a=recvonly\r\n",
        proto = m.protocol,
        pt = pt,
        rtpmap = rtpmap_line,
    );
    Ok(answer)
}

/// answer に載せる rtpmap 行 (1 行ぶんの文字列、末尾 `\r\n` 付き、または空)
/// を組み立てる。
///
/// - RFC 3551 §6 Table 4 の静的 PT 0/8 は canonical 名で出力。
/// - 動的 PT は offer の rtpmap (RFC 3264 §6) を引き継ぐ。
/// - その他の静的 PT は rtpmap 行を省く (RFC 4566 §6: 静的 PT は rtpmap
///   省略可能)。
fn rtpmap_for_answer(
    parsed: &SessionDescription,
    media: &crate::sdp::MediaDescription,
    pt: u8,
) -> Result<String> {
    // RFC 3551 §6: PT 0 = PCMU/8000 (1ch), PT 8 = PCMA/8000 (1ch)。
    // RFC 4566 §6: 静的 PT に rtpmap を書く場合、 encoding 名は登録名と
    // 一致 (MUST)。 ここでは安全側で canonical 名を出す。
    match pt {
        0 => return Ok("a=rtpmap:0 PCMU/8000\r\n".to_string()),
        8 => return Ok("a=rtpmap:8 PCMA/8000\r\n".to_string()),
        _ => {}
    }

    // RFC 4566 §6 / RFC 3551 §6: 動的 PT (96..=127) は offer 側で rtpmap
    // 定義必須。 まずメディアレベルから探し、 無ければセッションレベルを
    // フォールバック (RFC 4566 §6 では rtpmap はメディア属性だが、 実装に
    // よってはセッションレベルに置くため `SessionDescription::find_rtpmap`
    // を流用する)。
    let from_media = media.attributes.iter().find_map(|a| {
        let rm = a.as_rtpmap()?;
        if rm.payload_type == pt {
            Some(rm)
        } else {
            None
        }
    });
    let rm = from_media.or_else(|| parsed.find_rtpmap(pt));
    match rm {
        Some(rm) => {
            let params = rm
                .parameters
                .as_deref()
                .map(|p| format!("/{p}"))
                .unwrap_or_default();
            Ok(format!(
                "a=rtpmap:{pt} {enc}/{clock}{params}\r\n",
                pt = rm.payload_type,
                enc = rm.encoding,
                clock = rm.clock_rate,
                params = params,
            ))
        }
        None => {
            // 静的 PT で未対応 (例: PT=9 G722 等) なら rtpmap 省略。 動的 PT
            // で rtpmap 無しは offer 不正なので Err。
            if pt < 96 {
                Ok(String::new())
            } else {
                Err(anyhow!(
                    "offer の動的 PT {} に対応する rtpmap が見つからない (RFC 4566 §6)",
                    pt
                ))
            }
        }
    }
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

    /// RFC 3551 §6 Table 4 (Static PT 0 = PCMU/8000): answer 側で PT=0
    /// の rtpmap を書く場合、 RFC 4566 §6 により encoding 名は registered
    /// な "PCMU" でなければならない (MUST)。 build_minimal_answer は PT 0
    /// に対して `OPUS/48000/2` のような捏造マッピングを返してはならない
    /// (Issue #80)。
    #[test]
    fn rfc3551_6_static_pt0_answer_rtpmap_is_pcmu_8000() {
        let offer = "v=0\r\n\
                     o=- 1 1 IN IP4 192.0.2.1\r\n\
                     s=-\r\n\
                     c=IN IP4 192.0.2.1\r\n\
                     t=0 0\r\n\
                     m=audio 50000 UDP/TLS/RTP/SAVPF 0\r\n\
                     a=rtpmap:0 PCMU/8000\r\n\
                     a=sendrecv\r\n";
        let answer = build_minimal_answer(offer).expect("build answer for PT=0");
        assert!(
            answer.contains("m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n"),
            "PT=0 mirror: {}",
            answer
        );
        assert!(
            answer.contains("a=rtpmap:0 PCMU/8000\r\n"),
            "PT=0 must map to PCMU/8000 (RFC 3551 §6 / RFC 4566 §6): {}",
            answer
        );
        // 捏造禁止 (Issue #80 の核心バグ): OPUS は PT=0 に許されない。
        assert!(
            !answer.contains("OPUS/48000/2"),
            "PT=0 must NOT advertise OPUS (RFC 4566 §6 violation): {}",
            answer
        );
    }

    /// RFC 3551 §6 Table 4 (Static PT 8 = PCMA/8000): PT 0 と同じ理屈で
    /// PCMA に固定。
    #[test]
    fn rfc3551_6_static_pt8_answer_rtpmap_is_pcma_8000() {
        let offer = "v=0\r\n\
                     o=- 1 1 IN IP4 192.0.2.1\r\n\
                     s=-\r\n\
                     c=IN IP4 192.0.2.1\r\n\
                     t=0 0\r\n\
                     m=audio 50000 RTP/AVP 8\r\n\
                     a=rtpmap:8 PCMA/8000\r\n\
                     a=sendrecv\r\n";
        let answer = build_minimal_answer(offer).expect("build answer for PT=8");
        assert!(
            answer.contains("m=audio 0 RTP/AVP 8\r\n"),
            "PT=8 mirror: {}",
            answer
        );
        assert!(
            answer.contains("a=rtpmap:8 PCMA/8000\r\n"),
            "PT=8 must map to PCMA/8000 (RFC 3551 §6 / RFC 4566 §6): {}",
            answer
        );
        assert!(
            !answer.contains("OPUS"),
            "PT=8 must NOT advertise OPUS: {}",
            answer
        );
    }

    /// RFC 3264 §6 (Generating the Answer) + RFC 4566 §6 (rtpmap): 動的 PT
    /// の answer rtpmap は offer の rtpmap を引き継ぐ。 PT=111 で
    /// `opus/48000/2` を提示するオファに対しては `opus/48000/2` で answer。
    #[test]
    fn rfc3264_6_dynamic_pt111_answer_mirrors_offer_rtpmap() {
        let offer = "v=0\r\n\
                     o=- 1 1 IN IP4 192.0.2.1\r\n\
                     s=-\r\n\
                     c=IN IP4 192.0.2.1\r\n\
                     t=0 0\r\n\
                     m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n\
                     a=rtpmap:111 opus/48000/2\r\n\
                     a=sendrecv\r\n";
        let answer = build_minimal_answer(offer).expect("build answer for PT=111");
        assert!(answer.contains("m=audio 0 UDP/TLS/RTP/SAVPF 111\r\n"));
        assert!(
            answer.contains("a=rtpmap:111 opus/48000/2\r\n"),
            "dynamic PT must mirror offer rtpmap (RFC 3264 §6): {}",
            answer
        );
    }

    /// RFC 4566 §6: 動的 PT (96..=127) の offer が rtpmap 行を持っていない
    /// 場合、 codec が定義できないので answer 側はエラーを返す。 OPUS を
    /// 捏造して返してはならない (Issue #80)。
    #[test]
    fn rfc4566_6_dynamic_pt_without_rtpmap_errors() {
        let bad_offer = "v=0\r\n\
                         o=- 1 1 IN IP4 192.0.2.1\r\n\
                         s=-\r\n\
                         c=IN IP4 192.0.2.1\r\n\
                         t=0 0\r\n\
                         m=audio 50000 UDP/TLS/RTP/SAVPF 111\r\n\
                         a=sendrecv\r\n";
        assert!(
            build_minimal_answer(bad_offer).is_err(),
            "動的 PT に対応する rtpmap が無いオファは reject"
        );
    }

    /// RFC 4566 §6: 静的 PT で未対応 (例 PT=9 G722) の場合、 静的 PT は
    /// rtpmap 省略可能 (RFC 4566 §6) なので、 answer 側でも rtpmap を出さない。
    /// 少なくとも OPUS を捏造してはならない (Issue #80)。
    #[test]
    fn rfc4566_6_unknown_static_pt_omits_rtpmap() {
        // PT=9 = G722/8000 静的だが、 sabiden は未対応。 offer が rtpmap を
        // 載せていないケース。
        let offer = "v=0\r\n\
                     o=- 1 1 IN IP4 192.0.2.1\r\n\
                     s=-\r\n\
                     c=IN IP4 192.0.2.1\r\n\
                     t=0 0\r\n\
                     m=audio 50000 RTP/AVP 9\r\n\
                     a=sendrecv\r\n";
        let answer = build_minimal_answer(offer).expect("build answer for static PT=9");
        assert!(answer.contains("m=audio 0 RTP/AVP 9\r\n"));
        assert!(
            !answer.contains("a=rtpmap:9 OPUS"),
            "PT=9 に OPUS を割当てるのは違反: {}",
            answer
        );
        assert!(
            !answer.contains("OPUS/48000/2"),
            "未対応静的 PT で OPUS を捏造しない: {}",
            answer
        );
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
