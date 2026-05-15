//! Call Manager (通話制御)
//!
//! 二つの SIP レッグ (NGN UAC / 内線 UAS) をまたぐ通話状態を管理する。
//!
//! # 着信フロー (NGN → 内線, "フォーク着信")
//!
//! ```text
//! NGN ── INVITE ──► sabiden
//!                       │ fork_to_extensions: Uac::invite を全内線に並列発行
//!                       ├─► 内線 A
//!                       ├─► 内線 B
//!                       └─► 内線 C
//!         200 OK ◄──┤  最初に 200 を返したレッグを採用
//!         CANCEL ──►┴──┴─► 他レッグ
//! ```
//!
//! 1. [`fork_to_extensions`] が `Uac::invite` を `tokio::spawn` で並列起動
//! 2. 結果は `mpsc` チャネル経由で返ってくる。最初の `Established` を採用
//! 3. 残りの未確定レッグへ [`Uac::cancel_pending`] を送る
//! 4. 何も応答しなければ全レッグの完了 (Failed/Timeout) を待ってエラー
//!
//! # 発信フロー (内線 → NGN)
//!
//! `UasEvent::Invite` を受け取り、内線の SDP オファをそのまま `Uac::invite`
//! に渡して NGN に転送する (B2BUA だが SDP は穴開けなしで透過)。NGN の
//! 200 OK が来たら内線側の [`crate::sip::uas::ResponderHandle`] で 200 OK を返し、両側の
//! ダイアログを保持する。
//!
//! # RTP ブリッジ
//!
//! 両レッグが 200 OK / ACK を完了した時点で、SDP からピアの RTP
//! address/port を抽出し [`RtpBridge`] を起動する。両レッグそれぞれに
//! 別ソケットが必要なため、ソケットの bind は呼び出し側 (本マネージャ)
//! が責任を持つ。
//!
//! # 制限 (Phase 1)
//!
//! - トランスコードなし (G.711 μ-law をそのままコピー)
//! - DTMF / 保留 / 転送なし
//! - 1 通話 1 ブリッジ (multi-party 不可)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tracing::{debug, info, warn};

use super::bridge::{MediaBridge, RtpBridge};
use super::{CallId, CallState};
use crate::sdp::SessionDescription;
use crate::sip::message::SipResponse;
use crate::sip::registrar::ExtensionRegistrar;
use crate::sip::uac::{InviteOutcome, InvitePlan, Uac};

/// 1 内線レッグへ 1 INVITE を送ってフォーク結果を返すワーカ。
///
/// テストしやすくするため Uac 抽象化を経由せず Trait 経由で差し替え可能に
/// している。本実装の本番経路は [`UacForker`]。
#[async_trait::async_trait]
pub trait LegInviter: Send + Sync {
    /// 1 つの宛先に対して INVITE を送り、最終応答を返す。
    /// CANCEL 用に `InvitePlan` も返す。
    async fn invite(&self, target_uri: &str, sdp_offer: &[u8]) -> Result<LegOutcome>;
}

/// 1 レッグの INVITE 結果。
pub enum LegOutcome {
    /// 200 OK を受け取った。内側の `Uac` ダイアログは [`Uac`] が保持する。
    Established {
        plan: InvitePlan,
        response: SipResponse,
    },
    /// 4xx-6xx で確定失敗。
    Failed { plan: InvitePlan, status: u16 },
    /// タイムアウト等のトランスポート エラー。
    Errored { plan: Option<InvitePlan> },
}

/// `Uac` を使って 1 内線へ INVITE を送るデフォルト実装。
///
/// 内線へ向けた INVITE では NGN 用の `Uac::config` をそのまま使うのは
/// 不適切 (From URI が NGN 番号になる) なので、本実装では内線向け用に
/// 別の `Uac` インスタンスを構築する想定。テストでは Mock を使う。
pub struct UacForker {
    pub uac: Arc<Uac>,
    /// 各レッグの送信先 (NGN 側と違い内線ごとに変わる) を ID で引けるようにする。
    pub targets: HashMap<String, SocketAddr>,
}

#[async_trait::async_trait]
impl LegInviter for UacForker {
    async fn invite(&self, target_uri: &str, sdp_offer: &[u8]) -> Result<LegOutcome> {
        let plan = self.uac.build_invite(target_uri, Some(sdp_offer), None);
        let plan_for_return = plan.clone();
        let outcome = self.uac.invite(plan, Some(sdp_offer.to_vec())).await;
        match outcome {
            Ok(InviteOutcome::Established(call)) => Ok(LegOutcome::Established {
                plan: plan_for_return,
                response: call.response,
            }),
            Ok(InviteOutcome::Failed { response }) => Ok(LegOutcome::Failed {
                plan: plan_for_return,
                status: response.status_code,
            }),
            Err(e) => {
                warn!(target = target_uri, error=%e, "fork leg INVITE エラー");
                Ok(LegOutcome::Errored {
                    plan: Some(plan_for_return),
                })
            }
        }
    }
}

/// `fork_to_extensions` の結果。
pub enum ForkResult {
    /// 1 つの内線で 200 OK を取った。`winner_uri` の SDP answer を返す。
    Answered {
        winner_uri: String,
        response: SipResponse,
        /// Issue #87 / #121: WebRTC レッグが winner の場合に
        /// `start_bridge_for_inbound` から peer の MediaFrame I/O に
        /// アクセスするための handle。 SIP レッグなら `None`。
        ///
        /// 入手元は [`crate::call::orchestrator::fork_to_bindings`] (WebRTC
        /// 専用 leg)。 [`fork_to_extensions`] (SIP only) では常に `None`。
        webrtc_handle: Option<crate::call::orchestrator::WebRtcLegArtifacts>,
        /// Issue #81: WebRTC レッグが winner の場合に NGN 側 BYE を browser
        /// に伝搬するための WS ハンドル。 SIP レッグなら `None`。
        ///
        /// `NgnInboundHandler` は確立通話の Call-ID とこの WS を紐づけて
        /// 保持し、 NGN BYE 受信時に `ServerMessage::Bye` を push する
        /// (RFC 3261 §15.1.2 dialog 終了通知の B2BUA 伝搬。 RFC 5853 §3.2.2
        /// SBC framework: 内線レッグへの BYE 翻訳は B2BUA の責務)。
        webrtc_ws: Option<crate::webrtc::signaling::WsSink>,
    },
    /// 全レッグが Busy/Decline で確定失敗。
    AllFailed { last_status: Option<u16> },
    /// timeout までに 1 つも結果が取れなかった。
    Timeout,
}

/// 登録済み内線一覧へ INVITE をフォークし、最初の 200 を採用する。
///
/// 内部動作:
/// 1. 各内線へ並列に `inviter.invite` を spawn
/// 2. `mpsc` で先着順に LegOutcome を集める
/// 3. 200 OK が来たら winner として記録、残りに CANCEL
/// 4. 全レッグが失敗したら AllFailed
///
/// `cancel_remaining` クロージャは現状の `Uac` API では「invite` 中の
/// future に対して横から CANCEL する」のが書きにくいため、INVITE が完了
/// 済みの 4xx-6xx レッグについては自動で 487 同等扱いとし、未完了のレッグ
/// に対して CANCEL を送るのは外側で行う構造とする (テストで挙動確認)。
pub async fn fork_to_extensions(
    inviter: Arc<dyn LegInviter>,
    targets: Vec<String>,
    sdp_offer: Vec<u8>,
    overall_timeout: Duration,
) -> ForkResult {
    if targets.is_empty() {
        return ForkResult::AllFailed { last_status: None };
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<(String, LegOutcome)>();
    let total = targets.len();

    for target in targets {
        let inviter = inviter.clone();
        let sdp = sdp_offer.clone();
        let tx = tx.clone();
        let target_clone = target.clone();
        tokio::spawn(async move {
            match inviter.invite(&target, &sdp).await {
                Ok(outcome) => {
                    let _ = tx.send((target_clone, outcome));
                }
                Err(e) => {
                    warn!(target=%target, error=%e, "fork worker 失敗");
                    let _ = tx.send((target_clone, LegOutcome::Errored { plan: None }));
                }
            }
        });
    }
    drop(tx);

    let mut last_status: Option<u16> = None;
    let mut received = 0usize;
    let deadline = time::Instant::now() + overall_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(time::Instant::now());
        if remaining.is_zero() {
            return ForkResult::Timeout;
        }
        let next = match time::timeout(remaining, rx.recv()).await {
            Ok(Some(v)) => v,
            Ok(None) => break, // 全 worker 終了
            Err(_) => return ForkResult::Timeout,
        };
        received += 1;
        let (winner_uri, outcome) = next;
        match outcome {
            LegOutcome::Established { response, .. } => {
                info!(winner = %winner_uri, "fork: 内線 {} が応答", winner_uri);
                // 残りの未着信レッグは外側で CANCEL する責務だが、本フォーク
                // 関数のスコープでは「先着 200」に専念し、まだ走っている
                // worker タスクは drop で abort される (mpsc receiver drop)。
                return ForkResult::Answered {
                    winner_uri,
                    response,
                    webrtc_handle: None,
                    webrtc_ws: None,
                };
            }
            LegOutcome::Failed { status, .. } => {
                debug!(target=%winner_uri, status, "fork leg 失敗応答");
                last_status = Some(status);
            }
            LegOutcome::Errored { .. } => {
                debug!(target=%winner_uri, "fork leg トランスポート失敗");
            }
        }
        if received >= total {
            break;
        }
    }
    ForkResult::AllFailed { last_status }
}

/// 通話 1 件分の状態スナップショット。Call Manager のテーブルに保存する。
pub struct CallEntry {
    pub id: CallId,
    pub state: CallState,
    /// メディアブリッジ (確立後のみ Some)。`MediaBridge` enum で
    /// 純リレー (PCMU↔PCMU) とトランスコード (Opus↔PCMU) を切替える。
    pub bridge: Option<MediaBridge>,
}

/// 通話マネージャの簡易テーブル。
///
/// Call ID → CallEntry の Map と、内線登録テーブルへの参照を保持する。
/// 上位層 (main.rs) はこの構造体を Arc 共有して、UasEvent ハンドラと
/// インバウンド INVITE ハンドラの両方から呼び出す想定。
pub struct CallManager {
    inner: Mutex<CallManagerInner>,
    extensions: Arc<ExtensionRegistrar>,
}

#[derive(Default)]
struct CallManagerInner {
    calls: HashMap<CallId, CallEntry>,
}

impl CallManager {
    /// 内線登録テーブルへの参照だけ持って空で始める。
    pub fn new(extensions: Arc<ExtensionRegistrar>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(CallManagerInner::default()),
            extensions,
        })
    }

    /// 新しい通話エントリを登録し、ID を返す。
    pub async fn create_call(&self) -> CallId {
        let id = CallId::next();
        let mut inner = self.inner.lock().await;
        inner.calls.insert(
            id,
            CallEntry {
                id,
                state: CallState::Idle,
                bridge: None,
            },
        );
        id
    }

    /// 状態を遷移させる。
    pub async fn transition(&self, id: CallId, state: CallState) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let entry = inner
            .calls
            .get_mut(&id)
            .ok_or_else(|| anyhow!("不明な call: {}", id))?;
        debug!(%id, from=?entry.state, to=?state, "call state 遷移");
        entry.state = state;
        Ok(())
    }

    /// 純リレー RTP ブリッジを取り付ける (Connected 遷移時に呼ぶ)。
    ///
    /// 内部で [`MediaBridge::Relay`] にラップする。両側 PCMU 通話用。
    pub async fn attach_bridge(&self, id: CallId, bridge: RtpBridge) -> Result<()> {
        self.attach_media_bridge(id, MediaBridge::Relay(bridge))
            .await
    }

    /// 任意の [`MediaBridge`] (リレー or トランスコード) を取り付ける。
    /// Issue #29: WebRTC↔NGN 通話用の Opus⇔PCMU トランスコード経路で使う。
    pub async fn attach_media_bridge(&self, id: CallId, bridge: MediaBridge) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let entry = inner
            .calls
            .get_mut(&id)
            .ok_or_else(|| anyhow!("不明な call: {}", id))?;
        entry.bridge = Some(bridge);
        entry.state = CallState::Connected;
        Ok(())
    }

    /// 通話を終了する。RTP ブリッジを停止しテーブルから除く。
    pub async fn terminate(&self, id: CallId) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let Some(mut entry) = inner.calls.remove(&id) else {
            return Ok(());
        };
        entry.state = CallState::Terminated;
        if let Some(bridge) = entry.bridge.take() {
            // Drop に任せると abort 同期が遅れることがあるので明示的に stop。
            drop(inner);
            bridge.stop().await;
        }
        Ok(())
    }

    /// 指定 CallId のブリッジ socket / peer 経由で NGN レッグへ任意 RTP
    /// datagram を 1 つ注入する。
    ///
    /// Issue #69 (DTMF interop): SIP INFO で受け取った DTMF を RFC 4733
    /// telephone-event の RTP packet へ変換し、NGN レッグに乗せる用途。
    /// 該当 CallId にブリッジが付いていない / NGN ピア未学習の場合は `Err`。
    pub async fn inject_to_ngn(&self, id: CallId, datagram: &[u8]) -> Result<()> {
        let inner = self.inner.lock().await;
        let entry = inner
            .calls
            .get(&id)
            .ok_or_else(|| anyhow!("不明な call: {}", id))?;
        let bridge = entry
            .bridge
            .as_ref()
            .ok_or_else(|| anyhow!("call {} に RtpBridge が付いていない", id))?;
        bridge.send_to_ngn(datagram).await
    }

    /// 内線レッグへの注入版 (NGN→内線 INFO 経路の interop placeholder)。
    pub async fn inject_to_ext(&self, id: CallId, datagram: &[u8]) -> Result<()> {
        let inner = self.inner.lock().await;
        let entry = inner
            .calls
            .get(&id)
            .ok_or_else(|| anyhow!("不明な call: {}", id))?;
        let bridge = entry
            .bridge
            .as_ref()
            .ok_or_else(|| anyhow!("call {} に RtpBridge が付いていない", id))?;
        bridge.send_to_ext(datagram).await
    }

    /// 現在登録済みの通話数。テスト用。
    pub async fn len(&self) -> usize {
        self.inner.lock().await.calls.len()
    }

    /// 現在の状態 (テスト用)。
    pub async fn state_of(&self, id: CallId) -> Option<CallState> {
        self.inner.lock().await.calls.get(&id).map(|e| e.state)
    }

    /// 内線登録テーブルへの参照。
    pub fn extensions(&self) -> &Arc<ExtensionRegistrar> {
        &self.extensions
    }
}

/// SDP ボディから (RTP IP, RTP port) を取り出す。
///
/// メディアレベル `c=` を優先し、なければセッションレベル `c=` を使う
/// (RFC 4566 §5.7)。最初の `m=audio` を採用。
pub fn extract_rtp_endpoint(sdp_bytes: &[u8]) -> Result<SocketAddr> {
    let text = std::str::from_utf8(sdp_bytes)?;
    let sdp = SessionDescription::parse(text)?;
    let media = sdp
        .media
        .iter()
        .find(|m| m.media == "audio")
        .ok_or_else(|| anyhow!("SDP に audio media がない"))?;
    let ip = media
        .connection
        .as_ref()
        .map(|c| c.address)
        .or_else(|| sdp.connection.as_ref().map(|c| c.address))
        .ok_or_else(|| anyhow!("SDP に c= がない"))?;
    Ok(SocketAddr::new(ip, media.port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::scripted::{ScriptedAction, ScriptedInviter};

    /// 単一内線が即 200 を返すと Answered になる。
    #[tokio::test]
    async fn single_extension_answers() {
        let inviter = ScriptedInviter::builder()
            .script("sip:iphone@host", ScriptedAction::ok())
            .build();
        let result = fork_to_extensions(
            inviter,
            vec!["sip:iphone@host".to_string()],
            b"v=0\r\n".to_vec(),
            Duration::from_secs(1),
        )
        .await;
        match result {
            ForkResult::Answered { winner_uri, .. } => {
                assert_eq!(winner_uri, "sip:iphone@host");
            }
            _ => panic!("Answered 期待"),
        }
    }

    /// 複数内線で 1 つだけ 200 を返すと、それが winner になる。
    #[tokio::test]
    async fn multiple_extensions_first_to_answer_wins() {
        let inviter = ScriptedInviter::builder()
            .script(
                "sip:slow@host",
                ScriptedAction::DelayedStatus {
                    delay_ms: 200,
                    status: 200,
                },
            )
            .script(
                "sip:fast@host",
                ScriptedAction::DelayedStatus {
                    delay_ms: 50,
                    status: 200,
                },
            )
            .script("sip:busy@host", ScriptedAction::busy())
            .build();
        let result = fork_to_extensions(
            inviter.clone(),
            vec![
                "sip:slow@host".to_string(),
                "sip:fast@host".to_string(),
                "sip:busy@host".to_string(),
            ],
            b"v=0\r\n".to_vec(),
            Duration::from_secs(2),
        )
        .await;
        match result {
            ForkResult::Answered { winner_uri, .. } => {
                assert_eq!(winner_uri, "sip:fast@host");
            }
            _ => panic!("fast が勝つはず"),
        }
        // 全レッグに INVITE が飛んでいることを確認
        assert_eq!(inviter.call_count(), 3);
    }

    /// 全内線が拒否すると AllFailed。
    #[tokio::test]
    async fn all_extensions_busy_returns_all_failed() {
        let inviter = ScriptedInviter::builder()
            .script("sip:a@host", ScriptedAction::busy())
            .script("sip:b@host", ScriptedAction::busy())
            .build();
        let result = fork_to_extensions(
            inviter,
            vec!["sip:a@host".to_string(), "sip:b@host".to_string()],
            b"v=0\r\n".to_vec(),
            Duration::from_secs(1),
        )
        .await;
        match result {
            ForkResult::AllFailed { last_status } => assert_eq!(last_status, Some(486)),
            _ => panic!("AllFailed 期待"),
        }
    }

    /// 誰も応答しないと Timeout。
    #[tokio::test]
    async fn timeout_when_nobody_responds() {
        let inviter = ScriptedInviter::builder()
            .script("sip:silent@host", ScriptedAction::NeverRespond)
            .build();
        let result = fork_to_extensions(
            inviter,
            vec!["sip:silent@host".to_string()],
            b"v=0\r\n".to_vec(),
            Duration::from_millis(100),
        )
        .await;
        assert!(matches!(result, ForkResult::Timeout));
    }

    /// targets が空なら即 AllFailed。
    #[tokio::test]
    async fn empty_targets_is_all_failed() {
        let inviter = ScriptedInviter::builder().build();
        let result =
            fork_to_extensions(inviter, vec![], b"v=0\r\n".to_vec(), Duration::from_secs(1)).await;
        assert!(matches!(
            result,
            ForkResult::AllFailed { last_status: None }
        ));
    }

    #[tokio::test]
    async fn extract_rtp_endpoint_picks_media_level_connection() {
        let sdp = b"v=0\r\n\
                    o=- 1 1 IN IP4 192.0.2.1\r\n\
                    s=-\r\n\
                    c=IN IP4 192.0.2.1\r\n\
                    t=0 0\r\n\
                    m=audio 30000 RTP/AVP 0\r\n\
                    c=IN IP4 198.51.100.5\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        let addr = extract_rtp_endpoint(sdp).unwrap();
        assert_eq!(addr.to_string(), "198.51.100.5:30000");
    }

    #[tokio::test]
    async fn extract_rtp_endpoint_falls_back_to_session_level() {
        let sdp = b"v=0\r\n\
                    o=- 1 1 IN IP6 2001:db8::1\r\n\
                    s=-\r\n\
                    c=IN IP6 2001:db8::1\r\n\
                    t=0 0\r\n\
                    m=audio 40000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n";
        let addr = extract_rtp_endpoint(sdp).unwrap();
        assert_eq!(addr.to_string(), "[2001:db8::1]:40000");
    }

    /// CallManager の状態遷移と通話数管理。
    #[tokio::test]
    async fn call_manager_tracks_state_transitions() {
        let registrar = ExtensionRegistrar::new();
        let mgr = CallManager::new(registrar);
        let id = mgr.create_call().await;
        assert_eq!(mgr.state_of(id).await, Some(CallState::Idle));
        assert_eq!(mgr.len().await, 1);

        mgr.transition(id, CallState::Ringing).await.unwrap();
        assert_eq!(mgr.state_of(id).await, Some(CallState::Ringing));

        mgr.terminate(id).await.unwrap();
        assert_eq!(mgr.state_of(id).await, None);
        assert_eq!(mgr.len().await, 0);
    }

    #[tokio::test]
    async fn unknown_call_transition_errors() {
        let registrar = ExtensionRegistrar::new();
        let mgr = CallManager::new(registrar);
        let bogus = CallId(9999);
        assert!(mgr.transition(bogus, CallState::Connected).await.is_err());
    }
}
