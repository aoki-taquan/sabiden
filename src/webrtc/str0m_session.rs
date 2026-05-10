//! 実 WebRTC (ICE / DTLS-SRTP / RTP) を [`str0m`] で終端する [`PeerSession`].
//!
//! # Issue #28
//!
//! PR #26 で導入した [`PeerSession`] trait を str0m バックエンドで実装し、
//! ブラウザの WebRTC スタックとフル互換に喋れるようにする。
//!
//! # 設計
//!
//! - str0m は Sans-IO 設計。`Rtc` は I/O を行わず、`poll_output()` と
//!   `handle_input()` の往復で進む。これを 1 タスク (`run_loop`) で回し、
//!   その隣に UDP ソケットを置く。
//! - PeerSession trait の async API (`handle_offer` / `add_ice_candidate` /
//!   `close`) は内部の mpsc コマンドチャネルにメッセージを投げる。run_loop が
//!   コマンドを取り出し、`Rtc` を進めて応答する。
//! - 受信 RTP (`Event::MediaData`) は `media_in_tx` (現状はトレースのみ。
//!   Issue #29 で Call Manager 結線) に流す。
//! - ローカル候補は接続確定時 (バインド済み UDP の host candidate) に
//!   `local_cand_tx` に送出される。`take_local_candidates` で 1 度だけ
//!   受信側を取り出せる。
//!
//! # ICE モード
//!
//! ICE-Lite を採用する。sabiden は静的 IP/ポートを前提にしているため、
//! ホスト側で STUN/TURN を喋る必要がない。ブラウザ側が controlling、sabiden が
//! controlled になる。
//!
//! # 制約 / TODO
//!
//! - 本 PR では Opus RTP の中継までを範囲とし、G.711 トランスコードと
//!   Call Manager への結線は後続 PR で対応する (Opus パススルーは Issue #29
//!   側の `Transcoder` を再利用する流れ)。
//! - `ice_servers` (TURN) は SDP に乗せる選択肢として config 化したが、
//!   実 TURN allocate (Long-Term Credentials) は別 PR。
//! - UDP ポート範囲は最低限の挙動 (範囲内でランダム選択) のみ。複数同時
//!   セッションでのポート再利用回避は将来課題。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use rand::Rng;
use str0m::change::{SdpAnswer, SdpOffer};
use str0m::media::{Direction, MediaKind, MediaTime, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{sleep_until, Instant as TokioInstant};
use tracing::{debug, info, trace, warn};

use super::peer::{MediaFrame, PeerSession};
use crate::sdp::builder::DtlsIceParams;

/// PWA → orchestrator 方向の MediaFrame mpsc バッファ容量。
///
/// 20 ms ごとに 1 frame、 transcoder 側で 1 frame 処理 (~数 ms) なので
/// 64 frame ≒ 1.3 秒分。 NGN レッグ pacing 不在の高負荷時にも数秒の
/// 余裕がある。 RFC 3550 §6.4.1 ジッタ計算は受信側 (transcoder) で行う。
const MEDIA_RX_BUFFER: usize = 64;

/// `[webrtc]` config からこのバックエンド向けに切り出した最小限のパラメータ。
#[derive(Debug, Clone)]
pub struct Str0mConfig {
    /// ICE host candidate に載せる IP。設定必須。
    pub public_ip: IpAddr,
    /// メディア用 UDP ポート範囲 (inclusive)。
    pub port_range: (u16, u16),
    /// SDP に乗せる ICE server URL (TURN/STUN)。
    /// 本 PR ではブラウザ側に提示するためのメタ情報として保持するのみ。
    pub ice_servers: Vec<String>,
}

impl Str0mConfig {
    /// `crate::config::WebRtcConfig` から [`Str0mConfig`] を組み立てる。
    /// `public_ip` 未設定 / `udp_port_range` 不正なら `Err`。
    pub fn from_webrtc(cfg: &crate::config::WebRtcConfig) -> Result<Self> {
        let ip_str = cfg
            .public_ip
            .as_deref()
            .ok_or_else(|| anyhow!("[webrtc] public_ip が未設定 (str0m バックエンドでは必須)"))?;
        let public_ip: IpAddr = ip_str
            .parse()
            .with_context(|| format!("public_ip パース失敗: {}", ip_str))?;
        let port_range = parse_port_range(cfg.udp_port_range.as_deref().unwrap_or("40000-40999"))?;
        Ok(Self {
            public_ip,
            port_range,
            ice_servers: cfg.ice_servers.clone(),
        })
    }
}

/// `"40000-40999"` 形式をパース。両端 inclusive、低 < 高 を要求。
pub fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    let (lo, hi) = s
        .split_once('-')
        .ok_or_else(|| anyhow!("udp_port_range: '<lo>-<hi>' 形式必須"))?;
    let lo: u16 = lo.trim().parse().context("udp_port_range の下限")?;
    let hi: u16 = hi.trim().parse().context("udp_port_range の上限")?;
    if lo >= hi {
        return Err(anyhow!("udp_port_range: 下限 < 上限"));
    }
    Ok((lo, hi))
}

/// run_loop に送るコマンド。
enum Command {
    AcceptOffer {
        sdp: String,
        reply: oneshot::Sender<Result<String>>,
    },
    AddRemoteCandidate {
        candidate: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// sabiden 側を offerer として PCMU 音声の SDP オファを生成する。
    /// NGN → ブラウザ着信フローで、NGN から受け取った AVP オファに対し
    /// sabiden が DTLS-SRTP/SAVPF オファをブラウザ向けに作る用途。
    CreateOffer {
        reply: oneshot::Sender<Result<String>>,
    },
    /// `CreateOffer` で生成したオファに対するブラウザ answer を受理する。
    AcceptAnswer {
        sdp: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// 現在の Rtc から local DTLS fingerprint と ICE 認証情報を取り出す。
    /// AVP↔SAVPF SDP 変換ヘルパに渡す目的。
    GetLocalDtlsParams {
        setup: String,
        reply: oneshot::Sender<Result<DtlsIceParams>>,
    },
    /// orchestrator → str0m 方向の音声フレーム送信
    /// (RFC 8835 §3 WebRTC media plane)。 run_loop が
    /// `Rtc::writer(mid).write(pt, wallclock, rtp_time, payload)` で
    /// SRTP 化して UDP に出す。
    SendMedia { frame: MediaFrame },
    Close,
}

/// [`PeerSession`] の str0m 実装。
pub struct Str0mPeerSession {
    cmd_tx: mpsc::Sender<Command>,
    /// `take_local_candidates` で 1 度だけ取り出される。
    local_cand_rx: Mutex<Option<mpsc::Receiver<String>>>,
    /// `take_media_rx` で 1 度だけ取り出される (Issue #87)。
    /// run_loop が `Event::MediaData` を受けたときに 1 frame を流す。
    media_in_rx: Mutex<Option<mpsc::Receiver<MediaFrame>>>,
}

impl Str0mPeerSession {
    /// 新しいセッションを起動する。内部で UDP ソケットをバインドし、
    /// run_loop タスクを spawn する。
    pub async fn new(cfg: Str0mConfig) -> Result<Arc<Self>> {
        let socket = bind_udp_in_range(&cfg).await?;
        let local_addr = socket.local_addr()?;
        let host_advert = SocketAddr::new(cfg.public_ip, local_addr.port());
        info!(
            local_bind = %local_addr,
            host_candidate = %host_advert,
            "str0m: UDP socket bound"
        );

        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(32);
        let (local_cand_tx, local_cand_rx) = mpsc::channel::<String>(8);
        // Issue #87: ブラウザ → orchestrator の Opus メディアフレーム経路
        // (RFC 7587 / RFC 8835 §3)。 run_loop の `Event::MediaData` から
        // 1 frame ずつ流す。
        let (media_in_tx, media_in_rx) = mpsc::channel::<MediaFrame>(MEDIA_RX_BUFFER);

        // ICE host candidate を生成 (str0m に登録するアドレスは "対外的に
        // ブラウザが到達するアドレス"。Cloudflare Tunnel の場合は LAN IP でも
        // tunnel が解決するので問題ない)。
        let host = Candidate::host(host_advert, "udp")
            .map_err(|e| anyhow!("str0m host candidate: {}", e))?;

        // ICE-Lite で Rtc を構築。ICE-Lite では我々が controlled、ブラウザが
        // controlling。STUN binding は受けるだけ。
        // PCMU/8000 を有効化し、それ以外の音声/ビデオコーデックは無効化する
        // (NGN ↔ ブラウザの間を G.711 μ-law でパススルーする想定。Opus は
        //  本パスでは使わない)。
        let rtc = RtcConfig::new()
            .set_ice_lite(true)
            .clear_codecs()
            .enable_pcmu(true)
            .build(Instant::now());

        let socket = Arc::new(socket);
        let local_bind = local_addr;

        tokio::spawn(run_loop(RunCtx {
            rtc,
            socket: socket.clone(),
            local_bind,
            host_candidate: host,
            cmd_rx,
            local_cand_tx,
            media_in_tx,
            audio_mid: None,
            pending_offer: None,
        }));

        Ok(Arc::new(Self {
            cmd_tx,
            local_cand_rx: Mutex::new(Some(local_cand_rx)),
            media_in_rx: Mutex::new(Some(media_in_rx)),
        }))
    }

    /// 現在の str0m インスタンスから ICE-ufrag / ICE-pwd / DTLS fingerprint
    /// を取り出す。`setup` には SDP の `a=setup:<role>` に書く役割を入れる
    /// (sabiden が server として answer する場合は `"passive"`、offer する場合は
    /// `"actpass"`)。
    ///
    /// 取得した [`DtlsIceParams`] は [`crate::sdp::builder::convert_avp_to_savpf`]
    /// に渡して NGN→ブラウザ向け SDP を生成するのに使う。
    pub async fn local_dtls_params(&self, setup: &str) -> Result<DtlsIceParams> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::GetLocalDtlsParams {
                setup: setup.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow!("str0m run_loop が既に終了"))?;
        rx.await
            .map_err(|_| anyhow!("str0m run_loop が応答せず終了"))?
    }
}

#[async_trait]
impl PeerSession for Str0mPeerSession {
    async fn handle_offer(&self, sdp: &str) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::AcceptOffer {
                sdp: sdp.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow!("str0m run_loop が既に終了"))?;
        rx.await
            .map_err(|_| anyhow!("str0m run_loop が応答せず終了"))?
    }

    /// sabiden 側を offerer として PCMU 音声の WebRTC オファを生成する
    /// (RFC 3264 §5)。
    ///
    /// NGN→ブラウザ着信フローで使う。NGN から受け取った RTP/AVP の SDP
    /// オファをそのままブラウザに渡すと、ブラウザの WebRTC スタックは
    /// DTLS-SRTP 必須 (RFC 8827 §6.5) / ICE 認証情報必須 (RFC 8839 §4.1)
    /// で拒絶する。代わりに sabiden 側で新規 WebRTC オファを作って push する。
    async fn create_offer(&self) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::CreateOffer { reply: tx })
            .await
            .map_err(|_| anyhow!("str0m run_loop が既に終了"))?;
        rx.await
            .map_err(|_| anyhow!("str0m run_loop が応答せず終了"))?
    }

    /// `create_offer` で出した SDP に対するブラウザ answer を受理する
    /// (RFC 3264 §6)。
    async fn accept_answer(&self, sdp: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::AcceptAnswer {
                sdp: sdp.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow!("str0m run_loop が既に終了"))?;
        rx.await
            .map_err(|_| anyhow!("str0m run_loop が応答せず終了"))?
    }

    async fn add_ice_candidate(&self, candidate: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::AddRemoteCandidate {
                candidate: candidate.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| anyhow!("str0m run_loop が既に終了"))?;
        rx.await
            .map_err(|_| anyhow!("str0m run_loop が応答せず終了"))?
    }

    async fn take_local_candidates(&self) -> Option<mpsc::Receiver<String>> {
        self.local_cand_rx.lock().await.take()
    }

    /// Issue #87: ブラウザ → orchestrator の Opus メディアフレーム
    /// receiver を 1 度だけ取り出す (RFC 8835 §3 WebRTC media plane)。
    async fn take_media_rx(&self) -> Option<mpsc::Receiver<MediaFrame>> {
        self.media_in_rx.lock().await.take()
    }

    /// Issue #87: orchestrator → ブラウザの Opus メディアフレーム送信
    /// (RFC 3550 §5.1 / RFC 7587)。 run_loop に command で渡し、
    /// `Rtc::writer(mid).write` 経由で SRTP 化して UDP に送出する。
    async fn send_media(&self, frame: MediaFrame) -> Result<()> {
        // run_loop が既に終了している場合は受信側 drop で `Err` になる。
        // 呼出側 (RtpBridge ループ) は loop continue で次フレームに進む
        // 想定。 panic / unwrap は使わない。
        self.cmd_tx
            .send(Command::SendMedia { frame })
            .await
            .map_err(|_| anyhow!("str0m run_loop が既に終了"))
    }

    async fn close(&self) -> Result<()> {
        // ベストエフォート: run_loop が既に終了していても無視。
        let _ = self.cmd_tx.send(Command::Close).await;
        Ok(())
    }
}

struct RunCtx {
    rtc: Rtc,
    socket: Arc<UdpSocket>,
    local_bind: SocketAddr,
    host_candidate: Candidate,
    cmd_rx: mpsc::Receiver<Command>,
    local_cand_tx: mpsc::Sender<String>,
    /// Issue #87: 受信 Opus フレームを orchestrator に流すチャネル。
    /// `Event::MediaData` 1 件ごとに 1 frame 送る。 受信側が居なければ
    /// `try_send` で drop する (RFC 3550 §6.4.1: 失われた RTP パケット
    /// はエンド端側でジッタ計算する) — orchestrator 側で `take_media_rx`
    /// しない構成では media は流れないが ICE/DTLS は確立する。
    media_in_tx: mpsc::Sender<MediaFrame>,
    /// 最初に negotiate された audio Mid (`Event::MediaAdded` で確定)。
    /// `Command::SendMedia` で `Rtc::writer(mid)` に渡すために保持する。
    audio_mid: Option<Mid>,
    /// `create_offer` で出した SDP の保留オファ。`accept_answer` で消費する。
    pending_offer: Option<str0m::change::SdpPendingOffer>,
}

/// str0m を駆動する run loop。
///
/// 各イテレーションで:
/// 1. `poll_output()` で次のアクション (Transmit / Timeout / Event) を取得
/// 2. Transmit ならソケットへ送信、Event なら処理
/// 3. Timeout / 空ループになったら、UDP recv または cmd_rx 受信を待ち
///    `handle_input` に回す
async fn run_loop(mut ctx: RunCtx) {
    let mut buf = vec![0u8; 2048];
    let mut sent_local_cand = false;
    let mut closed = false;

    // 初期 host candidate を str0m に登録する。
    ctx.rtc.add_local_candidate(ctx.host_candidate.clone());

    while ctx.rtc.is_alive() && !closed {
        // 1) poll_output を timeout 値が出るまで回す
        let next_timeout = match ctx.rtc.poll_output() {
            Ok(Output::Timeout(t)) => t,
            Ok(Output::Transmit(t)) => {
                if let Err(e) = ctx.socket.send_to(&t.contents, t.destination).await {
                    warn!(error = %e, dest = %t.destination, "str0m: UDP send 失敗");
                }
                continue;
            }
            Ok(Output::Event(ev)) => {
                handle_event(
                    &ev,
                    &ctx.local_cand_tx,
                    &mut sent_local_cand,
                    &ctx.host_candidate,
                    &ctx.media_in_tx,
                    &mut ctx.audio_mid,
                )
                .await;
                continue;
            }
            Err(e) => {
                warn!(error = %e, "str0m: poll_output エラー、ループ終了");
                break;
            }
        };

        // 2) timeout / UDP / コマンドのどれかを待つ
        let now = Instant::now();
        let dur = next_timeout.saturating_duration_since(now);
        let deadline = TokioInstant::now() + dur;

        tokio::select! {
            biased;

            cmd = ctx.cmd_rx.recv() => {
                match cmd {
                    Some(Command::AcceptOffer { sdp, reply }) => {
                        let r = accept_offer(&mut ctx.rtc, &sdp);
                        let _ = reply.send(r);
                    }
                    Some(Command::AddRemoteCandidate { candidate, reply }) => {
                        let r = add_remote_candidate(&mut ctx.rtc, &candidate);
                        let _ = reply.send(r);
                    }
                    Some(Command::CreateOffer { reply }) => {
                        let r = create_offer(&mut ctx.rtc, &mut ctx.pending_offer);
                        let _ = reply.send(r);
                    }
                    Some(Command::AcceptAnswer { sdp, reply }) => {
                        let r = accept_answer(&mut ctx.rtc, &mut ctx.pending_offer, &sdp);
                        let _ = reply.send(r);
                    }
                    Some(Command::GetLocalDtlsParams { setup, reply }) => {
                        let r = get_local_dtls_params(&mut ctx.rtc, &setup);
                        let _ = reply.send(r);
                    }
                    Some(Command::SendMedia { frame }) => {
                        write_media(&mut ctx.rtc, ctx.audio_mid, &frame);
                    }
                    Some(Command::Close) | None => {
                        debug!("str0m: close コマンド受信");
                        closed = true;
                        ctx.rtc.disconnect();
                    }
                }
            }

            r = ctx.socket.recv_from(&mut buf) => {
                match r {
                    Ok((n, src)) => {
                        let receive = Receive::new(
                            Protocol::Udp,
                            src,
                            ctx.local_bind,
                            &buf[..n],
                        );
                        match receive {
                            Ok(rx) => {
                                let input = Input::Receive(Instant::now(), rx);
                                if ctx.rtc.accepts(&input) {
                                    if let Err(e) = ctx.rtc.handle_input(input) {
                                        warn!(error = %e, "str0m: handle_input エラー");
                                    }
                                } else {
                                    trace!(src = %src, len = n, "str0m: 非関係パケット (drop)");
                                }
                            }
                            Err(e) => {
                                trace!(error = %e, "str0m: Receive::new エラー (drop)");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "str0m: UDP recv エラー");
                        break;
                    }
                }
            }

            _ = sleep_until(deadline) => {
                if let Err(e) = ctx.rtc.handle_input(Input::Timeout(Instant::now())) {
                    warn!(error = %e, "str0m: timeout handle_input エラー");
                }
            }
        }
    }

    info!("str0m run_loop 終了");
}

fn accept_offer(rtc: &mut Rtc, sdp: &str) -> Result<String> {
    let offer = SdpOffer::from_sdp_string(sdp).map_err(|e| anyhow!("SDP offer パース: {}", e))?;
    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .map_err(|e| anyhow!("str0m accept_offer: {}", e))?;
    Ok(answer.to_sdp_string())
}

/// sabiden を offerer として PCMU 音声 1 本のオファを生成する。
///
/// `pending` には消費前の保留オファを保存する。既存の保留オファがある場合は
/// 上書きせずエラーを返す (ブラウザに二重 offer が出ると state machine が
/// 壊れる)。
fn create_offer(
    rtc: &mut Rtc,
    pending: &mut Option<str0m::change::SdpPendingOffer>,
) -> Result<String> {
    if pending.is_some() {
        return Err(anyhow!(
            "create_offer: 既に保留オファあり (accept_answer 待ち)"
        ));
    }
    let mut api = rtc.sdp_api();
    api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, p) = api
        .apply()
        .ok_or_else(|| anyhow!("create_offer: 変更が空 (codec 設定漏れ?)"))?;
    *pending = Some(p);
    Ok(offer.to_sdp_string())
}

/// 保留中の offer に対するブラウザ answer を str0m に渡す。
fn accept_answer(
    rtc: &mut Rtc,
    pending: &mut Option<str0m::change::SdpPendingOffer>,
    sdp: &str,
) -> Result<()> {
    let p = pending
        .take()
        .ok_or_else(|| anyhow!("accept_answer: 対応する保留 offer なし"))?;
    let answer =
        SdpAnswer::from_sdp_string(sdp).map_err(|e| anyhow!("SDP answer パース: {}", e))?;
    rtc.sdp_api()
        .accept_answer(p, answer)
        .map_err(|e| anyhow!("str0m accept_answer: {}", e))?;
    Ok(())
}

/// 現 Rtc の local DTLS fingerprint と ICE 認証情報を取り出して
/// SDP 変換ヘルパ用 [`DtlsIceParams`] にまとめる。
fn get_local_dtls_params(rtc: &mut Rtc, setup: &str) -> Result<DtlsIceParams> {
    let api = rtc.direct_api();
    let creds = api.local_ice_credentials();
    let fp = api.local_dtls_fingerprint();
    // Fingerprint::Display は "<algo> <HEX:...>" のフォーマットを直接吐くので
    // SDP 行末に乗せられる (DtlsIceParams::fingerprint の規約と一致)。
    let mut p = DtlsIceParams::new(creds.ufrag.clone(), creds.pass.clone(), fp.to_string());
    p.setup = setup.to_string();
    Ok(p)
}

fn add_remote_candidate(rtc: &mut Rtc, candidate: &str) -> Result<()> {
    // ブラウザは "candidate:..." 文字列をそのまま送ってくる。
    // 接頭辞 "a=" や "candidate:" の有無に対応する。
    let trimmed = candidate
        .trim()
        .trim_start_matches("a=")
        .trim_start_matches("candidate:");
    // str0m::Candidate::from_sdp_string は "candidate:..." 接頭辞も許容するが、
    // 念のため復元してから渡す。
    let sdp_form = if trimmed.is_empty() {
        return Err(anyhow!("空の ICE candidate"));
    } else {
        format!("candidate:{}", trimmed)
    };
    let cand = Candidate::from_sdp_string(&sdp_form)
        .map_err(|e| anyhow!("ICE candidate パース: {}", e))?;
    rtc.add_remote_candidate(cand);
    Ok(())
}

async fn handle_event(
    ev: &Event,
    local_cand_tx: &mpsc::Sender<String>,
    sent_local_cand: &mut bool,
    host_candidate: &Candidate,
    media_in_tx: &mpsc::Sender<MediaFrame>,
    audio_mid: &mut Option<Mid>,
) {
    match ev {
        Event::IceConnectionStateChange(s) => {
            debug!(state = ?s, "str0m: ICE state");
            // ブラウザに送るべきローカル候補は host_candidate 1 つ
            // (ICE-Lite なので reflexive/relay は本ノードでは生成しない)。
            // 接続が動き始めたタイミングで 1 度だけ trickle 送出する。
            if !*sent_local_cand {
                let line = host_candidate.to_sdp_string();
                if let Err(e) = local_cand_tx.try_send(line) {
                    debug!(error = %e, "str0m: local candidate 送出に失敗 (受信側未接続)");
                }
                *sent_local_cand = true;
            }
        }
        Event::Connected => {
            info!("str0m: DTLS 確立完了 (PeerConnection ready)");
        }
        Event::MediaAdded(m) => {
            info!(mid = ?m.mid, kind = ?m.kind, dir = ?m.direction, "str0m: media added");
            // Issue #87: SendMedia で `Rtc::writer(mid)` に渡すために
            // 最初の audio mid を保存する。 PCMU only 構成なので audio は 1 本だけ。
            if matches!(m.kind, MediaKind::Audio) && audio_mid.is_none() {
                *audio_mid = Some(m.mid);
            }
        }
        Event::MediaData(d) => {
            // Issue #87: 受信 Opus フレームを orchestrator (RtpBridge) に渡す。
            // RFC 7587 §4.2: Opus は通常 20 ms = 960 samples@48kHz だが、
            // 本実装は RtpTime / payload を素通しして transcoder 側で扱う。
            trace!(
                mid = ?d.mid,
                pt = ?d.pt,
                bytes = d.data.len(),
                "str0m: 受信 media frame"
            );
            let frame = MediaFrame {
                pt: u8::from(*d.pt),
                rtp_time: d.time.numer() as u32,
                payload: d.data.clone(),
                network_time: d.network_time,
            };
            // 受信側未接続 / 満杯時は drop (RFC 3550 §6.4.1: パケットロス想定)。
            // panic / unwrap は禁止 (CLAUDE.md §6.5)。
            if let Err(e) = media_in_tx.try_send(frame) {
                trace!(error = %e, "str0m: media_in_tx try_send 失敗 (drop)");
            }
        }
        Event::RtpPacket(_) => {
            // RTP モードでは PR スコープ外。Event::MediaData を採用するため到達しない。
        }
        _ => {}
    }
}

/// Issue #87: orchestrator → str0m の音声フレームを `Rtc::writer(mid).write` で
/// SRTP 化して送出する。
///
/// # 仕様
///
/// - **RFC 3550 §5.1**: `pt` (payload type) と `rtp_time` (timestamp) は
///   フレーム単位の単調増加数。 sabiden 側 transcoder が NGN→PWA 方向で
///   生成した値をそのまま渡す前提。
/// - **RFC 7587 §4.2** (Opus payload format): WebRTC は通常 48 kHz 単位の
///   timestamp。 PCMU 直送経路では 8 kHz。 codec config に依存するため
///   呼出側責務とする。
/// - **str0m `Writer::write` の仕様** (`media/writer.rs`): Connected 前の
///   write は drop されるが panic はしない。 mid 不在 / pt 未 negotiate は
///   `Err(RtcError)` を返すので警告のみ。
fn write_media(rtc: &mut Rtc, audio_mid: Option<Mid>, frame: &MediaFrame) {
    let Some(mid) = audio_mid else {
        trace!(pt = frame.pt, "str0m: audio mid 未確定 → media drop");
        return;
    };
    let writer = match rtc.writer(mid) {
        Some(w) => w,
        None => {
            trace!(?mid, "str0m: writer 取得失敗 (media 未 negotiate?)");
            return;
        }
    };
    let pt: Pt = Pt::from(frame.pt);
    // RFC 7587: Opus は 48 kHz、 RFC 3551: PCMU は 8 kHz。 codec 判定は
    // 呼出側 (transcoder) が `frame.pt` で済ませているので、 ここでは
    // negotiate 済 codec の clock rate を `Frequency` として取り出し、
    // RTP timestamp を `MediaTime` に組み立てる。
    let freq = match writer
        .payload_params()
        .find(|p| p.pt() == pt)
        .map(|p| p.spec().clock_rate)
    {
        Some(f) => f,
        None => {
            trace!(pt = frame.pt, "str0m: PT 未 negotiate → media drop");
            return;
        }
    };
    let media_time = MediaTime::new(u64::from(frame.rtp_time), freq);
    if let Err(e) = writer.write(pt, frame.network_time, media_time, frame.payload.clone()) {
        trace!(error = %e, "str0m: writer.write 失敗 (Connected 前 / pt 不一致)");
    }
}

/// `cfg.port_range` 内で空きポートが見つかるまで `bind` をリトライ。
///
/// 範囲が小さい場合は数十回程度のリトライで諦めてエラーを返す。
async fn bind_udp_in_range(cfg: &Str0mConfig) -> Result<UdpSocket> {
    let (lo, hi) = cfg.port_range;
    // ホスト側は IPv4 ANY で listen し、advertise だけ public_ip に置き換える。
    // (Cloudflare Tunnel / NAT 構成での一般的なパターン)
    let bind_ip: IpAddr = match cfg.public_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => return Err(anyhow!("IPv6 public_ip は未対応 (TODO)")),
    };

    // ThreadRng は !Send のため、ports を先に集めて await を含むループ外で生成する。
    let max_attempts = 64usize.min((hi - lo) as usize + 1);
    let ports: Vec<u16> = {
        let mut rng = rand::thread_rng();
        (0..max_attempts).map(|_| rng.gen_range(lo..=hi)).collect()
    };
    for port in ports {
        match UdpSocket::bind(SocketAddr::new(bind_ip, port)).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                trace!(port, error = %e, "str0m: UDP bind 失敗、リトライ");
            }
        }
    }
    Err(anyhow!(
        "UDP bind: ポート範囲 {}-{} に空きが見つからない",
        lo,
        hi
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WebRtcConfig;

    #[test]
    fn parse_port_range_ok() {
        assert_eq!(parse_port_range("40000-40999").unwrap(), (40000, 40999));
        assert_eq!(parse_port_range(" 1000 - 2000 ").unwrap(), (1000, 2000));
    }

    #[test]
    fn parse_port_range_rejects_bad_input() {
        assert!(parse_port_range("nope").is_err());
        assert!(parse_port_range("100").is_err());
        assert!(parse_port_range("200-100").is_err());
        assert!(parse_port_range("200-200").is_err());
    }

    #[test]
    fn str0m_config_requires_public_ip() {
        let cfg = WebRtcConfig {
            backend: "str0m".into(),
            ..WebRtcConfig::default()
        };
        assert!(Str0mConfig::from_webrtc(&cfg).is_err());
    }

    #[test]
    fn str0m_config_parses_basic() {
        let cfg = WebRtcConfig {
            backend: "str0m".into(),
            public_ip: Some("203.0.113.1".into()),
            udp_port_range: Some("40000-40099".into()),
            ice_servers: vec!["turn:turn.example.com:3478".into()],
            ..WebRtcConfig::default()
        };
        let s = Str0mConfig::from_webrtc(&cfg).unwrap();
        assert_eq!(s.public_ip, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(s.port_range, (40000, 40099));
        assert_eq!(s.ice_servers.len(), 1);
    }

    #[test]
    fn str0m_config_default_port_range() {
        let cfg = WebRtcConfig {
            backend: "str0m".into(),
            public_ip: Some("127.0.0.1".into()),
            ..WebRtcConfig::default()
        };
        let s = Str0mConfig::from_webrtc(&cfg).unwrap();
        assert_eq!(s.port_range, (40000, 40999));
    }

    /// 実 UDP socket をバインドして run_loop を起動。
    /// 実 SDP オファを与えて answer を受け取る往復が成立することを確認する。
    /// ICE/DTLS は完了しないが、`accept_offer` まで到達することが要点。
    #[tokio::test]
    async fn str0m_session_accept_offer_smoke() {
        // ローカル loopback アドレスで bind。port range は自由ポートで十分。
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (45000, 45999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        // ブラウザが投げてくる典型的な offer を模倣 (str0m 0.19 が解釈できる
        // 必須属性のみ含める)。
        let offer = include_str!("testdata/firefox_offer.sdp");
        let answer = session.handle_offer(offer).await.expect("answer 生成");
        assert!(answer.contains("v=0"));
        assert!(answer.contains("m=audio"));
        // ICE-Lite を有効にしているので answer に a=ice-lite が必ず入る
        assert!(
            answer.contains("a=ice-lite") || answer.contains("ice-lite"),
            "answer に ice-lite が含まれない: {}",
            answer
        );
        let _ = session.close().await;
    }

    #[tokio::test]
    async fn str0m_session_rejects_bad_offer() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (46000, 46999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let r = session.handle_offer("not-sdp").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn str0m_session_take_local_candidates_once() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (47000, 47999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let first = session.take_local_candidates().await;
        assert!(first.is_some(), "1 度目は受信器が取れる");
        let second = session.take_local_candidates().await;
        assert!(second.is_none(), "2 度目は None");
    }

    #[tokio::test]
    async fn str0m_session_add_ice_candidate_accepts_browser_format() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (48000, 48999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        // まず offer を渡しておく (remote ufrag を確立しないと一部実装が拒む)
        let offer = include_str!("testdata/firefox_offer.sdp");
        let _ = session.handle_offer(offer).await.unwrap();

        // ブラウザが送ってくる典型的な host candidate (a= プレフィックス無し)
        let cand = "candidate:1 1 udp 2122252543 192.168.1.10 56789 typ host";
        session.add_ice_candidate(cand).await.expect("受理");

        // "a=" 前置きでも受理する
        let cand2 = "a=candidate:2 1 udp 2122252543 192.168.1.10 56790 typ host";
        session
            .add_ice_candidate(cand2)
            .await
            .expect("受理 (a= 付)");
    }

    /// `local_dtls_params` が ufrag / pwd / fingerprint を non-empty に返す。
    #[tokio::test]
    async fn str0m_session_exposes_local_dtls_params() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (49000, 49999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let p = session
            .local_dtls_params("passive")
            .await
            .expect("取得成功");
        assert!(!p.ice_ufrag.is_empty(), "ufrag が空");
        assert!(!p.ice_pwd.is_empty(), "pwd が空");
        // fingerprint は "<algo> <hex:...>" 形式 (DtlsIceParams の規約)
        assert!(
            p.fingerprint.starts_with("sha-256 ") || p.fingerprint.starts_with("sha-1 "),
            "fingerprint 形式不正: {}",
            p.fingerprint
        );
        assert!(p.fingerprint.contains(':'), "fingerprint hex 区切り欠落");
        assert_eq!(p.setup, "passive");
    }

    /// sabiden 主導で SDP オファ (PCMU 1 本) を生成する。
    /// NGN→ブラウザ着信フローで使う想定。
    #[tokio::test]
    async fn str0m_session_create_offer_returns_pcmu_savpf() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (50000, 50999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let sdp = session.create_offer().await.expect("offer 生成");
        // PCMU codec + SAVPF proto がオファに乗っているか
        assert!(sdp.contains("m=audio"), "audio m= が無い: {}", sdp);
        assert!(
            sdp.contains("UDP/TLS/RTP/SAVPF"),
            "DTLS-SRTP proto 欠落: {}",
            sdp
        );
        assert!(
            sdp.to_uppercase().contains("PCMU"),
            "PCMU rtpmap 欠落: {}",
            sdp
        );
        // ICE-Lite なので a=ice-lite が含まれるはず
        assert!(sdp.contains("ice-lite"), "ice-lite 欠落: {}", sdp);
    }

    /// `create_offer` を 2 回連続で呼ぶと 2 回目はエラー (保留 offer 1 件のみ許容)。
    #[tokio::test]
    async fn str0m_session_create_offer_twice_errors() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (51000, 51999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let _ = session.create_offer().await.expect("1 回目");
        let r = session.create_offer().await;
        assert!(r.is_err(), "2 回目は保留中のためエラーであるべき");
    }

    /// Issue #87: `take_media_rx` は 1 度だけ Some、 2 度目は None。
    /// (sender 側生存中は他者が同じ receiver を奪えない。)
    #[tokio::test]
    async fn str0m_session_take_media_rx_once() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (54000, 54999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let first = session.take_media_rx().await;
        assert!(first.is_some(), "1 度目は受信器が取れる");
        let second = session.take_media_rx().await;
        assert!(second.is_none(), "2 度目は None");
        let _ = session.close().await;
    }

    /// Issue #87: `send_media` は run_loop 終了済でも Result で返す
    /// (panic / unwrap 禁止)。 Connected 前なら drop されるが Ok。
    #[tokio::test]
    async fn str0m_session_send_media_does_not_panic_before_connected() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (55000, 55999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let frame = MediaFrame {
            pt: 0, // PCMU
            rtp_time: 160,
            payload: vec![0xff; 160],
            network_time: std::time::Instant::now(),
        };
        // Connected 前 / mid 未確定 → run_loop 内部で drop されるが
        // command 送信自体は成功するはず。
        session.send_media(frame).await.expect("command 送信成功");
        let _ = session.close().await;
    }

    /// Issue #87: close 後の `send_media` は Err を返す (panic 禁止)。
    #[tokio::test]
    async fn str0m_session_send_media_after_close_returns_error() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (56000, 56999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let _ = session.close().await;
        // run_loop が close 命令で抜けるのを待つ
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let frame = MediaFrame {
            pt: 0,
            rtp_time: 0,
            payload: vec![],
            network_time: std::time::Instant::now(),
        };
        let r = session.send_media(frame).await;
        assert!(r.is_err(), "run_loop 終了後は Err になる: {:?}", r);
    }

    /// `accept_answer` は対応する保留オファが無ければエラーを返す。
    #[tokio::test]
    async fn str0m_session_accept_answer_without_offer_errors() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (52000, 52999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        let r = session.accept_answer("v=0\r\n").await;
        assert!(r.is_err());
    }

    /// NGN→ブラウザ着信フロー想定の統合テスト:
    /// 1. NGN の RTP/AVP オファ (PCMU PT=0) を擬似的に用意
    /// 2. str0m から local DTLS / ICE 認証情報を取り出す
    /// 3. `convert_avp_to_savpf` でブラウザ向け SDP に変換
    /// 4. 変換結果が SAVPF / DTLS-SRTP / PCMU を保ったまま再パース可能であること
    /// 5. 模擬ブラウザ answer を生成し `convert_savpf_to_avp` で NGN 用に逆変換
    ///    → PCMU が保持されていること
    #[tokio::test]
    async fn ngn_to_browser_sdp_conversion_round_trip() {
        use crate::sdp::builder::{convert_avp_to_savpf, convert_savpf_to_avp};
        use crate::sdp::SessionDescription;

        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (53500, 53999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();

        // (2) str0m から local DTLS / ICE 認証情報を取得
        // NGN→ブラウザ向けは sabiden が answer 側になるので setup=passive。
        let params = session
            .local_dtls_params("passive")
            .await
            .expect("dtls params");

        // (1) NGN 由来の RTP/AVP オファ
        let ngn_offer = b"v=0\r\n\
                          o=- 0 0 IN IP4 192.0.2.10\r\n\
                          s=-\r\n\
                          c=IN IP4 192.0.2.10\r\n\
                          t=0 0\r\n\
                          m=audio 30000 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=ptime:20\r\n\
                          a=sendrecv\r\n";

        // (3) ブラウザ向け SAVPF SDP を生成
        let browser_offer = convert_avp_to_savpf(ngn_offer, &params).expect("AVP->SAVPF 変換");
        let s = std::str::from_utf8(&browser_offer).unwrap();
        assert!(s.contains("UDP/TLS/RTP/SAVPF"), "SAVPF proto 不在");
        assert!(s.contains("a=rtpmap:0 PCMU/8000"), "PCMU rtpmap 損失");
        assert!(s.contains("a=fingerprint:"), "fingerprint 行欠落");
        assert!(s.contains("a=ice-ufrag:"), "ice-ufrag 行欠落");
        assert!(s.contains("a=ice-pwd:"), "ice-pwd 行欠落");
        assert!(s.contains("a=setup:passive"), "setup=passive 不在");
        assert!(s.contains("a=rtcp-mux"), "rtcp-mux 不在");
        // 再パース確認
        SessionDescription::parse(s).expect("変換結果が再パース可能");

        // (5) 模擬ブラウザ answer (典型的なフォーマット)。実際の ufrag/pwd は
        //     ブラウザ側で生成されるため、ここでは形式のみ検証する。
        let browser_answer = b"v=0\r\n\
                               o=mozilla 1 0 IN IP4 0.0.0.0\r\n\
                               s=-\r\n\
                               t=0 0\r\n\
                               a=group:BUNDLE 0\r\n\
                               m=audio 9 UDP/TLS/RTP/SAVPF 0\r\n\
                               c=IN IP4 0.0.0.0\r\n\
                               a=rtpmap:0 PCMU/8000\r\n\
                               a=ptime:20\r\n\
                               a=sendrecv\r\n\
                               a=ice-ufrag:browser\r\n\
                               a=ice-pwd:browserpasswordbrowserpassword\r\n\
                               a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
                               a=setup:active\r\n\
                               a=mid:0\r\n\
                               a=rtcp-mux\r\n";
        let ngn_answer = convert_savpf_to_avp(browser_answer).expect("SAVPF->AVP 変換");
        let parsed = SessionDescription::parse(std::str::from_utf8(&ngn_answer).unwrap()).unwrap();
        assert_eq!(parsed.media[0].protocol, "RTP/AVP");
        assert_eq!(parsed.media[0].formats, vec!["0"]);
        assert!(
            parsed.find_rtpmap(0).is_some(),
            "PCMU rtpmap が NGN 用 SDP から欠落"
        );
    }
}
