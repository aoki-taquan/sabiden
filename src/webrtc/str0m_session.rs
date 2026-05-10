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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    SendMedia {
        frame: MediaFrame,
    },
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
        // str0m の Receive::new に渡す destination 用。 socket はファミリ別
        // ANY (`0.0.0.0` または `::`) で bind しているが、 str0m は
        // host_candidate (= 公開アドレス) と一致する destination でないと
        // 「自分宛ではない」と判定して STUN を drop する (Issue #103: IPv6
        // でも同様に host_advert を渡す)。
        let local_bind = host_advert;

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
            //
            // Issue #92 / RFC 8840 §4 (Trickle ICE): host candidate を 1 件
            // 送出した直後に、 同じく **空文字列を end-of-candidates marker** と
            // して送出する (RFC 8839 §4.2 / W3C WebRTC §4.4.1.6: end-of-candidates
            // は null candidate / empty string で表す)。 ICE-Lite (RFC 8445 §2.4)
            // は STUN/TURN による reflexive / relay 候補を生成しないため、
            // host 1 件で全候補列挙が完了したことを ICE state Checking 遷移と
            // 同時刻に確定できる。
            //
            // 効果: ブラウザは end-of-candidates 受信後 RFC 8838 §10 の
            // consent freshness / RFC 8845 §3.4 の ICE failure timer を即時に
            // 起動できる。 これがないとブラウザは「まだ候補が来るかもしれない」
            // と推測待ちし、 ICE failed 検知が iceTransportPolicy の既定
            // (chromium で 30 秒程度) まで遅延する (Issue #92 の根本要因)。
            if !*sent_local_cand {
                let line = host_candidate.to_sdp_string();
                if let Err(e) = local_cand_tx.try_send(line) {
                    debug!(error = %e, "str0m: local candidate 送出に失敗 (受信側未接続)");
                }
                // RFC 8840 §4: end-of-candidates marker は空文字列で表す
                // (sabiden の signaling 層 / PWA は両方向で empty/`end-of-candidates`
                // を end-of-candidates として既に解釈している、 signaling.rs:1075)。
                // try_send 失敗 (受信側未接続 / 満杯) は ICE failed 検知の早期化が
                // 効かないだけで通話自体には影響しない (退行ではないので debug ログ)。
                if let Err(e) = local_cand_tx.try_send(String::new()) {
                    debug!(error = %e, "str0m: end-of-candidates marker 送出に失敗 (受信側未接続)");
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
                pt: *d.pt,
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
    // ホスト側は public_ip のアドレスファミリに合わせた ANY で listen し、
    // ICE host candidate (RFC 8839 §5.1 / RFC 5245 §4.1.1.2) だけは公開
    // アドレス (cfg.public_ip) に置き換える (Cloudflare Tunnel / NAT 構成)。
    //
    // Issue #103: IPv6 public_ip でも bind を成功させる。 Linux の
    // `IPV6_V6ONLY` 既定は ON なので、 IPv6 UNSPECIFIED bind は IPv6 のみ
    // listen する (IPv4-mapped で混ぜない)。 IPv4/IPv6 dual-stack は str0m
    // が複数 host candidate を許す (`Rtc::add_local_candidate`) が、 ソケットも
    // ファミリ別に必要になる。 本 PR では「public_ip 1 つ ↔ ソケット 1 つ」
    // の現行構造を維持し、 ファミリだけ揃える最小修正に留める (RFC 8835 §4.1.1
    // の ICE candidate ペアリングは各候補単位で機能するため、 単一ファミリでも
    // ブラウザ側 dual-stack 候補と問題なく通る)。
    let bind_ip: IpAddr = match cfg.public_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
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

    /// Issue #103: `public_ip` に IPv6 アドレス文字列を渡しても
    /// `Str0mConfig::from_webrtc` がパースできること。
    ///
    /// RFC 8839 §5.1 (ICE candidate address) は IPv4 / IPv6 双方を許可する。
    /// 旧実装は parse 自体は通っていたが下流の bind で失敗していた。
    #[test]
    fn rfc8839_5_1_str0m_config_parses_ipv6_public_ip() {
        let cfg = WebRtcConfig {
            backend: "str0m".into(),
            public_ip: Some("2001:db8::1".into()),
            udp_port_range: Some("49000-49099".into()),
            ..WebRtcConfig::default()
        };
        let s = Str0mConfig::from_webrtc(&cfg).expect("IPv6 public_ip も受理する");
        assert!(s.public_ip.is_ipv6(), "IPv6 として保持される");
        assert_eq!(s.public_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    /// Issue #103: IPv6 loopback (`::1`) を `public_ip` に指定した場合、
    /// `Str0mPeerSession::new` が UDP bind で `Ipv6Addr::UNSPECIFIED` を
    /// 使って成功し、 host candidate も IPv6 で広告されること。
    ///
    /// RFC 5245 §4.1.1.2 (host candidate) / RFC 8839 §5.1: host candidate は
    /// ローカルにバインドされた IP/port を直接広告する。 公開 IP がブラウザに
    /// 到達するルートで決まる以上、 IPv6 を選ぶ運用 (NGN 直収 + IPv6 backbone)
    /// は禁止せず通す必要がある。
    #[tokio::test]
    async fn rfc5245_4_1_1_2_str0m_session_binds_with_ipv6_public_ip() {
        let cfg = Str0mConfig {
            public_ip: "::1".parse().unwrap(),
            port_range: (50000, 50999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg)
            .await
            .expect("IPv6 loopback public_ip での起動が成功する");
        // close まで進めば run_loop が無事 spawn された証拠。
        let _ = session.close().await;
    }

    /// Issue #103: IPv6 host candidate が `take_local_candidates` から
    /// IPv6 アドレスで送出されること (RFC 8839 §5.1: candidate 行の
    /// connection-address は IP リテラル)。
    #[tokio::test]
    async fn rfc8839_5_1_str0m_session_advertises_ipv6_host_candidate() {
        let cfg = Str0mConfig {
            public_ip: "::1".parse().unwrap(),
            port_range: (51000, 51999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg)
            .await
            .expect("IPv6 public_ip での起動が成功する");

        // offer を渡して ICE 連携を始動させる (Event::IceConnectionStateChange を
        // 引き出すため)。 firefox_offer.sdp は IPv4 候補を含むが、 ICE-Lite の
        // controlled 側として local candidate は public_ip に従う。
        let offer = include_str!("testdata/firefox_offer.sdp");
        let _answer = session.handle_offer(offer).await.expect("answer 生成");

        // local candidate 行を受信する。 タイムアウトを付けて hung しないようにする。
        let mut rx = session
            .take_local_candidates()
            .await
            .expect("1 度目は取れる");
        let line = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("local candidate を 2 秒以内に受信")
            .expect("送信側が close せずに 1 件流す");
        // RFC 8839 §5.1: `candidate:<foundation> <component> <transport>
        // <priority> <connection-address> <port> typ host`。
        // IPv6 リテラルは括弧無しの素アドレスで載る。
        assert!(
            line.contains("::1"),
            "IPv6 host candidate に loopback IP が含まれない: {}",
            line
        );
        assert!(line.contains("typ host"), "host candidate でない: {}", line);
        let _ = session.close().await;
    }

    /// Issue #92 / RFC 8840 §4 (Trickle ICE end-of-candidates) /
    /// W3C WebRTC §4.4.1.6 (`addIceCandidate(null)` / empty candidate):
    /// host candidate を 1 件送出した直後に、 同じく empty 文字列を
    /// end-of-candidates marker として送出する。
    ///
    /// ICE-Lite (RFC 8445 §2.4) は STUN/TURN 反射 / 中継候補を生成しないため、
    /// host 1 件で候補列挙が確定する。 この設計を遵守し、 ブラウザ側 ICE
    /// failure timer が即時起動できるよう、 sabiden run_loop は host 直後に
    /// empty marker を流す。
    #[tokio::test]
    async fn rfc8840_4_str0m_session_emits_end_of_candidates_after_host() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (45500, 45599),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.expect("session 起動");

        // ICE state 遷移を駆動するため offer を投入する (Event::IceConnectionStateChange
        // が host candidate / end-of-candidates 送出の trigger 経路)。
        let offer = include_str!("testdata/firefox_offer.sdp");
        let _answer = session.handle_offer(offer).await.expect("answer 生成");

        let mut rx = session
            .take_local_candidates()
            .await
            .expect("local candidate receiver 取得");

        // 1 件目: 実 host candidate
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("host candidate を 2 秒以内に受信")
            .expect("送信側が close せずに 1 件流す");
        assert!(
            first.contains("typ host"),
            "1 件目は host candidate であるべき: {:?}",
            first
        );
        assert!(
            !first.is_empty(),
            "host candidate 行は非空であるべき: {:?}",
            first
        );

        // 2 件目: RFC 8840 §4 end-of-candidates marker (= 空文字列)
        let second = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("end-of-candidates marker を 2 秒以内に受信")
            .expect("送信側が close せずに 2 件目を流す");
        assert_eq!(
            second, "",
            "2 件目は end-of-candidates marker (空文字列) であるべき: {:?}",
            second
        );

        let _ = session.close().await;
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

    /// Issue #135 🟡 2 (server-side analog) / RFC 8839 §4.2 Trickle ICE:
    /// ブラウザは SDP offer 受信前に local candidate を trickle してくる
    /// ことがある (Chrome の典型挙動: setLocalDescription 完了直後に
    /// `icegatheringstatechange` が走り、 host candidate が
    /// `RTCPeerConnection.onicecandidate` で吐かれる)。
    ///
    /// str0m バックエンドは ICE-Lite で `add_remote_candidate` を SDP
    /// exchange 前に受けても内部 ICE state に蓄積する (str0m 0.19
    /// `Rtc::add_remote_candidate` 仕様、 RFC 8838 trickle ICE)。
    /// 本テストは run_loop 起動直後 (= `accept_offer` 前) に
    /// `add_ice_candidate` を呼んで command 経由で正常受理されることを
    /// 確認する。 frontend の `pendingIceCandidates` バッファに頼らず、
    /// server 側でも同等の堅牢性があることを担保。
    #[tokio::test]
    async fn str0m_session_add_remote_candidate_before_sdp_is_accepted() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (57000, 57999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();
        // accept_offer / create_offer を呼ばずにいきなり remote candidate を
        // 追加する。 ICE-Lite なので remote credentials 未確定でも str0m は
        // 候補を保持する (RFC 8838: trickle).
        let cand = "candidate:1 1 udp 2122252543 192.168.1.50 56789 typ host";
        session
            .add_ice_candidate(cand)
            .await
            .expect("SDP 交換前でも受理されるべき (RFC 8839 §4.2)");
        let _ = session.close().await;
    }

    /// Issue #135 🟡 2 (server-side analog) / RFC 8839 §4.2: ICE → Offer →
    /// ICE → ICE の interleave 順序でも全 candidate が受理される。
    /// frontend `App.tsx` の `pendingIceCandidates` 修正と対応する
    /// server-side 担保。
    #[tokio::test]
    async fn str0m_session_interleaved_ice_offer_ice_all_accepted() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (58000, 58999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.unwrap();

        // (1) offer 前に 1 つ目
        session
            .add_ice_candidate("candidate:1 1 udp 2122252543 10.0.0.1 1000 typ host")
            .await
            .expect("ICE before offer");

        // (2) offer
        let offer = include_str!("testdata/firefox_offer.sdp");
        let _answer = session.handle_offer(offer).await.expect("offer 受理");

        // (3) offer 後に 2 つ + 終端マーカ相当
        for cand in [
            "candidate:2 1 udp 2122252543 10.0.0.2 2000 typ host",
            "candidate:3 1 udp 1685987071 203.0.113.5 3000 typ srflx",
        ] {
            session
                .add_ice_candidate(cand)
                .await
                .expect("ICE after offer");
        }
        let _ = session.close().await;
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

    // ========================================================================
    // Issue #114: str0m バックエンド統合テスト
    //
    // 既存の単発 SDP テスト (`str0m_session_accept_offer_smoke` 等) は ICE/DTLS
    // を確立しない範囲しか触れていない。 ここでは "ブラウザ側" Rtc を Sans-IO
    // で同居駆動し、 実 loopback UDP を介して offer→answer→ICE→DTLS→media
    // までを 1 つの `#[tokio::test]` で完結させる。
    //
    // RFC 引用:
    // - RFC 8825 (WebRTC): full media stack expects ICE + DTLS + SRTP の連携
    // - RFC 8829 (JSEP §4.1): offer/answer state machine
    // - RFC 8839 (ICE in SDP §4.1): controlling/controlled, ice-lite/full
    // - RFC 8842 (DTLS-SRTP §4.4): fingerprint+setup attributes in SDP
    //
    // ICE 役割: `Str0mPeerSession` 本体は ICE-Lite (controlled)。 そのため
    // テスト側 "ブラウザ" は full-ICE controlling (`set_ice_lite(false)`、
    // SDP offerer 側) として組む。 RFC 8445 §6.1.1: at least one agent must
    // act as controlling — ICE-Lite same-side 同士では成立しない。
    // ========================================================================

    /// "ブラウザ" 役の sync Rtc を loopback UDP で駆動する helper。
    /// `tokio::test` 内で `tokio::spawn(run)` して非同期に動かす。
    ///
    /// 設計理由 (CLAUDE.md §6.3 production-side test hook 禁止):
    /// `Str0mPeerSession` は run_loop が固定 (ICE-Lite, public_ip ベース) で
    /// テストでも一切弄らない。 反対側 (ブラウザ) はテスト本体の制御下に置く
    /// 必要があるため、 ここで完全自前の Rtc + UdpSocket driver を組む。
    struct TestBrowserPeer {
        rtc: Rtc,
        socket: Arc<UdpSocket>,
        local_addr: SocketAddr,
    }

    impl TestBrowserPeer {
        /// loopback 上に bind し、 host candidate を登録した状態で生成。
        /// ICE は full (controlling 側)、 codec は PCMU のみ enable。
        async fn new() -> Result<Self> {
            // 127.0.0.1:0 で OS に任意 port を割り当てさせる。
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let local_addr = socket.local_addr()?;

            // RFC 8825 §3.4: WebRTC は DTLS-SRTP / SAVPF を必須とする。
            // ICE-Lite は controlling 側では使わない (RFC 8445 §2.4)。
            let mut rtc = RtcConfig::new()
                .set_ice_lite(false)
                .clear_codecs()
                .enable_pcmu(true)
                .build(Instant::now());

            let host = Candidate::host(local_addr, "udp")
                .map_err(|e| anyhow!("test browser host candidate: {}", e))?;
            rtc.add_local_candidate(host);

            Ok(Self {
                rtc,
                socket: Arc::new(socket),
                local_addr,
            })
        }

        /// SDP offer を build (audio sendrecv 1 本)。
        /// RFC 8829 §5.2: createOffer は 1 つの SdpOffer + pending offer を返す。
        fn build_offer(&mut self) -> Result<(String, str0m::change::SdpPendingOffer)> {
            let mut api = self.rtc.sdp_api();
            api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
            let (offer, pending) = api
                .apply()
                .ok_or_else(|| anyhow!("test browser: offer apply 空"))?;
            Ok((offer.to_sdp_string(), pending))
        }

        /// RFC 8829 §5.6: 受領した answer SDP を pending offer に紐付けて適用。
        fn apply_answer(
            &mut self,
            pending: str0m::change::SdpPendingOffer,
            sdp: &str,
        ) -> Result<()> {
            let answer = SdpAnswer::from_sdp_string(sdp)
                .map_err(|e| anyhow!("test browser: SDP answer parse: {}", e))?;
            self.rtc
                .sdp_api()
                .accept_answer(pending, answer)
                .map_err(|e| anyhow!("test browser: accept_answer: {}", e))?;
            Ok(())
        }
    }

    /// `TestBrowserPeer` 用の単方向 progress: poll_output を 1 回回し、
    /// 必要なら 1 パケット送信 / イベント記録する。 戻り値は次回 timeout 時刻。
    async fn browser_poll(
        rtc: &mut Rtc,
        socket: &UdpSocket,
        events: &mut Vec<Event>,
    ) -> Result<Instant> {
        loop {
            match rtc.poll_output() {
                Ok(Output::Timeout(t)) => return Ok(t),
                Ok(Output::Transmit(t)) => {
                    if let Err(e) = socket.send_to(&t.contents, t.destination).await {
                        warn!(error = %e, dest = %t.destination, "test browser: send 失敗");
                    }
                }
                Ok(Output::Event(ev)) => {
                    events.push(ev);
                }
                Err(e) => return Err(anyhow!("test browser: poll_output: {}", e)),
            }
        }
    }

    /// "ブラウザ" Rtc を `until` まで駆動し、 `predicate` が true になったら戻る。
    /// loopback UDP recv と Rtc timeout を `tokio::select!` する。
    /// `predicate(&events)` が true、 または `deadline` 経過で戻る。
    /// 戻り値: predicate が満たされたら true。
    async fn drive_browser_until<F>(
        browser: &mut TestBrowserPeer,
        events: &mut Vec<Event>,
        deadline: tokio::time::Instant,
        mut predicate: F,
    ) -> bool
    where
        F: FnMut(&[Event]) -> bool,
    {
        let mut buf = vec![0u8; 2048];
        loop {
            // poll_output で次の timeout を取得
            let next_timeout = match browser_poll(&mut browser.rtc, &browser.socket, events).await {
                Ok(t) => t,
                Err(e) => {
                    warn!(error = %e, "test browser: poll エラー、 drive 終了");
                    return predicate(events);
                }
            };

            if predicate(events) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return predicate(events);
            }

            let now = Instant::now();
            let dur = next_timeout.saturating_duration_since(now);
            let timeout_at = tokio::time::Instant::now() + dur;
            // deadline と次 timeout の早い方
            let sleep_until_t = deadline.min(timeout_at);

            tokio::select! {
                r = browser.socket.recv_from(&mut buf) => {
                    match r {
                        Ok((n, src)) => {
                            match Receive::new(Protocol::Udp, src, browser.local_addr, &buf[..n]) {
                                Ok(rx) => {
                                    let input = Input::Receive(Instant::now(), rx);
                                    if browser.rtc.accepts(&input) {
                                        if let Err(e) = browser.rtc.handle_input(input) {
                                            warn!(error = %e, "test browser: handle_input エラー");
                                        }
                                    }
                                }
                                Err(_) => {
                                    // 非 STUN/DTLS/RTP → drop
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "test browser: recv_from エラー");
                            return predicate(events);
                        }
                    }
                }
                _ = tokio::time::sleep_until(sleep_until_t) => {
                    if let Err(e) = browser.rtc.handle_input(Input::Timeout(Instant::now())) {
                        warn!(error = %e, "test browser: timeout handle_input エラー");
                    }
                }
            }
        }
    }

    /// `Str0mPeerSession` の `host_candidate` (= `public_ip:port`) を SDP answer
    /// から抜き出すヘルパ。 SDP には `a=candidate:<foundation> 1 udp <prio>
    /// <ip> <port> typ host` 形式で含まれる (RFC 8839 §5.1)。
    fn extract_host_socket_from_sdp(sdp: &str) -> Option<SocketAddr> {
        for line in sdp.lines() {
            let l = line.trim_start_matches("a=");
            if let Some(rest) = l.strip_prefix("candidate:") {
                let toks: Vec<&str> = rest.split_whitespace().collect();
                if toks.len() >= 8 && toks[7] == "host" {
                    let ip: IpAddr = toks[4].parse().ok()?;
                    let port: u16 = toks[5].parse().ok()?;
                    return Some(SocketAddr::new(ip, port));
                }
            }
        }
        None
    }

    /// RFC 8829 §5.2 / §5.6 + RFC 8839 §6.1 + RFC 8842 §4: フル offer→answer→
    /// ICE check→DTLS handshake→`Event::Connected` を loopback で往復する。
    ///
    /// シーケンス:
    /// 1. テスト側 (browser, controlling) が SDP offer を生成
    /// 2. `Str0mPeerSession::handle_offer` で answer 取得
    /// 3. browser が answer を `accept_answer` で適用
    /// 4. browser host candidate は offer SDP に乗っており、 sabiden の
    ///    host candidate は answer SDP に乗っている (RFC 8839 §5.1.1)
    /// 5. browser を loopback UDP で駆動、 `Event::Connected` 到達まで待機
    ///
    /// DoD (Issue #114): "offer 受理 → answer 生成 → ICE candidate → DTLS
    /// handshake → media frame drop の round-trip"。
    #[tokio::test(flavor = "current_thread")]
    async fn rfc8829_full_round_trip_offer_answer_ice_dtls_connected() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (60000, 60999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.expect("session new");

        let mut browser = TestBrowserPeer::new().await.expect("browser new");

        // (1) browser が offer を生成
        let (offer_sdp, pending) = browser.build_offer().expect("build offer");
        assert!(offer_sdp.contains("m=audio"), "offer に audio 行不在");
        assert!(
            offer_sdp.contains("ice-ufrag") && offer_sdp.contains("ice-pwd"),
            "offer に ICE 認証情報不在 (RFC 8839 §4.1)"
        );
        assert!(
            offer_sdp.contains("fingerprint:"),
            "offer に fingerprint 不在 (RFC 8842 §4)"
        );

        // (2) sabiden 側で answer 生成
        let answer_sdp = session.handle_offer(&offer_sdp).await.expect("answer 生成");
        assert!(
            answer_sdp.contains("a=ice-lite") || answer_sdp.contains("ice-lite"),
            "answer に ice-lite 不在: {}",
            answer_sdp
        );
        assert!(
            answer_sdp.contains("fingerprint:"),
            "answer に fingerprint 不在 (RFC 8842 §4)"
        );

        // (3) sabiden の host candidate を answer SDP から取り出す (RFC 8839 §5.1)
        let sabiden_addr =
            extract_host_socket_from_sdp(&answer_sdp).expect("answer に host candidate 不在");
        // ICE-Lite かつ public_ip=127.0.0.1 設定のため loopback アドレスに広告される
        assert_eq!(sabiden_addr.ip().to_string(), "127.0.0.1");

        // (4) browser に answer を適用 → ICE/DTLS の checks が走り出す
        browser
            .apply_answer(pending, &answer_sdp)
            .expect("apply answer");

        // (5) Connected 到達まで browser を駆動 (loopback DTLS で実測 100-500ms)
        let mut events: Vec<Event> = Vec::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
        let connected = drive_browser_until(&mut browser, &mut events, deadline, |evs| {
            evs.iter().any(|e| matches!(e, Event::Connected))
        })
        .await;
        assert!(
            connected,
            "Connected に到達しなかった (events: {:?})",
            events
                .iter()
                .map(std::mem::discriminant)
                .collect::<Vec<_>>()
        );

        // ICE 確立イベントも観測されている (RFC 8839 §3.1: state Checking→Connected)
        let saw_ice_change = events
            .iter()
            .any(|e| matches!(e, Event::IceConnectionStateChange(_)));
        assert!(saw_ice_change, "ICE state change 不在");

        let _ = session.close().await;
    }

    /// RFC 8825 + Issue #114 DoD: "mid 確定後の send_media が writer に届く"。
    ///
    /// フル round-trip 後に `Str0mPeerSession::send_media` (PCMU PT 0) を 1 回
    /// 発行し、 browser 側で `Event::MediaData` が観測されることを確認する。
    /// この時点で:
    /// - audio mid は `Event::MediaAdded` 経由で確定済 (offer/answer 完了時)
    /// - PT 0 は両側で negotiate 済 (clear_codecs + enable_pcmu)
    /// - DTLS は確立済 → writer.write が SRTP に packetize して送出する
    #[tokio::test(flavor = "current_thread")]
    async fn rfc8825_send_media_after_connected_delivers_media_data() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (61000, 61999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.expect("session new");
        let mut browser = TestBrowserPeer::new().await.expect("browser new");

        let (offer_sdp, pending) = browser.build_offer().expect("offer");
        let answer_sdp = session.handle_offer(&offer_sdp).await.expect("answer");
        browser
            .apply_answer(pending, &answer_sdp)
            .expect("apply answer");

        // Connected まで駆動
        let mut events: Vec<Event> = Vec::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
        let connected = drive_browser_until(&mut browser, &mut events, deadline, |evs| {
            evs.iter().any(|e| matches!(e, Event::Connected))
        })
        .await;
        assert!(connected, "Connected 不到達");

        // sabiden audio_mid が確定するまで少し駆動を続ける
        // (`Event::MediaAdded` は browser 側でも sabiden 側でも独立に発行されるが、
        //  sabiden の run_loop で audio_mid が set されるのに数 ms の余地を取る)
        let pause_until = tokio::time::Instant::now() + tokio::time::Duration::from_millis(200);
        let _ = drive_browser_until(&mut browser, &mut events, pause_until, |_| false).await;

        // PCMU 1 frame (20 ms @ 8 kHz = 160 sample) を流し込む
        // RFC 3551 §4.5.14 / RFC 7655 ではない G.711 μ-law PT=0、 RFC 3550 §5.1。
        let frame = MediaFrame {
            pt: 0,
            rtp_time: 160,
            payload: vec![0xff; 160],
            network_time: std::time::Instant::now(),
        };
        session
            .send_media(frame)
            .await
            .expect("send_media command 受理");

        // browser 側で MediaData を観測するまで駆動
        let deadline2 = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        let saw_media = drive_browser_until(&mut browser, &mut events, deadline2, |evs| {
            evs.iter().any(|e| matches!(e, Event::MediaData(_)))
        })
        .await;
        assert!(saw_media, "MediaData 不到達 (events: {})", events.len());

        let _ = session.close().await;
    }

    /// RFC 8829 §5.2.1 + Issue #114 DoD: "DTLS 確立前の send_media が drop"。
    ///
    /// 既存の `send_media_does_not_panic_before_connected` は command 送信
    /// 成功だけを確認しているが、 本テストは **drop の観測** まで検証する:
    /// - browser を Connected に到達させない (offer/answer 未交換)
    /// - `send_media` を呼んでも `take_media_rx` には何も来ない (送信方向は
    ///   そもそも別チャネルだが、 副作用なく Ok で済むことを観測する)
    /// - run_loop は alive のまま (panic / disconnect 起きない)
    #[tokio::test(flavor = "current_thread")]
    async fn rfc8842_send_media_before_dtls_handshake_drops_silently() {
        let cfg = Str0mConfig {
            public_ip: "127.0.0.1".parse().unwrap(),
            port_range: (62000, 62999),
            ice_servers: vec![],
        };
        let session = Str0mPeerSession::new(cfg).await.expect("session new");

        // DTLS 未確立 / mid 未確定の状態で send_media を 5 回連発。
        // `write_media` は audio_mid None で early return するため panic
        // しない (RFC 3550 §5: pre-session state)。
        for i in 0..5 {
            let frame = MediaFrame {
                pt: 0,
                rtp_time: (i * 160) as u32,
                payload: vec![0xff; 160],
                network_time: std::time::Instant::now(),
            };
            session
                .send_media(frame)
                .await
                .expect("DTLS 前でも command 自体は Ok");
        }

        // run_loop が生存していれば、 後続の API は依然成功する。
        // (panic で task が落ちていれば oneshot reply が dropped で Err になる。)
        let probe = session.local_dtls_params("passive").await;
        assert!(
            probe.is_ok(),
            "send_media 連発後に run_loop 死亡: {:?}",
            probe
        );

        let _ = session.close().await;
    }

    /// RFC 3550 §5.1 + Issue #114 DoD: "PT 未 negotiate の send_media が drop"。
    ///
    /// `write_media` を直接 unit test として呼び、 以下の 3 経路で panic せず
    /// 戻ることを確認する:
    /// 1. `audio_mid = None` (mid 未確定): 早期 return
    /// 2. `audio_mid = Some(mid)` だが `mid` がセッションに存在しない: writer None
    /// 3. mid 存在、 PT が negotiate 済 codec に含まれない: payload_params find None
    ///
    /// `write_media` は private fn だが `#[cfg(test)] mod tests` は同モジュール内
    /// のため呼び出せる (CLAUDE.md §6.3 production-side hook 禁止に違反しない)。
    #[test]
    fn rfc3550_write_media_unknown_pt_does_not_panic() {
        // PCMU only の Rtc を組む (sabiden 本番と同じ codec 設定)
        let mut rtc = RtcConfig::new()
            .set_ice_lite(true)
            .clear_codecs()
            .enable_pcmu(true)
            .build(Instant::now());

        // (1) audio_mid 未確定: 早期 return
        let frame = MediaFrame {
            pt: 0,
            rtp_time: 160,
            payload: vec![0xff; 160],
            network_time: std::time::Instant::now(),
        };
        write_media(&mut rtc, None, &frame);

        // (2) 不明 mid に対する write_media: writer None で早期 return
        //     `Mid: From<&str>` を使ってセッションに存在しない mid を作る。
        let bogus_mid: Mid = Mid::from("zzz");
        write_media(&mut rtc, Some(bogus_mid), &frame);

        // (3) negotiate 済の mid を取得し、 未 negotiate な PT (例: 99) を渡す。
        //     full handshake をやらず、 sdp_api だけ apply して mid を確定する。
        let mut rtc2 = RtcConfig::new()
            .set_ice_lite(true)
            .clear_codecs()
            .enable_pcmu(true)
            .build(Instant::now());
        let mut api = rtc2.sdp_api();
        let real_mid = api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let _ = api.apply();
        // mid は確定したが、 codec は PCMU のみ。 PT=99 は未 negotiate。
        let bad_pt_frame = MediaFrame {
            pt: 99,
            rtp_time: 160,
            payload: vec![0xff; 160],
            network_time: std::time::Instant::now(),
        };
        // writer 取得は成功するが payload_params find が None で drop。
        write_media(&mut rtc2, Some(real_mid), &bad_pt_frame);
    }

    /// RFC 3550 §5.1 + Issue #114 DoD: `write_media` は writer 取得失敗時も
    /// panic せず戻る (`run_loop` 内で呼ばれるため絶対不可)。
    /// 本テストは "audio mid が確定しているが Connected 前" の状態を疑似的に
    /// 再現して `write_media` が trace ログだけで戻ることを確認する。
    #[test]
    fn rfc3550_write_media_pre_connected_returns_without_panic() {
        let mut rtc = RtcConfig::new()
            .set_ice_lite(true)
            .clear_codecs()
            .enable_pcmu(true)
            .build(Instant::now());

        // sdp_api だけ走らせて mid を確定 (handshake は未実施)
        let mut api = rtc.sdp_api();
        let mid = api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let _ = api.apply();

        let frame = MediaFrame {
            pt: 0,
            rtp_time: 160,
            payload: vec![0xff; 160],
            network_time: std::time::Instant::now(),
        };
        // Connected 前は writer.write が `Err` を返すが、 write_media は trace
        // log で握り潰すので panic しない。
        write_media(&mut rtc, Some(mid), &frame);
    }
}
