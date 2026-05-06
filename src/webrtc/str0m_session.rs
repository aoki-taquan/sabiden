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
use str0m::change::SdpOffer;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{sleep_until, Instant as TokioInstant};
use tracing::{debug, info, trace, warn};

use super::peer::PeerSession;

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
    Close,
}

/// [`PeerSession`] の str0m 実装。
pub struct Str0mPeerSession {
    cmd_tx: mpsc::Sender<Command>,
    /// `take_local_candidates` で 1 度だけ取り出される。
    local_cand_rx: Mutex<Option<mpsc::Receiver<String>>>,
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

        // ICE host candidate を生成 (str0m に登録するアドレスは "対外的に
        // ブラウザが到達するアドレス"。Cloudflare Tunnel の場合は LAN IP でも
        // tunnel が解決するので問題ない)。
        let host = Candidate::host(host_advert, "udp")
            .map_err(|e| anyhow!("str0m host candidate: {}", e))?;

        // ICE-Lite で Rtc を構築。ICE-Lite では我々が controlled、ブラウザが
        // controlling。STUN binding は受けるだけ。
        let rtc = RtcConfig::new().set_ice_lite(true).build(Instant::now());

        let socket = Arc::new(socket);
        let local_bind = local_addr;

        tokio::spawn(run_loop(RunCtx {
            rtc,
            socket: socket.clone(),
            local_bind,
            host_candidate: host,
            cmd_rx,
            local_cand_tx,
        }));

        Ok(Arc::new(Self {
            cmd_tx,
            local_cand_rx: Mutex::new(Some(local_cand_rx)),
        }))
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
        }
        Event::MediaData(d) => {
            // 本 PR では取り回しのみ確認。Call Manager 結線は別 PR。
            trace!(
                mid = ?d.mid,
                pt = ?d.pt,
                bytes = d.data.len(),
                "str0m: 受信 media frame"
            );
            // TODO(#29): Opus → G.711 トランスコード経由で内線/NGN 側 RTP に
            // ブリッジ。今は単に drop。
        }
        Event::RtpPacket(_) => {
            // RTP モードでは PR スコープ外。Event::MediaData を採用するため到達しない。
        }
        _ => {}
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
}
