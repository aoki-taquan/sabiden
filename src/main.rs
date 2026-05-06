// 公開 API は将来の Phase で利用。CI の -D warnings に引っかからないよう module 単位で抑止
#[allow(dead_code)]
mod call;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod dhcp;
mod health;
#[allow(dead_code)]
mod observability;
#[allow(dead_code)]
mod rtp;
#[allow(dead_code)]
mod sdp;
#[allow(dead_code)]
mod sip;
#[allow(dead_code)]
mod webrtc;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::info;

use call::manager::UacForker;
use call::orchestrator::{wire_ngn_inbound_with_metrics, NgnInboundConfig, UasEventHandler};
use config::Config;
use observability::{Metrics, SipTraceWriter};
use sip::register::Registrar;
use sip::transaction::TransactionLayer;
use sip::uac::{Uac, UacConfig};
use sip::uas::ExtensionUas;

#[derive(Parser)]
#[command(name = "sabiden")]
#[command(about = "NTT ひかり電話 SIP クライアント (DIY 実装)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// SIP REGISTER を開始して常駐する
    Register {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
        /// SIP メッセージダンプ出力先 (Issue #20)。指定すると config の `[trace] dir` を上書き。
        #[arg(long)]
        trace_dir: Option<String>,
    },
    /// 設定ファイルのサンプルを出力する
    Init,
    /// DHCP Option 120 から SIP サーバを表示する
    DiscoverSip {
        #[arg(long)]
        lease_file: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // 構造化ログ: span を NEW/CLOSE で出し、call_id 等の field を全イベントに伝播。
    // RUST_LOG が未設定なら `sabiden=debug` がデフォルト (Issue #20)。
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sabiden=debug".parse()?),
        )
        .with_target(true)
        .with_span_events(
            tracing_subscriber::fmt::format::FmtSpan::NEW
                | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Register {
            config: config_path,
            trace_dir,
        } => run_register(&config_path, trace_dir.as_deref()).await?,

        Commands::Init => {
            println!("{}", Config::example());
        }

        Commands::DiscoverSip { lease_file } => {
            let servers = if let Some(path) = lease_file {
                dhcp::sip_servers_from_lease_file(&path)?
            } else {
                let from_env = dhcp::sip_servers_from_env();
                if from_env.is_empty() {
                    println!("環境変数 new_ip_sip_servers が未設定。既知アドレスを表示:");
                    dhcp::known_ntt_east_servers()
                } else {
                    from_env
                }
            };
            for s in &servers {
                println!("{}", s);
            }
        }
    }

    Ok(())
}

/// `register` サブコマンドの本体。
///
/// 起動シーケンス (#15 の設計):
/// 1. Config を読む
/// 2. NGN 側 UDP socket を bind し DSCP 32 を立てる
/// 3. NGN 側 `TransactionLayer::spawn` で `(layer, inbound_rx)` を取得
/// 4. NGN 側 `Uac` (内線→NGN プロキシ用) と `Registrar` を構築
/// 5. 内線 UAS を bind し、`with_handler(event_tx)` で接続用 mpsc を渡す
/// 6. 内線→NGN プロキシ用 `Uac` を内線レッグ用に複製した forker を作る
///    (`UacForker`) → `wire_ngn_inbound` で NGN 着信ハンドラを spawn
/// 7. `UasEventHandler::spawn` で UAS event ループを spawn
/// 8. UAS の受信ループを spawn
/// 9. health server を spawn
/// 10. `Registrar::run` を foreground で常駐させる
async fn run_register(config_path: &str, trace_dir_override: Option<&str>) -> Result<()> {
    let full_config = Config::load(config_path)?;
    let health_addr = full_config.health.bind_addr;
    let uas_config_opt = full_config.uas.clone();
    let extensions_cfg = full_config.extensions.clone();
    let trace_dir = trace_dir_override
        .map(|s| s.to_string())
        .or_else(|| full_config.trace.dir.clone());
    let sip_cfg = Arc::new(full_config.sip);
    info!(
        "設定読み込み完了: {}@{}",
        sip_cfg.phone_number, sip_cfg.domain
    );

    // (1) 観測: SIP トレース writer + メトリクス
    let metrics = Metrics::new();
    let tracer = match trace_dir.as_deref() {
        Some(dir) => match SipTraceWriter::open(dir) {
            Ok(w) => {
                info!("SIP トレース有効: dir={}", dir);
                w
            }
            Err(e) => {
                tracing::error!("SIP トレース初期化失敗 ({}); 無効化して継続", e);
                SipTraceWriter::disabled()
            }
        },
        None => SipTraceWriter::disabled(),
    };

    // (2) NGN 側 UDP socket
    let bind_addr: SocketAddr = sip_cfg.local_addr;
    let ngn_socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    info!("NGN UDP ソケット bind: {}", bind_addr);
    set_dscp(&ngn_socket, 32)?;

    // (3) NGN 側 TransactionLayer (トレース対応)
    let (ngn_layer, ngn_inbound_rx) =
        TransactionLayer::spawn_with_tracer(ngn_socket.clone(), tracer.clone());

    // (4) NGN 側 UAC (内線→NGN プロキシ専用) + Registrar
    let ngn_uac_cfg = UacConfig {
        local_uri: format!("sip:{}@{}", sip_cfg.phone_number, sip_cfg.domain),
        domain: sip_cfg.domain.clone(),
        local_addr: sip_cfg.local_addr,
        user_agent: "sabiden/0.1".to_string(),
    };
    let ngn_uac = Arc::new(Uac::new(
        ngn_uac_cfg,
        ngn_layer.clone(),
        sip_cfg.server_addr,
    ));
    let registrar = Registrar::with_metrics(
        sip_cfg.clone(),
        ngn_layer.clone(),
        sip_cfg.server_addr,
        metrics.clone(),
    );

    // (5) 内線 UAS bind + UasEvent チャネル
    let (uas_event_tx, uas_event_rx) = mpsc::unbounded_channel();
    let (uas, ext_registrar, ext_socket_for_forker) = if let Some(uas_cfg) = uas_config_opt {
        info!(
            "内線 UAS 起動 ({} 内線): {}",
            extensions_cfg.len(),
            uas_cfg.bind_addr
        );
        let uas =
            ExtensionUas::bind_with_metrics(uas_cfg, &extensions_cfg, metrics.clone()).await?;
        let ext_registrar = uas.registrar();
        // (6) 内線レッグ用 UAC を独立ソケットで構築
        // 内線網と NGN 網は別のトランザクション層で動かす必要があるため
        // 一時的な UDP ソケットを内線送信専用に bind する。
        let ext_send_sock = Arc::new(
            UdpSocket::bind(SocketAddr::new(ext_registrar_local_ip_or_loopback(), 0)).await?,
        );
        let uas = uas.with_handler(uas_event_tx.clone());
        (Some(uas), Some(ext_registrar), Some(ext_send_sock))
    } else {
        info!("内線 UAS は未設定のためスキップ");
        (None, None, None)
    };
    drop(uas_event_tx); // 内線 UAS が無ければ受信側はすぐ終わる

    // (6) NGN 着信ハンドラ: 内線レッグ用 forker を構築して spawn
    if let (Some(ext_registrar), Some(ext_send_sock)) =
        (ext_registrar.clone(), ext_socket_for_forker)
    {
        // 内線レッグ送信ソケットもトレース対応
        let (ext_layer, _ext_inbound_rx) =
            TransactionLayer::spawn_with_tracer(ext_send_sock.clone(), tracer.clone());
        let ext_uac_cfg = UacConfig {
            local_uri: "sip:sabiden@internal".to_string(),
            domain: "internal".to_string(),
            local_addr: ext_send_sock.local_addr()?,
            user_agent: "sabiden-b2bua/0.1".to_string(),
        };
        // 各内線へ送るときは contact から得た remote を使うため server_addr は仮値。
        // 実装簡略化のため、forker の各 leg は target URI のホスト部を解決して送る
        // (現在の Uac は単一 server_addr 設定なので、内線レッグでは server_addr を
        //  target ごとに切り替える形が望ましい。Phase 1 では簡略実装として
        //  ループバック向けに `127.0.0.1:0` を server_addr にしておき、
        //  実運用では SDP/Contact 解決を Issue #16 で拡張予定)。
        let placeholder_server: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ext_uac = Arc::new(Uac::new(ext_uac_cfg, ext_layer, placeholder_server));
        let forker = Arc::new(UacForker {
            uac: ext_uac,
            targets: HashMap::new(),
        });
        let cfg = NgnInboundConfig {
            fork_timeout: std::time::Duration::from_secs(20),
            realm: "sabiden".to_string(),
            bridge_ngn_bind_ip: None,
            bridge_ext_bind_ip: None,
        };
        let _handler = wire_ngn_inbound_with_metrics(
            ngn_layer.clone(),
            ngn_socket.clone(),
            ngn_inbound_rx,
            forker,
            ext_registrar,
            cfg,
            metrics.clone(),
        );
        info!("NGN 着信ハンドラ起動完了");
    } else {
        // 内線が無ければ着信を受けても捨てるしか無いので、ハンドラは作らない。
        // `inbound_rx` は drop しておく (TransactionLayer::recv_loop は
        // TU が落ちた時点で停止するので、リソース解放のため明示的に drop)。
        drop(ngn_inbound_rx);
        info!("内線が無いため NGN 着信ハンドラはスキップ");
    }

    // (7) UAS event ハンドラ
    let uas_handler = UasEventHandler::with_metrics(ngn_uac.clone(), metrics.clone());
    uas_handler.spawn(uas_event_rx);

    // (8) UAS 受信ループ
    if let Some(uas) = uas {
        tokio::spawn(async move {
            if let Err(e) = uas.run().await {
                tracing::error!("内線 UAS 終了: {}", e);
            }
        });
    }

    // (9) health server (メトリクス共有) と WebRTC シグナリング (Issue #23)
    let health_state = health::HealthState::new(registrar.registered_handle(), metrics.clone());
    let webrtc_signaling = if let Some(secret_hex) = full_config.webrtc.secret_hex.clone() {
        match hex::decode(&secret_hex) {
            Ok(secret_bytes) => {
                if let Some(ext_registrar) = ext_registrar.clone() {
                    let verifier = Arc::new(webrtc::Verifier::new(secret_bytes));
                    let ttl = std::time::Duration::from_secs(full_config.webrtc.register_ttl_secs);
                    info!(
                        "WebRTC ゲートウェイ有効: /signal (register_ttl={}s)",
                        ttl.as_secs()
                    );
                    Some(webrtc::SignalingState::new(verifier, ext_registrar, ttl))
                } else {
                    tracing::warn!("WebRTC ゲートウェイ設定済みだが内線 UAS 未設定のため無効化");
                    None
                }
            }
            Err(e) => {
                tracing::error!("webrtc.secret_hex デコード失敗: {}; ゲートウェイ無効", e);
                None
            }
        }
    } else {
        info!("WebRTC ゲートウェイは未設定 (webrtc.secret_hex 未指定)");
        None
    };
    tokio::spawn(async move {
        let result = if let Some(sig) = webrtc_signaling {
            health::run_with_signaling(health_addr, health_state, sig).await
        } else {
            health::run(health_addr, health_state).await
        };
        if let Err(e) = result {
            tracing::error!("health server 終了: {}", e);
        }
    });

    // (10) Registrar.run() を foreground で実行
    info!("REGISTER 開始 → {}", sip_cfg.server_addr);
    registrar.run().await?;

    Ok(())
}

/// 内線送信ソケットの bind IP。Linux ではループバックに固定する。
/// (実運用では `UasConfig::bind_addr` のホスト部を継承するのが望ましいが、
///  Phase 1 では LAN 内ループバック想定で簡略化する。)
fn ext_registrar_local_ip_or_loopback() -> std::net::IpAddr {
    "127.0.0.1".parse().unwrap()
}

#[cfg(target_os = "linux")]
fn set_dscp(socket: &UdpSocket, dscp: u32) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let tos = (dscp << 2) as libc::c_int;
    let fd = socket.as_raw_fd();
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_dscp(_socket: &UdpSocket, _dscp: u32) -> Result<()> {
    Ok(())
}
