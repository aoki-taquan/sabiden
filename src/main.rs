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

// Issue #42: テスト共通ハーネス。lib.rs と同じファイルを test ビルド時のみロードして
// `crate::testing::*` で参照できるようにする (bin と lib で `mod call;` 等を二重に
// 宣言する既存の構成上の対策。production ビルドには含まれない)。
// `#![allow(dead_code)]` は `testing.rs` 自身が宣言しているのでここでは付けない
// (clippy::duplicated_attributes 回避)。
#[cfg(test)]
mod testing;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::info;

use call::manager::{CallManager, UacForker};
use call::orchestrator::{NgnInboundConfig, UasEventHandler};
use config::Config;
use observability::call_log::CallLog;
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

    // (1) 観測: SIP トレース writer + メトリクス + 通話履歴 (Issue #278)
    let metrics = Metrics::new();
    // Issue #278: 通話履歴 ring buffer。 PWA の「最近の通話」 UI で利用する。
    // ring buffer 容量は 200 件 (= 1 日数十通話の運用で数日分残る規模)。
    // 永続化 (sqlite) は別 issue で扱う。
    let call_log = Arc::new(CallLog::new(200));
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
    // bind_addr (省略時 [::]:5060) で listen し、Via/Contact には local_addr を載せる。
    // local_addr は Config::load 内で auto-detect 済み (Issue #35)。
    let bind_addr: SocketAddr = sip_cfg.resolved_bind_addr();
    let local_addr_for_hdr: SocketAddr = sip_cfg.expect_local_addr();
    let ngn_socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    info!(
        "NGN UDP ソケット bind: {} (Via/Contact sent-by: {})",
        bind_addr, local_addr_for_hdr
    );
    set_dscp(&ngn_socket, 32)?;

    // (3) NGN 側 TransactionLayer (トレース対応)
    let (ngn_layer, ngn_inbound_rx) =
        TransactionLayer::spawn_with_tracer(ngn_socket.clone(), tracer.clone());

    // (4) NGN 側 UAC (内線→NGN プロキシ専用) + Registrar
    let ngn_uac_cfg = UacConfig {
        local_uri: format!("sip:{}@{}", sip_cfg.phone_number, sip_cfg.domain),
        domain: sip_cfg.domain.clone(),
        local_addr: local_addr_for_hdr,
        user_agent: "sabiden/0.1".to_string(),
        // Issue #113: NGN レッグの INVITE 401/407 challenge に対応する
        // ための Digest 資格情報。 NGN 直収モード (auth=none / `password = None`)
        // では None のまま、 IMS / SBC 経由構成で password が設定されていれば
        // INVITE 再認証に使う (RFC 3261 §22.2 §22.3)。
        auth_username: sip_cfg
            .password
            .as_ref()
            .map(|_| sip_cfg.phone_number.clone()),
        auth_password: sip_cfg.password.clone(),
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
    // UAS 関連情報をまとめて返す: (UAS, registrar, forker 用 send 専用 socket,
    //                             UAS 自身の TransactionLayer, UAS bind 済み addr)
    let (uas, ext_registrar, ext_socket_for_forker, uas_layer_for_b2bua, uas_local_addr) =
        if let Some(uas_cfg) = uas_config_opt {
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
            // B2BUA 用に UAS の Layer / addr を控えておく (内線へ BYE を送る経路)。
            let uas_layer = uas.layer();
            let uas_addr = uas.socket().local_addr()?;
            let uas = uas.with_handler(uas_event_tx.clone());
            (
                Some(uas),
                Some(ext_registrar),
                Some(ext_send_sock),
                Some(uas_layer),
                Some(uas_addr),
            )
        } else {
            info!("内線 UAS は未設定のためスキップ");
            (None, None, None, None, None)
        };
    drop(uas_event_tx); // 内線 UAS が無ければ受信側はすぐ終わる

    // (6+7) UAS event ハンドラと NGN 着信ハンドラ。両者で OutboundCallRegistry を
    // 共有することで、NGN→内線方向の BYE が同じ通話エントリを引けるようにする。
    //
    // Issue #40: `CallManager` を生成して両ハンドラに注入する。
    // - 内線→NGN 発信 (`UasEventHandler`): `prepare_outbound_bridge` 経由で
    //   sabiden 中継用 RTP ソケットを bind し SDP の `m=audio` port まで書換える。
    // - NGN→内線 着信 (`NgnInboundHandler`): `start_bridge_for_inbound` 経由で
    //   200 OK 返送前に RTP ブリッジを起動する。
    //
    // RTP ブリッジ用 bind IP の決定 (Issue #66 / `docs/asterisk-real-invite.md` §5.2):
    // - NGN レッグ: 既定で SIP local_addr (= eth1 NGN 側 IP)。`[bridge] ngn_bind_ip`
    //   で上書き可能。NGN へ広告する SDP `c=`/`o=` もこの IP に揃える。
    // - 内線レッグ: 既定では NGN レッグと同じ (1 NIC テスト構成用)。内線 UA
    //   (Linphone 等) が LAN 側 (例 192.168.20.0/24) にいる本番構成では
    //   `[bridge] ext_bind_ip` に eth0 LAN IP を設定する必要がある (内線 UA
    //   から到達可能でないと SDP に広告したエンドポイントへ RTP が届かない =
    //   音声無音になる、Issue #66 の根因)。
    let bridge_ngn_ip = full_config
        .bridge
        .ngn_bind_ip
        .unwrap_or_else(|| local_addr_for_hdr.ip());
    let bridge_ext_ip = full_config.bridge.ext_bind_ip.unwrap_or(bridge_ngn_ip);
    info!(
        bridge_ngn_ip = %bridge_ngn_ip,
        bridge_ext_ip = %bridge_ext_ip,
        "RTP ブリッジ bind IP を決定 (Issue #66)"
    );
    // Issue #147: PWA→NGN 発信通話の双方向 BYE 連動テーブルを 1 個構築し、
    // `UasEventHandler` (PWA outbound 成立時に insert) と `NgnInboundHandler`
    // (NGN→PWA BYE 受信時に lookup) で共有する。
    let webrtc_outbound_active: call::orchestrator::WebRtcOutboundActive =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    // Issue #147 (review #2 🔴): `CallManager` は **両ハンドラで 1 個共有** する。
    // outbound (`UasEventHandler::handle_pwa_outbound_offer`) で `create_call`
    // した CallId を、 NGN→PWA BYE 経路 (`NgnInboundHandler::handle_bye`) で
    // `terminate` する必要があり、 別インスタンスを持たせると `terminate` が
    // entry 無しで silent no-op になり RTP bridge socket / spawn task が
    // leak する (= NGN 側は 200 OK が返って dialog terminate されているのに
    // sabiden 側 bridge は永続)。 inbound 経路の `start_bridge_for_inbound` も
    // 同じ Arc を使うので NGN→内線 着信 / PWA outbound のどちらからの
    // BYE でも一貫して bridge を閉じられる。
    // RFC 3261 §15.1.2 / RFC 5853 §3.2.2 SBC framework: B2BUA は片側 dialog
    // 終了をもう片側へ伝搬する責務を負う。
    let shared_call_manager: Option<Arc<CallManager>> = ext_registrar
        .as_ref()
        .map(|er| CallManager::new(er.clone()));

    let uas_handler = if let Some(call_manager) = shared_call_manager.clone() {
        let mut h = UasEventHandler::with_call_manager_metrics_and_outbound_table(
            ngn_uac.clone(),
            call_manager,
            Some(bridge_ngn_ip),
            Some(bridge_ext_ip),
            metrics.clone(),
            webrtc_outbound_active.clone(),
        );
        if let (Some(uas_layer), uas_addr) = (uas_layer_for_b2bua.clone(), uas_local_addr) {
            // 内線レッグへ in-dialog (BYE 等) を送るため UAS の TransactionLayer を借用。
            h.attach_ext_layer(uas_layer, uas_addr);
        }
        // Issue #278: 内線→NGN / PWA→NGN 発信の通話履歴を集約する。
        h.set_call_log(call_log.clone()).await;
        h
    } else {
        // 内線が無いと CallManager の存在意義が無い (RTP ブリッジは内線レッグ前提)。
        // 透過モードのままで内線→NGN プロキシも閉じておく。
        let h = UasEventHandler::with_metrics(ngn_uac.clone(), metrics.clone());
        // Issue #278: 内線無し構成でも PWA 経路は無いが、 PWA outbound handler は
        // 別 enable 経路を持つ。 ここで CallLog を結線しておく。
        h.set_call_log(call_log.clone()).await;
        h
    };
    let uas_handler_for_forwarder: Arc<dyn call::orchestrator::OutboundDialogForwarder> =
        uas_handler.clone();
    // Issue #145: PWA→NGN 発信フローで `ClientMessage::Offer { target, sdp }`
    // を受けたシグナリング層がここに dispatch する。 `UasEventHandler` を
    // 流用することで、 既存の Uac / CallManager / RTP bridge bind IP の
    // 設定を再利用できる。
    let uas_handler_for_pwa_outbound: Arc<dyn webrtc::signaling::PwaOutboundHandler> =
        uas_handler.clone();
    // Issue #147: PWA WS close / `ClientMessage::Bye` 経路で NGN レッグへ
    // BYE を撃つ cleanup ハンドラ (= 同じ `UasEventHandler`)。
    let uas_handler_for_pwa_closer: Arc<dyn webrtc::signaling::PwaOutboundCloser> =
        uas_handler.clone();
    // Issue #279: PWA UI hold / unhold 経路で NGN レッグへ Re-INVITE を発行する
    // ハンドラ (= 同じ `UasEventHandler`)。 RFC 3264 §8.4 + RFC 3261 §14.1。
    let uas_handler_for_pwa_hold: Arc<dyn webrtc::signaling::PwaHoldHandler> = uas_handler.clone();

    // Bug B / Issue #268: NGN→PWA 着信通話の WS close cleanup ハンドラを
    // SignalingState (`with_pwa_inbound_closer`) に渡すため、 `ngn_handler` を
    // 外側スコープで保持する。 内線無し構成では `None` (= cleanup 経路無効)。
    let mut ngn_inbound_handler_for_signaling: Option<Arc<call::orchestrator::NgnInboundHandler>> =
        None;

    if let (Some(ext_registrar), Some(ext_send_sock), Some(inbound_call_manager)) = (
        ext_registrar.clone(),
        ext_socket_for_forker,
        shared_call_manager.clone(),
    ) {
        // 内線レッグ送信ソケットもトレース対応 (NGN→内線 着信フォーク用)
        let (ext_layer, _ext_inbound_rx) =
            TransactionLayer::spawn_with_tracer(ext_send_sock.clone(), tracer.clone());
        let ext_uac_cfg = UacConfig {
            local_uri: "sip:sabiden@internal".to_string(),
            domain: "internal".to_string(),
            local_addr: ext_send_sock.local_addr()?,
            user_agent: "sabiden-b2bua/0.1".to_string(),
            // 内線レッグは sabiden が UAS、 INVITE は内線→sabiden 方向の
            // み (NGN→内線 のフォーク INVITE は sabiden 発で内線が UAS)。
            // 内線 UA に対しては auth challenge を返さない設計 (PR #63)
            // のため UAC として再認証する経路もない。
            auth_username: None,
            auth_password: None,
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
            // NGN→内線 着信時も outbound と同じ bind IP 方針を使う
            // (`[bridge] ngn_bind_ip` / `ext_bind_ip` は両方向で意味が同じ)。
            bridge_ngn_bind_ip: Some(bridge_ngn_ip),
            bridge_ext_bind_ip: Some(bridge_ext_ip),
            // NGN へ返す 200 OK の Contact (in-dialog target) は eth1 sent-by IP
            // を載せる。 socket bind は `0.0.0.0` なので socket.local_addr() を
            // そのまま使うと NGN が ACK 不能で 10 秒後 CANCEL してくる。
            ngn_local_addr: Some(local_addr_for_hdr),
            // Issue #139: `webrtc_active` leak sweeper の周期。 既定 30 秒。
            // browser WS 切断のみ (NGN BYE 未到来) の経路で entry が leak する
            // のを防ぐ defense-in-depth。
            webrtc_active_sweep_interval: std::time::Duration::from_secs(30),
        };
        // 着信 NGN→内線 用 CallManager は **outbound 側と同じ Arc**
        // (`shared_call_manager`) を再利用する (Issue #147 review #2 🔴 fix)。
        // 別 Arc を作ると PWA outbound で create_call した CallId を inbound
        // 側で terminate しても entry 無しの silent no-op になり、 RTP bridge
        // socket / spawn task が leak する。
        let ngn_handler =
            call::orchestrator::wire_ngn_inbound_with_manager_metrics_and_outbound_table(
                ngn_layer.clone(),
                ngn_socket.clone(),
                ngn_inbound_rx,
                forker,
                ext_registrar,
                cfg,
                inbound_call_manager,
                metrics.clone(),
                webrtc_outbound_active.clone(),
            );
        // Issue #278: NGN 着信の通話履歴 (NGN→内線 / NGN→PWA) を集約する。
        // `UasEventHandler` と同じ `Arc<CallLog>` を共有し、 双方向 BYE 経路で
        // 同じ call_id を `record_end` できるようにする。
        ngn_handler.set_call_log(call_log.clone()).await;
        // NGN→内線 BYE 伝搬の経路を結線する (B2BUA 双方向 BYE)。
        ngn_handler
            .set_outbound_forwarder(uas_handler_for_forwarder)
            .await;
        // Bug B (Issue #268): SignalingState から PwaInboundCloser として参照できるよう
        // ハンドラを保持する。
        ngn_inbound_handler_for_signaling = Some(ngn_handler.clone());
        info!(
            bridge_ngn_ip = %bridge_ngn_ip,
            bridge_ext_ip = %bridge_ext_ip,
            "NGN 着信ハンドラ起動完了 (CallManager 注入済 / RTP ブリッジ有効)"
        );
    } else {
        // 内線が無ければ着信を受けても捨てるしか無いので、ハンドラは作らない。
        // `inbound_rx` は drop しておく (TransactionLayer::recv_loop は
        // TU が落ちた時点で停止するので、リソース解放のため明示的に drop)。
        drop(ngn_inbound_rx);
        info!("内線が無いため NGN 着信ハンドラはスキップ");
    }
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
    let health_state = health::HealthState::new(
        registrar.registered_handle(),
        metrics.clone(),
        call_log.clone(),
    );
    let webrtc_signaling = if let Some(secret_hex) = full_config.webrtc.secret_hex.clone() {
        match hex::decode(&secret_hex) {
            Ok(secret_bytes) => {
                if let Some(ext_registrar) = ext_registrar.clone() {
                    let verifier = Arc::new(webrtc::Verifier::new(secret_bytes));
                    let ttl = std::time::Duration::from_secs(full_config.webrtc.register_ttl_secs);
                    let backend = full_config.webrtc.backend.as_str();
                    info!(
                        "WebRTC ゲートウェイ有効: /signal (backend={} register_ttl={}s)",
                        backend,
                        ttl.as_secs()
                    );
                    // Issue #131: keepalive_interval / idle_timeout を config
                    // から渡す。 既定 30s/60s は Cloudflare Tunnel 100s idle に
                    // 対する余裕。 経路上に他の idle timer が挟まる場合のみ
                    // 設定で短縮する想定 (RFC 6455 §5.5.2 Ping は keepalive
                    // 用途として MAY)。
                    let keepalive_interval =
                        std::time::Duration::from_secs(full_config.webrtc.keepalive_interval_secs);
                    let idle_timeout =
                        std::time::Duration::from_secs(full_config.webrtc.idle_timeout_secs);
                    let mut state = webrtc::SignalingState::new(verifier, ext_registrar, ttl)
                        .with_keepalive(keepalive_interval, idle_timeout)
                        .with_pwa_outbound(uas_handler_for_pwa_outbound.clone())
                        .with_pwa_outbound_closer(uas_handler_for_pwa_closer.clone())
                        .with_pwa_hold_handler(uas_handler_for_pwa_hold.clone());
                    // Bug B / Issue #268: NGN→PWA 着信通話の WS close cleanup を
                    // 結線する (`NgnInboundHandler` が `PwaInboundCloser` を実装)。
                    if let Some(h) = ngn_inbound_handler_for_signaling.clone() {
                        let closer: Arc<dyn webrtc::signaling::PwaInboundCloser> = h;
                        state = state.with_pwa_inbound_closer(closer);
                    }
                    if backend == "str0m" {
                        match webrtc::Str0mConfig::from_webrtc(&full_config.webrtc) {
                            Ok(s_cfg) => {
                                let s_cfg = std::sync::Arc::new(s_cfg);
                                let factory: webrtc::signaling::PeerFactory =
                                    std::sync::Arc::new(move || {
                                        let cfg = s_cfg.clone();
                                        Box::pin(async move {
                                            let session =
                                                webrtc::Str0mPeerSession::new((*cfg).clone())
                                                    .await?;
                                            let p: std::sync::Arc<dyn webrtc::PeerSession> =
                                                session;
                                            Ok(p)
                                        })
                                    });
                                state = state.with_peer_factory(factory);
                            }
                            Err(e) => {
                                tracing::error!(
                                    "str0m 設定エラー (stub バックエンドにフォールバック): {}",
                                    e
                                );
                            }
                        }
                    }
                    Some(state)
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

/// NGN SIP 送信ソケットに DSCP 32 (TOS 0x80) を設定する。
///
/// NGN 直収モード (Issue #37) では IPv4 path で REGISTER するため、
/// `IPV6_TCLASS` だけでなく `IP_TOS` も併せて設定する。dual-stack v6 socket と
/// v4 socket の両方で正しく DSCP マーキングが効くよう保険的に両方呼ぶ
/// (`rtp::set_rtp_dscp` と同じ方針)。失敗は無視する。
#[cfg(target_os = "linux")]
fn set_dscp(socket: &UdpSocket, dscp: u32) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let tos = (dscp << 2) as libc::c_int;
    let fd = socket.as_raw_fd();
    unsafe {
        // IPv6 socket では IPV6_TCLASS。HGW 経由の従来運用 (NGN IPv6 path)。
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        // IPv4 path 用 IP_TOS (Issue #37 / NGN 直収モード)。
        // dual-stack v6 socket でも v4-mapped 送信時にこちらが効くカーネルがあるため
        // 保険でセットする。失敗は無視 (一部 socket タイプでは EOPNOTSUPP になる)。
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TOS,
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
