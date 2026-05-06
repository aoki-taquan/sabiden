mod config;
mod dhcp;
mod rtp;
mod sip;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tracing::info;

use config::Config;
use sip::register::Registrar;

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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sabiden=debug".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Register { config: config_path } => {
            let config = Arc::new(Config::from_file(&config_path)?.sip);
            info!("設定読み込み完了: {}@{}", config.phone_number, config.domain);

            let bind_addr: SocketAddr = config.local_addr;
            let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
            info!("UDP ソケット bind: {}", bind_addr);

            set_dscp(&socket, 32)?;

            let registrar = Registrar::new(config.clone(), socket, config.server_addr);
            info!("REGISTER 開始 → {}", config.server_addr);
            registrar.run().await?;
        }

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
