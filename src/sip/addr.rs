//! NGN 側 `local_addr` 自動検出ユーティリティ (Issue #35)。
//!
//! K8s デプロイ等で pod が起動するノードを固定 (nodeSelector) しなくても
//! 動かせるよう、起動時に「NGN サーバへ送るときカーネルが選ぶ source IP」を
//! ダミー UDP socket で問い合わせる。`connect()` は実際にパケットを送らない
//! (UDP は connectionless) ため、サーバ到達不能でも getsockname() でルーティ
//! ング テーブル上の選択結果を取得できる。

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};

/// NGN SIP サーバへの経路で使われる source IP を自動検出する。
///
/// `bind_port` は Via/Contact に載せる SIP listen ポート (通常 5060)。
/// 実際の listen は別ソケットで行うため、本関数は「IP の選択」のみが目的。
///
/// IPv6 サーバには `[::]:0`、IPv4 サーバには `0.0.0.0:0` を bind して
/// `connect()` → `local_addr()` する。これは Linux/macOS で標準的なパターン
/// (cf. `man 7 udp` "When the socket is connected, the kernel ...")。
pub fn detect_local_addr(server: SocketAddr, bind_port: u16) -> Result<SocketAddr> {
    let bind: SocketAddr = match server {
        SocketAddr::V6(_) => "[::]:0".parse().expect("static parse"),
        SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("static parse"),
    };
    let sock = std::net::UdpSocket::bind(bind)
        .with_context(|| format!("bind probe socket {} for local_addr detect", bind))?;
    sock.connect(server)
        .with_context(|| format!("UDP connect to {} (probe)", server))?;
    let local = sock.local_addr().context("getsockname() on probe socket")?;
    let ip: IpAddr = local.ip();
    Ok(SocketAddr::new(ip, bind_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 サーバ宛なら IPv4 source を返すこと (loopback でも成立)。
    #[test]
    fn detect_ipv4_returns_ipv4() {
        let server: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let local = detect_local_addr(server, 5060).expect("detect should succeed for v4 loopback");
        assert!(matches!(local, SocketAddr::V4(_)), "v4 server -> v4 local");
        assert_eq!(local.port(), 5060);
        // 127.0.0.0/8 内であること (Linux は通常 127.0.0.1)。
        let octets = match local.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        assert_eq!(octets[0], 127);
    }

    /// IPv6 サーバ宛なら IPv6 source を返すこと。
    /// (CI 環境によっては v6 loopback が無いケースもあるが Linux では基本利用可能)
    #[test]
    fn detect_ipv6_returns_ipv6() {
        let server: SocketAddr = "[::1]:5060".parse().unwrap();
        let local = match detect_local_addr(server, 5060) {
            Ok(l) => l,
            Err(_) => {
                // IPv6 loopback が無い CI でも CI を割らないように skip 扱い。
                eprintln!("IPv6 not available; skipping");
                return;
            }
        };
        assert!(matches!(local, SocketAddr::V6(_)), "v6 server -> v6 local");
        assert_eq!(local.port(), 5060);
    }

    /// `bind_port` 引数が反映されること (5060 以外でも OK)。
    #[test]
    fn detect_uses_requested_port() {
        let server: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let local = detect_local_addr(server, 15060).expect("detect");
        assert_eq!(local.port(), 15060);
    }
}
