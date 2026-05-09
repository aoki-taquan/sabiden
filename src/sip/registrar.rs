//! 内線登録テーブル (UAS 用)
//!
//! Linphone / Zoiper 等の SIP UA からの REGISTER で得られた Contact を
//! メモリ上に保持し、AOR (Address-of-Record) → Contact のマッピングを
//! 管理する。RFC 3261 §10.3 に準拠したシンプルな registrar。
//!
//! 永続化は今のところ行わず、再起動時には UA 側からの再 REGISTER で
//! 再構築する。Issue #4 の Phase 1 では in-memory のみで十分。
//!
//! # トランスポート
//!
//! 内線は SIP UDP UA (Linphone 等) と WebRTC ブラウザの 2 種類があり、
//! [`Binding::transport`] で区別する。NGN 着信フォークは transport ごとに
//! 別経路 (SIP UAC fork / WebSocket push) を呼び分ける。
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::webrtc::peer::PeerSession;
use crate::webrtc::signaling::{PendingAnswers, WsSink};

/// 内線がどのプロトコルで接続しているか。NGN 着信時の経路選択に使う。
#[derive(Clone)]
pub enum ExtTransport {
    /// 通常の SIP UDP UA (Linphone / iPhone 等)。
    /// `Binding::contact_uri` (または `remote`) を target に SIP UAC で
    /// `fork_to_extensions` する。
    Sip,
    /// WebRTC ブラウザ。SIP では呼び出せず、専用 WebSocket シグナリングで
    /// `ServerMessage::Offer` を push し、ブラウザが返す
    /// `ClientMessage::Answer` を待ち受ける。
    /// `pending` は orchestrator が `register(call_id)` で待機 oneshot を
    /// 確保し、`Answer { call_id, sdp }` 受信時に WS 受信ループから
    /// `deliver` で渡される共有テーブル。
    WebRtc {
        peer: Arc<dyn PeerSession>,
        ws: WsSink,
        pending: PendingAnswers,
    },
}

impl std::fmt::Debug for ExtTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtTransport::Sip => f.write_str("Sip"),
            ExtTransport::WebRtc { .. } => f.write_str("WebRtc"),
        }
    }
}

/// 1 つの内線が現在登録している Contact の状態。
#[derive(Debug, Clone)]
pub struct Binding {
    /// Contact ヘッダの URI (例: `sip:iphone@192.0.2.10:5060`)。
    /// WebRTC バインディングの場合はシグナリング層で組み立てた擬似 URI
    /// (例: `sip:alice@webrtc.peer`) になるが、`transport` で実体を判別する
    /// ので URI 文字列に意味は持たせない。
    pub contact_uri: String,
    /// UA から実際にパケットが届いた送信元アドレス。
    /// REGISTER の Contact がプライベート IP の場合があるため、UAS から
    /// 内線を呼び出す際は基本的にこちらを使う (RFC 5626 で言うところの
    /// "received" と同等の扱い)。
    /// WebRTC バインディングでは WS 接続時の TCP リモートアドレスが入るが、
    /// SIP の宛先には使われない。
    pub remote: SocketAddr,
    /// 期限。`Instant::now()` がこれを過ぎたら失効。
    pub expires_at: Instant,
    /// この Binding をどのプロトコルで呼び出すか。
    pub transport: ExtTransport,
}

impl Binding {
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// 内線登録テーブル。AOR (`username` 部分) をキーとして 1 つの Binding を
/// 保持する。本実装では同一 AOR に対して複数 Contact は持たず、新しい
/// REGISTER で上書きする (RFC 3261 §10.3 にあるとおり、登録は集合だが
/// 内線用途では端末 1 台だけを想定)。
#[derive(Default)]
pub struct ExtensionRegistrar {
    inner: RwLock<HashMap<String, Binding>>,
}

impl ExtensionRegistrar {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// AOR に SIP Binding を上書き登録する。expires が 0 のときは [`unregister`]
    /// と等価 (RFC 3261 §10.2.1.1)。
    /// 既定の transport は [`ExtTransport::Sip`]。
    pub async fn register(
        &self,
        aor: &str,
        contact_uri: String,
        remote: SocketAddr,
        expires: Duration,
    ) {
        self.register_with_transport(aor, contact_uri, remote, expires, ExtTransport::Sip)
            .await;
    }

    /// AOR に任意の transport の Binding を上書き登録する。
    pub async fn register_with_transport(
        &self,
        aor: &str,
        contact_uri: String,
        remote: SocketAddr,
        expires: Duration,
        transport: ExtTransport,
    ) {
        if expires.is_zero() {
            self.unregister(aor).await;
            return;
        }
        let binding = Binding {
            contact_uri,
            remote,
            expires_at: Instant::now() + expires,
            transport,
        };
        self.inner.write().await.insert(aor.to_string(), binding);
    }

    /// AOR の登録を削除する。
    pub async fn unregister(&self, aor: &str) {
        self.inner.write().await.remove(aor);
    }

    /// AOR から有効な Binding を取得する。期限切れは返さない。
    pub async fn lookup(&self, aor: &str) -> Option<Binding> {
        let now = Instant::now();
        let table = self.inner.read().await;
        table.get(aor).filter(|b| !b.is_expired(now)).cloned()
    }

    /// 有効な (AOR, Binding) を一覧取得する。テストや管理 API 用。
    pub async fn snapshot(&self) -> Vec<(String, Binding)> {
        let now = Instant::now();
        self.inner
            .read()
            .await
            .iter()
            .filter(|(_, b)| !b.is_expired(now))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// 期限切れエントリを掃除する。受付ループで定期的に呼び出すことを想定。
    pub async fn purge_expired(&self) -> usize {
        self.purge_expired_returning_removed().await.len()
    }

    /// 期限切れエントリを掃除し、削除された AOR 一覧を返す。
    ///
    /// Issue #68 の dialog 完全クローズ連鎖のため、purge ループは抹消された
    /// AOR ごとに B2BUA へ通知して NGN レッグの BYE を撃てる必要がある。
    /// `purge_expired` の上位互換ヘルパで、返り値の `Vec<String>` を上位層が
    /// 走査して `OutboundCallRegistry` を引き、対応する通話を NGN へ BYE する。
    pub async fn purge_expired_returning_removed(&self) -> Vec<String> {
        let now = Instant::now();
        let mut table = self.inner.write().await;
        let mut removed = Vec::new();
        table.retain(|aor, b| {
            if b.is_expired(now) {
                removed.push(aor.clone());
                false
            } else {
                true
            }
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "192.0.2.10:5060".parse().unwrap()
    }

    #[tokio::test]
    async fn register_then_lookup() {
        let r = ExtensionRegistrar::new();
        r.register(
            "iphone",
            "sip:iphone@192.0.2.10:5060".to_string(),
            addr(),
            Duration::from_secs(60),
        )
        .await;
        let b = r.lookup("iphone").await.expect("登録済み");
        assert_eq!(b.contact_uri, "sip:iphone@192.0.2.10:5060");
        assert_eq!(b.remote, addr());
    }

    #[tokio::test]
    async fn expires_zero_removes_binding() {
        let r = ExtensionRegistrar::new();
        r.register(
            "iphone",
            "sip:iphone@192.0.2.10:5060".to_string(),
            addr(),
            Duration::from_secs(60),
        )
        .await;
        r.register(
            "iphone",
            "sip:iphone@192.0.2.10:5060".to_string(),
            addr(),
            Duration::ZERO,
        )
        .await;
        assert!(r.lookup("iphone").await.is_none());
    }

    #[tokio::test]
    async fn expired_binding_not_returned() {
        let r = ExtensionRegistrar::new();
        // 期限切れの Binding を直接挿入
        let binding = Binding {
            contact_uri: "sip:x@192.0.2.10".into(),
            remote: addr(),
            expires_at: Instant::now() - Duration::from_secs(1),
            transport: ExtTransport::Sip,
        };
        r.inner.write().await.insert("x".into(), binding);
        assert!(r.lookup("x").await.is_none());
        let removed = r.purge_expired().await;
        assert_eq!(removed, 1);
    }

    #[tokio::test]
    async fn snapshot_returns_only_active() {
        let r = ExtensionRegistrar::new();
        r.register(
            "a",
            "sip:a@192.0.2.10".to_string(),
            addr(),
            Duration::from_secs(60),
        )
        .await;
        let snap = r.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "a");
    }
}
