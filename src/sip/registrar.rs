//! 内線登録テーブル (UAS 用)
//!
//! Linphone / Zoiper 等の SIP UA からの REGISTER で得られた Contact を
//! メモリ上に保持し、AOR (Address-of-Record) → Contact のマッピングを
//! 管理する。RFC 3261 §10.3 に準拠したシンプルな registrar。
//!
//! 永続化は今のところ行わず、再起動時には UA 側からの再 REGISTER で
//! 再構築する。Issue #4 の Phase 1 では in-memory のみで十分。
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// 1 つの内線が現在登録している Contact の状態。
#[derive(Debug, Clone)]
pub struct Binding {
    /// Contact ヘッダの URI (例: `sip:iphone@192.0.2.10:5060`)。
    pub contact_uri: String,
    /// UA から実際にパケットが届いた送信元アドレス。
    /// REGISTER の Contact がプライベート IP の場合があるため、UAS から
    /// 内線を呼び出す際は基本的にこちらを使う (RFC 5626 で言うところの
    /// "received" と同等の扱い)。
    pub remote: SocketAddr,
    /// 期限。`Instant::now()` がこれを過ぎたら失効。
    pub expires_at: Instant,
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

    /// AOR に Binding を上書き登録する。expires が 0 のときは [`unregister`]
    /// と等価 (RFC 3261 §10.2.1.1)。
    pub async fn register(
        &self,
        aor: &str,
        contact_uri: String,
        remote: SocketAddr,
        expires: Duration,
    ) {
        if expires.is_zero() {
            self.unregister(aor).await;
            return;
        }
        let binding = Binding {
            contact_uri,
            remote,
            expires_at: Instant::now() + expires,
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
        let now = Instant::now();
        let mut table = self.inner.write().await;
        let before = table.len();
        table.retain(|_, b| !b.is_expired(now));
        before - table.len()
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
