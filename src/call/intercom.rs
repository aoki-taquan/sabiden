//! 内線間 direct dial (intercom) — Issue #313
//!
//! sabiden 配下の内線同士の通話を NGN を介さず直接ブリッジするための補助層。
//!
//! # 役割
//!
//! - [`classify_dial_target`]: PWA / SIP UA から受け取った dial target を
//!   [`ExtensionRegistrar`] と突き合わせ、 内線 AOR にヒットしたら
//!   [`DialDestination::Internal`]、 それ以外は [`DialDestination::Ngn`] を返す。
//!   AOR ヒット最優先 = `lookup(target)` だけが「内線」 判定の唯一の根拠。
//!   ヒットしない番号は従来どおり NGN へプロキシする (= 後方互換)。
//!
//! - [`InternalCallRegistry`]: NGN を含まない内線間通話の確立済みエントリを
//!   保持する。 既存の [`OutboundCallRegistry`](crate::call::orchestrator::OutboundCallRegistry)
//!   は NGN レッグ前提 (`ngn_dialog: UacDialog`) で、 内線間通話 (NGN なし) を
//!   持てない。 そのため別テーブルで管理する。
//!
//! # RFC 引用
//!
//! - **RFC 3261 §13** (Initiating a Session): 内線間通話も両レッグそれぞれが
//!   normal SIP dialog として確立する。 sabiden は B2BUA (RFC 5853 §3.2.2)
//!   として両 dialog の終端 (BYE 伝搬等) を担う。
//! - **RFC 3551 §4.5.14** (PCMU PT 0, 8 kHz): 内線間でも基本 PCMU 固定。
//!   PWA-PWA 中継時の WebRTC レッグも `str0m::enable_pcmu` で PCMU only
//!   構成のため、 トランスコード不要 (= 既存 `direct_pcmu_passthrough` と同じ
//!   理屈)。
//!
//! # 並列性
//!
//! NGN レッグを使わないため、 NGN ch (= 物理 1 回線) を消費しない。
//! 内線間通話が走っている間でも NGN 発着信は別経路で独立に動く
//! (= multi-line 耐性)。 同時上限は [`IntercomConfig::max_concurrent_internal_calls`]
//! で抑える (バッファ無限大による DoS 防止)。

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

use super::bridge::{MediaBridge, WebRtcRelayBridge, WebRtcRelayConfig};
use super::manager::CallManager;
use super::CallId;
use crate::sip::registrar::{Binding, ExtensionRegistrar};
use crate::webrtc::peer::{MediaFrame, PeerSession};

/// Dial target の振り分け結果。
///
/// `classify_dial_target` の戻り値。 呼出側 (orchestrator の
/// `handle_pwa_outbound_offer` / `handle_invite`) は本 enum で
/// 「NGN へ転送するか / 内線間直接通話に分岐するか」 を決定する。
#[derive(Debug, Clone)]
pub enum DialDestination {
    /// 内線 AOR が registrar に登録済み。 NGN を介さず直接呼び出す。
    /// `binding` の `transport` で SIP UAC / WebRTC WS push のどちらで
    /// 呼び出すかを判別する (RFC 5853 §3.2.2 B2BUA leg dispatch)。
    Internal {
        /// 内線 binding (transport / contact / remote 等)。
        binding: Binding,
        /// 呼び出し先 AOR (例 `"alice"`)。
        aor: String,
    },
    /// 内線 AOR にヒットしなかったので NGN へ転送する (既存挙動)。
    Ngn {
        /// 元の dial target 文字列 (例 `"117"` / `"0312345678"`)。
        target: String,
    },
}

impl DialDestination {
    /// 内線間通話に分岐するかどうか。 呼出側のテンプレートが見やすくなる
    /// よう用意したヘルパ。
    pub fn is_internal(&self) -> bool {
        matches!(self, DialDestination::Internal { .. })
    }

    /// 内線 AOR (= `Internal` のとき)、 そうでなければ `None`。
    /// テスト assertion で `match` を書きたくない場合の薄い getter。
    pub fn internal_aor(&self) -> Option<&str> {
        match self {
            DialDestination::Internal { aor, .. } => Some(aor.as_str()),
            DialDestination::Ngn { .. } => None,
        }
    }
}

/// dial target を [`ExtensionRegistrar`] に問合せて [`DialDestination`] を返す。
///
/// # 判定ルール (RFC 3261 §10 / Issue #313)
///
/// 1. `target` を AOR として `registrar.lookup(target)` する。 ヒットしたら
///    [`DialDestination::Internal`] を返す。 期限切れ binding は registrar
///    側で自動除外されるので、 ここでは追加のチェック不要。
/// 2. ヒットしなければ [`DialDestination::Ngn`] を返す (= 従来挙動)。
///
/// AOR がヒットしないケースは PSTN 番号 (`117`, `0312345678` 等) の他、
/// 「存在しない内線番号」 も含む。 後者は NGN に投げて 404 で帰る挙動になるが、
/// これは band-aid 禁止 (CLAUDE.md §6.1) の観点では「`target` が NGN 番号
/// 文法に合うかは NGN 側で判断する」 設計選択。 sabiden 側は AOR ヒット
/// 有無のみを単一の真理として使う。
pub async fn classify_dial_target(target: &str, registrar: &ExtensionRegistrar) -> DialDestination {
    match registrar.lookup(target).await {
        Some(binding) => DialDestination::Internal {
            binding,
            aor: target.to_string(),
        },
        None => DialDestination::Ngn {
            target: target.to_string(),
        },
    }
}

/// 内線間通話 (= NGN レッグを持たない) 1 件分のステート。
///
/// 既存の [`OutboundCallEntry`](crate::call::orchestrator::OutboundCallEntry)
/// は `ngn_dialog: UacDialog` を必須としており、 内線間通話 (NGN なし) を
/// 表現できない。 そのため本構造体を別テーブルで管理する。
///
/// # フィールド
///
/// - `caller_call_id` / `callee_call_id`: SIP Call-ID。 caller / callee
///   いずれの BYE / CANCEL 経路からも引けるよう両方保持する (`HashMap` 二重
///   index は registry 側で持つ)。
/// - `caller_aor` / `callee_aor`: 内線 AOR (`"alice"` 等)。 観測 / ログ用と
///   PWA-PWA 中継時の peer 検索キーに使う。
/// - `bridge_call_id`: [`crate::call::manager::CallManager`] 内の bridge エントリ ID。
///   `terminate(bridge_call_id)` で `MediaBridge` を停止できる。
pub struct InternalCallEntry {
    /// 発信元 (caller) の Call-ID。
    pub caller_call_id: String,
    /// 着信先 (callee) の Call-ID。 PWA callee の場合は sabiden が生成した
    /// 擬似 Call-ID (= peer session ID 等) を入れる。
    pub callee_call_id: String,
    /// caller の AOR。
    pub caller_aor: String,
    /// callee の AOR。
    pub callee_aor: String,
    /// `CallManager` 内の bridge エントリ ID。
    pub bridge_call_id: CallId,
}

impl InternalCallEntry {
    /// テストおよび呼出側 helper 用のコンストラクタ。
    pub fn new(
        caller_call_id: impl Into<String>,
        callee_call_id: impl Into<String>,
        caller_aor: impl Into<String>,
        callee_aor: impl Into<String>,
        bridge_call_id: CallId,
    ) -> Arc<Self> {
        Arc::new(Self {
            caller_call_id: caller_call_id.into(),
            callee_call_id: callee_call_id.into(),
            caller_aor: caller_aor.into(),
            callee_aor: callee_aor.into(),
            bridge_call_id,
        })
    }
}

/// 内線間通話 (= NGN レッグなし) のレジストリ。
///
/// `caller_call_id` / `callee_call_id` 両方からエントリを引ける二重 index を
/// 内部に持つ。 これにより BYE 受信時に「caller の Call-ID か callee の
/// Call-ID か」 を呼出側が気にせずエントリを引ける。
///
/// 同時通話上限は本テーブル単体では強制しない (上限を入れる場所は呼出側で
/// `len()` を見て判断する)。 これは「容量チェック前にエントリ挿入する」
/// パターン (= ロック内チェック → 挿入) を避け、 呼出側で 486 Busy 等の
/// 応答を組み立てる時に責務を分けるため。 サイズチェック helper は
/// [`Self::can_accept`] で提供する。
#[derive(Default)]
pub struct InternalCallRegistry {
    inner: Mutex<InternalCallRegistryInner>,
}

#[derive(Default)]
struct InternalCallRegistryInner {
    /// caller Call-ID → entry。
    by_caller: HashMap<String, Arc<InternalCallEntry>>,
    /// callee Call-ID → caller Call-ID (逆引き)。
    callee_to_caller: HashMap<String, String>,
}

impl InternalCallRegistry {
    /// 空のレジストリを生成する。 `Arc` で wrap して `UasEventHandler` 等に
    /// 共有する。
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 確立済みエントリを挿入する。 同 Call-ID の上書きは「最後勝ち」
    /// (= 既存 [`OutboundCallRegistry::insert_confirmed`] と同じセマンティクス)。
    pub async fn insert(&self, entry: Arc<InternalCallEntry>) {
        let mut inner = self.inner.lock().await;
        inner
            .callee_to_caller
            .insert(entry.callee_call_id.clone(), entry.caller_call_id.clone());
        inner.by_caller.insert(entry.caller_call_id.clone(), entry);
    }

    /// caller Call-ID で entry を引く。
    pub async fn lookup_by_caller(&self, caller_call_id: &str) -> Option<Arc<InternalCallEntry>> {
        let inner = self.inner.lock().await;
        inner.by_caller.get(caller_call_id).cloned()
    }

    /// callee Call-ID で entry を引く。
    pub async fn lookup_by_callee(&self, callee_call_id: &str) -> Option<Arc<InternalCallEntry>> {
        let inner = self.inner.lock().await;
        let caller_id = inner.callee_to_caller.get(callee_call_id)?.clone();
        inner.by_caller.get(&caller_id).cloned()
    }

    /// caller Call-ID でエントリを取り除く。 callee 側 index も同時に消す。
    pub async fn remove_by_caller(&self, caller_call_id: &str) -> Option<Arc<InternalCallEntry>> {
        let mut inner = self.inner.lock().await;
        let entry = inner.by_caller.remove(caller_call_id)?;
        inner.callee_to_caller.remove(&entry.callee_call_id);
        Some(entry)
    }

    /// callee Call-ID でエントリを取り除く (caller index も同時に消す)。
    pub async fn remove_by_callee(&self, callee_call_id: &str) -> Option<Arc<InternalCallEntry>> {
        let mut inner = self.inner.lock().await;
        let caller_id = inner.callee_to_caller.remove(callee_call_id)?;
        inner.by_caller.remove(&caller_id)
    }

    /// 現在の通話数。
    pub async fn len(&self) -> usize {
        self.inner.lock().await.by_caller.len()
    }

    /// 同時通話上限 `max` に対し、 新規 1 件を受け入れられるか。
    ///
    /// `len() < max` を atomic に判定する helper。 呼出側は本関数が `false`
    /// を返したら 486 Busy Here 等で reject する (RFC 3261 §21.4.20)。
    pub async fn can_accept(&self, max: usize) -> bool {
        self.inner.lock().await.by_caller.len() < max
    }
}

/// `[intercom]` セクション設定 (Issue #313)。
///
/// TOML 表記:
/// ```toml
/// [intercom]
/// enabled = true
/// max_concurrent_internal_calls = 4
/// ```
///
/// 既定:
/// - `enabled = true` (AOR ヒット時は自動で内線間 dial に分岐)
/// - `max_concurrent_internal_calls = 4` (実機 SOHO 想定)
///
/// `enabled = false` のとき [`classify_dial_target`] は **呼出側で skip** し、
/// 常に NGN 経路を使う想定 (= 旧挙動を維持するキルスイッチ)。 本構造体自体は
/// classify のロジックを持たない (= 純データ型)。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntercomConfig {
    /// 機能 ON/OFF。 false にすると `classify_dial_target` を呼ばず常に NGN
    /// 経路を取る (= キルスイッチ)。 既定 `true`。
    #[serde(default = "default_intercom_enabled")]
    pub enabled: bool,
    /// 同時実行可能な内線間通話の上限。 これを超える新規発信は 486 Busy
    /// Here で reject する (RFC 3261 §21.4.20)。 既定 4。
    #[serde(default = "default_intercom_max_concurrent")]
    pub max_concurrent_internal_calls: usize,
}

impl Default for IntercomConfig {
    fn default() -> Self {
        Self {
            enabled: default_intercom_enabled(),
            max_concurrent_internal_calls: default_intercom_max_concurrent(),
        }
    }
}

fn default_intercom_enabled() -> bool {
    true
}

fn default_intercom_max_concurrent() -> usize {
    4
}

/// 上位の orchestrator から呼び出される内線間通話サービス。
///
/// [`InternalCallRegistry`] + 容量上限 ([`IntercomConfig::max_concurrent_internal_calls`])
/// を 1 つにまとめ、 dispatcher (`handle_pwa_outbound_offer` 等) が
/// `try_admit` → bridge 起動 → `register_call` のシーケンスを書きやすくする。
///
/// orchestrator が直接 `InternalCallRegistry` / `IntercomConfig` を扱うと
/// `Mutex<Option<...>>` の boilerplate が増えるため、 service 化してまとめる。
pub struct IntercomService {
    registry: Arc<InternalCallRegistry>,
    config: IntercomConfig,
}

impl IntercomService {
    /// 初期化。 `config.enabled = false` でも本 service は構築できる
    /// (= キルスイッチは呼出側で `is_enabled` を読んで分岐する想定)。
    pub fn new(config: IntercomConfig) -> Arc<Self> {
        Arc::new(Self {
            registry: InternalCallRegistry::new(),
            config,
        })
    }

    /// テスト / 共有のため registry 参照を返す。 BYE 経路など外部から
    /// remove したい場合に使う。
    pub fn registry(&self) -> Arc<InternalCallRegistry> {
        self.registry.clone()
    }

    /// 設定値の参照 (`enabled` / `max_concurrent_internal_calls`)。
    pub fn config(&self) -> &IntercomConfig {
        &self.config
    }

    /// `IntercomConfig::enabled` を返すヘルパ。
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// 新規 1 件を admit できるか。 容量超過は `Err(IntercomAdmitError::AtCapacity)`。
    /// 容量チェックを通った直後の `register_call` でレース挿入が起こりうるが、
    /// それは「上限 +1〜2 件」 程度の許容範囲なので簡易版で十分 (= 場当たり
    /// ではなく、 厳密なロックは hot path 性能の方が優先)。
    pub async fn try_admit(&self) -> std::result::Result<(), IntercomAdmitError> {
        if !self.config.enabled {
            return Err(IntercomAdmitError::Disabled);
        }
        if !self
            .registry
            .can_accept(self.config.max_concurrent_internal_calls)
            .await
        {
            return Err(IntercomAdmitError::AtCapacity {
                current: self.registry.len().await,
                max: self.config.max_concurrent_internal_calls,
            });
        }
        Ok(())
    }

    /// 確立済みエントリを登録する。 これは bridge 起動が成功した直後に呼ぶ。
    pub async fn register_call(&self, entry: Arc<InternalCallEntry>) {
        self.registry.insert(entry).await;
    }
}

/// `IntercomService::try_admit` の失敗種別。
#[derive(Debug)]
pub enum IntercomAdmitError {
    /// `IntercomConfig::enabled = false`。 呼出側は NGN 経路へフォールバック
    /// するか、 機能未設定エラーで返す。
    Disabled,
    /// 同時通話上限超過 (RFC 3261 §21.4.20 486 Busy Here で reject)。
    AtCapacity { current: usize, max: usize },
}

impl std::fmt::Display for IntercomAdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("intercom disabled in config"),
            Self::AtCapacity { current, max } => write!(
                f,
                "intercom at capacity: {} / {} (RFC 3261 §21.4.20)",
                current, max
            ),
        }
    }
}

impl std::error::Error for IntercomAdmitError {}

/// PWA↔PWA 内線間通話用に [`MediaBridge::WebRtcRelay`] を起動する helper。
///
/// caller / callee それぞれの [`PeerSession::take_media_rx`] を取り出して
/// `WebRtcRelayBridge::start` に渡し、 結果を [`CallManager`] に attach する。
/// 戻り値の [`CallId`] を [`InternalCallEntry::bridge_call_id`] にセットする。
///
/// # エラー条件
///
/// - 片側でも `take_media_rx` が `None` を返した場合 (stub backend / 既に
///   取得済み) は `Err`。 sabiden の str0m 本番経路では起動直後に 1 度だけ
///   取得可能なので、 通常は失敗しない。
/// - `CallManager::attach_media_bridge` 失敗時 (Unknown call) は `Err`。
pub async fn start_webrtc_relay_bridge(
    caller_peer: Arc<dyn PeerSession>,
    callee_peer: Arc<dyn PeerSession>,
    call_manager: &CallManager,
) -> Result<CallId> {
    let caller_rx = caller_peer
        .take_media_rx()
        .await
        .ok_or_else(|| anyhow::anyhow!("caller peer.take_media_rx None"))?;
    let callee_rx = callee_peer
        .take_media_rx()
        .await
        .ok_or_else(|| anyhow::anyhow!("callee peer.take_media_rx None"))?;
    let bridge: MediaBridge = WebRtcRelayBridge::start(WebRtcRelayConfig {
        caller_peer,
        caller_media_rx: caller_rx,
        callee_peer,
        callee_media_rx: callee_rx,
    })
    .into();
    let cid = call_manager.create_call().await;
    call_manager
        .attach_media_bridge(cid, bridge)
        .await
        .map_err(|e| anyhow::anyhow!("attach_media_bridge: {}", e))?;
    Ok(cid)
}

/// `take_media_rx` が既に消費済みの peer (テスト経路) でも bridge を組めるよう、
/// 呼出側が `mpsc::Receiver<MediaFrame>` を直接持っているとき用の代替 helper。
///
/// 主な用途はテスト / E2E ハーネス。 production code は
/// [`start_webrtc_relay_bridge`] を使う。
pub async fn start_webrtc_relay_bridge_with_explicit_rx(
    caller_peer: Arc<dyn PeerSession>,
    caller_media_rx: mpsc::Receiver<MediaFrame>,
    callee_peer: Arc<dyn PeerSession>,
    callee_media_rx: mpsc::Receiver<MediaFrame>,
    call_manager: &CallManager,
) -> Result<CallId> {
    let bridge: MediaBridge = WebRtcRelayBridge::start(WebRtcRelayConfig {
        caller_peer,
        caller_media_rx,
        callee_peer,
        callee_media_rx,
    })
    .into();
    let cid = call_manager.create_call().await;
    call_manager
        .attach_media_bridge(cid, bridge)
        .await
        .map_err(|e| anyhow::anyhow!("attach_media_bridge: {}", e))?;
    Ok(cid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::registrar::ExtTransport;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Issue #313 DoD: AOR が registrar に登録済みのとき [`classify_dial_target`]
    /// は `Internal { aor, binding }` を返す。
    #[tokio::test]
    async fn rfc3261_10_classify_returns_internal_when_aor_registered() {
        let reg = ExtensionRegistrar::new();
        reg.register(
            "alice",
            "sip:alice@192.0.2.10:5060".to_string(),
            addr("192.0.2.10:5060"),
            Duration::from_secs(60),
        )
        .await;
        let dest = classify_dial_target("alice", &reg).await;
        match dest {
            DialDestination::Internal { aor, binding } => {
                assert_eq!(aor, "alice");
                assert_eq!(binding.contact_uri, "sip:alice@192.0.2.10:5060");
                assert!(matches!(binding.transport, ExtTransport::Sip));
            }
            DialDestination::Ngn { .. } => panic!("Internal を期待"),
        }
    }

    /// Issue #313: AOR ヒットしない番号 (= NGN 番号 / 不在番号) は
    /// 既存挙動どおり [`DialDestination::Ngn`] を返す。
    #[tokio::test]
    async fn rfc3261_10_classify_falls_back_to_ngn_when_no_aor_match() {
        let reg = ExtensionRegistrar::new();
        let dest = classify_dial_target("117", &reg).await;
        match dest {
            DialDestination::Ngn { ref target } => {
                assert_eq!(target, "117");
                assert!(!dest.is_internal());
            }
            DialDestination::Internal { .. } => {
                panic!("AOR 未登録なので Ngn を期待")
            }
        }
    }

    /// 期限切れ binding は `registrar.lookup` 側で除外されるため、
    /// classify からも内線扱いにならない。
    #[tokio::test]
    async fn classify_treats_expired_binding_as_ngn() {
        let reg = ExtensionRegistrar::new();
        reg.register(
            "ghost",
            "sip:ghost@192.0.2.20:5060".to_string(),
            addr("192.0.2.20:5060"),
            Duration::from_millis(10),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let dest = classify_dial_target("ghost", &reg).await;
        assert!(
            matches!(dest, DialDestination::Ngn { .. }),
            "期限切れは NGN 扱い"
        );
    }

    /// `internal_aor()` ヘルパが Internal のみ Some を返す。
    #[tokio::test]
    async fn internal_aor_helper_returns_some_only_for_internal() {
        let reg = ExtensionRegistrar::new();
        reg.register(
            "bob",
            "sip:bob@198.51.100.5:5060".to_string(),
            addr("198.51.100.5:5060"),
            Duration::from_secs(60),
        )
        .await;
        let internal = classify_dial_target("bob", &reg).await;
        assert_eq!(internal.internal_aor(), Some("bob"));

        let ngn = classify_dial_target("0312345678", &reg).await;
        assert_eq!(ngn.internal_aor(), None);
    }

    /// [`InternalCallRegistry`] は caller / callee 両 Call-ID からエントリを
    /// 引け、 remove も双方向に整合する。
    #[tokio::test]
    async fn internal_registry_double_index_caller_and_callee() {
        let reg = InternalCallRegistry::new();
        let entry = InternalCallEntry::new("call-A", "call-B", "alice", "bob", CallId::next());
        reg.insert(entry.clone()).await;

        let by_caller = reg.lookup_by_caller("call-A").await.expect("caller");
        assert_eq!(by_caller.caller_aor, "alice");
        assert_eq!(by_caller.callee_aor, "bob");

        let by_callee = reg.lookup_by_callee("call-B").await.expect("callee");
        assert_eq!(by_callee.caller_aor, "alice");
        assert_eq!(by_callee.callee_aor, "bob");

        // remove で 1 件は両 index から消える。
        let removed = reg.remove_by_caller("call-A").await.expect("removed");
        assert_eq!(removed.callee_call_id, "call-B");
        assert!(reg.lookup_by_callee("call-B").await.is_none());
        assert!(reg.lookup_by_caller("call-A").await.is_none());
    }

    /// callee 側 Call-ID で remove しても caller 側 index がリークしない。
    #[tokio::test]
    async fn internal_registry_remove_by_callee_cleans_both_indices() {
        let reg = InternalCallRegistry::new();
        let entry = InternalCallEntry::new("call-1", "call-2", "x", "y", CallId::next());
        reg.insert(entry).await;
        assert!(reg.remove_by_callee("call-2").await.is_some());
        assert_eq!(reg.len().await, 0);
        assert!(reg.lookup_by_caller("call-1").await.is_none());
        assert!(reg.lookup_by_callee("call-2").await.is_none());
    }

    /// `can_accept(max)` は `len() < max` のときに true。 max = 0 は常時 false。
    #[tokio::test]
    async fn intercom_capacity_can_accept_respects_max() {
        let reg = InternalCallRegistry::new();
        assert!(reg.can_accept(1).await);
        assert!(!reg.can_accept(0).await);

        let e = InternalCallEntry::new("a", "b", "x", "y", CallId::next());
        reg.insert(e).await;
        assert!(!reg.can_accept(1).await);
        assert!(reg.can_accept(2).await);
    }

    /// `IntercomConfig::default()` は enabled=true / max=4。
    #[test]
    fn intercom_config_defaults_are_enabled_and_max_4() {
        let cfg = IntercomConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_concurrent_internal_calls, 4);
    }

    /// TOML から `[intercom]` セクションを上書きできる。
    #[test]
    fn intercom_config_parses_from_toml() {
        let toml_str = r#"
enabled = false
max_concurrent_internal_calls = 8
"#;
        let cfg: IntercomConfig = toml::from_str(toml_str).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_concurrent_internal_calls, 8);
    }

    /// TOML で `[intercom]` 全省略 → `IntercomConfig::default()` と同等
    /// (= enabled=true / max=4)。 後方互換性確認。
    #[test]
    fn intercom_config_defaults_when_toml_section_empty() {
        let cfg: IntercomConfig = toml::from_str("").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_concurrent_internal_calls, 4);
    }

    /// Issue #313: `IntercomService::try_admit` は容量内 OK / 容量超過 AtCapacity /
    /// disabled 構成では Disabled を返す。
    #[tokio::test]
    async fn rfc3261_21_4_20_intercom_service_admit_capacity_gating() {
        let svc = IntercomService::new(IntercomConfig {
            enabled: true,
            max_concurrent_internal_calls: 2,
        });

        // 0/2 → OK
        svc.try_admit().await.unwrap();

        // 1 件挿入
        let e1 = InternalCallEntry::new("c1", "p1", "alice", "bob", CallId::next());
        svc.register_call(e1).await;
        svc.try_admit().await.unwrap();

        // 2 件挿入 (上限到達)
        let e2 = InternalCallEntry::new("c2", "p2", "carol", "dave", CallId::next());
        svc.register_call(e2).await;
        match svc.try_admit().await {
            Err(IntercomAdmitError::AtCapacity { current, max }) => {
                assert_eq!(current, 2);
                assert_eq!(max, 2);
            }
            other => panic!("AtCapacity を期待: {:?}", other),
        }

        // disabled service は AtCapacity 前に Disabled を返す
        let svc_off = IntercomService::new(IntercomConfig {
            enabled: false,
            max_concurrent_internal_calls: 10,
        });
        assert!(matches!(
            svc_off.try_admit().await,
            Err(IntercomAdmitError::Disabled)
        ));
    }

    /// Issue #313 DoD: PWA→PWA 内線間通話で双方向 audio が成立する
    /// (integration test、 mock peer 2 個 + 実 CallManager + 実 MediaBridge::WebRtcRelay)。
    ///
    /// orchestrator 抜きの shell test だが、 [`IntercomService`] +
    /// [`start_webrtc_relay_bridge_with_explicit_rx`] + [`CallManager`] +
    /// [`MediaBridge::WebRtcRelay`] の組み合わせで PWA caller →
    /// sabiden → PWA callee の片方向 frame 配送が成立することを確認する。
    /// 反対方向も対称に動く。
    #[tokio::test]
    async fn rfc5853_pwa_to_pwa_intercom_integration_bidirectional() {
        use crate::webrtc::peer::MediaFrame;
        use std::sync::atomic::{AtomicU32, Ordering as AOrd};
        use std::time::Instant;
        use tokio::sync::Mutex as TMutex;

        struct CapturePeer {
            label: &'static str,
            received: Arc<TMutex<Vec<MediaFrame>>>,
            count: Arc<AtomicU32>,
        }

        #[async_trait::async_trait]
        impl PeerSession for CapturePeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, frame: MediaFrame) -> anyhow::Result<()> {
                tracing::debug!(label = self.label, "captured frame");
                self.count.fetch_add(1, AOrd::SeqCst);
                self.received.lock().await.push(frame);
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let caller_recv = Arc::new(TMutex::new(Vec::new()));
        let callee_recv = Arc::new(TMutex::new(Vec::new()));
        let caller_count = Arc::new(AtomicU32::new(0));
        let callee_count = Arc::new(AtomicU32::new(0));

        let caller_peer: Arc<dyn PeerSession> = Arc::new(CapturePeer {
            label: "caller",
            received: caller_recv.clone(),
            count: caller_count.clone(),
        });
        let callee_peer: Arc<dyn PeerSession> = Arc::new(CapturePeer {
            label: "callee",
            received: callee_recv.clone(),
            count: callee_count.clone(),
        });

        let (caller_up_tx, caller_up_rx) = mpsc::channel::<MediaFrame>(8);
        let (callee_up_tx, callee_up_rx) = mpsc::channel::<MediaFrame>(8);

        // 同時通話上限 4 (= default) の service を構築。
        let svc = IntercomService::new(IntercomConfig::default());
        svc.try_admit().await.expect("admit");

        // registrar に callee を登録 (= classify は Internal を返す前提を確認)
        let registrar = ExtensionRegistrar::new();
        registrar
            .register(
                "bob",
                "sip:bob@webrtc.peer".to_string(),
                "127.0.0.1:5060".parse().unwrap(),
                std::time::Duration::from_secs(60),
            )
            .await;
        match classify_dial_target("bob", &registrar).await {
            DialDestination::Internal { aor, .. } => assert_eq!(aor, "bob"),
            other => panic!("Internal を期待: {:?}", other),
        }

        let call_mgr = CallManager::new(registrar);

        let cid = start_webrtc_relay_bridge_with_explicit_rx(
            caller_peer,
            caller_up_rx,
            callee_peer,
            callee_up_rx,
            &call_mgr,
        )
        .await
        .expect("start_webrtc_relay_bridge");

        // 内線通話を registry に登録 (orchestrator が本流でやる手順を再現)。
        svc.register_call(InternalCallEntry::new(
            "caller-call-id",
            "callee-call-id",
            "alice",
            "bob",
            cid,
        ))
        .await;
        assert_eq!(svc.registry().len().await, 1);

        // 双方向に PCMU MediaFrame を 3 個ずつ流して、 反対側の peer に届くこと
        // を確認する (RFC 3551 §4.5.14 PCMU 20ms = 160 sample)。
        for i in 0..3u32 {
            caller_up_tx
                .send(MediaFrame {
                    pt: 0,
                    rtp_time: 160 * i,
                    payload: vec![0xC0 | (i as u8); 160],
                    network_time: Instant::now(),
                })
                .await
                .unwrap();
            callee_up_tx
                .send(MediaFrame {
                    pt: 0,
                    rtp_time: 160 * (i + 100),
                    payload: vec![0xD0 | (i as u8); 160],
                    network_time: Instant::now(),
                })
                .await
                .unwrap();
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while callee_count.load(AOrd::SeqCst) < 3 || caller_count.load(AOrd::SeqCst) < 3 {
            if std::time::Instant::now() > deadline {
                panic!(
                    "PWA-PWA 双方向 audio が成立しない: caller_recv={} callee_recv={}",
                    caller_count.load(AOrd::SeqCst),
                    callee_count.load(AOrd::SeqCst)
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        // 内容透過確認 (payload first byte の高 nibble = caller/callee マーカ)。
        let callee_got = callee_recv.lock().await;
        for (i, f) in callee_got.iter().enumerate() {
            assert_eq!(f.pt, 0);
            assert_eq!(f.payload[0] & 0xF0, 0xC0, "caller→callee frame {}", i);
        }
        let caller_got = caller_recv.lock().await;
        for (i, f) in caller_got.iter().enumerate() {
            assert_eq!(f.pt, 0);
            assert_eq!(f.payload[0] & 0xF0, 0xD0, "callee→caller frame {}", i);
        }

        // 内線間通話エントリを終了させる (CallManager terminate でブリッジ停止)。
        call_mgr.terminate(cid).await.expect("terminate");
        svc.registry().remove_by_caller("caller-call-id").await;
        assert_eq!(svc.registry().len().await, 0);
    }

    /// Issue #313 DoD: PWA caller → SIP UA callee の内線間通話で双方向 audio が
    /// 成立する (integration test、 mock SIP peer = UDP socket、 mock PWA peer =
    /// `PeerSession` 実装)。
    ///
    /// この経路では sabiden は:
    /// - PWA leg = `WebRtcAudioBridge` の peer 側 I/O を使う (str0m MediaFrame)
    /// - SIP UA leg = `WebRtcAudioBridge` の `ngn_socket` を流用して UDP RTP を
    ///   端末へ流す。 SIP UA は両側 PCMU 構成 (RFC 3551 §4.5.14) を前提とし
    ///   `direct_pcmu_passthrough = true` で transcode を skip する。
    ///
    /// 実装上 `WebRtcAudioBridge` の "ngn_socket" 名は NGN 専用ではなく
    /// 「PCMU UDP socket」 として汎用に使えるため、 内線 SIP UA 側にそのまま
    /// repurpose できる (= 既存実装の再利用)。
    #[tokio::test]
    async fn rfc5853_pwa_to_sip_ua_intercom_integration_bidirectional() {
        use crate::call::transcoder::{WebRtcAudioBridge, WebRtcAudioConfig, DEFAULT_OPUS_PT};
        use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
        use crate::webrtc::peer::MediaFrame;
        use std::sync::atomic::{AtomicU32, Ordering as AOrd};
        use std::time::Instant;
        use tokio::net::UdpSocket;
        use tokio::sync::Mutex as TMutex;
        use tokio::time::timeout;

        struct CapturePeer {
            received: Arc<TMutex<Vec<MediaFrame>>>,
            count: Arc<AtomicU32>,
        }
        #[async_trait::async_trait]
        impl PeerSession for CapturePeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn send_media(&self, frame: MediaFrame) -> anyhow::Result<()> {
                self.count.fetch_add(1, AOrd::SeqCst);
                self.received.lock().await.push(frame);
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        // SIP UA leg = 普通の UDP socket (mock SIP UA はこの port に向けて送受信する)。
        let sabi_to_sipua_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sabi_to_sipua_addr = sabi_to_sipua_sock.local_addr().unwrap();
        let sip_ua_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sip_ua_addr = sip_ua_sock.local_addr().unwrap();

        // PWA leg = mock peer + caller_up channel
        let pwa_received = Arc::new(TMutex::new(Vec::new()));
        let pwa_count = Arc::new(AtomicU32::new(0));
        let pwa_peer: Arc<dyn PeerSession> = Arc::new(CapturePeer {
            received: pwa_received.clone(),
            count: pwa_count.clone(),
        });
        let (pwa_up_tx, pwa_up_rx) = mpsc::channel::<MediaFrame>(8);

        // WebRtcAudioBridge を "ngn_socket = SIP UA leg socket" として起動。
        // direct_pcmu_passthrough = true で SIP UA 側も PCMU PT0 を素通し。
        let bridge = WebRtcAudioBridge::start(WebRtcAudioConfig {
            ngn_socket: sabi_to_sipua_sock.clone(),
            ngn_peer: Some(sip_ua_addr),
            peer: pwa_peer.clone(),
            peer_media_rx: pwa_up_rx,
            opus_payload_type: DEFAULT_OPUS_PT,
            direct_pcmu_passthrough: true,
            metrics: None,
        });
        let bridge_arc: MediaBridge = bridge.into();

        // Step 1: SIP UA → sabiden RTP (PCMU PT 0) を受信した sabiden が
        // peer.send_media で PWA に届ける。
        let pkt = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 0,
            ssrc: 0xCAFE,
            payload: vec![0xff; 160],
        }
        .to_bytes();
        sip_ua_sock.send_to(&pkt, sabi_to_sipua_addr).await.unwrap();

        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        while pwa_count.load(AOrd::SeqCst) == 0 {
            if Instant::now() > deadline {
                panic!("SIP UA→PWA frame が PWA に届かない");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let got = pwa_received.lock().await;
        assert_eq!(got[0].pt, 0, "PCMU PT 0 で PWA に渡る");
        assert_eq!(got[0].payload.len(), 160, "PCMU 20ms = 160 byte");
        drop(got);

        // Step 2: PWA → sabiden MediaFrame を sabiden が SIP UA UDP に転送する。
        pwa_up_tx
            .send(MediaFrame {
                pt: 0,
                rtp_time: 160,
                payload: vec![0xee; 160],
                network_time: Instant::now(),
            })
            .await
            .unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, _src) = timeout(
            std::time::Duration::from_secs(2),
            sip_ua_sock.recv_from(&mut buf),
        )
        .await
        .expect("PWA→SIP UA frame が SIP UA に届かない")
        .unwrap();
        let recv_rtp = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv_rtp.payload_type, PAYLOAD_TYPE_ULAW);
        assert_eq!(recv_rtp.payload, vec![0xee; 160]);

        bridge_arc.stop().await;
    }

    /// Issue #313 DoD: SIP UA → SIP UA の内線間通話で双方向 RTP が成立する
    /// (integration test、 既存 `RtpBridge` を流用)。 両側とも PCMU UDP なので
    /// `MediaBridge::Relay` で純リレーするだけで十分。
    #[tokio::test]
    async fn rfc3551_sip_ua_to_sip_ua_intercom_integration_bidirectional() {
        use crate::call::bridge::{BridgeConfig, RtpBridge};
        use crate::rtp::packet::{RtpPacket, PAYLOAD_TYPE_ULAW};
        use tokio::net::UdpSocket;
        use tokio::time::timeout;

        // sabiden 側 caller-leg / callee-leg socket
        let caller_leg_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let callee_leg_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let caller_leg_addr = caller_leg_sock.local_addr().unwrap();
        let callee_leg_addr = callee_leg_sock.local_addr().unwrap();

        // mock SIP UA 2 台
        let caller_ua = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee_ua = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caller_ua_addr = caller_ua.local_addr().unwrap();
        let callee_ua_addr = callee_ua.local_addr().unwrap();

        // RtpBridge を「caller-leg ⇄ callee-leg」 として起動 (NGN 名は historical)。
        let bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: caller_leg_sock, // caller-leg
            ext_socket: callee_leg_sock, // callee-leg
            ngn_peer: Some(caller_ua_addr),
            ext_peer: Some(callee_ua_addr),
            metrics: None,
        })
        .unwrap();

        // caller_ua → caller-leg → callee-leg → callee_ua
        let pkt1 = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 1,
            timestamp: 0,
            ssrc: 0xAAAA,
            payload: vec![0x11; 160],
        }
        .to_bytes();
        caller_ua.send_to(&pkt1, caller_leg_addr).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let (n, _) = timeout(
            std::time::Duration::from_secs(1),
            callee_ua.recv_from(&mut buf),
        )
        .await
        .expect("caller→callee 配送失敗")
        .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.ssrc, 0xAAAA);

        // callee_ua → callee-leg → caller-leg → caller_ua
        let pkt2 = RtpPacket {
            payload_type: PAYLOAD_TYPE_ULAW,
            marker: false,
            sequence: 2,
            timestamp: 160,
            ssrc: 0xBBBB,
            payload: vec![0x22; 160],
        }
        .to_bytes();
        callee_ua.send_to(&pkt2, callee_leg_addr).await.unwrap();
        let (n, _) = timeout(
            std::time::Duration::from_secs(1),
            caller_ua.recv_from(&mut buf),
        )
        .await
        .expect("callee→caller 配送失敗")
        .unwrap();
        let recv = RtpPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(recv.ssrc, 0xBBBB);

        bridge.stop().await;
    }

    /// Issue #313 multi-line DoD: 内線間通話 (caller→callee) と NGN 発着信
    /// (= 別 CallId の `MediaBridge::Relay` を想定) が同時に立っても registry / mgr
    /// 上で独立に扱われ、 互いの停止が他方を巻き込まないことを確認する。
    /// 実 NGN UDP ソケットは使わず、 「NGN 側通話を表す `Relay` の `CallId`
    /// と intercom の `CallId` が独立に管理される」 ことだけを検証する。
    #[tokio::test]
    async fn issue313_multi_line_internal_and_ngn_coexist_independently() {
        use crate::call::bridge::{BridgeConfig, RtpBridge};
        use tokio::net::UdpSocket;

        let registrar = ExtensionRegistrar::new();
        registrar
            .register(
                "alice",
                "sip:alice@webrtc.peer".to_string(),
                "127.0.0.1:5060".parse().unwrap(),
                std::time::Duration::from_secs(60),
            )
            .await;
        let call_mgr = CallManager::new(registrar.clone());

        // ---- NGN 経路の通話 (PCMU↔PCMU RtpBridge) を 1 件先に確立 ----
        let ngn_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ext_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ngn_bridge = RtpBridge::start(BridgeConfig {
            ngn_socket: ngn_sock,
            ext_socket: ext_sock,
            ngn_peer: None,
            ext_peer: None,
            metrics: None,
        })
        .unwrap();
        let ngn_call_id = call_mgr.create_call().await;
        call_mgr
            .attach_media_bridge(ngn_call_id, ngn_bridge.into())
            .await
            .unwrap();

        // ---- intercom service で内線間通話 1 件を確立 ----
        let svc = IntercomService::new(IntercomConfig::default());
        svc.try_admit().await.unwrap();

        // mock peer
        struct NoopPeer;
        #[async_trait::async_trait]
        impl PeerSession for NoopPeer {
            async fn handle_offer(&self, _sdp: &str) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn create_offer(&self) -> anyhow::Result<String> {
                Ok(String::new())
            }
            async fn accept_answer(&self, _sdp: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn add_ice_candidate(&self, _c: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }
        let caller_peer: Arc<dyn PeerSession> = Arc::new(NoopPeer);
        let callee_peer: Arc<dyn PeerSession> = Arc::new(NoopPeer);
        let (_t1, r1) = mpsc::channel::<MediaFrame>(1);
        let (_t2, r2) = mpsc::channel::<MediaFrame>(1);
        let intercom_call_id =
            start_webrtc_relay_bridge_with_explicit_rx(caller_peer, r1, callee_peer, r2, &call_mgr)
                .await
                .unwrap();
        svc.register_call(InternalCallEntry::new(
            "X",
            "Y",
            "alice",
            "bob",
            intercom_call_id,
        ))
        .await;

        // 同時に 2 通話が独立に走っている (= multi-line)
        assert_eq!(call_mgr.len().await, 2);
        assert_eq!(svc.registry().len().await, 1);

        // 内線間通話を終了しても NGN 経路は影響を受けない (独立性確認)。
        call_mgr.terminate(intercom_call_id).await.unwrap();
        svc.registry().remove_by_caller("X").await;
        assert_eq!(call_mgr.len().await, 1, "NGN 経路は残っているべき");
        assert!(call_mgr.state_of(ngn_call_id).await.is_some());
        assert_eq!(svc.registry().len().await, 0);

        // 逆も同様: NGN 経路を終了しても internal registry は無影響。
        call_mgr.terminate(ngn_call_id).await.unwrap();
        assert_eq!(call_mgr.len().await, 0);
    }
}
