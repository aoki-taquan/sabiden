pub mod addr;
pub mod auth;
pub mod dialog;
pub mod message;
pub mod register;
pub mod registrar;
pub mod transaction;
pub mod uac;
pub mod uas;
pub mod utils;

use std::sync::{OnceLock, RwLock};

/// REGISTER 200 OK で受領した Service-Route (RFC 3608 §3.2)。
/// IMS では subsequent request の Route ヘッダに echo MUST。
///
/// TODO(本流対応): 複数 AOR 対応時は per-AOR HashMap 化が必要
/// (CLAUDE.md §9 既知の `static CSEQ` と同種パターン、 単一 AOR 前提)。
/// `docs/refactor-plan.md` §4 に追記。 follow-up Issue 起票予定。
static SERVICE_ROUTE: OnceLock<RwLock<Option<String>>> = OnceLock::new();

fn service_route_cell() -> &'static RwLock<Option<String>> {
    SERVICE_ROUTE.get_or_init(|| RwLock::new(None))
}

/// REGISTER 200 OK 受領後、 Service-Route ヘッダ値を保存する。
/// `None` を渡すとクリア。
pub fn store_service_route(value: Option<String>) {
    if let Ok(mut guard) = service_route_cell().write() {
        *guard = value;
    }
}

/// 保存済み Service-Route を取得 (subsequent INVITE 等の Route ヘッダ用)。
pub fn current_service_route() -> Option<String> {
    service_route_cell().read().ok().and_then(|g| g.clone())
}

/// NGN P-CSCF を直指定する outbound_proxy 風 Route (Asterisk pcap 互換、
/// `docs/asterisk-real-invite.md` §5.5)。 REGISTER server_addr を保存し
/// subsequent INVITE の Route として固定使用 (Service-Route の domain だけでは
/// 解決経路に多段 hop が入り NGN 実機適合に劣るため)。
///
/// TODO(本流対応): 複数 AOR / 複数 P-CSCF 対応時は per-AOR map 化必要
/// (CLAUDE.md §9 既知の静的 mutable singleton パターンと同種)。
static OUTBOUND_PROXY_ROUTE: OnceLock<RwLock<Option<String>>> = OnceLock::new();
fn outbound_proxy_route_cell() -> &'static RwLock<Option<String>> {
    OUTBOUND_PROXY_ROUTE.get_or_init(|| RwLock::new(None))
}
pub fn store_outbound_proxy_route(value: Option<String>) {
    if let Ok(mut guard) = outbound_proxy_route_cell().write() {
        *guard = value;
    }
}
pub fn current_outbound_proxy_route() -> Option<String> {
    outbound_proxy_route_cell()
        .read()
        .ok()
        .and_then(|g| g.clone())
}
