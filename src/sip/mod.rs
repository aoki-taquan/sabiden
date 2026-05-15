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
/// 複数 AOR 対応するなら per-AOR HashMap 化が必要 (現在は単一 AOR 前提)。
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

/// NGN P-CSCF を直指定する outbound_proxy 風 Route (Asterisk pcap 互換)。
/// REGISTER server_addr を Route として固定使用。
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

/// Phase 1-C: 500 受領時に強制 re-REGISTER を要求するシグナル。
/// 3GPP TS 24.229 §5.2.6 (P-CSCF restoration) で 500 は "registration を作り直せ"
/// の indication。 orchestrator が 500 検知時に notify、 Registrar が次の register
/// cycle を即時実行する (refresh sleep を抜ける)。
static RE_REGISTER_NOTIFY: OnceLock<tokio::sync::Notify> = OnceLock::new();

pub fn re_register_notify() -> &'static tokio::sync::Notify {
    RE_REGISTER_NOTIFY.get_or_init(tokio::sync::Notify::new)
}

/// 強制 re-REGISTER を要求する (orchestrator から 500 検知時にコール)。
pub fn request_re_register() {
    re_register_notify().notify_one();
}
