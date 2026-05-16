//! ヘルスチェック HTTP サーバ
//!
//! Kubernetes の liveness / readiness probe 用エンドポイントと、
//! Prometheus 互換のメトリクス エンドポイントを提供する。
//!
//! - `GET /healthz`: プロセス生存確認 (常に 200)
//! - `GET /readyz`:  REGISTER 成功時のみ 200、それ以外は 503
//! - `GET /metrics`: Prometheus text exposition format
//!
//! REGISTER 状態は `Arc<AtomicBool>` で SIP レイヤと共有する。
//! メトリクス本体は [`crate::observability::Metrics`] を共有することで、
//! SIP / RTP / Call レイヤから atomic 加算するだけで Prometheus に
//! 反映される。`prometheus` クレートを引き込まないため依存は変わらない。
//!
//! `axum` (hyper ベース) を採用したのは、追加依存が tokio/hyper 系に閉じており
//! 軽量かつ非同期 main にそのまま乗るため。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::info;

use crate::observability::call_log::CallLog;
use crate::observability::Metrics;
use crate::webrtc::signaling::{signal_ws_handler, SignalingState};

/// `GET /api/call-log/recent?n=20` のクエリパラメータ (Issue #278)。
///
/// `n` は最新通話件数の上限。 省略時は [`DEFAULT_CALL_LOG_LIMIT`]、 過大値は
/// `CallLog` 側の ring buffer 容量で打ち切られる。
#[derive(Debug, Deserialize)]
pub struct CallLogQuery {
    pub n: Option<usize>,
}

/// `n` 省略時のデフォルト件数 (PWA UI で同時表示する想定の数)。
pub const DEFAULT_CALL_LOG_LIMIT: usize = 20;

/// ヘルスサーバが参照する共有状態
#[derive(Clone)]
pub struct HealthState {
    /// REGISTER 成功フラグ。SIP レイヤから書き込まれる
    pub registered: Arc<AtomicBool>,
    /// 観測カウンタ。各層と Arc 共有する。
    pub metrics: Arc<Metrics>,
    /// Issue #278: 通話履歴 ring buffer。 `/api/call-log/recent` で公開する。
    pub call_log: Arc<CallLog>,
}

impl HealthState {
    pub fn new(registered: Arc<AtomicBool>, metrics: Arc<Metrics>, call_log: Arc<CallLog>) -> Self {
        Self {
            registered,
            metrics,
            call_log,
        }
    }
}

/// `/healthz` `/readyz` `/metrics` `/api/call-log/recent` を提供する `Router` を構築する
pub fn router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/api/call-log/recent", get(call_log_recent))
        .with_state(state)
}

/// `/healthz` `/readyz` `/metrics` に加え、WebRTC シグナリング `/signal` を
/// 追加した Router を構築する (Issue #23)。
///
/// `signal` は `SignalingState` を別 State として持つ axum の MethodRouter
/// に紐づく。両 State を 1 つの Router に同居させるため、`/signal` 用の
/// サブルータを `with_state` 適用後に `merge` する。
pub fn router_with_signaling(state: HealthState, signaling: SignalingState) -> Router {
    let signal_router = Router::new()
        .route("/signal", get(signal_ws_handler))
        .with_state(signaling);
    router(state).merge(signal_router)
}

/// 指定したアドレスで HTTP サーバを起動する。`run` は終了するまで返らない。
pub async fn run(bind_addr: SocketAddr, state: HealthState) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind health server: {}", bind_addr))?;
    let actual = listener.local_addr().unwrap_or(bind_addr);
    info!("health server listening: {}", actual);

    axum::serve(listener, router(state))
        .await
        .context("health server crashed")?;
    Ok(())
}

/// シグナリング付き HTTP サーバを起動する (Issue #23)。
///
/// WS の `ConnectInfo<SocketAddr>` を抽出するため、
/// `into_make_service_with_connect_info` で listener を消費する。
pub async fn run_with_signaling(
    bind_addr: SocketAddr,
    state: HealthState,
    signaling: SignalingState,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind health server: {}", bind_addr))?;
    let actual = listener.local_addr().unwrap_or(bind_addr);
    info!("health server (with /signal) listening: {}", actual);

    let app = router_with_signaling(state, signaling);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("health server crashed")?;
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    // プロセスが応答できる時点で生存とみなす
    (StatusCode::OK, "ok\n")
}

async fn readyz(State(state): State<HealthState>) -> impl IntoResponse {
    if state.registered.load(Ordering::SeqCst) {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

async fn metrics(State(state): State<HealthState>) -> impl IntoResponse {
    let registered = state.registered.load(Ordering::SeqCst);
    let body = state.metrics.render_prometheus(registered);
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

/// `GET /api/call-log/recent?n=20` — Issue #278 PWA「最近の通話」 UI 向け JSON API。
///
/// `n` を省略すると [`DEFAULT_CALL_LOG_LIMIT`] 件、 ring buffer 容量を超える `n` は
/// 内部で打ち切られる。 レスポンスは新しい順 (= 最新通話が先頭) の配列。
async fn call_log_recent(
    State(state): State<HealthState>,
    Query(q): Query<CallLogQuery>,
) -> impl IntoResponse {
    let n = q.n.unwrap_or(DEFAULT_CALL_LOG_LIMIT);
    let entries = state.call_log.recent(n);
    (StatusCode::OK, Json(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::InviteResult;
    use axum::body::to_bytes;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    fn make_state(registered: bool) -> HealthState {
        HealthState::new(
            Arc::new(AtomicBool::new(registered)),
            Metrics::new(),
            Arc::new(CallLog::new(100)),
        )
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn healthz_always_ok() {
        let app = router(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_unregistered_returns_503() {
        let app = router(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readyz_registered_returns_200() {
        let state = make_state(false);
        // SIP レイヤが REGISTER 成功を書き込んだ状況をシミュレート
        state.registered.store(true, Ordering::SeqCst);
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_reflects_registered_flag() {
        let state = make_state(true);
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("sabiden_sip_registered 1"));
    }

    #[tokio::test]
    async fn metrics_zero_when_not_registered() {
        let app = router(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_string(resp).await;
        assert!(body.contains("sabiden_sip_registered 0"));
    }

    #[tokio::test]
    async fn metrics_includes_extended_series() {
        let state = make_state(true);
        state.metrics.record_register(true);
        state.metrics.record_invite_ngn(InviteResult::Answered);
        state.metrics.add_rtp_ngn_to_ext(3);
        state.metrics.set_extension_registered(2);
        state.metrics.inc_call_active();

        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_string(resp).await;
        // 新規追加のメトリクスが /metrics に出ることを確認
        assert!(body.contains("sabiden_sip_register_total{result=\"success\"} 1"));
        assert!(body.contains("sabiden_sip_invite_total{direction=\"ngn\",result=\"answered\"} 1"));
        assert!(body.contains("sabiden_rtp_bridge_packets_total{direction=\"ngn_to_ext\"} 3"));
        assert!(body.contains("sabiden_extension_registered 2"));
        assert!(body.contains("sabiden_call_active 1"));
    }

    /// Issue #278: `GET /api/call-log/recent` が JSON で履歴を返す。
    ///
    /// `record_start` / `record_end` で 2 件の通話 (outbound + inbound) を
    /// CallLog に書き込んでから endpoint を叩く。 返値が新しい順かつ outcome /
    /// remote_number / direction が正しいことを assert する。
    ///
    /// PR #286 review 🟡#2: 旧実装は `body.contains("...")` による文字列検索だった
    /// ため、 (a) JSON 構造の検証になっていない (b) key/value 取り違えに気付け
    /// ない、 という弱点があった。 serde_json で実際に `Vec<Value>` にパースし、
    /// array indexing で fields を検証する。
    #[tokio::test]
    async fn call_log_recent_returns_entries_in_newest_first_order() {
        use crate::observability::call_log::{Direction, Outcome};

        let state = make_state(true);
        // 1 件目: outbound (発信) → Answered。
        state
            .call_log
            .record_start(Direction::Outbound, "117".into(), "cid-1".into());
        state.call_log.record_end("cid-1", Outcome::Answered);
        // 2 件目: inbound (着信) → Missed。
        state
            .call_log
            .record_start(Direction::Inbound, "0312345678".into(), "cid-2".into());
        state.call_log.record_end("cid-2", Outcome::Missed);

        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/call-log/recent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let arr: Vec<serde_json::Value> =
            serde_json::from_str(&body).expect("response must be a JSON array");
        assert_eq!(arr.len(), 2, "expected 2 entries, body = {body}");

        // [0] = 新しい方 (cid-2、 inbound, missed)
        assert_eq!(arr[0]["call_id"], "cid-2");
        assert_eq!(arr[0]["direction"], "inbound");
        assert_eq!(arr[0]["remote_number"], "0312345678");
        assert_eq!(arr[0]["outcome"]["kind"], "missed");
        // [1] = 古い方 (cid-1、 outbound, answered)
        assert_eq!(arr[1]["call_id"], "cid-1");
        assert_eq!(arr[1]["direction"], "outbound");
        assert_eq!(arr[1]["remote_number"], "117");
        assert_eq!(arr[1]["outcome"]["kind"], "answered");
    }

    /// Issue #278: `?n=1` で件数を絞れる。
    #[tokio::test]
    async fn call_log_recent_respects_n_query_parameter() {
        use crate::observability::call_log::{Direction, Outcome};

        let state = make_state(true);
        for i in 0..3 {
            state.call_log.record_start(
                Direction::Outbound,
                format!("117-{i}"),
                format!("cid-{i}"),
            );
            state
                .call_log
                .record_end(&format!("cid-{i}"), Outcome::Answered);
        }

        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/call-log/recent?n=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let arr: Vec<serde_json::Value> =
            serde_json::from_str(&body).expect("response must be a JSON array");
        // 最新 1 件 (= cid-2) のみ。
        assert_eq!(arr.len(), 1, "expected 1 entry with n=1, body = {body}");
        assert_eq!(arr[0]["call_id"], "cid-2");
        assert_eq!(arr[0]["remote_number"], "117-2");
    }

    /// Issue #278: 空 ring buffer でも 200 + `[]` を返す。
    #[tokio::test]
    async fn call_log_recent_returns_empty_array_when_no_calls() {
        let app = router(make_state(true));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/call-log/recent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let arr: Vec<serde_json::Value> =
            serde_json::from_str(&body).expect("response must be a JSON array");
        assert!(arr.is_empty(), "expected empty array, got {body}");
    }

    /// Issue #278 (PR #286 review 🟡#3): record_start のみ実施された
    /// "進行中通話" (= record_end が未到達) が `GET /api/call-log/recent`
    /// で **`outcome=null` + `duration_secs=null`** として正しくシリアライズ
    /// されることを確認する。 PWA UI 側はこの形を「通話中 / 結果未確定」として
    /// 描画するため、 silent な構造変化 (例えば `outcome` フィールド欠落) が
    /// regression にならないように JSON 構造で assert する。
    #[tokio::test]
    async fn call_log_recent_serializes_orphan_entry_with_null_outcome_and_duration() {
        use crate::observability::call_log::Direction;

        let state = make_state(true);
        // record_start だけで record_end は呼ばない (= まだ通話中、 または
        // 例外で record_end ホップが落ちた orphan)。
        state
            .call_log
            .record_start(Direction::Inbound, "0312345678".into(), "cid-orphan".into());

        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/call-log/recent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let arr: Vec<serde_json::Value> =
            serde_json::from_str(&body).expect("response must be a JSON array");
        assert_eq!(arr.len(), 1);
        let entry = &arr[0];
        assert_eq!(entry["call_id"], "cid-orphan");
        assert_eq!(entry["direction"], "inbound");
        assert_eq!(entry["remote_number"], "0312345678");
        // 進行中なので outcome / duration_secs は null
        assert!(
            entry["outcome"].is_null(),
            "outcome must be null for in-progress call, got {entry:?}"
        );
        assert!(
            entry["duration_secs"].is_null(),
            "duration_secs must be null for in-progress call, got {entry:?}"
        );
        // start_unix_ms は有効値 (u64)。
        assert!(entry["start_unix_ms"].is_u64());
    }
}
