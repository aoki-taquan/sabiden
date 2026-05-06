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
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tracing::info;

use crate::observability::Metrics;

/// ヘルスサーバが参照する共有状態
#[derive(Clone)]
pub struct HealthState {
    /// REGISTER 成功フラグ。SIP レイヤから書き込まれる
    pub registered: Arc<AtomicBool>,
    /// 観測カウンタ。各層と Arc 共有する。
    pub metrics: Arc<Metrics>,
}

impl HealthState {
    pub fn new(registered: Arc<AtomicBool>, metrics: Arc<Metrics>) -> Self {
        Self {
            registered,
            metrics,
        }
    }
}

/// `/healthz` `/readyz` `/metrics` を提供する `Router` を構築する
pub fn router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::InviteResult;
    use axum::body::to_bytes;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    fn make_state(registered: bool) -> HealthState {
        HealthState::new(Arc::new(AtomicBool::new(registered)), Metrics::new())
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
}
