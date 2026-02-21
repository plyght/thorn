use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thorn_db::ThornDb;
use tracing::info;

pub struct ApiState {
    pub db: ThornDb,
    pub capture_enabled: Arc<AtomicBool>,
}

pub fn api_router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/api/stats", get(stats_handler))
        .route("/api/scans", get(scans_handler))
        .route("/api/wallets", get(wallets_handler))
        .route("/api/wallets", post(add_wallet_handler))
        .route("/api/hits", get(hits_handler))
        .route("/api/targets", get(targets_handler))
        .route("/api/capture/status", get(capture_status_handler))
        .route("/api/capture/toggle", post(capture_toggle_handler))
        .route("/health", get(health_handler))
        .with_state(state)
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "thorn-api"
    }))
}

async fn stats_handler(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let stats = state.db.stats().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(&stats).unwrap_or_default()))
}

#[derive(Deserialize)]
struct PaginationParams {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
}

async fn scans_handler(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let scans = state
        .db
        .get_scan_results(params.limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(&scans).unwrap_or_default()))
}

async fn wallets_handler(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let wallets = state
        .db
        .get_wallets(params.limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(&wallets).unwrap_or_default()))
}

#[derive(Deserialize)]
struct AddWalletBody {
    address: String,
    #[serde(default = "default_chain")]
    chain: String,
}

fn default_chain() -> String {
    "base".to_string()
}

async fn add_wallet_handler(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<AddWalletBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    state
        .db
        .upsert_wallet(&body.address, &body.chain, 0.0, 0, "Unknown", None, 0.0, 0.0)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    info!(wallet = %body.address, chain = %body.chain, "wallet added via API");
    Ok(Json(serde_json::json!({
        "status": "ok",
        "address": body.address,
        "chain": body.chain,
    })))
}

async fn hits_handler(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hits = state
        .db
        .get_honeypot_hits(params.limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(&hits).unwrap_or_default()))
}

async fn targets_handler(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let targets = state
        .db
        .get_discovered_targets(params.limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::to_value(&targets).unwrap_or_default()))
}

async fn capture_status_handler(
    State(state): State<Arc<ApiState>>,
) -> Json<serde_json::Value> {
    let enabled = state.capture_enabled.load(Ordering::Relaxed);
    Json(serde_json::json!({ "enabled": enabled }))
}

#[derive(Deserialize)]
struct CaptureToggleBody {
    enabled: bool,
}

async fn capture_toggle_handler(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<CaptureToggleBody>,
) -> Json<serde_json::Value> {
    let prev = state.capture_enabled.swap(body.enabled, Ordering::Relaxed);
    info!(
        previous = prev,
        current = body.enabled,
        "capture toggle changed"
    );
    Json(serde_json::json!({
        "previous": prev,
        "enabled": body.enabled,
    }))
}

pub async fn run_api(
    bind: &str,
    port: u16,
    db: ThornDb,
    capture_enabled: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(ApiState { db, capture_enabled });
    let router = api_router(state);

    let addr = format!("{}:{}", bind, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("API server listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
