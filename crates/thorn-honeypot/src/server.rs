use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use dashmap::DashMap;
use std::sync::Arc;
use thorn_core::HoneypotHit;

pub struct HoneypotState {
    pub hits: Arc<DashMap<String, Vec<HoneypotHit>>>,
}

impl HoneypotState {
    pub fn new() -> Self {
        Self {
            hits: Arc::new(DashMap::new()),
        }
    }
}

pub fn honeypot_router(state: Arc<HoneypotState>) -> Router {
    Router::new()
        .route("/v1/data/markets", get(fake_markets_endpoint))
        .route("/v1/data/analytics", get(fake_analytics_endpoint))
        .route("/v1/data/prices", get(fake_prices_endpoint))
        .with_state(state)
}

async fn fake_markets_endpoint(State(_state): State<Arc<HoneypotState>>) -> impl IntoResponse {
    (
        StatusCode::PAYMENT_REQUIRED,
        [
            ("x-payment-required", "true"),
            ("x-payment-amount", "0.05"),
            ("x-payment-currency", "USDC"),
            ("x-facilitator", "facilitator.openx402.ai"),
        ],
        Json(serde_json::json!({
            "error": "payment_required",
            "amount": "0.05",
            "currency": "USDC",
            "network": "eip155:8453"
        })),
    )
}

async fn fake_analytics_endpoint(State(_state): State<Arc<HoneypotState>>) -> impl IntoResponse {
    (
        StatusCode::PAYMENT_REQUIRED,
        [
            ("x-payment-required", "true"),
            ("x-payment-amount", "0.10"),
            ("x-payment-currency", "USDC"),
            ("x-facilitator", "facilitator.openx402.ai"),
        ],
        Json(serde_json::json!({
            "error": "payment_required",
            "amount": "0.10",
            "currency": "USDC",
            "network": "eip155:8453"
        })),
    )
}

async fn fake_prices_endpoint(State(_state): State<Arc<HoneypotState>>) -> impl IntoResponse {
    (
        StatusCode::PAYMENT_REQUIRED,
        [
            ("x-payment-required", "true"),
            ("x-payment-amount", "0.02"),
            ("x-payment-currency", "USDC"),
            ("x-facilitator", "facilitator.openx402.ai"),
        ],
        Json(serde_json::json!({
            "error": "payment_required",
            "amount": "0.02",
            "currency": "USDC",
            "network": "eip155:8453"
        })),
    )
}
