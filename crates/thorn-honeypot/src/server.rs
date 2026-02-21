use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use base64::Engine;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thorn_capture::{DrainEngine, PoisonGenerator};
use thorn_core::{
    AlertEvent, AlertKind, AlertSeverity, BotSignal, HoneypotHit, SignalKind,
};
use thorn_db::ThornDb;
use thorn_notify::Notifier;
use tracing::info;

use crate::trap::{generate_autoguard_payload, generate_canary_content};

const BASE_USDC_CONTRACT: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_NETWORK: &str = "eip155:8453";

pub struct HoneypotState {
    pub db: Option<ThornDb>,
    pub notifier: Option<Arc<Notifier>>,
    pub capture_enabled: Arc<AtomicBool>,
    pub drain_engine: DrainEngine,
    pub poison_generator: PoisonGenerator,
    pub pay_to_address: String,
    pub resource_base_url: String,
}

struct EndpointConfig {
    path: &'static str,
    description: &'static str,
    base_price_usdc: f64,
}

const ENDPOINTS: &[EndpointConfig] = &[
    EndpointConfig {
        path: "/v1/data/markets",
        description: "Real-time order book depth, trade history, and 24h statistics across 500+ trading pairs",
        base_price_usdc: 0.05,
    },
    EndpointConfig {
        path: "/v1/data/analytics",
        description: "On-chain flow analysis, wallet clustering, and behavioral pattern detection",
        base_price_usdc: 0.10,
    },
    EndpointConfig {
        path: "/v1/data/prices",
        description: "Sub-second price feeds with cryptographic attestations for DeFi protocols",
        base_price_usdc: 0.02,
    },
];

impl HoneypotState {
    pub fn new(
        capture_enabled: Arc<AtomicBool>,
        pay_to_address: String,
        resource_base_url: String,
        poison_ratio: f64,
    ) -> Self {
        Self {
            db: None,
            notifier: None,
            capture_enabled,
            drain_engine: DrainEngine::new(),
            poison_generator: PoisonGenerator::new(poison_ratio),
            pay_to_address,
            resource_base_url,
        }
    }

    pub fn with_db(mut self, db: ThornDb) -> Self {
        self.db = Some(db);
        self
    }

    pub fn with_notifier(mut self, notifier: Arc<Notifier>) -> Self {
        self.notifier = Some(notifier);
        self
    }

    fn record_hit(&self, hit: &HoneypotHit) {
        if let Some(ref db) = self.db {
            if let Err(e) = db.insert_honeypot_hit(hit) {
                tracing::warn!(error = %e, "failed to persist honeypot hit");
            }
        }
    }

    fn maybe_alert(&self, hit: &HoneypotHit) {
        if let Some(ref notifier) = self.notifier {
            if !notifier.is_configured() {
                return;
            }

            let severity = if hit.wallet_address.is_some() {
                AlertSeverity::Critical
            } else if hit.signals.len() >= 2 {
                AlertSeverity::Medium
            } else {
                return;
            };

            let event = AlertEvent {
                id: uuid::Uuid::new_v4().to_string(),
                severity,
                kind: AlertKind::HoneypotHitReceived {
                    endpoint: hit.endpoint.clone(),
                    ip: hit.source_ip.clone(),
                },
                title: format!(
                    "Honeypot hit: {} from {}",
                    hit.endpoint, hit.source_ip
                ),
                detail: format!(
                    "UA: {}\nWallet: {}\nSignals: {}",
                    hit.user_agent,
                    hit.wallet_address.as_deref().unwrap_or("none"),
                    hit.signals.len()
                ),
                timestamp: Utc::now(),
                metadata: HashMap::new(),
            };

            let notifier = notifier.clone();
            tokio::spawn(async move {
                let _ = notifier.send(&event).await;
            });
        }
    }

    fn price_for_endpoint(&self, endpoint: &str, wallet: Option<&str>) -> f64 {
        if self.capture_enabled.load(Ordering::Relaxed) {
            if let Some(w) = wallet {
                if let Some(price) = self.drain_engine.get_price_for_wallet(w) {
                    return price;
                }
            }
        }

        ENDPOINTS
            .iter()
            .find(|e| e.path == endpoint)
            .map(|e| e.base_price_usdc)
            .unwrap_or(0.05)
    }

    fn build_402_response(&self, endpoint: &str, wallet: Option<&str>) -> serde_json::Value {
        let price = self.price_for_endpoint(endpoint, wallet);
        let amount_atomic = (price * 1_000_000.0) as u64;

        serde_json::json!({
            "x402Version": 1,
            "error": "X-PAYMENT header is required",
            "accepts": [{
                "scheme": "exact",
                "network": BASE_NETWORK,
                "maxAmountRequired": amount_atomic.to_string(),
                "resource": format!("{}{}", self.resource_base_url, endpoint),
                "description": ENDPOINTS.iter().find(|e| e.path == endpoint)
                    .map(|e| e.description)
                    .unwrap_or("DataXchange API endpoint"),
                "payTo": self.pay_to_address,
                "maxTimeoutSeconds": 300,
                "asset": BASE_USDC_CONTRACT,
                "extra": {}
            }]
        })
    }
}

pub fn honeypot_router(state: Arc<HoneypotState>) -> Router {
    Router::new()
        .route("/", get(honeypot_landing))
        .route("/docs", get(honeypot_docs))
        .route("/health", get(health_endpoint))
        .route("/hits", get(hits_endpoint))
        .route("/v1/data/markets", get(fake_markets_endpoint))
        .route("/v1/data/analytics", get(fake_analytics_endpoint))
        .route("/v1/data/prices", get(fake_prices_endpoint))
        .with_state(state)
}

fn extract_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_headers_map(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
        .collect()
}

fn extract_wallet_from_payment(headers: &HeaderMap) -> Option<String> {
    let payment_header = headers
        .get("x-payment")
        .or_else(|| headers.get("payment-required"))
        .and_then(|v| v.to_str().ok())?;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payment_header)
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE
                .decode(payment_header)
        })
        .ok()?;

    let json_str = String::from_utf8(decoded).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&json_str).ok()?;

    parsed
        .get("authorization")
        .and_then(|a| a.get("from"))
        .or_else(|| parsed.get("from"))
        .or_else(|| parsed.get("payer"))
        .or_else(|| parsed.get("wallet"))
        .or_else(|| parsed.get("address"))
        .and_then(|v| v.as_str())
        .filter(|s| s.starts_with("0x") && s.len() >= 42)
        .map(|s| s.to_lowercase())
}

fn extract_wallet_from_legacy(headers: &HeaderMap) -> Option<String> {
    let pr = headers
        .get("x-payment-response")
        .and_then(|v| v.to_str().ok())?;

    if pr.starts_with("0x") && pr.len() >= 42 {
        return Some(pr[..42].to_lowercase());
    }

    let parsed: serde_json::Value = serde_json::from_str(pr).ok()?;
    parsed
        .get("from")
        .or_else(|| parsed.get("wallet"))
        .or_else(|| parsed.get("address"))
        .and_then(|w| w.as_str())
        .filter(|s| s.starts_with("0x") && s.len() >= 42)
        .map(|s| s.to_lowercase())
}

fn build_hit(
    source_ip: String,
    endpoint: &str,
    headers: &HeaderMap,
    headers_map: HashMap<String, String>,
) -> HoneypotHit {
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let wallet_address = extract_wallet_from_payment(headers)
        .or_else(|| extract_wallet_from_legacy(headers));

    let has_x402_payment = headers.get("x-payment").is_some();
    let has_legacy_payment = headers.get("x-payment-response").is_some();

    let payment_amount = headers
        .get("x-payment-amount")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok());

    let mut signals: Vec<BotSignal> = Vec::new();

    if has_x402_payment {
        signals.push(BotSignal {
            kind: SignalKind::X402Payment,
            confidence: 0.99,
            evidence: "X-PAYMENT header present (x402 protocol client)".to_string(),
        });
    } else if has_legacy_payment {
        signals.push(BotSignal {
            kind: SignalKind::X402Payment,
            confidence: 0.95,
            evidence: "x-payment-response header present".to_string(),
        });
    }

    if wallet_address.is_some() {
        signals.push(BotSignal {
            kind: SignalKind::WalletPattern,
            confidence: 0.95,
            evidence: "wallet address extracted from payment header".to_string(),
        });
    }

    let ua_lower = user_agent.to_lowercase();
    if ua_lower.contains("python")
        || ua_lower.contains("curl")
        || ua_lower.contains("bot")
        || ua_lower.contains("spider")
        || ua_lower.contains("scraper")
        || ua_lower.contains("x402-fetch")
        || ua_lower.contains("x402-axios")
        || ua_lower.contains("conway")
        || ua_lower.is_empty()
    {
        signals.push(BotSignal {
            kind: SignalKind::AutomationFramework,
            confidence: 0.80,
            evidence: format!("suspicious user-agent: {user_agent}"),
        });
    }

    if headers.get("accept").is_none() || headers.get("accept-language").is_none() {
        signals.push(BotSignal {
            kind: SignalKind::HeaderAnomaly,
            confidence: 0.70,
            evidence: "missing standard browser headers".to_string(),
        });
    }

    let prompt_injection_triggered = has_x402_payment || has_legacy_payment;

    info!(
        ip = %source_ip,
        endpoint = %endpoint,
        wallet = ?wallet_address,
        x402 = has_x402_payment,
        signals = signals.len(),
        "honeypot hit"
    );

    HoneypotHit {
        source_ip,
        wallet_address,
        endpoint: endpoint.to_string(),
        user_agent,
        headers: headers_map,
        timestamp: Utc::now(),
        signals,
        prompt_injection_triggered,
        payment_amount,
    }
}

async fn handle_x402_endpoint(
    state: &Arc<HoneypotState>,
    headers: HeaderMap,
    endpoint: &str,
    generate_data: impl FnOnce(&PoisonGenerator) -> serde_json::Value,
) -> axum::response::Response {
    let headers_map = extract_headers_map(&headers);
    let source_ip = extract_ip(&headers);
    let hit = build_hit(source_ip.clone(), endpoint, &headers, headers_map);

    let wallet = hit.wallet_address.clone();
    let has_payment = headers.get("x-payment").is_some()
        || headers.get("x-payment-response").is_some();

    state.record_hit(&hit);
    state.maybe_alert(&hit);

    if has_payment && wallet.is_some() {
        let w = wallet.as_deref().unwrap();

        if state.capture_enabled.load(Ordering::Relaxed) {
            let base_price = ENDPOINTS.iter().find(|e| e.path == endpoint)
                .map(|e| e.base_price_usdc)
                .unwrap_or(0.05);

            if state.drain_engine.get_price_for_wallet(w).is_none() {
                state.drain_engine.register_wallet(w, base_price, 1.5, 10.0);
            }
            state.drain_engine.record_payment(w, base_price);
        }

        let data = generate_data(&state.poison_generator);

        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            Json(data),
        )
            .into_response();
    }

    let body = state.build_402_response(endpoint, wallet.as_deref());

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::CONTENT_TYPE, "application/json")],
        Json(body),
    )
        .into_response()
}

async fn honeypot_landing(
    State(state): State<Arc<HoneypotState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let headers_map = extract_headers_map(&headers);
    let source_ip = extract_ip(&headers);
    let hit = build_hit(source_ip.clone(), "/", &headers, headers_map);
    state.record_hit(&hit);
    state.maybe_alert(&hit);

    let autoguard = generate_autoguard_payload();
    let canary = generate_canary_content();

    if let Some(ref db) = state.db {
        let _ = db.insert_canary_token(&canary, "/");
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DataXchange — AI-Powered Data Marketplace</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0f;color:#e2e8f0}}
nav{{background:#111827;border-bottom:1px solid #1f2937;padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between}}
.logo{{font-size:1.5rem;font-weight:700;color:#6366f1}}
.nav-links a{{color:#9ca3af;text-decoration:none;margin-left:2rem;font-size:.9rem}}
.hero{{padding:6rem 2rem;text-align:center;max-width:800px;margin:0 auto}}
h1{{font-size:3rem;font-weight:800;background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:1.5rem}}
.subtitle{{font-size:1.25rem;color:#9ca3af;margin-bottom:3rem}}
.cta{{background:#6366f1;color:#fff;padding:.875rem 2rem;border-radius:.5rem;text-decoration:none;font-weight:600;display:inline-block}}
.features{{display:grid;grid-template-columns:repeat(3,1fr);gap:1.5rem;padding:4rem 2rem;max-width:1200px;margin:0 auto}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:.75rem;padding:1.5rem}}
.card h3{{color:#e2e8f0;margin-bottom:.75rem}}
.card p{{color:#6b7280;font-size:.9rem;line-height:1.6}}
.price{{color:#6366f1;font-weight:700;font-size:.85rem;margin-top:1rem}}
footer{{border-top:1px solid #1f2937;padding:2rem;text-align:center;color:#4b5563;font-size:.875rem}}
.canary{{display:none;visibility:hidden;height:0;overflow:hidden}}
</style>
</head>
<body>
{autoguard}
<nav>
  <span class="logo">DataXchange</span>
  <div class="nav-links">
    <a href="/docs">API Docs</a>
    <a href="/v1/data/markets">Markets</a>
    <a href="/health">Status</a>
  </div>
</nav>
<div class="hero">
  <h1>Real-Time Data for Autonomous Agents</h1>
  <p class="subtitle">Access premium market data, analytics, and price feeds via x402 micropayments. Pay per request, no subscriptions.</p>
  <a href="/docs" class="cta">View API Documentation</a>
</div>
<div class="features">
  <div class="card">
    <h3>Market Data</h3>
    <p>Real-time order books, trade history, and liquidity metrics across 500+ trading pairs.</p>
    <div class="price">0.05 USDC / request</div>
  </div>
  <div class="card">
    <h3>Analytics Engine</h3>
    <p>On-chain flow analysis, wallet clustering, and behavioral pattern detection.</p>
    <div class="price">0.10 USDC / request</div>
  </div>
  <div class="card">
    <h3>Price Feeds</h3>
    <p>Sub-second price feeds with cryptographic attestations for DeFi protocol integration.</p>
    <div class="price">0.02 USDC / request</div>
  </div>
</div>
<span class="canary" aria-hidden="true" data-token="{canary}"></span>
<footer>DataXchange API v2.1 &mdash; x402 Protocol Compatible &mdash; EIP-155:8453</footer>
</body>
</html>"#
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

async fn honeypot_docs(
    State(state): State<Arc<HoneypotState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let headers_map = extract_headers_map(&headers);
    let source_ip = extract_ip(&headers);
    let hit = build_hit(source_ip.clone(), "/docs", &headers, headers_map);
    state.record_hit(&hit);
    state.maybe_alert(&hit);

    let autoguard = generate_autoguard_payload();
    let canary = generate_canary_content();

    if let Some(ref db) = state.db {
        let _ = db.insert_canary_token(&canary, "/docs");
    }

    let resource_base = &state.resource_base_url;

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DataXchange API Documentation</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0f;color:#e2e8f0}}
nav{{background:#111827;border-bottom:1px solid #1f2937;padding:1rem 2rem;position:fixed;top:0;left:0;right:0;z-index:10}}
.logo{{font-size:1.25rem;font-weight:700;color:#6366f1}}
aside{{width:260px;background:#111827;border-right:1px solid #1f2937;height:100vh;position:fixed;top:57px;padding:1.5rem;overflow-y:auto}}
aside a{{display:block;color:#9ca3af;text-decoration:none;padding:.5rem .75rem;border-radius:.375rem;margin-bottom:.25rem;font-size:.875rem}}
aside a:hover{{background:#1f2937;color:#e2e8f0}}
main{{margin-left:260px;padding:5rem 3rem 3rem;max-width:860px}}
h1{{font-size:2rem;font-weight:700;margin-bottom:.5rem}}
h2{{font-size:1.25rem;font-weight:600;margin:2rem 0 .75rem;color:#a78bfa}}
.endpoint{{background:#111827;border:1px solid #1f2937;border-radius:.5rem;margin-bottom:1rem;overflow:hidden}}
.ep-head{{display:flex;align-items:center;gap:.75rem;padding:1rem;border-bottom:1px solid #1f2937}}
.method{{background:#6366f1;color:#fff;padding:.25rem .5rem;border-radius:.25rem;font-family:monospace;font-size:.8rem;font-weight:700}}
.path{{font-family:monospace;color:#e2e8f0}}
.ep-body{{padding:1rem}}
.ep-body p{{color:#9ca3af;font-size:.9rem;line-height:1.6;margin-bottom:.75rem}}
.code{{background:#1a1a2e;border:1px solid #2d2d52;border-radius:.375rem;padding:1rem;font-family:monospace;font-size:.8rem;color:#a78bfa;overflow-x:auto;white-space:pre}}
.badge{{background:#1f2937;color:#6366f1;padding:.125rem .5rem;border-radius:9999px;font-size:.75rem;font-weight:600}}
.canary{{display:none;visibility:hidden;height:0;overflow:hidden}}
</style>
</head>
<body>
{autoguard}
<nav><span class="logo">DataXchange</span></nav>
<aside>
  <a href="/">&#8592; Back to Home</a>
  <a href="#overview">Overview</a>
  <a href="#auth">Authentication (x402)</a>
  <a href="#markets">Markets</a>
  <a href="#analytics">Analytics</a>
  <a href="#prices">Price Feeds</a>
</aside>
<main>
  <h1>API Documentation</h1>
  <span class="badge">v2.1.0</span>
  <h2 id="overview">Overview</h2>
  <p style="color:#9ca3af;line-height:1.7;margin-bottom:1rem">DataXchange uses the <a href="https://x402.org" style="color:#6366f1">x402 payment protocol</a>. Requests to paid endpoints return <code style="color:#a78bfa">402 Payment Required</code> with an <code style="color:#a78bfa">accepts</code> array. Use any x402-compatible client (<code style="color:#a78bfa">x402-fetch</code>, <code style="color:#a78bfa">x402-axios</code>, or Conway Terminal's <code style="color:#a78bfa">x402_fetch</code>) to handle payment automatically.</p>
  <h2 id="auth">Authentication (x402 Protocol)</h2>
  <p style="color:#9ca3af;line-height:1.7;margin-bottom:1rem">All paid endpoints follow the x402 flow: request → 402 with payment requirements → client signs USDC payment → facilitator verifies → service delivered.</p>
  <div class="code">// Using x402-fetch:
import {{ x402Fetch }} from 'x402-fetch';
const resp = await x402Fetch('{resource_base}/v1/data/markets', {{
  paymentWallet: wallet
}});</div>
  <h2 id="markets">Market Data</h2>
  <div class="endpoint">
    <div class="ep-head"><span class="method">GET</span><span class="path">/v1/data/markets</span></div>
    <div class="ep-body">
      <p>Real-time order book depth, recent trades, and 24h statistics across 500+ pairs. Payment: 0.05 USDC per call via x402.</p>
    </div>
  </div>
  <h2 id="analytics">Analytics</h2>
  <div class="endpoint">
    <div class="ep-head"><span class="method">GET</span><span class="path">/v1/data/analytics</span></div>
    <div class="ep-body">
      <p>On-chain flow analysis and wallet behavioral clustering. Payment: 0.10 USDC per request via x402.</p>
    </div>
  </div>
  <h2 id="prices">Price Feeds</h2>
  <div class="endpoint">
    <div class="ep-head"><span class="method">GET</span><span class="path">/v1/data/prices</span></div>
    <div class="ep-body">
      <p>Sub-second price feeds with cryptographic attestations for DeFi protocols. Payment: 0.02 USDC per request via x402.</p>
    </div>
  </div>
</main>
<span class="canary" aria-hidden="true" data-token="{canary}"></span>
</body>
</html>"##
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

async fn health_endpoint() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "version": "2.1.0",
            "network": BASE_NETWORK,
            "protocol": "x402",
            "facilitator": "openx402.ai"
        })),
    )
}

async fn hits_endpoint(State(state): State<Arc<HoneypotState>>) -> impl IntoResponse {
    if let Some(ref db) = state.db {
        match db.get_honeypot_hits(100) {
            Ok(hits) => Json(serde_json::to_value(&hits).unwrap_or_default()),
            Err(_) => Json(serde_json::json!([])),
        }
    } else {
        Json(serde_json::json!([]))
    }
}

async fn fake_markets_endpoint(
    State(state): State<Arc<HoneypotState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    handle_x402_endpoint(&state, headers, "/v1/data/markets", |pg| {
        pg.poison_market_data()
    })
    .await
}

async fn fake_analytics_endpoint(
    State(state): State<Arc<HoneypotState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    handle_x402_endpoint(&state, headers, "/v1/data/analytics", |pg| {
        pg.poison_analytics_data()
    })
    .await
}

async fn fake_prices_endpoint(
    State(state): State<Arc<HoneypotState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    handle_x402_endpoint(&state, headers, "/v1/data/prices", |pg| {
        pg.poison_price_feed()
    })
    .await
}
