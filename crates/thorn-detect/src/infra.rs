use std::collections::HashMap;
use thorn_core::{BotSignal, InfraFingerprint, SignalKind};

pub fn analyze_infrastructure(
    headers: &HashMap<String, String>,
    domain: &str,
) -> (Vec<BotSignal>, InfraFingerprint) {
    let mut signals = Vec::new();
    let mut fingerprint = InfraFingerprint::default();

    fingerprint.server_header = headers.get("server").cloned();

    if let Some(sig) = check_x402_headers(headers) {
        fingerprint.has_x402 = true;
        signals.push(sig);
    }

    if let Some(sig) = check_conway_indicators(headers, domain) {
        fingerprint.conway_indicators.push(sig.evidence.clone());
        signals.push(sig);
    }

    (signals, fingerprint)
}

fn check_x402_headers(headers: &HashMap<String, String>) -> Option<BotSignal> {
    let x402_indicators = [
        "x-payment",
        "x-payment-response",
        "x-payment-required",
        "x-facilitator",
    ];

    for indicator in &x402_indicators {
        if headers.contains_key(*indicator) {
            return Some(BotSignal {
                kind: SignalKind::X402Payment,
                confidence: 0.8,
                evidence: format!("x402 header present: {}", indicator),
            });
        }
    }

    None
}

fn check_conway_indicators(headers: &HashMap<String, String>, domain: &str) -> Option<BotSignal> {
    let conway_patterns = ["conway.tech", "life.conway.tech", "conway.domains"];

    for pattern in &conway_patterns {
        if domain.contains(pattern) {
            return Some(BotSignal {
                kind: SignalKind::ConwayInfrastructure,
                confidence: 0.95,
                evidence: format!("Conway infrastructure detected: {}", domain),
            });
        }
    }

    if let Some(server) = headers.get("server") {
        if server.to_lowercase().contains("conway") {
            return Some(BotSignal {
                kind: SignalKind::ConwayInfrastructure,
                confidence: 0.9,
                evidence: format!("Conway server header: {}", server),
            });
        }
    }

    None
}
