use std::collections::HashMap;
use thorn_core::{BotSignal, SignalKind};

pub fn analyze_behavioral_signals(
    headers: &HashMap<String, String>,
    request_times_ms: &[u64],
    user_agent: &str,
) -> Vec<BotSignal> {
    let mut signals = Vec::new();

    if let Some(sig) = check_timing_anomalies(request_times_ms) {
        signals.push(sig);
    }

    if let Some(sig) = check_automation_artifacts(headers, user_agent) {
        signals.push(sig);
    }

    if let Some(sig) = check_request_pattern(headers) {
        signals.push(sig);
    }

    signals
}

fn check_timing_anomalies(request_times_ms: &[u64]) -> Option<BotSignal> {
    if request_times_ms.len() < 3 {
        return None;
    }

    let mut intervals: Vec<f64> = Vec::new();
    for pair in request_times_ms.windows(2) {
        intervals.push((pair[1] as f64) - (pair[0] as f64));
    }

    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;

    if mean < 1.0 {
        return None;
    }

    let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
    let cv = variance.sqrt() / mean;

    if cv < 0.05 && mean < 2000.0 {
        return Some(BotSignal {
            kind: SignalKind::TimingAnomaly,
            confidence: 0.85,
            evidence: format!(
                "machine-precise request timing: CV={:.4} mean={:.0}ms (n={})",
                cv,
                mean,
                intervals.len()
            ),
        });
    }

    if cv < 0.15 && mean < 500.0 {
        return Some(BotSignal {
            kind: SignalKind::TimingAnomaly,
            confidence: 0.65,
            evidence: format!(
                "suspiciously regular timing: CV={:.4} mean={:.0}ms",
                cv, mean
            ),
        });
    }

    None
}

fn check_automation_artifacts(
    headers: &HashMap<String, String>,
    user_agent: &str,
) -> Option<BotSignal> {
    let mut hits: Vec<String> = Vec::new();

    let ua_lower = user_agent.to_lowercase();

    let headless_markers = [
        "headlesschrome",
        "phantomjs",
        "selenium",
        "puppeteer",
        "playwright",
        "webdriver",
    ];
    for marker in &headless_markers {
        if ua_lower.contains(marker) {
            hits.push(format!("ua contains '{}'", marker));
        }
    }

    let sdk_markers = [
        ("python-requests", "python-requests"),
        ("aiohttp", "aiohttp"),
        ("httpx", "httpx"),
        ("axios", "axios"),
        ("node-fetch", "node-fetch"),
        ("go-http-client", "Go HTTP"),
        ("java/", "Java HTTP"),
    ];
    for (marker, label) in &sdk_markers {
        if ua_lower.contains(marker) {
            hits.push(format!("{} SDK", label));
        }
    }

    if headers.contains_key("sec-ch-ua") && !headers.contains_key("sec-ch-ua-platform") {
        hits.push("incomplete client hints".to_string());
    }

    if let Some(accept) = headers.get("accept") {
        if accept == "*/*" && !headers.contains_key("accept-language") {
            hits.push("generic accept + no accept-language".to_string());
        }
    }

    if hits.is_empty() {
        return None;
    }

    let confidence = (0.5 + hits.len() as f64 * 0.1).min(0.95);
    Some(BotSignal {
        kind: SignalKind::AutomationFramework,
        confidence,
        evidence: format!("automation artifacts: {}", hits.join(", ")),
    })
}

fn check_request_pattern(headers: &HashMap<String, String>) -> Option<BotSignal> {
    let mut anomalies: Vec<String> = Vec::new();

    let standard_browser_headers = ["accept", "accept-language", "accept-encoding", "connection"];
    let missing: Vec<&str> = standard_browser_headers
        .iter()
        .filter(|&&h| !headers.contains_key(h))
        .copied()
        .collect();

    if missing.len() >= 3 {
        anomalies.push(format!("missing browser headers: {}", missing.join(", ")));
    }

    let key_count = headers.len();
    if key_count <= 3 {
        anomalies.push(format!("sparse headers (only {})", key_count));
    }

    if let Some(encoding) = headers.get("accept-encoding") {
        if !encoding.contains("gzip") && !encoding.contains("br") {
            anomalies.push("no compression support".to_string());
        }
    }

    if anomalies.is_empty() {
        return None;
    }

    let confidence = (0.4 + anomalies.len() as f64 * 0.15).min(0.85);
    Some(BotSignal {
        kind: SignalKind::HeaderAnomaly,
        confidence,
        evidence: format!("request pattern: {}", anomalies.join("; ")),
    })
}
