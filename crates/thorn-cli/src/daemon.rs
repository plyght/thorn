use crate::config::ThornConfig;
use chrono::Utc;
use dashmap::{DashMap, DashSet};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thorn_chain::tracker::WalletTracker;
use thorn_core::{BotScore, Chain};
use thorn_detect::{content, infra, scoring};
use thorn_honeypot::server::{honeypot_router, HoneypotState};
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

#[derive(Serialize)]
struct ScanResult {
    url: String,
    domain: String,
    score: f64,
    classification: String,
    signals: Vec<SignalEntry>,
    scanned_at: String,
}

#[derive(Serialize)]
struct SignalEntry {
    kind: String,
    confidence: f64,
    evidence: String,
}

#[derive(Serialize)]
struct WalletResult {
    wallet: String,
    chain: String,
    status: String,
    total_spent: f64,
    total_earned: f64,
    parent_wallet: Option<String>,
    signals: Vec<SignalEntry>,
    tracked_at: String,
}

struct DaemonState {
    honeypot: Arc<HoneypotState>,
    known_wallets: Arc<DashSet<String>>,
    results_dir: PathBuf,
    scan_results: Arc<DashMap<String, ScanResult>>,
    wallet_results: Arc<DashMap<String, WalletResult>>,
}

fn score_to_signals(score: &BotScore) -> Vec<SignalEntry> {
    score
        .signals
        .iter()
        .map(|s| SignalEntry {
            kind: format!("{:?}", s.kind),
            confidence: s.confidence,
            evidence: s.evidence.clone(),
        })
        .collect()
}

fn parse_chain(s: &str) -> Chain {
    match s.to_lowercase().as_str() {
        "base" => Chain::Base,
        "solana" | "sol" => Chain::Solana,
        "ethereum" | "eth" => Chain::Ethereum,
        other => Chain::Unknown(other.to_string()),
    }
}

fn default_rpc(chain: &Chain) -> &'static str {
    match chain {
        Chain::Base => "https://mainnet.base.org",
        Chain::Solana => "https://api.mainnet-beta.solana.com",
        Chain::Ethereum => "https://eth.llamarpc.com",
        Chain::Unknown(_) => "https://mainnet.base.org",
    }
}

pub async fn run_daemon(config: ThornConfig) -> Result<(), Box<dyn std::error::Error>> {
    let results_dir = PathBuf::from(&config.output.results_dir);
    std::fs::create_dir_all(&results_dir)?;

    let state = Arc::new(DaemonState {
        honeypot: Arc::new(HoneypotState::new()),
        known_wallets: Arc::new(DashSet::new()),
        results_dir: results_dir.clone(),
        scan_results: Arc::new(DashMap::new()),
        wallet_results: Arc::new(DashMap::new()),
    });

    if let Some(track) = &config.track {
        for w in &track.watch_wallets {
            state.known_wallets.insert(w.clone());
        }
    }

    info!("starting thorn daemon");

    let honeypot_state = state.honeypot.clone();
    let honeypot_port = config.honeypot.port;
    let honeypot_bind = config.honeypot.bind.clone();
    let honeypot_handle = tokio::spawn(async move {
        let router = honeypot_router(honeypot_state);
        let addr = format!("{}:{}", honeypot_bind, honeypot_port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                info!("honeypot listening on {}", addr);
                if let Err(e) = axum::serve(listener, router).await {
                    error!("honeypot server error: {}", e);
                }
            }
            Err(e) => error!("honeypot bind failed on {}: {}", addr, e),
        }
    });

    let wallet_state = state.clone();
    let wallet_handle = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            let honeypot_hits = wallet_state.honeypot.hits.clone();
            for entry in honeypot_hits.iter() {
                for hit in entry.value() {
                    if let Some(ref wallet) = hit.wallet_address {
                        if !wallet.is_empty() && !wallet_state.known_wallets.contains(wallet) {
                            info!("new wallet discovered from honeypot: {}", wallet);
                            wallet_state.known_wallets.insert(wallet.clone());
                        }
                    }
                }
            }
        }
    });

    let scan_handle = if let Some(scan_config) = config.scan {
        let scan_state = state.clone();
        let targets = scan_config.targets;
        let interval_secs = scan_config.interval_secs;
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(interval_secs));
            let client = reqwest::Client::builder()
                .user_agent("Mozilla/5.0 (compatible; ThornBot/0.1)")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build http client");
            loop {
                tick.tick().await;
                info!("running scheduled scan of {} target(s)", targets.len());
                for target in &targets {
                    if let Err(e) =
                        scan_target(&client, target, &scan_state).await
                    {
                        warn!("scan failed for {}: {}", target, e);
                    }
                }
                persist_results(&scan_state).await;
            }
        }))
    } else {
        None
    };

    let crawl_handle = if let Some(crawl_config) = config.crawl {
        let crawl_state = state.clone();
        let seeds = crawl_config.seeds;
        let depth = crawl_config.depth;
        let concurrent = crawl_config.concurrent;
        let interval_secs = crawl_config.interval_secs;
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(interval_secs));
            loop {
                tick.tick().await;
                info!("running scheduled crawl of {} seed(s)", seeds.len());
                if let Err(e) =
                    crawl_targets(&seeds, depth, concurrent, &crawl_state).await
                {
                    warn!("crawl failed: {}", e);
                }
                persist_results(&crawl_state).await;
            }
        }))
    } else {
        None
    };

    let track_handle = if config.track.is_some() {
        let track_state = state.clone();
        let track_config = config.track.unwrap();
        let chain = parse_chain(&track_config.chain);
        let rpc_url = track_config
            .rpc_url
            .unwrap_or_else(|| default_rpc(&chain).to_string());
        let interval_secs = track_config.interval_secs;
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(interval_secs));
            let tracker = WalletTracker::new(rpc_url, chain);
            loop {
                tick.tick().await;
                let wallets: Vec<String> =
                    track_state.known_wallets.iter().map(|w| w.clone()).collect();
                if wallets.is_empty() {
                    continue;
                }
                info!("tracking {} wallet(s)", wallets.len());
                for wallet in &wallets {
                    if let Err(e) =
                        track_wallet(&tracker, wallet, &track_state).await
                    {
                        warn!("track failed for {}: {}", wallet, e);
                    }
                }
                persist_results(&track_state).await;
            }
        }))
    } else {
        None
    };

    info!("daemon running — honeypot + schedulers active");
    info!(
        "results persisted to {}",
        results_dir.display()
    );

    tokio::select! {
        _ = honeypot_handle => error!("honeypot task exited"),
        _ = wallet_handle => error!("wallet watcher task exited"),
        _ = async { if let Some(h) = scan_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            error!("scan task exited")
        }
        _ = async { if let Some(h) = crawl_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            error!("crawl task exited")
        }
        _ = async { if let Some(h) = track_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            error!("track task exited")
        }
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
        }
    }

    persist_results(&state).await;
    info!("daemon stopped");
    Ok(())
}

async fn scan_target(
    client: &reqwest::Client,
    target: &str,
    state: &Arc<DaemonState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };

    let resp = client.get(&url).send().await?;
    let status = resp.status().as_u16();

    let mut headers_map: HashMap<String, String> = HashMap::new();
    for (key, val) in resp.headers() {
        if let Ok(v) = val.to_str() {
            headers_map.insert(key.as_str().to_string(), v.to_string());
        }
    }

    let html = resp.text().await?;
    let parsed_url = url::Url::parse(&url)?;
    let domain = parsed_url.host_str().unwrap_or("unknown").to_string();

    let raw_page = slither_core::RawPage {
        url: url.clone(),
        domain: domain.clone(),
        html: html.clone(),
        status,
        headers: headers_map.clone(),
        crawled_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let transformer = fang::Transformer::new();
    let (title, body, headings) = match transformer.transform(&raw_page) {
        Ok(d) => (d.title, d.body, d.headings),
        Err(_) => (String::new(), html, Vec::new()),
    };

    let (infra_signals, _fingerprint) = infra::analyze_infrastructure(&headers_map, &domain);
    let content_signals = content::analyze_content(&body, &title, &headings);

    let mut all_signals = infra_signals;
    all_signals.extend(content_signals);

    if status == 402 {
        all_signals.push(thorn_core::BotSignal {
            kind: thorn_core::SignalKind::X402Payment,
            confidence: 0.7,
            evidence: "HTTP 402 Payment Required response".to_string(),
        });
    }

    let score = scoring::compute_bot_score(all_signals);

    info!(
        "scan {} — score={:.2} classification={:?}",
        url, score.score, score.classification
    );

    let result = ScanResult {
        url: url.clone(),
        domain,
        score: score.score,
        classification: format!("{:?}", score.classification),
        signals: score_to_signals(&score),
        scanned_at: Utc::now().to_rfc3339(),
    };

    state.scan_results.insert(url, result);
    Ok(())
}

async fn crawl_targets(
    seeds: &[String],
    depth: usize,
    concurrent: usize,
    state: &Arc<DaemonState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = slither_core::CrawlerConfig {
        max_concurrent: concurrent,
        max_depth: depth,
        rate_limit_per_second: 10,
        user_agent: "ThornBot/0.1".to_string(),
        respect_robots: true,
        request_timeout_secs: 30,
    };

    let crawler = snake::Crawler::new(config);
    let transformer = fang::Transformer::new();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<slither_core::RawPage>(100);

    let crawl_seeds: Vec<(String, usize, slither_core::CrawlScope)> = seeds
        .iter()
        .map(|u| (u.clone(), depth, slither_core::CrawlScope::SameDomain))
        .collect();

    let crawl_handle = tokio::spawn(async move {
        if let Err(e) = crawler.crawl(crawl_seeds, tx).await {
            error!("crawler error: {}", e);
        }
    });

    while let Some(page) = rx.recv().await {
        let url = page.url.clone();
        let domain = page.domain.clone();
        let page_headers = page.headers.clone();
        let status = page.status;

        let (title, body, headings) = match transformer.transform(&page) {
            Ok(doc) => (doc.title, doc.body, doc.headings),
            Err(_) => continue,
        };

        let (infra_signals, _) = infra::analyze_infrastructure(&page_headers, &domain);
        let content_signals = content::analyze_content(&body, &title, &headings);

        let mut all_signals = infra_signals;
        all_signals.extend(content_signals);

        if status == 402 {
            all_signals.push(thorn_core::BotSignal {
                kind: thorn_core::SignalKind::X402Payment,
                confidence: 0.7,
                evidence: "HTTP 402 Payment Required response".to_string(),
            });
        }

        let score = scoring::compute_bot_score(all_signals);

        if score.score > 0.4 {
            info!(
                "crawl detected bot signal: {} score={:.2} {:?}",
                url, score.score, score.classification
            );
        }

        let result = ScanResult {
            url: url.clone(),
            domain,
            score: score.score,
            classification: format!("{:?}", score.classification),
            signals: score_to_signals(&score),
            scanned_at: Utc::now().to_rfc3339(),
        };

        state.scan_results.insert(url, result);
    }

    crawl_handle.await.ok();
    Ok(())
}

async fn track_wallet(
    tracker: &WalletTracker,
    wallet: &str,
    state: &Arc<DaemonState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let profile = tracker.build_automaton_profile(wallet).await.map_err(|e| {
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            as Box<dyn std::error::Error + Send + Sync>
    })?;

    info!(
        "tracked {} — status={:?} spent={:.6}",
        wallet, profile.status, profile.total_spent
    );

    let signals: Vec<SignalEntry> = profile
        .signals
        .iter()
        .map(|s| SignalEntry {
            kind: format!("{:?}", s.kind),
            confidence: s.confidence,
            evidence: s.evidence.clone(),
        })
        .collect();

    let result = WalletResult {
        wallet: wallet.to_string(),
        chain: format!("{:?}", profile.chain),
        status: format!("{:?}", profile.status),
        total_spent: profile.total_spent,
        total_earned: profile.total_earned,
        parent_wallet: profile.parent_wallet,
        signals,
        tracked_at: Utc::now().to_rfc3339(),
    };

    state.wallet_results.insert(wallet.to_string(), result);
    Ok(())
}

async fn persist_results(state: &Arc<DaemonState>) {
    let scans: Vec<serde_json::Value> = state
        .scan_results
        .iter()
        .filter_map(|r| serde_json::to_value(r.value()).ok())
        .collect();

    if !scans.is_empty() {
        let path = state.results_dir.join("scans.json");
        match serde_json::to_string_pretty(&scans) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("failed to write scans: {}", e);
                }
            }
            Err(e) => warn!("failed to serialize scans: {}", e),
        }
    }

    let wallets: Vec<serde_json::Value> = state
        .wallet_results
        .iter()
        .filter_map(|r| serde_json::to_value(r.value()).ok())
        .collect();

    if !wallets.is_empty() {
        let path = state.results_dir.join("wallets.json");
        match serde_json::to_string_pretty(&wallets) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("failed to write wallets: {}", e);
                }
            }
            Err(e) => warn!("failed to serialize wallets: {}", e),
        }
    }

    let hits_count: usize = state.honeypot.hits.iter().map(|e| e.value().len()).sum();
    if hits_count > 0 {
        let path = state.results_dir.join("honeypot_hits.json");
        let hits: HashMap<String, serde_json::Value> = state
            .honeypot
            .hits
            .iter()
            .filter_map(|e| {
                serde_json::to_value(e.value())
                    .ok()
                    .map(|v| (e.key().clone(), v))
            })
            .collect();
        match serde_json::to_string_pretty(&hits) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("failed to write honeypot hits: {}", e);
                }
            }
            Err(e) => warn!("failed to serialize honeypot hits: {}", e),
        }
    }
}
