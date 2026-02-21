use crate::config::ThornConfig;
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thorn_archive::R2Archive;
use thorn_chain::scanner::X402Scanner;
use thorn_chain::tracker::WalletTracker;
use thorn_core::{AlertEvent, AlertKind, AlertSeverity, Chain, ScanRecord};
use thorn_db::ThornDb;
use thorn_detect::{content, infra, scoring};
use thorn_honeypot::server::{honeypot_router, HoneypotState};
use thorn_notify::Notifier;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

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

pub fn make_capture_toggle(config: &ThornConfig) -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(
        config.capture.as_ref().map(|c| c.enabled).unwrap_or(false),
    ))
}

pub async fn run_daemon(
    config: ThornConfig,
    capture_enabled: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let results_dir = PathBuf::from(&config.output.results_dir);
    std::fs::create_dir_all(&results_dir)?;

    let db_path = config
        .db
        .as_ref()
        .map(|d| d.path.clone())
        .unwrap_or_else(|| format!("{}/thorn.db", results_dir.display()));

    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let db = ThornDb::open(&db_path)?;
    info!(path = %db_path, "database opened");

    let notifier = Arc::new(match &config.notify {
        Some(nc) => Notifier::new(
            nc.webhook_urls.clone(),
            nc.ntfy_topic.clone(),
            nc.ntfy_server.clone(),
        ),
        None => Notifier::noop(),
    });

    if notifier.is_configured() {
        info!("notifications configured");
    }

    let archive: Option<Arc<R2Archive>> = match &config.r2 {
        Some(r2c) => match R2Archive::new(&r2c.bucket, &r2c.account_id, &r2c.access_key_id, &r2c.secret_access_key) {
            Ok(a) => {
                info!(bucket = %r2c.bucket, "R2 archive connected");
                Some(Arc::new(a))
            }
            Err(e) => {
                warn!(error = %e, "R2 archive init failed, continuing without archival");
                None
            }
        },
        None => None,
    };

    if let Some(track) = &config.track {
        for w in &track.watch_wallets {
            let chain_str = &track.chain;
            db.upsert_wallet(w, chain_str, 0.0, 0, "Unknown", None, 0.0, 0.0)?;
            info!(wallet = %w, "initial watch wallet registered");
        }
    }

    info!(
        capture = capture_enabled.load(Ordering::Relaxed),
        "starting thorn daemon"
    );

    let honeypot_state = Arc::new(
        HoneypotState::new()
            .with_db(db.clone_handle())
            .with_notifier(notifier.clone()),
    );
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

    let scanner_handle = {
        let scanner_cfg = config.scanner.as_ref();
        let enabled = scanner_cfg.map(|s| s.enabled).unwrap_or(true);
        if enabled {
            let rpc_url = scanner_cfg
                .map(|s| s.rpc_url.clone())
                .unwrap_or_else(|| "https://mainnet.base.org".to_string());
            let poll_ms = scanner_cfg.map(|s| s.poll_interval_ms).unwrap_or(2000);
            let seed_wallets: Vec<String> = scanner_cfg
                .map(|s| s.seed_wallets.clone())
                .unwrap_or_default();
            let scanner_db = db.clone_handle();
            let scanner_notifier = notifier.clone();
            Some(tokio::spawn(async move {
                let mut scanner = X402Scanner::new(rpc_url, poll_ms);

                for seed in &seed_wallets {
                    let existing = scanner_db.get_wallet_addresses().unwrap_or_default();
                    if !existing.contains(seed) {
                        let _ = scanner_db.upsert_wallet(
                            seed, "Base", 0.0, 0, "Seed", None, 0.0, 0.0,
                        );
                        info!(wallet = %seed, "registered scanner seed wallet");
                    }
                }

                loop {
                    let known_wallets = scanner_db.get_wallet_address_set().unwrap_or_default();

                    if known_wallets.is_empty() {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        continue;
                    }

                    match scanner.poll_new_transfers(&known_wallets).await {
                        Ok(wallets) => {
                            for w in &wallets {
                                if !known_wallets.contains(&w.address) {
                                    let _ = scanner_db.upsert_wallet(
                                        &w.address,
                                        &format!("{:?}", w.chain),
                                        0.0,
                                        0,
                                        "Discovered",
                                        None,
                                        0.0,
                                        0.0,
                                    );

                                    let reason = match &w.discovery_reason {
                                        thorn_chain::scanner::DiscoveryReason::GraphExpansion {
                                            known_side,
                                        } => format!("graph expansion from {}", &known_side[..known_side.len().min(10)]),
                                        thorn_chain::scanner::DiscoveryReason::Seed => {
                                            "seed wallet".to_string()
                                        }
                                    };

                                    let event = AlertEvent {
                                        id: uuid::Uuid::new_v4().to_string(),
                                        severity: AlertSeverity::High,
                                        kind: AlertKind::WalletDiscovered {
                                            address: w.address.clone(),
                                            chain: w.chain.clone(),
                                        },
                                        title: format!(
                                            "x402 wallet: {}",
                                            &w.address[..w.address.len().min(10)]
                                        ),
                                        detail: format!(
                                            "Wallet {} discovered via {} ({:.4} USDC) tx:{}",
                                            w.address, reason, w.amount_usdc, w.tx_hash
                                        ),
                                        timestamp: Utc::now(),
                                        metadata: HashMap::new(),
                                    };
                                    let _ = scanner_notifier.send(&event).await;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "x402 scanner poll failed");
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(scanner.poll_interval_ms())).await;
                }
            }))
        } else {
            info!("x402 scanner disabled");
            None
        }
    };

    let discovery_db = db.clone_handle();
    let discovery_notifier = notifier.clone();
    let discovery_handle = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(5));
        let client = reqwest::Client::builder()
            .user_agent("Mozilla/5.0 (compatible; ThornBot/0.1)")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build http client");
        loop {
            tick.tick().await;

            let wallets = match discovery_db.get_wallets_discovered_from_honeypot() {
                Ok(w) => w,
                Err(_) => continue,
            };

            for wallet in &wallets {
                let existing = discovery_db.get_wallet_addresses().unwrap_or_default();
                if !existing.contains(wallet) {
                    info!(wallet = %wallet, "new wallet discovered from honeypot");
                    let _ = discovery_db.upsert_wallet(wallet, "base", 0.0, 0, "Unknown", None, 0.0, 0.0);

                    let event = AlertEvent {
                        id: uuid::Uuid::new_v4().to_string(),
                        severity: AlertSeverity::High,
                        kind: AlertKind::WalletDiscovered {
                            address: wallet.clone(),
                            chain: Chain::Base,
                        },
                        title: format!("New wallet discovered: {}", &wallet[..wallet.len().min(10)]),
                        detail: format!("Wallet {} found via honeypot interaction", wallet),
                        timestamp: Utc::now(),
                        metadata: HashMap::new(),
                    };
                    let _ = discovery_notifier.send(&event).await;
                }
            }

            let targets = discovery_db.get_unscanned_targets(10).unwrap_or_default();
            for (target_url, _priority) in &targets {
                info!(url = %target_url, "scanning discovered target");
                if let Err(e) = scan_and_store(&client, target_url, &discovery_db).await {
                    warn!(url = %target_url, error = %e, "discovered target scan failed");
                }
                let _ = discovery_db.mark_target_scanned(target_url);
            }
        }
    });

    let scan_handle = if let Some(scan_config) = config.scan {
        let scan_db = db.clone_handle();
        let scan_notifier = notifier.clone();
        let targets = scan_config.targets;
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(10));
            let client = reqwest::Client::builder()
                .user_agent("Mozilla/5.0 (compatible; ThornBot/0.1)")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build http client");
            loop {
                tick.tick().await;
                let unscanned = scan_db.get_unscanned_targets(0).unwrap_or_default();
                let has_work = !unscanned.is_empty();
                if !has_work && targets.is_empty() {
                    continue;
                }
                let work_targets: Vec<String> = if has_work {
                    unscanned.into_iter().map(|(url, _)| url).collect()
                } else {
                    targets.clone()
                };
                info!("scanning {} target(s)", work_targets.len());
                for target in &work_targets {
                    match scan_and_store(&client, target, &scan_db).await {
                        Ok(Some(score)) if score > 0.6 => {
                            let event = AlertEvent {
                                id: uuid::Uuid::new_v4().to_string(),
                                severity: AlertSeverity::High,
                                kind: AlertKind::BotDetected {
                                    url: target.clone(),
                                    score,
                                },
                                title: format!("Bot detected: {}", target),
                                detail: format!("Score: {:.2}", score),
                                timestamp: Utc::now(),
                                metadata: HashMap::new(),
                            };
                            let _ = scan_notifier.send(&event).await;
                        }
                        Err(e) => warn!("scan failed for {}: {}", target, e),
                        _ => {}
                    }
                }
            }
        }))
    } else {
        None
    };

    let crawl_handle = if let Some(crawl_config) = config.crawl {
        let crawl_db = db.clone_handle();
        let config_seeds = crawl_config.seeds;
        let depth = crawl_config.depth;
        let concurrent = crawl_config.concurrent;
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                let mut seeds = config_seeds.clone();
                if let Ok(domain_urls) = crawl_db.get_domain_urls_for_crawl() {
                    for url in domain_urls {
                        if !seeds.contains(&url) {
                            seeds.push(url);
                        }
                    }
                }
                if seeds.is_empty() {
                    continue;
                }
                info!("crawling {} seed(s) (config + discovered)", seeds.len());
                if let Err(e) = crawl_and_store(&seeds, depth, concurrent, &crawl_db).await {
                    warn!("crawl failed: {}", e);
                }
                tokio::time::sleep(Duration::from_secs(300)).await;
            }
        }))
    } else {
        None
    };

    let track_handle = if config.track.is_some() {
        let track_db = db.clone_handle();
        let track_notifier = notifier.clone();
        let track_config = config.track.unwrap();
        let chain = parse_chain(&track_config.chain);
        let rpc_url = track_config
            .rpc_url
            .unwrap_or_else(|| default_rpc(&chain).to_string());
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(10));
            let tracker = WalletTracker::new(rpc_url, chain);
            loop {
                tick.tick().await;
                let wallets = track_db.get_wallet_addresses().unwrap_or_default();
                if wallets.is_empty() {
                    continue;
                }
                info!("tracking {} wallet(s)", wallets.len());
                for wallet in &wallets {
                    if let Err(e) = track_and_store(&tracker, wallet, &track_db, &track_notifier).await {
                        warn!("track failed for {}: {}", wallet, e);
                    }
                }
            }
        }))
    } else {
        None
    };

    let archive_handle = if let Some(arc) = archive {
        let archive_db = db.clone_handle();
        let archive_interval = config
            .r2
            .as_ref()
            .map(|r| r.archive_interval_secs)
            .unwrap_or(3600);
        Some(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(archive_interval));
            loop {
                tick.tick().await;
                info!("running periodic R2 archival");

                if let Ok(hits) = archive_db.get_honeypot_hits(1000) {
                    if !hits.is_empty() {
                        let json = serde_json::to_value(&hits).unwrap_or_default();
                        if let Err(e) = arc.archive_honeypot_hits(&json).await {
                            warn!(error = %e, "R2 honeypot archive failed");
                        }
                    }
                }

                if let Ok(scans) = archive_db.get_scan_results(1000) {
                    if !scans.is_empty() {
                        let json = serde_json::to_value(&scans).unwrap_or_default();
                        if let Err(e) = arc.archive_scan_results(&json).await {
                            warn!(error = %e, "R2 scan archive failed");
                        }
                    }
                }
            }
        }))
    } else {
        None
    };

    let stats = db.stats()?;
    info!(
        scans = stats.scan_results,
        hits = stats.honeypot_hits,
        wallets = stats.wallets,
        targets = stats.discovered_targets,
        capture = capture_enabled.load(Ordering::Relaxed),
        "daemon running — honeypot + continuous loops + x402 scanner active"
    );

    tokio::select! {
        _ = honeypot_handle => error!("honeypot task exited"),
        _ = discovery_handle => error!("discovery task exited"),
        _ = async { if let Some(h) = scanner_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            error!("scanner task exited")
        }
        _ = async { if let Some(h) = scan_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            error!("scan task exited")
        }
        _ = async { if let Some(h) = crawl_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            error!("crawl task exited")
        }
        _ = async { if let Some(h) = track_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            error!("track task exited")
        }
        _ = async { if let Some(h) = archive_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            error!("archive task exited")
        }
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
        }
    }

    info!("daemon stopped");
    Ok(())
}

async fn scan_and_store(
    client: &reqwest::Client,
    target: &str,
    db: &ThornDb,
) -> Result<Option<f64>, Box<dyn std::error::Error + Send + Sync>> {
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

    let (infra_signals, fingerprint) = infra::analyze_infrastructure(&headers_map, &domain);
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
        url = %url,
        score = score.score,
        classification = ?score.classification,
        "scan complete"
    );

    let record = ScanRecord {
        id: uuid::Uuid::new_v4().to_string(),
        url: url.clone(),
        domain: domain.clone(),
        score: score.score,
        classification: format!("{:?}", score.classification),
        signals: score.signals.clone(),
        scanned_at: Utc::now(),
    };
    db.insert_scan_result(&record)?;

    let infra_json = serde_json::to_string(&fingerprint).unwrap_or_else(|_| "{}".to_string());
    db.upsert_domain(
        &domain,
        None,
        Some(score.score),
        Some(&format!("{:?}", score.classification)),
        &infra_json,
    )?;

    Ok(Some(score.score))
}

async fn crawl_and_store(
    seeds: &[String],
    depth: usize,
    concurrent: usize,
    db: &ThornDb,
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

        let (infra_signals, fingerprint) = infra::analyze_infrastructure(&page_headers, &domain);
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
                url = %url,
                score = score.score,
                classification = ?score.classification,
                "crawl detected bot signal"
            );

            let _ = db.insert_discovered_target(&url, "CrawlLink", &domain, score.score);
        }

        let record = ScanRecord {
            id: uuid::Uuid::new_v4().to_string(),
            url,
            domain: domain.clone(),
            score: score.score,
            classification: format!("{:?}", score.classification),
            signals: score.signals.clone(),
            scanned_at: Utc::now(),
        };
        let _ = db.insert_scan_result(&record);

        let infra_json = serde_json::to_string(&fingerprint).unwrap_or_else(|_| "{}".to_string());
        let _ = db.upsert_domain(
            &domain,
            None,
            Some(score.score),
            Some(&format!("{:?}", score.classification)),
            &infra_json,
        );
    }

    crawl_handle.await.ok();
    Ok(())
}

async fn track_and_store(
    tracker: &WalletTracker,
    wallet: &str,
    db: &ThornDb,
    _notifier: &Notifier,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let profile = tracker.build_automaton_profile(wallet).await.map_err(|e| {
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            as Box<dyn std::error::Error + Send + Sync>
    })?;

    info!(
        wallet = %wallet,
        status = ?profile.status,
        spent = profile.total_spent,
        "tracked wallet"
    );

    db.upsert_wallet(
        wallet,
        &format!("{:?}", profile.chain),
        profile.total_spent,
        0,
        &format!("{:?}", profile.status),
        profile.parent_wallet.as_deref(),
        profile.total_spent,
        profile.total_earned,
    )
    .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    if let Some(ref parent) = profile.parent_wallet {
        let _ = db.insert_wallet_child(parent, wallet);

        let existing = db.get_wallet_addresses().unwrap_or_default();
        if !existing.contains(parent) {
            let _ = db.upsert_wallet(parent, &format!("{:?}", profile.chain), 0.0, 0, "Unknown", None, 0.0, 0.0);
            info!(parent = %parent, child = %wallet, "discovered parent wallet");
        }
    }

    for child in &profile.children_wallets {
        let _ = db.insert_wallet_child(wallet, child);
    }

    for domain in &profile.domains {
        let _ = db.insert_discovered_target(
            &format!("https://{}", domain),
            "WalletTrace",
            wallet,
            0.8,
        );
    }

    let x402_txs = tracker.get_x402_transactions(wallet).await.unwrap_or_default();
    for tx in &x402_txs {
        let _ = db.insert_x402_transaction(tx);
    }

    Ok(())
}
