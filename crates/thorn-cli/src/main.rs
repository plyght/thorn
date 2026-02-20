mod config;
mod daemon;

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::sync::Arc;
use thorn_chain::tracker::WalletTracker;
use thorn_core::Chain;
use thorn_detect::{content, infra, scoring};
use thorn_honeypot::server::{honeypot_router, HoneypotState};

#[derive(Parser)]
#[command(name = "thorn")]
#[command(about = "Detect, track, and counter autonomous AI bots")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(help = "URL or domain to scan for bot signals")]
        target: String,
    },
    Track {
        #[arg(help = "Wallet address to trace")]
        wallet: String,
        #[arg(short, long, default_value = "base")]
        chain: String,
        #[arg(long, help = "Custom RPC endpoint URL")]
        rpc_url: Option<String>,
    },
    Honeypot {
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
    Crawl {
        #[arg(help = "Seed URLs to crawl and analyze")]
        urls: Vec<String>,
        #[arg(short, long, default_value = "2")]
        depth: usize,
        #[arg(short, long, default_value = "10")]
        concurrent: usize,
    },
    Daemon {
        #[arg(short = 'f', long, default_value = "thorn.toml", help = "Path to config file")]
        config: String,
    },
}

fn parse_chain(s: &str) -> Chain {
    match s.to_lowercase().as_str() {
        "base" => Chain::Base,
        "solana" | "sol" => Chain::Solana,
        "ethereum" | "eth" => Chain::Ethereum,
        other => Chain::Unknown(other.to_string()),
    }
}

fn default_rpc(chain: &Chain) -> Option<&'static str> {
    match chain {
        Chain::Base => Some("https://mainnet.base.org"),
        Chain::Solana => Some("https://api.mainnet-beta.solana.com"),
        Chain::Ethereum => Some("https://eth.llamarpc.com"),
        Chain::Unknown(_) => None,
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "thorn=info".into()),
        )
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Scan { target } => run_scan(target).await,
        Commands::Track {
            wallet,
            chain,
            rpc_url,
        } => run_track(wallet, chain, rpc_url).await,
        Commands::Honeypot { port } => run_honeypot(port).await,
        Commands::Crawl {
            urls,
            depth,
            concurrent,
        } => run_crawl(urls, depth, concurrent).await,
        Commands::Daemon { config: config_path } => {
            match config::ThornConfig::from_file(&config_path) {
                Ok(cfg) => daemon::run_daemon(cfg).await,
                Err(e) => Err(format!("failed to load config {}: {}", config_path, e).into()),
            }
        }
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

async fn run_scan(target: String) -> Result<(), Box<dyn std::error::Error>> {
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.clone()
    } else {
        format!("https://{}", target)
    };

    println!("scanning {} for bot signals...", url);

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; ThornBot/0.1)")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

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

    println!("\n--- scan results for {} ---", url);
    println!("status: {}", status);
    println!("domain: {}", domain);

    if let Some(server) = &fingerprint.server_header {
        println!("server: {}", server);
    }
    if fingerprint.has_x402 {
        println!("x402: DETECTED");
    }
    if !fingerprint.conway_indicators.is_empty() {
        println!("conway indicators: {:?}", fingerprint.conway_indicators);
    }

    println!("\nsignals ({}):", score.signals.len());
    for sig in &score.signals {
        println!(
            "  [{:.0}%] {:?}: {}",
            sig.confidence * 100.0,
            sig.kind,
            sig.evidence
        );
    }

    println!("\nbot score: {:.2}", score.score);
    println!("classification: {:?}", score.classification);

    Ok(())
}

async fn run_track(
    wallet: String,
    chain_str: String,
    rpc_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let chain = parse_chain(&chain_str);

    let rpc = match rpc_url {
        Some(url) => url,
        None => match default_rpc(&chain) {
            Some(url) => url.to_string(),
            None => {
                return Err(
                    format!("unknown chain: {}. use base, solana, or ethereum", chain_str).into(),
                );
            }
        },
    };

    println!("tracking wallet {} on {:?}...", wallet, chain);

    let tracker = WalletTracker::new(rpc, chain);
    let profile = tracker.build_automaton_profile(&wallet).await?;

    println!("\n--- automaton profile ---");
    println!("wallet: {}", profile.wallet_address);
    println!("chain: {:?}", profile.chain);
    println!("status: {:?}", profile.status);
    println!("first seen: {}", profile.first_seen);
    println!("last seen: {}", profile.last_seen);
    println!("total spent: {:.6}", profile.total_spent);
    println!("total earned: {:.6}", profile.total_earned);

    if let Some(parent) = &profile.parent_wallet {
        println!("parent wallet: {}", parent);
    }
    if !profile.children_wallets.is_empty() {
        println!("children: {:?}", profile.children_wallets);
    }
    if !profile.domains.is_empty() {
        println!("domains: {:?}", profile.domains);
    }

    println!("\nsignals ({}):", profile.signals.len());
    for sig in &profile.signals {
        println!(
            "  [{:.0}%] {:?}: {}",
            sig.confidence * 100.0,
            sig.kind,
            sig.evidence
        );
    }

    Ok(())
}

async fn run_honeypot(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(HoneypotState::new());
    let router = honeypot_router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("honeypot listening on 0.0.0.0:{}", port);
    println!("endpoints:");
    println!("  GET /             - landing page (HTML trap)");
    println!("  GET /docs         - API documentation (HTML trap)");
    println!("  GET /v1/data/*    - fake x402 API endpoints");
    println!("  GET /health       - health check");
    println!("  GET /hits         - view logged hits");

    axum::serve(listener, router).await?;

    Ok(())
}

async fn run_crawl(
    urls: Vec<String>,
    depth: usize,
    concurrent: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if urls.is_empty() {
        return Err("at least one seed URL required".into());
    }

    println!(
        "crawling {} url(s) depth={} concurrent={}...",
        urls.len(),
        depth,
        concurrent
    );

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

    let seeds: Vec<(String, usize, slither_core::CrawlScope)> = urls
        .into_iter()
        .map(|u| (u, depth, slither_core::CrawlScope::SameDomain))
        .collect();

    let crawl_handle = tokio::spawn(async move {
        if let Err(e) = crawler.crawl(seeds, tx).await {
            eprintln!("crawl error: {}", e);
        }
    });

    let mut total = 0u64;
    let mut bot_count = 0u64;

    while let Some(page) = rx.recv().await {
        total += 1;
        let url = page.url.clone();
        let domain = page.domain.clone();
        let page_headers = page.headers.clone();

        let (title, body, headings) = match transformer.transform(&page) {
            Ok(doc) => (doc.title, doc.body, doc.headings),
            Err(e) => {
                tracing::warn!("transform failed for {}: {}", url, e);
                continue;
            }
        };

        let (infra_signals, _fingerprint) = infra::analyze_infrastructure(&page_headers, &domain);
        let content_signals = content::analyze_content(&body, &title, &headings);

        let mut all_signals = infra_signals;
        all_signals.extend(content_signals);

        if page.status == 402 {
            all_signals.push(thorn_core::BotSignal {
                kind: thorn_core::SignalKind::X402Payment,
                confidence: 0.7,
                evidence: "HTTP 402 Payment Required response".to_string(),
            });
        }

        let score = scoring::compute_bot_score(all_signals);

        let is_bot = score.score > 0.4;
        if is_bot {
            bot_count += 1;
        }

        let marker = if is_bot { "!" } else { "ok" };
        println!(
            "  [{}] {} {:.2} {:?} - {}",
            marker, page.status, score.score, score.classification, url
        );

        if !score.signals.is_empty() && is_bot {
            for sig in &score.signals {
                println!(
                    "      [{:.0}%] {:?}: {}",
                    sig.confidence * 100.0,
                    sig.kind,
                    sig.evidence
                );
            }
        }
    }

    crawl_handle.await?;

    println!("\n--- crawl summary ---");
    println!("pages scanned: {}", total);
    println!("bot signals detected: {}", bot_count);
    println!("clean pages: {}", total - bot_count);

    Ok(())
}
