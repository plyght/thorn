use clap::{Parser, Subcommand};

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

    match cli.command {
        Commands::Scan { target } => {
            println!("scanning {} for bot signals...", target);
            todo!()
        }
        Commands::Track { wallet, chain } => {
            println!("tracking wallet {} on {}...", wallet, chain);
            todo!()
        }
        Commands::Honeypot { port } => {
            println!("starting honeypot on port {}...", port);
            todo!()
        }
        Commands::Crawl {
            urls,
            depth,
            concurrent,
        } => {
            println!(
                "crawling {} url(s) depth={} concurrent={}...",
                urls.len(),
                depth,
                concurrent
            );
            todo!()
        }
    }
}
