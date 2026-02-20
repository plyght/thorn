use serde::Deserialize;

#[derive(Deserialize)]
pub struct ThornConfig {
    pub honeypot: HoneypotConfig,
    pub scan: Option<ScanConfig>,
    pub crawl: Option<CrawlConfig>,
    pub track: Option<TrackConfig>,
    pub output: OutputConfig,
}

#[derive(Deserialize)]
pub struct HoneypotConfig {
    #[serde(default = "default_honeypot_port")]
    pub port: u16,
    #[serde(default = "default_honeypot_bind")]
    pub bind: String,
}

#[derive(Deserialize)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    #[serde(default = "default_scan_interval")]
    pub interval_secs: u64,
}

#[derive(Deserialize)]
pub struct CrawlConfig {
    pub seeds: Vec<String>,
    #[serde(default = "default_crawl_depth")]
    pub depth: usize,
    #[serde(default = "default_crawl_concurrent")]
    pub concurrent: usize,
    #[serde(default = "default_crawl_interval")]
    pub interval_secs: u64,
}

#[derive(Deserialize)]
pub struct TrackConfig {
    #[serde(default = "default_chain")]
    pub chain: String,
    pub rpc_url: Option<String>,
    #[serde(default)]
    pub watch_wallets: Vec<String>,
    #[serde(default = "default_track_interval")]
    pub interval_secs: u64,
}

#[derive(Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_results_dir")]
    pub results_dir: String,
}

fn default_honeypot_port() -> u16 {
    3000
}
fn default_honeypot_bind() -> String {
    "0.0.0.0".to_string()
}
fn default_scan_interval() -> u64 {
    3600
}
fn default_crawl_depth() -> usize {
    2
}
fn default_crawl_concurrent() -> usize {
    10
}
fn default_crawl_interval() -> u64 {
    7200
}
fn default_chain() -> String {
    "base".to_string()
}
fn default_track_interval() -> u64 {
    300
}
fn default_results_dir() -> String {
    "./thorn-data".to_string()
}

impl ThornConfig {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}
