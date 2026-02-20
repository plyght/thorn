use serde::Deserialize;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ThornConfig {
    pub honeypot: HoneypotConfig,
    pub scan: Option<ScanConfig>,
    pub crawl: Option<CrawlConfig>,
    pub track: Option<TrackConfig>,
    pub output: OutputConfig,
    pub db: Option<DbConfig>,
    pub notify: Option<NotifyConfig>,
    pub r2: Option<R2Config>,
    pub api: Option<ApiConfig>,
    pub capture: Option<CaptureConfig>,
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

#[derive(Deserialize)]
pub struct DbConfig {
    #[serde(default = "default_db_path")]
    pub path: String,
}

#[derive(Deserialize)]
pub struct NotifyConfig {
    #[serde(default)]
    pub webhook_urls: Vec<String>,
    pub ntfy_topic: Option<String>,
    pub ntfy_server: Option<String>,
}

#[derive(Deserialize)]
pub struct R2Config {
    pub bucket: String,
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default = "default_archive_interval")]
    pub archive_interval_secs: u64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ApiConfig {
    #[serde(default = "default_api_port")]
    pub port: u16,
    #[serde(default = "default_api_bind")]
    pub bind: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct CaptureConfig {
    #[serde(default = "default_capture_enabled")]
    pub enabled: bool,
    #[serde(default = "default_poison_ratio")]
    pub poison_ratio: f64,
    #[serde(default = "default_drain_base_price")]
    pub drain_base_price: f64,
    #[serde(default = "default_drain_multiplier")]
    pub drain_multiplier: f64,
    #[serde(default = "default_drain_max_price")]
    pub drain_max_price: f64,
    #[serde(default)]
    pub monitor_domains: Vec<String>,
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
fn default_db_path() -> String {
    "./thorn-data/thorn.db".to_string()
}
fn default_archive_interval() -> u64 {
    3600
}
fn default_api_port() -> u16 {
    3001
}
fn default_api_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_capture_enabled() -> bool {
    false
}
fn default_poison_ratio() -> f64 {
    0.3
}
fn default_drain_base_price() -> f64 {
    0.05
}
fn default_drain_multiplier() -> f64 {
    1.5
}
fn default_drain_max_price() -> f64 {
    10.0
}

impl ThornConfig {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}
