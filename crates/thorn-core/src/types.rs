use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotSignal {
    pub kind: SignalKind,
    pub confidence: f64,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalKind {
    AiGeneratedContent,
    AutomationFramework,
    SyntheticMouseMovement,
    DomInjection,
    X402Payment,
    ConwayInfrastructure,
    WalletPattern,
    Erc8004Identity,
    HeaderAnomaly,
    StructuralHomogeneity,
    DeploymentCadence,
    TimingAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotScore {
    pub score: f64,
    pub signals: Vec<BotSignal>,
    pub classification: BotClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BotClassification {
    Human,
    LikelyHuman,
    Uncertain,
    LikelyBot,
    ConfirmedBot,
    ConwayAutomaton,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatonProfile {
    pub wallet_address: String,
    pub chain: Chain,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub domains: Vec<String>,
    pub sandboxes: Vec<String>,
    pub parent_wallet: Option<String>,
    pub children_wallets: Vec<String>,
    pub total_spent: f64,
    pub total_earned: f64,
    pub status: AutomatonStatus,
    pub signals: Vec<BotSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomatonStatus {
    Alive,
    LowBalance,
    Dead,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Chain {
    Base,
    Solana,
    Ethereum,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub chain: Chain,
    pub balance_usdc: f64,
    pub transaction_count: u64,
    pub first_tx: Option<DateTime<Utc>>,
    pub last_tx: Option<DateTime<Utc>>,
    pub funded_by: Option<String>,
    pub funded_wallets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Transaction {
    pub tx_hash: String,
    pub from_wallet: String,
    pub to_wallet: String,
    pub amount_usdc: f64,
    pub service_url: String,
    pub timestamp: DateTime<Utc>,
    pub chain: Chain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotHit {
    pub source_ip: String,
    pub wallet_address: Option<String>,
    pub endpoint: String,
    pub user_agent: String,
    pub headers: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
    pub signals: Vec<BotSignal>,
    pub prompt_injection_triggered: bool,
    pub payment_amount: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainIntel {
    pub domain: String,
    pub registrar: Option<String>,
    pub registered_at: Option<DateTime<Utc>>,
    pub wallet_address: Option<String>,
    pub bot_score: Option<BotScore>,
    pub content_hash: Option<u64>,
    pub infrastructure: InfraFingerprint,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InfraFingerprint {
    pub server_header: Option<String>,
    pub hosting_provider: Option<String>,
    pub tls_issuer: Option<String>,
    pub has_x402: bool,
    pub conway_indicators: Vec<String>,
}
