use chrono::Utc;
use serde_json::{json, Value};
use thorn_core::{
    AutomatonProfile, AutomatonStatus, BotSignal, Chain, SignalKind, ThornError, ThornResult,
    WalletInfo, X402Transaction,
};

const BASE_USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

pub struct WalletTracker {
    rpc_url: String,
    chain: Chain,
    client: reqwest::Client,
}

impl WalletTracker {
    pub fn new(rpc_url: String, chain: Chain) -> Self {
        Self {
            rpc_url,
            chain,
            client: reqwest::Client::new(),
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> ThornResult<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });
        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await?
            .json::<Value>()
            .await?;
        if let Some(err) = resp.get("error") {
            return Err(ThornError::Chain(err.to_string()));
        }
        Ok(resp["result"].clone())
    }

    pub async fn get_wallet_info(&self, address: &str) -> ThornResult<WalletInfo> {
        match &self.chain {
            Chain::Base | Chain::Ethereum => {
                let balance_hex = self
                    .rpc("eth_getBalance", json!([address, "latest"]))
                    .await?;
                let tx_count_hex = self
                    .rpc("eth_getTransactionCount", json!([address, "latest"]))
                    .await?;
                let balance_str = balance_hex
                    .as_str()
                    .ok_or_else(|| ThornError::Chain("invalid balance response".into()))?;
                let tx_count_str = tx_count_hex
                    .as_str()
                    .ok_or_else(|| ThornError::Chain("invalid tx count response".into()))?;
                let balance_wei =
                    u128::from_str_radix(balance_str.trim_start_matches("0x"), 16)
                        .map_err(|e| ThornError::Chain(e.to_string()))?;
                let tx_count =
                    u64::from_str_radix(tx_count_str.trim_start_matches("0x"), 16)
                        .map_err(|e| ThornError::Chain(e.to_string()))?;
                let balance_usdc = balance_wei as f64 / 1e18;
                Ok(WalletInfo {
                    address: address.to_string(),
                    chain: self.chain.clone(),
                    balance_usdc,
                    transaction_count: tx_count,
                    first_tx: None,
                    last_tx: None,
                    funded_by: None,
                    funded_wallets: vec![],
                })
            }
            Chain::Solana => {
                let balance_resp = self.rpc("getBalance", json!([address])).await?;
                let sigs_resp = self
                    .rpc(
                        "getSignaturesForAddress",
                        json!([address, { "limit": 1000 }]),
                    )
                    .await?;
                let lamports = balance_resp["value"]
                    .as_u64()
                    .ok_or_else(|| ThornError::Chain("invalid balance response".into()))?;
                let tx_count = sigs_resp.as_array().map(|a| a.len() as u64).unwrap_or(0);
                let balance_usdc = lamports as f64 / 1e9;
                Ok(WalletInfo {
                    address: address.to_string(),
                    chain: self.chain.clone(),
                    balance_usdc,
                    transaction_count: tx_count,
                    first_tx: None,
                    last_tx: None,
                    funded_by: None,
                    funded_wallets: vec![],
                })
            }
            Chain::Unknown(name) => {
                Err(ThornError::Chain(format!("unsupported chain: {}", name)))
            }
        }
    }

    pub async fn get_x402_transactions(
        &self,
        address: &str,
    ) -> ThornResult<Vec<X402Transaction>> {
        match &self.chain {
            Chain::Base | Chain::Ethereum => {
                let addr_padded = format!(
                    "0x000000000000000000000000{}",
                    address.trim_start_matches("0x").to_lowercase()
                );
                let logs_resp = self
                    .rpc(
                        "eth_getLogs",
                        json!([{
                            "address": BASE_USDC,
                            "topics": [TRANSFER_TOPIC, null, addr_padded],
                            "fromBlock": "earliest",
                            "toBlock": "latest"
                        }]),
                    )
                    .await?;
                let logs = logs_resp
                    .as_array()
                    .ok_or_else(|| ThornError::Chain("invalid logs response".into()))?;
                let offset = logs.len().saturating_sub(100);
                let mut txs = Vec::new();
                for log in &logs[offset..] {
                    let tx_hash = log["transactionHash"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let topics = log["topics"].as_array();
                    let from_topic = topics
                        .and_then(|t| t.get(1))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let from_wallet = if from_topic.len() >= 42 {
                        format!("0x{}", &from_topic[from_topic.len() - 40..])
                    } else {
                        from_topic.to_string()
                    };
                    let data = log["data"].as_str().unwrap_or("0x");
                    let amount_raw =
                        u128::from_str_radix(data.trim_start_matches("0x"), 16).unwrap_or(0);
                    let amount_usdc = amount_raw as f64 / 1e6;
                    txs.push(X402Transaction {
                        tx_hash,
                        from_wallet,
                        to_wallet: address.to_string(),
                        amount_usdc,
                        service_url: String::new(),
                        timestamp: Utc::now(),
                        chain: self.chain.clone(),
                    });
                }
                Ok(txs)
            }
            Chain::Solana => {
                let sigs_resp = self
                    .rpc(
                        "getSignaturesForAddress",
                        json!([address, { "limit": 100 }]),
                    )
                    .await?;
                let sigs = sigs_resp
                    .as_array()
                    .ok_or_else(|| ThornError::Chain("invalid signatures response".into()))?;
                let mut txs = Vec::new();
                for sig_info in sigs.iter().take(100) {
                    let sig = sig_info["signature"].as_str().unwrap_or_default();
                    if sig.is_empty() {
                        continue;
                    }
                    let tx_resp = self
                        .rpc(
                            "getTransaction",
                            json!([sig, {
                                "encoding": "json",
                                "maxSupportedTransactionVersion": 0
                            }]),
                        )
                        .await?;
                    if tx_resp.is_null() {
                        continue;
                    }
                    let block_time = tx_resp["blockTime"].as_i64().unwrap_or(0);
                    let timestamp = chrono::DateTime::from_timestamp(block_time, 0)
                        .unwrap_or_else(Utc::now);
                    let accounts = tx_resp["transaction"]["message"]["accountKeys"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let from_wallet = accounts
                        .first()
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    txs.push(X402Transaction {
                        tx_hash: sig.to_string(),
                        from_wallet,
                        to_wallet: address.to_string(),
                        amount_usdc: 0.0,
                        service_url: String::new(),
                        timestamp,
                        chain: self.chain.clone(),
                    });
                }
                Ok(txs)
            }
            Chain::Unknown(name) => {
                Err(ThornError::Chain(format!("unsupported chain: {}", name)))
            }
        }
    }

    pub async fn trace_funding_chain(&self, address: &str) -> ThornResult<Vec<String>> {
        let mut chain_vec: Vec<String> = Vec::new();
        let mut current = address.to_string();
        for _ in 0..10 {
            let parent = self.find_first_funder(&current).await?;
            match parent {
                Some(p) if p != current && !chain_vec.contains(&p) => {
                    chain_vec.push(p.clone());
                    current = p;
                }
                _ => break,
            }
        }
        Ok(chain_vec)
    }

    async fn find_first_funder(&self, address: &str) -> ThornResult<Option<String>> {
        match &self.chain {
            Chain::Base | Chain::Ethereum => {
                let addr_padded = format!(
                    "0x000000000000000000000000{}",
                    address.trim_start_matches("0x").to_lowercase()
                );
                let logs_resp = self
                    .rpc(
                        "eth_getLogs",
                        json!([{
                            "address": BASE_USDC,
                            "topics": [TRANSFER_TOPIC, null, addr_padded],
                            "fromBlock": "earliest",
                            "toBlock": "latest"
                        }]),
                    )
                    .await?;
                let logs = logs_resp
                    .as_array()
                    .ok_or_else(|| ThornError::Chain("invalid logs response".into()))?;
                if logs.is_empty() {
                    return Ok(None);
                }
                let first_log = &logs[0];
                let topics = first_log["topics"].as_array();
                let from_topic = topics
                    .and_then(|t| t.get(1))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if from_topic.len() < 42 {
                    return Ok(None);
                }
                Ok(Some(format!("0x{}", &from_topic[from_topic.len() - 40..])))
            }
            Chain::Solana => {
                let sigs_resp = self
                    .rpc(
                        "getSignaturesForAddress",
                        json!([address, { "limit": 1000 }]),
                    )
                    .await?;
                let sigs = sigs_resp
                    .as_array()
                    .ok_or_else(|| ThornError::Chain("invalid signatures response".into()))?;
                if sigs.is_empty() {
                    return Ok(None);
                }
                let oldest = sigs.last().unwrap();
                let sig = oldest["signature"].as_str().unwrap_or_default();
                if sig.is_empty() {
                    return Ok(None);
                }
                let tx_resp = self
                    .rpc(
                        "getTransaction",
                        json!([sig, {
                            "encoding": "json",
                            "maxSupportedTransactionVersion": 0
                        }]),
                    )
                    .await?;
                if tx_resp.is_null() {
                    return Ok(None);
                }
                let accounts = tx_resp["transaction"]["message"]["accountKeys"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                Ok(accounts
                    .first()
                    .and_then(|v| v.as_str())
                    .filter(|a| *a != address)
                    .map(|a| a.to_string()))
            }
            Chain::Unknown(name) => {
                Err(ThornError::Chain(format!("unsupported chain: {}", name)))
            }
        }
    }

    pub async fn build_automaton_profile(
        &self,
        wallet_address: &str,
    ) -> ThornResult<AutomatonProfile> {
        let wallet_info = self.get_wallet_info(wallet_address).await?;
        let x402_txs = self.get_x402_transactions(wallet_address).await?;
        let funding_chain = self.trace_funding_chain(wallet_address).await?;

        let status = if wallet_info.balance_usdc == 0.0 {
            AutomatonStatus::Dead
        } else if wallet_info.balance_usdc < 1.0 {
            AutomatonStatus::LowBalance
        } else {
            AutomatonStatus::Alive
        };

        let mut signals: Vec<BotSignal> = Vec::new();
        if !x402_txs.is_empty() {
            signals.push(BotSignal {
                kind: SignalKind::X402Payment,
                confidence: 0.9,
                evidence: format!("{} x402 transactions detected", x402_txs.len()),
            });
            let avg_amount =
                x402_txs.iter().map(|t| t.amount_usdc).sum::<f64>() / x402_txs.len() as f64;
            if x402_txs.len() >= 5 && avg_amount < 1.0 {
                signals.push(BotSignal {
                    kind: SignalKind::WalletPattern,
                    confidence: 0.75,
                    evidence: format!(
                        "{} small x402 payments avg {:.4} USDC",
                        x402_txs.len(),
                        avg_amount
                    ),
                });
            }
        }

        let now = Utc::now();
        let first_seen = x402_txs.first().map(|t| t.timestamp).unwrap_or(now);
        let last_seen = x402_txs.last().map(|t| t.timestamp).unwrap_or(now);
        let total_spent = x402_txs.iter().map(|t| t.amount_usdc).sum::<f64>();
        let parent_wallet = funding_chain.first().cloned();

        Ok(AutomatonProfile {
            wallet_address: wallet_address.to_string(),
            chain: self.chain.clone(),
            first_seen,
            last_seen,
            domains: vec![],
            sandboxes: vec![],
            parent_wallet,
            children_wallets: vec![],
            total_spent,
            total_earned: 0.0,
            status,
            signals,
        })
    }
}
