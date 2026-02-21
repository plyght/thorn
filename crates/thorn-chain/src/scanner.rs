use serde_json::{json, Value};
use thorn_core::{Chain, ThornError, ThornResult};
use tracing::info;

const BASE_USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

pub struct X402Scanner {
    rpc_url: String,
    client: reqwest::Client,
    last_block: u64,
    poll_interval_ms: u64,
}

pub struct DiscoveredWallet {
    pub address: String,
    pub chain: Chain,
    pub tx_hash: String,
    pub amount_usdc: f64,
    pub counterparty: String,
    pub block_number: u64,
}

impl X402Scanner {
    pub fn new(rpc_url: String, poll_interval_ms: u64) -> Self {
        Self {
            rpc_url,
            client: reqwest::Client::new(),
            last_block: 0,
            poll_interval_ms,
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

    async fn get_block_number(&self) -> ThornResult<u64> {
        let result = self.rpc("eth_blockNumber", json!([])).await?;
        let hex = result
            .as_str()
            .ok_or_else(|| ThornError::Chain("invalid block number".into()))?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map_err(|e| ThornError::Chain(e.to_string()))
    }

    pub async fn poll_new_transfers(&mut self) -> ThornResult<Vec<DiscoveredWallet>> {
        let current_block = self.get_block_number().await?;

        if self.last_block == 0 {
            self.last_block = current_block.saturating_sub(100);
            info!(
                from_block = self.last_block,
                current = current_block,
                "x402 scanner initialized, starting from recent blocks"
            );
        }

        if current_block <= self.last_block {
            return Ok(vec![]);
        }

        let from_block = self.last_block + 1;
        let to_block = current_block.min(from_block + 2000);

        let from_hex = format!("0x{:x}", from_block);
        let to_hex = format!("0x{:x}", to_block);

        let logs = self
            .rpc(
                "eth_getLogs",
                json!([{
                    "address": BASE_USDC,
                    "topics": [TRANSFER_TOPIC],
                    "fromBlock": from_hex,
                    "toBlock": to_hex
                }]),
            )
            .await?;

        let logs_arr = logs.as_array().ok_or_else(|| {
            ThornError::Chain("invalid logs response".into())
        })?;

        let mut wallets = Vec::new();

        for log in logs_arr {
            let topics = match log["topics"].as_array() {
                Some(t) if t.len() >= 3 => t,
                _ => continue,
            };

            let data = log["data"].as_str().unwrap_or("0x0");
            let amount_raw =
                u128::from_str_radix(data.trim_start_matches("0x"), 16).unwrap_or(0);
            let amount_usdc = amount_raw as f64 / 1e6;

            if amount_usdc < 0.001 || amount_usdc > 100.0 {
                continue;
            }

            let from_topic = topics[1].as_str().unwrap_or_default();
            let to_topic = topics[2].as_str().unwrap_or_default();

            let from_addr = extract_address(from_topic);
            let to_addr = extract_address(to_topic);

            let tx_hash = log["transactionHash"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let block_hex = log["blockNumber"].as_str().unwrap_or("0x0");
            let block_number =
                u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).unwrap_or(0);

            wallets.push(DiscoveredWallet {
                address: from_addr.clone(),
                chain: Chain::Base,
                tx_hash: tx_hash.clone(),
                amount_usdc,
                counterparty: to_addr.clone(),
                block_number,
            });

            wallets.push(DiscoveredWallet {
                address: to_addr,
                chain: Chain::Base,
                tx_hash,
                amount_usdc,
                counterparty: from_addr,
                block_number,
            });
        }

        self.last_block = to_block;

        if !wallets.is_empty() {
            info!(
                blocks = format!("{}..{}", from_block, to_block),
                transfers = wallets.len() / 2,
                "x402 scanner found USDC transfers"
            );
        }

        Ok(wallets)
    }

    pub fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
    }
}

fn extract_address(topic: &str) -> String {
    if topic.len() >= 42 {
        format!("0x{}", &topic[topic.len() - 40..])
    } else {
        topic.to_string()
    }
}
