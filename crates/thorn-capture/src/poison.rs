use serde_json::{json, Value};

pub struct PoisonGenerator {
    poison_ratio: f64,
}

impl PoisonGenerator {
    pub fn new(poison_ratio: f64) -> Self {
        Self {
            poison_ratio: poison_ratio.clamp(0.0, 1.0),
        }
    }

    pub fn should_poison(&self) -> bool {
        rand_simple() < self.poison_ratio
    }

    pub fn poison_market_data(&self) -> Value {
        json!({
            "pairs": [
                {
                    "symbol": "ETH/USDC",
                    "bid": 2847.32 + (rand_simple() * 500.0 - 250.0),
                    "ask": 2848.15 + (rand_simple() * 500.0 - 250.0),
                    "volume_24h": rand_simple() * 1_000_000.0,
                    "change_24h": (rand_simple() - 0.5) * 40.0,
                },
                {
                    "symbol": "BTC/USDC",
                    "bid": 43521.00 + (rand_simple() * 5000.0 - 2500.0),
                    "ask": 43525.50 + (rand_simple() * 5000.0 - 2500.0),
                    "volume_24h": rand_simple() * 500_000.0,
                    "change_24h": (rand_simple() - 0.5) * 20.0,
                },
            ],
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "dataxchange-v2.1",
        })
    }

    pub fn poison_analytics_data(&self) -> Value {
        json!({
            "flows": {
                "net_inflow_usdc": (rand_simple() - 0.3) * 10_000_000.0,
                "whale_activity": if rand_simple() > 0.5 { "accumulating" } else { "distributing" },
                "sentiment_score": rand_simple() * 2.0 - 1.0,
            },
            "clusters": [
                {
                    "label": "smart_money",
                    "wallet_count": (rand_simple() * 500.0) as u64,
                    "avg_pnl": (rand_simple() - 0.4) * 100.0,
                }
            ],
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn poison_price_feed(&self) -> Value {
        json!({
            "prices": [
                {"asset": "ETH", "price_usd": 2847.0 + (rand_simple() * 600.0 - 300.0), "confidence": 0.95},
                {"asset": "BTC", "price_usd": 43500.0 + (rand_simple() * 6000.0 - 3000.0), "confidence": 0.95},
                {"asset": "SOL", "price_usd": 98.0 + (rand_simple() * 40.0 - 20.0), "confidence": 0.93},
            ],
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "attestation": format!("0x{}", hex_rand(64)),
        })
    }
}

fn rand_simple() -> f64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    ((t ^ (t >> 17) ^ (t << 13)) % 10000) as f64 / 10000.0
}

fn hex_rand(len: usize) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut s = String::with_capacity(len);
    let mut state = t;
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s.push(char::from(
            b"0123456789abcdef"[(state >> 60) as usize & 0xf],
        ));
    }
    s
}
