use dashmap::DashMap;
use std::sync::Arc;
use tracing::info;

pub struct DrainEngine {
    price_state: Arc<DashMap<String, WalletPriceState>>,
}

struct WalletPriceState {
    current_price: f64,
    _base_price: f64,
    multiplier: f64,
    max_price: f64,
    requests_served: u64,
    total_drained: f64,
}

impl DrainEngine {
    pub fn new() -> Self {
        Self {
            price_state: Arc::new(DashMap::new()),
        }
    }

    pub fn register_wallet(&self, wallet: &str, base_price: f64, multiplier: f64, max_price: f64) {
        self.price_state.insert(
            wallet.to_string(),
            WalletPriceState {
                current_price: base_price,
                _base_price: base_price,
                multiplier,
                max_price,
                requests_served: 0,
                total_drained: 0.0,
            },
        );
        info!(wallet = %wallet, base = base_price, max = max_price, "drain strategy registered");
    }

    pub fn get_price_for_wallet(&self, wallet: &str) -> Option<f64> {
        self.price_state.get(wallet).map(|s| s.current_price)
    }

    pub fn record_payment(&self, wallet: &str, amount: f64) {
        if let Some(mut state) = self.price_state.get_mut(wallet) {
            state.requests_served += 1;
            state.total_drained += amount;
            state.current_price = (state.current_price * state.multiplier).min(state.max_price);
            info!(
                wallet = %wallet,
                price = state.current_price,
                total = state.total_drained,
                "price escalated"
            );
        }
    }

    pub fn get_drain_stats(&self, wallet: &str) -> Option<(f64, u64, f64)> {
        self.price_state
            .get(wallet)
            .map(|s| (s.current_price, s.requests_served, s.total_drained))
    }

    pub fn total_drained(&self) -> f64 {
        self.price_state.iter().map(|e| e.total_drained).sum()
    }
}
