use thorn_core::{AutomatonProfile, Chain, ThornResult, WalletInfo, X402Transaction};

pub struct WalletTracker {
    rpc_url: String,
    chain: Chain,
}

impl WalletTracker {
    pub fn new(rpc_url: String, chain: Chain) -> Self {
        Self { rpc_url, chain }
    }

    pub async fn get_wallet_info(&self, _address: &str) -> ThornResult<WalletInfo> {
        todo!()
    }

    pub async fn get_x402_transactions(&self, _address: &str) -> ThornResult<Vec<X402Transaction>> {
        todo!()
    }

    pub async fn trace_funding_chain(&self, _address: &str) -> ThornResult<Vec<String>> {
        todo!()
    }

    pub async fn build_automaton_profile(
        &self,
        _wallet_address: &str,
    ) -> ThornResult<AutomatonProfile> {
        todo!()
    }
}
