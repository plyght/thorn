use serde::Deserialize;
use thorn_core::{ThornError, ThornResult};
use tracing::{debug, info, warn};

const OPENX402_DISCOVERY: &str = "https://facilitator.openx402.ai/discovery/resources";
const CDP_BAZAAR_DISCOVERY: &str =
    "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
const OPENX402_WHITELIST: &str = "https://facilitator.openx402.ai/whitelist";
const CRTSH_CONWAY: &str = "https://crt.sh/?q=%.conway.tech&output=json";

pub struct FacilitatorDiscovery {
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct DiscoveredService {
    pub resource_url: String,
    pub pay_to: String,
    pub network: String,
    pub max_amount: String,
    pub description: String,
    pub source: DiscoveryEndpoint,
}

#[derive(Debug, Clone)]
pub enum DiscoveryEndpoint {
    OpenX402,
    CdpBazaar,
}

#[derive(Deserialize)]
struct DiscoveryResponse {
    items: Option<Vec<DiscoveryItem>>,
    resources: Option<Vec<DiscoveryItem>>,
}

#[derive(Deserialize)]
struct DiscoveryItem {
    resource: Option<String>,
    url: Option<String>,
    accepts: Option<Vec<PaymentRequirement>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaymentRequirement {
    pay_to: Option<String>,
    network: Option<String>,
    max_amount_required: Option<String>,
    #[serde(alias = "amount")]
    amount: Option<String>,
    resource: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct WhitelistResponse {
    whitelisted: Option<bool>,
}

impl FacilitatorDiscovery {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent("Mozilla/5.0 (compatible; ThornBot/0.1)")
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn discover_services(&self) -> Vec<DiscoveredService> {
        let mut services = Vec::new();

        match self.query_endpoint(OPENX402_DISCOVERY, DiscoveryEndpoint::OpenX402).await {
            Ok(mut s) => {
                info!(count = s.len(), source = "openx402", "facilitator discovery");
                services.append(&mut s);
            }
            Err(e) => warn!(error = %e, "openx402 discovery failed"),
        }

        match self.query_endpoint(CDP_BAZAAR_DISCOVERY, DiscoveryEndpoint::CdpBazaar).await {
            Ok(mut s) => {
                info!(count = s.len(), source = "cdp_bazaar", "facilitator discovery");
                services.append(&mut s);
            }
            Err(e) => debug!(error = %e, "cdp bazaar discovery failed"),
        }

        services
    }

    async fn query_endpoint(
        &self,
        url: &str,
        source: DiscoveryEndpoint,
    ) -> ThornResult<Vec<DiscoveredService>> {
        let resp = self.client.get(url).send().await?;

        if !resp.status().is_success() {
            return Err(ThornError::Chain(format!(
                "discovery endpoint returned {}",
                resp.status()
            )));
        }

        let body: DiscoveryResponse = resp
            .json()
            .await
            .map_err(|e| ThornError::Chain(e.to_string()))?;

        let items = body.items.or(body.resources).unwrap_or_default();
        let mut services = Vec::new();

        for item in &items {
            let resource_url = item
                .resource
                .as_deref()
                .or(item.url.as_deref())
                .unwrap_or_default()
                .to_string();

            if let Some(accepts) = &item.accepts {
                for req in accepts {
                    if let Some(pay_to) = &req.pay_to {
                        services.push(DiscoveredService {
                            resource_url: req
                                .resource
                                .as_deref()
                                .unwrap_or(&resource_url)
                                .to_string(),
                            pay_to: pay_to.clone(),
                            network: req.network.clone().unwrap_or_default(),
                            max_amount: req
                                .max_amount_required
                                .clone()
                                .or_else(|| req.amount.clone())
                                .unwrap_or_default(),
                            description: req.description.clone().unwrap_or_default(),
                            source: source.clone(),
                        });
                    }
                }
            }
        }

        Ok(services)
    }

    pub async fn check_whitelist(&self, address: &str) -> ThornResult<bool> {
        let url = format!("{}/{}", OPENX402_WHITELIST, address);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ThornError::Chain(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let body: WhitelistResponse = resp
            .json()
            .await
            .map_err(|e| ThornError::Chain(e.to_string()))?;

        Ok(body.whitelisted.unwrap_or(false))
    }

    pub fn extract_pay_to_addresses(services: &[DiscoveredService]) -> Vec<String> {
        let mut addrs: Vec<String> = services
            .iter()
            .map(|s| s.pay_to.to_lowercase())
            .collect();
        addrs.sort();
        addrs.dedup();
        addrs
    }
}

pub struct ConwayEnumerator {
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct ConwaySubdomain {
    pub subdomain: String,
    pub is_sandbox: bool,
}

#[derive(Deserialize)]
struct CrtShEntry {
    common_name: Option<String>,
    name_value: Option<String>,
}

impl ConwayEnumerator {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent("Mozilla/5.0 (compatible; ThornBot/0.1)")
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn enumerate_subdomains(&self) -> ThornResult<Vec<ConwaySubdomain>> {
        let resp = self
            .client
            .get(CRTSH_CONWAY)
            .send()
            .await
            .map_err(|e| ThornError::Chain(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ThornError::Chain(format!(
                "crt.sh returned {}",
                resp.status()
            )));
        }

        let entries: Vec<CrtShEntry> = resp
            .json()
            .await
            .map_err(|e| ThornError::Chain(e.to_string()))?;

        let mut subdomains = std::collections::HashSet::new();
        for entry in &entries {
            let name = entry
                .name_value
                .as_deref()
                .or(entry.common_name.as_deref())
                .unwrap_or_default();

            for line in name.lines() {
                let trimmed = line.trim().to_lowercase();
                if trimmed.ends_with(".conway.tech") && !trimmed.starts_with('*') {
                    subdomains.insert(trimmed);
                }
            }
        }

        let result: Vec<ConwaySubdomain> = subdomains
            .into_iter()
            .map(|s| {
                let is_sandbox = s.ends_with(".life.conway.tech") && s != "life.conway.tech";
                ConwaySubdomain {
                    subdomain: s,
                    is_sandbox,
                }
            })
            .collect();

        info!(
            total = result.len(),
            sandboxes = result.iter().filter(|s| s.is_sandbox).count(),
            "conway subdomain enumeration"
        );

        Ok(result)
    }
}
