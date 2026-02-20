use thorn_core::{ThornError, ThornResult};

pub struct DomainMonitor {
    client: reqwest::Client,
}

impl DomainMonitor {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn check_domain_status(&self, domain: &str) -> ThornResult<DomainStatus> {
        let rdap_url = format!("https://rdap.org/domain/{}", domain);
        let resp = self
            .client
            .get(&rdap_url)
            .send()
            .await
            .map_err(|e| ThornError::Capture(e.to_string()))?;

        if resp.status() == 404 {
            return Ok(DomainStatus::Available);
        }

        if !resp.status().is_success() {
            return Ok(DomainStatus::Unknown);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ThornError::Capture(e.to_string()))?;

        let events = body["events"].as_array();
        let expiry = events.and_then(|evts| {
            evts.iter().find_map(|e| {
                if e["eventAction"].as_str() == Some("expiration") {
                    e["eventDate"].as_str().and_then(|d| {
                        chrono::DateTime::parse_from_rfc3339(d)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                    })
                } else {
                    None
                }
            })
        });

        match expiry {
            Some(exp) => {
                let now = chrono::Utc::now();
                let days_until = (exp - now).num_days();
                if days_until < 0 {
                    Ok(DomainStatus::Expired)
                } else if days_until < 30 {
                    Ok(DomainStatus::ExpiringSoon {
                        days_remaining: days_until as u32,
                        expiry: exp,
                    })
                } else {
                    Ok(DomainStatus::Registered {
                        expiry: exp,
                    })
                }
            }
            None => Ok(DomainStatus::Registered {
                expiry: chrono::Utc::now(),
            }),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum DomainStatus {
    Available,
    Registered { expiry: chrono::DateTime<chrono::Utc> },
    ExpiringSoon { days_remaining: u32, expiry: chrono::DateTime<chrono::Utc> },
    Expired,
    Unknown,
}
