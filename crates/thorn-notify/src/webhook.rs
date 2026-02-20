use thorn_core::{AlertEvent, ThornError, ThornResult};
use tracing::{info, warn};

pub struct WebhookNotifier {
    client: reqwest::Client,
    urls: Vec<String>,
}

impl WebhookNotifier {
    pub fn new(urls: Vec<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            urls,
        }
    }

    pub async fn send(&self, event: &AlertEvent) -> ThornResult<()> {
        let payload = serde_json::to_value(event).map_err(|e| ThornError::Notify(e.to_string()))?;

        for url in &self.urls {
            match self.post_webhook(url, &payload).await {
                Ok(_) => info!(url = %url, event_id = %event.id, "webhook delivered"),
                Err(e) => warn!(url = %url, error = %e, "webhook delivery failed"),
            }
        }
        Ok(())
    }

    async fn post_webhook(&self, url: &str, payload: &serde_json::Value) -> ThornResult<()> {
        let is_slack = url.contains("hooks.slack.com");

        let body = if is_slack {
            self.format_slack(payload)
        } else {
            payload.clone()
        };

        let resp = self
            .client
            .post(url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| ThornError::Notify(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ThornError::Notify(format!(
                "webhook returned {}",
                resp.status()
            )));
        }
        Ok(())
    }

    fn format_slack(&self, event: &serde_json::Value) -> serde_json::Value {
        let severity = event["severity"].as_str().unwrap_or("Unknown");
        let title = event["title"].as_str().unwrap_or("Thorn Alert");
        let detail = event["detail"].as_str().unwrap_or("");
        let emoji = match severity {
            "Critical" => ":rotating_light:",
            "High" => ":warning:",
            "Medium" => ":large_blue_diamond:",
            _ => ":information_source:",
        };

        serde_json::json!({
            "text": format!("{} *[{}]* {}\n{}", emoji, severity, title, detail),
            "unfurl_links": false
        })
    }
}
