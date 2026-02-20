use thorn_core::{AlertEvent, AlertSeverity, ThornError, ThornResult};
use tracing::{info, warn};

pub struct NtfyNotifier {
    client: reqwest::Client,
    server: String,
    topic: String,
}

impl NtfyNotifier {
    pub fn new(topic: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            server: "https://ntfy.sh".to_string(),
            topic,
        }
    }

    pub fn with_server(mut self, server: String) -> Self {
        self.server = server;
        self
    }

    pub async fn send(&self, event: &AlertEvent) -> ThornResult<()> {
        let url = format!("{}/{}", self.server, self.topic);
        let priority = match event.severity {
            AlertSeverity::Critical => "5",
            AlertSeverity::High => "4",
            AlertSeverity::Medium => "3",
            AlertSeverity::Low => "2",
        };
        let tags = match event.severity {
            AlertSeverity::Critical => "rotating_light,skull",
            AlertSeverity::High => "warning",
            AlertSeverity::Medium => "blue_circle",
            AlertSeverity::Low => "information_source",
        };

        let resp = self
            .client
            .post(&url)
            .header("Title", &event.title)
            .header("Priority", priority)
            .header("Tags", tags)
            .body(event.detail.clone())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| ThornError::Notify(e.to_string()))?;

        if resp.status().is_success() {
            info!(topic = %self.topic, event_id = %event.id, "ntfy notification sent");
        } else {
            warn!(
                topic = %self.topic,
                status = %resp.status(),
                "ntfy delivery failed"
            );
        }
        Ok(())
    }
}
