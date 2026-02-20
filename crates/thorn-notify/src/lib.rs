pub mod webhook;
pub mod ntfy;

use thorn_core::{AlertEvent, ThornResult};

pub struct Notifier {
    webhook: Option<webhook::WebhookNotifier>,
    ntfy: Option<ntfy::NtfyNotifier>,
}

impl Notifier {
    pub fn new(
        webhook_urls: Vec<String>,
        ntfy_topic: Option<String>,
        ntfy_server: Option<String>,
    ) -> Self {
        let webhook = if webhook_urls.is_empty() {
            None
        } else {
            Some(webhook::WebhookNotifier::new(webhook_urls))
        };

        let ntfy = ntfy_topic.map(|topic| {
            let n = ntfy::NtfyNotifier::new(topic);
            match ntfy_server {
                Some(server) => n.with_server(server),
                None => n,
            }
        });

        Self { webhook, ntfy }
    }

    pub fn noop() -> Self {
        Self {
            webhook: None,
            ntfy: None,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.webhook.is_some() || self.ntfy.is_some()
    }

    pub async fn send(&self, event: &AlertEvent) -> ThornResult<()> {
        if let Some(ref wh) = self.webhook {
            wh.send(event).await?;
        }
        if let Some(ref n) = self.ntfy {
            n.send(event).await?;
        }
        Ok(())
    }
}
