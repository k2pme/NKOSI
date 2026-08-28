use crate::trait_notif::Notifier;
use crate::types::{Alert, AlertLevel, WebhookConfig, WebhookFormat};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

pub struct WebhookNotifier {
    config: WebhookConfig,
    min_level: AlertLevel,
    client: Client,
}

impl WebhookNotifier {
    pub fn new(config: WebhookConfig, min_level: AlertLevel) -> Self {
        Self {
            config,
            min_level,
            client: Client::new(),
        }
    }

    fn format_payload(&self, alert: &Alert) -> serde_json::Value {
        match self.config.format {
            WebhookFormat::Json => {
                json!({
                    "id": alert.id,
                    "timestamp": alert.timestamp.to_rfc3339(),
                    "level": format!("{:?}", alert.level),
                    "title": alert.title,
                    "message": alert.message,
                    "source": alert.source,
                    "details": alert.details
                })
            }
            WebhookFormat::Slack => {
                let color = match alert.level {
                    AlertLevel::Info => "#36a64f",
                    AlertLevel::Warning => "#ff9900",
                    AlertLevel::Critical => "#ff0000",
                    AlertLevel::Emergency => "#9b59b6",
                };

                json!({
                    "attachments": [{
                        "color": color,
                        "title": format!("[{:?}] {}", alert.level, alert.title),
                        "text": alert.message,
                        "fields": [
                            {"title": "Source", "value": alert.source, "short": true},
                            {"title": "Time", "value": alert.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(), "short": true}
                        ],
                        "footer": "NKOSI Security",
                        "ts": alert.timestamp.timestamp()
                    }]
                })
            }
            WebhookFormat::Discord => {
                let color = match alert.level {
                    AlertLevel::Info => 0x36a64f,
                    AlertLevel::Warning => 0xff9900,
                    AlertLevel::Critical => 0xff0000,
                    AlertLevel::Emergency => 0x9b59b6,
                };

                json!({
                    "embeds": [{
                        "title": format!("[{:?}] {}", alert.level, alert.title),
                        "description": alert.message,
                        "color": color,
                        "fields": [
                            {"name": "Source", "value": alert.source, "inline": true},
                            {"name": "Time", "value": alert.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(), "inline": true}
                        ],
                        "footer": {"text": "NKOSI Security"},
                        "timestamp": alert.timestamp.to_rfc3339()
                    }]
                })
            }
        }
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    async fn send(&self, alert: &Alert) -> anyhow::Result<()> {
        let payload = self.format_payload(alert);

        let mut request = self.client.post(&self.config.url).json(&payload);

        if let Some(headers) = &self.config.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Webhook returned status: {}",
                response.status()
            ));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn min_level(&self) -> AlertLevel {
        self.min_level.clone()
    }
}
