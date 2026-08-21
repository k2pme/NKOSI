use async_trait::async_trait;
use crate::trait_notif::Notifier;
use crate::types::{Alert, AlertLevel, SmsConfig};
use reqwest::Client;

pub struct SmsNotifier {
    config: SmsConfig,
    min_level: AlertLevel,
    client: Client,
}

impl SmsNotifier {
    pub fn new(config: SmsConfig, min_level: AlertLevel) -> Self {
        Self {
            config,
            min_level,
            client: Client::new(),
        }
    }

    fn format_message(&self, alert: &Alert) -> String {
        let prefix = match alert.level {
            AlertLevel::Info => "[NKOSI INFO]",
            AlertLevel::Warning => "[NKOSI WARN]",
            AlertLevel::Critical => "[NKOSI CRIT]",
            AlertLevel::Emergency => "[NKOSI EMER]",
        };

        let mut msg = format!(
            "{} {} - {}",
            prefix, alert.title, alert.message,
        );

        if let Some(details) = &alert.details {
            if let Some(score) = &details.score {
                msg.push_str(&format!(" (score: {}/100)", score));
            }
            if let Some(action) = &details.action_taken {
                msg.push_str(&format!(" [{}]", action));
            }
        }

        // SMS max 160 chars
        if msg.len() > 160 {
            msg.truncate(157);
            msg.push_str("...");
        }

        msg
    }

    async fn send_twilio(&self, to: &str, body: &str) -> anyhow::Result<()> {
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.config.account_sid
        );

        let response = self.client
            .post(&url)
            .basic_auth(&self.config.account_sid, Some(&self.config.auth_token))
            .form(&[
                ("To", to),
                ("From", &self.config.from_number),
                ("Body", body),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Twilio API error: {}", err));
        }

        Ok(())
    }

    async fn send_signalwire(&self, to: &str, body: &str) -> anyhow::Result<()> {
        let url = format!(
            "https://{}/api/laml/2010-04-01/Accounts/{}/Messages.json",
            self.config.signalwire_host.as_deref().unwrap_or("signalwire.com"),
            self.config.account_sid
        );

        let response = self.client
            .post(&url)
            .basic_auth(&self.config.account_sid, Some(&self.config.auth_token))
            .form(&[
                ("To", to),
                ("From", &self.config.from_number),
                ("Body", body),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("SignalWire API error: {}", err));
        }

        Ok(())
    }
}

#[async_trait]
impl Notifier for SmsNotifier {
    async fn send(&self, alert: &Alert) -> anyhow::Result<()> {
        let message = self.format_message(alert);

        for number in &self.config.to_numbers {
            let result = if self.config.signalwire_host.is_some() {
                self.send_signalwire(number, &message).await
            } else {
                self.send_twilio(number, &message).await
            };

            if let Err(e) = result {
                tracing::error!("Failed to send SMS to {}: {}", number, e);
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "sms"
    }

    fn min_level(&self) -> AlertLevel {
        self.min_level.clone()
    }
}
