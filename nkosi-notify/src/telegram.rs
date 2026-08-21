use async_trait::async_trait;
use crate::trait_notif::Notifier;
use crate::types::{Alert, AlertLevel, TelegramConfig};
use reqwest::Client;
use serde_json::json;

pub struct TelegramNotifier {
    config: TelegramConfig,
    min_level: AlertLevel,
    client: Client,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig, min_level: AlertLevel) -> Self {
        Self {
            config,
            min_level,
            client: Client::new(),
        }
    }

    fn format_message(&self, alert: &Alert) -> String {
        let emoji = match alert.level {
            AlertLevel::Info => "ℹ️",
            AlertLevel::Warning => "⚠️",
            AlertLevel::Critical => "🚨",
            AlertLevel::Emergency => "🔥",
        };

        let mut msg = format!(
            "{} *NKOSI Security Alert*\n\n\
             *Level:* {:?}\n\
             *Title:* {}\n\
             *Time:* {}\n\
             *Source:* {}\n\n\
             {}",
            emoji,
            alert.level,
            alert.title,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            alert.source,
            alert.message,
        );

        if let Some(details) = &alert.details {
            if let Some(path) = &details.file_path {
                msg.push_str(&format!("\n📁 File: `{}`", path));
            }
            if let Some(pid) = &details.pid {
                msg.push_str(&format!("\n🔢 PID: {}", pid));
            }
            if let Some(score) = &details.score {
                msg.push_str(&format!("\n📊 Score: {}/100", score));
            }
            if let Some(action) = &details.action_taken {
                msg.push_str(&format!("\n⚡ Action: {}", action));
            }
        }

        msg
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    async fn send(&self, alert: &Alert) -> anyhow::Result<()> {
        let message = self.format_message(alert);
        let parse_mode = if self.config.parse_mode.is_empty() {
            "Markdown"
        } else {
            &self.config.parse_mode
        };

        let payload = json!({
            "chat_id": self.config.chat_id,
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": true,
        });

        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.config.bot_token
        );

        let response = self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Telegram API error: {}", body));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "telegram"
    }

    fn min_level(&self) -> AlertLevel {
        self.min_level.clone()
    }
}
