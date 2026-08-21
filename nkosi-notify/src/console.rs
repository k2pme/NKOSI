use async_trait::async_trait;
use crate::trait_notif::Notifier;
use crate::types::{Alert, AlertLevel};

pub struct ConsoleNotifier {
    colored: bool,
    min_level: AlertLevel,
}

impl ConsoleNotifier {
    pub fn new(colored: bool, min_level: AlertLevel) -> Self {
        Self { colored, min_level }
    }

    fn format_alert(&self, alert: &Alert) -> String {
        let level_str = match alert.level {
            AlertLevel::Info => "INFO",
            AlertLevel::Warning => "WARN",
            AlertLevel::Critical => "CRIT",
            AlertLevel::Emergency => "EMER",
        };

        if self.colored {
            let color = match alert.level {
                AlertLevel::Info => "\x1b[36m",      // Cyan
                AlertLevel::Warning => "\x1b[33m",   // Yellow
                AlertLevel::Critical => "\x1b[31m",  // Red
                AlertLevel::Emergency => "\x1b[35m", // Magenta
            };
            let reset = "\x1b[0m";
            
            format!(
                "{}[{} {}]{} {} - {}{}",
                color, level_str, alert.timestamp.format("%Y-%m-%d %H:%M:%S"), reset,
                alert.title, alert.message,
                if let Some(details) = &alert.details {
                    format!("\n  Détails: {:?}", details)
                } else {
                    String::new()
                }
            )
        } else {
            format!(
                "[{} {}] {} - {}{}",
                level_str, alert.timestamp.format("%Y-%m-%d %H:%M:%S"),
                alert.title, alert.message,
                if let Some(details) = &alert.details {
                    format!("\n  Détails: {:?}", details)
                } else {
                    String::new()
                }
            )
        }
    }
}

#[async_trait]
impl Notifier for ConsoleNotifier {
    async fn send(&self, alert: &Alert) -> anyhow::Result<()> {
        let formatted = self.format_alert(alert);
        
        match alert.level {
            AlertLevel::Info => tracing::info!("{}", formatted),
            AlertLevel::Warning => tracing::warn!("{}", formatted),
            AlertLevel::Critical | AlertLevel::Emergency => tracing::error!("{}", formatted),
        }
        
        Ok(())
    }

    fn name(&self) -> &str {
        "console"
    }

    fn min_level(&self) -> AlertLevel {
        self.min_level.clone()
    }
}
