use async_trait::async_trait;
use crate::trait_notif::Notifier;
use crate::types::{Alert, AlertLevel, SyslogConfig};

pub struct SyslogNotifier {
    config: SyslogConfig,
    min_level: AlertLevel,
}

impl SyslogNotifier {
    pub fn new(config: SyslogConfig, min_level: AlertLevel) -> anyhow::Result<Self> {
        Ok(Self { config, min_level })
    }

    fn format_message(&self, alert: &Alert) -> String {
        let level_str = match alert.level {
            AlertLevel::Info => "INFO",
            AlertLevel::Warning => "WARNING",
            AlertLevel::Critical => "CRITICAL",
            AlertLevel::Emergency => "EMERGENCY",
        };

        format!(
            "[NKOSI {}] {} - {}{}",
            level_str,
            alert.title,
            alert.message,
            if let Some(details) = &alert.details {
                format!(" | {:?}", details)
            } else {
                String::new()
            }
        )
    }
}

#[async_trait]
impl Notifier for SyslogNotifier {
    async fn send(&self, alert: &Alert) -> anyhow::Result<()> {
        let message = self.format_message(alert);
        
        // Write to syslog using the syslog crate or fallback to logger
        // For now, use tracing which can be configured to write to syslog
        match alert.level {
            AlertLevel::Info => tracing::info!("[SYSLOG] {}", message),
            AlertLevel::Warning => tracing::warn!("[SYSLOG] {}", message),
            AlertLevel::Critical | AlertLevel::Emergency => {
                tracing::error!("[SYSLOG] {}", message)
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "syslog"
    }

    fn min_level(&self) -> AlertLevel {
        self.min_level.clone()
    }
}
