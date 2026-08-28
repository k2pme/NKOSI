use crate::console::ConsoleNotifier;
use crate::email::EmailNotifier;
use crate::sms::SmsNotifier;
use crate::syslog::SyslogNotifier;
use crate::telegram::TelegramNotifier;
use crate::trait_notif::Notifier;
use crate::types::{Alert, AlertLevel, NotifyConfig};
use crate::webhook::WebhookNotifier;
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct NotifyManager {
    notifiers: Vec<Arc<dyn Notifier>>,
    config: NotifyConfig,
}

impl NotifyManager {
    pub fn new(config: NotifyConfig) -> Self {
        let mut manager = Self {
            notifiers: Vec::new(),
            config: config.clone(),
        };

        if !config.enabled {
            info!("Notifications disabled");
            return manager;
        }

        // Console notifier (always available)
        if let Some(console_config) = &config.console {
            manager.notifiers.push(Arc::new(ConsoleNotifier::new(
                console_config.colored,
                config.min_level.clone(),
            )));
        }

        // Email notifier
        if let Some(email_config) = &config.email {
            match EmailNotifier::new(email_config.clone(), config.min_level.clone()) {
                Ok(notifier) => {
                    manager.notifiers.push(Arc::new(notifier));
                    info!(
                        "Email notifier configured: {}:{}",
                        email_config.smtp_host, email_config.smtp_port
                    );
                }
                Err(e) => warn!("Failed to configure email notifier: {}", e),
            }
        }

        // Webhook notifiers
        if let Some(webhook_configs) = &config.webhook {
            for wh_config in webhook_configs {
                let notifier = WebhookNotifier::new(wh_config.clone(), config.min_level.clone());
                manager.notifiers.push(Arc::new(notifier));
                info!("Webhook notifier configured: {}", wh_config.name);
            }
        }

        // Syslog notifier
        if let Some(syslog_config) = &config.syslog {
            match SyslogNotifier::new(syslog_config.clone(), config.min_level.clone()) {
                Ok(notifier) => {
                    manager.notifiers.push(Arc::new(notifier));
                    info!("Syslog notifier configured");
                }
                Err(e) => warn!("Failed to configure syslog notifier: {}", e),
            }
        }

        // Telegram notifier
        if let Some(telegram_config) = &config.telegram {
            let notifier = TelegramNotifier::new(telegram_config.clone(), config.min_level.clone());
            manager.notifiers.push(Arc::new(notifier));
            info!(
                "Telegram notifier configured: chat_id={}",
                telegram_config.chat_id
            );
        }

        // SMS notifier
        if let Some(sms_config) = &config.sms {
            let notifier = SmsNotifier::new(sms_config.clone(), config.min_level.clone());
            manager.notifiers.push(Arc::new(notifier));
            info!(
                "SMS notifier configured: {} numbers",
                sms_config.to_numbers.len()
            );
        }

        info!(
            "NotifyManager initialized with {} notifiers",
            manager.notifiers.len()
        );
        manager
    }

    pub async fn notify(&self, alert: Alert) {
        if !self.config.enabled {
            return;
        }

        if !self.should_notify(&alert.level) {
            return;
        }

        for notifier in &self.notifiers {
            if alert.level >= notifier.min_level() {
                match notifier.send(&alert).await {
                    Ok(_) => {
                        info!("Alert sent via {}: {}", notifier.name(), alert.title);
                    }
                    Err(e) => {
                        error!("Failed to send alert via {}: {}", notifier.name(), e);
                    }
                }
            }
        }
    }

    fn should_notify(&self, level: &AlertLevel) -> bool {
        *level >= self.config.min_level
    }

    pub fn notifiers_count(&self) -> usize {
        self.notifiers.len()
    }
}
