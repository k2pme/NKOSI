use async_trait::async_trait;
use crate::trait_notif::Notifier;
use crate::types::{Alert, AlertLevel, EmailConfig};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

pub struct EmailNotifier {
    config: EmailConfig,
    min_level: AlertLevel,
}

impl EmailNotifier {
    pub fn new(config: EmailConfig, min_level: AlertLevel) -> anyhow::Result<Self> {
        Ok(Self { config, min_level })
    }

    fn create_email(&self, alert: &Alert) -> anyhow::Result<Message> {
        let level_str = match alert.level {
            AlertLevel::Info => "INFO",
            AlertLevel::Warning => "WARNING",
            AlertLevel::Critical => "CRITICAL",
            AlertLevel::Emergency => "EMERGENCY",
        };

        let subject = format!(
            "[NKOSI {}] {}",
            level_str, alert.title
        );

        let body = format!(
            "NKOSI Security Alert\n\n\
             Level: {}\n\
             Time: {}\n\
             Title: {}\n\n\
             Message:\n{}\n\n\
             {}",
            level_str,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            alert.title,
            alert.message,
            if let Some(details) = &alert.details {
                format!("Details:\n{:#?}", details)
            } else {
                String::new()
            }
        );

        let email = Message::builder()
            .from(self.config.from.parse()?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)?;

        Ok(email)
    }

    fn send_sync(&self, alert: &Alert) -> anyhow::Result<()> {
        let email = self.create_email(alert)?;
        
        let credentials = Credentials::new(
            self.config.username.clone(),
            self.config.password.clone(),
        );

        let mailer = SmtpTransport::relay(&self.config.smtp_host)?
            .port(self.config.smtp_port)
            .credentials(credentials)
            .build();

        mailer.send(&email)?;
        
        Ok(())
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    async fn send(&self, alert: &Alert) -> anyhow::Result<()> {
        let config = self.config.clone();
        let alert_clone = alert.clone();
        
        tokio::task::spawn_blocking(move || {
            let notifier = EmailNotifier {
                config,
                min_level: AlertLevel::Info,
            };
            notifier.send_sync(&alert_clone)
        })
        .await?
    }

    fn name(&self) -> &str {
        "email"
    }

    fn min_level(&self) -> AlertLevel {
        self.min_level.clone()
    }
}
