use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub level: AlertLevel,
    pub title: String,
    pub message: String,
    pub source: String,
    pub details: Option<AlertDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDetails {
    pub file_path: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub score: Option<u32>,
    pub detection_engine: Option<String>,
    pub threat_type: Option<String>,
    pub action_taken: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyConfig {
    pub enabled: bool,
    pub email: Option<EmailConfig>,
    pub webhook: Option<Vec<WebhookConfig>>,
    pub syslog: Option<SyslogConfig>,
    pub console: Option<ConsoleConfig>,
    pub telegram: Option<TelegramConfig>,
    pub sms: Option<SmsConfig>,
    pub min_level: AlertLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub use_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub format: WebhookFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WebhookFormat {
    Json,
    Slack,
    Discord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    pub facility: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleConfig {
    pub colored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
    pub parse_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    pub provider: String,
    pub account_sid: String,
    pub auth_token: String,
    pub from_number: String,
    pub to_numbers: Vec<String>,
    pub signalwire_host: Option<String>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            email: None,
            webhook: None,
            syslog: None,
            console: Some(ConsoleConfig { colored: true }),
            telegram: None,
            sms: None,
            min_level: AlertLevel::Warning,
        }
    }
}
