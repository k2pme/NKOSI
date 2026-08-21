use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NkosiConfig {
    pub agent: AgentConfig,
    pub monitors: MonitorConfig,
    pub risk: RiskConfig,
    pub quarantine: QuarantineConfig,
    pub threat_intel: ThreatIntelConfig,
    pub logging: LoggingConfig,
    pub notifications: NotificationConfig,
}

impl Default for NkosiConfig {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            monitors: MonitorConfig::default(),
            risk: RiskConfig::default(),
            quarantine: QuarantineConfig::default(),
            threat_intel: ThreatIntelConfig::default(),
            logging: LoggingConfig::default(),
            notifications: NotificationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub name: String,
    pub db_path: PathBuf,
    pub log_path: PathBuf,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            name: "nkosi-agent".to_string(),
            db_path: PathBuf::from("/var/lib/nkosi/nkosi.db"),
            log_path: PathBuf::from("/var/log/nkosi/agent.log"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorConfig {
    pub watched_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
    pub process_monitor_enabled: bool,
    pub network_monitor_enabled: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            watched_paths: vec![
                PathBuf::from("/home"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/tmp"),
                PathBuf::from("/etc/cron.d"),
                PathBuf::from("/etc/cron.daily"),
                PathBuf::from("/etc/cron.hourly"),
                PathBuf::from("/etc/cron.weekly"),
                PathBuf::from("/etc/cron.monthly"),
                PathBuf::from("/etc/systemd/system"),
                PathBuf::from("/etc/init.d"),
                PathBuf::from("/root/.config/autostart"),
                PathBuf::from("/home/*/.config/autostart"),
            ],
            excluded_paths: vec![PathBuf::from("/home/*/.cache"), PathBuf::from("/proc"), PathBuf::from("/sys")],
            process_monitor_enabled: true,
            network_monitor_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskConfig {
    pub low_threshold: u32,
    pub suspicious_threshold: u32,
    pub malicious_threshold: u32,
    pub weights: RiskWeights,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            low_threshold: 30,
            suspicious_threshold: 70,
            malicious_threshold: 70,
            weights: RiskWeights::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskWeights {
    pub hash: u32,
    pub yara: u32,
    pub static_analysis: u32,
    pub behavior: u32,
    pub network: u32,
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            hash: 80,
            yara: 40,
            static_analysis: 20,
            behavior: 30,
            network: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QuarantineConfig {
    pub path: PathBuf,
    pub remove_permissions: bool,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/nkosi/quarantine"),
            remove_permissions: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThreatIntelConfig {
    pub update_interval_hours: u32,
    pub sources: Vec<TiSource>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            update_interval_hours: 6,
            sources: vec![
                TiSource { name: "MalwareBazaar".to_string(), url: "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(), enabled: true },
                TiSource { name: "ThreatFox".to_string(), url: "https://threatfox.abuse.ch/export/csv/recent/".to_string(), enabled: true },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TiSource {
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

impl Default for TiSource {
    fn default() -> Self {
        Self { name: String::new(), url: String::new(), enabled: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: PathBuf,
    pub max_size_mb: u32,
    pub retention_days: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_path: PathBuf::from("/var/log/nkosi/agent.log"),
            max_size_mb: 100,
            retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub min_level: String,
    pub email: Option<EmailNotificationConfig>,
    pub webhook: Option<Vec<WebhookNotificationConfig>>,
    pub syslog: Option<SyslogNotificationConfig>,
    pub console: Option<ConsoleNotificationConfig>,
    pub telegram: Option<TelegramNotificationConfig>,
    pub sms: Option<SmsNotificationConfig>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_level: "warning".to_string(),
            email: None,
            webhook: None,
            syslog: None,
            console: Some(ConsoleNotificationConfig { colored: true }),
            telegram: None,
            sms: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailNotificationConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub use_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookNotificationConfig {
    pub name: String,
    pub url: String,
    pub headers: Option<HashMap<String, String>>,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogNotificationConfig {
    pub facility: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleNotificationConfig {
    pub colored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramNotificationConfig {
    pub bot_token: String,
    pub chat_id: String,
    pub parse_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsNotificationConfig {
    pub provider: String,
    pub account_sid: String,
    pub auth_token: String,
    pub from_number: String,
    pub to_numbers: Vec<String>,
    pub signalwire_host: Option<String>,
}

impl NkosiConfig {
    pub fn load(path: &str) -> Result<Self, crate::error::NkosiError> {
        let content = std::fs::read_to_string(path)?;
        let config: NkosiConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<(), crate::error::NkosiError> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
