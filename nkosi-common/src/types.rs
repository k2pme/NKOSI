use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    FileCreated,
    FileModified,
    FileDeleted,
    ProcessStarted,
    ProcessExited,
    NetworkConnection,
    NetworkBlocked,
    Detection,
    ResponseAction,
    ScanStarted,
    ScanCompleted,
    ThreatIntelUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Clean,
    Low,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseAction {
    Allow,
    Alert,
    Kill,
    Block,
    Quarantine,
    Restore,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionEngine {
    Hash,
    Yara,
    StaticAnalysis,
    Behavior,
    Network,
    ThreatIntel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IndicatorType {
    Sha256,
    Sha1,
    Md5,
    Ip,
    Domain,
    Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub source_module: String,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub user: Option<String>,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub domain: Option<String>,
    pub incident_id: Option<Uuid>,
    pub severity: Severity,
    pub score: Option<u32>,
    pub action: Option<ResponseAction>,
    pub result: Option<String>,
    pub agent_id: Option<String>,
    pub agent_host: Option<String>,
}

impl Event {
    pub fn new(event_type: EventType, source_module: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            source_module: source_module.to_string(),
            pid: None,
            ppid: None,
            user: None,
            file_path: None,
            file_hash: None,
            remote_ip: None,
            remote_port: None,
            domain: None,
            incident_id: None,
            severity: Severity::Info,
            score: None,
            action: None,
            result: None,
            agent_id: None,
            agent_host: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub id: Uuid,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub malware_family: Option<String>,
    pub confidence: f32,
    pub severity: Severity,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub tags: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: Uuid,
    pub event_id: Uuid,
    pub incident_id: Option<Uuid>,
    pub detection_engine: DetectionEngine,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub confidence: f32,
    pub score_contribution: u32,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuarantineStatus {
    Quarantined,
    Restored,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: Uuid,
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub reason: String,
    pub score: u32,
    pub quarantined_at: DateTime<Utc>,
    pub restored_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub status: QuarantineStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    File,
    Directory,
    Quick,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub scan_type: ScanType,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub files_scanned: u32,
    pub threats_found: u32,
    pub suspicious_found: u32,
    pub status: ScanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    Open,
    Investigating,
    Resolved,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: IncidentStatus,
    pub global_score: u32,
    pub summary: Option<String>,
}

// ── AC-15: Agent health / degraded mode ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentHealthStatus {
    Running,
    Degraded,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleHealth {
    pub name: String,
    pub status: ModuleStatus,
    pub message: Option<String>,
    pub since: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModuleStatus {
    Ok,
    Failed,
    Disabled,
}

// F2.11: Console centralisée — Agent tracking

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Online,
    Offline,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub hostname: String,
    pub ip_address: String,
    pub os_version: String,
    pub nkosi_version: String,
    pub agent_name: String,
    pub status: AgentStatus,
    pub last_seen: DateTime<Utc>,
    pub registered_at: DateTime<Utc>,
    pub events_count: u32,
    pub threats_count: u32,
    pub score: u32,
}
