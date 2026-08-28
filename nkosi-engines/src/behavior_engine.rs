use nkosi_common::types::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct BehaviorEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub details: String,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub struct ProcessBehavior {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub executable: String,
    pub events: Vec<BehaviorEvent>,
    pub risk_score: u32,
}

pub struct BehaviorEngine {
    process_behaviors: Arc<RwLock<HashMap<u32, ProcessBehavior>>>,
    window_size_secs: u64,
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BehaviorEngine {
    pub fn new() -> Self {
        Self {
            process_behaviors: Arc::new(RwLock::new(HashMap::new())),
            window_size_secs: 300, // 5 minutes window
        }
    }

    pub async fn record_event(
        &self,
        pid: u32,
        ppid: Option<u32>,
        executable: &str,
        event_type: &str,
        details: &str,
        severity: Severity,
    ) {
        let mut behaviors = self.process_behaviors.write().await;
        
        let behavior = behaviors.entry(pid).or_insert_with(|| ProcessBehavior {
            pid,
            ppid,
            executable: executable.to_string(),
            events: Vec::new(),
            risk_score: 0,
        });

        let event = BehaviorEvent {
            timestamp: chrono::Utc::now(),
            event_type: event_type.to_string(),
            details: details.to_string(),
            severity,
        };

        behavior.events.push(event);
        behavior.risk_score = self.calculate_process_risk(behavior);

        debug!(
            "Recorded behavior event for PID {}: {} - {} (score: {})",
            pid, event_type, details, behavior.risk_score
        );
    }

    pub async fn check_file_access(&self, pid: u32, path: &Path) -> Option<Detection> {
        let behaviors = self.process_behaviors.read().await;
        
        if let Some(behavior) = behaviors.get(&pid) {
            let path_str = path.to_string_lossy();
            
            // Check for suspicious file access patterns
            if path_str.contains("/etc/shadow") || path_str.contains("/etc/passwd") {
                return Some(Detection {
                    id: uuid::Uuid::new_v4(),
                    event_id: uuid::Uuid::new_v4(),
                    incident_id: None,
                    detection_engine: DetectionEngine::Behavior,
                    rule_id: Some("BEHAVIOR-001".to_string()),
                    rule_name: Some("Sensitive File Access".to_string()),
                    confidence: 0.7,
                    score_contribution: 30,
                    details: Some(format!(
                        "Process {} (PID: {}) accessed sensitive file: {}",
                        behavior.executable, pid, path_str
                    )),
                });
            }

            if path_str.contains("/etc/sudoers") || path_str.contains("/etc/sudoers.d") {
                return Some(Detection {
                    id: uuid::Uuid::new_v4(),
                    event_id: uuid::Uuid::new_v4(),
                    incident_id: None,
                    detection_engine: DetectionEngine::Behavior,
                    rule_id: Some("BEHAVIOR-002".to_string()),
                    rule_name: Some("Sudoers File Access".to_string()),
                    confidence: 0.8,
                    score_contribution: 40,
                    details: Some(format!(
                        "Process {} (PID: {}) accessed sudoers: {}",
                        behavior.executable, pid, path_str
                    )),
                });
            }

            if path_str.starts_with("/home") && path_str.contains(".ssh") {
                return Some(Detection {
                    id: uuid::Uuid::new_v4(),
                    event_id: uuid::Uuid::new_v4(),
                    incident_id: None,
                    detection_engine: DetectionEngine::Behavior,
                    rule_id: Some("BEHAVIOR-003".to_string()),
                    rule_name: Some("SSH Directory Access".to_string()),
                    confidence: 0.6,
                    score_contribution: 25,
                    details: Some(format!(
                        "Process {} (PID: {}) accessed SSH directory: {}",
                        behavior.executable, pid, path_str
                    )),
                });
            }
        }

        None
    }

    pub async fn check_network_activity(&self, pid: u32, remote_addr: &str) -> Option<Detection> {
        let behaviors = self.process_behaviors.read().await;
        
        if let Some(behavior) = behaviors.get(&pid) {
            // Check for suspicious network patterns
            let network_events: Vec<_> = behavior.events.iter()
                .filter(|e| e.event_type == "network_connection")
                .collect();

            if network_events.len() > 10 {
                return Some(Detection {
                    id: uuid::Uuid::new_v4(),
                    event_id: uuid::Uuid::new_v4(),
                    incident_id: None,
                    detection_engine: DetectionEngine::Behavior,
                    rule_id: Some("BEHAVIOR-004".to_string()),
                    rule_name: Some("High Network Activity".to_string()),
                    confidence: 0.6,
                    score_contribution: 20,
                    details: Some(format!(
                        "Process {} (PID: {}) made {} network connections",
                        behavior.executable, pid, network_events.len()
                    )),
                });
            }

            if let Some((_ip, port_str)) = remote_addr.rsplit_once(':')
                && let Ok(port) = port_str.parse::<u16>()
                && (port == 4444 || port == 5555 || port == 6666 || port == 7777)
            {
                return Some(Detection {
                    id: uuid::Uuid::new_v4(),
                    event_id: uuid::Uuid::new_v4(),
                    incident_id: None,
                    detection_engine: DetectionEngine::Behavior,
                    rule_id: Some("BEHAVIOR-005".to_string()),
                    rule_name: Some("Suspicious Port Connection".to_string()),
                    confidence: 0.8,
                    score_contribution: 50,
                    details: Some(format!(
                        "Process {} (PID: {}) connected to suspicious port {}",
                        behavior.executable, pid, port
                    )),
                });
            }
        }

        None
    }

    pub async fn get_process_risk_score(&self, pid: u32) -> u32 {
        let behaviors = self.process_behaviors.read().await;
        
        if let Some(behavior) = behaviors.get(&pid) {
            behavior.risk_score
        } else {
            0
        }
    }

    pub async fn get_suspicious_processes(&self) -> Vec<ProcessBehavior> {
        let behaviors = self.process_behaviors.read().await;
        
        behaviors.values()
            .filter(|b| b.risk_score >= 30)
            .cloned()
            .collect()
    }

    fn calculate_process_risk(&self, behavior: &ProcessBehavior) -> u32 {
        let mut score = 0;

        // Count events by severity
        for event in &behavior.events {
            match event.severity {
                Severity::Critical => score += 30,
                Severity::High => score += 20,
                Severity::Medium => score += 10,
                Severity::Low => score += 5,
                Severity::Info => score += 1,
            }
        }

        // Check for multiple event types
        let event_types: Vec<_> = behavior.events.iter()
            .map(|e| &e.event_type)
            .collect();
        let unique_types: Vec<_> = event_types.into_iter().collect();
        
        if unique_types.len() > 3 {
            score += 20;
        }

        score.min(100)
    }

    pub async fn cleanup_old_events(&self) {
        let mut behaviors = self.process_behaviors.write().await;
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(self.window_size_secs as i64);

        for behavior in behaviors.values_mut() {
            behavior.events.retain(|e| e.timestamp > cutoff);
        }

        // Remove processes with no events
        behaviors.retain(|_, b| !b.events.is_empty());
    }
}
