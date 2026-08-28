use std::collections::HashMap;
use nkosi_common::types::*;

pub struct HealthTracker {
    modules: HashMap<String, ModuleHealth>,
}

impl HealthTracker {
    pub fn new() -> Self {
        Self { modules: HashMap::new() }
    }

    pub fn record_ok(&mut self, name: &str) {
        self.modules.insert(name.to_string(), ModuleHealth {
            name: name.to_string(),
            status: ModuleStatus::Ok,
            message: None,
            since: chrono::Utc::now(),
        });
    }

    pub fn record_failed(&mut self, name: &str, reason: &str) {
        self.modules.insert(name.to_string(), ModuleHealth {
            name: name.to_string(),
            status: ModuleStatus::Failed,
            message: Some(reason.to_string()),
            since: chrono::Utc::now(),
        });
    }

    pub fn record_disabled(&mut self, name: &str) {
        self.modules.insert(name.to_string(), ModuleHealth {
            name: name.to_string(),
            status: ModuleStatus::Disabled,
            message: None,
            since: chrono::Utc::now(),
        });
    }

    pub fn agent_status(&self) -> AgentHealthStatus {
        if self.modules.values().any(|m| m.status == ModuleStatus::Failed) {
            AgentHealthStatus::Degraded
        } else {
            AgentHealthStatus::Running
        }
    }

    pub fn snapshot(&self) -> Vec<ModuleHealth> {
        self.modules.values().cloned().collect()
    }
}

#[test]
pub fn test_health_all_ok() {
    let mut tracker = HealthTracker::new();
    tracker.record_ok("database");
    tracker.record_ok("ti_service");
    tracker.record_ok("filesystem_monitor");

    assert_eq!(tracker.agent_status(), AgentHealthStatus::Running);
    assert_eq!(tracker.snapshot().len(), 3);
}

#[test]
pub fn test_health_one_failed() {
    let mut tracker = HealthTracker::new();
    tracker.record_ok("database");
    tracker.record_failed("ti_service", "connection timeout");

    assert_eq!(tracker.agent_status(), AgentHealthStatus::Degraded);
}

#[test]
pub fn test_health_disabled_module() {
    let mut tracker = HealthTracker::new();
    tracker.record_ok("database");
    tracker.record_disabled("process_monitor");

    // Disabled should not cause degraded
    assert_eq!(tracker.agent_status(), AgentHealthStatus::Running);
}

#[test]
pub fn test_health_multiple_failures() {
    let mut tracker = HealthTracker::new();
    tracker.record_failed("database", "locked");
    tracker.record_failed("ti_service", "timeout");
    tracker.record_ok("filesystem_monitor");

    assert_eq!(tracker.agent_status(), AgentHealthStatus::Degraded);

    let snapshot = tracker.snapshot();
    let failed: Vec<_> = snapshot.iter()
        .filter(|m| m.status == ModuleStatus::Failed)
        .collect();
    assert_eq!(failed.len(), 2, "Should have 2 failed modules");
}

#[test]
pub fn test_health_snapshot() {
    let mut tracker = HealthTracker::new();
    tracker.record_ok("database");
    tracker.record_failed("ti_service", "error");

    let snapshot = tracker.snapshot();
    assert_eq!(snapshot.len(), 2);

    let db_health = snapshot.iter().find(|m| m.name == "database").unwrap();
    assert_eq!(db_health.status, ModuleStatus::Ok);

    let ti_health = snapshot.iter().find(|m| m.name == "ti_service").unwrap();
    assert_eq!(ti_health.status, ModuleStatus::Failed);
    assert_eq!(ti_health.message.as_deref(), Some("error"));
}
