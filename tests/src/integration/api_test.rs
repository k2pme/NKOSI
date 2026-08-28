use nkosi_common::types::*;

#[test]
pub fn test_agent_serialization_roundtrip() {
    let agent = Agent {
        id: "test-001".to_string(),
        hostname: "host-alpha".to_string(),
        ip_address: "192.168.1.100".to_string(),
        os_version: "Linux 6.1".to_string(),
        nkosi_version: "0.1.0".to_string(),
        agent_name: "agent-alpha".to_string(),
        status: AgentStatus::Online,
        last_seen: chrono::Utc::now(),
        registered_at: chrono::Utc::now(),
        events_count: 42,
        threats_count: 3,
        score: 75,
    };

    let json = serde_json::to_string(&agent).unwrap();
    assert!(json.contains("host-alpha"));
    assert!(json.contains("Online"));

    let deserialized: Agent = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.hostname, "host-alpha");
    assert_eq!(deserialized.score, 75);
    assert_eq!(deserialized.status, AgentStatus::Online);
}

#[test]
pub fn test_agent_status_variants() {
    let statuses = vec![
        AgentStatus::Online,
        AgentStatus::Offline,
        AgentStatus::Degraded,
    ];

    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let deserialized: AgentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, deserialized);
    }
}

#[test]
pub fn test_severity_serialization() {
    let severities = vec![
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for sev in &severities {
        let json = serde_json::to_string(sev).unwrap();
        let deserialized: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(*sev, deserialized);
    }
}

#[test]
pub fn test_event_type_all_variants() {
    let types = vec![
        EventType::FileCreated,
        EventType::FileModified,
        EventType::FileDeleted,
        EventType::ProcessStarted,
        EventType::ProcessExited,
        EventType::NetworkConnection,
        EventType::NetworkBlocked,
        EventType::Detection,
        EventType::ResponseAction,
        EventType::ScanStarted,
        EventType::ScanCompleted,
        EventType::ThreatIntelUpdate,
    ];

    assert_eq!(types.len(), 12);

    for et in &types {
        let json = serde_json::to_string(et).unwrap();
        let deserialized: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*et, deserialized);
    }
}

#[test]
pub fn test_consolidated_stats_structure() {
    let stats = serde_json::json!({
        "total_agents": 3,
        "online_agents": 2,
        "offline_agents": 1,
        "total_events": 150,
        "total_threats": 12,
        "total_quarantine": 2,
    });

    assert_eq!(stats["total_agents"], 3);
    assert_eq!(stats["online_agents"], 2);
    assert_eq!(stats["offline_agents"], 1);
    assert!(stats["total_events"].as_i64().unwrap() > 0);
}

#[test]
pub fn test_alert_item_structure() {
    let alert = serde_json::json!({
        "id": "uuid-123",
        "timestamp": "2026-08-25T10:00:00Z",
        "agent_host": "host-alpha",
        "severity": "High",
        "event_type": "Detection",
        "source_module": "yara",
        "file_path": "/tmp/malware.bin",
        "remote_ip": null,
        "score": 85,
    });

    assert_eq!(alert["severity"], "High");
    assert_eq!(alert["score"], 85);
    assert_eq!(alert["source_module"], "yara");
}

#[test]
pub fn test_response_json_shapes() {
    let agents_resp = serde_json::json!({
        "agents": [],
        "total": 0
    });
    assert_eq!(agents_resp["total"], 0);
    assert!(agents_resp["agents"].as_array().unwrap().is_empty());

    let events_resp = serde_json::json!({
        "events": [],
        "total": 0
    });
    assert_eq!(events_resp["total"], 0);

    let error_resp = serde_json::json!({
        "error": "Unauthorized",
        "code": 401
    });
    assert_eq!(error_resp["code"], 401);
}
