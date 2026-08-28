use tempfile::TempDir;

struct TestDb {
    _tmp: TempDir,
    db: nkosi_db::Database,
}

impl TestDb {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("test.db");
        let db = nkosi_db::Database::new(&db_path).unwrap();
        Self { _tmp: tmp, db }
    }
}

#[test]
pub fn test_db_insert_event() {
    let test = TestDb::new();
    let repo = nkosi_db::EventRepository::new(&test.db);

    let mut event = nkosi_common::types::Event::new(
        nkosi_common::types::EventType::FileCreated,
        "test_monitor",
    );
    event.file_path = Some("/tmp/test.txt".to_string());

    let result = repo.insert(&event);
    assert!(
        result.is_ok(),
        "Event insert should succeed: {:?}",
        result.err()
    );
}

#[test]
pub fn test_db_insert_detection() {
    let test = TestDb::new();
    let event_repo = nkosi_db::EventRepository::new(&test.db);
    let repo = nkosi_db::DetectionRepository::new(&test.db);

    // Insert an event first (FK constraint)
    let event = nkosi_common::types::Event::new(
        nkosi_common::types::EventType::FileCreated,
        "test_monitor",
    );
    event_repo.insert(&event).unwrap();

    let detection = nkosi_common::types::Detection {
        id: uuid::Uuid::new_v4(),
        event_id: event.id,
        incident_id: None,
        detection_engine: nkosi_common::types::DetectionEngine::Yara,
        rule_id: Some("test-rule".to_string()),
        rule_name: Some("Test Rule".to_string()),
        confidence: 0.9,
        score_contribution: 75,
        details: Some("Test detection".to_string()),
    };

    let result = repo.insert(&detection);
    assert!(
        result.is_ok(),
        "Detection insert should succeed: {:?}",
        result.err()
    );
}

#[test]
pub fn test_db_insert_indicator() {
    let test = TestDb::new();
    let repo = nkosi_db::ThreatIndicatorRepository::new(&test.db);

    let indicator = nkosi_common::types::ThreatIndicator {
        id: uuid::Uuid::new_v4(),
        indicator_type: nkosi_common::types::IndicatorType::Sha256,
        value: "abc123def456".to_string(),
        malware_family: Some("TestMalware".to_string()),
        confidence: 0.8,
        severity: nkosi_common::types::Severity::High,
        source: "test".to_string(),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        tags: vec!["test".to_string()],
        enabled: true,
    };

    let result = repo.insert(&indicator);
    assert!(
        result.is_ok(),
        "Indicator insert should succeed: {:?}",
        result.err()
    );

    // Query back
    let found = repo.find_by_value("abc123def456").unwrap();
    assert!(found.is_some(), "Indicator should be found");
}

#[test]
pub fn test_db_insert_quarantine() {
    let test = TestDb::new();
    let repo = nkosi_db::QuarantineRepository::new(&test.db);

    let item = nkosi_common::types::QuarantineItem {
        id: uuid::Uuid::new_v4(),
        original_path: "/tmp/malware.txt".to_string(),
        quarantine_path: "/var/quarantine/malware.txt".to_string(),
        sha256: "abc123".to_string(),
        reason: "Test quarantine".to_string(),
        score: 85,
        quarantined_at: chrono::Utc::now(),
        restored_at: None,
        deleted_at: None,
        status: nkosi_common::types::QuarantineStatus::Quarantined,
    };

    let result = repo.insert(&item);
    assert!(
        result.is_ok(),
        "Quarantine insert should succeed: {:?}",
        result.err()
    );

    let items = repo.get_active().unwrap();
    assert_eq!(items.len(), 1, "Should have one active quarantine item");
}

#[test]
pub fn test_db_insert_incident() {
    let test = TestDb::new();
    let repo = nkosi_db::IncidentRepository::new(&test.db);

    let incident = nkosi_common::types::Incident {
        id: uuid::Uuid::new_v4(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        status: nkosi_common::types::IncidentStatus::Open,
        global_score: 75,
        summary: Some("Test incident".to_string()),
    };

    let result = repo.insert(&incident);
    assert!(
        result.is_ok(),
        "Incident insert should succeed: {:?}",
        result.err()
    );

    let found = repo.get_by_id(&incident.id).unwrap();
    assert!(found.is_some(), "Incident should be found");
    assert_eq!(
        found.unwrap().status,
        nkosi_common::types::IncidentStatus::Open
    );
}
