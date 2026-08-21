pub mod schema;
pub mod repositories;

pub use schema::Database;
pub use repositories::*;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use nkosi_common::types::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn setup_test_db() -> Database {
        let db_path = PathBuf::from(":memory:");
        Database::new(&db_path).unwrap()
    }

    #[test]
    fn test_database_initialization() {
        let _db = setup_test_db();
    }

    #[test]
    fn test_insert_and_get_event() {
        let db = setup_test_db();
        let repo = EventRepository::new(&db);

        let mut event = Event::new(EventType::FileCreated, "test");
        event.file_path = Some("/tmp/test.txt".to_string());
        event.severity = Severity::Info;

        repo.insert(&event).unwrap();

        let retrieved = repo.get_by_id(&event.id).unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.event_type, EventType::FileCreated);
        assert_eq!(retrieved.file_path, Some("/tmp/test.txt".to_string()));
    }

    #[test]
    fn test_insert_and_find_threat_indicator() {
        let db = setup_test_db();
        let repo = ThreatIndicatorRepository::new(&db);

        let indicator = ThreatIndicator {
            id: Uuid::new_v4(),
            indicator_type: IndicatorType::Sha256,
            value: "abc123def456".to_string(),
            malware_family: Some("TestMalware".to_string()),
            confidence: 0.95,
            severity: Severity::High,
            source: "test".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            tags: vec!["test".to_string()],
            enabled: true,
        };

        repo.insert(&indicator).unwrap();

        let found = repo.find_by_value("abc123def456").unwrap();
        assert!(found.is_some());

        let found = found.unwrap();
        assert_eq!(found.malware_family, Some("TestMalware".to_string()));
        assert_eq!(found.confidence, 0.95);
    }

    #[test]
    fn test_insert_and_get_quarantine_item() {
        let db = setup_test_db();
        let repo = QuarantineRepository::new(&db);

        let item = QuarantineItem {
            id: Uuid::new_v4(),
            original_path: "/tmp/malware.exe".to_string(),
            quarantine_path: "/var/lib/nkosi/quarantine/malware.exe".to_string(),
            sha256: "abc123".to_string(),
            reason: "YARA match".to_string(),
            score: 85,
            quarantined_at: Utc::now(),
            restored_at: None,
            deleted_at: None,
            status: QuarantineStatus::Quarantined,
        };

        repo.insert(&item).unwrap();

        let active = repo.get_active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].original_path, "/tmp/malware.exe");
    }

    #[test]
    fn test_insert_and_get_scan() {
        let db = setup_test_db();
        let repo = ScanRepository::new(&db);

        let scan = Scan {
            id: Uuid::new_v4(),
            scan_type: ScanType::Quick,
            target: "/home".to_string(),
            started_at: Utc::now(),
            completed_at: None,
            files_scanned: 0,
            threats_found: 0,
            suspicious_found: 0,
            status: ScanStatus::Running,
        };

        repo.insert(&scan).unwrap();
    }
}
