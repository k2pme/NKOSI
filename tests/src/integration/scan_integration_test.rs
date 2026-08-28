use tempfile::TempDir;

struct TestDb {
    _tmp: TempDir,
    db: nkosi_db::Database,
}

impl TestDb {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("test_scan_integration.db");
        let db = nkosi_db::Database::new(&db_path).unwrap();
        Self { _tmp: tmp, db }
    }
}

#[test]
pub fn scan_and_store_results() {
    let test = TestDb::new();
    let event_repo = nkosi_db::EventRepository::new(&test.db);

    let hash_engine = nkosi_engines::HashEngine::new();
    let yara_engine = nkosi_engines::YaraEngine::new();
    let static_analyzer = nkosi_engines::StaticAnalyzer::new();

    // Create test files
    let tmp = tempfile::tempdir().unwrap();
    let clean_file = tmp.path().join("clean.txt");
    std::fs::write(&clean_file, "This is a harmless file").unwrap();

    // Scan clean file
    let detection = scan_single(&clean_file, &hash_engine, &yara_engine, &static_analyzer);
    assert!(detection.is_none(), "Clean file should not be detected");

    // Store an event for the clean scan
    let mut event = nkosi_common::types::Event::new(
        nkosi_common::types::EventType::FileCreated,
        "integration_test",
    );
    event.file_path = Some(clean_file.display().to_string());
    event.severity = nkosi_common::types::Severity::Info;
    event_repo.insert(&event).unwrap();

    // Verify stored
    let recent = event_repo.get_recent(10).unwrap();
    assert!(!recent.is_empty(), "Should have stored events");
    let found = recent.iter().any(|e| {
        e.file_path.as_ref() == Some(&clean_file.display().to_string())
    });
    assert!(found, "Should find our event by file path");
}

#[test]
pub fn scan_risk_assessment_pipeline() {
    let hash_engine = nkosi_engines::HashEngine::new();
    let yara_engine = nkosi_engines::YaraEngine::new();
    let static_analyzer = nkosi_engines::StaticAnalyzer::new();
    let risk_engine = nkosi_risk::RiskEngine::new(nkosi_risk::RiskConfig::default());

    let tmp = tempfile::tempdir().unwrap();

    // Test with a PHP webshell-like file
    let php_file = tmp.path().join("shell.php");
    std::fs::write(&php_file, "<?php eval($_GET['cmd']); ?>").unwrap();

    let detection = scan_single(&php_file, &hash_engine, &yara_engine, &static_analyzer);

    // If YARA detects it, verify risk assessment
    if let Some(det) = detection {
        let assessment = risk_engine.evaluate(vec![det]);
        assert!(assessment.score > 0, "Risk score should be > 0 for detected file");
        // Level is not public, just verify score is positive
    }
}

#[test]
pub fn scan_and_persist_full_flow() {
    let test = TestDb::new();
    let event_repo = nkosi_db::EventRepository::new(&test.db);

    let hash_engine = nkosi_engines::HashEngine::new();
    let yara_engine = nkosi_engines::YaraEngine::new();
    let static_analyzer = nkosi_engines::StaticAnalyzer::new();

    let tmp = tempfile::tempdir().unwrap();

    // Create multiple test files
    let files: Vec<_> = (0..5)
        .map(|i| {
            let path = tmp.path().join(format!("test_{}.txt", i));
            std::fs::write(&path, format!("Content for file {}", i)).unwrap();
            path
        })
        .collect();

    // Scan all files
    let mut _detections = 0u32;
    for file in &files {
        let mut event = nkosi_common::types::Event::new(
            nkosi_common::types::EventType::FileCreated,
            "integration_scan",
        );
        event.file_path = Some(file.display().to_string());

        if let Some(det) = scan_single(file, &hash_engine, &yara_engine, &static_analyzer) {
            _detections += 1;
            event.severity = nkosi_common::types::Severity::High;
            event.score = Some(det.score_contribution);
        } else {
            event.severity = nkosi_common::types::Severity::Info;
        }

        event_repo.insert(&event).unwrap();
    }

    // Verify all events stored
    let all = event_repo.get_recent(100).unwrap();
    assert!(all.len() >= 5, "Should have at least 5 events stored");

    // Verify events have correct file paths
    for file in &files {
        let path_str = file.display().to_string();
        let found = all.iter().any(|e| e.file_path.as_ref() == Some(&path_str));
        assert!(found, "Should find event for {}", path_str);
    }
}

pub fn scan_single(
    path: &std::path::Path,
    hash_engine: &nkosi_engines::HashEngine,
    yara_engine: &nkosi_engines::YaraEngine,
    static_analyzer: &nkosi_engines::StaticAnalyzer,
) -> Option<nkosi_common::types::Detection> {
    if let Some(d) = hash_engine.analyze_file(path) {
        return Some(d);
    }
    let yara = yara_engine.scan_file(path);
    if !yara.is_empty() {
        return yara.into_iter().next();
    }
    static_analyzer.analyze_file(path)
}
