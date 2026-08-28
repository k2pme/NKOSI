#[test]
pub fn test_quarantine_flow() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let quarantine_path = tmp_dir.path().join("quarantine");
    std::fs::create_dir_all(&quarantine_path).unwrap();

    // Create a test file to quarantine
    let test_file = tmp_dir.path().join("malware.txt");
    std::fs::write(&test_file, "malicious content").unwrap();
    assert!(test_file.exists());

    // Create a dummy DB for ResponseEngine
    let db_path = tmp_dir.path().join("test.db");
    let db = nkosi_db::Database::new(&db_path).unwrap();

    let response = nkosi_response::ResponseEngine::new(quarantine_path.clone(), Some(db));

    // Execute quarantine action (blocking call)
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(response.execute_action(
        &nkosi_common::types::ResponseAction::Quarantine,
        Some(test_file.to_str().unwrap()),
        None,
        None,
        85,
        "Test quarantine",
    ));

    assert!(result.is_ok(), "Quarantine should succeed");

    // Original file should be removed
    assert!(!test_file.exists(), "Original file should be quarantined");

    // Quarantine directory should have the file
    let entries: Vec<_> = std::fs::read_dir(&quarantine_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "Quarantine should contain one file");
}

#[test]
pub fn test_quarantine_items_list() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let quarantine_path = tmp_dir.path().join("quarantine");
    std::fs::create_dir_all(&quarantine_path).unwrap();

    let db_path = tmp_dir.path().join("test.db");
    let db = nkosi_db::Database::new(&db_path).unwrap();

    let response = nkosi_response::ResponseEngine::new(quarantine_path, Some(db));

    let items = response.get_quarantine_items();
    assert!(items.is_empty(), "Empty quarantine should return no items");
}
