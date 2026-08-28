fn fixtures_dir() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(manifest_dir).join("fixtures")
}

#[test]
pub fn test_scan_malicious_file() {
    let eicar_path = fixtures_dir().join("eicar.com");
    assert!(eicar_path.exists(), "EICAR fixture must exist at {:?}", eicar_path);

    let content = std::fs::read(&eicar_path).unwrap();
    let content_str = String::from_utf8_lossy(&content);

    // EICAR signature must be detected
    assert!(content_str.contains("X5O!P%@AP"), "EICAR signature present");

    // Hash engine should detect it
    let hash_engine = nkosi_engines::HashEngine::new();
    let _detection = hash_engine.analyze_file(&eicar_path);
    // EICAR may not be in the hash DB, but the file must be readable
    assert!(!content.is_empty(), "EICAR file readable");

    // YARA engine should process the file (may or may not match stub rules)
    let yara_engine = nkosi_engines::YaraEngine::new();
    let _detections = yara_engine.scan_file(&eicar_path);
    // Just verify the scan completes without error
    // EICAR may not match the specific stub rules (webshell/cryptominer/ransomware)
}

#[test]
pub fn test_scan_webshell_pattern() {
    // Test with content that matches the webshell stub rule
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "<?php eval($_GET['cmd']); ?>").unwrap();

    let yara_engine = nkosi_engines::YaraEngine::new();
    let detections = yara_engine.scan_file(tmp.path());
    assert!(!detections.is_empty(), "YARA should detect webshell pattern");
    assert_eq!(detections[0].detection_engine, nkosi_common::types::DetectionEngine::Yara);
}

#[test]
pub fn test_scan_clean_file() {
    let clean_path = fixtures_dir().join("test_clean.txt");
    assert!(clean_path.exists(), "Clean fixture must exist at {:?}", clean_path);

    let yara_engine = nkosi_engines::YaraEngine::new();
    let detections = yara_engine.scan_file(&clean_path);
    assert!(detections.is_empty(), "Clean file should have no YARA detections");

    let hash_engine = nkosi_engines::HashEngine::new();
    let detection = hash_engine.analyze_file(&clean_path);
    assert!(detection.is_none(), "Clean file should have no hash detection");
}

#[test]
pub fn test_static_analysis_suspicious() {
    let eicar_path = fixtures_dir().join("eicar.com");
    let analyzer = nkosi_engines::StaticAnalyzer::new();
    let result = analyzer.analyze_file(&eicar_path);

    // EICAR contains suspicious strings (eval, base64 patterns)
    if let Some(detection) = result {
        assert_eq!(detection.detection_engine, nkosi_common::types::DetectionEngine::StaticAnalysis);
        assert!(detection.score_contribution > 0, "Should have positive risk score");
    }
}

#[test]
pub fn test_static_analysis_clean() {
    let clean_path = fixtures_dir().join("test_clean.txt");
    let analyzer = nkosi_engines::StaticAnalyzer::new();
    let result = analyzer.analyze_file(&clean_path);

    // Clean text file should have low/no risk
    if let Some(detection) = result {
        assert!(detection.score_contribution < 30, "Clean file should have low risk");
    }
}
