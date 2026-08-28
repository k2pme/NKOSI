use nkosi_engines::{HashEngine, StaticAnalyzer, YaraEngine};
use std::path::Path;

#[test]
pub fn test_yara_fuzz_random_bytes() {
    let engine = YaraEngine::new();
    let tmp = tempfile::tempdir().unwrap();

    let payloads: Vec<(&str, &[u8])> = vec![
        ("empty", b""),
        ("null_bytes", &[0u8; 1000]),
        ("max_u8", &[255u8; 1000]),
        ("binary_elf", b"\x7fELF\x02\x01\x01"),
        ("zip_header", b"PK\x03\x04"),
        ("pdf_header", b"%PDF-1.4"),
        ("random", b"\xde\xad\xbe\xef\xca\xfe"),
    ];

    for (name, data) in &payloads {
        let path = tmp.path().join(format!("fuzz_{}.bin", name));
        std::fs::write(&path, data).unwrap();
        let _ = engine.scan_file(&path);
    }
}

#[test]
pub fn test_hash_fuzz_edge_cases() {
    let engine = HashEngine::new();
    let tmp = tempfile::tempdir().unwrap();

    let empty = tmp.path().join("empty");
    std::fs::write(&empty, b"").unwrap();
    let result = engine.compute_sha256(&empty);
    assert!(result.is_ok());

    let fake = tmp.path().join("nonexistent");
    let result = engine.compute_sha256(&fake);
    assert!(result.is_err());

    let large = tmp.path().join("large");
    std::fs::write(&large, vec![0u8; 1_000_000]).unwrap();
    let result = engine.compute_sha256(&large);
    assert!(result.is_ok());
}

#[test]
pub fn test_hash_fuzz_analyze_nonexistent() {
    let engine = HashEngine::new();
    let result = engine.analyze_file(Path::new("/tmp/__does_not_exist__"));
    assert!(result.is_none());
}

#[test]
pub fn test_hash_fuzz_analyze_with_threat_db() {
    let engine = HashEngine::new();
    engine.load_threat_hashes(vec!["deadbeef".to_string()]);
    let tmp = tempfile::tempdir().unwrap();

    let f = tmp.path().join("sample");
    std::fs::write(&f, b"payload").unwrap();
    let result = engine.analyze_file(&f);
    assert!(result.is_none());
}

#[test]
pub fn test_static_analyzer_fuzz() {
    let analyzer = StaticAnalyzer::new();
    let tmp = tempfile::tempdir().unwrap();

    let payloads: Vec<(&str, &[u8])> = vec![
        ("empty", b""),
        ("text", b"Just some normal text"),
        ("php_tag", b"<?php echo 'hello'; ?>"),
        ("script_tag", b"<script>alert('xss')</script>"),
        ("sql_inject", b"' OR 1=1 --"),
        ("binary_garbage", &[0xFF; 500]),
    ];

    for (name, data) in &payloads {
        let path = tmp.path().join(format!("fuzz_{}.bin", name));
        std::fs::write(&path, data).unwrap();
        let _ = analyzer.analyze_file(&path);
    }
}

#[test]
pub fn test_static_analyzer_fuzz_nonexistent() {
    let analyzer = StaticAnalyzer::new();
    let result = analyzer.analyze_file(Path::new("/tmp/__does_not_exist__"));
    assert!(result.is_none());
}

#[test]
pub fn test_yara_fuzz_path_is_directory() {
    let engine = YaraEngine::new();
    let tmp = tempfile::tempdir().unwrap();
    let _ = engine.scan_file(tmp.path());
}

#[test]
pub fn test_static_analyzer_fuzz_path_is_directory() {
    let analyzer = StaticAnalyzer::new();
    let tmp = tempfile::tempdir().unwrap();
    let _ = analyzer.analyze_file(tmp.path());
}
