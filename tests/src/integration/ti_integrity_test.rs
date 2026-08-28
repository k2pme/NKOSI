use nkosi_common::types::IndicatorType;
use nkosi_ti::integrity_check;

#[test]
fn test_min_size_validation_end_to_end() {
    // Simulate a feed that's too short
    assert!(!integrity_check::validate_min_size(
        "tiny",
        50,
        "TestSource"
    ));
    assert!(integrity_check::validate_min_size(
        &"x".repeat(200),
        50,
        "TestSource"
    ));
}

#[test]
fn test_audit_hash_deterministic() {
    let body = "sample threat intelligence feed content with hashes and indicators";
    let h1 = integrity_check::compute_audit_hash(body);
    let h2 = integrity_check::compute_audit_hash(body);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 16, "Audit hash should be 16 hex chars");
}

#[test]
fn test_audit_hash_varies_with_content() {
    let h1 = integrity_check::compute_audit_hash("feed_A");
    let h2 = integrity_check::compute_audit_hash("feed_B");
    assert_ne!(h1, h2);
}

#[test]
fn test_indicator_value_validation_all_types() {
    // Sha256
    let good_sha256 = "a".repeat(64);
    assert!(integrity_check::validate_indicator_value(
        &IndicatorType::Sha256,
        &good_sha256
    ));
    assert!(!integrity_check::validate_indicator_value(
        &IndicatorType::Sha256,
        "short"
    ));

    // Sha1
    let good_sha1 = "b".repeat(40);
    assert!(integrity_check::validate_indicator_value(
        &IndicatorType::Sha1,
        &good_sha1
    ));
    assert!(!integrity_check::validate_indicator_value(
        &IndicatorType::Sha1,
        "short"
    ));

    // Md5
    let good_md5 = "c".repeat(32);
    assert!(integrity_check::validate_indicator_value(
        &IndicatorType::Md5,
        &good_md5
    ));
    assert!(!integrity_check::validate_indicator_value(
        &IndicatorType::Md5,
        "short"
    ));

    // IP
    assert!(integrity_check::validate_indicator_value(
        &IndicatorType::Ip,
        "10.0.0.1:80"
    ));
    assert!(!integrity_check::validate_indicator_value(
        &IndicatorType::Ip,
        "bad-ip"
    ));

    // Domain
    assert!(integrity_check::validate_indicator_value(
        &IndicatorType::Domain,
        "evil.com"
    ));
    assert!(!integrity_check::validate_indicator_value(
        &IndicatorType::Domain,
        "nodot"
    ));

    // Url
    assert!(integrity_check::validate_indicator_value(
        &IndicatorType::Url,
        "https://evil.com"
    ));
    assert!(!integrity_check::validate_indicator_value(
        &IndicatorType::Url,
        "ftp://evil.com"
    ));
}

#[test]
fn test_threatfox_parse_with_integrity() {
    let client = nkosi_ti::threatfox::ThreatFoxClient::new();
    let json = serde_json::json!({
        "query_status": "ok",
        "data": [
            {
                "ioc_type": "ip:port",
                "ioc": "192.168.1.100:443",
                "malware": "TestMalware",
                "confidence_level": 75
            },
            {
                "ioc_type": "domain",
                "ioc": "malware.example.com",
                "malware": "TestBot",
                "confidence_level": 85
            }
        ]
    });
    let indicators = client.parse_json_response(&json.to_string());
    assert_eq!(indicators.len(), 2);
    assert_eq!(indicators[0].source, "ThreatFox");
    assert_eq!(indicators[1].source, "ThreatFox");
}

#[test]
fn test_threatfox_rejects_invalid_values() {
    let client = nkosi_ti::threatfox::ThreatFoxClient::new();
    let json = serde_json::json!({
        "query_status": "ok",
        "data": [
            {
                "ioc_type": "sha256",
                "ioc": "not-a-valid-hash",
                "malware": "TestMalware",
                "confidence_level": 50
            }
        ]
    });
    let indicators = client.parse_json_response(&json.to_string());
    assert!(indicators.is_empty(), "Invalid sha256 should be rejected");
}

#[test]
fn test_urlhaus_parse_with_integrity() {
    let client = nkosi_ti::urlhaus::UrlhausClient::new();
    let csv = "12345,2024-01-01,http://evil.com/payload,offline,malware_download,,2024-01-02\n";
    let indicators = client.parse_csv(csv);
    assert_eq!(indicators.len(), 1);
    assert_eq!(indicators[0].value, "http://evil.com/payload");
    assert_eq!(indicators[0].source, "URLhaus");
}

#[test]
fn test_urlhaus_rejects_non_http() {
    let client = nkosi_ti::urlhaus::UrlhausClient::new();
    let csv = "12345,2024-01-01,ftp://evil.com/payload,ok,malware,,2024-01-01\n";
    let indicators = client.parse_csv(csv);
    assert!(indicators.is_empty(), "FTP URLs should be rejected");
}
