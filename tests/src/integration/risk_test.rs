use nkosi_common::types::*;
use nkosi_risk::{RiskConfig, RiskEngine};

fn make_detection(engine: DetectionEngine, score: u32) -> Detection {
    Detection {
        id: uuid::Uuid::new_v4(),
        event_id: uuid::Uuid::new_v4(),
        incident_id: None,
        detection_engine: engine,
        rule_id: Some("test-rule".to_string()),
        rule_name: Some("Test Rule".to_string()),
        confidence: 0.8,
        score_contribution: score,
        details: Some("Test detection".to_string()),
    }
}

#[test]
pub fn test_risk_clean() {
    let engine = RiskEngine::new(RiskConfig::default());
    let detections = vec![make_detection(DetectionEngine::Hash, 10)];
    let assessment = engine.evaluate(detections);

    assert_eq!(assessment.level, RiskLevel::Clean);
    assert!(assessment.score < 30);
}

#[test]
pub fn test_risk_low() {
    let engine = RiskEngine::new(RiskConfig::default());
    let detections = vec![make_detection(DetectionEngine::Yara, 40)];
    let assessment = engine.evaluate(detections);

    // Score 40 is >= low_threshold (30) but < suspicious_threshold (70)
    assert_eq!(assessment.level, RiskLevel::Low);
}

#[test]
pub fn test_risk_malicious() {
    let engine = RiskEngine::new(RiskConfig::default());
    let detections = vec![make_detection(DetectionEngine::Yara, 90)];
    let assessment = engine.evaluate(detections);

    assert_eq!(assessment.level, RiskLevel::Malicious);
    assert!(assessment.score >= 70);
}

#[test]
pub fn test_risk_action_mapping() {
    let engine = RiskEngine::new(RiskConfig::default());

    let clean_action = engine.get_recommended_action(&RiskLevel::Clean);
    assert!(matches!(clean_action, ResponseAction::Allow));

    let malicious_action = engine.get_recommended_action(&RiskLevel::Malicious);
    assert!(matches!(
        malicious_action,
        ResponseAction::Quarantine | ResponseAction::Kill
    ));
}

#[test]
pub fn test_risk_multiple_detections() {
    let engine = RiskEngine::new(RiskConfig::default());
    let detections = vec![
        make_detection(DetectionEngine::Hash, 40),
        make_detection(DetectionEngine::Yara, 60),
        make_detection(DetectionEngine::StaticAnalysis, 30),
    ];
    let assessment = engine.evaluate(detections);

    // Score should be aggregated from multiple detections
    assert!(
        assessment.score >= 30,
        "Score should reflect multiple detections"
    );
}
