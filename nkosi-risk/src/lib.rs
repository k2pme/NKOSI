use nkosi_common::types::*;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct RiskConfig {
    pub low_threshold: u32,
    pub suspicious_threshold: u32,
    pub malicious_threshold: u32,
    pub weights: RiskWeights,
}

#[derive(Debug, Clone)]
pub struct RiskWeights {
    pub hash: u32,
    pub yara: u32,
    pub static_analysis: u32,
    pub behavior: u32,
    pub network: u32,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            low_threshold: 30,
            suspicious_threshold: 70,
            malicious_threshold: 70,
            weights: RiskWeights {
                hash: 80,
                yara: 40,
                static_analysis: 20,
                behavior: 30,
                network: 50,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskAssessment {
    pub score: u32,
    pub level: RiskLevel,
    pub detections: Vec<Detection>,
    pub details: String,
}

pub struct RiskEngine {
    config: RiskConfig,
}

impl RiskEngine {
    pub fn new(config: RiskConfig) -> Self {
        Self { config }
    }

    pub fn evaluate(&self, detections: Vec<Detection>) -> RiskAssessment {
        if detections.is_empty() {
            return RiskAssessment {
                score: 0,
                level: RiskLevel::Clean,
                detections: Vec::new(),
                details: "No detections".to_string(),
            };
        }

        let mut weighted_score: u32 = 0;
        let mut total_weight: u32 = 0;
        let mut details = Vec::new();

        for detection in &detections {
            let weight = self.get_weight(&detection.detection_engine);
            let contribution = (detection.score_contribution as f32 * detection.confidence) as u32;
            let weighted_contribution = (contribution as f32 * weight as f32 / 100.0) as u32;

            weighted_score += weighted_contribution;
            total_weight += weight;

            details.push(format!(
                "{:?}: {} (score: {}, confidence: {:.2}, weight: {})",
                detection.detection_engine,
                detection.rule_name.as_deref().unwrap_or("Unknown"),
                detection.score_contribution,
                detection.confidence,
                weight
            ));

            debug!(
                "Detection: {} - contribution: {} - weighted: {}",
                detection.rule_name.as_deref().unwrap_or("Unknown"),
                contribution,
                weighted_contribution
            );
        }

        // Normalize score to 0-100
        let normalized_score = if total_weight > 0 {
            (weighted_score as f32 / total_weight as f32 * 100.0) as u32
        } else {
            0
        };

        let level = self.determine_level(normalized_score);

        info!(
            "Risk assessment: score={}, level={:?}, detections={}",
            normalized_score,
            level,
            detections.len()
        );

        RiskAssessment {
            score: normalized_score.min(100),
            level,
            detections,
            details: details.join("; "),
        }
    }

    fn get_weight(&self, engine: &DetectionEngine) -> u32 {
        match engine {
            DetectionEngine::Hash => self.config.weights.hash,
            DetectionEngine::Yara => self.config.weights.yara,
            DetectionEngine::StaticAnalysis => self.config.weights.static_analysis,
            DetectionEngine::Behavior => self.config.weights.behavior,
            DetectionEngine::Network => self.config.weights.network,
            DetectionEngine::ThreatIntel => 100,
        }
    }

    fn determine_level(&self, score: u32) -> RiskLevel {
        if score >= self.config.malicious_threshold {
            RiskLevel::Malicious
        } else if score >= self.config.suspicious_threshold {
            RiskLevel::Suspicious
        } else if score >= self.config.low_threshold {
            RiskLevel::Low
        } else {
            RiskLevel::Clean
        }
    }

    pub fn get_recommended_action(&self, level: &RiskLevel) -> ResponseAction {
        match level {
            RiskLevel::Clean => ResponseAction::Allow,
            RiskLevel::Low => ResponseAction::Alert,
            RiskLevel::Suspicious => ResponseAction::Alert,
            RiskLevel::Malicious => ResponseAction::Quarantine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detection(engine: DetectionEngine, score: u32, confidence: f32) -> Detection {
        Detection {
            id: uuid::Uuid::new_v4(),
            event_id: uuid::Uuid::new_v4(),
            incident_id: None,
            detection_engine: engine,
            rule_id: Some("TEST".to_string()),
            rule_name: Some("Test Detection".to_string()),
            confidence,
            score_contribution: score,
            details: Some("Test".to_string()),
        }
    }

    #[test]
    fn test_empty_detections() {
        let engine = RiskEngine::new(RiskConfig::default());
        let result = engine.evaluate(vec![]);
        assert_eq!(result.score, 0);
        assert_eq!(result.level, RiskLevel::Clean);
    }

    #[test]
    fn test_clean_file() {
        let engine = RiskEngine::new(RiskConfig::default());
        let detections = vec![make_detection(DetectionEngine::StaticAnalysis, 10, 0.5)];
        let result = engine.evaluate(detections);
        assert!(result.score < 30);
        assert_eq!(result.level, RiskLevel::Clean);
    }

    #[test]
    fn test_suspicious_file() {
        let engine = RiskEngine::new(RiskConfig::default());
        let detections = vec![
            make_detection(DetectionEngine::Yara, 80, 0.9),
            make_detection(DetectionEngine::StaticAnalysis, 50, 0.7),
        ];
        let result = engine.evaluate(detections);
        assert!(result.score >= 30);
    }

    #[test]
    fn test_malicious_file() {
        let engine = RiskEngine::new(RiskConfig::default());
        let detections = vec![make_detection(DetectionEngine::Hash, 100, 1.0)];
        let result = engine.evaluate(detections);
        assert_eq!(result.level, RiskLevel::Malicious);
        assert!(result.score >= 70);
    }

    #[test]
    fn test_multiple_detections() {
        let engine = RiskEngine::new(RiskConfig::default());
        let detections = vec![
            make_detection(DetectionEngine::Hash, 100, 1.0),
            make_detection(DetectionEngine::Yara, 90, 0.9),
            make_detection(DetectionEngine::StaticAnalysis, 70, 0.8),
        ];
        let result = engine.evaluate(detections);
        assert!(result.score >= 70);
        assert_eq!(result.level, RiskLevel::Malicious);
    }

    #[test]
    fn test_get_recommended_action() {
        let engine = RiskEngine::new(RiskConfig::default());

        assert_eq!(
            engine.get_recommended_action(&RiskLevel::Clean),
            ResponseAction::Allow
        );
        assert_eq!(
            engine.get_recommended_action(&RiskLevel::Low),
            ResponseAction::Alert
        );
        assert_eq!(
            engine.get_recommended_action(&RiskLevel::Suspicious),
            ResponseAction::Alert
        );
        assert_eq!(
            engine.get_recommended_action(&RiskLevel::Malicious),
            ResponseAction::Quarantine
        );
    }

    #[test]
    fn test_custom_config() {
        let config = RiskConfig {
            low_threshold: 10,
            suspicious_threshold: 40,
            malicious_threshold: 80,
            weights: RiskWeights {
                hash: 100,
                yara: 50,
                static_analysis: 30,
                behavior: 40,
                network: 60,
            },
        };

        let engine = RiskEngine::new(config);
        let detections = vec![make_detection(DetectionEngine::Hash, 50, 0.8)];
        let result = engine.evaluate(detections);
        assert!(result.score > 0);
    }

    #[test]
    fn test_score_normalization() {
        let engine = RiskEngine::new(RiskConfig::default());
        let detections = vec![make_detection(DetectionEngine::Hash, 100, 1.0)];
        let result = engine.evaluate(detections);
        assert!(result.score <= 100);
    }
}
