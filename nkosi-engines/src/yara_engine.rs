use nkosi_common::types::*;
use std::path::Path;
use tracing::{debug, info};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct YaraRule {
    pub id: String,
    pub name: String,
    pub family: String,
    pub severity: Severity,
    pub confidence: f32,
    pub patterns: Vec<String>,
    pub strings: Vec<String>,
}

pub struct YaraEngine {
    rules: Vec<YaraRule>,
}

impl YaraEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
        };
        engine.load_default_rules();
        engine
    }

    fn load_default_rules(&mut self) {
        // Malware patterns
        self.rules.push(YaraRule {
            id: "YARA-001".to_string(),
            name: "Suspicious Shell Commands".to_string(),
            family: "Backdoor".to_string(),
            severity: Severity::Medium,
            confidence: 0.6,
            patterns: vec![
                r"eval\s*\(".to_string(),
                r"exec\s*\(".to_string(),
                r"system\s*\(".to_string(),
                r"base64_decode\s*\(".to_string(),
            ],
            strings: vec![
                "wget http".to_string(),
                "curl http".to_string(),
                "nc -e".to_string(),
                "bash -i".to_string(),
            ],
        });

        self.rules.push(YaraRule {
            id: "YARA-002".to_string(),
            name: "Crypto Miner Indicators".to_string(),
            family: "Cryptominer".to_string(),
            severity: Severity::High,
            confidence: 0.8,
            patterns: vec![
                r"stratum\+tcp".to_string(),
                r"xmrig".to_string(),
                r"minerd".to_string(),
                r"cpuminer".to_string(),
            ],
            strings: vec![
                "pool.mining".to_string(),
                "stratum".to_string(),
                "difficulty".to_string(),
            ],
        });

        self.rules.push(YaraRule {
            id: "YARA-003".to_string(),
            name: "Ransomware Indicators".to_string(),
            family: "Ransomware".to_string(),
            severity: Severity::Critical,
            confidence: 0.9,
            patterns: vec![
                r"\.encrypted".to_string(),
                r"\.locked".to_string(),
                r"\.crypto".to_string(),
                r"README.*DECRYPT".to_string(),
            ],
            strings: vec![
                "decrypt".to_string(),
                "bitcoin".to_string(),
                "wallet".to_string(),
                "ransom".to_string(),
            ],
        });

        self.rules.push(YaraRule {
            id: "YARA-004".to_string(),
            name: "Webshell Indicators".to_string(),
            family: "Webshell".to_string(),
            severity: Severity::High,
            confidence: 0.85,
            patterns: vec![
                r"eval\s*\(\s*\$_(GET|POST|REQUEST)".to_string(),
                r"system\s*\(\s*\$_(GET|POST|REQUEST)".to_string(),
                r"passthru\s*\(\s*\$_(GET|POST|REQUEST)".to_string(),
            ],
            strings: vec![
                "shell_exec".to_string(),
                "exec(".to_string(),
                "system(".to_string(),
            ],
        });

        info!("Loaded {} YARA rules", self.rules.len());
    }

    pub fn scan_file(&self, path: &Path) -> Vec<Detection> {
        let mut detections = Vec::new();

        if let Ok(content) = std::fs::read(path) {
            let content_str = String::from_utf8_lossy(&content);
            
            for rule in &self.rules {
                if self.matches_rule(&content_str, rule) {
                    debug!("YARA rule {} matched: {}", rule.id, rule.name);
                    
                    detections.push(Detection {
                        id: uuid::Uuid::new_v4(),
                        event_id: uuid::Uuid::new_v4(),
                        detection_engine: DetectionEngine::Yara,
                        rule_id: Some(rule.id.clone()),
                        rule_name: Some(rule.name.clone()),
                        confidence: rule.confidence,
                        score_contribution: self.calculate_score(&rule.severity, rule.confidence),
                        details: Some(format!(
                            "YARA match: {} (family: {}, severity: {:?})",
                            rule.name, rule.family, rule.severity
                        )),
                    });
                }
            }
        }

        detections
    }

    fn matches_rule(&self, content: &str, rule: &YaraRule) -> bool {
        // Check string patterns
        for pattern in &rule.patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    return true;
                }
            }
        }

        // Check literal strings
        for string in &rule.strings {
            if content.contains(string) {
                return true;
            }
        }

        false
    }

    fn calculate_score(&self, severity: &Severity, confidence: f32) -> u32 {
        let base_score = match severity {
            Severity::Critical => 90,
            Severity::High => 70,
            Severity::Medium => 50,
            Severity::Low => 30,
            Severity::Info => 10,
        };
        
        (base_score as f32 * confidence) as u32
    }

    pub fn get_rules(&self) -> &[YaraRule] {
        &self.rules
    }

    pub fn add_rule(&mut self, rule: YaraRule) {
        self.rules.push(rule);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_rules_loaded() {
        let engine = YaraEngine::new();
        assert!(engine.get_rules().len() >= 4);
    }

    #[test]
    fn test_scan_clean_file() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"This is a clean file with no malicious content").unwrap();
        temp.flush().unwrap();

        let engine = YaraEngine::new();
        let detections = engine.scan_file(temp.path());
        assert!(detections.is_empty());
    }

    #[test]
    fn test_scan_cryptominer() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"stratum+tcp://pool.mining.com:3333").unwrap();
        temp.flush().unwrap();

        let engine = YaraEngine::new();
        let detections = engine.scan_file(temp.path());
        assert!(!detections.is_empty());
        
        let detection = &detections[0];
        assert_eq!(detection.detection_engine, DetectionEngine::Yara);
        assert!(detection.details.as_ref().unwrap().contains("Cryptominer"));
    }

    #[test]
    fn test_scan_webshell() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"eval($_GET['cmd'])").unwrap();
        temp.flush().unwrap();

        let engine = YaraEngine::new();
        let detections = engine.scan_file(temp.path());
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_scan_ransomware() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"All your files have been encrypted. Pay bitcoin to decrypt").unwrap();
        temp.flush().unwrap();

        let engine = YaraEngine::new();
        let detections = engine.scan_file(temp.path());
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_add_custom_rule() {
        let mut engine = YaraEngine::new();
        let initial_count = engine.get_rules().len();
        
        engine.add_rule(YaraRule {
            id: "CUSTOM-001".to_string(),
            name: "Test Rule".to_string(),
            family: "Test".to_string(),
            severity: Severity::Low,
            confidence: 0.5,
            patterns: vec![r"TEST_PATTERN".to_string()],
            strings: vec![],
        });
        
        assert_eq!(engine.get_rules().len(), initial_count + 1);
    }

    #[test]
    fn test_matches_rule() {
        let engine = YaraEngine::new();
        let rule = YaraRule {
            id: "TEST".to_string(),
            name: "Test".to_string(),
            family: "Test".to_string(),
            severity: Severity::Low,
            confidence: 0.5,
            patterns: vec![r"eval\s*\(".to_string()],
            strings: vec!["test_string".to_string()],
        };

        assert!(engine.matches_rule("eval(something)", &rule));
        assert!(engine.matches_rule("has test_string inside", &rule));
        assert!(!engine.matches_rule("nothing matches", &rule));
    }
}
