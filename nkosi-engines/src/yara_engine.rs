use nkosi_common::types::*;
use std::path::Path;
use tracing::{debug, info, warn};

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
    real_yara: bool,
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            real_yara: false,
        };
        engine.load_default_rules();
        engine.load_rules_from_directory(Path::new("/etc/nkosi/rules"));
        engine
    }

    pub fn new_with_real_yara() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            real_yara: true,
        };
        engine.load_default_rules();
        engine.load_rules_from_directory(Path::new("/etc/nkosi/rules"));
        info!("YARA real engine enabled");
        engine
    }

    /// Prefers the real YARA engine when the `real-yara` feature is enabled,
    /// otherwise falls back to the regex-based stub. Use this in production
    /// entry points (agent, cli) so the compiled engine matches the feature.
    pub fn new_prefer_real() -> Self {
        #[cfg(feature = "real-yara")]
        {
            Self::new_with_real_yara()
        }
        #[cfg(not(feature = "real-yara"))]
        {
            Self::new()
        }
    }

    fn load_default_rules(&mut self) {
        let default_rules = vec![
            YaraRule {
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
            },
            YaraRule {
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
            },
            YaraRule {
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
            },
            YaraRule {
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
            },
        ];

        self.rules.extend(default_rules);
        info!("Loaded {} default YARA rules", self.rules.len());
    }

    fn load_rules_from_directory(&mut self, dir: &Path) {
        if !dir.exists() || !dir.is_dir() {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("Cannot read YARA rules directory {}: {}", dir.display(), e);
                return;
            }
        };

        let mut loaded = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false)
                && let Ok(content) = std::fs::read_to_string(&path)
            {
                let idx = self.rules.len() + loaded + 1;
                let rule = Self::parse_yara_rule_file(&path, &content, idx);
                if let Some(rule) = rule {
                    self.rules.push(rule);
                    loaded += 1;
                }
            }
        }

        if loaded > 0 {
            info!("Loaded {} external YARA rules from {}", loaded, dir.display());
        }
    }

    fn parse_yara_rule_file(path: &Path, content: &str, idx: usize) -> Option<YaraRule> {
        let name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut strings = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("$")
                && trimmed.contains('=')
                && let Some(value) = trimmed.split('=').nth(1)
            {
                let value = value.trim().trim_matches('"');
                if !value.is_empty() {
                    strings.push(value.to_string());
                }
            }
        }

        Some(YaraRule {
            id: format!("EXT-{}", idx),
            name,
            family: "External".to_string(),
            severity: Severity::Medium,
            confidence: 0.7,
            patterns: Vec::new(),
            strings,
        })
    }

    pub fn scan_file(&self, path: &Path) -> Vec<Detection> {
        if self.real_yara {
            return self.scan_file_real_yara(path);
        }

        warn!("YARA-stub: using regex-based simulation instead of real YARA");
        self.scan_file_stub(path)
    }

    fn scan_file_stub(&self, path: &Path) -> Vec<Detection> {
        let mut detections = Vec::new();

        if let Ok(content) = std::fs::read(path) {
            let content_str = String::from_utf8_lossy(&content);

            for rule in &self.rules {
                if Self::matches_rule(&content_str, rule) {
                    debug!("YARA stub rule {} matched: {}", rule.id, rule.name);

                    detections.push(Detection {
                        id: uuid::Uuid::new_v4(),
                        event_id: uuid::Uuid::new_v4(),
                        incident_id: None,
                        detection_engine: DetectionEngine::Yara,
                        rule_id: Some(rule.id.clone()),
                        rule_name: Some(rule.name.clone()),
                        confidence: rule.confidence,
                        score_contribution: Self::calculate_score(&rule.severity, rule.confidence),
                        details: Some(format!(
                            "YARA match (stub): {} (family: {}, severity: {:?})",
                            rule.name, rule.family, rule.severity
                        )),
                    });
                }
            }
        }

        detections
    }

    fn scan_file_real_yara(&self, path: &Path) -> Vec<Detection> {
        let mut detections = Vec::new();

        #[cfg(feature = "real-yara")]
        {
            let content = match std::fs::read(path) {
                Ok(c) => c,
                Err(_) => return detections,
            };

            let mut compiler = match yara::Compiler::new() {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to create YARA compiler: {}", e);
                    return detections;
                }
            };

            for rule in &self.rules {
                let pattern = rule.strings.first().map(|s| s.as_str()).unwrap_or("");
                let yara_rule = format!(
                    "rule {} {{ strings: $a = \"{}\" condition: $a }}",
                    rule.id,
                    pattern.replace("\"", "\\\"")
                );
                compiler = compiler.add_rules_str(&yara_rule).unwrap_or_else(|e| {
                    warn!("Failed to add YARA rule {}: {}", rule.id, e);
                    yara::Compiler::new().unwrap()
                });
            }

            let rules = match compiler.compile_rules() {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to compile YARA rules: {}", e);
                    return detections;
                }
            };

            let mut scanner = match rules.scanner() {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to create YARA scanner: {}", e);
                    return detections;
                }
            };

            if let Ok(matches) = scanner.scan_mem(&content) {
                for m in matches {
                    let rule_name = m.identifier.to_string();
                    debug!("Real YARA matched rule: {}", rule_name);
                    detections.push(Detection {
                        id: uuid::Uuid::new_v4(),
                        event_id: uuid::Uuid::new_v4(),
                        incident_id: None,
                        detection_engine: DetectionEngine::Yara,
                        rule_id: Some(rule_name.clone()),
                        rule_name: Some(rule_name.clone()),
                        confidence: 0.9,
                        score_contribution: 80,
                        details: Some(format!("YARA real match: {}", rule_name)),
                    });
                }
            }
        }

        #[cfg(not(feature = "real-yara"))]
        {
            warn!("real-yara feature not enabled, falling back to stub");
            detections.extend(self.scan_file_stub(path));
        }

        detections
    }

    fn matches_rule(content: &str, rule: &YaraRule) -> bool {
        for pattern in &rule.patterns {
            if let Ok(re) = regex::Regex::new(pattern)
                && re.is_match(content)
            {
                return true;
            }
        }

        for string in &rule.strings {
            if content.contains(string) {
                return true;
            }
        }

        false
    }

    fn calculate_score(severity: &Severity, confidence: f32) -> u32 {
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

    pub fn is_real_yara(&self) -> bool {
        self.real_yara
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

        assert!(YaraEngine::matches_rule("eval(something)", &rule));
        assert!(YaraEngine::matches_rule("has test_string inside", &rule));
        assert!(!YaraEngine::matches_rule("nothing matches", &rule));
    }

    #[test]
    fn test_stub_logs_warning() {
        let engine = YaraEngine::new();
        assert!(!engine.is_real_yara());
        let _ = engine.scan_file(Path::new("/tmp"));
    }
}
