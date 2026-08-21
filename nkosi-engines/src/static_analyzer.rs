use nkosi_common::types::*;
use std::path::Path;
use tracing::debug;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct StaticAnalysisResult {
    pub file_type: String,
    pub is_executable: bool,
    pub has_suid: bool,
    pub suspicious_strings: Vec<String>,
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub shell_commands: Vec<String>,
    pub risk_score: u32,
}

pub struct StaticAnalyzer {
    url_regex: Regex,
    ip_regex: Regex,
    shell_patterns: Vec<String>,
}

impl StaticAnalyzer {
    pub fn new() -> Self {
        Self {
            url_regex: Regex::new(r"https?://[^\s]+").unwrap(),
            ip_regex: Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap(),
            shell_patterns: vec![
                "eval".to_string(),
                "exec".to_string(),
                "system".to_string(),
                "passthru".to_string(),
                "shell_exec".to_string(),
                "popen".to_string(),
                "proc_open".to_string(),
                "base64_decode".to_string(),
                "base64_encode".to_string(),
                "gzinflate".to_string(),
                "gzuncompress".to_string(),
            ],
        }
    }

    pub fn analyze_file(&self, path: &Path) -> Option<Detection> {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return None,
        };

        let content = match std::fs::read(path) {
            Ok(c) => c,
            Err(_) => return None,
        };

        let content_str = String::from_utf8_lossy(&content);
        let file_type = self.detect_file_type(path, &content);
        let is_executable = self.is_executable(path, &metadata);
        let has_suid = self.has_suid_bit(&metadata);

        let suspicious_strings = self.find_suspicious_strings(&content_str);
        let urls = self.extract_urls(&content_str);
        let ips = self.extract_ips(&content_str);
        let shell_commands = self.find_shell_commands(&content_str);

        let risk_score = self.calculate_risk_score(
            is_executable,
            has_suid,
            &suspicious_strings,
            &urls,
            &ips,
            &shell_commands,
        );

        debug!(
            "Static analysis of {}: type={}, exec={}, suid={}, risk={}",
            path.display(),
            file_type,
            is_executable,
            has_suid,
            risk_score
        );

        if risk_score > 0 {
            Some(Detection {
                id: uuid::Uuid::new_v4(),
                event_id: uuid::Uuid::new_v4(),
                detection_engine: DetectionEngine::StaticAnalysis,
                rule_id: Some("STATIC-RISK".to_string()),
                rule_name: Some("Static Analysis Risk".to_string()),
                confidence: 0.5,
                score_contribution: risk_score,
                details: Some(format!(
                    "Type: {}, Exec: {}, SUID: {}, Suspicious strings: {}, URLs: {}, IPs: {}, Shell cmds: {}",
                    file_type,
                    is_executable,
                    has_suid,
                    suspicious_strings.len(),
                    urls.len(),
                    ips.len(),
                    shell_commands.len()
                )),
            })
        } else {
            None
        }
    }

    fn detect_file_type(&self, path: &Path, content: &[u8]) -> String {
        if content.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
            "ELF".to_string()
        } else if content.starts_with(&[0x4d, 0x5a]) {
            "PE".to_string()
        } else if content.starts_with(&[0x23, 0x21]) {
            "Script".to_string()
        } else if let Some(ext) = path.extension() {
            match ext.to_str().unwrap_or("") {
                "py" => "Python".to_string(),
                "pl" => "Perl".to_string(),
                "rb" => "Ruby".to_string(),
                "sh" | "bash" => "Shell".to_string(),
                "php" => "PHP".to_string(),
                "js" => "JavaScript".to_string(),
                _ => "Unknown".to_string(),
            }
        } else {
            "Unknown".to_string()
        }
    }

    fn is_executable(&self, _path: &Path, metadata: &std::fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    fn has_suid_bit(&self, metadata: &std::fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o4000 != 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    fn find_suspicious_strings(&self, content: &str) -> Vec<String> {
        let mut suspicious = Vec::new();
        
        let suspicious_patterns = vec![
            r"(?i)password",
            r"(?i)secret",
            r"(?i)api.?key",
            r"(?i)token",
            r"(?i)private.?key",
            r"(?i)ssh.?key",
            r"(?i)credential",
        ];

        for pattern in suspicious_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for _ in re.find_iter(content) {
                    suspicious.push(pattern.to_string());
                    break;
                }
            }
        }

        suspicious
    }

    fn extract_urls(&self, content: &str) -> Vec<String> {
        self.url_regex
            .find_iter(content)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    fn extract_ips(&self, content: &str) -> Vec<String> {
        self.ip_regex
            .find_iter(content)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    fn find_shell_commands(&self, content: &str) -> Vec<String> {
        let mut found = Vec::new();
        
        for pattern in &self.shell_patterns {
            if content.contains(pattern) {
                found.push(pattern.clone());
            }
        }

        found
    }

    fn calculate_risk_score(
        &self,
        is_executable: bool,
        has_suid: bool,
        suspicious_strings: &[String],
        urls: &[String],
        ips: &[String],
        shell_commands: &[String],
    ) -> u32 {
        let mut score = 0;

        if is_executable {
            score += 5;
        }

        if has_suid {
            score += 20;
        }

        score += (suspicious_strings.len() as u32) * 5;
        score += (urls.len() as u32) * 3;
        score += (ips.len() as u32) * 4;
        score += (shell_commands.len() as u32) * 8;

        score.min(100)
    }
}
