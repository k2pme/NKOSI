use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityBaseline {
    pub created_at: String,
    pub files: HashMap<String, FileHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityFinding {
    pub path: String,
    pub finding_type: String,
    pub severity: String,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub timestamp: String,
    pub baseline_exists: bool,
    pub findings: Vec<IntegrityFinding>,
    pub score: u32,
    pub summary: String,
}

pub struct IntegrityScanner {
    baseline_path: PathBuf,
    watched_dirs: Vec<PathBuf>,
}

impl Default for IntegrityScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrityScanner {
    pub fn new() -> Self {
        Self {
            baseline_path: PathBuf::from("/var/lib/nkosi/baseline.json"),
            watched_dirs: vec![
                "/bin".into(),
                "/sbin".into(),
                "/usr/bin".into(),
                "/usr/sbin".into(),
                "/usr/local/bin".into(),
            ],
        }
    }

    pub fn scan(&self) -> Result<IntegrityReport> {
        info!("Starting integrity scan");
        let mut findings = Vec::new();

        // Load existing baseline
        let baseline = self.load_baseline();
        let baseline_exists = baseline.is_some();

        // Scan current state
        let current_state = self.scan_files()?;

        if let Some(old_baseline) = baseline {
            // Compare with baseline
            findings.extend(self.compare_with_baseline(&old_baseline, &current_state));
        } else {
            info!("No baseline found, creating initial baseline");
            self.save_baseline(&current_state)?;
        }

        let score = self.calculate_score(&findings);
        let summary = self.generate_summary(&findings, score, baseline_exists);

        info!(
            "Integrity scan completed: {} findings, score: {}",
            findings.len(),
            score
        );

        Ok(IntegrityReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            baseline_exists,
            findings,
            score,
            summary,
        })
    }

    pub fn create_baseline(&self) -> Result<IntegrityBaseline> {
        info!("Creating integrity baseline");
        let state = self.scan_files()?;
        self.save_baseline(&state)?;
        Ok(state)
    }

    fn load_baseline(&self) -> Option<IntegrityBaseline> {
        if self.baseline_path.exists()
            && let Ok(content) = std::fs::read_to_string(&self.baseline_path)
            && let Ok(baseline) = serde_json::from_str(&content)
        {
            return Some(baseline);
        }
        None
    }

    fn save_baseline(&self, baseline: &IntegrityBaseline) -> Result<()> {
        if let Some(parent) = self.baseline_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(baseline)?;
        std::fs::write(&self.baseline_path, content)?;
        Ok(())
    }

    fn scan_files(&self) -> Result<IntegrityBaseline> {
        let mut files = HashMap::new();

        for dir in &self.watched_dirs {
            if !dir.exists() {
                continue;
            }

            for entry in walkdir::WalkDir::new(dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let path = entry.path();
                if let Ok(metadata) = std::fs::metadata(path)
                    && let Ok(hash) = self.compute_hash(path)
                {
                    let file_hash = FileHash {
                        path: path.display().to_string(),
                        sha256: hash,
                        size: metadata.len(),
                        modified: metadata
                            .modified()
                            .map(|t| format!("{:?}", t))
                            .unwrap_or_default(),
                    };
                    files.insert(path.display().to_string(), file_hash);
                }
            }
        }

        Ok(IntegrityBaseline {
            created_at: chrono::Utc::now().to_rfc3339(),
            files,
        })
    }

    fn compute_hash(&self, path: &Path) -> Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = std::io::Read::read(&mut file, &mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn compare_with_baseline(
        &self,
        baseline: &IntegrityBaseline,
        current: &IntegrityBaseline,
    ) -> Vec<IntegrityFinding> {
        let mut findings = Vec::new();

        // Check for modified files
        for (path, old_hash) in &baseline.files {
            if let Some(new_hash) = current.files.get(path) {
                if old_hash.sha256 != new_hash.sha256 {
                    findings.push(IntegrityFinding {
                        path: path.clone(),
                        finding_type: "Modified".to_string(),
                        severity: "Critical".to_string(),
                        expected: Some(old_hash.sha256.clone()),
                        actual: Some(new_hash.sha256.clone()),
                    });
                }
            } else {
                findings.push(IntegrityFinding {
                    path: path.clone(),
                    finding_type: "Deleted".to_string(),
                    severity: "High".to_string(),
                    expected: Some(old_hash.sha256.clone()),
                    actual: None,
                });
            }
        }

        // Check for new files
        for path in current.files.keys() {
            if !baseline.files.contains_key(path) {
                findings.push(IntegrityFinding {
                    path: path.clone(),
                    finding_type: "New".to_string(),
                    severity: "Medium".to_string(),
                    expected: None,
                    actual: Some(current.files[path].sha256.clone()),
                });
            }
        }

        findings
    }

    fn calculate_score(&self, findings: &[IntegrityFinding]) -> u32 {
        let mut score = 0;
        for finding in findings {
            match finding.severity.as_str() {
                "Critical" => score += 40,
                "High" => score += 25,
                "Medium" => score += 10,
                "Low" => score += 5,
                _ => {}
            }
        }
        score.min(100)
    }

    fn generate_summary(
        &self,
        findings: &[IntegrityFinding],
        score: u32,
        baseline_exists: bool,
    ) -> String {
        if !baseline_exists {
            "Initial baseline created. Run again later to detect changes.".to_string()
        } else if findings.is_empty() {
            "System integrity verified. No changes detected since baseline.".to_string()
        } else {
            let modified = findings
                .iter()
                .filter(|f| f.finding_type == "Modified")
                .count();
            let deleted = findings
                .iter()
                .filter(|f| f.finding_type == "Deleted")
                .count();
            let new = findings.iter().filter(|f| f.finding_type == "New").count();

            format!(
                "Integrity check: {} modified, {} deleted, {} new files. Risk score: {}/100",
                modified, deleted, new, score
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = IntegrityScanner::new();
        assert!(!scanner.watched_dirs.is_empty());
    }
}
