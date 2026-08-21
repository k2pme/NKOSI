use nkosi_common::types::*;
use sha2::{Sha256, Digest};
use std::path::Path;
use tracing::{debug, info, warn};

pub struct HashEngine {
    known_hashes: Vec<String>,
}

impl HashEngine {
    pub fn new() -> Self {
        Self {
            known_hashes: Vec::new(),
        }
    }

    pub fn load_threat_hashes(&mut self, hashes: Vec<String>) {
        self.known_hashes = hashes;
        info!("Loaded {} threat hashes", self.known_hashes.len());
    }

    pub fn compute_sha256(&self, path: &Path) -> anyhow::Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        use std::io::Read;
        let mut buffer = [0u8; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn is_known_malware(&self, hash: &str) -> bool {
        self.known_hashes.contains(&hash.to_string())
    }

    pub fn analyze_file(&self, path: &Path) -> Option<Detection> {
        match self.compute_sha256(path) {
            Ok(hash) => {
                debug!("Computed SHA-256 for {}: {}", path.display(), hash);
                
                if self.is_known_malware(&hash) {
                    info!("Known malware hash detected: {}", hash);
                    Some(Detection {
                        id: uuid::Uuid::new_v4(),
                        event_id: uuid::Uuid::new_v4(),
                        detection_engine: DetectionEngine::Hash,
                        rule_id: Some("HASH-MALWARE".to_string()),
                        rule_name: Some("Known Malware Hash".to_string()),
                        confidence: 1.0,
                        score_contribution: 100,
                        details: Some(format!("Hash {} matches known malware", hash)),
                    })
                } else {
                    debug!("Hash not in threat database: {}", hash);
                    None
                }
            }
            Err(e) => {
                warn!("Failed to compute hash for {}: {}", path.display(), e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compute_sha256() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"Hello, World!").unwrap();
        temp.flush().unwrap();

        let engine = HashEngine::new();
        let hash = engine.compute_sha256(temp.path()).unwrap();
        
        assert_eq!(hash, "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
    }

    #[test]
    fn test_is_known_malware() {
        let mut engine = HashEngine::new();
        engine.load_threat_hashes(vec![
            "abc123".to_string(),
            "def456".to_string(),
        ]);

        assert!(engine.is_known_malware("abc123"));
        assert!(engine.is_known_malware("def456"));
        assert!(!engine.is_known_malware("unknown"));
    }

    #[test]
    fn test_analyze_file_clean() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"This is a clean file").unwrap();
        temp.flush().unwrap();

        let engine = HashEngine::new();
        let result = engine.analyze_file(temp.path());
        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_file_malware() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"malware content").unwrap();
        temp.flush().unwrap();

        let hash = {
            let engine = HashEngine::new();
            engine.compute_sha256(temp.path()).unwrap()
        };

        let mut engine = HashEngine::new();
        engine.load_threat_hashes(vec![hash]);

        let result = engine.analyze_file(temp.path());
        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(detection.detection_engine, DetectionEngine::Hash);
        assert_eq!(detection.confidence, 1.0);
        assert_eq!(detection.score_contribution, 100);
    }

    #[test]
    fn test_analyze_nonexistent_file() {
        let engine = HashEngine::new();
        let result = engine.analyze_file(Path::new("/nonexistent/file"));
        assert!(result.is_none());
    }
}
