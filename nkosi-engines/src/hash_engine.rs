use lru::LruCache;
use nkosi_common::types::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

pub struct HashEngine {
    known_hashes: RwLock<HashSet<String>>,
    sha256_cache: Mutex<LruCache<String, String>>,
}

impl Default for HashEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HashEngine {
    pub fn new() -> Self {
        Self {
            known_hashes: RwLock::new(HashSet::new()),
            sha256_cache: Mutex::new(LruCache::new(NonZeroUsize::new(10000).unwrap())),
        }
    }

    pub fn load_threat_hashes(&self, hashes: Vec<String>) {
        let count = hashes.len();
        *self.known_hashes.write().unwrap_or_else(|e| e.into_inner()) =
            hashes.into_iter().collect();
        self.sha256_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        info!("Loaded {} threat hashes", count);
    }

    pub fn compute_sha256(&self, path: &Path) -> anyhow::Result<String> {
        // A path alone is unsafe: a modified file must never reuse a stale digest.
        let metadata = std::fs::metadata(path)?;
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let key = format!("{}:{}:{}", path.display(), metadata.len(), modified);
        {
            let mut cache = self.sha256_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.get(&key) {
                return Ok(cached.clone());
            }
        }

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

        let result = format!("{:x}", hasher.finalize());
        self.sha256_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key, result.clone());
        Ok(result)
    }

    pub fn is_known_malware(&self, hash: &str) -> bool {
        self.known_hashes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(hash)
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
                        incident_id: None,
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

        assert_eq!(
            hash,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[test]
    fn test_is_known_malware() {
        let engine = HashEngine::new();
        engine.load_threat_hashes(vec!["abc123".to_string(), "def456".to_string()]);

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

        let engine = HashEngine::new();
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

    #[test]
    fn test_cache_is_invalidated_when_file_changes() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"first").unwrap();
        temp.flush().unwrap();

        let engine = HashEngine::new();
        let first = engine.compute_sha256(temp.path()).unwrap();
        std::fs::write(temp.path(), b"a longer replacement payload").unwrap();
        let second = engine.compute_sha256(temp.path()).unwrap();

        assert_ne!(
            first, second,
            "a modified file must not reuse a cached digest"
        );
    }
}
