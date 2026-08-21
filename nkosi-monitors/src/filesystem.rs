use crate::event_bus::{EventBus, FileMetadata, MonitorEvent};
use nkosi_common::types::EventType;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

pub struct FilesystemMonitor {
    watched_paths: Vec<PathBuf>,
    excluded_paths: Vec<PathBuf>,
    event_bus: Arc<EventBus>,
}

impl FilesystemMonitor {
    pub fn new(
        watched_paths: Vec<PathBuf>,
        excluded_paths: Vec<PathBuf>,
        event_bus: Arc<EventBus>,
    ) -> Self {
        Self {
            watched_paths,
            excluded_paths,
            event_bus,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Starting filesystem monitor");

        let watched = Self::expand_patterns(&self.watched_paths);

        for path in &watched {
            if path.exists() {
                info!("Watching: {}", path.display());
            } else {
                warn!("Path does not exist: {}", path.display());
            }
        }

        let event_bus = self.event_bus.clone();
        let excluded = self.excluded_paths.clone();

        tokio::spawn(async move {
            Self::monitor_loop(event_bus, watched, excluded).await;
        });

        Ok(())
    }

    fn expand_patterns(patterns: &[PathBuf]) -> Vec<PathBuf> {
        let mut expanded = Vec::new();
        for pattern in patterns {
            let pattern_str = pattern.to_string_lossy();
            if pattern_str.contains('*') {
                let matches = Self::expand_glob(&pattern_str);
                if matches.is_empty() {
                    warn!("No match for watched path pattern: {}", pattern_str);
                } else {
                    expanded.extend(matches);
                }
            } else {
                expanded.push(pattern.clone());
            }
        }
        expanded
    }

    fn expand_glob(pattern: &str) -> Vec<PathBuf> {
        let mut current: Vec<PathBuf> = vec![PathBuf::from("/")];
        for component in pattern.split('/').filter(|c| !c.is_empty()) {
            let mut next = Vec::new();
            for base in &current {
                if !component.contains('*') {
                    next.push(base.join(component));
                } else if let Ok(entries) = std::fs::read_dir(base) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if Self::match_component(&name, component) {
                            next.push(base.join(&name));
                        }
                    }
                }
            }
            current = next;
        }
        current.into_iter().filter(|p| p.exists()).collect()
    }

    fn match_component(name: &str, pattern: &str) -> bool {
        match pattern.split_once('*') {
            None => name == pattern,
            Some((prefix, suffix)) => {
                name.starts_with(prefix)
                    && name.ends_with(suffix)
                    && name.len() >= prefix.len() + suffix.len()
            }
        }
    }

    async fn monitor_loop(
        event_bus: Arc<EventBus>,
        watched_paths: Vec<PathBuf>,
        excluded_paths: Vec<PathBuf>,
    ) {
        let mut known_files: std::collections::HashMap<PathBuf, std::time::SystemTime> = 
            std::collections::HashMap::new();

        // Initial scan
        for path in &watched_paths {
            if path.exists() {
                Self::scan_directory(path, &excluded_paths, &mut known_files);
            }
        }

        // Monitor loop
        loop {
            for path in &watched_paths {
                if path.exists() {
                    let mut current_files: std::collections::HashMap<PathBuf, std::time::SystemTime> = 
                        std::collections::HashMap::new();
                    
                    Self::scan_directory(path, &excluded_paths, &mut current_files);

                    // Check for new files
                    for (file_path, modified) in &current_files {
                        if !known_files.contains_key(file_path) {
                            let metadata = Self::get_metadata(file_path);
                            let monitor_event = MonitorEvent::FileEvent {
                                path: file_path.to_string_lossy().to_string(),
                                event_type: EventType::FileCreated,
                                metadata,
                            };
                            event_bus.send(monitor_event);
                        } else if let Some(old_modified) = known_files.get(file_path) {
                            if modified > old_modified {
                                let metadata = Self::get_metadata(file_path);
                                let monitor_event = MonitorEvent::FileEvent {
                                    path: file_path.to_string_lossy().to_string(),
                                    event_type: EventType::FileModified,
                                    metadata,
                                };
                                event_bus.send(monitor_event);
                            }
                        }
                    }

                    // Check for deleted files
                    for (file_path, _) in &known_files {
                        if !current_files.contains_key(file_path) {
                            let metadata = FileMetadata {
                                size: 0,
                                permissions: String::new(),
                                owner: None,
                                modified: None,
                            };
                            let monitor_event = MonitorEvent::FileEvent {
                                path: file_path.to_string_lossy().to_string(),
                                event_type: EventType::FileDeleted,
                                metadata,
                            };
                            event_bus.send(monitor_event);
                        }
                    }

                    known_files = current_files;
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }

    fn scan_directory(
        path: &Path,
        excluded: &[PathBuf],
        files: &mut std::collections::HashMap<PathBuf, std::time::SystemTime>,
    ) {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                
                if Self::is_excluded(&file_path, excluded) {
                    continue;
                }

                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        if let Ok(modified) = metadata.modified() {
                            files.insert(file_path, modified);
                        }
                    } else if metadata.is_dir() {
                        Self::scan_directory(&file_path, excluded, files);
                    }
                }
            }
        }
    }

    fn is_excluded(path: &Path, excluded: &[PathBuf]) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in excluded {
            if let Some(pattern_str) = pattern.to_str() {
                if path_str.contains(pattern_str) {
                    return true;
                }
            }
        }
        false
    }

    fn get_metadata(path: &Path) -> FileMetadata {
        let mut metadata = FileMetadata {
            size: 0,
            permissions: String::new(),
            owner: None,
            modified: None,
        };

        if let Ok(meta) = std::fs::metadata(path) {
            metadata.size = meta.len();
            metadata.permissions = format!("{:?}", meta.permissions());
            
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                metadata.owner = Some(format!("uid:{}", meta.uid()));
            }

            if let Ok(modified) = meta.modified() {
                if let Ok(time) = modified.duration_since(std::time::UNIX_EPOCH) {
                    metadata.modified = Some(format!("{}", time.as_secs()));
                }
            }
        }

        metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_component() {
        assert!(FilesystemMonitor::match_component("clodlin", "*"));
        assert!(FilesystemMonitor::match_component("cron.d", "cron.*"));
        assert!(FilesystemMonitor::match_component("cron.daily", "cron.*"));
        assert!(!FilesystemMonitor::match_component("etc", "cron.*"));
        assert!(FilesystemMonitor::match_component("home", "home"));
        assert!(!FilesystemMonitor::match_component("homes", "home"));
    }

    #[test]
    fn test_expand_patterns_without_glob() {
        let patterns = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
        let expanded = FilesystemMonitor::expand_patterns(&patterns);
        assert_eq!(expanded, patterns);
    }

    #[test]
    fn test_expand_glob() {
        let base = std::env::temp_dir().join("nkosi-glob-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("user1/.config/autostart")).unwrap();
        std::fs::create_dir_all(base.join("user2/.config/autostart")).unwrap();

        let pattern = format!("{}/user*/.config/autostart", base.display());
        let mut matches = FilesystemMonitor::expand_glob(&pattern);
        matches.sort();

        assert_eq!(matches.len(), 2);
        assert!(matches[0].ends_with("user1/.config/autostart"));
        assert!(matches[1].ends_with("user2/.config/autostart"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_expand_glob_no_match() {
        let pattern = "/nkosi-nonexistent-xyz/*/autostart";
        assert!(FilesystemMonitor::expand_glob(pattern).is_empty());
    }

    #[test]
    fn test_expand_patterns_mixed() {
        let base = std::env::temp_dir().join("nkosi-glob-test2");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("alice/.config/autostart")).unwrap();

        let patterns = vec![
            PathBuf::from("/tmp"),
            PathBuf::from(format!("{}/*/.config/autostart", base.display())),
        ];
        let expanded = FilesystemMonitor::expand_patterns(&patterns);

        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0], PathBuf::from("/tmp"));
        assert!(expanded[1].ends_with("alice/.config/autostart"));

        let _ = std::fs::remove_dir_all(&base);
    }
}
