use crate::event_bus::{EventBus, FileMetadata, MonitorEvent};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use nkosi_common::types::EventType;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

const IN_CREATE: u32 = 0x0000_0100;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_DELETE: u32 = 0x0000_0200;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MODIFY: u32 = 0x0000_0002;
const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_ISDIR: u32 = 0x4000_0000;

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
        let watched: Vec<PathBuf> = watched.into_iter().filter(|p| p.exists()).collect();

        for path in &watched {
            info!("Watching: {}", path.display());
        }

        let event_bus = self.event_bus.clone();
        let excluded = self.excluded_paths.clone();

        // The recursive inotify watch setup can be very expensive on large
        // watched trees (e.g. a full /home). Run it in a dedicated blocking
        // thread so the agent's main loop is never delayed (start returns at
        // once and the agent can proceed to connect/register with the central).
        std::thread::spawn(move || match Inotify::init(InitFlags::empty()) {
            Ok(inotify) => {
                let mut backend = InotifyBackend {
                    inotify,
                    watch_dirs: HashMap::new(),
                    excluded: excluded.clone(),
                    watch_budget: Self::inotify_watch_limit().saturating_sub(256),
                };
                for root in &watched {
                    backend.add_watch_recursive(root);
                }
                if !backend.watch_dirs.is_empty() {
                    info!(
                        "Real-time monitoring active (inotify), {} directories watched",
                        backend.watch_dirs.len()
                    );
                    backend.run(event_bus);
                } else {
                    warn!("inotify: no directory could be watched, falling back to polling");
                    let bus = event_bus.clone();
                    let watched = watched.clone();
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().expect("rt");
                        rt.block_on(Self::polling_loop(bus, watched, excluded));
                    });
                }
            }
            Err(e) => {
                warn!("inotify unavailable ({}), falling back to polling", e);
                let bus = event_bus.clone();
                let watched = watched.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().expect("rt");
                    rt.block_on(Self::polling_loop(bus, watched, excluded));
                });
            }
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

    /// Lit fs.inotify.max_user_watches (fallback 8192).
    fn inotify_watch_limit() -> usize {
        std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(8192)
    }

    /// Exclusion : pattern littéral → sous-chaîne ; pattern avec `*` → glob
    /// (le match exact OU tout chemin situé sous le répertoire correspondant).
    pub fn is_excluded(path: &Path, excluded: &[PathBuf]) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in excluded {
            let Some(p) = pattern.to_str() else { continue };
            if p.contains('*') {
                let base = p.trim_end_matches('/');
                if Self::wildcard_match(&path_str, base)
                    || Self::wildcard_match(&path_str, &format!("{}/*", base))
                {
                    return true;
                }
            } else if path_str.contains(p) {
                return true;
            }
        }
        false
    }

    /// Glob classique : `*` = n'importe quelle séquence (y compris `/`).
    fn wildcard_match(s: &str, p: &str) -> bool {
        let s: Vec<char> = s.chars().collect();
        let p: Vec<char> = p.chars().collect();
        let (mut si, mut pi) = (0usize, 0usize);
        let (mut star, mut mark) = (None::<usize>, 0usize);
        while si < s.len() {
            if pi < p.len() && p[pi] == s[si] {
                si += 1;
                pi += 1;
            } else if pi < p.len() && p[pi] == '*' {
                star = Some(pi);
                mark = si;
                pi += 1;
            } else if let Some(sp) = star {
                pi = sp + 1;
                mark += 1;
                si = mark;
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == '*' {
            pi += 1;
        }
        pi == p.len()
    }

    async fn polling_loop(
        event_bus: Arc<EventBus>,
        watched_paths: Vec<PathBuf>,
        excluded: Vec<PathBuf>,
    ) {
        warn!("Using polling fallback (1s interval)");
        let mut known_files: HashMap<PathBuf, std::time::SystemTime> = HashMap::new();

        for path in &watched_paths {
            if path.exists() {
                Self::scan_directory(path, &excluded, &mut known_files);
            }
        }

        loop {
            for path in &watched_paths {
                if path.exists() {
                    let mut current_files: HashMap<PathBuf, std::time::SystemTime> = HashMap::new();

                    Self::scan_directory(path, &excluded, &mut current_files);

                    for (file_path, modified) in &current_files {
                        if !known_files.contains_key(file_path) {
                            let metadata = Self::get_metadata(file_path);
                            event_bus.send(MonitorEvent::FileEvent {
                                path: file_path.to_string_lossy().to_string(),
                                event_type: EventType::FileCreated,
                                metadata,
                            });
                        } else if let Some(old_modified) = known_files.get(file_path)
                            && modified > old_modified
                        {
                            let metadata = Self::get_metadata(file_path);
                            event_bus.send(MonitorEvent::FileEvent {
                                path: file_path.to_string_lossy().to_string(),
                                event_type: EventType::FileModified,
                                metadata,
                            });
                        }
                    }

                    for file_path in known_files.keys() {
                        if !current_files.contains_key(file_path) {
                            let metadata = FileMetadata {
                                size: 0,
                                permissions: String::new(),
                                owner: None,
                                modified: None,
                            };
                            event_bus.send(MonitorEvent::FileEvent {
                                path: file_path.to_string_lossy().to_string(),
                                event_type: EventType::FileDeleted,
                                metadata,
                            });
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
        files: &mut HashMap<PathBuf, std::time::SystemTime>,
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

            if let Ok(modified) = meta.modified()
                && let Ok(time) = modified.duration_since(std::time::UNIX_EPOCH)
            {
                metadata.modified = Some(format!("{}", time.as_secs()));
            }
        }

        metadata
    }
}

struct InotifyBackend {
    inotify: Inotify,
    watch_dirs: HashMap<WatchDescriptor, PathBuf>,
    excluded: Vec<PathBuf>,
    watch_budget: usize,
}

impl InotifyBackend {
    /// Ajoute un watch sur dir et ses sous-répertoires (hors exclusions).
    fn add_watch_recursive(&mut self, dir: &Path) {
        if self.watch_dirs.len() >= self.watch_budget {
            return;
        }
        self.add_watch(dir);
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if self.watch_dirs.len() >= self.watch_budget {
                    warn!(
                        "inotify watch budget reached ({}), some subdirectories are not watched",
                        self.watch_budget
                    );
                    return;
                }
                let path = entry.path();
                if FilesystemMonitor::is_excluded(&path, &self.excluded) {
                    continue;
                }
                if path.is_dir() {
                    self.add_watch_recursive(&path);
                }
            }
        }
    }

    fn add_watch(&mut self, dir: &Path) {
        let flags = AddWatchFlags::IN_CREATE
            | AddWatchFlags::IN_MODIFY
            | AddWatchFlags::IN_DELETE
            | AddWatchFlags::IN_MOVED_FROM
            | AddWatchFlags::IN_MOVED_TO
            | AddWatchFlags::IN_CLOSE_WRITE;
        match self.inotify.add_watch(dir, flags) {
            Ok(wd) => {
                self.watch_dirs.insert(wd, dir.to_path_buf());
                debug!("inotify watch added: {}", dir.display());
            }
            Err(e) => {
                debug!("inotify watch failed on {}: {}", dir.display(), e);
            }
        }
    }

    fn run(mut self, event_bus: Arc<EventBus>) {
        loop {
            match self.inotify.read_events() {
                Ok(events) => {
                    for event in events {
                        let Some(dir) = self.watch_dirs.get(&event.wd).cloned() else {
                            continue;
                        };
                        let Some(name_os) = event.name else {
                            continue;
                        };
                        let Some(name) = name_os.to_str() else {
                            continue;
                        };
                        let full_path = dir.join(name);

                        if FilesystemMonitor::is_excluded(&full_path, &self.excluded) {
                            continue;
                        }

                        let mask = event.mask.bits();

                        // Nouveau répertoire : le surveiller récursivement
                        if mask & IN_ISDIR != 0
                            && (mask & IN_CREATE != 0 || mask & IN_MOVED_TO != 0)
                        {
                            self.add_watch_recursive(&full_path);
                            continue;
                        }

                        let event_type = if mask & IN_CREATE != 0 || mask & IN_MOVED_TO != 0 {
                            EventType::FileCreated
                        } else if mask & IN_MODIFY != 0 || mask & IN_CLOSE_WRITE != 0 {
                            EventType::FileModified
                        } else if mask & IN_DELETE != 0 || mask & IN_MOVED_FROM != 0 {
                            EventType::FileDeleted
                        } else {
                            continue;
                        };

                        debug!("fs event {:?}: {}", event_type, full_path.display());

                        event_bus.send(MonitorEvent::FileEvent {
                            path: full_path.to_string_lossy().to_string(),
                            event_type,
                            metadata: FilesystemMonitor::get_metadata(&full_path),
                        });
                    }
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    warn!("inotify read failed ({}), monitor stopped", e);
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_match() {
        assert!(FilesystemMonitor::wildcard_match(
            "/home/bob/.cache",
            "/home/*/.cache"
        ));
        assert!(!FilesystemMonitor::wildcard_match(
            "/home/bob/docs",
            "/home/*/.cache"
        ));
        assert!(FilesystemMonitor::wildcard_match(
            "/home/bob/.cache/opencode/x",
            "/home/*/.cache/*"
        ));
        assert!(FilesystemMonitor::wildcard_match("/a/b/.git", "*/.git"));
        assert!(FilesystemMonitor::wildcard_match(
            "/a/b/.git/objects",
            "*/.git/*"
        ));
    }

    #[test]
    fn test_exclusion_glob_under_dir() {
        let excluded = vec![
            PathBuf::from("/proc"),
            PathBuf::from("/home/*/.cache"),
            PathBuf::from("*/node_modules"),
        ];
        assert!(FilesystemMonitor::is_excluded(
            Path::new("/proc/1/cmdline"),
            &excluded
        ));
        assert!(FilesystemMonitor::is_excluded(
            Path::new("/x/proc/y"),
            &excluded
        ));
        assert!(FilesystemMonitor::is_excluded(
            Path::new("/home/alice/.cache"),
            &excluded
        ));
        assert!(FilesystemMonitor::is_excluded(
            Path::new("/home/alice/.cache/opencode/node_modules/foo"),
            &excluded
        ));
        assert!(FilesystemMonitor::is_excluded(
            Path::new("/srv/app/node_modules/leftpad/index.js"),
            &excluded
        ));
        assert!(!FilesystemMonitor::is_excluded(
            Path::new("/home/alice/documents/report.txt"),
            &excluded
        ));
    }

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
