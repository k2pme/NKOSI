use crate::event_bus::{EventBus, MonitorEvent};
use nkosi_common::types::EventType;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

const MAX_TREE_ENTRIES: usize = 50_000;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub executable: String,
    pub args: Vec<String>,
    pub user: Option<String>,
}

pub struct ProcessMonitor {
    event_bus: Arc<EventBus>,
    known_pids: HashMap<u32, ProcessInfo>,
    process_tree: Arc<Mutex<HashMap<u32, u32>>>,
}

impl ProcessMonitor {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self {
            event_bus,
            known_pids: HashMap::new(),
            process_tree: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        info!("Starting process monitor");

        self.scan_existing_processes().await?;

        let event_bus = self.event_bus.clone();
        let process_tree = self.process_tree.clone();
        let initial = self.known_pids.clone();

        tokio::spawn(async move {
            Self::monitor_loop(event_bus, process_tree, initial).await;
        });

        Ok(())
    }

    async fn scan_existing_processes(&mut self) -> anyhow::Result<()> {
        if !PathBuf::from("/proc").exists() {
            warn!("/proc not available, process monitoring limited");
            return Ok(());
        }

        for pid in list_pids() {
            if let Some(info) = Self::get_process_info(pid) {
                if let Some(ppid) = info.ppid {
                    Self::record_lineage(&self.process_tree, pid, ppid);
                }
                self.known_pids.insert(pid, info);
            }
        }

        debug!("Scanned {} existing processes", self.known_pids.len());
        Ok(())
    }

    fn record_lineage(tree: &Mutex<HashMap<u32, u32>>, pid: u32, ppid: u32) {
        let mut guard = match tree.lock() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("Mutex empoisonné dans process monitor, récupération: {}", e);
                e.into_inner()
            }
        };
        guard.insert(pid, ppid);
        if guard.len() > MAX_TREE_ENTRIES {
            // Evict oldest half (HashMap has no order; drop arbitrary keys beyond cap)
            let excess = guard.len() - MAX_TREE_ENTRIES / 2;
            let keys: Vec<u32> = guard.keys().take(excess).cloned().collect();
            for k in keys {
                guard.remove(&k);
            }
        }
    }

    async fn monitor_loop(
        event_bus: Arc<EventBus>,
        process_tree: Arc<Mutex<HashMap<u32, u32>>>,
        mut known: HashMap<u32, ProcessInfo>,
    ) {
        loop {
            let mut current: HashMap<u32, ProcessInfo> = HashMap::new();
            for pid in list_pids() {
                if let Some(info) = Self::get_process_info(pid) {
                    if let Some(ppid) = info.ppid {
                        Self::record_lineage(&process_tree, pid, ppid);
                    }
                    current.insert(pid, info);
                }
            }

            // New processes
            for (pid, info) in &current {
                if !known.contains_key(pid) {
                    debug!("Process started: {} ({})", info.executable, pid);
                    event_bus.send(MonitorEvent::ProcessEvent {
                        pid: info.pid,
                        ppid: info.ppid,
                        executable: info.executable.clone(),
                        args: info.args.clone(),
                        event_type: EventType::ProcessStarted,
                    });
                }
            }

            // Exited processes
            for (pid, info) in &known {
                if !current.contains_key(pid) {
                    debug!("Process exited: {} ({})", info.executable, pid);
                    event_bus.send(MonitorEvent::ProcessEvent {
                        pid: *pid,
                        ppid: info.ppid,
                        executable: info.executable.clone(),
                        args: Vec::new(),
                        event_type: EventType::ProcessExited,
                    });
                }
            }

            known = current;

            tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
        }
    }

    /// Reconstitue la chaîne d'ancêtres d'un PID (y compris processus terminés).
    pub fn get_lineage(&self, pid: u32) -> Vec<u32> {
        let tree = match self.process_tree.lock() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("Mutex empoisonné dans process monitor, récupération: {}", e);
                e.into_inner()
            }
        };
        let mut lineage = vec![pid];
        let mut current = pid;
        for _ in 0..32 {
            match tree.get(&current) {
                Some(&ppid) if ppid != current && !lineage.contains(&ppid) => {
                    lineage.push(ppid);
                    current = ppid;
                }
                _ => break,
            }
        }
        lineage
    }

    fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        let proc_path = format!("/proc/{}", pid);

        let executable = std::fs::read_link(format!("{}/exe", proc_path))
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        let args = std::fs::read_to_string(format!("{}/cmdline", proc_path))
            .ok()
            .map(|s| {
                s.split('\0')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let stat = std::fs::read_to_string(format!("{}/stat", proc_path)).ok()?;
        // The comm field may contain spaces; it is enclosed in parentheses.
        let close = stat.rfind(')')?;
        let rest = &stat[close + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // fields[0] == state, fields[1] == ppid
        let ppid = fields.get(1).and_then(|s| s.parse::<u32>().ok());

        let user = std::fs::read_to_string(format!("{}/status", proc_path))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|line| line.starts_with("Uid:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .map(|s| s.to_string())
            });

        Some(ProcessInfo {
            pid,
            ppid,
            executable,
            args,
            user,
        })
    }

    pub fn get_known_pids(&self) -> &HashMap<u32, ProcessInfo> {
        &self.known_pids
    }
}

fn list_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                pids.push(pid);
            }
        }
    }
    pids
}
