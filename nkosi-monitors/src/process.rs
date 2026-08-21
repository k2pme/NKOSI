use crate::event_bus::{EventBus, MonitorEvent};
use nkosi_common::types::EventType;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

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
}

impl ProcessMonitor {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self {
            event_bus,
            known_pids: HashMap::new(),
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        info!("Starting process monitor");
        
        self.scan_existing_processes().await?;
        
        let event_bus = self.event_bus.clone();
        
        tokio::spawn(async move {
            Self::monitor_loop(event_bus).await;
        });

        Ok(())
    }

    async fn scan_existing_processes(&mut self) -> anyhow::Result<()> {
        let proc_dir = PathBuf::from("/proc");
        
        if !proc_dir.exists() {
            warn!("/proc not available, process monitoring limited");
            return Ok(());
        }

        for entry in std::fs::read_dir(&proc_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            
            if let Some(pid_str) = name.to_str() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if let Some(info) = Self::get_process_info(pid) {
                        self.known_pids.insert(pid, info);
                    }
                }
            }
        }

        debug!("Scanned {} existing processes", self.known_pids.len());
        Ok(())
    }

    async fn monitor_loop(event_bus: Arc<EventBus>) {
        loop {
            let mut current_pids = HashMap::new();
            
            let proc_dir = PathBuf::from("/proc");
            if proc_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&proc_dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        if let Some(pid_str) = name.to_str() {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                if let Some(info) = Self::get_process_info(pid) {
                                    current_pids.insert(pid, info);
                                }
                            }
                        }
                    }
                }
            }

            let new_pids: Vec<u32> = current_pids.keys()
                .filter(|pid| !Self::is_known_pid(**pid))
                .cloned()
                .collect();

            for pid in new_pids {
                if let Some(info) = current_pids.get(&pid) {
                    let event = MonitorEvent::ProcessEvent {
                        pid: info.pid,
                        ppid: info.ppid,
                        executable: info.executable.clone(),
                        args: info.args.clone(),
                        event_type: EventType::ProcessStarted,
                    };
                    event_bus.send(event);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
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

        let ppid = std::fs::read_to_string(format!("{}/stat", proc_path))
            .ok()
            .and_then(|s| {
                let parts: Vec<&str> = s.split_whitespace().collect();
                if parts.len() > 3 {
                    parts[3].parse::<u32>().ok()
                } else {
                    None
                }
            });

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

    fn is_known_pid(pid: u32) -> bool {
        PathBuf::from(format!("/proc/{}", pid)).exists()
    }

    pub fn get_known_pids(&self) -> &HashMap<u32, ProcessInfo> {
        &self.known_pids
    }
}
