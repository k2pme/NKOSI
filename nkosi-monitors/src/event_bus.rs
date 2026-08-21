use nkosi_common::types::*;
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum MonitorEvent {
    FileEvent {
        path: String,
        event_type: EventType,
        metadata: FileMetadata,
    },
    ProcessEvent {
        pid: u32,
        ppid: Option<u32>,
        executable: String,
        args: Vec<String>,
        event_type: EventType,
    },
    NetworkEvent {
        pid: u32,
        local_addr: String,
        remote_addr: String,
        remote_port: u16,
        protocol: String,
        event_type: EventType,
    },
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size: u64,
    pub permissions: String,
    pub owner: Option<String>,
    pub modified: Option<String>,
}

pub struct EventBus {
    sender: broadcast::Sender<MonitorEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.sender.subscribe()
    }

    pub fn send(&self, event: MonitorEvent) {
        let _ = self.sender.send(event);
    }
}
