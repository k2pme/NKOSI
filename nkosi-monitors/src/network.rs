use crate::event_bus::{EventBus, MonitorEvent};
use nkosi_common::types::EventType;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub pid: Option<u32>,
    pub state: String,
}

pub struct NetworkMonitor {
    event_bus: Arc<EventBus>,
    known_connections: HashMap<String, NetworkConnection>,
}

impl NetworkMonitor {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self {
            event_bus,
            known_connections: HashMap::new(),
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        info!("Starting network monitor");
        
        let event_bus = self.event_bus.clone();
        
        tokio::spawn(async move {
            Self::monitor_loop(event_bus).await;
        });

        Ok(())
    }

    async fn monitor_loop(event_bus: Arc<EventBus>) {
        loop {
            let connections = Self::get_network_connections();
            
            let mut new_connections = Vec::new();
            
            for conn in connections {
                let key = format!("{}:{}-{}:{}", 
                    conn.local_addr, conn.local_port,
                    conn.remote_addr, conn.remote_port);
                
                if !Self::is_known_connection(&key) {
                    new_connections.push(conn);
                }
            }

            for conn in new_connections {
                let event = MonitorEvent::NetworkEvent {
                    pid: conn.pid.unwrap_or(0),
                    local_addr: conn.local_addr.clone(),
                    remote_addr: conn.remote_addr.clone(),
                    remote_port: conn.remote_port,
                    protocol: conn.protocol.clone(),
                    event_type: EventType::NetworkConnection,
                };
                event_bus.send(event);
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        }
    }

    fn get_network_connections() -> Vec<NetworkConnection> {
        let mut connections = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            Self::parse_net_tcp(&content, &mut connections, "TCP");
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp6") {
            Self::parse_net_tcp(&content, &mut connections, "TCP6");
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/udp") {
            Self::parse_net_tcp(&content, &mut connections, "UDP");
        }

        connections
    }

    fn parse_net_tcp(content: &str, connections: &mut Vec<NetworkConnection>, protocol: &str) {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let local_addr = Self::parse_ip_port(parts[1]);
                let remote_addr = Self::parse_ip_port(parts[2]);
                let state = Self::parse_state(parts[3]);
                let inode = parts[9].parse::<u32>().unwrap_or(0);

                if let Some((local_ip, local_port)) = local_addr {
                    if let Some((remote_ip, remote_port)) = remote_addr {
                        connections.push(NetworkConnection {
                            local_addr: local_ip,
                            local_port,
                            remote_addr: remote_ip,
                            remote_port,
                            protocol: protocol.to_string(),
                            pid: Self::find_pid_by_inode(inode),
                            state,
                        });
                    }
                }
            }
        }
    }

    fn parse_ip_port(addr: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() == 2 {
            let ip_hex = parts[0];
            let port_hex = parts[1];
            
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                let ip = Self::parse_hex_ip(ip_hex);
                return Some((ip, port));
            }
        }
        None
    }

    fn parse_hex_ip(hex: &str) -> String {
        if hex.len() == 8 {
            let bytes: Vec<u8> = (0..8)
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
                .collect();
            
            if bytes.len() == 4 {
                return format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
            }
        }
        hex.to_string()
    }

    fn parse_state(state_hex: &str) -> String {
        match state_hex {
            "01" => "ESTABLISHED".to_string(),
            "02" => "SYN_SENT".to_string(),
            "03" => "SYN_RECV".to_string(),
            "04" => "FIN_WAIT1".to_string(),
            "05" => "FIN_WAIT2".to_string(),
            "06" => "TIME_WAIT".to_string(),
            "07" => "CLOSE".to_string(),
            "08" => "CLOSE_WAIT".to_string(),
            "09" => "LAST_ACK".to_string(),
            "0A" => "LISTEN".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }

    fn find_pid_by_inode(inode: u32) -> Option<u32> {
        let proc_dir = std::path::PathBuf::from("/proc");
        if !proc_dir.exists() {
            return None;
        }

        if let Ok(entries) = std::fs::read_dir(&proc_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Ok(pid) = name.to_str().unwrap_or("").parse::<u32>() {
                    let fd_dir = format!("/proc/{}/fd", pid);
                    if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                        for fd in fds.flatten() {
                            if let Ok(link) = std::fs::read_link(fd.path()) {
                                let link_str = link.to_string_lossy();
                                if link_str.contains(&format!("socket:[{}]", inode)) {
                                    return Some(pid);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn is_known_connection(_key: &str) -> bool {
        std::path::PathBuf::from("/proc/net/tcp").exists()
    }

    pub fn get_known_connections(&self) -> &HashMap<String, NetworkConnection> {
        &self.known_connections
    }
}
