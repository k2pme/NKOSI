use crate::event_bus::{EventBus, MonitorEvent};
use nkosi_common::types::EventType;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, info};

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

struct InodeCache {
    map: HashMap<u32, u32>,
    last_refresh: Option<Instant>,
}

impl InodeCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            last_refresh: None,
        }
    }
}

pub struct NetworkMonitor {
    event_bus: Arc<EventBus>,
    known_connections: HashMap<String, NetworkConnection>,
    inode_cache: Arc<Mutex<InodeCache>>,
}

impl NetworkMonitor {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        let inode_cache = Arc::new(Mutex::new(InodeCache::new()));
        // Build initial cache so first events already carry PIDs
        if let Ok(mut cache) = inode_cache.try_lock() {
            cache.map = Self::scan_inode_map();
            cache.last_refresh = Some(Instant::now());
            info!("Network monitor inode cache primed: {} sockets", cache.map.len());
        }

        Self {
            event_bus,
            known_connections: HashMap::new(),
            inode_cache,
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        info!("Starting network monitor");

        let event_bus = self.event_bus.clone();
        let inode_cache = self.inode_cache.clone();
        let known: HashSet<String> = self.known_connections.keys().cloned().collect();

        tokio::spawn(async move {
            Self::monitor_loop(event_bus, inode_cache, known).await;
        });

        Ok(())
    }

    async fn monitor_loop(
        event_bus: Arc<EventBus>,
        inode_cache: Arc<Mutex<InodeCache>>,
        mut known_keys: HashSet<String>,
    ) {
        loop {
            let connections = Self::get_network_connections(&inode_cache);
            let mut current_keys = HashSet::new();

            for conn in connections {
                let key = format!(
                    "{}:{}-{}:{}-{}",
                    conn.protocol, conn.local_addr, conn.local_port,
                    conn.remote_addr, conn.remote_port
                );
                current_keys.insert(key.clone());

                if !known_keys.contains(&key) && conn.state != "LISTEN" {
                    debug!(
                        "New connection {} {}:{} -> {}:{} (pid {:?})",
                        conn.protocol, conn.local_addr, conn.local_port,
                        conn.remote_addr, conn.remote_port, conn.pid
                    );
                    event_bus.send(MonitorEvent::NetworkEvent {
                        pid: conn.pid.unwrap_or(0),
                        local_addr: conn.local_addr.clone(),
                        remote_addr: conn.remote_addr.clone(),
                        remote_port: conn.remote_port,
                        protocol: conn.protocol.clone(),
                        event_type: EventType::NetworkConnection,
                    });
                }
            }

            known_keys = current_keys;

            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        }
    }

    fn get_network_connections(inode_cache: &Arc<Mutex<InodeCache>>) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            Self::parse_net_tcp(&content, &mut connections, "TCP", inode_cache);
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp6") {
            Self::parse_net_tcp(&content, &mut connections, "TCP6", inode_cache);
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/udp") {
            Self::parse_net_tcp(&content, &mut connections, "UDP", inode_cache);
        }

        connections
    }

    fn parse_net_tcp(
        content: &str,
        connections: &mut Vec<NetworkConnection>,
        protocol: &str,
        inode_cache: &Arc<Mutex<InodeCache>>,
    ) {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let local_addr = Self::parse_ip_port(parts[1]);
                let remote_addr = Self::parse_ip_port(parts[2]);
                let state = Self::parse_state(parts[3]);
                let inode = parts[9].parse::<u32>().unwrap_or(0);

                if let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) =
                    (local_addr, remote_addr)
                {
                    connections.push(NetworkConnection {
                        local_addr: local_ip,
                        local_port,
                        remote_addr: remote_ip,
                        remote_port,
                        protocol: protocol.to_string(),
                        pid: Self::find_pid_by_inode(inode, inode_cache),
                        state,
                    });
                }
            }
        }
    }

    /// Résout un inode socket en PID via le cache ; rafraîchit si absent.
    fn find_pid_by_inode(inode: u32, cache: &Arc<Mutex<InodeCache>>) -> Option<u32> {
        {
            let guard = match cache.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    tracing::error!("Mutex empoisonné dans network monitor, récupération: {}", e);
                    e.into_inner()
                }
            };
            if let Some(pid) = guard.map.get(&inode) {
                return Some(*pid);
            }
        }

        // Cache miss: full refresh of the inode map
        let map = Self::scan_inode_map();
        let mut guard = match cache.lock() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("Mutex empoisonné dans network monitor, récupération: {}", e);
                e.into_inner()
            }
        };
        guard.map = map;
        guard.last_refresh = Some(Instant::now());
        guard.map.get(&inode).copied()
    }

    /// Construit la table socket inode -> PID en parcourant /proc/*/fd une seule fois.
    fn scan_inode_map() -> HashMap<u32, u32> {
        let mut map = HashMap::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return map;
        };

        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let fd_dir = format!("/proc/{}/fd", pid);
            let Ok(fds) = std::fs::read_dir(&fd_dir) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd.path()) {
                    let link_str = link.to_string_lossy();
                    if link_str.starts_with("socket:[")
                        && let Some(inner) = link_str
                            .strip_prefix("socket:[")
                            .and_then(|s| s.strip_suffix(']'))
                            .and_then(|s| s.parse::<u32>().ok())
                    {
                        map.insert(inner, pid);
                    }
                }
            }
        }

        map
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
                .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
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

    pub fn get_known_connections(&self) -> &HashMap<String, NetworkConnection> {
        &self.known_connections
    }
}
