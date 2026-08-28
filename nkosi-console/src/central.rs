use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::Request;
use tracing::{debug, warn};

#[allow(clippy::module_inception)]
pub mod central {
    tonic::include_proto!("nkosi.central");
}

pub use central::*;
use central::nkosi_central_client::NkosiCentralClient;

/// A queryable snapshot of the aggregated remote agents/events, held in memory
/// and refreshed periodically by the console's background poller. Keeping a
/// snapshot off the HTTP request path makes the REST layer fast and resilient
/// when the central server is temporarily unavailable.
#[derive(Clone, Default)]
pub struct CentralSnapshot {
    pub agents: Vec<AgentInfo>,
    pub heartbeats: Vec<AgentHeartbeat>,
    pub events: Vec<SecurityEvent>,
    pub last_refresh: String,
    pub reachable: bool,
}

#[derive(Clone)]
pub struct CentralClient {
    addr: String,
    conn: Arc<Mutex<Option<NkosiCentralClient<tonic::transport::Channel>>>>,
}

impl CentralClient {
    pub fn new(addr: String) -> Self {
        Self {
            addr,
            conn: Arc::new(Mutex::new(None)),
        }
    }

    async fn client(&self) -> Option<NkosiCentralClient<tonic::transport::Channel>> {
        let mut conn = self.conn.lock().await;
        if let Some(client) = conn.as_ref() {
            return Some(client.clone());
        }
        match NkosiCentralClient::connect(format!("http://{}", self.addr)).await {
            Ok(client) => {
                debug!("Connected to central at {}", self.addr);
                *conn = Some(client.clone());
                Some(client)
            }
            Err(e) => {
                warn!("Central unreachable ({}): {}", self.addr, e);
                None
            }
        }
    }

    /// Fetch a full aggregated snapshot from the central server.
    pub async fn fetch(&self) -> CentralSnapshot {
        let mut snapshot = CentralSnapshot::default();

        let Some(mut client) = self.client().await else {
            return snapshot;
        };

        let agents = match client.get_agents(Request::new(Empty {})).await {
            Ok(resp) => resp.into_inner().agents,
            Err(e) => {
                warn!("get_agents failed: {}", e);
                return snapshot;
            }
        };
        snapshot.reachable = true;
        snapshot.agents = agents;

        // Fetch all events once (host attribution via the `agent_id` field that
        // the central server tags on each event). Also fetch the aggregated
        // stats for totals/online counts.
        if let Ok(resp) = client
            .get_events(Request::new(EventQuery {
                limit: 2000,
                ..Default::default()
            }))
            .await
        {
            snapshot.events = resp.into_inner().events;
        }

        let now = chrono::Utc::now().timestamp();

        // Derive per-agent heartbeat-like status. Because the proto exposes
        // events_count/threats_count only via heartbeats, we derive them from
        // the event stream at console level when no explicit heartbeat RPC is
        // available.
        let counts: std::collections::HashMap<String, (u32, u32)> = {
            let mut m: std::collections::HashMap<String, (u32, u32)> =
                std::collections::HashMap::new();
            for e in &snapshot.events {
                let entry = m.entry(e.agent_id.clone()).or_insert((0, 0));
                entry.0 += 1;
                if matches!(e.severity.as_str(), "Critical" | "High" | "Medium") {
                    entry.1 += 1;
                }
            }
            m
        };

        snapshot.heartbeats = snapshot
            .agents
            .iter()
            .map(|a| {
                let (ev, th) = counts.get(&a.agent_id).copied().unwrap_or((0, 0));
                AgentHeartbeat {
                    agent_id: a.agent_id.clone(),
                    timestamp: now,
                    events_count: ev,
                    threats_count: th,
                    score: 0,
                }
            })
            .collect();

        snapshot.last_refresh = chrono::Utc::now().to_rfc3339();
        snapshot
    }
}

/// Connectivity summary exposed on the API.
pub fn connectivity(snapshot: &CentralSnapshot) -> serde_json::Value {
    serde_json::json!({
        "reachable": snapshot.reachable,
        "last_refresh": snapshot.last_refresh,
    })
}
