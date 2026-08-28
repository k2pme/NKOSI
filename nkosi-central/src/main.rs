use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use nkosi_common::types::*;
use nkosi_db::{AgentRepository, Database, EventRepository};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub mod central {
    tonic::include_proto!("nkosi.central");
}

use central::nkosi_central_server::{NkosiCentral, NkosiCentralServer};
use central::*;

/// Maximum number of events kept in the in-memory ring buffer.
const MAX_IN_MEMORY_EVENTS: usize = 10_000;
/// Upper bound on rows fetched from SQLite when merging/scanning recent events.
const DB_EVENT_LOOKBACK_LIMIT: i32 = 5_000;

fn proto_agent_to_agent(info: &AgentInfo) -> Agent {
    Agent {
        id: info.agent_id.clone(),
        hostname: info.hostname.clone(),
        ip_address: info.ip_address.clone(),
        os_version: info.os_version.clone(),
        nkosi_version: info.nkosi_version.clone(),
        agent_name: info.agent_name.clone(),
        status: AgentStatus::Online,
        last_seen: Utc::now(),
        registered_at: Utc::now(),
        events_count: 0,
        threats_count: 0,
        score: 0,
    }
}

fn proto_event_to_event(se: &SecurityEvent, agent_id: &str) -> Event {
    Event {
        id: uuid::Uuid::parse_str(&se.id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
        timestamp: DateTime::from_timestamp(se.timestamp, 0)
            .unwrap_or_else(Utc::now)
            .with_timezone(&Utc),
        event_type: serde_json::from_str(&format!("\"{}\"", se.event_type))
            .unwrap_or(EventType::FileCreated),
        source_module: se.source_module.clone(),
        pid: None,
        ppid: None,
        user: None,
        file_path: if se.file_path.is_empty() {
            None
        } else {
            Some(se.file_path.clone())
        },
        file_hash: if se.file_hash.is_empty() {
            None
        } else {
            Some(se.file_hash.clone())
        },
        remote_ip: if se.remote_ip.is_empty() {
            None
        } else {
            Some(se.remote_ip.clone())
        },
        remote_port: if se.remote_port == 0 {
            None
        } else {
            Some(se.remote_port as u16)
        },
        domain: if se.domain.is_empty() {
            None
        } else {
            Some(se.domain.clone())
        },
        incident_id: None,
        severity: serde_json::from_str(&format!("\"{}\"", se.severity)).unwrap_or(Severity::Info),
        score: if se.score == 0 { None } else { Some(se.score) },
        action: None,
        result: if se.details.is_empty() {
            None
        } else {
            Some(se.details.clone())
        },
        agent_id: if agent_id.is_empty() {
            None
        } else {
            Some(agent_id.to_string())
        },
        agent_host: None,
    }
}

fn db_agent_to_proto(agent: &Agent) -> AgentInfo {
    AgentInfo {
        agent_id: agent.id.clone(),
        hostname: agent.hostname.clone(),
        ip_address: agent.ip_address.clone(),
        os_version: agent.os_version.clone(),
        nkosi_version: agent.nkosi_version.clone(),
        agent_name: agent.agent_name.clone(),
    }
}

/// Serializes a common-type severity back to its bare variant name (e.g. `High`),
/// matching the plain-string representation used by the protobuf messages.
fn db_event_severity_name(event: &Event) -> String {
    serde_json::to_string(&event.severity)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

fn db_event_to_proto(event: &Event) -> SecurityEvent {
    SecurityEvent {
        id: event.id.to_string(),
        timestamp: event.timestamp.timestamp(),
        event_type: serde_json::to_string(&event.event_type)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string(),
        source_module: event.source_module.clone(),
        severity: db_event_severity_name(event),
        score: event.score.unwrap_or(0),
        file_path: event.file_path.clone().unwrap_or_default(),
        file_hash: event.file_hash.clone().unwrap_or_default(),
        remote_ip: event.remote_ip.clone().unwrap_or_default(),
        remote_port: event.remote_port.map(u32::from).unwrap_or(0),
        domain: event.domain.clone().unwrap_or_default(),
        details: event.result.clone().unwrap_or_default(),
        agent_id: event.agent_id.clone().unwrap_or_default(),
    }
}

pub struct CentralService {
    agents: Arc<RwLock<HashMap<String, AgentInfo>>>,
    heartbeats: Arc<RwLock<HashMap<String, AgentHeartbeat>>>,
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    db: Database,
}

impl std::fmt::Debug for CentralService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CentralService").finish_non_exhaustive()
    }
}

impl CentralService {
    pub fn new(db: Database) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            heartbeats: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(Vec::new())),
            db,
        }
    }
}

#[tonic::async_trait]
impl NkosiCentral for CentralService {
    async fn register_agent(
        &self,
        request: Request<AgentInfo>,
    ) -> Result<Response<AgentRegistration>, Status> {
        let agent = request.into_inner();
        info!(
            "Agent registered: {} ({})",
            agent.agent_name, agent.agent_id
        );

        {
            let mut agents = self.agents.write().await;
            agents.insert(agent.agent_id.clone(), agent.clone());
        }

        let agent_repo = AgentRepository::new(&self.db);
        let record = proto_agent_to_agent(&agent);
        if let Err(e) = agent_repo.upsert(&record) {
            warn!("Failed to persist agent {}: {}", agent.agent_id, e);
        }

        Ok(Response::new(AgentRegistration {
            central_id: uuid::Uuid::new_v4().to_string(),
            success: true,
            message: format!("Agent '{}' registered successfully", agent.agent_name),
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<AgentHeartbeat>,
    ) -> Result<Response<HeartbeatAck>, Status> {
        let hb = request.into_inner();
        info!(
            "Heartbeat from agent: {} (score: {})",
            hb.agent_id, hb.score
        );

        let agent_repo = AgentRepository::new(&self.db);
        if let Err(e) =
            agent_repo.update_heartbeat(&hb.agent_id, hb.score, hb.events_count, hb.threats_count)
        {
            warn!("Failed to persist heartbeat for {}: {}", hb.agent_id, e);
        }

        let mut heartbeats = self.heartbeats.write().await;
        heartbeats.insert(hb.agent_id.clone(), hb);

        Ok(Response::new(HeartbeatAck {
            success: true,
            message: "Heartbeat received".to_string(),
            server_time: chrono::Utc::now().timestamp(),
            update_available: false,
            latest_version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    async fn report_events(
        &self,
        request: Request<EventBatch>,
    ) -> Result<Response<EventAck>, Status> {
        let batch = request.into_inner();
        let count = batch.events.len();
        info!("Received {} events from agent: {}", count, batch.agent_id);

        let event_repo = EventRepository::new(&self.db);

        let mut persisted = 0usize;
        let mut events = self.events.write().await;
        for mut event in batch.events {
            event.id = uuid::Uuid::new_v4().to_string();
            // Tag the event with its originating agent for multi-server
            // host attribution in the console.
            event.agent_id = batch.agent_id.clone();
            match event_repo.insert(&proto_event_to_event(&event, &batch.agent_id)) {
                Ok(()) => persisted += 1,
                Err(e) => warn!("Failed to persist event {}: {}", event.id, e),
            }
            events.push(event);
        }

        // Keep only last MAX_IN_MEMORY_EVENTS events
        let len = events.len();
        if len > MAX_IN_MEMORY_EVENTS {
            events.drain(0..len - MAX_IN_MEMORY_EVENTS);
        }

        if persisted < count {
            warn!("Only {}/{} events persisted to database", persisted, count);
        }

        Ok(Response::new(EventAck {
            success: true,
            received_count: count as u32,
            message: format!("{} events received", count),
        }))
    }

    async fn get_agents(&self, _request: Request<Empty>) -> Result<Response<AgentList>, Status> {
        let mut merged: HashMap<String, AgentInfo> = self.agents.read().await.clone();

        let agent_repo = AgentRepository::new(&self.db);
        match agent_repo.get_all() {
            Ok(db_agents) => {
                for agent in &db_agents {
                    merged
                        .entry(agent.id.clone())
                        .or_insert_with(|| db_agent_to_proto(agent));
                }
            }
            Err(e) => warn!("Failed to load agents from database: {}", e),
        }

        let agent_list: Vec<AgentInfo> = merged.into_values().collect();

        Ok(Response::new(AgentList {
            agents: agent_list,
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn get_events(
        &self,
        request: Request<EventQuery>,
    ) -> Result<Response<EventList>, Status> {
        let query = request.into_inner();

        let mut results: Vec<SecurityEvent> = {
            let events = self.events.read().await;
            events
                .iter()
                .filter(|e| {
                    if !query.agent_id.is_empty() && e.agent_id != query.agent_id {
                        return false;
                    }
                    if !query.severity.is_empty() && e.severity != query.severity {
                        return false;
                    }
                    if query.start_time > 0 && e.timestamp < query.start_time {
                        return false;
                    }
                    if query.end_time > 0 && e.timestamp > query.end_time {
                        return false;
                    }
                    true
                })
                .cloned()
                .collect()
        };

        let event_repo = EventRepository::new(&self.db);
        match event_repo.get_recent(DB_EVENT_LOOKBACK_LIMIT) {
            Ok(db_events) => {
                for event in &db_events {
                    let ts = event.timestamp.timestamp();
                    if !query.agent_id.is_empty() && event.source_module != query.agent_id {
                        continue;
                    }
                    if !query.severity.is_empty() && db_event_severity_name(event) != query.severity
                    {
                        continue;
                    }
                    if query.start_time > 0 && ts < query.start_time {
                        continue;
                    }
                    if query.end_time > 0 && ts > query.end_time {
                        continue;
                    }
                    results.push(db_event_to_proto(event));
                }
            }
            Err(e) => warn!("Failed to load events from database: {}", e),
        }

        // Dedup events present in both memory and the database.
        let mut seen = HashSet::new();
        results.retain(|e| seen.insert(e.id.clone()));

        let filtered: Vec<SecurityEvent> = results.into_iter().take(query.limit as usize).collect();

        let total = filtered.len() as u32;
        Ok(Response::new(EventList {
            events: filtered,
            total,
        }))
    }

    async fn get_stats(&self, _request: Request<Empty>) -> Result<Response<Stats>, Status> {
        let agents = self.agents.read().await;
        let heartbeats = self.heartbeats.read().await;
        let events = self.events.read().await;

        let now = chrono::Utc::now().timestamp();
        let one_day_ago = now - 86400;

        let online_agents = heartbeats
            .values()
            .filter(|hb| now - hb.timestamp < 300) // 5 minutes
            .count() as u32;

        // Merge agents from memory and database for totals and average score.
        let agent_repo = AgentRepository::new(&self.db);
        let db_agents = agent_repo.get_all().unwrap_or_default();

        let known_ids: HashSet<&str> = agents.keys().map(String::as_str).collect();
        let heartbeat_ids: HashSet<&str> = heartbeats.keys().map(String::as_str).collect();

        let mut total_agents = agents.len() as u32;
        let mut score_sum: u64 = heartbeats.values().map(|hb| u64::from(hb.score)).sum();
        let mut score_count: u64 = heartbeats.len() as u64;

        for agent in &db_agents {
            if !known_ids.contains(agent.id.as_str()) {
                total_agents += 1;
            }
            if !heartbeat_ids.contains(agent.id.as_str()) {
                score_sum += u64::from(agent.score);
                score_count += 1;
            }
        }

        let avg_score = score_sum
            .checked_div(score_count)
            .and_then(|avg| u32::try_from(avg).ok())
            .unwrap_or(100);

        // Merge 24h events from memory and database (dedup by id).
        struct StatEvent {
            id: String,
            severity: String,
            source_module: String,
        }

        let mut stat_events: Vec<StatEvent> = events
            .iter()
            .filter(|e| e.timestamp > one_day_ago)
            .map(|e| StatEvent {
                id: e.id.clone(),
                severity: e.severity.clone(),
                source_module: e.source_module.clone(),
            })
            .collect();

        let event_repo = EventRepository::new(&self.db);
        match event_repo.get_recent(DB_EVENT_LOOKBACK_LIMIT) {
            Ok(db_events) => {
                for event in db_events {
                    if event.timestamp.timestamp() <= one_day_ago {
                        continue;
                    }
                    stat_events.push(StatEvent {
                        id: event.id.to_string(),
                        severity: db_event_severity_name(&event),
                        source_module: event.source_module.clone(),
                    });
                }
            }
            Err(e) => warn!("Failed to load events from database for stats: {}", e),
        }

        let mut seen_ids = HashSet::new();
        stat_events.retain(|e| seen_ids.insert(e.id.clone()));

        let total_events_24h = stat_events.len() as u32;

        let threats_24h = stat_events
            .iter()
            .filter(|e| matches!(e.severity.as_str(), "Critical" | "High" | "Medium"))
            .count() as u32;

        let mut events_by_agent: HashMap<String, u32> = HashMap::new();
        let mut threats_by_severity: HashMap<String, u32> = HashMap::new();

        for event in &stat_events {
            *events_by_agent
                .entry(event.source_module.clone())
                .or_insert(0) += 1;
            *threats_by_severity
                .entry(event.severity.clone())
                .or_insert(0) += 1;
        }

        Ok(Response::new(Stats {
            total_agents,
            online_agents,
            offline_agents: total_agents.saturating_sub(online_agents),
            total_events_24h,
            total_threats_24h: threats_24h,
            avg_score,
            events_by_agent,
            threats_by_severity,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let data_dir = PathBuf::from("./data");
    std::fs::create_dir_all(&data_dir).ok();
    let db_path = data_dir.join("central.db");
    let db = Database::new(&db_path).expect("Failed to open central database");

    // Bind address configurable via env (default IPv4 any-interface so remote
    // agents and the console can reach it by default).
    let bind = std::env::var("NKOSI_CENTRAL_BIND").unwrap_or_else(|_| "0.0.0.0:50051".to_string());
    let addr = bind.parse().expect("Invalid NKOSI_CENTRAL_BIND address");
    let service = CentralService::new(db);

    info!("NKOSI Central server starting on {}", addr);

    // Periodic cleanup: mark agents that have not sent a heartbeat recently as offline.
    let db_for_cleanup = service.db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let repo = AgentRepository::new(&db_for_cleanup);
            if let Ok(count) = repo.mark_offline_stale(300)
                && count > 0
            {
                info!("Marked {} agents as offline", count);
            }
        }
    });

    tonic::transport::Server::builder()
        .add_service(NkosiCentralServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
