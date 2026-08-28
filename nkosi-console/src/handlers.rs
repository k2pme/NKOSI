use actix_web::{web, HttpResponse};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::central::{self, CentralSnapshot};

pub type SnapshotState = Arc<RwLock<CentralSnapshot>>;

#[derive(Serialize)]
struct AgentsResponse {
    agents: Vec<AgentView>,
    total: usize,
    timestamp: String,
}

#[derive(Serialize)]
struct AgentView {
    id: String,
    hostname: String,
    ip_address: String,
    os_version: String,
    nkosi_version: String,
    agent_name: String,
    events_count: u32,
    threats_count: u32,
    score: u32,
    status: String,
}

fn agent_view(a: &central::AgentInfo, hb_map: &HashMap<String, &central::AgentHeartbeat>) -> AgentView {
    let hb = hb_map.get(&a.agent_id);
    let online = hb.map(|h| {
        let now = chrono::Utc::now().timestamp();
        now - h.timestamp < 300
    }).unwrap_or(false);
    AgentView {
        id: a.agent_id.clone(),
        hostname: a.hostname.clone(),
        ip_address: a.ip_address.clone(),
        os_version: a.os_version.clone(),
        nkosi_version: a.nkosi_version.clone(),
        agent_name: a.agent_name.clone(),
        events_count: hb.map(|h| h.events_count).unwrap_or(0),
        threats_count: hb.map(|h| h.threats_count).unwrap_or(0),
        score: hb.map(|h| h.score).unwrap_or(0),
        status: if online { "online".into() } else { "offline".into() },
    }
}

#[derive(Serialize)]
struct EventView {
    id: String,
    timestamp: i64,
    event_type: String,
    agent_id: String,
    agent_host: String,
    severity: String,
    score: u32,
    file_path: String,
    file_hash: String,
    remote_ip: String,
    remote_port: u32,
    domain: String,
    details: String,
}

fn event_view(e: &central::SecurityEvent, host: &str) -> EventView {
    EventView {
        id: e.id.clone(),
        timestamp: e.timestamp,
        event_type: e.event_type.clone(),
        agent_id: e.agent_id.clone(),
        agent_host: host.to_string(),
        severity: e.severity.clone(),
        score: e.score,
        file_path: e.file_path.clone(),
        file_hash: e.file_hash.clone(),
        remote_ip: e.remote_ip.clone(),
        remote_port: e.remote_port,
        domain: e.domain.clone(),
        details: e.details.clone(),
    }
}

#[derive(Serialize)]
struct AlertsResponse {
    alerts: Vec<EventView>,
    total: usize,
}

#[derive(Serialize)]
struct StatsResponse {
    total_agents: u32,
    online_agents: u32,
    offline_agents: u32,
    total_events_24h: u32,
    total_threats_24h: u32,
    avg_score: u32,
    events_by_agent: HashMap<String, u32>,
    threats_by_severity: HashMap<String, u32>,
}

#[derive(Serialize)]
struct ReportResponse {
    generated: String,
    stats: StatsResponse,
    agents: Vec<AgentView>,
    unreviewed_threats: Vec<EventView>,
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

fn build_snapshot_views(snapshot: &CentralSnapshot) -> (Vec<AgentView>, HashMap<String, &central::AgentHeartbeat>) {
    let mut hb_map: HashMap<String, &central::AgentHeartbeat> = HashMap::new();
    for hb in &snapshot.heartbeats {
        hb_map.entry(hb.agent_id.clone()).or_insert(hb);
    }
    let agents: Vec<AgentView> = snapshot
        .agents
        .iter()
        .map(|a| agent_view(a, &hb_map))
        .collect();
    (agents, hb_map)
}

fn host_of_event(snapshot: &CentralSnapshot, e: &central::SecurityEvent) -> String {
    snapshot
        .agents
        .iter()
        .find(|a| a.agent_id == e.agent_id)
        .map(|a| a.hostname.clone())
        .unwrap_or_else(|| e.source_module.clone())
}

/// GET /console/agents?host=<hostname filter>
pub async fn get_agents(
    state: web::Data<SnapshotState>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let snapshot = state.read().await.clone();
    let (mut agents, _) = build_snapshot_views(&snapshot);
    if let Some(host) = query.get("host") {
        agents.retain(|a| {
            a.hostname.to_lowercase().contains(&host.to_lowercase())
                || a.ip_address.contains(host)
                || a.agent_name.to_lowercase().contains(&host.to_lowercase())
        });
    }
    let total = agents.len();
    HttpResponse::Ok().json(AgentsResponse { agents, total, timestamp: snapshot.last_refresh })
}

/// GET /console/events?agent_id=&severity=&host=
pub async fn get_events(
    state: web::Data<SnapshotState>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let snapshot = state.read().await.clone();
    let mut events: Vec<EventView> = snapshot
        .events
        .iter()
        .map(|e| event_view(e, &host_of_event(&snapshot, e)))
        .collect();

    if let Some(host) = query.get("host") {
        events.retain(|e| e.agent_host.to_lowercase().contains(&host.to_lowercase()));
    }
    if let Some(agent) = query.get("agent_id") {
        events.retain(|e| e.agent_id == *agent);
    }
    if let Some(sev) = query.get("severity") {
        events.retain(|e| e.severity.eq_ignore_ascii_case(sev));
    }
    if let Some(limit) = query.get("limit").and_then(|l| l.parse::<usize>().ok()) {
        events.truncate(limit);
    }
    events.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
    let total = events.len();
    HttpResponse::Ok().json(AlertsResponse { alerts: events, total })
}

/// GET /console/alerts?host=&severity=
pub async fn get_alerts(
    state: web::Data<SnapshotState>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let snapshot = state.read().await.clone();
    let mut alerts: Vec<EventView> = snapshot
        .events
        .iter()
        .filter(|e| severity_rank(&e.severity) >= 2)
        .map(|e| event_view(e, &host_of_event(&snapshot, e)))
        .collect();

    if let Some(host) = query.get("host") {
        alerts.retain(|e| e.agent_host.to_lowercase().contains(&host.to_lowercase()));
    }
    if let Some(sev) = query.get("severity") {
        alerts.retain(|e| e.severity.eq_ignore_ascii_case(sev));
    }
    if let Some(limit) = query.get("limit").and_then(|l| l.parse::<usize>().ok()) {
        alerts.truncate(limit);
    }
    alerts.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
    let total = alerts.len();
    HttpResponse::Ok().json(AlertsResponse { alerts, total })
}

/// GET /console/stats
pub async fn get_stats(state: web::Data<SnapshotState>) -> HttpResponse {
    let snapshot = state.read().await.clone();
    let now = chrono::Utc::now().timestamp();
    let one_day = now - 86400;

    let online_agents = snapshot
        .heartbeats
        .iter()
        .filter(|h| now - h.timestamp < 300)
        .count() as u32;
    let total_agents = snapshot.agents.len() as u32;

    let events_24h: Vec<&central::SecurityEvent> =
        snapshot.events.iter().filter(|e| e.timestamp > one_day).collect();
    let threats_24h = events_24h
        .iter()
        .filter(|e| severity_rank(&e.severity) >= 2)
        .count() as u32;

    let mut threats_by_severity: HashMap<String, u32> = HashMap::new();
    let mut events_by_agent: HashMap<String, u32> = HashMap::new();
    for e in &events_24h {
        *events_by_agent.entry(host_of_event(&snapshot, e)).or_insert(0) += 1;
        *threats_by_severity.entry(e.severity.clone()).or_insert(0) += 1;
    }

    let score_sum: u64 = snapshot.heartbeats.iter().map(|h| u64::from(h.score)).sum();
    let score_count = snapshot.heartbeats.len().max(1) as u64;
    let avg_score = (score_sum / score_count) as u32;

    HttpResponse::Ok().json(StatsResponse {
        total_agents,
        online_agents,
        offline_agents: total_agents.saturating_sub(online_agents),
        total_events_24h: events_24h.len() as u32,
        total_threats_24h: threats_24h,
        avg_score,
        events_by_agent,
        threats_by_severity,
    })
}

/// GET /console/report?host=&limit=
/// Consolidated report for F2.11.
pub async fn get_report(
    state: web::Data<SnapshotState>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let snapshot = state.read().await.clone();
    let (mut agents, _) = build_snapshot_views(&snapshot);

    if let Some(host) = query.get("host") {
        agents.retain(|a| {
            a.hostname.to_lowercase().contains(&host.to_lowercase())
                || a.ip_address.contains(host)
        });
    }
    let agent_ids: std::collections::HashSet<String> = agents.iter().map(|a| a.id.clone()).collect();

    let mut threats: Vec<EventView> = snapshot
        .events
        .iter()
        .filter(|e| {
            severity_rank(&e.severity) >= 2
                && (agent_ids.is_empty() || agent_ids.contains(&e.agent_id))
        })
        .map(|e| event_view(e, &host_of_event(&snapshot, e)))
        .collect();

    if let Some(host) = query.get("host") {
        threats.retain(|e| e.agent_host.to_lowercase().contains(&host.to_lowercase()));
    }

    let stats = compute_stats_from(&snapshot);

    let limit = query.get("limit").and_then(|l| l.parse::<usize>().ok()).unwrap_or(50);
    threats.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
    threats.truncate(limit);

    HttpResponse::Ok().json(ReportResponse {
        generated: chrono::Utc::now().to_rfc3339(),
        stats,
        agents,
        unreviewed_threats: threats,
    })
}

/// GET /console/connectivity
pub async fn get_connectivity(state: web::Data<SnapshotState>) -> HttpResponse {
    let snapshot = state.read().await.clone();
    HttpResponse::Ok().json(central::connectivity(&snapshot))
}

fn compute_stats_from(snapshot: &CentralSnapshot) -> StatsResponse {
    let now = chrono::Utc::now().timestamp();
    let one_day = now - 86400;
    let online_agents = snapshot
        .heartbeats
        .iter()
        .filter(|h| now - h.timestamp < 300)
        .count() as u32;
    let total_agents = snapshot.agents.len() as u32;
    let events_24h: Vec<&central::SecurityEvent> =
        snapshot.events.iter().filter(|e| e.timestamp > one_day).collect();
    let threats_24h = events_24h
        .iter()
        .filter(|e| severity_rank(&e.severity) >= 2)
        .count() as u32;
    let mut threats_by_severity: HashMap<String, u32> = HashMap::new();
    let mut events_by_agent: HashMap<String, u32> = HashMap::new();
    for e in &events_24h {
        *events_by_agent.entry(host_of_event(snapshot, e)).or_insert(0) += 1;
        *threats_by_severity.entry(e.severity.clone()).or_insert(0) += 1;
    }
    let score_sum: u64 = snapshot.heartbeats.iter().map(|h| u64::from(h.score)).sum();
    let score_count = snapshot.heartbeats.len().max(1) as u64;
    StatsResponse {
        total_agents,
        online_agents,
        offline_agents: total_agents.saturating_sub(online_agents),
        total_events_24h: events_24h.len() as u32,
        total_threats_24h: threats_24h,
        avg_score: (score_sum / score_count) as u32,
        events_by_agent,
        threats_by_severity,
    }
}
