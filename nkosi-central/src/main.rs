use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::info;

pub mod central {
    tonic::include_proto!("nkosi.central");
}

use central::nkosi_central_server::{NkosiCentral, NkosiCentralServer};
use central::*;

#[derive(Debug, Default)]
pub struct CentralService {
    agents: Arc<RwLock<HashMap<String, AgentInfo>>>,
    heartbeats: Arc<RwLock<HashMap<String, AgentHeartbeat>>>,
    events: Arc<RwLock<Vec<SecurityEvent>>>,
}

impl CentralService {
    pub fn new() -> Self {
        Self::default()
    }
}

#[tonic::async_trait]
impl NkosiCentral for CentralService {
    async fn register_agent(
        &self,
        request: Request<AgentInfo>,
    ) -> Result<Response<AgentRegistration>, Status> {
        let agent = request.into_inner();
        info!("Agent registered: {} ({})", agent.agent_name, agent.agent_id);

        let mut agents = self.agents.write().await;
        agents.insert(agent.agent_id.clone(), agent.clone());

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
        info!("Heartbeat from agent: {} (score: {})", hb.agent_id, hb.score);

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

        let mut events = self.events.write().await;
        for mut event in batch.events {
            event.id = uuid::Uuid::new_v4().to_string();
            events.push(event);
        }

        // Keep only last 10000 events
        let len = events.len();
        if len > 10000 {
            events.drain(0..len - 10000);
        }

        Ok(Response::new(EventAck {
            success: true,
            received_count: count as u32,
            message: format!("{} events received", count),
        }))
    }

    async fn get_agents(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentList>, Status> {
        let agents = self.agents.read().await;
        let agent_list: Vec<AgentInfo> = agents.values().cloned().collect();

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
        let events = self.events.read().await;

        let filtered: Vec<SecurityEvent> = events
            .iter()
            .filter(|e| {
                if !query.agent_id.is_empty() && e.source_module != query.agent_id {
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
            .take(query.limit as usize)
            .cloned()
            .collect();

        let total = filtered.len() as u32;
        Ok(Response::new(EventList {
            events: filtered,
            total,
        }))
    }

    async fn get_stats(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Stats>, Status> {
        let agents = self.agents.read().await;
        let heartbeats = self.heartbeats.read().await;
        let events = self.events.read().await;

        let now = chrono::Utc::now().timestamp();
        let one_day_ago = now - 86400;

        let online_agents = heartbeats
            .values()
            .filter(|hb| now - hb.timestamp < 300) // 5 minutes
            .count() as u32;

        let events_24h: Vec<&SecurityEvent> = events
            .iter()
            .filter(|e| e.timestamp > one_day_ago)
            .collect();

        let threats_24h = events_24h
            .iter()
            .filter(|e| matches!(e.severity.as_str(), "Critical" | "High" | "Medium"))
            .count() as u32;

        let mut events_by_agent: HashMap<String, u32> = HashMap::new();
        let mut threats_by_severity: HashMap<String, u32> = HashMap::new();

        for event in &events_24h {
            *events_by_agent.entry(event.source_module.clone()).or_insert(0) += 1;
            *threats_by_severity.entry(event.severity.clone()).or_insert(0) += 1;
        }

        Ok(Response::new(Stats {
            total_agents: agents.len() as u32,
            online_agents,
            offline_agents: agents.len() as u32 - online_agents,
            total_events_24h: events_24h.len() as u32,
            total_threats_24h: threats_24h,
            avg_score: 100,
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

    let addr = "[::1]:50051".parse()?;
    let service = CentralService::new();

    info!("NKOSI Central server starting on {}", addr);

    tonic::transport::Server::builder()
        .add_service(NkosiCentralServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
