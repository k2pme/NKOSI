use actix_web::{web, HttpRequest, HttpResponse};
use serde::Serialize;
use std::sync::Arc;

use crate::state::{AppState, ErrorResponse, get_client_ip, extract_api_key};
use nkosi_common::types::Severity;

#[derive(Serialize)]
struct AgentsResponse {
    agents: Vec<nkosi_common::types::Agent>,
    total: usize,
}

#[derive(Serialize)]
struct AgentDetailResponse {
    agent: Option<nkosi_common::types::Agent>,
}

#[derive(Serialize)]
struct AlertItem {
    id: String,
    timestamp: String,
    agent_host: String,
    severity: String,
    event_type: String,
    source_module: String,
    file_path: Option<String>,
    remote_ip: Option<String>,
    score: Option<u32>,
}

#[derive(Serialize)]
struct AlertsResponse {
    alerts: Vec<AlertItem>,
    total: usize,
}

#[derive(Serialize)]
struct ConsolidatedStatsResponse {
    total_agents: u32,
    online_agents: u32,
    offline_agents: u32,
    total_events: u32,
    total_threats: u32,
    total_quarantine: u32,
}

#[derive(Serialize)]
struct ConsolidatedReportResponse {
    stats: ConsolidatedStatsResponse,
    agents: Vec<nkosi_common::types::Agent>,
    recent_alerts: Vec<AlertItem>,
}

fn event_to_alert(e: &nkosi_common::types::Event) -> AlertItem {
    AlertItem {
        id: e.id.to_string(),
        timestamp: e.timestamp.to_rfc3339(),
        agent_host: String::new(),
        severity: serde_json::to_string(&e.severity).unwrap_or_default(),
        event_type: serde_json::to_string(&e.event_type).unwrap_or_default(),
        source_module: e.source_module.clone(),
        file_path: e.file_path.clone(),
        remote_ip: e.remote_ip.clone(),
        score: e.score,
    }
}

pub async fn get_agents(data: web::Data<Arc<AppState>>, req: HttpRequest) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
    }

    let repo = nkosi_db::AgentRepository::new(&data.db);
    match repo.get_all() {
        Ok(agents) => HttpResponse::Ok().json(AgentsResponse { total: agents.len(), agents }),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

pub async fn get_agent_detail(data: web::Data<Arc<AppState>>, req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
    }

    let agent_id = path.into_inner();
    let repo = nkosi_db::AgentRepository::new(&data.db);
    match repo.get_by_id(&agent_id) {
        Ok(agent) => HttpResponse::Ok().json(AgentDetailResponse { agent }),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

pub async fn get_alertes(data: web::Data<Arc<AppState>>, req: HttpRequest) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
    }

    let repo = nkosi_db::AgentRepository::new(&data.db);
    match repo.get_events_filtered(None, None, None, 500) {
        Ok(events) => {
            let alerts: Vec<AlertItem> = events.iter()
                .filter(|e| matches!(e.severity, Severity::Critical | Severity::High | Severity::Medium))
                .map(event_to_alert)
                .collect();
            let total = alerts.len();
            HttpResponse::Ok().json(AlertsResponse { total, alerts })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

pub async fn get_consolidated_stats(data: web::Data<Arc<AppState>>, req: HttpRequest) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
    }

    let repo = nkosi_db::AgentRepository::new(&data.db);
    match repo.get_consolidated_stats() {
        Ok(stats) => HttpResponse::Ok().json(ConsolidatedStatsResponse {
            total_agents: stats.total_agents,
            online_agents: stats.online_agents,
            offline_agents: stats.offline_agents,
            total_events: stats.total_events,
            total_threats: stats.total_threats,
            total_quarantine: stats.total_quarantine,
        }),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

pub async fn get_consolidated_report(data: web::Data<Arc<AppState>>, req: HttpRequest) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
    }

    let repo = nkosi_db::AgentRepository::new(&data.db);
    let stats = repo.get_consolidated_stats().ok();
    let agents = repo.get_all().unwrap_or_default();
    let alerts_result = repo.get_events_filtered(None, None, None, 100);

    let recent_alerts = alerts_result.unwrap_or_default().iter()
        .filter(|e| matches!(e.severity, Severity::Critical | Severity::High | Severity::Medium))
        .map(event_to_alert)
        .collect();

    HttpResponse::Ok().json(ConsolidatedReportResponse {
        stats: stats.map(|s| ConsolidatedStatsResponse {
            total_agents: s.total_agents,
            online_agents: s.online_agents,
            offline_agents: s.offline_agents,
            total_events: s.total_events,
            total_threats: s.total_threats,
            total_quarantine: s.total_quarantine,
        }).unwrap_or(ConsolidatedStatsResponse {
            total_agents: 0, online_agents: 0, offline_agents: 0,
            total_events: 0, total_threats: 0, total_quarantine: 0,
        }),
        agents,
        recent_alerts,
    })
}
