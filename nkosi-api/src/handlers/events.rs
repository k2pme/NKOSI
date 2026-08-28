use actix_web::{HttpRequest, HttpResponse, web};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;

use crate::state::{
    AppState, ErrorResponse, ScanQuery, extract_api_key, get_client_ip, is_public_path,
};

#[derive(Serialize)]
struct EventsResponse {
    events: Vec<nkosi_common::types::Event>,
    total: usize,
}

#[derive(Debug, Deserialize)]
pub struct FilteredEventsQuery {
    pub agent_id: Option<String>,
    pub host: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<i32>,
}

pub async fn get_events(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    query: web::Query<ScanQuery>,
) -> HttpResponse {
    if !is_public_path(req.path()) {
        let client_ip = get_client_ip(&req);
        if !data.rate_limiter.check(&client_ip).await {
            return HttpResponse::TooManyRequests().json(ErrorResponse {
                error: "Rate limit exceeded".to_string(),
                code: 429,
            });
        }
        let key = extract_api_key(&req);
        if !data.api_key_auth.validate(&key) {
            warn!("Unauthorized access from {}", client_ip);
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "Invalid or missing X-API-Key header".to_string(),
                code: 401,
            });
        }
    }

    if let Err(e) = query.validate() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: e,
            code: 400,
        });
    }

    let limit = query.limit.unwrap_or(100) as i32;
    match data.db.get_recent(limit) {
        Ok(events) => HttpResponse::Ok().json(EventsResponse {
            total: events.len(),
            events,
        }),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
            code: 500,
        }),
    }
}

pub async fn get_events_filtered(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    query: web::Query<FilteredEventsQuery>,
) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse {
            error: "Rate limit exceeded".to_string(),
            code: 429,
        });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid or missing X-API-Key header".to_string(),
            code: 401,
        });
    }

    let limit = query.limit.unwrap_or(100).min(10000);
    let repo = nkosi_db::AgentRepository::new(&data.db);
    match repo.get_events_filtered(
        query.agent_id.as_deref(),
        query.host.as_deref(),
        query.severity.as_deref(),
        limit,
    ) {
        Ok(events) => {
            let total = events.len();
            HttpResponse::Ok().json(EventsResponse { total, events })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
            code: 500,
        }),
    }
}
