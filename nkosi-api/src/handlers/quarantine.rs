use actix_web::{web, HttpRequest, HttpResponse};
use serde::Serialize;
use std::sync::Arc;

use crate::state::{AppState, ErrorResponse, get_client_ip, extract_api_key, is_public_path};

#[derive(Serialize)]
struct QuarantineResponse {
    items: Vec<nkosi_common::types::QuarantineItem>,
    total: usize,
}

pub async fn get_quarantine(data: web::Data<Arc<AppState>>, req: HttpRequest) -> HttpResponse {
    if !is_public_path(req.path()) {
        let client_ip = get_client_ip(&req);
        if !data.rate_limiter.check(&client_ip).await {
            return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
        }
        let key = extract_api_key(&req);
        if !data.api_key_auth.validate(&key) {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
        }
    }

    match data.db.get_active() {
        Ok(items) => HttpResponse::Ok().json(QuarantineResponse { total: items.len(), items }),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}
