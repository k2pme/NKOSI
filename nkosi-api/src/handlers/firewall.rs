use actix_web::{HttpRequest, HttpResponse, web};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;

use crate::state::{AppState, ErrorResponse, extract_api_key, get_client_ip};
use nkosi_scanner::FirewallManager;

#[derive(Serialize)]
struct FirewallStatusResponse {
    ipv4_available: bool,
    ipv6_available: bool,
    nkosi_chain_exists: bool,
    rules_count: u32,
    blacklist_count: u32,
    whitelist_count: u32,
}

#[derive(Debug, Deserialize)]
pub struct FirewallBlockRequest {
    pub ip: String,
    pub comment: Option<String>,
}

impl FirewallBlockRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.ip.is_empty() {
            return Err("IP is required".to_string());
        }
        let parts: Vec<&str> = self.ip.split('/').collect();
        let ip_part = parts[0];
        let octets: Vec<u8> = ip_part.split('.').filter_map(|o| o.parse().ok()).collect();
        if octets.len() != 4 {
            return Err(format!("Invalid IP: {}", self.ip));
        }
        if parts.len() == 2 {
            let prefix: u32 = parts[1].parse().map_err(|_| "Invalid CIDR".to_string())?;
            if prefix > 32 {
                return Err("CIDR prefix > 32".to_string());
            }
        }
        if let Some(ref comment) = self.comment
            && comment.len() > 256
        {
            return Err("Comment too long (max 256)".to_string());
        }
        Ok(())
    }
}

pub async fn get_firewall_status(data: web::Data<Arc<AppState>>, req: HttpRequest) -> HttpResponse {
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

    let mgr = FirewallManager::new();
    match mgr.status() {
        Ok(status) => HttpResponse::Ok().json(FirewallStatusResponse {
            ipv4_available: status.ipv4_available,
            ipv6_available: status.ipv6_available,
            nkosi_chain_exists: status.nkosi_chain_exists,
            rules_count: status.rules_count,
            blacklist_count: status.blacklist_count,
            whitelist_count: status.whitelist_count,
        }),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
            code: 500,
        }),
    }
}

pub async fn block_ip(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    body: web::Json<FirewallBlockRequest>,
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
        warn!("Unauthorized firewall block from {}", client_ip);
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid or missing X-API-Key header".to_string(),
            code: 401,
        });
    }

    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: e,
            code: 400,
        });
    }

    let mgr = FirewallManager::new();
    match mgr.block_ip(&body.ip, body.comment.as_deref(), false) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("IP {} blocked", body.ip)
        })),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
            code: 500,
        }),
    }
}

pub async fn unblock_ip(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    path: web::Path<String>,
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
        warn!("Unauthorized firewall unblock from {}", client_ip);
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid or missing X-API-Key header".to_string(),
            code: 401,
        });
    }

    let ip = path.into_inner();
    let parts: Vec<&str> = ip.split('/').collect();
    let octets: Vec<u8> = parts[0].split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: format!("Invalid IP: {}", ip),
            code: 400,
        });
    }

    let mgr = FirewallManager::new();
    match mgr.unblock_ip(&ip) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true, "message": format!("IP {} unblocked", ip)
        })),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: e.to_string(),
            code: 500,
        }),
    }
}
