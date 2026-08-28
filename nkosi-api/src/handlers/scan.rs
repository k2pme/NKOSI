use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;

use crate::state::{AppState, ErrorResponse, get_client_ip, extract_api_key};
use crate::{SCANS_TOTAL};
use nkosi_scanner::{RootkitScanner, IntegrityScanner, KernelScanner, SshBruteforceScanner, SshBruteforceConfig};

#[derive(Serialize)]
struct ScanResponse {
    success: bool,
    message: String,
    score: Option<u32>,
    findings_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    #[serde(default)]
    path: Option<String>,
    #[serde(default = "default_scan_type")]
    scan_type: String,
}

fn default_scan_type() -> String {
    "quick".to_string()
}

impl ScanRequest {
    pub fn validate(&self) -> Result<(), String> {
        let valid_types = ["quick", "full", "rootkit", "integrity", "kernel", "ssh"];
        if !valid_types.contains(&self.scan_type.as_str()) {
            return Err(format!("Invalid scan_type: {}. Use: {:?}", self.scan_type, valid_types));
        }
        if let Some(ref path) = self.path {
            if path.contains("..") || path.contains('~') {
                return Err("Path cannot contain '..' or '~'".to_string());
            }
            if !path.starts_with('/') {
                return Err("Path must be absolute".to_string());
            }
            if path.len() > 4096 {
                return Err("Path too long (max 4096)".to_string());
            }
        }
        Ok(())
    }
}

pub async fn trigger_scan(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    body: web::Json<ScanRequest>,
) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        warn!("Unauthorized scan attempt from {}", client_ip);
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
    }

    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest().json(ErrorResponse { error: e, code: 400 });
    }

    let result = match body.scan_type.as_str() {
        "rootkit" => {
            let scanner = RootkitScanner::new();
            scanner.scan().map(|r| (r.score, r.findings.len()))
        }
        "integrity" => {
            let scanner = IntegrityScanner::new();
            scanner.scan().map(|r| (r.score, r.findings.len()))
        }
        "kernel" => {
            let scanner = KernelScanner::new();
            scanner.scan().map(|r| (r.score, r.findings.len()))
        }
        "ssh" => {
            let config = SshBruteforceConfig::default();
            let scanner = SshBruteforceScanner::new(config);
            scanner.scan().map(|r| (r.score, r.attackers.len()))
        }
        _ => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid scan type".to_string(), code: 400,
            });
        }
    };

    match result {
        Ok((score, findings_count)) => {
            SCANS_TOTAL.inc();
            HttpResponse::Ok().json(ScanResponse {
                success: true,
                message: format!("Scan completed: {} findings", findings_count),
                score: Some(score),
                findings_count,
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}
