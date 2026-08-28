use actix_web::HttpRequest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use nkosi_common::config::NkosiConfig;
use nkosi_db::Database;

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub api_keys: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub rate_limit_per_second: u32,
}

impl Default for ApiConfig {
    fn default() -> Self {
        let default_key = format!("nkosi_{}", hex::encode([0u8; 32]));
        Self {
            api_keys: vec![default_key],
            allowed_origins: vec!["http://localhost:8080".to_string()],
            rate_limit_per_second: 10,
        }
    }
}

#[derive(Debug, Clone)]
struct RateLimiterEntry {
    count: u32,
    window_start: Instant,
}

pub struct IpRateLimiter {
    limits: RwLock<HashMap<String, RateLimiterEntry>>,
    max_per_second: u32,
}

impl IpRateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            limits: RwLock::new(HashMap::new()),
            max_per_second,
        }
    }

    pub async fn check(&self, ip: &str) -> bool {
        let mut limits = self.limits.write().await;
        let now = Instant::now();

        let entry = limits.entry(ip.to_string()).or_insert(RateLimiterEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) > Duration::from_secs(1) {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
        entry.count <= self.max_per_second
    }
}

#[derive(Clone)]
pub struct ApiKeyAuth {
    valid_keys: Vec<String>,
}

impl ApiKeyAuth {
    pub fn new(keys: Vec<String>) -> Self {
        Self { valid_keys: keys }
    }

    pub fn validate(&self, key: &str) -> bool {
        self.valid_keys.iter().any(|valid| {
            if valid.len() != key.len() {
                return false;
            }
            valid
                .bytes()
                .zip(key.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        })
    }
}

pub struct AppState {
    pub db: Arc<Database>,
    pub _config: Arc<NkosiConfig>,
    pub api_key_auth: ApiKeyAuth,
    pub rate_limiter: Arc<IpRateLimiter>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    #[allow(dead_code)]
    pub path: Option<String>,
    pub limit: Option<usize>,
}

impl ScanQuery {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(limit) = self.limit
            && (limit == 0 || limit > 10000)
        {
            return Err("Limit must be 1-10000".to_string());
        }
        Ok(())
    }
}

pub fn get_client_ip(req: &HttpRequest) -> String {
    // Forwarded headers are attacker-controlled unless this process is only
    // reachable through a trusted reverse proxy.
    if std::env::var("NKOSI_TRUST_PROXY").as_deref() == Ok("1") {
        if let Some(forwarded) = req.headers().get("X-Forwarded-For")
            && let Ok(val) = forwarded.to_str()
            && let Some(ip) = val.split(',').next()
        {
            return ip.trim().to_string();
        }
        if let Some(real_ip) = req.headers().get("X-Real-IP")
            && let Ok(val) = real_ip.to_str()
        {
            return val.trim().to_string();
        }
    }
    req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn extract_api_key(req: &HttpRequest) -> String {
    req.headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

pub fn is_public_path(path: &str) -> bool {
    path == "/"
        || path.starts_with("/index.html")
        || path.starts_with("/metrics")
        || path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".ico")
}
