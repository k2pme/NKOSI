use actix_cors::Cors;
use actix_web::{web, App, HttpServer, HttpResponse, HttpRequest, middleware};
use actix_files::Files;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use nkosi_common::config::NkosiConfig;
use nkosi_db::Database;
use nkosi_scanner::{RootkitScanner, IntegrityScanner, KernelScanner, SshBruteforceScanner, SshBruteforceConfig, FirewallManager};

use prometheus::{Encoder, TextEncoder, IntCounter, IntGauge, Registry};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref EVENTS_TOTAL: IntCounter = IntCounter::new("nkosi_events_total", "Total events processed").unwrap();
    pub static ref THREATS_DETECTED: IntCounter = IntCounter::new("nkosi_threats_detected", "Total threats detected").unwrap();
    pub static ref SCANS_TOTAL: IntCounter = IntCounter::new("nkosi_scans_total", "Total scans performed").unwrap();
    pub static ref QUARANTINE_FILES: IntGauge = IntGauge::new("nkosi_quarantine_files", "Files in quarantine").unwrap();
    pub static ref REGISTRY: Registry = Registry::new();
}

// ============================================================
// Security Configuration
// ============================================================

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub api_keys: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub rate_limit_per_second: u32,
}

impl Default for ApiConfig {
    fn default() -> Self {
        let default_key = format!("nkosi_{}", hex::encode(&[0u8; 32]));
        Self {
            api_keys: vec![default_key],
            allowed_origins: vec!["http://localhost:8080".to_string()],
            rate_limit_per_second: 10,
        }
    }
}

// ============================================================
// Rate Limiter (per IP)
// ============================================================

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

// ============================================================
// API Key Auth
// ============================================================

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
            valid.bytes().zip(key.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        })
    }
}

// ============================================================
// App State
// ============================================================

struct AppState {
    db: Arc<Database>,
    config: Arc<NkosiConfig>,
    api_key_auth: ApiKeyAuth,
    rate_limiter: Arc<IpRateLimiter>,
}

// ============================================================
// Response Types
// ============================================================

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    version: String,
    db_status: String,
}

#[derive(Serialize)]
struct ScanResponse {
    success: bool,
    message: String,
    score: Option<u32>,
    findings_count: usize,
}

#[derive(Serialize)]
struct EventsResponse {
    events: Vec<nkosi_common::types::Event>,
    total: usize,
}

#[derive(Serialize)]
struct QuarantineResponse {
    items: Vec<nkosi_common::types::QuarantineItem>,
    total: usize,
}

#[derive(Serialize)]
struct FirewallStatusResponse {
    ipv4_available: bool,
    ipv6_available: bool,
    nkosi_chain_exists: bool,
    rules_count: u32,
    blacklist_count: u32,
    whitelist_count: u32,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: u16,
}

// ============================================================
// Input Validation
// ============================================================

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
        if let Some(ref comment) = self.comment {
            if comment.len() > 256 {
                return Err("Comment too long (max 256)".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    pub path: Option<String>,
    pub limit: Option<usize>,
}

impl ScanQuery {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(limit) = self.limit {
            if limit == 0 || limit > 10000 {
                return Err("Limit must be 1-10000".to_string());
            }
        }
        Ok(())
    }
}

// ============================================================
// Helper: get client IP
// ============================================================

fn get_client_ip(req: &HttpRequest) -> String {
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(val) = forwarded.to_str() {
            if let Some(ip) = val.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(val) = real_ip.to_str() {
            return val.trim().to_string();
        }
    }
    req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// ============================================================
// Helper: validate API key + rate limit
// ============================================================

fn extract_api_key(req: &HttpRequest) -> String {
    req.headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn is_public_path(path: &str) -> bool {
    path == "/"
        || path.starts_with("/index.html")
        || path.starts_with("/metrics")
        || path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".ico")
}

// ============================================================
// API Handlers
// ============================================================

async fn get_status(_data: web::Data<Arc<AppState>>) -> HttpResponse {
    HttpResponse::Ok().json(StatusResponse {
        status: "running".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        db_status: "connected".to_string(),
    })
}

async fn get_metrics() -> HttpResponse {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(buffer)
}

async fn get_events(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    query: web::Query<ScanQuery>,
) -> HttpResponse {
    // Auth check
    if !is_public_path(req.path()) {
        let client_ip = get_client_ip(&req);
        if !data.rate_limiter.check(&client_ip).await {
            return HttpResponse::TooManyRequests().json(ErrorResponse {
                error: "Rate limit exceeded".to_string(), code: 429,
            });
        }
        let key = extract_api_key(&req);
        if !data.api_key_auth.validate(&key) {
            warn!("Unauthorized access from {}", client_ip);
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "Invalid or missing X-API-Key header".to_string(), code: 401,
            });
        }
    }

    if let Err(e) = query.validate() {
        return HttpResponse::BadRequest().json(ErrorResponse { error: e, code: 400 });
    }

    let limit = query.limit.unwrap_or(100) as i32;
    match data.db.get_recent(limit) {
        Ok(events) => HttpResponse::Ok().json(EventsResponse { total: events.len(), events }),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

async fn get_quarantine(data: web::Data<Arc<AppState>>, req: HttpRequest) -> HttpResponse {
    if !is_public_path(req.path()) {
        let client_ip = get_client_ip(&req);
        if !data.rate_limiter.check(&client_ip).await {
            return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
        }
        let key = extract_api_key(&req);
        if !data.api_key_auth.validate(&key) {
            warn!("Unauthorized access from {}", client_ip);
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
        }
    }

    match data.db.get_active() {
        Ok(items) => HttpResponse::Ok().json(QuarantineResponse { total: items.len(), items }),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

async fn trigger_scan(
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

async fn get_firewall_status(data: web::Data<Arc<AppState>>, req: HttpRequest) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
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
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

async fn block_ip(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    body: web::Json<FirewallBlockRequest>,
) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        warn!("Unauthorized firewall block from {}", client_ip);
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
    }

    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest().json(ErrorResponse { error: e, code: 400 });
    }

    let mgr = FirewallManager::new();
    match mgr.block_ip(&body.ip, body.comment.as_deref(), false) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("IP {} blocked", body.ip)
        })),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

async fn unblock_ip(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let client_ip = get_client_ip(&req);
    if !data.rate_limiter.check(&client_ip).await {
        return HttpResponse::TooManyRequests().json(ErrorResponse { error: "Rate limit exceeded".to_string(), code: 429 });
    }
    let key = extract_api_key(&req);
    if !data.api_key_auth.validate(&key) {
        warn!("Unauthorized firewall unblock from {}", client_ip);
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "Invalid or missing X-API-Key header".to_string(), code: 401 });
    }

    let ip = path.into_inner();
    let parts: Vec<&str> = ip.split('/').collect();
    let octets: Vec<u8> = parts[0].split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return HttpResponse::BadRequest().json(ErrorResponse { error: format!("Invalid IP: {}", ip), code: 400 });
    }

    let mgr = FirewallManager::new();
    match mgr.unblock_ip(&ip) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true, "message": format!("IP {} unblocked", ip)
        })),
        Err(e) => HttpResponse::InternalServerError().json(ErrorResponse { error: e.to_string(), code: 500 }),
    }
}

// ============================================================
// Main
// ============================================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // Try /etc/nkosi/nkosi.toml, then local config/nkosi-dev.toml
    let config = NkosiConfig::load("/etc/nkosi/nkosi.toml")
        .or_else(|_| NkosiConfig::load("config/nkosi-dev.toml"))
        .unwrap_or_default();
    let db = Database::new(&config.agent.db_path).expect("Failed to open database");
    let db = Arc::new(db);

    let api_config = load_api_config();
    info!("API keys configured: {}", api_config.api_keys.len());
    info!("Allowed origins: {:?}", api_config.allowed_origins);

    let api_key_auth = ApiKeyAuth::new(api_config.api_keys.clone());
    let rate_limiter = Arc::new(IpRateLimiter::new(api_config.rate_limit_per_second));

    let state = Arc::new(AppState {
        db,
        config: Arc::new(config),
        api_key_auth,
        rate_limiter,
    });

    let bind = "0.0.0.0:8080";
    info!("Starting NKOSI API on {}", bind);

    let allowed_origins = api_config.allowed_origins.clone();

    HttpServer::new(move || {
        let cors = if allowed_origins.is_empty() || allowed_origins.contains(&"*".to_string()) {
            Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600)
        } else {
            let mut cors = Cors::default();
            for origin in &allowed_origins {
                cors = cors.allowed_origin(origin);
            }
            cors.allowed_methods(vec!["GET", "POST"])
                .allowed_headers(vec![
                    actix_web::http::header::CONTENT_TYPE,
                    actix_web::http::header::AUTHORIZATION,
                ])
                .allow_any_header()
                .max_age(3600)
        };

        App::new()
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(state.clone()))
            // Public
            .route("/api/status", web::get().to(get_status))
            .route("/metrics", web::get().to(get_metrics))
            // Protected (auth checked inside handlers)
            .route("/api/events", web::get().to(get_events))
            .route("/api/quarantine", web::get().to(get_quarantine))
            .route("/api/scan", web::post().to(trigger_scan))
            .route("/api/firewall/status", web::get().to(get_firewall_status))
            .route("/api/firewall/block", web::post().to(block_ip))
            .route("/api/firewall/unblock/{ip}", web::post().to(unblock_ip))
            // Dashboard (public)
            .service(Files::new("/", "./dashboard").index_file("index.html"))
    })
    .bind(bind)?
    .run()
    .await
}

// ============================================================
// Load API configuration
// ============================================================

fn load_api_config() -> ApiConfig {
    let api_keys: Vec<String> = std::env::var("NKOSI_API_KEYS")
        .map(|k| k.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let allowed_origins: Vec<String> = std::env::var("NKOSI_ALLOWED_ORIGINS")
        .map(|o| o.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|_| vec!["http://localhost:8080".to_string()]);

    let rate_limit: u32 = std::env::var("NKOSI_RATE_LIMIT")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(10);

    if api_keys.is_empty() {
        let default_key = format!("nkosi_{}", hex::encode(&[1u8; 32]));
        info!("No NKOSI_API_KEYS set. Default key: {}", default_key);
        ApiConfig {
            api_keys: vec![default_key],
            allowed_origins,
            rate_limit_per_second: rate_limit,
        }
    } else {
        ApiConfig {
            api_keys,
            allowed_origins,
            rate_limit_per_second: rate_limit,
        }
    }
}
