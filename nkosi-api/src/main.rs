mod handlers;
mod state;

use actix_cors::Cors;
use actix_files::Files;
use actix_web::{App, HttpServer, middleware, web};
use std::sync::Arc;
use tracing::info;

use nkosi_common::config::NkosiConfig;
use nkosi_db::Database;

use lazy_static::lazy_static;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};

use crate::state::{ApiConfig, ApiKeyAuth, AppState, IpRateLimiter};

lazy_static! {
    pub static ref EVENTS_TOTAL: IntCounter =
        IntCounter::new("nkosi_events_total", "Total events processed").unwrap();
    pub static ref THREATS_DETECTED: IntCounter =
        IntCounter::new("nkosi_threats_detected", "Total threats detected").unwrap();
    pub static ref SCANS_TOTAL: IntCounter =
        IntCounter::new("nkosi_scans_total", "Total scans performed").unwrap();
    pub static ref QUARANTINE_FILES: IntGauge =
        IntGauge::new("nkosi_quarantine_files", "Files in quarantine").unwrap();
    pub static ref REGISTRY: Registry = Registry::new();
}

fn register_metrics() {
    for metric in [
        Box::new(EVENTS_TOTAL.clone()) as Box<dyn prometheus::core::Collector>,
        Box::new(THREATS_DETECTED.clone()),
        Box::new(SCANS_TOTAL.clone()),
        Box::new(QUARANTINE_FILES.clone()),
    ] {
        // Metrics may already be registered in tests or embedded deployments.
        if let Err(e) = REGISTRY.register(metric) {
            tracing::warn!("Unable to register Prometheus metric: {}", e);
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    register_metrics();

    let api_keys_env = std::env::var("NKOSI_API_KEYS").unwrap_or_default();
    let allow_default = std::env::var("NKOSI_ALLOW_DEFAULT_KEY").unwrap_or_default() == "1";

    if api_keys_env.is_empty() && !allow_default {
        eprintln!("ERREUR: Aucune API key configurée.");
        eprintln!(
            "Définissez NKOSI_API_KEYS=clé1,clé2 ou NKOSI_ALLOW_DEFAULT_KEY=1 pour le mode dev."
        );
        std::process::exit(1);
    }

    if allow_default && api_keys_env.is_empty() {
        tracing::warn!("Mode dev: API key par défaut utilisée. NE PAS UTILISER EN PRODUCTION.");
    }

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
        _config: Arc::new(config),
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
            .route("/api/status", web::get().to(handlers::status::get_status))
            .route("/metrics", web::get().to(get_metrics))
            // Protected (auth checked inside handlers)
            .route("/api/events", web::get().to(handlers::events::get_events))
            .route(
                "/api/quarantine",
                web::get().to(handlers::quarantine::get_quarantine),
            )
            .route("/api/scan", web::post().to(handlers::scan::trigger_scan))
            .route(
                "/api/firewall/status",
                web::get().to(handlers::firewall::get_firewall_status),
            )
            .route(
                "/api/firewall/block",
                web::post().to(handlers::firewall::block_ip),
            )
            .route(
                "/api/firewall/unblock/{ip}",
                web::post().to(handlers::firewall::unblock_ip),
            )
            // Multi-agent (F2.11)
            .route("/api/agents", web::get().to(handlers::agents::get_agents))
            .route(
                "/api/agents/{id}",
                web::get().to(handlers::agents::get_agent_detail),
            )
            .route(
                "/api/events/filtered",
                web::get().to(handlers::events::get_events_filtered),
            )
            .route("/api/alertes", web::get().to(handlers::agents::get_alertes))
            .route(
                "/api/stats/consolidated",
                web::get().to(handlers::agents::get_consolidated_stats),
            )
            .route(
                "/api/report/consolidated",
                web::get().to(handlers::agents::get_consolidated_report),
            )
            // Dashboard (public)
            .service(Files::new("/", "./dashboard").index_file("index.html"))
    })
    .bind(bind)?
    .run()
    .await
}

async fn get_metrics() -> actix_web::HttpResponse {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    actix_web::HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(buffer)
}

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
        let default_key = format!("nkosi_{}", hex::encode([1u8; 32]));
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
