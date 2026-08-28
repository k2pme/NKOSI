use actix_web::{HttpResponse, web};
use serde::Serialize;
use std::sync::Arc;

use crate::state::AppState;

#[derive(Serialize)]
struct ModuleHealthStatus {
    name: String,
    status: String,
    message: Option<String>,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    version: String,
    db_status: String,
    modules: Vec<ModuleHealthStatus>,
}

fn health_file_path() -> std::path::PathBuf {
    if let Ok(runtime_dir) = std::env::var("RUNTIME_DIRECTORY") {
        return std::path::PathBuf::from(runtime_dir).join("health.json");
    }
    let run_path = std::path::PathBuf::from("/run/nkosi/health.json");
    if run_path.parent().is_some_and(|p| p.exists()) {
        return run_path;
    }
    std::path::PathBuf::from("data/health.json")
}

pub async fn get_status(_data: web::Data<Arc<AppState>>) -> HttpResponse {
    let health_file = health_file_path();
    let modules = if health_file.exists() {
        std::fs::read_to_string(health_file)
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<nkosi_common::types::ModuleHealth>>(&s).ok())
            .map(|mh| {
                mh.into_iter()
                    .map(|m| ModuleHealthStatus {
                        name: m.name,
                        status: format!("{:?}", m.status),
                        message: m.message,
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![ModuleHealthStatus {
            name: "agent".to_string(),
            status: "unknown".to_string(),
            message: Some("Health file not found".to_string()),
        }]
    };

    let agent_status = if modules.iter().any(|m| m.status == "Failed") {
        "degraded"
    } else if modules
        .iter()
        .all(|m| m.status == "Ok" || m.status == "Disabled")
    {
        "running"
    } else {
        "unknown"
    };

    HttpResponse::Ok().json(StatusResponse {
        status: agent_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        db_status: "connected".to_string(),
        modules,
    })
}
