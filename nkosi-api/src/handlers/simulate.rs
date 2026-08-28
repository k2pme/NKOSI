use actix_web::{HttpRequest, HttpResponse, web};
use nkosi_common::config::SimulationScenario;
use nkosi_common::types::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

use crate::state::{AppState, ErrorResponse, extract_api_key, get_client_ip};

#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    #[serde(default)]
    pub scenarios: Vec<SimulationScenario>,
    #[serde(default)]
    pub count: u32,
}

#[derive(Debug, Serialize)]
pub struct SimulateResponse {
    pub simulated: u32,
    pub events: Vec<Event>,
    pub message: String,
}

pub async fn simulate_threats(
    data: web::Data<Arc<AppState>>,
    req: HttpRequest,
    body: web::Json<SimulateRequest>,
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
        warn!("Unauthorized simulation access from {}", client_ip);
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "Invalid or missing X-API-Key header".to_string(),
            code: 401,
        });
    }

    let count = body.count.clamp(1, 50);
    let scenarios = if body.scenarios.is_empty() {
        vec![
            SimulationScenario::Ransomware,
            SimulationScenario::Cryptominer,
            SimulationScenario::Webshell,
        ]
    } else {
        body.scenarios.clone()
    };

    let mut simulated = 0u32;
    let mut events = Vec::new();

    for _ in 0..count {
        for scenario in &scenarios {
            let event = generate_simulated_event(scenario);
            events.push(event.clone());

            let repo = nkosi_db::EventRepository::new(&data.db);
            if let Err(e) = repo.insert(&event) {
                warn!("Failed to insert simulated event: {}", e);
            } else {
                simulated += 1;
            }
        }
    }

    HttpResponse::Ok().json(SimulateResponse {
        simulated,
        events,
        message: format!("Simulated {} threat events", simulated),
    })
}

fn generate_simulated_event(scenario: &SimulationScenario) -> Event {
    let (file_path, score, severity, _detection_engine) = match scenario {
        SimulationScenario::Ransomware => (
            "/tmp/simulated_ransomware_note.txt",
            95,
            Severity::Critical,
            DetectionEngine::StaticAnalysis,
        ),
        SimulationScenario::Cryptominer => (
            "/tmp/simulated_cryptominer",
            85,
            Severity::High,
            DetectionEngine::Yara,
        ),
        SimulationScenario::Webshell => (
            "/tmp/simulated_shell.php",
            80,
            Severity::High,
            DetectionEngine::Yara,
        ),
        SimulationScenario::Trojan => (
            "/tmp/simulated_trojan.bin",
            100,
            Severity::Critical,
            DetectionEngine::Hash,
        ),
        SimulationScenario::Spyware => (
            "/tmp/simulated_spyware",
            75,
            Severity::High,
            DetectionEngine::StaticAnalysis,
        ),
        SimulationScenario::Backdoor => (
            "/tmp/simulated_backdoor.sh",
            90,
            Severity::Critical,
            DetectionEngine::StaticAnalysis,
        ),
    };

    let mut event = Event::new(EventType::Detection, "simulator_api");
    event.file_path = Some(file_path.to_string());
    event.file_hash = Some(Uuid::new_v4().to_string());
    event.score = Some(score);
    event.severity = severity;
    event.action = Some(ResponseAction::Quarantine);
    event.result = Some(format!("Simulated {:?} detection", scenario));
    event.agent_id = Some("simulation".to_string());
    event.agent_host = Some("simulated-host".to_string());

    event
}
