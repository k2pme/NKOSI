use nkosi_common::types::*;
use nkosi_db::{Database, IncidentRepository, DetectionRepository, EventRepository};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

const INCIDENT_WINDOW_SECS: i64 = 30;

pub struct IncidentManager {
    db: Database,
    pending: HashMap<String, PendingIncident>,
}

#[derive(Debug, Clone)]
struct PendingIncident {
    id: uuid::Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    status: IncidentStatus,
    global_score: u32,
    detections: Vec<Detection>,
    events: Vec<Event>,
    _keys: Vec<String>,
}

impl IncidentManager {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            pending: HashMap::new(),
        }
    }

    pub async fn process_detections(&mut self, detections: Vec<Detection>, event: &Event) {
        if detections.is_empty() {
            return;
        }

        let mut total_score: u32 = 0;
        for d in &detections {
            total_score += d.score_contribution;
        }
        let avg_score = total_score / detections.len() as u32;

        let file_key = event.file_path.clone().unwrap_or_else(|| "unknown".to_string());
        let pid_key = event.pid.map(|p| p.to_string()).unwrap_or_else(|| "no_pid".to_string());
        let key = format!("{}:{}", file_key, pid_key);

        if let Some(pending) = self.pending.get_mut(&key) {
            let now = chrono::Utc::now();
            let elapsed = (now - pending.created_at).num_seconds();

            if elapsed <= INCIDENT_WINDOW_SECS {
                pending.detections.extend(detections);
                pending.events.push(event.clone());
                pending.global_score = pending.global_score.max(avg_score);
                pending.updated_at = now;
                let pending_id = pending.id;
                let pending_score = pending.global_score;
                let _ = pending;
                self.update_incident_inner(pending_id, pending_score).await;
                return;
            } else {
                let pending_clone = pending.clone();
                let _ = pending;
                self.finalize_incident(&pending_clone).await;
            }
        }

        let id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let mut pending = PendingIncident {
            id,
            created_at: now,
            updated_at: now,
            status: IncidentStatus::Open,
            global_score: avg_score,
            detections,
            events: vec![event.clone()],
            _keys: vec![key.clone()],
        };

        if avg_score >= 70 {
            pending.status = IncidentStatus::Investigating;
        }

        self.pending.insert(key, pending.clone());
        self.persist_incident(&pending).await;
    }

    async fn update_incident_inner(&self, id: uuid::Uuid, score: u32) {
        let repo = IncidentRepository::new(&self.db);
        if let Err(e) = repo.update_score(&id, score) {
            warn!("Failed to update incident score: {}", e);
        }

        if score >= 70 {
            let _ = repo.update_status(&id, IncidentStatus::Investigating);
        }
    }

    async fn persist_incident(&self, pending: &PendingIncident) {
        let incident = Incident {
            id: pending.id,
            created_at: pending.created_at,
            updated_at: pending.updated_at,
            status: pending.status.clone(),
            global_score: pending.global_score,
            summary: Some(self.build_summary(pending)),
        };

        let incident_repo = IncidentRepository::new(&self.db);
        if let Err(e) = incident_repo.insert(&incident) {
            warn!("Failed to persist incident: {}", e);
            return;
        }

        let detection_repo = DetectionRepository::new(&self.db);
        for detection in &pending.detections {
            if let Err(e) = detection_repo.insert(detection) {
                warn!("Failed to persist detection: {}", e);
            }
        }

        let event_repo = EventRepository::new(&self.db);
        for event in &pending.events {
            let mut ev = event.clone();
            ev.incident_id = Some(pending.id);
            if let Err(e) = event_repo.insert(&ev) {
                warn!("Failed to link event to incident: {}", e);
            }
        }

        info!("Incident {} created: score={}, status={:?}, detections={}",
            pending.id, pending.global_score, pending.status, pending.detections.len());
    }

    async fn finalize_incident(&mut self, pending: &PendingIncident) {
        let repo = IncidentRepository::new(&self.db);
        let status = if pending.global_score >= 70 {
            IncidentStatus::Resolved
        } else {
            IncidentStatus::FalsePositive
        };
        let status_clone = status.clone();
        let _ = repo.update_status(&pending.id, status_clone);
        info!("Incident {} finalized: {:?}", pending.id, status);
    }

    fn build_summary(&self, pending: &PendingIncident) -> String {
        let engines: Vec<String> = pending.detections.iter()
            .map(|d| format!("{:?}", d.detection_engine))
            .collect();
        let rules: Vec<String> = pending.detections.iter()
            .filter_map(|d| d.rule_name.clone())
            .collect();

        format!(
            "Incident with {} detections (score: {}). Engines: {}. Rules: {}",
            pending.detections.len(),
            pending.global_score,
            engines.join(", "),
            rules.join(", ")
        )
    }

    #[allow(dead_code)]
    pub async fn get_recent_incidents(&self, limit: i32) -> Vec<Incident> {
        let repo = IncidentRepository::new(&self.db);
        repo.get_recent(limit).unwrap_or_default()
    }

    #[allow(dead_code)]
    pub async fn get_incident(&self, id: &uuid::Uuid) -> Option<Incident> {
        let repo = IncidentRepository::new(&self.db);
        repo.get_by_id(id).ok().flatten()
    }

    #[allow(dead_code)]
    pub async fn get_incident_details(&self, id: &uuid::Uuid) -> Option<IncidentDetails> {
        let incident = self.get_incident(id).await?;
        let detection_repo = DetectionRepository::new(&self.db);
        let event_repo = EventRepository::new(&self.db);

        let detections = detection_repo.get_by_incident(id).unwrap_or_default();
        let events = event_repo.get_by_incident(id).unwrap_or_default();

        Some(IncidentDetails {
            incident,
            detections,
            events,
        })
    }

    #[allow(dead_code)]
    pub async fn resolve_incident(&self, id: &uuid::Uuid) {
        let repo = IncidentRepository::new(&self.db);
        let _ = repo.update_status(id, IncidentStatus::Resolved);
    }

    #[allow(dead_code)]
    pub async fn mark_false_positive(&self, id: &uuid::Uuid) {
        let repo = IncidentRepository::new(&self.db);
        let _ = repo.update_status(id, IncidentStatus::FalsePositive);
    }

    #[allow(dead_code)]
    pub async fn prune_stale(&mut self) {
        let now = chrono::Utc::now();
        let stale_keys: Vec<String> = self.pending.keys()
            .filter(|key| {
                if let Some(pending) = self.pending.get(*key) {
                    (now - pending.created_at).num_seconds() > INCIDENT_WINDOW_SECS * 2
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        for key in stale_keys {
            if let Some(pending) = self.pending.remove(&key)
                && pending.detections.len() >= 3
            {
                let pending_clone = pending.clone();
                self.finalize_incident(&pending_clone).await;
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentDetails {
    pub incident: Incident,
    pub detections: Vec<Detection>,
    pub events: Vec<Event>,
}
