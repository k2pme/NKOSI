use anyhow::Result;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use nkosi_common::config::NkosiConfig;
use nkosi_common::types::*;
use nkosi_db::Database;
use nkosi_engines::{HashEngine, YaraEngine, StaticAnalyzer};
use nkosi_risk::{RiskEngine, RiskConfig};
use nkosi_response::ResponseEngine;
use std::path::Path;
use crate::report;

fn scan_file(
    path: &Path,
    hash_engine: &HashEngine,
    yara_engine: &YaraEngine,
    static_analyzer: &StaticAnalyzer,
) -> Option<Detection> {
    if let Some(detection) = hash_engine.analyze_file(path) {
        return Some(detection);
    }
    
    let yara_detections = yara_engine.scan_file(path);
    if !yara_detections.is_empty() {
        return Some(yara_detections.into_iter().next().unwrap());
    }
    
    if let Some(detection) = static_analyzer.analyze_file(path) {
        return Some(detection);
    }
    
    None
}

pub async fn handle_scan(db: &Database, config: &NkosiConfig, path: &Path, recursive: bool, quiet: bool, dry_run: bool) -> Result<()> {
    println!("{}", "Scan en cours...".cyan().bold());
    println!("  Chemin: {}", path.display());
    println!("  Récursif: {}", recursive);
    if dry_run {
        println!("  {} Mode dry-run (aucune action ne sera effectuée)", "⚠️".yellow());
    }
    println!();
    
    let hash_engine = HashEngine::new();
    let yara_engine = YaraEngine::new();
    let static_analyzer = StaticAnalyzer::new();
    let risk_engine = RiskEngine::new(RiskConfig::default());
    let response_engine = ResponseEngine::new(
        config.quarantine.path.clone(),
        Some(db.clone()),
    );
    
    let pb = if !quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.cyan} {msg}")?
        );
        pb.set_message("Scan en cours...");
        Some(pb)
    } else {
        None
    };
    
    let started_at = chrono::Utc::now();
    let mut scanned_files = 0u32;
    let mut detected_threats = 0u32;
    let mut quarantined_files = 0u32;
    let mut report_detections: Vec<report::DetectionEntry> = Vec::new();
    
    if path.is_file() {
        if let Some(detection) = scan_file(path, &hash_engine, &yara_engine, &static_analyzer) {
            let assessment = risk_engine.evaluate(vec![detection]);
            
            report_detections.push(report::DetectionEntry {
                file_path: path.to_string_lossy().to_string(),
                engine: "multi".to_string(),
                rule_name: Some("Static Analysis".to_string()),
                score: assessment.score,
                confidence: 0.7,
                details: Some(assessment.details.clone()),
                action: None,
            });
            
            println!("  {} {} - Score: {}/100 ({:?})", 
                "⚠️".red().bold(),
                path.display().to_string().red(),
                assessment.score,
                assessment.level
            );
            
            if assessment.score >= 70 {
                let action = risk_engine.get_recommended_action(&assessment.level);
                if dry_run {
                    println!("    [DRY-RUN] Action ignorée: {:?}", action);
                } else {
                    match response_engine.execute_action(&action, Some(&path.to_string_lossy()), None, None, assessment.score, &assessment.details).await {
                        Ok(_) => {
                            println!("    Action: {:?}", action);
                            report_detections.last_mut().unwrap().action = Some(format!("{:?}", action));
                            quarantined_files += 1;
                        }
                        Err(e) => println!("    Erreur action: {}", e),
                    }
                }
            }
            detected_threats += 1;
        }
        scanned_files += 1;
    } else if path.is_dir() {
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Some(detection) = scan_file(entry.path(), &hash_engine, &yara_engine, &static_analyzer) {
                let assessment = risk_engine.evaluate(vec![detection]);
                
                report_detections.push(report::DetectionEntry {
                    file_path: entry.path().to_string_lossy().to_string(),
                    engine: "multi".to_string(),
                    rule_name: Some("Static Analysis".to_string()),
                    score: assessment.score,
                    confidence: 0.7,
                    details: Some(assessment.details.clone()),
                    action: None,
                });
                
                if !quiet {
                    println!("  {} {} - Score: {}/100", 
                        "⚠️".red(),
                        entry.path().display().to_string().red(),
                        assessment.score
                    );
                }
                
                if assessment.score >= 70 {
                    let action = risk_engine.get_recommended_action(&assessment.level);
                    if dry_run {
                        if !quiet {
                            println!("    [DRY-RUN] Action ignorée: {:?}", action);
                        }
                    } else {
                        let _ = response_engine.execute_action(&action, Some(&entry.path().to_string_lossy()), None, None, assessment.score, &assessment.details).await;
                        report_detections.last_mut().unwrap().action = Some(format!("{:?}", action));
                        quarantined_files += 1;
                    }
                }
                detected_threats += 1;
            }
            scanned_files += 1;
        }
    }
    
    if let Some(pb) = pb {
        pb.finish_with_message("Scan terminé");
    }

    let report_gen = report::ReportGenerator::new();
    let scan_report = report_gen.generate(
        "scan",
        &path.to_string_lossy(),
        scanned_files,
        report_detections,
        started_at,
    );
    
    let report_dir = std::path::Path::new("data/reports");
    std::fs::create_dir_all(report_dir)?;
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    
    let json_path = report_dir.join(format!("scan_{}.json", timestamp));
    let txt_path = report_dir.join(format!("scan_{}.txt", timestamp));
    
    report_gen.save_json(&scan_report, &json_path)?;
    report_gen.save_txt(&scan_report, &txt_path)?;
    
    println!();
    println!("  {} Scan terminé:", "✅".green().bold());
    println!("    • Fichiers scannés: {}", scanned_files);
    println!("    • Menaces détectées: {}", detected_threats);
    println!("    • Mis en quarantaine: {}", quarantined_files);
    println!("    • Rapport: {}", json_path.display());
    
    Ok(())
}

pub async fn handle_quick_scan(db: &Database, config: &NkosiConfig) -> Result<()> {
    println!("{}", "Scan rapide des répertoires critiques...".cyan().bold());
    
    let critical_dirs = vec![
        "/tmp",
        "/var/tmp",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/home",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/systemd/system",
        "/etc/init.d",
    ];
    
    for dir in &critical_dirs {
        if Path::new(dir).exists() {
            println!("  Scan de {}", dir);
            handle_scan(db, config, Path::new(dir), true, true, false).await?;
        }
    }
    
    println!();
    println!("{}", "Scan rapide terminé!".green().bold());
    Ok(())
}

pub async fn handle_full_scan(db: &Database, config: &NkosiConfig) -> Result<()> {
    println!("{}", "Scan complet du système...".cyan().bold());
    
    let root_dirs = vec![
        "/",
        "/home",
        "/usr",
        "/var",
        "/tmp",
        "/opt",
    ];
    
    for dir in &root_dirs {
        if Path::new(dir).exists() {
            println!("  Scan de {}", dir);
            handle_scan(db, config, Path::new(dir), true, true, false).await?;
        }
    }
    
    println!();
    println!("{}", "Scan complet terminé!".green().bold());
    Ok(())
}
