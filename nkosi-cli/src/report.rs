use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub scan_type: String,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_secs: f64,
    pub files_scanned: u32,
    pub threats_found: u32,
    pub suspicious_found: u32,
    pub detections: Vec<DetectionEntry>,
    pub summary: ScanSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionEntry {
    pub file_path: String,
    pub engine: String,
    pub rule_name: Option<String>,
    pub score: u32,
    pub confidence: f32,
    pub details: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub risk_level: String,
    pub max_score: u32,
    pub engines_triggered: Vec<String>,
    pub recommendations: Vec<String>,
}

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(
        &self,
        scan_type: &str,
        target: &str,
        files_scanned: u32,
        detections: Vec<DetectionEntry>,
        started_at: DateTime<Utc>,
    ) -> ScanReport {
        let completed_at = Utc::now();
        let duration = (completed_at - started_at).num_milliseconds() as f64 / 1000.0;

        let threats_found = detections.iter().filter(|d| d.score >= 70).count() as u32;
        let suspicious_found = detections
            .iter()
            .filter(|d| d.score >= 30 && d.score < 70)
            .count() as u32;

        let max_score = detections.iter().map(|d| d.score).max().unwrap_or(0);

        let risk_level = match max_score {
            0 => "Clean".to_string(),
            1..=29 => "Low".to_string(),
            30..=69 => "Suspicious".to_string(),
            _ => "Malicious".to_string(),
        };

        let engines_triggered: Vec<String> = detections
            .iter()
            .map(|d| d.engine.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let mut recommendations = Vec::new();
        if threats_found > 0 {
            recommendations.push("Quarantine malicious files immediately".to_string());
            recommendations.push("Block associated network connections".to_string());
            recommendations.push("Investigate incident timeline".to_string());
        }
        if suspicious_found > 0 {
            recommendations.push("Review suspicious files manually".to_string());
            recommendations.push("Enable enhanced monitoring".to_string());
        }
        if threats_found == 0 && suspicious_found == 0 {
            recommendations.push("System appears clean".to_string());
        }

        ScanReport {
            scan_id: uuid::Uuid::new_v4().to_string(),
            scan_type: scan_type.to_string(),
            target: target.to_string(),
            started_at,
            completed_at,
            duration_secs: duration,
            files_scanned,
            threats_found,
            suspicious_found,
            detections,
            summary: ScanSummary {
                risk_level,
                max_score,
                engines_triggered,
                recommendations,
            },
        }
    }

    pub fn save_json(&self, report: &ScanReport, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(report)?;
        std::fs::write(path, &json)?;
        info!("JSON report saved: {}", path.display());
        Ok(())
    }

    pub fn save_txt(&self, report: &ScanReport, path: &Path) -> anyhow::Result<()> {
        let mut txt = String::new();
        txt.push_str("========================================\n");
        txt.push_str("         NKOSI SCAN REPORT              \n");
        txt.push_str("========================================\n\n");
        txt.push_str(&format!("Scan ID:      {}\n", report.scan_id));
        txt.push_str(&format!("Type:         {}\n", report.scan_type));
        txt.push_str(&format!("Target:       {}\n", report.target));
        txt.push_str(&format!(
            "Started:      {}\n",
            report.started_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        txt.push_str(&format!(
            "Completed:    {}\n",
            report.completed_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        txt.push_str(&format!("Duration:     {:.1}s\n", report.duration_secs));
        txt.push_str(&format!("Files:        {}\n", report.files_scanned));
        txt.push_str("\n--- Summary ---\n");
        txt.push_str(&format!("Risk Level:   {}\n", report.summary.risk_level));
        txt.push_str(&format!("Max Score:    {}\n", report.summary.max_score));
        txt.push_str(&format!("Threats:      {}\n", report.threats_found));
        txt.push_str(&format!("Suspicious:   {}\n", report.suspicious_found));
        txt.push_str(&format!(
            "Engines:      {}\n",
            report.summary.engines_triggered.join(", ")
        ));

        if !report.detections.is_empty() {
            txt.push_str("\n--- Detections ---\n");
            for (i, d) in report.detections.iter().enumerate() {
                txt.push_str(&format!(
                    "{}. [{}] {} (score: {}, conf: {:.0}%)\n",
                    i + 1,
                    d.engine,
                    d.file_path,
                    d.score,
                    d.confidence * 100.0
                ));
                if let Some(ref rule) = d.rule_name {
                    txt.push_str(&format!("   Rule: {}\n", rule));
                }
                if let Some(ref details) = d.details {
                    txt.push_str(&format!("   Details: {}\n", details));
                }
                if let Some(ref action) = d.action {
                    txt.push_str(&format!("   Action: {}\n", action));
                }
            }
        }

        if !report.summary.recommendations.is_empty() {
            txt.push_str("\n--- Recommendations ---\n");
            for rec in &report.summary.recommendations {
                txt.push_str(&format!("  - {}\n", rec));
            }
        }

        txt.push_str("\n========================================\n");

        std::fs::write(path, &txt)?;
        info!("TXT report saved: {}", path.display());
        Ok(())
    }
}
