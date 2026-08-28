use anyhow::Result;
use clap::Subcommand;
use nkosi_common::types::AgentStatus;
use nkosi_db::Database;

#[derive(Subcommand)]
pub enum ReportCommand {
    /// Rapport consolidé de tous les agents
    Consolidated {
        /// Fichier de sortie (défaut: stdout)
        #[arg(short, long)]
        output: Option<String>,
        /// Format de sortie (json ou text)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

pub fn handle_consolidated_report(db: &Database, output: Option<&str>, format: &str) -> Result<()> {
    let repo = nkosi_db::AgentRepository::new(db);

    let agents = repo.get_all().unwrap_or_default();
    let stats = repo.get_consolidated_stats().ok();

    if format == "json" {
        let report = serde_json::json!({
            "stats": stats,
            "agents": agents,
            "generated_at": chrono::Utc::now().to_rfc3339(),
        });
        let json = serde_json::to_string_pretty(&report)?;
        if let Some(path) = output {
            std::fs::write(path, &json)?;
            println!("Rapport écrit dans {}", path);
        } else {
            println!("{}", json);
        }
    } else {
        let mut lines = Vec::new();
        lines.push("=== NKOSI Rapport Consolidé ===".to_string());
        lines.push(format!("Généré le: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")));
        lines.push(String::new());

        if let Some(ref s) = stats {
            lines.push("--- Statistiques Globales ---".to_string());
            lines.push(format!("  Agents total: {} ({} en ligne, {} hors ligne)", s.total_agents, s.online_agents, s.offline_agents));
            lines.push(format!("  Événements total: {}", s.total_events));
            lines.push(format!("  Menaces détectées: {}", s.total_threats));
            lines.push(format!("  Fichiers en quarantaine: {}", s.total_quarantine));
            lines.push(String::new());
        }

        lines.push("--- Agents ---".to_string());
        if agents.is_empty() {
            lines.push("  Aucun agent enregistré".to_string());
        } else {
            for agent in &agents {
                lines.push(format!(
                    "  {} ({}) — {} — Score: {} — Dernier seen: {}",
                    agent.hostname, agent.ip_address,
                    match agent.status {
                        AgentStatus::Online => "En ligne",
                        AgentStatus::Offline => "Hors ligne",
                        AgentStatus::Degraded => "Dégradé",
                    },
                    agent.score,
                    agent.last_seen.format("%Y-%m-%d %H:%M:%S"),
                ));
            }
        }

        let report = lines.join("\n");
        if let Some(path) = output {
            std::fs::write(path, &report)?;
            println!("Rapport écrit dans {}", path);
        } else {
            println!("{}", report);
        }
    }

    Ok(())
}
