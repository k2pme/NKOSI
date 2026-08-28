use anyhow::Result;
use colored::*;
use nkosi_common::types::*;
use nkosi_db::Database;

pub async fn handle_status(db: &Database) -> Result<()> {
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║       NKOSI Security Status          ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    
    let event_repo = nkosi_db::EventRepository::new(db);
    let events = event_repo.get_recent(100)?;
    
    let quarantine_repo = nkosi_db::QuarantineRepository::new(db);
    let quarantine_items = quarantine_repo.get_active()?;
    
    println!();
    println!("  {} Base de données:", "📊".blue());
    println!("    • Événements: {}", events.len());
    println!("    • Quarantaine: {}", quarantine_items.len());
    
    println!();
    println!("  {} Événements récents:", "📋".green());
    for event in events.iter().take(5) {
        let severity_icon = match event.severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Info => "⚪",
        };
        println!(
            "    {} [{:?}] {} - {:?}",
            severity_icon,
            event.event_type,
            event.source_module,
            event.severity
        );
    }
    
    if events.is_empty() {
        println!("    {}", "Aucun événement récent".dimmed());
    }
    
    println!();
    Ok(())
}
