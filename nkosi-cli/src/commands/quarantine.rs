use anyhow::Result;
use clap::Subcommand;
use colored::*;
use nkosi_common::types::*;
use nkosi_db::Database;
use nkosi_response::ResponseEngine;

#[derive(Subcommand)]
pub enum QuarantineAction {
    /// Lister les éléments en quarantaine
    List,

    /// Restaurer un fichier depuis la quarantaine
    Restore {
        /// ID de l'élément à restaurer
        id: String,
    },

    /// Supprimer un élément de la quarantaine
    Delete {
        /// ID de l'élément à supprimer
        id: String,
    },

    /// Purger tous les éléments de la quarantaine
    Purge {
        /// Confirmer la suppression
        #[arg(short, long)]
        confirm: bool,
    },
}

pub async fn handle_quarantine(action: QuarantineAction, db: &Database) -> Result<()> {
    let repo = nkosi_db::QuarantineRepository::new(db);
    let response_engine = ResponseEngine::new(
        std::env::var("NKOSI_QUARANTINE_PATH")
            .unwrap_or_else(|_| "/tmp/nkosi-quarantine".to_string())
            .into(),
        Some(db.clone()),
    );

    match action {
        QuarantineAction::List => {
            let items = repo.get_active()?;

            println!("{}", "╔══════════════════════════════════════╗".cyan());
            println!("{}", "║        Quarantine NKOSI              ║".cyan());
            println!("{}", "╚══════════════════════════════════════╝".cyan());

            if items.is_empty() {
                println!();
                println!("  {}", "La quarantaine est vide".dimmed());
            } else {
                println!("  {} éléments en quarantaine:", items.len());
                println!();
                for item in &items {
                    println!("  📁 {}", item.original_path.yellow());
                    println!("    ID: {}", item.id);
                    println!("    Score: {}/100", item.score);
                    println!("    Date: {}", item.quarantined_at);
                    println!();
                }
            }
        }
        QuarantineAction::Restore { id } => {
            let uuid = uuid::Uuid::parse_str(&id)?;
            match repo.get_by_id(&uuid) {
                Ok(Some(item)) => {
                    println!("Restauration de: {}", item.original_path);
                    match response_engine
                        .execute_action(
                            &ResponseAction::Restore,
                            Some(&item.quarantine_path),
                            None,
                            None,
                            item.score,
                            "Restauration manuelle",
                        )
                        .await
                    {
                        Ok(_) => println!("{} Restauration réussie!", "✓".green()),
                        Err(e) => println!("{} Erreur: {}", "✗".red(), e),
                    }
                }
                Ok(None) => println!("{} Élément non trouvé: {}", "✗".red(), id),
                Err(e) => println!("{} Erreur: {}", "✗".red(), e),
            }
        }
        QuarantineAction::Delete { id } => {
            let uuid = uuid::Uuid::parse_str(&id)?;
            match repo.get_by_id(&uuid) {
                Ok(Some(item)) => {
                    println!("Suppression de: {}", item.original_path);
                    match response_engine
                        .execute_action(
                            &ResponseAction::Delete,
                            Some(&item.quarantine_path),
                            None,
                            None,
                            item.score,
                            "Suppression manuelle",
                        )
                        .await
                    {
                        Ok(_) => println!("{} Suppression réussie!", "✓".green()),
                        Err(e) => println!("{} Erreur: {}", "✗".red(), e),
                    }
                }
                Ok(None) => println!("{} Élément non trouvé: {}", "✗".red(), id),
                Err(e) => println!("{} Erreur: {}", "✗".red(), e),
            }
        }
        QuarantineAction::Purge { confirm } => {
            let items = repo.get_active()?;

            if items.is_empty() {
                println!("La quarantaine est déjà vide");
                return Ok(());
            }

            if !confirm {
                println!(
                    "⚠️  Ceci va supprimer {} éléments de la quarantaine",
                    items.len()
                );
                println!("Utilisez --confirm pour confirmer");
                return Ok(());
            }

            println!("Suppression de {} éléments...", items.len());
            for item in &items {
                match response_engine
                    .execute_action(
                        &ResponseAction::Delete,
                        Some(&item.quarantine_path),
                        None,
                        None,
                        item.score,
                        "Purge",
                    )
                    .await
                {
                    Ok(_) => println!("  ✓ {}", item.original_path),
                    Err(e) => println!("  ✗ {} - Erreur: {}", item.original_path, e),
                }
            }
            println!("{} Purge terminée!", "✓".green());
        }
    }

    Ok(())
}
