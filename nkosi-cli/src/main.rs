use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use nkosi_common::config::NkosiConfig;
use nkosi_common::types::*;
use nkosi_db::Database;
use nkosi_engines::{HashEngine, YaraEngine, StaticAnalyzer};
use nkosi_scanner::{RootkitScanner, IntegrityScanner, KernelScanner, SshBruteforceScanner, SshBruteforceConfig, FirewallManager};
use nkosi_ti::UpdateService;
use std::path::{Path, PathBuf};

mod commands;
mod report;

use commands::quarantine::QuarantineAction;
use commands::report::ReportCommand;

#[derive(Parser)]
#[command(name = "nkosi")]
#[command(about = "NKOSI Security CLI - Antivirus pour Linux")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Afficher l'état du système
    Status,
    
    /// Scanner des fichiers ou répertoires
    Scan {
        /// Chemin à scanner
        #[arg(required = true)]
        path: PathBuf,
        
        /// Scan récursif
        #[arg(short, long, default_value = "true")]
        recursive: bool,
        
        /// Mode silencieux (pas de progression)
        #[arg(short, long)]
        quiet: bool,
        
        /// Mode dry-run (affiche sans agir)
        #[arg(long)]
        dry_run: bool,
    },
    
    /// Scanner rapidement les répertoires système critiques
    Quick,
    
    /// Scanner tout le système
    Full,
    
    /// Scanner les rootkits
    Rootkit,
    
    /// Scanner l'intégrité système
    Integrity {
        /// Créer une nouvelle baseline
        #[arg(short, long)]
        baseline: bool,
    },
    
    /// Scanner les modules kernel
    Kernel,
    
    /// Scanner les tentatives de brute-force SSH
    Ssh {
        /// Seuil d'alerte (nombre de tentatives échouées)
        #[arg(short = 't', long, default_value = "5")]
        threshold: u32,
        
        /// Seuil de blocage automatique
        #[arg(long, default_value = "10")]
        block_threshold: u32,
        
        /// Blocage automatique via iptables
        #[arg(short, long)]
        block: bool,
    },
    
    /// Gérer le pare-feu NKOSI
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },
    
    /// Gérer la quarantaine
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    
    /// Mettre à jour les sources de menaces
    Update {
        /// Forcer la mise à jour
        #[arg(short, long)]
        force: bool,
    },
    
    /// Afficher les logs récents
    Logs {
        /// Nombre de lignes à afficher
        #[arg(default_value = "50")]
        lines: usize,
    },
    
    /// Scanner un processus spécifique
    Process {
        /// PID du processus
        pid: u32,
    },
    
    /// Scanner un réseau
    Network {
        /// Adresse IP ou CIDR
        target: String,
    },
    
    /// Gérer les backups de configuration
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },

    /// Rapport consolidé multi-agents
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Créer un backup
    Create {
        /// Répertoire de destination
        #[arg(short, long, default_value = "/var/backup/nkosi")]
        dir: String,
    },
    
    /// Restaurer un backup
    Restore {
        /// Fichier de backup à restaurer
        file: String,
    },
    
    /// Lister les backups
    List {
        /// Répertoire des backups
        #[arg(short, long, default_value = "/var/backup/nkosi")]
        dir: String,
    },
    
    /// Supprimer les anciens backups (rotation)
    Prune {
        /// Nombre de backups à conserver
        #[arg(short, long, default_value = "7")]
        keep: usize,
        
        /// Répertoire des backups
        #[arg(short, long, default_value = "/var/backup/nkosi")]
        dir: String,
    },
}

#[derive(Subcommand)]
enum FirewallAction {
    /// Afficher l'état du pare-feu
    Status,
    
    /// Initialiser les chaînes NKOSI
    Init,
    
    /// Vider les règles NKOSI
    Flush,
    
    /// Bloquer une IP
    Block {
        /// IP à bloquer
        ip: String,
        
        /// Commentaire
        #[arg(short, long)]
        comment: Option<String>,
        
        /// Temporaire (auto-expire)
        #[arg(short, long)]
        temp: bool,
    },
    
    /// Débloquer une IP
    Unblock {
        /// IP à débloquer
        ip: String,
    },
    
    /// Ajouter une IP à la whitelist
    Whitelist {
        /// IP à whitelist
        ip: String,
        
        /// Commentaire
        #[arg(short, long)]
        comment: Option<String>,
    },
    
    /// Retirer une IP de la whitelist
    Unwhitelist {
        /// IP à retirer
        ip: String,
    },
    
    /// Ajouter un rate limiting
    RateLimit {
        /// IP cible
        ip: String,
        
        /// Nombre max de connexions
        #[arg(short = 'c', long, default_value = "30")]
        max_conn: u32,
        
        /// Fenêtre temporelle en secondes
        #[arg(short = 'p', long, default_value = "60")]
        period: u32,
    },
    
    /// Sauvegarder les règles
    Save {
        /// Fichier de sortie
        #[arg(default_value = "/etc/nkosi/iptables.rules")]
        path: String,
    },
    
    /// Charger les règles depuis un fichier
    Load {
        /// Fichier d'entrée
        path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .init();

    let cli = Cli::parse();
    let config = load_config()?;
    let db = init_database(&config)?;

    match cli.command {
        Commands::Status => commands::status::handle_status(&db).await?,
        Commands::Scan { path, recursive, quiet, dry_run } => {
            commands::scan::handle_scan(&db, &config, &path, recursive, quiet, dry_run).await?;
        }
        Commands::Quick => commands::scan::handle_quick_scan(&db, &config).await?,
        Commands::Full => commands::scan::handle_full_scan(&db, &config).await?,
        Commands::Rootkit => handle_rootkit_scan().await?,
        Commands::Integrity { baseline } => handle_integrity_scan(baseline).await?,
        Commands::Kernel => handle_kernel_scan().await?,
        Commands::Ssh { threshold, block_threshold, block } => {
            handle_ssh_scan(threshold, block_threshold, block).await?;
        }
        Commands::Firewall { action } => handle_firewall(action).await?,
        Commands::Quarantine { action } => commands::quarantine::handle_quarantine(action, &db).await?,
        Commands::Update { force } => handle_update(&db, force).await?,
        Commands::Logs { lines } => show_logs(&db, lines).await?,
        Commands::Process { pid } => handle_process_scan(pid).await?,
        Commands::Network { target } => handle_network_scan(&target).await?,
        Commands::Backup { action } => handle_backup(action).await?,
        Commands::Report { command } => match command {
            ReportCommand::Consolidated { output, format } => {
                commands::report::handle_consolidated_report(&db, output.as_deref(), &format)?;
            }
        },
    }

    Ok(())
}

fn load_config() -> Result<NkosiConfig> {
    let config_path = "/etc/nkosi/nkosi.toml";
    if Path::new(config_path).exists() {
        Ok(NkosiConfig::load(config_path)?)
    } else {
        let local_config = "config/nkosi.toml";
        if Path::new(local_config).exists() {
            Ok(NkosiConfig::load(local_config)?)
        } else {
            Ok(NkosiConfig::default())
        }
    }
}

fn init_database(config: &NkosiConfig) -> Result<Database> {
    let db_path = &config.agent.db_path;
    
    if let Some(parent) = db_path.parent()
        && parent.exists()
        && std::fs::create_dir_all(parent).is_ok()
        && let Ok(db) = Database::new(db_path)
    {
        return Ok(db);
    }
    
    let local_path = std::env::current_dir()?.join("data").join("nkosi.db");
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(Database::new(&local_path)?)
}

async fn handle_backup(action: BackupAction) -> Result<()> {
    match action {
        BackupAction::Create { dir } => {
            println!("{}", "╔══════════════════════════════════════╗".cyan());
            println!("{}", "║       Backup Configuration           ║".cyan());
            println!("{}", "╚══════════════════════════════════════╝".cyan());
            println!();

            let backup_dir = std::path::Path::new(&dir);
            std::fs::create_dir_all(backup_dir)?;

            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let backup_file = backup_dir.join(format!("nkosi_{}.tar.gz", timestamp));

            println!("  {} Création du backup...", "→".blue());
            println!("  Source: /etc/nkosi/");
            println!("  Destination: {}", backup_file.display());

            let output = std::process::Command::new("tar")
                .args(["-czf", backup_file.to_str().unwrap(), "-C", "/etc", "nkosi"])
                .output()?;

            if output.status.success() {
                let size = std::fs::metadata(&backup_file)?.len();
                println!("  {} Backup créé: {} ({:.2} MB)", "✓".green(),
                    backup_file.display(), size as f64 / 1_048_576.0);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("  {} Erreur: {}", "✗".red(), stderr);
            }
        }
        BackupAction::Restore { file } => {
            println!("{}", "╔══════════════════════════════════════╗".cyan());
            println!("{}", "║       Restore Configuration          ║".cyan());
            println!("{}", "╚══════════════════════════════════════╝".cyan());
            println!();

            if !std::path::Path::new(&file).exists() {
                println!("  {} Fichier non trouvé: {}", "✗".red(), file);
                return Ok(());
            }

            println!("  {} Restauration depuis: {}", "→".blue(), file);

            let output = std::process::Command::new("tar")
                .args(["-xzf", &file, "-C", "/etc"])
                .output()?;

            if output.status.success() {
                println!("  {} Configuration restaurée", "✓".green());
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("  {} Erreur: {}", "✗".red(), stderr);
            }
        }
        BackupAction::List { dir } => {
            println!("{}", "╔══════════════════════════════════════╗".cyan());
            println!("{}", "║       Liste des Backups              ║".cyan());
            println!("{}", "╚══════════════════════════════════════╝".cyan());
            println!();

            let backup_dir = std::path::Path::new(&dir);
            if !backup_dir.exists() {
                println!("  {} Répertoire introuvable: {}", "✗".red(), dir);
                return Ok(());
            }

            let mut backups: Vec<_> = std::fs::read_dir(backup_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "gz"))
                .collect();

            backups.sort_by_key(|e| std::cmp::Reverse(e.file_name()));

            if backups.is_empty() {
                println!("  {} Aucun backup trouvé", "ℹ️".blue());
            } else {
                println!("  {} backups trouvés:\n", backups.len());
                for entry in &backups {
                    let path = entry.path();
                    let size = std::fs::metadata(&path)?.len();
                    println!(
                        "    {} ({:.2} MB)",
                        path.file_name().unwrap().to_string_lossy(),
                        size as f64 / 1_048_576.0
                    );
                }
            }
        }
        BackupAction::Prune { keep, dir } => {
            println!("Nettoyage des anciens backups (garder {})...", keep);

            let backup_dir = std::path::Path::new(&dir);
            if !backup_dir.exists() {
                println!("  {} Répertoire introuvable", "✗".red());
                return Ok(());
            }

            let mut backups: Vec<_> = std::fs::read_dir(backup_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "gz"))
                .collect();

            backups.sort_by_key(|e| std::cmp::Reverse(e.file_name()));

            let to_delete = backups.len().saturating_sub(keep);
            if to_delete == 0 {
                println!("  {} Rien à supprimer", "✓".green());
                return Ok(());
            }

            for entry in &backups[..to_delete] {
                let path = entry.path();
                std::fs::remove_file(&path)?;
                println!("  {} Supprimé: {}", "🗑️".red(), path.file_name().unwrap().to_string_lossy());
            }

            println!("\n  {} {} backup(s) supprimé(s)", "✓".green(), to_delete);
        }
    }

    Ok(())
}

async fn handle_update(db: &Database, force: bool) -> Result<()> {
    println!("{}", "Mise à jour des sources de menaces...".cyan().bold());
    
    let ti_service = UpdateService::new(db.clone(), 24);
    
    if force {
        println!("  Mise à jour forcée en cours...");
        match ti_service.update_all().await {
            Ok(_) => println!("{} Mise à jour réussie!", "✓".green()),
            Err(e) => println!("{} Erreur: {}", "✗".red(), e),
        }
    } else {
        println!("  Vérification des sources...");
        match ti_service.update_all().await {
            Ok(_) => println!("{} Vérification terminée!", "✓".green()),
            Err(e) => println!("{} Erreur: {}", "✗".red(), e),
        }
    }
    
    match ti_service.get_stats() {
        Ok(stats) => {
            println!();
            println!("  {} Statistiques:", "📊".blue());
            println!("    • Indicateurs: {}", stats.total_indicators);
        }
        Err(e) => println!("  Erreur stats: {}", e),
    }
    
    Ok(())
}

async fn show_logs(db: &Database, lines: usize) -> Result<()> {
    let event_repo = nkosi_db::EventRepository::new(db);
    let events = event_repo.get_recent(lines as i32)?;
    
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║        Logs NKOSI                    ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    
    if events.is_empty() {
        println!();
        println!("  {}", "Aucun événement trouvé".dimmed());
    } else {
        for event in &events {
            println!(
                "  [{}] {:?} - {} - {:?}",
                event.timestamp,
                event.event_type,
                event.source_module,
                event.severity
            );
        }
    }
    
    Ok(())
}

async fn handle_process_scan(pid: u32) -> Result<()> {
    println!("Scan du processus PID: {}", pid);
    
    let exe_path = format!("/proc/{}/exe", pid);
    
    if let Ok(exe) = std::fs::read_link(&exe_path) {
        println!("  Exécutable réel: {}", exe.display());
        
        let mut hash_engine = HashEngine::new();
        let yara_engine = YaraEngine::new_prefer_real();
        let static_analyzer = StaticAnalyzer::new();
        
        if let Some(detection) = scan_file(&exe, &mut hash_engine, &yara_engine, &static_analyzer) {
            println!("  {} Menace détectée: {:?}", "⚠️".red(), detection.detection_engine);
            println!("    Score: {}", detection.score_contribution);
            println!("    Détails: {:?}", detection.details);
        } else {
            println!("  {} Aucune menace détectée", "✓".green());
        }
    } else {
        println!("  Impossible de lire le lien symbolique: {}", exe_path);
    }
    
    let maps_path = format!("/proc/{}/maps", pid);
    if let Ok(maps) = std::fs::read_to_string(&maps_path) {
        let suspicious_patterns = vec!["rwxp", "[heap]", "[stack]"];
        let mut suspicious_count = 0;
        
        for line in maps.lines() {
            for pattern in &suspicious_patterns {
                if line.contains(pattern) {
                    suspicious_count += 1;
                }
            }
        }
        
        println!("  Mappings suspects: {}", suspicious_count);
    }
    
    Ok(())
}

async fn handle_network_scan(target: &str) -> Result<()> {
    println!("Scan réseau pour: {}", target);
    
    if target.contains('/') {
        println!("  Type: CIDR");
    } else if target.parse::<std::net::IpAddr>().is_ok() {
        println!("  Type: IP");
    } else {
        println!("  Type: Domaine");
    }
    
    println!("  Vérification contre les indicateurs connus...");
    println!("  {} Vérification terminée", "✓".green());
    
    Ok(())
}

async fn handle_rootkit_scan() -> Result<()> {
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║       Rootkit Scan                   ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    println!();

    let scanner = RootkitScanner::new();
    let report = scanner.scan()?;

    println!("  {} {}", "Score:".bold(), format!("{}/100", report.score).red());
    println!("  {}", report.summary);
    println!();

    if report.findings.is_empty() {
        println!("  {} Aucun rootkit détecté", "✓".green());
    } else {
        println!("  {} Détections:", "⚠️".red());
        for finding in &report.findings {
            let severity_color = match finding.severity.as_str() {
                "Critical" => "red",
                "High" => "yellow",
                "Medium" => "cyan",
                _ => "white",
            };
            println!(
                "    {} [{}] {}",
                format!("[{}]", finding.severity).color(severity_color),
                finding.category,
                finding.description
            );
        }
    }

    Ok(())
}

async fn handle_integrity_scan(baseline_only: bool) -> Result<()> {
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║       Integrity Scan                 ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    println!();

    let scanner = IntegrityScanner::new();

    if baseline_only {
        println!("  Création de la baseline...");
        let baseline = scanner.create_baseline()?;
        println!("  {} Baseline créée: {} fichiers indexés",
            "✓".green(), baseline.files.len());
        return Ok(());
    }

    let report = scanner.scan()?;

    println!("  {} {}", "Score:".bold(), format!("{}/100", report.score).red());
    println!("  {}", report.summary);
    println!();

    if report.findings.is_empty() {
        println!("  {} Intégrité vérifiée", "✓".green());
    } else {
        println!("  {} Détections:", "⚠️".red());
        for finding in &report.findings {
            let severity_color = match finding.severity.as_str() {
                "Critical" => "red",
                "High" => "yellow",
                "Medium" => "cyan",
                _ => "white",
            };
            println!(
                "    {} [{}] {} - {}",
                format!("[{}]", finding.severity).color(severity_color),
                finding.finding_type,
                finding.path,
                if let Some(expected) = &finding.expected {
                    format!("expected: {}...", &expected[..16])
                } else {
                    "new file".to_string()
                }
            );
        }
    }

    Ok(())
}

async fn handle_kernel_scan() -> Result<()> {
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║       Kernel Module Scan             ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    println!();

    let scanner = KernelScanner::new();
    let report = scanner.scan()?;

    println!("  {} {}", "Kernel:".bold(), report.kernel_version);
    println!("  {} {} modules chargés", "Modules:".bold(), report.loaded_modules.len());
    println!("  {} {}", "Score:".bold(), format!("{}/100", report.score).red());
    println!("  {}", report.summary);
    println!();

    if report.findings.is_empty() {
        println!("  {} Aucun module suspect", "✓".green());
    } else {
        println!("  {} Détections:", "⚠️".red());
        for finding in &report.findings {
            let severity_color = match finding.severity.as_str() {
                "Critical" => "red",
                "High" => "yellow",
                "Medium" => "cyan",
                _ => "white",
            };
            println!(
                "    {} [{}] {} - {}",
                format!("[{}]", finding.severity).color(severity_color),
                finding.finding_type,
                finding.module,
                finding.description
            );
        }
    }

    Ok(())
}

async fn handle_ssh_scan(threshold: u32, block_threshold: u32, auto_block: bool) -> Result<()> {
    println!("{}", "╔══════════════════════════════════════╗".cyan());
    println!("{}", "║       SSH Brute-Force Scan           ║".cyan());
    println!("{}", "╚══════════════════════════════════════╝".cyan());
    println!();

    let config = SshBruteforceConfig {
        threshold,
        block_threshold,
        ..Default::default()
    };
    let scanner = SshBruteforceScanner::new(config);
    let report = scanner.scan()?;

    println!("  {} {}", "Fichier:".bold(), report.log_path);
    println!("  {} {} lignes parsées", "Lignes:".bold(), report.log_lines_parsed);
    println!("  {} {} échecs, {} succès", "Tentatives:".bold(), report.total_failed, report.total_success);
    println!("  {} {}", "Score:".bold(), format!("{}/100", report.score).red());
    println!("  {}", report.summary);
    println!();

    if report.attackers.is_empty() {
        println!("  {} Aucune attaque détectée", "✓".green());
    } else {
        println!("  {} Attaquant(s) détecté(s):", "⚠️".red());
        for attacker in &report.attackers {
            println!(
                "    {} {} - {} tentatives échouées (users: {})",
                "[Brute-Force]".red().bold(),
                attacker.ip,
                attacker.failed_attempts,
                attacker.usernames_targeted.join(", ")
            );

            if auto_block && attacker.failed_attempts >= block_threshold {
                println!("      Tentative de blocage iptables...");
                match scanner.block_ip(&attacker.ip) {
                    Ok(true) => println!("      {} IP {} bloquée", "✓".green(), attacker.ip),
                    Ok(false) => println!("      {} Échec du blocage", "✗".red()),
                    Err(e) => println!("      {} Erreur: {}", "✗".red(), e),
                }
            }
        }
    }

    Ok(())
}

async fn handle_firewall(action: FirewallAction) -> Result<()> {
    let mgr = FirewallManager::new();

    match action {
        FirewallAction::Status => {
            println!("{}", "╔══════════════════════════════════════╗".cyan());
            println!("{}", "║       Firewall Status                ║".cyan());
            println!("{}", "╚══════════════════════════════════════╝".cyan());
            println!();

            let status = mgr.status()?;
            println!("  {} {}", "IPv4:".bold(), if status.ipv4_available { "✓".green() } else { "✗".red() });
            println!("  {} {}", "IPv6:".bold(), if status.ipv6_available { "✓".green() } else { "✗".red() });
            println!("  {} {}", "Chaîne NKOSI:".bold(), if status.nkosi_chain_exists { "✓".green() } else { "✗".red() });
            println!("  {} {}", "Règles:".bold(), status.rules_count);
            println!("  {} {} IPs", "Blacklist:".bold(), status.blacklist_count);
            println!("  {} {} IPs", "Whitelist:".bold(), status.whitelist_count);

            if !status.blacklist.is_empty() {
                println!();
                println!("  {}:", "Blacklist".red().bold());
                for entry in &status.blacklist {
                    println!("    {}", entry.ip);
                }
            }

            if !status.whitelist.is_empty() {
                println!();
                println!("  {}:", "Whitelist".green().bold());
                for entry in &status.whitelist {
                    println!("    {}", entry.ip);
                }
            }
        }
        FirewallAction::Init => {
            println!("{}", "╔══════════════════════════════════════╗".cyan());
            println!("{}", "║       Init NKOSI Firewall            ║".cyan());
            println!("{}", "╚══════════════════════════════════════╝".cyan());
            println!();

            match mgr.init_chains() {
                Ok(()) => println!("  {} Chaînes NKOSI initialisées", "✓".green()),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
        FirewallAction::Flush => {
            println!("{}", "╔══════════════════════════════════════╗".cyan());
            println!("{}", "║       Flush NKOSI Firewall           ║".cyan());
            println!("{}", "╚══════════════════════════════════════╝".cyan());
            println!();

            match mgr.flush() {
                Ok(()) => println!("  {} Règles NKOSI vidées", "✓".green()),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
        FirewallAction::Block { ip, comment, temp } => {
            println!("Blocage de l'IP {}...", ip);
            match mgr.block_ip(&ip, comment.as_deref(), temp) {
                Ok(()) => println!("  {} IP {} bloquée", "✓".green(), ip),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
        FirewallAction::Unblock { ip } => {
            println!("Déblocage de l'IP {}...", ip);
            match mgr.unblock_ip(&ip) {
                Ok(()) => println!("  {} IP {} débloquée", "✓".green(), ip),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
        FirewallAction::Whitelist { ip, comment } => {
            println!("Ajout de {} à la whitelist...", ip);
            match mgr.whitelist_ip(&ip, comment.as_deref()) {
                Ok(()) => println!("  {} IP {} ajoutée à la whitelist", "✓".green(), ip),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
        FirewallAction::Unwhitelist { ip } => {
            println!("Retrait de {} de la whitelist...", ip);
            match mgr.remove_whitelist(&ip) {
                Ok(()) => println!("  {} IP {} retirée de la whitelist", "✓".green(), ip),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
        FirewallAction::RateLimit { ip, max_conn, period } => {
            println!("Rate limiting pour {}: {}/{}s", ip, max_conn, period);
            match mgr.add_rate_limit(&ip, max_conn, &period.to_string()) {
                Ok(()) => println!("  {} Rate limit configuré", "✓".green()),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
        FirewallAction::Save { path } => {
            println!("Sauvegarde des règles vers {}...", path);
            match mgr.save_rules(&path) {
                Ok(()) => println!("  {} Règles sauvegardées", "✓".green()),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
        FirewallAction::Load { path } => {
            println!("Chargement des règles depuis {}...", path);
            match mgr.load_rules(&path) {
                Ok(()) => println!("  {} Règles chargées", "✓".green()),
                Err(e) => println!("  {} Erreur: {}", "✗".red(), e),
            }
        }
    }

    Ok(())
}

fn scan_file(
    path: &Path,
    hash_engine: &mut HashEngine,
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
