use anyhow::Result;
use nkosi_common::config::NkosiConfig;
use nkosi_common::types::*;
use nkosi_db::Database;
use nkosi_engines::{HashEngine, StaticAnalyzer, YaraEngine};
use nkosi_risk::{RiskConfig, RiskEngine};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};

const SCAN_DONE: &str = "\0scan_done\0";

pub struct App {
    pub should_quit: bool,
    pub current_tab: usize,
    pub tabs: Vec<String>,
    pub stats: Stats,
    pub events: Vec<Event>,
    pub scan_results: Vec<String>,
    pub scan_path: String,
    pub watched_paths: Vec<String>,
    pub scan_running: bool,
    scan_rx: Option<Receiver<String>>,
    pub quarantine_items: Vec<QuarantineItem>,
    pub logs: Vec<Event>,
    pub config: NkosiConfig,
    db: Database,
}

#[derive(Default)]
pub struct Stats {
    pub total_events: usize,
    pub total_threats: usize,
    pub quarantine_items: usize,
}

impl App {
    pub fn new() -> Result<Self> {
        let config = load_config()?;
        let db = init_database(&config)?;

        let watched_paths: Vec<String> = config
            .monitors
            .watched_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();

        let mut app = Self {
            should_quit: false,
            current_tab: 0,
            tabs: vec![
                "Tableau de bord".to_string(),
                "Scan".to_string(),
                "Quarantine".to_string(),
                "Logs".to_string(),
                "Paramètres".to_string(),
            ],
            stats: Stats::default(),
            events: Vec::new(),
            scan_results: Vec::new(),
            scan_path: watched_paths.first().cloned().unwrap_or_else(|| "/tmp".to_string()),
            watched_paths,
            scan_running: false,
            scan_rx: None,
            quarantine_items: Vec::new(),
            logs: Vec::new(),
            config: config.clone(),
            db,
        };

        app.refresh()?;
        Ok(app)
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn next_tab(&mut self) {
        self.current_tab = (self.current_tab + 1) % self.tabs.len();
    }

    pub fn previous_tab(&mut self) {
        if self.current_tab > 0 {
            self.current_tab -= 1;
        } else {
            self.current_tab = self.tabs.len() - 1;
        }
    }

    pub fn next_item(&mut self) {
        // Placeholder for list navigation
    }

    pub fn previous_item(&mut self) {
        // Placeholder for list navigation
    }

    pub fn select_item(&mut self) {
        // Placeholder for item selection
    }

    pub fn refresh(&mut self) -> Result<()> {
        self.update_stats()?;
        self.update_events()?;
        self.update_quarantine()?;
        self.update_logs()?;
        Ok(())
    }

    pub fn next_scan_path(&mut self) {
        if self.watched_paths.is_empty() || self.scan_running {
            return;
        }
        if let Some(pos) = self.watched_paths.iter().position(|p| *p == self.scan_path) {
            self.scan_path = self.watched_paths[(pos + 1) % self.watched_paths.len()].clone();
        } else if let Some(first) = self.watched_paths.first() {
            self.scan_path = first.clone();
        }
    }

    pub fn previous_scan_path(&mut self) {
        if self.watched_paths.is_empty() || self.scan_running {
            return;
        }
        if let Some(pos) = self.watched_paths.iter().position(|p| *p == self.scan_path) {
            let len = self.watched_paths.len();
            self.scan_path = self.watched_paths[(pos + len - 1) % len].clone();
        } else if let Some(first) = self.watched_paths.first() {
            self.scan_path = first.clone();
        }
    }

    pub fn start_scan(&mut self) {
        if self.scan_running {
            return;
        }

        let path = self.scan_path.clone();
        if !Path::new(&path).exists() {
            self.scan_results = vec![format!("Chemin non trouvé: {}", path)];
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.scan_rx = Some(rx);
        self.scan_results.clear();
        self.scan_results.push(format!("Scan de {} en cours...", path));
        self.scan_running = true;

        std::thread::spawn(move || run_scan(path, tx));
    }

    pub fn poll_scan(&mut self) {
        if let Some(rx) = &self.scan_rx {
            while let Ok(line) = rx.try_recv() {
                if line == SCAN_DONE {
                    self.scan_running = false;
                    self.scan_rx = None;
                    return;
                }
                self.scan_results.push(line);
            }
        }
    }

    pub fn show_logs(&mut self) {
        self.current_tab = 3;
    }

    fn update_stats(&mut self) -> Result<()> {
        let event_repo = nkosi_db::EventRepository::new(&self.db);
        let events = event_repo.get_recent(100)?;
        self.stats.total_events = events.len();

        let quarantine_repo = nkosi_db::QuarantineRepository::new(&self.db);
        let quarantine_items = quarantine_repo.get_active()?;
        self.stats.quarantine_items = quarantine_items.len();

        self.stats.total_threats = events.iter()
            .filter(|e| matches!(e.event_type, EventType::Detection))
            .count();

        Ok(())
    }

    fn update_events(&mut self) -> Result<()> {
        let event_repo = nkosi_db::EventRepository::new(&self.db);
        self.events = event_repo.get_recent(20)?;
        Ok(())
    }

    fn update_quarantine(&mut self) -> Result<()> {
        let quarantine_repo = nkosi_db::QuarantineRepository::new(&self.db);
        self.quarantine_items = quarantine_repo.get_active()?;
        Ok(())
    }

    fn update_logs(&mut self) -> Result<()> {
        let event_repo = nkosi_db::EventRepository::new(&self.db);
        self.logs = event_repo.get_recent(100)?;
        Ok(())
    }
}

fn run_scan(path: String, tx: Sender<String>) {
    let hash_engine = HashEngine::new();
    let yara_engine = YaraEngine::new();
    let static_analyzer = StaticAnalyzer::new();
    let risk_engine = RiskEngine::new(RiskConfig::default());

    let mut scanned_files = 0u32;
    let mut detected_threats = 0u32;

    for entry in walkdir::WalkDir::new(&path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        scanned_files += 1;

        if let Some(detection) = scan_file(entry.path(), &hash_engine, &yara_engine, &static_analyzer) {
            detected_threats += 1;
            let assessment = risk_engine.evaluate(vec![detection]);
            let _ = tx.send(format!(
                "⚠ {} — Score: {}/100 ({:?})",
                entry.path().display(),
                assessment.score,
                assessment.level
            ));
        }
    }

    let _ = tx.send(String::new());
    let _ = tx.send(format!("Scan terminé:"));
    let _ = tx.send(format!("  • Fichiers scannés: {}", scanned_files));
    let _ = tx.send(format!("  • Menaces détectées: {}", detected_threats));
    let _ = tx.send(SCAN_DONE.to_string());
}

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

    static_analyzer.analyze_file(path)
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

    if let Some(parent) = db_path.parent() {
        if parent.exists() {
            if std::fs::create_dir_all(parent).is_ok() {
                if let Ok(db) = Database::new(db_path) {
                    return Ok(db);
                }
            }
        }
    }

    let local_path = std::env::current_dir()?.join("data").join("nkosi.db");
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(Database::new(&local_path)?)
}
