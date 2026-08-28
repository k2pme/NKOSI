use anyhow::Result;
use nkosi_common::config::NkosiConfig;
use nkosi_common::types::*;
use nkosi_core::{init_database, load_config};
use nkosi_db::Database;
use nkosi_engines::{BehaviorEngine, HashEngine, StaticAnalyzer, YaraEngine};
use nkosi_monitors::{EventBus, FilesystemMonitor, MonitorEvent, NetworkMonitor, ProcessMonitor};
use nkosi_notify::{Alert, AlertDetails, AlertLevel, NotifyConfig, NotifyManager};
use nkosi_response::ResponseEngine;
use nkosi_risk::{RiskConfig, RiskEngine};
use nkosi_ti::UpdateService;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::Request;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

pub mod central {
    tonic::include_proto!("nkosi.central");
}
use central::nkosi_central_client::NkosiCentralClient;
use central::*;

fn central_request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    if let Ok(token) = std::env::var("NKOSI_CENTRAL_TOKEN")
        && !token.is_empty()
        && let Ok(value) = token.parse()
    {
        request.metadata_mut().insert("x-nkosi-token", value);
    }
    request
}

mod incidents;
mod updater;
use incidents::IncidentManager;

// ── AC-15: Health tracker ──

struct HealthTracker {
    modules: HashMap<String, ModuleHealth>,
    _was_degraded: bool,
}

impl HealthTracker {
    fn new() -> Self {
        Self {
            modules: HashMap::new(),
            _was_degraded: false,
        }
    }

    fn record_ok(&mut self, name: &str) {
        self.modules.insert(
            name.to_string(),
            ModuleHealth {
                name: name.to_string(),
                status: ModuleStatus::Ok,
                message: None,
                since: chrono::Utc::now(),
            },
        );
    }

    fn record_failed(&mut self, name: &str, reason: &str) {
        warn!("Module '{}' failed: {}", name, reason);
        self.modules.insert(
            name.to_string(),
            ModuleHealth {
                name: name.to_string(),
                status: ModuleStatus::Failed,
                message: Some(reason.to_string()),
                since: chrono::Utc::now(),
            },
        );
    }

    fn record_disabled(&mut self, name: &str) {
        self.modules.insert(
            name.to_string(),
            ModuleHealth {
                name: name.to_string(),
                status: ModuleStatus::Disabled,
                message: None,
                since: chrono::Utc::now(),
            },
        );
    }

    fn agent_status(&self) -> AgentHealthStatus {
        if self
            .modules
            .values()
            .any(|m| m.status == ModuleStatus::Failed)
        {
            AgentHealthStatus::Degraded
        } else {
            AgentHealthStatus::Running
        }
    }

    fn snapshot(&self) -> Vec<ModuleHealth> {
        self.modules.values().cloned().collect()
    }
}

// ── Central (gRPC) client ──

struct CentralClient {
    client: Option<NkosiCentralClient<tonic::transport::Channel>>,
    agent_id: String,
}

impl CentralClient {
    async fn connect(addr: &str, agent_id: &str) -> Self {
        match NkosiCentralClient::connect(format!("http://{}", addr)).await {
            Ok(client) => {
                info!("Connected to central at {}", addr);
                Self {
                    client: Some(client),
                    agent_id: agent_id.to_string(),
                }
            }
            Err(e) => {
                warn!("Failed to connect to central at {}: {}", addr, e);
                Self {
                    client: None,
                    agent_id: agent_id.to_string(),
                }
            }
        }
    }

    async fn register(&mut self, hostname: &str, ip: &str, version: &str) {
        if let Some(ref mut client) = self.client {
            let req = AgentInfo {
                agent_id: self.agent_id.clone(),
                hostname: hostname.to_string(),
                ip_address: ip.to_string(),
                os_version: std::env::var("OS").unwrap_or_else(|_| "Linux".to_string()),
                nkosi_version: version.to_string(),
                agent_name: format!("agent-{}", hostname),
            };
            match client.register_agent(central_request(req)).await {
                Ok(resp) => info!("Registered with central: {}", resp.into_inner().message),
                Err(e) => warn!("Failed to register with central: {}", e),
            }
        }
    }

    async fn send_heartbeat(&mut self, score: u32, events: u32, threats: u32) {
        if let Some(ref mut client) = self.client {
            let hb = AgentHeartbeat {
                agent_id: self.agent_id.clone(),
                timestamp: chrono::Utc::now().timestamp(),
                events_count: events,
                threats_count: threats,
                score,
            };
            if let Err(e) = client.heartbeat(central_request(hb)).await {
                warn!("Heartbeat failed: {}", e);
            }
        }
    }

    #[allow(dead_code)]
    async fn send_events(&mut self, events: Vec<SecurityEvent>) {
        if let Some(ref mut client) = self.client
            && !events.is_empty()
        {
            let batch = EventBatch {
                agent_id: self.agent_id.clone(),
                events,
            };
            match client.report_events(central_request(batch)).await {
                Ok(resp) => debug!(
                    "Reported {} events to central",
                    resp.into_inner().received_count
                ),
                Err(e) => warn!("Failed to report events to central: {}", e),
            }
        }
    }

    /// Push recent higher-severity events from the local DB to the central
    /// server so the centralized console can aggregate them.
    async fn report_recent_events(&mut self, db: &Database) {
        if self.client.is_none() {
            return;
        }
        let repo = nkosi_db::EventRepository::new(db);
        let Ok(events) = repo.get_recent(200) else {
            return;
        };

        let now = chrono::Utc::now().timestamp();
        let batch: Vec<SecurityEvent> = events
            .iter()
            .filter(|e| {
                // Only forward events worth correlating (medium+) to avoid noise.
                matches!(
                    e.severity,
                    Severity::Medium | Severity::High | Severity::Critical
                )
            })
            .map(|e| SecurityEvent {
                id: e.id.to_string(),
                timestamp: now,
                event_type: serde_json::to_string(&e.event_type)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
                source_module: e.source_module.clone(),
                severity: serde_json::to_string(&e.severity)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
                score: e.score.unwrap_or(0),
                file_path: e.file_path.clone().unwrap_or_default(),
                file_hash: e.file_hash.clone().unwrap_or_default(),
                remote_ip: e.remote_ip.clone().unwrap_or_default(),
                remote_port: e.remote_port.map(u32::from).unwrap_or(0),
                domain: e.domain.clone().unwrap_or_default(),
                details: e.result.clone().unwrap_or_default(),
                agent_id: self.agent_id.clone(),
            })
            .collect();

        self.send_events(batch).await;
    }
}

fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

fn get_local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Stable identity is required for central-side inventory and event deduplication.
/// It is kept next to the local database, which is already persistent across restarts.
fn get_or_create_agent_id(db_path: &std::path::Path) -> String {
    let id_path = db_path.with_file_name("agent-id");
    if let Ok(id) = std::fs::read_to_string(&id_path) {
        let id = id.trim();
        if uuid::Uuid::parse_str(id).is_ok() {
            return id.to_string();
        }
        warn!(
            "Ignoring invalid persisted agent ID at {}",
            id_path.display()
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = id_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        warn!("Unable to create agent ID directory: {}", e);
        return id;
    }
    if let Err(e) = std::fs::write(&id_path, format!("{}\n", id)) {
        warn!("Unable to persist agent ID: {}", e);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600));
        }
    }
    id
}

fn health_file_path() -> std::path::PathBuf {
    // Prefer systemd runtime directory if available
    if let Ok(runtime_dir) = std::env::var("RUNTIME_DIRECTORY") {
        return std::path::PathBuf::from(runtime_dir).join("health.json");
    }
    // Fallback to /run/nkosi/health.json
    let run_path = std::path::PathBuf::from("/run/nkosi/health.json");
    if run_path.parent().is_some_and(|p| p.exists()) {
        return run_path;
    }
    // Last resort: current directory
    std::path::PathBuf::from("data/health.json")
}

async fn write_health_file(health: &Arc<RwLock<HealthTracker>>) {
    let snapshot = health.read().await.snapshot();
    if let Some(parent) = health_file_path().parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Ok(json) = serde_json::to_string(&snapshot)
        && let Err(e) = std::fs::write(health_file_path(), json)
    {
        warn!("Failed to write health file: {}", e);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    info!("Starting NKOSI Security Agent");

    let config = load_config()?;
    info!("Configuration loaded");

    let health = Arc::new(RwLock::new(HealthTracker::new()));

    // Database — critical but non-fatal
    let db = match init_database(&config) {
        Ok(db) => {
            health.write().await.record_ok("database");
            info!("Database initialized");
            db
        }
        Err(e) => {
            // Fallback: local DB
            let local_path = std::path::PathBuf::from("data/nkosi.db");
            std::fs::create_dir_all("data").ok();
            match Database::new(&local_path) {
                Ok(db) => {
                    health
                        .write()
                        .await
                        .record_failed("database", &format!("{} (fallback to local)", e));
                    db
                }
                Err(e2) => {
                    health
                        .write()
                        .await
                        .record_failed("database", &format!("{} and fallback failed: {}", e, e2));
                    panic!("No database available: {} / {}", e, e2);
                }
            }
        }
    };

    let notify_config = convert_notify_config(&config);
    let notify_manager = Arc::new(NotifyManager::new(notify_config));
    health.write().await.record_ok("notifications");
    info!(
        "Notification manager initialized with {} notifiers",
        notify_manager.notifiers_count()
    );

    notify_manager
        .notify(Alert {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            level: AlertLevel::Info,
            title: "NKOSI Agent Started".to_string(),
            message: "NKOSI Security Agent has started successfully".to_string(),
            source: "agent".to_string(),
            details: None,
        })
        .await;

    // TI service — non-critical
    let ti_service = UpdateService::from_config(db.clone(), &config.threat_intel);
    match ti_service.start().await {
        Ok(()) => {
            health.write().await.record_ok("ti_service");
            info!("Threat Intelligence Update Service started");
        }
        Err(e) => {
            health
                .write()
                .await
                .record_failed("ti_service", &e.to_string());
            warn!("TI service failed to start: {}", e);
        }
    }

    let event_bus = Arc::new(EventBus::new(1000));
    let engines = Arc::new(Engines::new(&config, &db));
    let risk_engine = Arc::new(RiskEngine::new(to_risk_config(&config.risk)));
    let response_engine = Arc::new(ResponseEngine::new(
        config.quarantine.path.clone(),
        Some(db.clone()),
    ));
    let incident_manager = Arc::new(tokio::sync::Mutex::new(IncidentManager::new(db.clone())));

    // TI updates are asynchronous. Refresh the in-memory hash set periodically so
    // a successful feed update becomes an active detection without a restart.
    let hash_engine = engines.hash.clone();
    let db_for_hash_refresh = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let repo = nkosi_db::ThreatIndicatorRepository::new(&db_for_hash_refresh);
            match repo.get_enabled_sha256_values() {
                Ok(hashes) => hash_engine.load_threat_hashes(hashes),
                Err(e) => warn!("Failed to refresh TI hash cache: {}", e),
            }
        }
    });

    health.write().await.record_ok("engines");

    let db_clone = db.clone();
    let engines_clone = engines.clone();
    let risk_clone = risk_engine.clone();
    let response_clone = response_engine.clone();
    let event_bus_clone = event_bus.clone();
    let notify_clone = notify_manager.clone();
    let incident_clone = incident_manager.clone();

    tokio::spawn(async move {
        process_events(
            event_bus_clone,
            engines_clone,
            risk_clone,
            response_clone,
            db_clone,
            notify_clone,
            incident_clone,
        )
        .await;
    });

    // Monitors — each independently degradable
    match start_monitors(&config, event_bus, &health).await {
        Ok(()) => info!("All monitors started"),
        Err(e) => warn!("Some monitors failed: {}", e),
    }

    let agent_status = health.read().await.agent_status();
    info!("NKOSI Agent started — status: {:?}", agent_status);

    // Send notification if agent started in degraded mode
    if agent_status == AgentHealthStatus::Degraded {
        let failed: Vec<String> = health
            .read()
            .await
            .snapshot()
            .iter()
            .filter(|m| m.status == ModuleStatus::Failed)
            .map(|m| format!("{}: {}", m.name, m.message.as_deref().unwrap_or("unknown")))
            .collect();
        notify_manager
            .notify(Alert {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                level: AlertLevel::Warning,
                title: "NKOSI Agent started in DEGRADED mode".to_string(),
                message: format!("Failed modules: {}", failed.join(", ")),
                source: "health_tracker".to_string(),
                details: None,
            })
            .await;
    }

    // Write health status to shared file for API consumption
    write_health_file(&health).await;

    // Central connection (optional, via NKOSI_CENTRAL_ADDR)
    let agent_id = get_or_create_agent_id(&config.agent.db_path);
    let central_addr = std::env::var("NKOSI_CENTRAL_ADDR").unwrap_or_default();
    let hostname = get_hostname();
    let nkosi_version = env!("CARGO_PKG_VERSION");

    let mut central_client = if !central_addr.is_empty() {
        let mut c = CentralClient::connect(&central_addr, &agent_id).await;
        c.register(&hostname, &get_local_ip(), nkosi_version).await;
        Some(c)
    } else {
        info!("NKOSI_CENTRAL_ADDR not set, running in standalone mode");
        None
    };

    if let Some(mut cc) = central_client.take() {
        let db_for_central = db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let recent = nkosi_db::EventRepository::new(&db_for_central)
                    .get_recent(200)
                    .unwrap_or_default();
                let threats = recent
                    .iter()
                    .filter(|event| matches!(event.severity, Severity::High | Severity::Critical))
                    .count() as u32;
                let score = recent
                    .iter()
                    .filter_map(|event| event.score)
                    .max()
                    .unwrap_or(0);
                cc.send_heartbeat(score, recent.len() as u32, threats).await;
                // Forward recent security events so the centralized console can
                // aggregate alerts across all servers.
                cc.report_recent_events(&db_for_central).await;
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("Shutting down NKOSI Agent");

    notify_manager
        .notify(Alert {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            level: AlertLevel::Info,
            title: "NKOSI Agent Stopped".to_string(),
            message: "NKOSI Security Agent is shutting down".to_string(),
            source: "agent".to_string(),
            details: None,
        })
        .await;

    Ok(())
}

struct Engines {
    pub hash: Arc<HashEngine>,
    pub yara: YaraEngine,
    pub static_analyzer: StaticAnalyzer,
    pub behavior: BehaviorEngine,
}

impl Engines {
    fn new(_config: &NkosiConfig, db: &Database) -> Self {
        let hash = HashEngine::new();
        match nkosi_db::ThreatIndicatorRepository::new(db).get_enabled_sha256_values() {
            Ok(hashes) => hash.load_threat_hashes(hashes),
            Err(e) => warn!("Failed to load TI hashes at startup: {}", e),
        }
        Self {
            hash: Arc::new(hash),
            yara: YaraEngine::new_prefer_real(),
            static_analyzer: StaticAnalyzer::new(),
            behavior: BehaviorEngine::new(),
        }
    }
}

fn to_risk_config(config: &nkosi_common::config::RiskConfig) -> RiskConfig {
    RiskConfig {
        low_threshold: config.low_threshold,
        suspicious_threshold: config.suspicious_threshold,
        malicious_threshold: config.malicious_threshold,
        weights: nkosi_risk::RiskWeights {
            hash: config.weights.hash,
            yara: config.weights.yara,
            static_analysis: config.weights.static_analysis,
            behavior: config.weights.behavior,
            network: config.weights.network,
        },
    }
}

fn convert_notify_config(config: &NkosiConfig) -> NotifyConfig {
    let min_level = match config.notifications.min_level.as_str() {
        "info" => AlertLevel::Info,
        "warning" => AlertLevel::Warning,
        "critical" => AlertLevel::Critical,
        "emergency" => AlertLevel::Emergency,
        _ => AlertLevel::Warning,
    };

    NotifyConfig {
        enabled: config.notifications.enabled,
        min_level,
        email: config
            .notifications
            .email
            .as_ref()
            .map(|e| nkosi_notify::EmailConfig {
                smtp_host: e.smtp_host.clone(),
                smtp_port: e.smtp_port,
                username: e.username.clone(),
                password: e.password.clone(),
                from: e.from.clone(),
                to: e.to.clone(),
                use_tls: e.use_tls,
            }),
        webhook: config.notifications.webhook.as_ref().map(|wh| {
            wh.iter()
                .map(|w| nkosi_notify::WebhookConfig {
                    name: w.name.clone(),
                    url: w.url.clone(),
                    headers: w.headers.clone(),
                    format: match w.format.as_str() {
                        "slack" => nkosi_notify::WebhookFormat::Slack,
                        "discord" => nkosi_notify::WebhookFormat::Discord,
                        _ => nkosi_notify::WebhookFormat::Json,
                    },
                })
                .collect()
        }),
        syslog: config
            .notifications
            .syslog
            .as_ref()
            .map(|s| nkosi_notify::SyslogConfig {
                facility: s.facility.clone(),
                severity: s.severity.clone(),
            }),
        console: config
            .notifications
            .console
            .as_ref()
            .map(|c| nkosi_notify::ConsoleConfig { colored: c.colored }),
        telegram: config
            .notifications
            .telegram
            .as_ref()
            .map(|t| nkosi_notify::TelegramConfig {
                bot_token: t.bot_token.clone(),
                chat_id: t.chat_id.clone(),
                parse_mode: t
                    .parse_mode
                    .clone()
                    .unwrap_or_else(|| "Markdown".to_string()),
            }),
        sms: config
            .notifications
            .sms
            .as_ref()
            .map(|s| nkosi_notify::SmsConfig {
                provider: s.provider.clone(),
                account_sid: s.account_sid.clone(),
                auth_token: s.auth_token.clone(),
                from_number: s.from_number.clone(),
                to_numbers: s.to_numbers.clone(),
                signalwire_host: s.signalwire_host.clone(),
            }),
    }
}

async fn start_monitors(
    config: &NkosiConfig,
    event_bus: Arc<EventBus>,
    health: &Arc<RwLock<HealthTracker>>,
) -> Result<()> {
    info!("Starting monitors...");

    // Filesystem monitor — critical
    match FilesystemMonitor::new(
        config.monitors.watched_paths.clone(),
        config.monitors.excluded_paths.clone(),
        event_bus.clone(),
    )
    .start()
    .await
    {
        Ok(()) => health.write().await.record_ok("filesystem_monitor"),
        Err(e) => health
            .write()
            .await
            .record_failed("filesystem_monitor", &e.to_string()),
    }

    // Process monitor
    if config.monitors.process_monitor_enabled {
        match ProcessMonitor::new(event_bus.clone()).start().await {
            Ok(()) => health.write().await.record_ok("process_monitor"),
            Err(e) => health
                .write()
                .await
                .record_failed("process_monitor", &e.to_string()),
        }
    } else {
        health.write().await.record_disabled("process_monitor");
    }

    // Network monitor
    if config.monitors.network_monitor_enabled {
        match NetworkMonitor::new(event_bus.clone()).start().await {
            Ok(()) => health.write().await.record_ok("network_monitor"),
            Err(e) => health
                .write()
                .await
                .record_failed("network_monitor", &e.to_string()),
        }
    } else {
        health.write().await.record_disabled("network_monitor");
    }

    info!("Monitors started (health status updated)");
    Ok(())
}

async fn process_events(
    event_bus: Arc<EventBus>,
    engines: Arc<Engines>,
    risk_engine: Arc<RiskEngine>,
    response_engine: Arc<ResponseEngine>,
    db: Database,
    notify_manager: Arc<NotifyManager>,
    incident_manager: Arc<tokio::sync::Mutex<IncidentManager>>,
) {
    let mut receiver = event_bus.subscribe();

    info!("Event processing started");

    loop {
        let event = match receiver.recv().await {
            Ok(event) => event,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                warn!(
                    "Event processor lagged by {} events; continuing with newest events",
                    count
                );
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        };
        match event {
            MonitorEvent::FileEvent {
                path,
                event_type,
                metadata: _,
            } => {
                debug!("File event: {:?} - {}", event_type, path);

                // Record clean file creations so real-time activity is observable (AC-02)
                if event_type == EventType::FileCreated {
                    let mut created = Event::new(EventType::FileCreated, "filesystem_monitor");
                    created.file_path = Some(path.clone());
                    let repo = nkosi_db::EventRepository::new(&db);
                    if let Err(e) = repo.insert(&created) {
                        warn!("Failed to save file-created event: {}", e);
                    }
                }

                let file_path = Path::new(&path);
                let mut detections = Vec::new();

                if let Some(detection) = engines.hash.analyze_file(file_path) {
                    detections.push(detection);
                }

                let yara_detections = engines.yara.scan_file(file_path);
                detections.extend(yara_detections);

                if let Some(detection) = engines.static_analyzer.analyze_file(file_path) {
                    detections.push(detection);
                }

                if !detections.is_empty() {
                    let assessment = risk_engine.evaluate(detections.clone());

                    info!(
                        "Risk assessment for {}: score={}, level={:?}",
                        path, assessment.score, assessment.level
                    );

                    let alert_level = match assessment.level {
                        RiskLevel::Malicious => AlertLevel::Critical,
                        RiskLevel::Suspicious => AlertLevel::Warning,
                        RiskLevel::Low => AlertLevel::Info,
                        RiskLevel::Clean => AlertLevel::Info,
                    };

                    if assessment.level != RiskLevel::Clean {
                        notify_manager
                            .notify(Alert {
                                id: uuid::Uuid::new_v4().to_string(),
                                timestamp: chrono::Utc::now(),
                                level: alert_level,
                                title: format!("Threat detected: {}", path),
                                message: format!(
                                    "Risk score: {}/100 ({:?})",
                                    assessment.score, assessment.level
                                ),
                                source: "file_monitor".to_string(),
                                details: Some(AlertDetails {
                                    file_path: Some(path.clone()),
                                    process_name: None,
                                    pid: None,
                                    score: Some(assessment.score),
                                    detection_engine: assessment
                                        .detections
                                        .first()
                                        .map(|d| format!("{:?}", d.detection_engine)),
                                    threat_type: None,
                                    action_taken: Some(format!(
                                        "{:?}",
                                        risk_engine.get_recommended_action(&assessment.level)
                                    )),
                                }),
                            })
                            .await;
                    }

                    let action = risk_engine.get_recommended_action(&assessment.level);

                    if let Err(e) = response_engine
                        .execute_action(
                            &action,
                            Some(&path),
                            None,
                            None,
                            assessment.score,
                            &assessment.details,
                        )
                        .await
                    {
                        warn!("Response action failed: {}", e);
                    }

                    let mut event = Event::new(EventType::Detection, "risk_engine");
                    event.file_path = Some(path);
                    event.score = Some(assessment.score);
                    event.severity = match assessment.level {
                        RiskLevel::Malicious => Severity::Critical,
                        RiskLevel::Suspicious => Severity::High,
                        RiskLevel::Low => Severity::Medium,
                        RiskLevel::Clean => Severity::Info,
                    };
                    event.action = Some(action);
                    event.result = Some(assessment.details);

                    let repo = nkosi_db::EventRepository::new(&db);
                    if let Err(e) = repo.insert(&event) {
                        warn!("Failed to save event to database: {}", e);
                    }

                    let det_repo = nkosi_db::DetectionRepository::new(&db);
                    for detection in &assessment.detections {
                        let mut det = detection.clone();
                        det.event_id = event.id;
                        if let Err(e) = det_repo.insert(&det) {
                            warn!("Failed to save detection: {}", e);
                        }
                    }

                    let mut im = incident_manager.lock().await;
                    im.process_detections(assessment.detections, &event).await;
                }
            }
            MonitorEvent::ProcessEvent {
                pid,
                ppid,
                executable,
                args,
                event_type,
            } => {
                debug!(
                    "Process event: {:?} - PID {} - {}",
                    event_type, pid, executable
                );

                engines
                    .behavior
                    .record_event(
                        pid,
                        ppid,
                        &executable,
                        "process_start",
                        &args.join(" "),
                        Severity::Info,
                    )
                    .await;

                let score = engines.behavior.get_process_risk_score(pid).await;
                if score >= 30 {
                    let alert_level = if score >= 70 {
                        AlertLevel::Critical
                    } else {
                        AlertLevel::Warning
                    };

                    notify_manager
                        .notify(Alert {
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Utc::now(),
                            level: alert_level,
                            title: format!("Suspicious process: {}", executable),
                            message: format!("Process risk score: {}", score),
                            source: "process_monitor".to_string(),
                            details: Some(AlertDetails {
                                file_path: Some(executable.clone()),
                                process_name: Some(executable.clone()),
                                pid: Some(pid),
                                score: Some(score),
                                detection_engine: Some("Behavior".to_string()),
                                threat_type: None,
                                action_taken: None,
                            }),
                        })
                        .await;

                    let action = if score >= 70 {
                        ResponseAction::Kill
                    } else {
                        ResponseAction::Alert
                    };

                    if let Err(e) = response_engine
                        .execute_action(
                            &action,
                            None,
                            Some(pid),
                            None,
                            score,
                            &format!("Suspicious process behavior (score: {})", score),
                        )
                        .await
                    {
                        warn!("Response action failed: {}", e);
                    }
                }
            }
            MonitorEvent::NetworkEvent {
                pid,
                local_addr: _,
                remote_addr,
                remote_port,
                protocol,
                event_type,
            } => {
                debug!(
                    "Network event: {:?} - PID {} - {}:{} ({})",
                    event_type, pid, remote_addr, remote_port, protocol
                );

                let remote = format!("{}:{}", remote_addr, remote_port);
                engines
                    .behavior
                    .record_event(
                        pid,
                        None,
                        "network",
                        "network_connection",
                        &remote,
                        Severity::Info,
                    )
                    .await;

                if let Some(detection) = engines.behavior.check_network_activity(pid, &remote).await
                {
                    let risk_score = detection.score_contribution;

                    if risk_score >= 50 {
                        notify_manager
                            .notify(Alert {
                                id: uuid::Uuid::new_v4().to_string(),
                                timestamp: chrono::Utc::now(),
                                level: AlertLevel::Warning,
                                title: format!(
                                    "Suspicious network: {}:{} via PID {}",
                                    remote_addr, remote_port, pid
                                ),
                                message: detection.details.unwrap_or_default(),
                                source: "network_monitor".to_string(),
                                details: Some(AlertDetails {
                                    file_path: None,
                                    process_name: None,
                                    pid: Some(pid),
                                    score: Some(risk_score),
                                    detection_engine: Some("Behavior".to_string()),
                                    threat_type: None,
                                    action_taken: Some("Block".to_string()),
                                }),
                            })
                            .await;

                        let action = ResponseAction::Block;
                        if let Err(e) = response_engine
                            .execute_action(
                                &action,
                                None,
                                Some(pid),
                                Some(remote_addr.as_str()),
                                risk_score,
                                &format!("Suspicious network connection to {}", remote),
                            )
                            .await
                        {
                            warn!("Response action failed: {}", e);
                        }
                    }
                }
            }
        }
    }
}
