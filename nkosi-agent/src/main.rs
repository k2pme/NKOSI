use anyhow::Result;
use nkosi_common::config::NkosiConfig;
use nkosi_common::types::*;
use nkosi_db::Database;
use nkosi_engines::{HashEngine, YaraEngine, StaticAnalyzer, BehaviorEngine};
use nkosi_monitors::{EventBus, FilesystemMonitor, ProcessMonitor, NetworkMonitor, MonitorEvent};
use nkosi_notify::{NotifyManager, Alert, AlertLevel, AlertDetails, NotifyConfig};
use nkosi_risk::{RiskEngine, RiskConfig};
use nkosi_response::ResponseEngine;
use nkosi_ti::UpdateService;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, debug, warn};
use tracing_subscriber::EnvFilter;

mod updater;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    info!("Starting NKOSI Security Agent");

    let config = load_config().await?;
    info!("Configuration loaded");

    let db = init_database(&config).await?;
    info!("Database initialized");

    let notify_config = convert_notify_config(&config);
    let notify_manager = Arc::new(NotifyManager::new(notify_config));
    info!("Notification manager initialized with {} notifiers", notify_manager.notifiers_count());

    notify_manager.notify(Alert {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        level: AlertLevel::Info,
        title: "NKOSI Agent Started".to_string(),
        message: "NKOSI Security Agent has started successfully".to_string(),
        source: "agent".to_string(),
        details: None,
    }).await;

    let ti_service = UpdateService::new(db.clone(), config.threat_intel.update_interval_hours);
    ti_service.start().await?;
    info!("Threat Intelligence Update Service started");

    let event_bus = Arc::new(EventBus::new(1000));
    let engines = Arc::new(Engines::new(&config));
    let risk_engine = Arc::new(RiskEngine::new(RiskConfig::default()));
    let response_engine = Arc::new(ResponseEngine::new(
        config.quarantine.path.clone(),
        Some(db.clone()),
    ));

    let db_clone = db.clone();
    let engines_clone = engines.clone();
    let risk_clone = risk_engine.clone();
    let response_clone = response_engine.clone();
    let event_bus_clone = event_bus.clone();
    let notify_clone = notify_manager.clone();
    
    tokio::spawn(async move {
        process_events(event_bus_clone, engines_clone, risk_clone, response_clone, db_clone, notify_clone).await;
    });

    start_monitors(&config, event_bus).await?;
    
    info!("NKOSI Agent started successfully");
    info!("Protection active - monitoring system");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down NKOSI Agent");

    notify_manager.notify(Alert {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        level: AlertLevel::Info,
        title: "NKOSI Agent Stopped".to_string(),
        message: "NKOSI Security Agent is shutting down".to_string(),
        source: "agent".to_string(),
        details: None,
    }).await;

    Ok(())
}

struct Engines {
    pub hash: HashEngine,
    pub yara: YaraEngine,
    pub static_analyzer: StaticAnalyzer,
    pub behavior: BehaviorEngine,
}

impl Engines {
    fn new(_config: &NkosiConfig) -> Self {
        Self {
            hash: HashEngine::new(),
            yara: YaraEngine::new(),
            static_analyzer: StaticAnalyzer::new(),
            behavior: BehaviorEngine::new(),
        }
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
        email: config.notifications.email.as_ref().map(|e| nkosi_notify::EmailConfig {
            smtp_host: e.smtp_host.clone(),
            smtp_port: e.smtp_port,
            username: e.username.clone(),
            password: e.password.clone(),
            from: e.from.clone(),
            to: e.to.clone(),
            use_tls: e.use_tls,
        }),
        webhook: config.notifications.webhook.as_ref().map(|wh| {
            wh.iter().map(|w| nkosi_notify::WebhookConfig {
                name: w.name.clone(),
                url: w.url.clone(),
                headers: w.headers.clone(),
                format: match w.format.as_str() {
                    "slack" => nkosi_notify::WebhookFormat::Slack,
                    "discord" => nkosi_notify::WebhookFormat::Discord,
                    _ => nkosi_notify::WebhookFormat::Json,
                },
            }).collect()
        }),
        syslog: config.notifications.syslog.as_ref().map(|s| nkosi_notify::SyslogConfig {
            facility: s.facility.clone(),
            severity: s.severity.clone(),
        }),
        console: config.notifications.console.as_ref().map(|c| nkosi_notify::ConsoleConfig {
            colored: c.colored,
        }),
        telegram: config.notifications.telegram.as_ref().map(|t| nkosi_notify::TelegramConfig {
            bot_token: t.bot_token.clone(),
            chat_id: t.chat_id.clone(),
            parse_mode: t.parse_mode.clone().unwrap_or_else(|| "Markdown".to_string()),
        }),
        sms: config.notifications.sms.as_ref().map(|s| nkosi_notify::SmsConfig {
            provider: s.provider.clone(),
            account_sid: s.account_sid.clone(),
            auth_token: s.auth_token.clone(),
            from_number: s.from_number.clone(),
            to_numbers: s.to_numbers.clone(),
            signalwire_host: s.signalwire_host.clone(),
        }),
    }
}

async fn load_config() -> Result<NkosiConfig> {
    let config_path = "/etc/nkosi/nkosi.toml";
    if Path::new(config_path).exists() {
        Ok(NkosiConfig::load(config_path)?)
    } else {
        let local_config = "config/nkosi.toml";
        if Path::new(local_config).exists() {
            info!("Using local configuration");
            Ok(NkosiConfig::load(local_config)?)
        } else {
            info!("Using default configuration");
            Ok(NkosiConfig::default())
        }
    }
}

async fn init_database(config: &NkosiConfig) -> Result<Database> {
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
    info!("Using local database: {}", local_path.display());
    Ok(Database::new(&local_path)?)
}

async fn start_monitors(config: &NkosiConfig, event_bus: Arc<EventBus>) -> Result<()> {
    info!("Starting monitors...");
    
    let fs_monitor = FilesystemMonitor::new(
        config.monitors.watched_paths.clone(),
        config.monitors.excluded_paths.clone(),
        event_bus.clone(),
    );
    fs_monitor.start().await?;
    
    if config.monitors.process_monitor_enabled {
        let mut proc_monitor = ProcessMonitor::new(event_bus.clone());
        proc_monitor.start().await?;
    }
    
    if config.monitors.network_monitor_enabled {
        let mut net_monitor = NetworkMonitor::new(event_bus.clone());
        net_monitor.start().await?;
    }
    
    info!("All monitors started");
    Ok(())
}

async fn process_events(
    event_bus: Arc<EventBus>,
    engines: Arc<Engines>,
    risk_engine: Arc<RiskEngine>,
    response_engine: Arc<ResponseEngine>,
    db: Database,
    notify_manager: Arc<NotifyManager>,
) {
    let mut receiver = event_bus.subscribe();
    
    info!("Event processing started");

    while let Ok(event) = receiver.recv().await {
        match event {
            MonitorEvent::FileEvent { path, event_type, metadata: _ } => {
                debug!("File event: {:?} - {}", event_type, path);
                
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
                    let assessment = risk_engine.evaluate(detections);
                    
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
                        notify_manager.notify(Alert {
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
                                detection_engine: assessment.detections.first().map(|d| format!("{:?}", d.detection_engine)),
                                threat_type: None,
                                action_taken: Some(format!("{:?}", risk_engine.get_recommended_action(&assessment.level))),
                            }),
                        }).await;
                    }

                    let action = risk_engine.get_recommended_action(&assessment.level);
                    
                    if let Err(e) = response_engine.execute_action(
                        &action,
                        Some(&path),
                        None,
                        assessment.score,
                        &assessment.details,
                    ).await {
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
                }
            }
            MonitorEvent::ProcessEvent { pid, ppid, executable, args, event_type } => {
                debug!("Process event: {:?} - PID {} - {}", event_type, pid, executable);
                
                engines.behavior.record_event(
                    pid,
                    ppid,
                    &executable,
                    "process_start",
                    &args.join(" "),
                    Severity::Info,
                ).await;

                let score = engines.behavior.get_process_risk_score(pid).await;
                if score >= 30 {
                    let alert_level = if score >= 70 {
                        AlertLevel::Critical
                    } else {
                        AlertLevel::Warning
                    };

                    notify_manager.notify(Alert {
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
                    }).await;

                    let action = if score >= 70 {
                        ResponseAction::Kill
                    } else {
                        ResponseAction::Alert
                    };

                    if let Err(e) = response_engine.execute_action(
                        &action,
                        None,
                        Some(pid),
                        score,
                        &format!("Suspicious process behavior (score: {})", score),
                    ).await {
                        warn!("Response action failed: {}", e);
                    }
                }
            }
            MonitorEvent::NetworkEvent { pid, local_addr: _, remote_addr, remote_port, protocol, event_type } => {
                debug!("Network event: {:?} - PID {} - {}:{} ({})", 
                    event_type, pid, remote_addr, remote_port, protocol);
                
                let remote = format!("{}:{}", remote_addr, remote_port);
                engines.behavior.record_event(
                    pid,
                    None,
                    "network",
                    "network_connection",
                    &remote,
                    Severity::Info,
                ).await;

                if let Some(detection) = engines.behavior.check_network_activity(pid, &remote).await {
                    let risk_score = detection.score_contribution;
                    
                    if risk_score >= 50 {
                        notify_manager.notify(Alert {
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Utc::now(),
                            level: AlertLevel::Warning,
                            title: format!("Suspicious network: {}:{} via PID {}", remote_addr, remote_port, pid),
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
                        }).await;

                        let action = ResponseAction::Block;
                        if let Err(e) = response_engine.execute_action(
                            &action,
                            None,
                            Some(pid),
                            risk_score,
                            &format!("Suspicious network connection to {}", remote),
                        ).await {
                            warn!("Response action failed: {}", e);
                        }
                    }
                }
            }
        }
    }
}
