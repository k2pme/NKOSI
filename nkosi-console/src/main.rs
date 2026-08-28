mod central;
mod handlers;

use actix_cors::Cors;
use actix_files::Files;
use actix_web::{App, HttpServer, middleware, web};
use clap::Parser;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::central::{CentralClient, CentralSnapshot};

#[derive(Parser)]
#[command(
    name = "nkosi-console",
    about = "NKOSI centralized multi-server console"
)]
struct Args {
    /// Central gRPC server address (host:port).
    #[arg(long, env = "NKOSI_CENTRAL_ADDR", default_value = "127.0.0.1:50051")]
    central_addr: String,

    /// HTTP bind address for the console API + dashboard.
    #[arg(long, env = "NKOSI_CONSOLE_BIND", default_value = "0.0.0.0:9090")]
    bind: String,

    /// Poll interval (seconds) used to refresh the aggregated snapshot.
    #[arg(long, env = "NKOSI_CONSOLE_POLL_SECS", default_value = "5")]
    poll_secs: u64,

    /// Path to the dashboard static directory.
    #[arg(long, default_value = "./nkosi-console/dashboard")]
    dashboard_dir: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();

    let client = CentralClient::new(args.central_addr.clone());
    let snapshot_state: handlers::SnapshotState = Arc::new(RwLock::new(CentralSnapshot::default()));

    // Warm the snapshot once before serving so the dashboard isn't empty.
    {
        let initial = client.fetch().await;
        let mut guard = snapshot_state.write().await;
        *guard = initial;
    }

    // Spawn the periodic poller sharing the same state.
    {
        let client_for_poll = CentralClient::new(args.central_addr.clone());
        let state_snapshot = snapshot_state.clone();
        let poll_secs = args.poll_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_secs));
            loop {
                interval.tick().await;
                let snap = client_for_poll.fetch().await;
                {
                    let mut guard = state_snapshot.write().await;
                    *guard = snap;
                }
            }
        });
    }

    info!(
        "NKOSI console for central {} on {} (dashboard: {})",
        args.central_addr, args.bind, args.dashboard_dir
    );

    let dashboard_dir = args.dashboard_dir.clone();

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
        App::new()
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(snapshot_state.clone()))
            .route("/console/agents", web::get().to(handlers::get_agents))
            .route("/console/events", web::get().to(handlers::get_events))
            .route("/console/alerts", web::get().to(handlers::get_alerts))
            .route("/console/stats", web::get().to(handlers::get_stats))
            .route("/console/report", web::get().to(handlers::get_report))
            .route(
                "/console/connectivity",
                web::get().to(handlers::get_connectivity),
            )
            .service(Files::new("/", &dashboard_dir).index_file("index.html"))
    })
    .bind(args.bind)?
    .run()
    .await
}
