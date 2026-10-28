//! `rivet-relay` binary entry point.
//!
//! Dispatches between the `init` subcommand (provisioning a fresh deployment)
//! and the `serve` subcommand (the default — actually running the relay).

use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;

use rivetlink_server::cli::{Cli, Command};
use rivetlink_server::config::ServerConfig;
use rivetlink_server::db::{audit, refresh_tokens};
use rivetlink_server::router::create_router;
use rivetlink_server::sessions::manager::SessionManager;
use rivetlink_server::signaling::router::run_signaling_router;
use rivetlink_server::state::AppState;
use rivetlink_server::websocket::connection::ConnectionMap;

/// Signal future that resolves when SIGTERM or SIGINT is received.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(error = %e, "failed to listen for CTRL+C");
        }
    };

    #[cfg(unix)]
    let sigterm = async {
        if let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("received SIGINT, shutting down gracefully");
        }
        () = sigterm => {
            tracing::info!("received SIGTERM, shutting down gracefully");
        }
    }
}

/// Hourly, delete expired refresh tokens and audit rows past retention, so
/// neither table grows without bound.
async fn prune_old_rows(db: sqlx::PgPool, audit_retention_days: i64) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        tick.tick().await;
        if let Err(e) = refresh_tokens::delete_expired(&db).await {
            tracing::warn!(error = %e, "pruning refresh tokens failed");
        }
        if audit_retention_days > 0 {
            if let Err(e) = audit::delete_older_than(&db, audit_retention_days).await {
                tracing::warn!(error = %e, "pruning audit logs failed");
            }
        }
    }
}

/// Run the relay server. Loads config, opens DB, applies migrations, binds the
/// listener, then serves until shutdown.
#[allow(clippy::cognitive_complexity)] // linear startup sequence, splitting hurts readability
async fn serve() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("RivetLink Relay Server starting");

    let config = match ServerConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to load configuration");
            return std::process::ExitCode::FAILURE;
        },
    };

    let db = match PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!(error = %e, "failed to connect to database");
            return std::process::ExitCode::FAILURE;
        },
    };

    tracing::info!("connected to PostgreSQL");

    if let Err(e) = sqlx::migrate!("../../migrations").run(&db).await {
        tracing::error!(error = %e, "failed to run migrations");
        return std::process::ExitCode::FAILURE;
    }

    tracing::info!("migrations applied");

    let connections = ConnectionMap::new();
    let sessions = SessionManager::new();
    let (signaling_tx, signaling_rx) =
        tokio::sync::mpsc::channel(rivetlink_server::websocket::gateway::SIGNALING_QUEUE);

    let state = AppState {
        db,
        config: config.clone(),
        connections: connections.clone(),
        sessions: sessions.clone(),
        signaling_tx,
    };

    tokio::spawn(run_signaling_router(signaling_rx, connections, sessions));
    tokio::spawn(prune_old_rows(
        state.db.clone(),
        config.audit_retention_days,
    ));

    let router = create_router(state);

    let listener = match tokio::net::TcpListener::bind(&config.bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, bind_addr = %config.bind_addr, "failed to bind");
            return std::process::ExitCode::FAILURE;
        },
    };

    tracing::info!(bind_addr = %config.bind_addr, "server listening");

    if let Err(e) = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        tracing::error!(error = %e, "server error");
        return std::process::ExitCode::FAILURE;
    }

    tracing::info!("server shut down complete");
    std::process::ExitCode::SUCCESS
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Serve) {
        Command::Init(args) => match rivetlink_server::cli::init::run(args) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("init failed: {e}");
                std::process::ExitCode::FAILURE
            },
        },
        Command::Serve => serve().await,
    }
}
