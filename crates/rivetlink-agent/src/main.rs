//! `rivet-agent` binary entry point.

use clap::Parser;
use tracing_subscriber::EnvFilter;

use rivetlink_agent::cli::Cli;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    match rivetlink_agent::runner::run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "agent failed");
            std::process::ExitCode::FAILURE
        },
    }
}
