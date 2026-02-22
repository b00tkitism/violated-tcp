mod client;
mod config;
mod packet;
mod server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "gfw-resist-proxy")]
#[command(about = "High-performance TCP violation proxy for bypassing GFW IP blocking")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in server mode (on the VPS)
    Server,
    /// Run in client mode (on local machine)
    Client,
}

fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = Arc::new(config::Config::load(&cli.config)?);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    match cli.command {
        Commands::Server => {
            tracing::warn!("Starting GFW-Resist proxy in SERVER mode");
            rt.block_on(server::run(config))?;
        }
        Commands::Client => {
            tracing::warn!("Starting GFW-Resist proxy in CLIENT mode");
            rt.block_on(client::run(config))?;
        }
    }

    Ok(())
}
