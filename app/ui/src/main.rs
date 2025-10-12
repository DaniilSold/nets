use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use collector::{CollectorBackend, FlowEvent, MockCollector};
use tokio::runtime::Runtime;
use tracing::info;

#[derive(Parser)]
#[command(author, version, about = "Local monitoring desktop UI stub")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Launches the UI event loop (placeholder implementation)
    Run,
    /// Demonstrates mock flow rendering
    Demo,
}

pub fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    match args.command {
        Command::Run => run_ui(),
        Command::Demo => demo_table(),
    }
}

fn run_ui() -> Result<()> {
    info!("UI run invoked - awaiting Tauri/GTK integration");
    Ok(())
}

fn demo_table() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async move {
        let collector = MockCollector::default();
        collector.subscribe(Arc::new(|flow: FlowEvent| {
            println!(
                "{:<20} {:<6} {:<21} -> {:<21} {:<6} bytes={}",
                flow.process
                    .as_ref()
                    .and_then(|p| p.name.clone())
                    .unwrap_or_else(|| "(unknown)".into()),
                flow.proto,
                format!("{}:{}", flow.src_ip, flow.src_port),
                format!("{}:{}", flow.dst_ip, flow.dst_port),
                flow.state.clone().unwrap_or_else(|| "".into()),
                flow.bytes
            );
        }));
        collector.start().await?;
        collector.stop().await?;
        Ok(())
    })
}
