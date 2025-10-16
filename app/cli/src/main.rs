use std::sync::Arc;

use analyzer::{dsl::load_rules_from_str, Analyzer};
use anyhow::Result;
use chrono::Duration;
use clap::{Parser, Subcommand};
use collector::{self, CollectorBackend, FlowEvent};
use storage::Storage;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about = "Local Monitoring CLI")]
struct Args {
    #[arg(long, default_value = "./config/config.toml")]
    config: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the collector and print flows to stdout
    Tui,
    /// List the most recent flows from storage
    Flows {
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Evaluate DSL rules against a mock flow
    RuleTest {
        #[arg(long)]
        rule_file: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    match args.command {
        Command::Tui => run_tui(),
        Command::Flows { limit } => show_flows(limit),
        Command::RuleTest { rule_file } => run_rule_test(&rule_file),
    }
}

fn run_tui() -> Result<()> {
    info!("starting CLI TUI mode");
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let backend: Arc<dyn CollectorBackend> = match collector::default_backend() {
            Ok(backend) => backend,
            Err(err) => {
                warn!(error = ?err, "collector backend unavailable, using mock event generator");
                Arc::new(collector::MockCollector::default())
            }
        };

        backend.subscribe(Arc::new(|flow: FlowEvent| {
            println!(
                "{:?} {}:{} -> {}:{} bytes={}",
                flow.state, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.bytes
            );
        }));
        backend.start().await?;
        info!(message = "collector running. press Ctrl+C to stop");
        tokio::signal::ctrl_c().await?;
        backend.stop().await?;
        Ok(())
    })
}

fn show_flows(limit: usize) -> Result<()> {
    let storage = Storage::open("./nets.db", &[0u8; 32])?;
    let flows = storage.query_flows(limit)?;
    for flow in flows {
        println!(
            "#{} {} {}:{} -> {}:{} bytes={}",
            flow.id, flow.proto, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.bytes
        );
    }
    Ok(())
}

fn run_rule_test(path: &str) -> Result<()> {
    let data = std::fs::read_to_string(path)?;
    let rules = load_rules_from_str(&data)?;
    let mut analyzer = Analyzer::new(Duration::hours(1), rules);
    let mock_flow = normalizer::NormalizedFlow {
        window_start: chrono::Utc::now(),
        window_end: chrono::Utc::now(),
        proto: "TCP".into(),
        src_ip: "10.0.0.5".into(),
        src_port: 51515,
        dst_ip: "10.0.0.8".into(),
        dst_port: 445,
        direction: collector::FlowDirection::Lateral,
        bytes: 4096,
        packets: 12,
        process: Some("notesync.exe".into()),
    };
    for alert in analyzer.ingest(mock_flow) {
        println!("Alert {} severity {:?}", alert.id, alert.severity);
    }
    Ok(())
}
