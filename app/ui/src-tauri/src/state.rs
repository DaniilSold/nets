use std::{fs, path::PathBuf};

use analyzer::Alert;
use chrono::{DateTime, Utc};
use collector::FlowEvent;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DaemonStatus {
    pub connected: bool,
    pub mode: Mode,
    pub cpu_load: f32,
    pub memory_mb: f32,
    pub last_heartbeat: DateTime<Utc>,
    pub capture_enabled: bool,
    pub flows_per_second: f32,
    pub sample_ratio: String,
    pub drop_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Observer,
    Guardian,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiSettings {
    pub sample_rate: u32,
    pub max_header_bytes: u32,
    pub lan_only: bool,
    pub enable_logging: bool,
    pub animations_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub count: u32,
    pub last_observed: DateTime<Utc>,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub process: Option<String>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActivity {
    pub pid: i32,
    pub name: String,
    pub user: Option<String>,
    pub signed: Option<bool>,
    pub hash: Option<String>,
    pub listening_ports: Vec<u16>,
    pub total_flows: u64,
    pub last_active: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: GraphNodeKind,
    pub label: String,
    pub risk: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GraphNodeKind {
    Process,
    Endpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphLink {
    pub id: String,
    pub source: String,
    pub target: String,
    pub protocol: String,
    pub volume: u64,
    pub risk: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub nodes: Vec<GraphNode>,
    pub links: Vec<GraphLink>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiSnapshot {
    pub flows: Vec<FlowEvent>,
    pub alerts: Vec<Alert>,
    pub dns: Vec<DnsRecord>,
    pub services: Vec<ServiceRecord>,
    pub processes: Vec<ProcessActivity>,
    pub graph: GraphSnapshot,
    pub status: DaemonStatus,
    pub settings: UiSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum UiEvent {
    Flow(FlowEvent),
    Alert(Alert),
    Status(DaemonStatus),
}

pub struct UiState {
    pub snapshot: RwLock<UiSnapshot>,
    pub locale: RwLock<String>,
    pub sender: broadcast::Sender<UiEvent>,
    pub config_path: PathBuf,
    pub exports_dir: PathBuf,
}

impl UiState {
    pub fn new(snapshot: UiSnapshot, locale: String) -> anyhow::Result<Self> {
        let (sender, _) = broadcast::channel(256);
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("./"))
            .join("nets");
        fs::create_dir_all(&config_dir)?;
        let config_path = config_dir.join("ui.json");

        let exports_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("./"))
            .join("NetMonExports");
        fs::create_dir_all(&exports_dir)?;

        Ok(Self {
            snapshot: RwLock::new(snapshot),
            locale: RwLock::new(locale),
            sender,
            config_path,
            exports_dir,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.sender.subscribe()
    }

    pub fn exports_dir(&self) -> PathBuf {
        self.exports_dir.clone()
    }
}
