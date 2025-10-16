use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    sync::{watch, Mutex as AsyncMutex},
    task::JoinHandle,
    time::{sleep, Duration},
};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Layer2EventKind {
    Arp,
    Nd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer2EventMetadata {
    pub kind: Layer2EventKind,
    pub operation: String,
    pub mac_src: Option<String>,
    pub ip_src: Option<String>,
    pub mac_dst: Option<String>,
    pub ip_dst: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub ppid: Option<i32>,
    pub name: Option<String>,
    pub exe_path: Option<String>,
    pub sha256_16: Option<String>,
    pub user: Option<String>,
    pub signed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRisk {
    pub score: u8,
    pub level: String,
    pub rule_id: Option<String>,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    pub ts_first: DateTime<Utc>,
    pub ts_last: DateTime<Utc>,
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub iface: Option<String>,
    pub direction: FlowDirection,
    pub state: Option<String>,
    pub bytes: u64,
    pub packets: u64,
    pub process: Option<ProcessIdentity>,
    pub layer2: Option<Layer2EventMetadata>,
    pub risk: Option<FlowRisk>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub ja3: Option<String>,
    pub dns_qname: Option<String>,
    pub dns_qtype: Option<String>,
    pub dns_rcode: Option<String>,
}

impl Default for FlowEvent {
    fn default() -> Self {
        let epoch = Utc.timestamp_opt(0, 0).unwrap();
        Self {
            ts_first: epoch,
            ts_last: epoch,
            proto: String::new(),
            src_ip: String::new(),
            src_port: 0,
            dst_ip: String::new(),
            dst_port: 0,
            iface: None,
            direction: FlowDirection::Inbound,
            state: None,
            bytes: 0,
            packets: 0,
            process: None,
            layer2: None,
            risk: None,
            sni: None,
            alpn: None,
            ja3: None,
            dns_qname: None,
            dns_qtype: None,
            dns_rcode: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FlowDirection {
    Inbound,
    Outbound,
    Lateral,
}

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("feature not supported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("initialization failed: {0}")]
    Initialization(String),
    #[error("io error: {0}")]
    Io(String),
}

#[async_trait::async_trait]
pub trait CollectorBackend: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn subscribe(&self, handler: FlowHandler);
}

pub type FlowHandler = Arc<dyn Fn(FlowEvent) + Send + Sync + 'static>;

#[derive(Default, Clone)]
pub struct SharedHandlers {
    inner: Arc<Mutex<Vec<FlowHandler>>>,
}

impl SharedHandlers {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn add(&self, handler: FlowHandler) {
        self.inner.lock().push(handler);
    }

    pub fn emit(&self, event: FlowEvent) {
        let handlers = self.inner.lock().clone();
        for handler in handlers {
            handler(event.clone());
        }
    }
}

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod mac;

/// Platform-independent factory
pub fn default_backend() -> Result<Arc<dyn CollectorBackend>> {
    #[cfg(target_os = "linux")]
    {
        return Ok(Arc::new(linux::LinuxCollector::new()?));
    }

    #[cfg(target_os = "windows")]
    {
        return Ok(Arc::new(windows::WindowsCollector::new()?));
    }

    #[cfg(target_os = "macos")]
    {
        return Ok(Arc::new(mac::MacCollector::new()?));
    }

    #[allow(unreachable_code)]
    Err(CollectorError::Unsupported("platform").into())
}

/// Simple in-process mock collector used for tests and CLI demonstrations.
pub struct MockCollector {
    handlers: SharedHandlers,
    shutdown_tx: watch::Sender<bool>,
    worker: AsyncMutex<Option<JoinHandle<()>>>,
}

impl Default for MockCollector {
    fn default() -> Self {
        let (shutdown_tx, _rx) = watch::channel(false);
        Self {
            handlers: SharedHandlers::new(),
            shutdown_tx,
            worker: AsyncMutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl CollectorBackend for MockCollector {
    async fn start(&self) -> Result<()> {
        info!("mock collector started");
        let mut guard = self.worker.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let handlers = self.handlers.clone();
        *guard = Some(tokio::spawn(async move {
            let mut counter: u64 = 0;
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = sleep(Duration::from_secs(1)) => {
                        counter += 1;
                        let now = Utc::now();
                        let port = 10_000 + (counter % 1_000) as u16;
                        let event = FlowEvent {
                            ts_first: now,
                            ts_last: now,
                            proto: if counter % 2 == 0 { "TCP".into() } else { "UDP".into() },
                            src_ip: "127.0.0.1".into(),
                            src_port: port,
                            dst_ip: "127.0.0.1".into(),
                            dst_port: port + 1,
                            direction: FlowDirection::Lateral,
                            bytes: counter * 512,
                            packets: counter * 4,
                            ..FlowEvent::default()
                        };
                        handlers.emit(event);
                    }
                }
            }
        }));

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("mock collector stopped");
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.worker.lock().await.take() {
            let _ = handle.await;
        }
        Ok(())
    }

    fn subscribe(&self, handler: FlowHandler) {
        self.handlers.add(handler);
    }
}

impl MockCollector {
    pub fn emit(&self, event: FlowEvent) {
        self.handlers.emit(event);
    }
}
