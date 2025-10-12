use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
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
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub ja3: Option<String>,
    pub dns_qname: Option<String>,
    pub dns_qtype: Option<String>,
    pub dns_rcode: Option<String>,
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

#[derive(Default)]
pub struct SharedHandlers {
    inner: Mutex<Vec<FlowHandler>>,
}

impl SharedHandlers {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
        }
    }

    pub fn add(&self, handler: FlowHandler) {
        self.inner.lock().push(handler);
    }

    pub fn emit(&self, event: FlowEvent) {
        for handler in self.inner.lock().iter() {
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
#[derive(Default)]
pub struct MockCollector {
    handlers: SharedHandlers,
}

#[async_trait::async_trait]
impl CollectorBackend for MockCollector {
    async fn start(&self) -> Result<()> {
        info!("mock collector started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("mock collector stopped");
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
