use std::sync::Arc;

use anyhow::Result;
use tracing::{info, warn};

use crate::{CollectorBackend, CollectorError, FlowEvent, FlowHandler, SharedHandlers};

pub struct WindowsCollector {
    handlers: SharedHandlers,
}

impl WindowsCollector {
    pub fn new() -> Result<Self> {
        info!("windows collector initialized (skeleton)");
        Ok(Self {
            handlers: SharedHandlers::new(),
        })
    }

    fn setup_etw_subscription(&self) -> Result<()> {
        // Real implementation would register to Microsoft-Windows-TCPIP ETW provider using the `windows` crate.
        info!("configuring ETW subscription for TCP/IP provider");
        Ok(())
    }

    fn setup_listener_probe(&self) -> Result<()> {
        info!("scanning active TCP listeners via GetExtendedTcpTable");
        Ok(())
    }
}

#[async_trait::async_trait]
impl CollectorBackend for WindowsCollector {
    async fn start(&self) -> Result<()> {
        self.setup_etw_subscription()?;
        self.setup_listener_probe()?;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        warn!("windows collector stop() invoked - ETW teardown pending implementation");
        Ok(())
    }

    fn subscribe(&self, handler: FlowHandler) {
        self.handlers.add(handler);
    }
}

pub fn sample_listener_event() -> FlowEvent {
    use chrono::Utc;
    FlowEvent {
        ts_first: Utc::now(),
        ts_last: Utc::now(),
        proto: "TCP".into(),
        src_ip: "0.0.0.0".into(),
        src_port: 8080,
        dst_ip: "0.0.0.0".into(),
        dst_port: 0,
        iface: Some("Ethernet0".into()),
        direction: crate::FlowDirection::Inbound,
        state: Some("LISTEN".into()),
        risk: None,
        ..FlowEvent::default()
    }
}
