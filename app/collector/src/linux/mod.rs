use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tracing::{debug, info};

use crate::{CollectorBackend, CollectorError, FlowHandler, SharedHandlers};

/// LinuxCollector wires up the eBPF/XDP programs and relays metadata events through
/// an async broadcast channel. The actual eBPF bytecode is expected to be generated
/// offline and embedded via `include_bytes!` in future iterations; this skeleton
/// focuses on the control-plane plumbing and graceful degradation.
pub struct LinuxCollector {
    handlers: SharedHandlers,
    _shutdown_tx: broadcast::Sender<()>,
}

impl LinuxCollector {
    pub fn new() -> Result<Self> {
        let (tx, _rx) = broadcast::channel(16);
        // eBPF program loading would live here using aya::BpfLoader
        // For the skeleton we simply log the initialization intent.
        info!("linux collector initialized (skeleton)");
        Ok(Self {
            handlers: SharedHandlers::new(),
            _shutdown_tx: tx,
        })
    }

    fn spawn_reader(&self) {
        // In the real implementation, this function would read from an aya::maps::AsyncPerfEventArray
        // and transform kernel events into FlowEvent structures. The stub just emits debug logs.
        debug!("spawn_reader invoked - awaiting eBPF events");
    }
}

#[async_trait::async_trait]
impl CollectorBackend for LinuxCollector {
    async fn start(&self) -> Result<()> {
        self.spawn_reader();
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self._shutdown_tx
            .send(())
            .map_err(|e| CollectorError::Initialization(e.to_string()))?;
        Ok(())
    }

    fn subscribe(&self, handler: FlowHandler) {
        self.handlers.add(handler);
    }
}

/// Helper invoked by integration tests to replay PCAP streams into the collector.
pub async fn replay_pcap(path: &str, backend: Arc<dyn CollectorBackend>) -> Result<()> {
    // Placeholder for offline replay logic using pcap crate.
    info!(path, "replay_pcap invoked");
    backend
        .start()
        .await
        .context("starting backend for replay")?;
    backend.stop().await?;
    Ok(())
}
