use anyhow::Result;
use tracing::info;

use crate::{CollectorBackend, FlowHandler, SharedHandlers};

pub struct MacCollector {
    handlers: SharedHandlers,
}

impl MacCollector {
    pub fn new() -> Result<Self> {
        info!("macOS collector initialized (skeleton)");
        Ok(Self {
            handlers: SharedHandlers::new(),
        })
    }
}

#[async_trait::async_trait]
impl CollectorBackend for MacCollector {
    async fn start(&self) -> Result<()> {
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    fn subscribe(&self, handler: FlowHandler) {
        self.handlers.add(handler);
    }
}
