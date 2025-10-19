// Windows collector using IP Helper API, ETW, and WFP
// Provides comprehensive L2-L4 network monitoring with process binding

mod actions;
mod anomaly_detector;
mod network_monitor;
mod process_info;
mod protocol_detector;

pub use actions::ActionHandler;
pub use anomaly_detector::{Anomaly, AnomalyDetector};
pub use network_monitor::NetworkMonitor;
pub use process_info::ProcessInfoCollector;
pub use protocol_detector::{LocalProtocol, ProtocolDetector};

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::{
    sync::{watch, Mutex as AsyncMutex},
    task::JoinHandle,
    time::{sleep, Duration},
};
use tracing::{debug, info, warn};

use crate::{
    CollectorBackend, FlowDirection, FlowEvent, FlowHandler, ProcessIdentity, SharedHandlers,
};

pub struct WindowsCollector {
    handlers: SharedHandlers,
    anomaly_detector: AnomalyDetector,
    shutdown_tx: watch::Sender<bool>,
    worker: AsyncMutex<Option<JoinHandle<()>>>,
}

impl WindowsCollector {
    pub fn new() -> Result<Self> {
        info!("initializing Windows collector with IP Helper API");
        let (shutdown_tx, _rx) = watch::channel(false);
        Ok(Self {
            handlers: SharedHandlers::new(),
            anomaly_detector: AnomalyDetector::new(),
            shutdown_tx,
            worker: AsyncMutex::new(None),
        })
    }

    /// Collect complete network snapshot (TCP + UDP)
    fn collect_snapshot() -> Result<Vec<FlowEvent>> {
        let mut events = Vec::new();

        // Collect TCP connections
        match NetworkMonitor::collect_tcp_connections() {
            Ok(tcp_events) => events.extend(tcp_events),
            Err(e) => warn!("failed to collect TCP connections: {}", e),
        }

        // Collect UDP endpoints
        match NetworkMonitor::collect_udp_endpoints() {
            Ok(udp_events) => events.extend(udp_events),
            Err(e) => warn!("failed to collect UDP endpoints: {}", e),
        }

        Ok(events)
    }

    /// Enrich flow with protocol detection and anomaly analysis
    fn enrich_flow(&self, mut flow: FlowEvent) -> (FlowEvent, Vec<Anomaly>) {
        // Detect local protocols
        if let Some(proto) = ProtocolDetector::detect_protocol(&flow) {
            debug!(
                "detected protocol: {} on {}:{}",
                proto.as_str(),
                flow.dst_ip,
                flow.dst_port
            );
        }

        // Analyze for anomalies
        let anomalies = self.anomaly_detector.analyze_flow(&flow);

        if !anomalies.is_empty() {
            info!("detected {} anomalies for flow", anomalies.len());
            // Mark flow as risky if anomalies detected
            flow.risk = Some(crate::FlowRisk {
                score: 75,
                level: "Medium".to_string(),
                rule_id: Some("anomaly".to_string()),
                rationale: Some(format!("Anomalies: {:?}", anomalies)),
            });
        }

        (flow, anomalies)
    }
}

#[async_trait::async_trait]
impl CollectorBackend for WindowsCollector {
    async fn start(&self) -> Result<()> {
        info!("starting Windows network collector");

        let mut guard = self.worker.lock().await;
        if guard.is_some() {
            info!("collector already running");
            return Ok(());
        }

        let handlers = self.handlers.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        *guard = Some(tokio::spawn(async move {
            info!("Windows collector worker started");

            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            info!("shutdown signal received");
                            break;
                        }
                    }
                    _ = sleep(Duration::from_secs(2)) => {
                        match tokio::task::spawn_blocking(WindowsCollector::collect_snapshot).await {
                            Ok(Ok(events)) => {
                                debug!("collected {} network events", events.len());
                                for event in events {
                                    handlers.emit(event);
                                }
                            }
                            Ok(Err(err)) => {
                                warn!(error = ?err, "failed to collect network snapshot");
                            }
                            Err(join_err) => {
                                warn!(error = ?join_err, "collection task panicked");
                            }
                        }
                    }
                }
            }

            debug!("Windows collector worker stopped");
        }));

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("stopping Windows collector");
        let _ = self.shutdown_tx.send(true);

        if let Some(handle) = self.worker.lock().await.take() {
            let _ = handle.await;
        }

        info!("Windows collector stopped");
        Ok(())
    }

    fn subscribe(&self, handler: FlowHandler) {
        self.handlers.add(handler);
    }
}

/// Generate sample listener event for testing
pub fn sample_listener_event() -> FlowEvent {
    FlowEvent {
        ts_first: Utc::now(),
        ts_last: Utc::now(),
        proto: "TCP".into(),
        src_ip: "0.0.0.0".into(),
        src_port: 8080,
        dst_ip: "0.0.0.0".into(),
        dst_port: 0,
        iface: Some("Ethernet0".into()),
        direction: FlowDirection::Inbound,
        state: Some("LISTEN".into()),
        risk: None,
        process: Some(ProcessIdentity {
            pid: 1234,
            ppid: Some(1000),
            name: Some("test.exe".into()),
            exe_path: Some("C:\\test\\test.exe".into()),
            sha256_16: Some("a1b2c3d4".into()),
            user: Some("DOMAIN\\User".into()),
            signed: Some(false),
        }),
        ..FlowEvent::default()
    }
}

/// Generate sample mDNS event for testing
pub fn sample_mdns_event() -> FlowEvent {
    FlowEvent {
        ts_first: Utc::now(),
        ts_last: Utc::now(),
        proto: "UDP".into(),
        src_ip: "192.168.1.100".into(),
        src_port: 5353,
        dst_ip: "224.0.0.251".into(),
        dst_port: 5353,
        direction: FlowDirection::Outbound,
        state: None,
        bytes: 120,
        packets: 1,
        dns_qname: Some("_http._tcp.local".into()),
        dns_qtype: Some("PTR".into()),
        dns_rcode: Some("NOERROR".into()),
        ..FlowEvent::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        let collector = WindowsCollector::new();
        assert!(collector.is_ok());
    }

    #[test]
    fn test_sample_events() {
        let listener = sample_listener_event();
        assert_eq!(listener.proto, "TCP");
        assert_eq!(listener.src_port, 8080);

        let mdns = sample_mdns_event();
        assert_eq!(mdns.proto, "UDP");
        assert_eq!(mdns.dst_port, 5353);
    }
}
