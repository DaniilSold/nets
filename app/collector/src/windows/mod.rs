use std::{
    net::{IpAddr, Ipv4Addr},
    process::Command,
};

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
    shutdown_tx: watch::Sender<bool>,
    worker: AsyncMutex<Option<JoinHandle<()>>>,
}

impl WindowsCollector {
    pub fn new() -> Result<Self> {
        info!("windows collector initialized (skeleton)");
        let (shutdown_tx, _rx) = watch::channel(false);
        Ok(Self {
            handlers: SharedHandlers::new(),
            shutdown_tx,
            worker: AsyncMutex::new(None),
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

    fn collect_snapshot() -> Result<Vec<FlowEvent>> {
        let output = Command::new("netstat")
            .args(["-ano"])
            .output()
            .context("executing netstat -ano")?;

        if !output.status.success() {
            anyhow::bail!("netstat exited with status {:?}", output.status);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut events = Vec::new();
        for line in stdout.lines() {
            if let Some(event) = Self::parse_netstat_line(line) {
                events.push(event);
            }
        }
        Ok(events)
    }

    fn parse_netstat_line(line: &str) -> Option<FlowEvent> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.starts_with("Proto") || trimmed.starts_with("Active") {
            return None;
        }

        let mut parts = trimmed.split_whitespace();
        let proto = parts.next()?;
        if !(proto.eq_ignore_ascii_case("tcp") || proto.eq_ignore_ascii_case("udp")) {
            return None;
        }

        let local = parts.next()?;
        let remote = parts.next()?;
        let (state, pid_str) = if proto.eq_ignore_ascii_case("tcp") {
            let state = parts.next().map(|s| s.to_string());
            let pid = parts.next().unwrap_or("0").to_string();
            (state, pid)
        } else {
            (None, parts.next().unwrap_or("0").to_string())
        };

        let pid = pid_str.parse::<i32>().unwrap_or_default();
        let (local_ip, local_port) = Self::split_address(local);
        let (remote_ip, remote_port) = Self::split_address(remote);
        let direction = Self::infer_direction(&local_ip, &remote_ip);

        let now = Utc::now();
        Some(FlowEvent {
            ts_first: now,
            ts_last: now,
            proto: proto.to_uppercase(),
            src_ip: local_ip,
            src_port: local_port,
            dst_ip: remote_ip,
            dst_port: remote_port,
            direction,
            state,
            process: if pid > 0 {
                Some(ProcessIdentity {
                    pid,
                    ppid: None,
                    name: None,
                    exe_path: None,
                    sha256_16: None,
                    user: None,
                    signed: None,
                })
            } else {
                None
            },
            ..FlowEvent::default()
        })
    }

    fn split_address(addr: &str) -> (String, u16) {
        if addr == "*:*" {
            return ("*".into(), 0);
        }

        if let Some(port_sep) = addr.rfind(':') {
            let (ip_part, port_part) = addr.split_at(port_sep);
            let port = port_part.trim_start_matches(':').parse().unwrap_or(0);
            let ip = ip_part.trim_matches(['[', ']'].as_ref()).to_string();
            return (ip, port);
        }

        (addr.trim_matches(['[', ']'].as_ref()).to_string(), 0)
    }

    fn infer_direction(local_ip: &str, remote_ip: &str) -> FlowDirection {
        if remote_ip == "0.0.0.0" || remote_ip == "*" || remote_ip == "::" {
            return FlowDirection::Inbound;
        }

        if let (Ok(local), Ok(remote)) = (local_ip.parse::<IpAddr>(), remote_ip.parse::<IpAddr>()) {
            if let (IpAddr::V4(local_v4), IpAddr::V4(remote_v4)) = (local, remote) {
                if Self::same_subnet(local_v4, remote_v4) {
                    return FlowDirection::Lateral;
                }
            }
        }

        FlowDirection::Outbound
    }

    fn same_subnet(local: Ipv4Addr, remote: Ipv4Addr) -> bool {
        let local_octets = local.octets();
        let remote_octets = remote.octets();
        local_octets[0..3] == remote_octets[0..3]
    }
}

#[async_trait::async_trait]
impl CollectorBackend for WindowsCollector {
    async fn start(&self) -> Result<()> {
        self.setup_etw_subscription()?;
        self.setup_listener_probe()?;

        let mut guard = self.worker.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        let handlers = self.handlers.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        *guard = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = sleep(Duration::from_secs(2)) => {
                        match tokio::task::spawn_blocking(WindowsCollector::collect_snapshot).await {
                            Ok(Ok(events)) => {
                                for event in events {
                                    handlers.emit(event);
                                }
                            }
                            Ok(Err(err)) => {
                                warn!(error = ?err, "failed to collect netstat snapshot");
                            }
                            Err(join_err) => {
                                warn!(error = ?join_err, "netstat task panicked");
                            }
                        }
                    }
                }
            }
            debug!("windows collector worker stopped");
        }));
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        warn!("windows collector stop() invoked - shutting down worker");
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
        direction: crate::FlowDirection::Inbound,
        state: Some("LISTEN".into()),
        risk: None,
        ..FlowEvent::default()
    }
}
