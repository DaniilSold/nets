use std::{
    ffi::OsString,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::Command,
};
#[cfg(windows)]
use std::os::windows::prelude::OsStringExt;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::{
    sync::{watch, Mutex as AsyncMutex},
    task::JoinHandle,
    time::{sleep, Duration},
};
use tracing::{debug, info, warn};
#[cfg(windows)]
use windows::Win32::{
    Foundation::HANDLE,
    Security::{GetTokenInformation, TokenUser, TOKEN_QUERY},
    System::{
        Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS},
        ProcessStatus::K32GetModuleFileNameExW,
        Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};
#[cfg(windows)]
use sha2::{Digest, Sha256};

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
        let mut pid_map: std::collections::HashMap<i32, ProcessIdentity> =
            Self::snapshot_processes();
        for line in stdout.lines() {
            if let Some(mut event) = Self::parse_netstat_line(line) {
                if let Some(proc) = &event.process {
                    if let Some(meta) = pid_map.get(&proc.pid) {
                        event.process = Some(meta.clone());
                    }
                }
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

    #[cfg(windows)]
    fn snapshot_processes() -> std::collections::HashMap<i32, ProcessIdentity> {
        unsafe {
            let mut map = std::collections::HashMap::new();
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok();
            if snapshot.is_err() {
                return map;
            }
            let snapshot = snapshot.unwrap();
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snapshot, &mut entry).as_bool() {
                loop {
                    let pid = entry.th32ProcessID as i32;
                    let name = wchar_to_string(&entry.szExeFile);
                    let (exe_path, sha256_16) = get_process_path_and_hash(pid);
                    let identity = ProcessIdentity {
                        pid,
                        ppid: Some(entry.th32ParentProcessID as i32),
                        name: Some(name),
                        exe_path,
                        sha256_16,
                        user: None,
                        signed: None,
                    };
                    map.insert(pid, identity);
                    if !Process32NextW(snapshot, &mut entry).as_bool() {
                        break;
                    }
                }
            }
            map
        }
    }

    #[cfg(not(windows))]
    fn snapshot_processes() -> std::collections::HashMap<i32, ProcessIdentity> {
        std::collections::HashMap::new()
    }
}

#[cfg(windows)]
fn wchar_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(windows)]
fn get_process_path_and_hash(pid: i32) -> (Option<String>, Option<String>) {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid as u32);
        if handle.is_err() {
            return (None, None);
        }
        let handle = handle.unwrap();
        let mut buf = vec![0u16; 260];
        let len = K32GetModuleFileNameExW(handle, HANDLE(0), &mut buf);
        if len == 0 {
            return (None, None);
        }
        let path = OsString::from_wide(&buf[..len as usize]).to_string_lossy().to_string();
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => return (Some(path), None),
        };
        let mut hasher = Sha256::new();
        let mut reader = std::io::BufReader::new(&mut file);
        let _ = std::io::copy(&mut reader, &mut hasher);
        let hash = hasher.finalize();
        let short = hex::encode(hash)[..16].to_string();
        (Some(path), Some(short))
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
