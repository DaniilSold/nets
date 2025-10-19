use std::{collections::HashMap, fs::File, io::Write, time::Duration};
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::{async_runtime::spawn, AppHandle, Emitter, State, WebviewWindow};
use tokio::sync::RwLockWriteGuard;
use tokio::time::interval;

use crate::{
    resources,
    state::{DaemonStatus, Mode, UiEvent, UiSettings, UiSnapshot, UiState},
};
use storage::Storage;
use rand::RngCore;
use policy::{NoopBackend, QuarantineDecision, PolicyBackend};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetSummary {
    pub id: String,
    pub label: HashMap<String, String>,
    pub description: HashMap<String, String>,
}

fn persist_settings(state: &UiState, settings: &UiSettings, locale: &str) -> anyhow::Result<()> {
    #[derive(Serialize)]
    struct Persisted<'a> {
        settings: &'a UiSettings,
        locale: &'a str,
    }
    let payload = Persisted { settings, locale };
    resources::save_json(&state.config_path, &payload)
}

#[tauri::command]
pub async fn load_snapshot(state: State<'_, UiState>) -> Result<UiSnapshot, String> {
    let snapshot = state.snapshot.read().await.clone();
    Ok(snapshot)
}

#[tauri::command]
pub async fn update_settings(
    state: State<'_, UiState>,
    settings: UiSettings,
) -> Result<UiSettings, String> {
    {
        let mut guard = state.snapshot.write().await;
        guard.settings = settings.clone();
    }
    let locale = state.locale.read().await.clone();
    persist_settings(&state, &settings, &locale).map_err(|e| e.to_string())?;
    Ok(settings)
}

#[tauri::command]
pub async fn set_locale(state: State<'_, UiState>, locale: String) -> Result<(), String> {
    {
        let mut guard = state.locale.write().await;
        *guard = locale.clone();
    }
    let settings = {
        let guard = state.snapshot.read().await;
        guard.settings.clone()
    };
    persist_settings(&state, &settings, &locale).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_presets() -> Vec<PresetSummary> {
    vec![
        PresetSummary {
            id: "lan-essentials".into(),
            label: HashMap::from([
                ("en".into(), "LAN essentials".into()),
                ("ru".into(), "Базовый LAN".into()),
            ]),
            description: HashMap::from([
                (
                    "en".into(),
                    "Focus on ARP, DNS, and inbound listeners in the local network".into(),
                ),
                (
                    "ru".into(),
                    "Фокус на ARP, DNS и входящих слушателях в локальной сети".into(),
                ),
            ]),
        },
        PresetSummary {
            id: "dns-focus".into(),
            label: HashMap::from([
                ("en".into(), "DNS focus".into()),
                ("ru".into(), "DNS анализ".into()),
            ]),
            description: HashMap::from([
                (
                    "en".into(),
                    "Capture NXDOMAIN bursts and suspicious service discovery".into(),
                ),
                (
                    "ru".into(),
                    "Отслеживание всплесков NXDOMAIN и аномального сервис-дискавери".into(),
                ),
            ]),
        },
        PresetSummary {
            id: "investigation".into(),
            label: HashMap::from([
                ("en".into(), "Investigation".into()),
                ("ru".into(), "Расследование".into()),
            ]),
            description: HashMap::from([
                (
                    "en".into(),
                    "Maximum retention, verbose logging, quarantine prompts".into(),
                ),
                (
                    "ru".into(),
                    "Максимальное хранение, подробные логи, подсказки карантина".into(),
                ),
            ]),
        },
    ]
}

#[tauri::command]
pub async fn apply_preset(
    state: State<'_, UiState>,
    preset_id: String,
) -> Result<UiSettings, String> {
    let mut guard: RwLockWriteGuard<'_, UiSnapshot> = state.snapshot.write().await;
    let settings = match preset_id.as_str() {
        "lan-essentials" => UiSettings {
            sample_rate: 10,
            max_header_bytes: 256,
            lan_only: true,
            enable_logging: false,
            animations_enabled: true,
        },
        "dns-focus" => UiSettings {
            sample_rate: 5,
            max_header_bytes: 192,
            lan_only: false,
            enable_logging: true,
            animations_enabled: true,
        },
        "investigation" => UiSettings {
            sample_rate: 1,
            max_header_bytes: 512,
            lan_only: false,
            enable_logging: true,
            animations_enabled: false,
        },
        _ => return Err("unknown preset".into()),
    };
    guard.settings = settings.clone();
    drop(guard);
    let locale = state.locale.read().await.clone();
    persist_settings(&state, &settings, &locale).map_err(|e| e.to_string())?;
    Ok(settings)
}

#[tauri::command]
pub async fn export_report(state: State<'_, UiState>) -> Result<String, String> {
    let snapshot = state.snapshot.read().await.clone();
    let exports_dir = state.exports_dir();
    let file_path = exports_dir.join(format!(
        "nets-report-{}.html",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    let mut file = File::create(&file_path).map_err(|e| e.to_string())?;
    write!(
        file,
        "<html><head><meta charset=\"utf-8\"/><title>Nets report</title></head><body><h1>Nets offline report</h1><p>Flows: {}<p><p>Alerts: {}<p></body></html>",
        snapshot.flows.len(),
        snapshot.alerts.len()
    )
    .map_err(|e| e.to_string())?;
    Ok(file_path.display().to_string())
}

#[tauri::command]
pub async fn export_pcap(
    state: State<'_, UiState>,
    flow_id: Option<String>,
) -> Result<String, String> {
    let exports_dir = state.exports_dir();
    let filename = flow_id
        .map(|id| format!("flow-{id}.pcap"))
        .unwrap_or_else(|| "snippet.pcap".into());
    let destination = exports_dir.join(filename);
    resources::write_sample_pcap(&destination).map_err(|e| e.to_string())?;
    Ok(destination.display().to_string())
}

#[tauri::command]
pub async fn toggle_mode_command(state: State<'_, UiState>) -> Result<(), String> {
    toggle_mode(&*state);
    Ok(())
}

#[tauri::command]
pub async fn toggle_capture_command(state: State<'_, UiState>) -> Result<(), String> {
    toggle_capture(&*state);
    Ok(())
}

#[tauri::command]
pub async fn start_event_stream(
    window: WebviewWindow,
    state: State<'_, UiState>,
) -> Result<(), String> {
    let state = state.inner().clone();
    spawn(async move {
        let mut rx = state.subscribe();
        while let Ok(event) = rx.recv().await {
            if window.emit("ui-event", &event).is_err() {
                break;
            }
            // Opportunistically persist recent flows and alerts to local storage for history.
            match &event {
                UiEvent::Flow(flow) => {
                    if let Err(err) = persist_flow(flow) {
                        tracing::warn!(error = %err, "failed to persist flow");
                    }
                }
                UiEvent::Alert(alert) => {
                    if let Err(err) = persist_alert(alert) {
                        tracing::warn!(error = %err, "failed to persist alert");
                    }
                }
                UiEvent::Status(_) => {}
            }
        }
    });
    Ok(())
}

pub fn spawn_status_heartbeat(handle: AppHandle, state: UiState) {
    spawn(async move {
        let mut rx = state.subscribe();
        let mut ticker = interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                Ok(event) = rx.recv() => {
                    if matches!(event, UiEvent::Status(_)) {
                        if handle.emit("ui-event", &event).is_err() {
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    let status = {
                        let snapshot = state.snapshot.read().await;
                        snapshot.status.clone()
                    };
                    let mut updated = status;
                    updated.last_heartbeat = Utc::now();
                    if handle.emit("ui-event", &UiEvent::Status(updated)).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

pub fn emit_mock_flow(handle: &AppHandle, flow: collector::FlowEvent, state: &UiState) {
    let mut snapshot = futures::executor::block_on(state.snapshot.write());
    snapshot.flows.insert(0, flow.clone());
    if snapshot.flows.len() > 2000 {
        snapshot.flows.pop();
    }
    drop(snapshot);
    let _ = state.sender.send(UiEvent::Flow(flow.clone()));
    let _ = handle.emit("ui-event", &UiEvent::Flow(flow));
}

pub fn emit_mock_alert(handle: &AppHandle, alert: analyzer::Alert, state: &UiState) {
    let mut snapshot = futures::executor::block_on(state.snapshot.write());
    snapshot.alerts.insert(0, alert.clone());
    if snapshot.alerts.len() > 1000 {
        snapshot.alerts.pop();
    }
    drop(snapshot);
    let _ = state.sender.send(UiEvent::Alert(alert.clone()));
    let _ = handle.emit("ui-event", &UiEvent::Alert(alert));
}

pub fn bootstrap_mock_stream(handle: AppHandle, state: UiState) {
    spawn(async move {
        let flows: Vec<collector::FlowEvent> =
            resources::load_json("mock_flows.json").expect("flows fixture");
        let alerts: Vec<analyzer::Alert> =
            resources::load_json("mock_alerts.json").expect("alerts fixture");
        let mut ticker = interval(Duration::from_secs(6));
        let mut flow_iter = flows.into_iter().cycle();
        let mut alert_iter = alerts.into_iter().cycle();
        loop {
            ticker.tick().await;
            if let Some(flow) = flow_iter.next() {
                emit_mock_flow(&handle, flow, &state);
            }
            if Utc::now().timestamp() % 3 == 0 {
                if let Some(alert) = alert_iter.next() {
                    emit_mock_alert(&handle, alert, &state);
                }
            }
        }
    });
}

pub fn bootstrap_collector_stream(handle: AppHandle, state: UiState) {
    spawn(async move {
        let backend = match collector::default_backend() {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(error = ?err, "collector backend unavailable; falling back to mock stream");
                bootstrap_mock_stream(handle.clone(), state.clone());
                return;
            }
        };

        let handle_clone = handle.clone();
        let state_clone = state.clone();
        backend.subscribe(Arc::new(move |flow: collector::FlowEvent| {
            // Emit flow into UI
            emit_mock_flow(&handle_clone, flow.clone(), &state_clone);
            // Simple built-in detection for unexpected listeners
            if let Some(alert) = analyzer::detect_listener(&flow) {
                emit_mock_alert(&handle_clone, alert, &state_clone);
            }
        }));

        if let Err(err) = backend.start().await {
            tracing::warn!(error = ?err, "failed to start collector backend; using mock stream");
            bootstrap_mock_stream(handle.clone(), state.clone());
            return;
        }

        // Keep a weak heartbeat to reflect running backend; we don't stop it here to let app lifetime manage it.
        let mut ticker = interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            // no-op, just keep task alive
        }
    });
}

#[tauri::command]
pub async fn apply_quarantine_command(_state: State<'_, UiState>, pid: Option<i32>, ports: Vec<u16>) -> Result<(), String> {
    let decision = QuarantineDecision {
        process: pid.map(|p| format!("pid:{p}")),
        ports,
        expires_in_seconds: 600,
    };
    if let Err(err) = policy::validate_decision(&decision) {
        return Err(err.to_string());
    }
    let backend = NoopBackend::default();
    backend.apply(&decision).map_err(|e| e.to_string())
}

pub fn bootstrap_snapshot() -> anyhow::Result<UiSnapshot> {
    let flows = resources::load_json("mock_flows.json")?;
    let alerts = resources::load_json("mock_alerts.json")?;
    let dns = resources::load_json("mock_dns.json")?;
    let services = resources::load_json("mock_services.json")?;
    let processes = resources::load_json("mock_processes.json")?;
    let graph = resources::load_json("mock_graph.json")?;
    let status = resources::load_json("mock_status.json")?;
    let settings = resources::load_json("mock_settings.json")?;
    Ok(UiSnapshot {
        flows,
        alerts,
        dns,
        services,
        processes,
        graph,
        status,
        settings,
    })
}

fn storage_path() -> std::path::PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| std::path::PathBuf::from("./"));
    base.join("NetMonDB").join("events.db")
}

fn load_or_init_storage() -> anyhow::Result<Storage> {
    let path = storage_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let key = get_or_create_key(path.parent().unwrap());
    Storage::open(path, &key)
}

fn persist_flow(flow: &collector::FlowEvent) -> anyhow::Result<()> {
    let store = load_or_init_storage()?;
    let _ = store.put_flow(flow)?;
    Ok(())
}

fn persist_alert(alert: &analyzer::Alert) -> anyhow::Result<()> {
    let store = load_or_init_storage()?;
    store.put_alert(alert)?;
    Ok(())
}

fn get_or_create_key(dir: &std::path::Path) -> [u8; 32] {
    let key_path = dir.join("key.bin");
    if let Ok(bytes) = std::fs::read(&key_path) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return key;
        }
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let _ = std::fs::write(&key_path, &key);
    key
}

pub fn load_locale_from_disk(state: &UiState) -> anyhow::Result<Option<String>> {
    if !state.config_path.exists() {
        return Ok(None);
    }
    #[derive(Deserialize)]
    struct Persisted {
        locale: Option<String>,
    }
    let persisted: Persisted = serde_json::from_str(&std::fs::read_to_string(&state.config_path)?)?;
    Ok(persisted.locale)
}

pub fn update_status(state: &UiState, status: DaemonStatus) {
    let mut snapshot = futures::executor::block_on(state.snapshot.write());
    snapshot.status = status.clone();
    drop(snapshot);
    let _ = state.sender.send(UiEvent::Status(status.clone()));
}

pub fn toggle_mode(state: &UiState) {
    let mut snapshot = futures::executor::block_on(state.snapshot.write());
    snapshot.status.mode = match snapshot.status.mode {
        Mode::Observer => Mode::Guardian,
        Mode::Guardian => Mode::Observer,
    };
    snapshot.status.last_heartbeat = Utc::now();
    let status = snapshot.status.clone();
    drop(snapshot);
    let _ = state.sender.send(UiEvent::Status(status));
}

pub fn toggle_capture(state: &UiState) {
    let mut snapshot = futures::executor::block_on(state.snapshot.write());
    snapshot.status.capture_enabled = !snapshot.status.capture_enabled;
    snapshot.status.last_heartbeat = Utc::now();
    let status = snapshot.status.clone();
    drop(snapshot);
    let _ = state.sender.send(UiEvent::Status(status));
}
