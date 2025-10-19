use std::{collections::HashMap, fs::File, io::Write, time::Duration};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::{async_runtime::spawn, AppHandle, Emitter, State, WebviewWindow};
use tokio::sync::RwLockWriteGuard;
use tokio::time::interval;

use crate::{
    resources,
    state::{DaemonStatus, Mode, UiEvent, UiSettings, UiSnapshot, UiState},
};
use std::sync::Arc;
use chrono::Duration as ChronoDuration;

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
pub async fn quarantine_flow(
    _state: State<'_, UiState>,
    pid: Option<i32>,
    exe_path: Option<String>,
    ports: Vec<u16>,
    duration_seconds: u64,
) -> Result<(), String> {
    // Placeholder: integrate with policy backend and WFP on Windows in future iterations.
    tracing::info!(?pid, ?exe_path, ?ports, duration_seconds, "quarantine request received");
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
    // Start real collector backend once per app lifetime; fallback to mock if unavailable.
    {
        let mut guard = state.collector.lock();
        if guard.is_none() {
            let backend: Arc<dyn collector::CollectorBackend> = match collector::default_backend() {
                Ok(backend) => backend,
                Err(_err) => Arc::new(collector::MockCollector::default()),
            };
            let ui_sender = state.sender.clone();
            backend.subscribe(Arc::new(move |flow: collector::FlowEvent| {
                let _ = ui_sender.send(UiEvent::Flow(flow));
            }));
            // Fire-and-forget start
            tauri::async_runtime::spawn({
                let backend = backend.clone();
                async move {
                    let _ = backend.start().await;
                }
            });
            *guard = Some(backend);
        }
    }
    spawn(async move {
        let mut rx = state.subscribe();
        while let Ok(event) = rx.recv().await {
            if window.emit("ui-event", &event).is_err() {
                break;
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

pub fn spawn_analyzer_pipeline(state: UiState) {
    spawn(async move {
        // Load DSL rules bundled at compile time
        let rules_yaml: &str = include_str!("../../../../rules/default.rules");
        let mut analyzer = analyzer::Analyzer::new(
            ChronoDuration::hours(1),
            analyzer::dsl::load_rules_from_str(rules_yaml).unwrap_or_default(),
        );
        let normalizer = normalizer::Normalizer::new(ChronoDuration::seconds(60));

        let mut rx = state.subscribe();
        while let Ok(event) = rx.recv().await {
            if let UiEvent::Flow(flow) = event {
                if let Ok(norm) = normalizer.normalize(flow.clone()) {
                    for alert in analyzer.ingest(norm) {
                        let _ = state.sender.send(UiEvent::Alert(alert));
                    }
                }
            }
        }
    });
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
