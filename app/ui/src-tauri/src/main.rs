#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod resources;
mod state;

use std::time::Duration;

use commands::{
    apply_preset, bootstrap_mock_stream, bootstrap_snapshot, export_pcap, export_report,
    list_presets, load_snapshot, set_locale, start_event_stream, toggle_capture_command,
    toggle_mode_command, update_settings,
};
use state::UiState;
use tauri::{async_runtime::spawn, Manager};
use tokio::time::interval;
use tracing::info;

fn main() {
    tracing_subscriber::fmt().with_target(false).init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            load_snapshot,
            update_settings,
            set_locale,
            export_report,
            export_pcap,
            apply_preset,
            list_presets,
            start_event_stream,
            toggle_mode_command,
            toggle_capture_command,
        ])
        .setup(|app| {
            let snapshot = bootstrap_snapshot()?;
            let state = UiState::new(snapshot, "en".into())?;
            let locale_from_disk = commands::load_locale_from_disk(&state).unwrap_or(None);
            if let Some(locale) = locale_from_disk {
                *state.locale.blocking_write() = locale;
            }
            let state_handle = app.manage(state);

            // Kick-off event stream
            let handle = app.handle();
            bootstrap_mock_stream(handle.clone(), state_handle.state::<UiState>());

            // Periodic daemon status simulation
            let status_state = state_handle.state::<UiState>().clone();
            spawn(async move {
                let mut ticker = interval(Duration::from_secs(30));
                loop {
                    ticker.tick().await;
                    let status = {
                        let mut snapshot = status_state.snapshot.write().await;
                        snapshot.status.cpu_load = (snapshot.status.cpu_load * 0.7) + 1.3;
                        snapshot.status.memory_mb = (snapshot.status.memory_mb * 0.9) + 3.0;
                        snapshot.status.last_heartbeat = chrono::Utc::now();
                        if snapshot.status.cpu_load > 20.0 {
                            snapshot.status.cpu_load = 4.0;
                        }
                        snapshot.status.clone()
                    };
                    let _ = status_state.sender.send(state::UiEvent::Status(status));
                }
            });

            info!("ui ready");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("failed to run tauri application");
}
