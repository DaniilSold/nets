use std::{borrow::Cow, fs, path::PathBuf};

use anyhow::Context;
use base64::{engine::general_purpose, Engine};
use serde::de::DeserializeOwned;

pub fn resource_path(name: &str) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("resources");
    base.join(name)
}

fn embedded_resource(name: &str) -> Option<Cow<'static, str>> {
    match name {
        "mock_flows.json" => Some(Cow::Borrowed(include_str!("mock_flows.json"))),
        "mock_alerts.json" => Some(Cow::Borrowed(include_str!("mock_alerts.json"))),
        "mock_dns.json" => Some(Cow::Borrowed(include_str!("mock_dns.json"))),
        "mock_services.json" => Some(Cow::Borrowed(include_str!("mock_services.json"))),
        "mock_processes.json" => Some(Cow::Borrowed(include_str!("mock_processes.json"))),
        "mock_graph.json" => Some(Cow::Borrowed(include_str!("mock_graph.json"))),
        "mock_status.json" => Some(Cow::Borrowed(include_str!("mock_status.json"))),
        "mock_settings.json" => Some(Cow::Borrowed(include_str!("mock_settings.json"))),
        _ => None,
    }
}

pub fn load_json<T: DeserializeOwned>(name: &str) -> anyhow::Result<T> {
    let path = resource_path(name);
    let data = match fs::read_to_string(&path) {
        Ok(contents) => Cow::Owned(contents),
        Err(_) => embedded_resource(name)
            .ok_or_else(|| anyhow::anyhow!("missing embedded resource {name}"))?,
    };
    let value =
        serde_json::from_str(&data).with_context(|| format!("failed to parse resource {name}"))?;
    Ok(value)
}

pub fn save_json<T: serde::Serialize>(path: &PathBuf, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(value)?;
    fs::write(path, data)?;
    Ok(())
}

#[allow(dead_code)]
pub fn copy_resource(name: &str, destination: &PathBuf) -> anyhow::Result<()> {
    let src = resource_path(name);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, destination)?;
    Ok(())
}

pub fn write_sample_pcap(destination: &PathBuf) -> anyhow::Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let encoded = include_str!("sample.pcap.b64");
    let data = general_purpose::STANDARD
        .decode(encoded.trim())
        .context("failed to decode embedded sample PCAP")?;
    fs::write(destination, data).context("failed to write sample PCAP")?;
    Ok(())
}
