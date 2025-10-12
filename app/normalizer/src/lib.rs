use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use collector::{FlowDirection, FlowEvent};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedFlow {
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub proto: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub direction: FlowDirection,
    pub bytes: u64,
    pub packets: u64,
    pub process: Option<String>,
}

pub struct Normalizer {
    window: Duration,
}

impl Normalizer {
    pub fn new(window: Duration) -> Self {
        Self { window }
    }

    pub fn normalize(&self, event: FlowEvent) -> Result<NormalizedFlow> {
        debug!(?event, "normalizing flow event");
        let window_start =
            event.ts_first - Duration::nanoseconds(event.ts_first.timestamp_subsec_nanos() as i64);
        let normalized = NormalizedFlow {
            window_start,
            window_end: event.ts_first + self.window,
            proto: event.proto,
            src_ip: event.src_ip,
            src_port: event.src_port,
            dst_ip: event.dst_ip,
            dst_port: event.dst_port,
            direction: event.direction,
            bytes: event.bytes,
            packets: event.packets,
            process: event.process.and_then(|p| p.name),
        };
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn normalize_basic() {
        let normalizer = Normalizer::new(Duration::seconds(60));
        let event = FlowEvent {
            ts_first: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            ts_last: Utc.timestamp_opt(1_700_000_005, 0).unwrap(),
            proto: "TCP".into(),
            src_ip: "10.0.0.1".into(),
            src_port: 12345,
            dst_ip: "10.0.0.2".into(),
            dst_port: 443,
            iface: Some("eth0".into()),
            direction: FlowDirection::Outbound,
            state: Some("ESTABLISHED".into()),
            bytes: 1024,
            packets: 10,
            process: None,
            layer2: None,
            risk: None,
            sni: None,
            alpn: None,
            ja3: None,
            dns_qname: None,
            dns_qtype: None,
            dns_rcode: None,
        };
        let normalized = normalizer.normalize(event).unwrap();
        assert_eq!(normalized.bytes, 1024);
        assert_eq!(normalized.dst_port, 443);
    }
}
