// Anomaly detection for suspicious network activity
// Detects hidden listeners, p2p connections, ARP spoofing, scanning, lateral movement

use crate::{FlowDirection, FlowEvent};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::protocol_detector::{LocalProtocol, ProtocolDetector};

pub struct AnomalyDetector {
    state: Arc<Mutex<DetectorState>>,
}

struct DetectorState {
    // Track listening ports per process
    known_listeners: HashMap<i32, HashSet<u16>>,

    // Track DNS query patterns
    dns_queries: HashMap<String, DnsPattern>,

    // Track connection patterns
    connection_tracker: HashMap<String, ConnectionPattern>,

    // Track ARP/ND activity
    arp_cache: HashMap<String, ArpEntry>,

    // Last scan detection time
    last_scan_check: Instant,
}

#[derive(Clone)]
struct DnsPattern {
    query_count: u32,
    failed_count: u32,
    unique_domains: HashSet<String>,
    last_seen: Instant,
}

#[derive(Clone)]
struct ConnectionPattern {
    count: u32,
    unique_ports: HashSet<u16>,
    first_seen: Instant,
    last_seen: Instant,
}

#[derive(Clone)]
struct ArpEntry {
    mac: String,
    ip: String,
    last_seen: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    HiddenListener {
        pid: i32,
        port: u16,
        process_name: Option<String>,
    },
    UnexpectedP2P {
        src_ip: String,
        dst_ip: String,
        dst_port: u16,
    },
    ArpSpoofing {
        ip: String,
        old_mac: String,
        new_mac: String,
    },
    PortScanning {
        src_ip: String,
        target_ip: String,
        port_count: usize,
    },
    LateralMovement {
        src_ip: String,
        dst_ip: String,
        protocol: String,
    },
    SuspiciousDns {
        domain: String,
        reason: String,
    },
    LocalProxy {
        pid: i32,
        port: u16,
        process_name: Option<String>,
    },
    UnexpectedMulticast {
        protocol: String,
        dst_ip: String,
    },
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(DetectorState {
                known_listeners: HashMap::new(),
                dns_queries: HashMap::new(),
                connection_tracker: HashMap::new(),
                arp_cache: HashMap::new(),
                last_scan_check: Instant::now(),
            })),
        }
    }

    /// Analyze flow for anomalies
    pub fn analyze_flow(&self, flow: &FlowEvent) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Check for hidden listeners
        if let Some(anomaly) = self.check_hidden_listener(flow) {
            anomalies.push(anomaly);
        }

        // Check for lateral movement
        if let Some(anomaly) = self.check_lateral_movement(flow) {
            anomalies.push(anomaly);
        }

        // Check for port scanning
        if let Some(anomaly) = self.check_port_scanning(flow) {
            anomalies.push(anomaly);
        }

        // Check DNS patterns
        if let Some(anomaly) = self.check_dns_anomaly(flow) {
            anomalies.push(anomaly);
        }

        // Check for local proxies/tunnels
        if let Some(anomaly) = self.check_local_proxy(flow) {
            anomalies.push(anomaly);
        }

        // Check for unexpected multicast
        if let Some(anomaly) = self.check_unexpected_multicast(flow) {
            anomalies.push(anomaly);
        }

        anomalies
    }

    /// Detect hidden listening services
    fn check_hidden_listener(&self, flow: &FlowEvent) -> Option<Anomaly> {
        if flow.direction != FlowDirection::Inbound {
            return None;
        }

        if let Some(state_str) = &flow.state {
            if state_str == "LISTEN" {
                if let Some(process) = &flow.process {
                    let pid = process.pid;
                    let port = flow.src_port;

                    let mut state = self.state.lock().unwrap();

                    // Check if this is a new listener
                    let listeners = state.known_listeners.entry(pid).or_insert_with(HashSet::new);

                    if !listeners.contains(&port) {
                        // New listener detected
                        listeners.insert(port);

                        // Check if it's suspicious (non-system process, unusual port)
                        if Self::is_suspicious_listener(process, port) {
                            return Some(Anomaly::HiddenListener {
                                pid,
                                port,
                                process_name: process.name.clone(),
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Check for lateral movement patterns
    fn check_lateral_movement(&self, flow: &FlowEvent) -> Option<Anomaly> {
        if flow.direction != FlowDirection::Lateral {
            return None;
        }

        // Check for suspicious lateral protocols
        if let Some(proto) = ProtocolDetector::detect_protocol(flow) {
            match proto {
                LocalProtocol::SMB | LocalProtocol::RDP | LocalProtocol::LDAP => {
                    // These are common lateral movement vectors
                    return Some(Anomaly::LateralMovement {
                        src_ip: flow.src_ip.clone(),
                        dst_ip: flow.dst_ip.clone(),
                        protocol: proto.as_str().to_string(),
                    });
                }
                _ => {}
            }
        }

        None
    }

    /// Detect port scanning
    fn check_port_scanning(&self, flow: &FlowEvent) -> Option<Anomaly> {
        let mut state = self.state.lock().unwrap();

        let key = format!("{}:{}", flow.src_ip, flow.dst_ip);
        let pattern = state
            .connection_tracker
            .entry(key.clone())
            .or_insert_with(|| ConnectionPattern {
                count: 0,
                unique_ports: HashSet::new(),
                first_seen: Instant::now(),
                last_seen: Instant::now(),
            });

        pattern.count += 1;
        pattern.unique_ports.insert(flow.dst_port);
        pattern.last_seen = Instant::now();

        // Detect scanning: many unique ports in short time
        let duration = pattern.last_seen.duration_since(pattern.first_seen);
        if pattern.unique_ports.len() > 10 && duration < Duration::from_secs(60) {
            return Some(Anomaly::PortScanning {
                src_ip: flow.src_ip.clone(),
                target_ip: flow.dst_ip.clone(),
                port_count: pattern.unique_ports.len(),
            });
        }

        None
    }

    /// Check DNS query patterns for anomalies
    fn check_dns_anomaly(&self, flow: &FlowEvent) -> Option<Anomaly> {
        if !ProtocolDetector::is_dns_flow(flow) {
            return None;
        }

        if let Some(qname) = &flow.dns_qname {
            let mut state = self.state.lock().unwrap();

            let pattern = state
                .dns_queries
                .entry(qname.clone())
                .or_insert_with(|| DnsPattern {
                    query_count: 0,
                    failed_count: 0,
                    unique_domains: HashSet::new(),
                    last_seen: Instant::now(),
                });

            pattern.query_count += 1;
            pattern.last_seen = Instant::now();

            if let Some(rcode) = &flow.dns_rcode {
                if rcode != "NOERROR" {
                    pattern.failed_count += 1;
                }
            }

            // Detect suspicious patterns
            // High failure rate
            if pattern.query_count > 10 && pattern.failed_count as f32 / pattern.query_count as f32 > 0.8 {
                return Some(Anomaly::SuspiciousDns {
                    domain: qname.clone(),
                    reason: "High failure rate (potential DGA/C2)".to_string(),
                });
            }

            // Randomized domain names (basic heuristic)
            if Self::is_dga_domain(qname) {
                return Some(Anomaly::SuspiciousDns {
                    domain: qname.clone(),
                    reason: "Potential DGA-generated domain".to_string(),
                });
            }
        }

        None
    }

    /// Check for local proxy/tunnel services
    fn check_local_proxy(&self, flow: &FlowEvent) -> Option<Anomaly> {
        if flow.direction != FlowDirection::Inbound {
            return None;
        }

        // Common proxy ports
        let proxy_ports = [8080, 8888, 3128, 1080, 9050, 9150];

        if let Some(state_str) = &flow.state {
            if state_str == "LISTEN" && proxy_ports.contains(&flow.src_port) {
                if let Some(process) = &flow.process {
                    // Check if it's a known proxy application
                    if !Self::is_known_proxy_app(&process.name) {
                        return Some(Anomaly::LocalProxy {
                            pid: process.pid,
                            port: flow.src_port,
                            process_name: process.name.clone(),
                        });
                    }
                }
            }
        }

        None
    }

    /// Check for unexpected multicast/broadcast traffic
    fn check_unexpected_multicast(&self, flow: &FlowEvent) -> Option<Anomaly> {
        if let Some(proto) = ProtocolDetector::detect_protocol(flow) {
            // Check if local discovery is allowed
            if matches!(
                proto,
                LocalProtocol::MDNS | LocalProtocol::LLMNR | LocalProtocol::SSDP
            ) {
                // Could be flagged if local discovery is disabled in policy
                // For now, just log it
                debug!("Local discovery protocol detected: {:?}", proto);
            }
        }

        None
    }

    /// Check if listener is suspicious
    fn is_suspicious_listener(process: &crate::ProcessIdentity, port: u16) -> bool {
        // System ports (<1024) from non-privileged processes are suspicious
        if port < 1024 {
            if let Some(path) = &process.exe_path {
                // Not in system directories
                if !path.starts_with("C:\\Windows\\") && !path.starts_with("C:\\Program Files\\") {
                    return true;
                }
            }
        }

        // Unsigned binaries listening on network are suspicious
        if let Some(signed) = process.signed {
            if !signed && port < 49152 {
                return true;
            }
        }

        false
    }

    /// Basic DGA domain detection heuristic
    fn is_dga_domain(domain: &str) -> bool {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.is_empty() {
            return false;
        }

        let name = parts[0];

        // Check for high entropy / randomness
        if name.len() > 15 {
            let vowels = name.chars().filter(|c| "aeiou".contains(*c)).count();
            let consonants = name.len() - vowels;

            // Very few vowels suggests random generation
            if vowels < name.len() / 5 {
                return true;
            }

            // Check for digit/letter mix
            let digits = name.chars().filter(|c| c.is_ascii_digit()).count();
            if digits > name.len() / 3 {
                return true;
            }
        }

        false
    }

    /// Check if process is known proxy application
    fn is_known_proxy_app(name: &Option<String>) -> bool {
        if let Some(name) = name {
            let name_lower = name.to_lowercase();
            [
                "chrome", "firefox", "edge", "proxy", "squid", "nginx", "privoxy",
            ]
            .iter()
            .any(|&app| name_lower.contains(app))
        } else {
            false
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}
