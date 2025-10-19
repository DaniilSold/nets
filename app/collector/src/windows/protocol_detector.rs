// Protocol detector for local service discovery and DNS monitoring
// Detects mDNS, LLMNR, NBNS, SSDP, DHCP, SMB, RDP and other local protocols

use crate::FlowEvent;
use tracing::debug;

pub struct ProtocolDetector;

impl ProtocolDetector {
    /// Well-known ports for local protocols
    pub const MDNS_PORT: u16 = 5353;
    pub const LLMNR_PORT: u16 = 5355;
    pub const NBNS_PORT: u16 = 137;
    pub const NBDGM_PORT: u16 = 138;
    pub const NBSSN_PORT: u16 = 139;
    pub const SSDP_PORT: u16 = 1900;
    pub const DHCP_CLIENT_PORT: u16 = 68;
    pub const DHCP_SERVER_PORT: u16 = 67;
    pub const DNS_PORT: u16 = 53;
    pub const SMB_PORT: u16 = 445;
    pub const RDP_PORT: u16 = 3389;
    pub const WINS_PORT: u16 = 42;
    pub const KERBEROS_PORT: u16 = 88;
    pub const LDAP_PORT: u16 = 389;
    pub const LDAPS_PORT: u16 = 636;

    /// Multicast addresses
    pub const MDNS_MULTICAST_V4: &'static str = "224.0.0.251";
    pub const MDNS_MULTICAST_V6: &'static str = "ff02::fb";
    pub const LLMNR_MULTICAST_V4: &'static str = "224.0.0.252";
    pub const LLMNR_MULTICAST_V6: &'static str = "ff02::1:3";
    pub const SSDP_MULTICAST_V4: &'static str = "239.255.255.250";
    pub const SSDP_MULTICAST_V6: &'static str = "ff02::c";

    /// Detect and classify local protocol based on flow characteristics
    pub fn detect_protocol(flow: &FlowEvent) -> Option<LocalProtocol> {
        let proto = flow.proto.as_str();
        let src_port = flow.src_port;
        let dst_port = flow.dst_port;
        let dst_ip = flow.dst_ip.as_str();

        match proto {
            "UDP" => {
                // mDNS detection
                if (src_port == Self::MDNS_PORT || dst_port == Self::MDNS_PORT)
                    && (dst_ip == Self::MDNS_MULTICAST_V4 || dst_ip == Self::MDNS_MULTICAST_V6)
                {
                    return Some(LocalProtocol::MDNS);
                }

                // LLMNR detection
                if (src_port == Self::LLMNR_PORT || dst_port == Self::LLMNR_PORT)
                    && (dst_ip == Self::LLMNR_MULTICAST_V4
                        || dst_ip == Self::LLMNR_MULTICAST_V6)
                {
                    return Some(LocalProtocol::LLMNR);
                }

                // NetBIOS Name Service
                if src_port == Self::NBNS_PORT || dst_port == Self::NBNS_PORT {
                    return Some(LocalProtocol::NBNS);
                }

                // NetBIOS Datagram Service
                if src_port == Self::NBDGM_PORT || dst_port == Self::NBDGM_PORT {
                    return Some(LocalProtocol::NBDatagam);
                }

                // SSDP (UPnP discovery)
                if (src_port == Self::SSDP_PORT || dst_port == Self::SSDP_PORT)
                    && (dst_ip == Self::SSDP_MULTICAST_V4 || dst_ip == Self::SSDP_MULTICAST_V6)
                {
                    return Some(LocalProtocol::SSDP);
                }

                // DHCP
                if (src_port == Self::DHCP_CLIENT_PORT && dst_port == Self::DHCP_SERVER_PORT)
                    || (src_port == Self::DHCP_SERVER_PORT
                        && dst_port == Self::DHCP_CLIENT_PORT)
                {
                    return Some(LocalProtocol::DHCP);
                }

                // DNS
                if src_port == Self::DNS_PORT || dst_port == Self::DNS_PORT {
                    return Some(LocalProtocol::DNS);
                }

                // Kerberos
                if src_port == Self::KERBEROS_PORT || dst_port == Self::KERBEROS_PORT {
                    return Some(LocalProtocol::Kerberos);
                }
            }
            "TCP" => {
                // SMB
                if src_port == Self::SMB_PORT || dst_port == Self::SMB_PORT {
                    return Some(LocalProtocol::SMB);
                }

                // NetBIOS Session Service
                if src_port == Self::NBSSN_PORT || dst_port == Self::NBSSN_PORT {
                    return Some(LocalProtocol::NBSession);
                }

                // RDP
                if src_port == Self::RDP_PORT || dst_port == Self::RDP_PORT {
                    return Some(LocalProtocol::RDP);
                }

                // DNS over TCP
                if src_port == Self::DNS_PORT || dst_port == Self::DNS_PORT {
                    return Some(LocalProtocol::DNS);
                }

                // LDAP
                if src_port == Self::LDAP_PORT || dst_port == Self::LDAP_PORT {
                    return Some(LocalProtocol::LDAP);
                }

                // LDAPS
                if src_port == Self::LDAPS_PORT || dst_port == Self::LDAPS_PORT {
                    return Some(LocalProtocol::LDAPS);
                }

                // Kerberos
                if src_port == Self::KERBEROS_PORT || dst_port == Self::KERBEROS_PORT {
                    return Some(LocalProtocol::Kerberos);
                }
            }
            _ => {}
        }

        None
    }

    /// Check if flow is DNS-related
    pub fn is_dns_flow(flow: &FlowEvent) -> bool {
        flow.src_port == Self::DNS_PORT
            || flow.dst_port == Self::DNS_PORT
            || flow.dst_port == Self::MDNS_PORT
            || flow.dst_port == Self::LLMNR_PORT
    }

    /// Check if flow is local service discovery
    pub fn is_local_discovery(flow: &FlowEvent) -> bool {
        matches!(
            Self::detect_protocol(flow),
            Some(
                LocalProtocol::MDNS
                    | LocalProtocol::LLMNR
                    | LocalProtocol::NBNS
                    | LocalProtocol::SSDP
            )
        )
    }

    /// Check if flow targets private network
    pub fn is_private_network(ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            match addr {
                std::net::IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    // RFC1918 + link-local + loopback
                    octets[0] == 10
                        || (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31))
                        || (octets[0] == 192 && octets[1] == 168)
                        || (octets[0] == 169 && octets[1] == 254)
                        || octets[0] == 127
                }
                std::net::IpAddr::V6(v6) => {
                    let segments = v6.segments();
                    // Link-local, ULA, loopback
                    (segments[0] & 0xffc0) == 0xfe80
                        || (segments[0] & 0xfe00) == 0xfc00
                        || v6.is_loopback()
                }
            }
        } else {
            false
        }
    }

    /// Get protocol description
    pub fn protocol_description(proto: LocalProtocol) -> &'static str {
        match proto {
            LocalProtocol::MDNS => "Multicast DNS (mDNS) - Local service discovery",
            LocalProtocol::LLMNR => "Link-Local Multicast Name Resolution - Windows name resolution",
            LocalProtocol::NBNS => "NetBIOS Name Service - Legacy Windows naming",
            LocalProtocol::NBDatagam => "NetBIOS Datagram Service",
            LocalProtocol::NBSession => "NetBIOS Session Service",
            LocalProtocol::SSDP => "Simple Service Discovery Protocol (UPnP)",
            LocalProtocol::DHCP => "Dynamic Host Configuration Protocol",
            LocalProtocol::DNS => "Domain Name System",
            LocalProtocol::SMB => "Server Message Block - File sharing",
            LocalProtocol::RDP => "Remote Desktop Protocol",
            LocalProtocol::LDAP => "Lightweight Directory Access Protocol",
            LocalProtocol::LDAPS => "LDAP over SSL/TLS",
            LocalProtocol::Kerberos => "Kerberos authentication",
            LocalProtocol::WINS => "Windows Internet Name Service",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProtocol {
    MDNS,
    LLMNR,
    NBNS,
    NBDatagam,
    NBSession,
    SSDP,
    DHCP,
    DNS,
    SMB,
    RDP,
    LDAP,
    LDAPS,
    Kerberos,
    WINS,
}

impl LocalProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            LocalProtocol::MDNS => "mDNS",
            LocalProtocol::LLMNR => "LLMNR",
            LocalProtocol::NBNS => "NBNS",
            LocalProtocol::NBDatagam => "NB-DGRAM",
            LocalProtocol::NBSession => "NB-SESSION",
            LocalProtocol::SSDP => "SSDP",
            LocalProtocol::DHCP => "DHCP",
            LocalProtocol::DNS => "DNS",
            LocalProtocol::SMB => "SMB",
            LocalProtocol::RDP => "RDP",
            LocalProtocol::LDAP => "LDAP",
            LocalProtocol::LDAPS => "LDAPS",
            LocalProtocol::Kerberos => "Kerberos",
            LocalProtocol::WINS => "WINS",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowDirection;
    use chrono::Utc;

    #[test]
    fn test_mdns_detection() {
        let flow = FlowEvent {
            ts_first: Utc::now(),
            ts_last: Utc::now(),
            proto: "UDP".into(),
            src_ip: "192.168.1.100".into(),
            src_port: 5353,
            dst_ip: "224.0.0.251".into(),
            dst_port: 5353,
            direction: FlowDirection::Outbound,
            ..FlowEvent::default()
        };

        assert_eq!(
            ProtocolDetector::detect_protocol(&flow),
            Some(LocalProtocol::MDNS)
        );
    }

    #[test]
    fn test_smb_detection() {
        let flow = FlowEvent {
            ts_first: Utc::now(),
            ts_last: Utc::now(),
            proto: "TCP".into(),
            src_ip: "192.168.1.100".into(),
            src_port: 49152,
            dst_ip: "192.168.1.10".into(),
            dst_port: 445,
            direction: FlowDirection::Lateral,
            ..FlowEvent::default()
        };

        assert_eq!(
            ProtocolDetector::detect_protocol(&flow),
            Some(LocalProtocol::SMB)
        );
    }

    #[test]
    fn test_private_network() {
        assert!(ProtocolDetector::is_private_network("192.168.1.1"));
        assert!(ProtocolDetector::is_private_network("10.0.0.1"));
        assert!(ProtocolDetector::is_private_network("172.16.0.1"));
        assert!(!ProtocolDetector::is_private_network("8.8.8.8"));
    }
}
