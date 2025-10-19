// Windows network monitoring using IP Helper API and extended TCP/UDP tables
// Provides L2-L4 network flow tracking with process binding

#[cfg(windows)]
use std::mem;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use chrono::Utc;
#[cfg(windows)]
use tracing::{debug, warn};
#[cfg(windows)]
use windows::Win32::{
    Foundation::NO_ERROR,
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

use crate::{FlowDirection, FlowEvent};

use super::process_info::ProcessInfoCollector;

#[cfg(windows)]
pub struct NetworkMonitor;

#[cfg(windows)]
impl NetworkMonitor {
    /// Collect all TCP connections with process binding
    pub fn collect_tcp_connections() -> Result<Vec<FlowEvent>> {
        let mut events = Vec::new();

        // IPv4 TCP connections
        match Self::get_tcp_table_v4() {
            Ok(table) => {
                for row in table {
                    if let Some(event) = Self::tcp_row_to_event(row) {
                        events.push(event);
                    }
                }
            }
            Err(e) => warn!("failed to get IPv4 TCP table: {}", e),
        }

        // IPv6 TCP connections
        match Self::get_tcp_table_v6() {
            Ok(table) => {
                for row in table {
                    if let Some(event) = Self::tcp6_row_to_event(row) {
                        events.push(event);
                    }
                }
            }
            Err(e) => warn!("failed to get IPv6 TCP table: {}", e),
        }

        Ok(events)
    }

    /// Collect all UDP endpoints with process binding
    pub fn collect_udp_endpoints() -> Result<Vec<FlowEvent>> {
        let mut events = Vec::new();

        // IPv4 UDP endpoints
        match Self::get_udp_table_v4() {
            Ok(table) => {
                for row in table {
                    if let Some(event) = Self::udp_row_to_event(row) {
                        events.push(event);
                    }
                }
            }
            Err(e) => warn!("failed to get IPv4 UDP table: {}", e),
        }

        // IPv6 UDP endpoints
        match Self::get_udp_table_v6() {
            Ok(table) => {
                for row in table {
                    if let Some(event) = Self::udp6_row_to_event(row) {
                        events.push(event);
                    }
                }
            }
            Err(e) => warn!("failed to get IPv6 UDP table: {}", e),
        }

        Ok(events)
    }

    /// Get IPv4 TCP table with owner PID
    #[cfg(windows)]
    fn get_tcp_table_v4() -> Result<Vec<MIB_TCPROW_OWNER_PID>> {
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result != NO_ERROR.0 {
                anyhow::bail!("GetExtendedTcpTable failed: {}", result);
            }

            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );

            Ok(rows.to_vec())
        }
    }

    /// Get IPv6 TCP table with owner PID
    #[cfg(windows)]
    fn get_tcp_table_v6() -> Result<Vec<MIB_TCP6ROW_OWNER_PID>> {
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result != NO_ERROR.0 {
                anyhow::bail!("GetExtendedTcpTable (v6) failed: {}", result);
            }

            let table = &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );

            Ok(rows.to_vec())
        }
    }

    /// Get IPv4 UDP table with owner PID
    #[cfg(windows)]
    fn get_udp_table_v4() -> Result<Vec<MIB_UDPROW_OWNER_PID>> {
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != NO_ERROR.0 {
                anyhow::bail!("GetExtendedUdpTable failed: {}", result);
            }

            let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );

            Ok(rows.to_vec())
        }
    }

    /// Get IPv6 UDP table with owner PID
    #[cfg(windows)]
    fn get_udp_table_v6() -> Result<Vec<MIB_UDP6ROW_OWNER_PID>> {
        unsafe {
            let mut size = 0u32;
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != NO_ERROR.0 {
                anyhow::bail!("GetExtendedUdpTable (v6) failed: {}", result);
            }

            let table = &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(),
                table.dwNumEntries as usize,
            );

            Ok(rows.to_vec())
        }
    }

    /// Convert IPv4 TCP row to FlowEvent
    #[cfg(windows)]
    fn tcp_row_to_event(row: MIB_TCPROW_OWNER_PID) -> Option<FlowEvent> {
        let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let local_port = ((row.dwLocalPort >> 8) | (row.dwLocalPort << 8)) as u16;
        let remote_addr = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
        let remote_port = ((row.dwRemotePort >> 8) | (row.dwRemotePort << 8)) as u16;

        let state = Self::tcp_state_to_string(row.dwState);
        let direction = Self::infer_direction(&local_addr.to_string(), &remote_addr.to_string());
        let process = ProcessInfoCollector::get_process_info(row.dwOwningPid as i32);

        let now = Utc::now();
        Some(FlowEvent {
            ts_first: now,
            ts_last: now,
            proto: "TCP".into(),
            src_ip: local_addr.to_string(),
            src_port: local_port,
            dst_ip: remote_addr.to_string(),
            dst_port: remote_port,
            direction,
            state: Some(state),
            process,
            ..FlowEvent::default()
        })
    }

    /// Convert IPv6 TCP row to FlowEvent
    #[cfg(windows)]
    fn tcp6_row_to_event(row: MIB_TCP6ROW_OWNER_PID) -> Option<FlowEvent> {
        let local_addr = Ipv6Addr::from(row.ucLocalAddr);
        let local_port = ((row.dwLocalPort >> 8) | (row.dwLocalPort << 8)) as u16;
        let remote_addr = Ipv6Addr::from(row.ucRemoteAddr);
        let remote_port = ((row.dwRemotePort >> 8) | (row.dwRemotePort << 8)) as u16;

        let state = Self::tcp_state_to_string(row.dwState);
        let direction = Self::infer_direction(&local_addr.to_string(), &remote_addr.to_string());
        let process = ProcessInfoCollector::get_process_info(row.dwOwningPid as i32);

        let now = Utc::now();
        Some(FlowEvent {
            ts_first: now,
            ts_last: now,
            proto: "TCP".into(),
            src_ip: local_addr.to_string(),
            src_port: local_port,
            dst_ip: remote_addr.to_string(),
            dst_port: remote_port,
            direction,
            state: Some(state),
            process,
            ..FlowEvent::default()
        })
    }

    /// Convert IPv4 UDP row to FlowEvent
    #[cfg(windows)]
    fn udp_row_to_event(row: MIB_UDPROW_OWNER_PID) -> Option<FlowEvent> {
        let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let local_port = ((row.dwLocalPort >> 8) | (row.dwLocalPort << 8)) as u16;

        let process = ProcessInfoCollector::get_process_info(row.dwOwningPid as i32);

        let now = Utc::now();
        Some(FlowEvent {
            ts_first: now,
            ts_last: now,
            proto: "UDP".into(),
            src_ip: local_addr.to_string(),
            src_port: local_port,
            dst_ip: "0.0.0.0".into(),
            dst_port: 0,
            direction: FlowDirection::Inbound,
            state: Some("LISTEN".into()),
            process,
            ..FlowEvent::default()
        })
    }

    /// Convert IPv6 UDP row to FlowEvent
    #[cfg(windows)]
    fn udp6_row_to_event(row: MIB_UDP6ROW_OWNER_PID) -> Option<FlowEvent> {
        let local_addr = Ipv6Addr::from(row.ucLocalAddr);
        let local_port = ((row.dwLocalPort >> 8) | (row.dwLocalPort << 8)) as u16;

        let process = ProcessInfoCollector::get_process_info(row.dwOwningPid as i32);

        let now = Utc::now();
        Some(FlowEvent {
            ts_first: now,
            ts_last: now,
            proto: "UDP".into(),
            src_ip: local_addr.to_string(),
            src_port: local_port,
            dst_ip: "::".into(),
            dst_port: 0,
            direction: FlowDirection::Inbound,
            state: Some("LISTEN".into()),
            process,
            ..FlowEvent::default()
        })
    }

    /// Convert TCP state code to string
    #[cfg(windows)]
    fn tcp_state_to_string(state: u32) -> String {
        match state {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    /// Infer flow direction based on IP addresses
    fn infer_direction(local_ip: &str, remote_ip: &str) -> FlowDirection {
        if remote_ip == "0.0.0.0" || remote_ip == "::" {
            return FlowDirection::Inbound;
        }

        // Check if local network (RFC1918, link-local)
        if Self::is_private_ip(remote_ip) {
            return FlowDirection::Lateral;
        }

        FlowDirection::Outbound
    }

    /// Check if IP is in private range
    fn is_private_ip(ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            match addr {
                IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    // RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    // Link-local: 169.254.0.0/16
                    octets[0] == 10
                        || (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31))
                        || (octets[0] == 192 && octets[1] == 168)
                        || (octets[0] == 169 && octets[1] == 254)
                }
                IpAddr::V6(v6) => {
                    // Link-local: fe80::/10
                    // ULA: fc00::/7
                    let segments = v6.segments();
                    (segments[0] & 0xffc0) == 0xfe80 || (segments[0] & 0xfe00) == 0xfc00
                }
            }
        } else {
            false
        }
    }
}

#[cfg(not(windows))]
pub struct NetworkMonitor;

#[cfg(not(windows))]
impl NetworkMonitor {
    pub fn collect_tcp_connections() -> anyhow::Result<Vec<crate::FlowEvent>> {
        Ok(Vec::new())
    }

    pub fn collect_udp_endpoints() -> anyhow::Result<Vec<crate::FlowEvent>> {
        Ok(Vec::new())
    }
}
