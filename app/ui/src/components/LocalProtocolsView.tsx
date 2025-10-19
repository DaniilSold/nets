import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { FlowEvent } from '../types/ui';

interface LocalProtocolsViewProps {
  flows: FlowEvent[];
}

interface LocalProtocolStats {
  protocol: string;
  count: number;
  lastSeen: string;
  processes: Set<number>;
}

export function LocalProtocolsView({ flows }: LocalProtocolsViewProps) {
  const { t } = useTranslation();

  const localProtocols = useMemo(() => {
    const stats = new Map<string, LocalProtocolStats>();

    // Well-known local protocol ports
    const protocolPorts = new Map([
      [5353, 'mDNS'],
      [5355, 'LLMNR'],
      [137, 'NetBIOS-NS'],
      [138, 'NetBIOS-DGM'],
      [139, 'NetBIOS-SSN'],
      [445, 'SMB'],
      [1900, 'SSDP'],
      [67, 'DHCP-Server'],
      [68, 'DHCP-Client'],
      [3389, 'RDP'],
      [88, 'Kerberos'],
      [389, 'LDAP'],
      [636, 'LDAPS'],
    ]);

    // Multicast addresses
    const multicastAddresses = new Set([
      '224.0.0.251', // mDNS IPv4
      'ff02::fb',    // mDNS IPv6
      '224.0.0.252', // LLMNR IPv4
      'ff02::1:3',   // LLMNR IPv6
      '239.255.255.250', // SSDP IPv4
      'ff02::c',     // SSDP IPv6
    ]);

    flows.forEach((flow) => {
      let protocol: string | undefined;

      // Check by port
      protocol = protocolPorts.get(flow.dst_port) || protocolPorts.get(flow.src_port);

      // Check by multicast address
      if (!protocol && multicastAddresses.has(flow.dst_ip)) {
        if (flow.dst_port === 5353) protocol = 'mDNS';
        else if (flow.dst_port === 5355) protocol = 'LLMNR';
        else if (flow.dst_port === 1900) protocol = 'SSDP';
      }

      // Check DNS queries
      if (flow.dns_qname && (flow.dst_port === 53 || flow.dst_port === 5353 || flow.dst_port === 5355)) {
        if (!protocol) protocol = 'DNS';
      }

      if (protocol) {
        const existing = stats.get(protocol);
        if (existing) {
          existing.count++;
          if (flow.ts_last > existing.lastSeen) {
            existing.lastSeen = flow.ts_last;
          }
          if (flow.process) {
            existing.processes.add(flow.process.pid);
          }
        } else {
          stats.set(protocol, {
            protocol,
            count: 1,
            lastSeen: flow.ts_last,
            processes: flow.process ? new Set([flow.process.pid]) : new Set(),
          });
        }
      }
    });

    return Array.from(stats.values()).sort((a, b) => b.count - a.count);
  }, [flows]);

  if (localProtocols.length === 0) {
    return <p>{t('localProtocols.empty')}</p>;
  }

  return (
    <div className="local-protocols-container">
      <h2>{t('localProtocols.title')}</h2>
      <p className="description">{t('localProtocols.description')}</p>

      <div className="protocols-grid">
        {localProtocols.map((stat) => (
          <div key={stat.protocol} className="protocol-card">
            <div className="card-header">
              <h3>{stat.protocol}</h3>
              <span className="badge">{stat.count}</span>
            </div>
            <div className="card-body">
              <div className="stat-row">
                <span className="label">{t('localProtocols.occurrences')}</span>
                <span className="value">{stat.count.toLocaleString()}</span>
              </div>
              <div className="stat-row">
                <span className="label">{t('localProtocols.processes')}</span>
                <span className="value">{stat.processes.size}</span>
              </div>
              <div className="stat-row">
                <span className="label">{t('localProtocols.lastSeen')}</span>
                <span className="value">{new Date(stat.lastSeen).toLocaleTimeString()}</span>
              </div>
            </div>
            <div className="card-footer">
              <span className="description-text">{getProtocolDescription(stat.protocol, t)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function getProtocolDescription(protocol: string, t: any): string {
  const descriptions: Record<string, string> = {
    'mDNS': t('localProtocols.descriptions.mdns'),
    'LLMNR': t('localProtocols.descriptions.llmnr'),
    'NetBIOS-NS': t('localProtocols.descriptions.nbns'),
    'NetBIOS-DGM': t('localProtocols.descriptions.nbdgm'),
    'NetBIOS-SSN': t('localProtocols.descriptions.nbssn'),
    'SMB': t('localProtocols.descriptions.smb'),
    'SSDP': t('localProtocols.descriptions.ssdp'),
    'DHCP-Server': t('localProtocols.descriptions.dhcp'),
    'DHCP-Client': t('localProtocols.descriptions.dhcp'),
    'RDP': t('localProtocols.descriptions.rdp'),
    'Kerberos': t('localProtocols.descriptions.kerberos'),
    'LDAP': t('localProtocols.descriptions.ldap'),
    'LDAPS': t('localProtocols.descriptions.ldaps'),
    'DNS': t('localProtocols.descriptions.dns'),
  };

  return descriptions[protocol] || t('localProtocols.descriptions.unknown');
}
