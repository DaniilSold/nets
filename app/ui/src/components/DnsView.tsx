import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { DnsRecord, ServiceRecord } from '../types/ui';

interface DnsViewProps {
  records: DnsRecord[];
  services: ServiceRecord[];
}

const dnsChannels = ['mDNS', 'LLMNR', 'NBNS', 'SSDP'] as const;

type DnsChannel = (typeof dnsChannels)[number];

export function DnsView({ records, services }: DnsViewProps) {
  const { t } = useTranslation();
  const [activeChannels, setActiveChannels] = useState<Set<DnsChannel>>(new Set(dnsChannels));

  const toggleChannel = (channel: DnsChannel) => {
    setActiveChannels((previous) => {
      const next = new Set(previous);
      if (next.has(channel)) {
        next.delete(channel);
      } else {
        next.add(channel);
      }
      return next;
    });
  };

  const visibleRecords = useMemo(() => {
    if (activeChannels.size === dnsChannels.length) return records;
    return records.filter((record) => {
      const channel = (record.channel ?? 'DNS') as DnsChannel;
      if (!dnsChannels.includes(channel)) return true;
      return activeChannels.has(channel);
    });
  }, [activeChannels, records]);

  const visibleServices = useMemo(() => {
    if (activeChannels.size === dnsChannels.length) return services;
    return services.filter((service) =>
      dnsChannels.includes(service.protocol as DnsChannel)
        ? activeChannels.has(service.protocol as DnsChannel)
        : true
    );
  }, [activeChannels, services]);

  if (!records.length && !services.length) {
    return <p>{t('dns.empty')}</p>;
  }

  return (
    <div className="dns-view">
      <div className="table-controls">
        {dnsChannels.map((channel) => (
          <button
            key={channel}
            className="chip-button"
            aria-pressed={activeChannels.has(channel)}
            onClick={() => toggleChannel(channel)}
          >
            {t(`dns.toggles.${channel.toLowerCase() as 'mdns' | 'llmnr' | 'nbns' | 'ssdp'}`) ?? channel}
          </button>
        ))}
      </div>
      <section>
        <h3>{t('dns.records')}</h3>
        <div className="process-table" role="table">
          <header>{t('dns.columns.qname')}</header>
          <header>{t('dns.columns.qtype')}</header>
          <header>{t('dns.columns.rcode')}</header>
          <header>{t('dns.columns.count')}</header>
          <header>{t('dns.columns.last')}</header>
          {visibleRecords.map((record) => (
            <>
              <div key={`${record.id}-qname`}>{record.qname}</div>
              <div key={`${record.id}-type`}>{record.qtype}</div>
              <div key={`${record.id}-rcode`}>{record.rcode}</div>
              <div key={`${record.id}-count`}>{record.count}</div>
              <div key={`${record.id}-last`}>{new Date(record.last_observed).toLocaleString()}</div>
            </>
          ))}
        </div>
      </section>
      <section>
        <h3>{t('dns.services')}</h3>
        <div className="process-table" role="table">
          <header>{t('dns.servicesColumns.name')}</header>
          <header>{t('dns.servicesColumns.address')}</header>
          <header>{t('dns.servicesColumns.port')}</header>
          <header>{t('dns.servicesColumns.process')}</header>
          <header>{t('dns.servicesColumns.last')}</header>
          {visibleServices.map((service) => (
            <>
              <div key={`${service.id}-name`}>{service.name}</div>
              <div key={`${service.id}-addr`}>{service.address}</div>
              <div key={`${service.id}-port`}>{service.port}</div>
              <div key={`${service.id}-proc`}>{service.process ?? '—'}</div>
              <div key={`${service.id}-last`}>{new Date(service.last_seen).toLocaleString()}</div>
            </>
          ))}
        </div>
      </section>
    </div>
  );
}
