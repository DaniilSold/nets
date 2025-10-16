import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ProcessActivity } from '../types/ui';

interface ProcessesViewProps {
  processes: ProcessActivity[];
}

export function ProcessesView({ processes }: ProcessesViewProps) {
  const { t } = useTranslation();
  const [listeningOnly, setListeningOnly] = useState(false);

  const filtered = useMemo(() => {
    if (!listeningOnly) return processes;
    return processes.filter((process) => process.listening_ports.length > 0);
  }, [listeningOnly, processes]);

  if (!filtered.length) {
    return <p>{t('processes.empty')}</p>;
  }

  return (
    <div className="processes-container">
      <div className="table-controls">
        <button
          className="chip-button"
          onClick={() => setListeningOnly((prev) => !prev)}
          aria-pressed={listeningOnly}
        >
          {t('processes.listeningOnly')}
        </button>
      </div>
      <div className="process-table" role="table">
        <header>{t('processes.columns.name')}</header>
        <header>{t('processes.columns.pid')}</header>
        <header>{t('processes.columns.user')}</header>
        <header>{t('processes.columns.signed')}</header>
        <header>{t('processes.columns.hash')}</header>
        <header>{t('processes.columns.ports')}</header>
        <header>{t('processes.columns.flows')}</header>
        <header>{t('processes.columns.last')}</header>
        {filtered.map((proc) => (
          <>
            <div key={`${proc.pid}-name`}>{proc.name}</div>
            <div key={`${proc.pid}-pid`}>{proc.pid}</div>
            <div key={`${proc.pid}-user`}>{proc.user ?? '—'}</div>
            <div key={`${proc.pid}-signed`}>{proc.signed ? t('processes.signed.yes') : t('processes.signed.no')}</div>
            <div key={`${proc.pid}-hash`}>{proc.hash ?? '—'}</div>
            <div key={`${proc.pid}-ports`}>{proc.listening_ports.join(', ') || '—'}</div>
            <div key={`${proc.pid}-flows`}>{proc.total_flows}</div>
            <div key={`${proc.pid}-last`}>{proc.last_active}</div>
          </>
        ))}
      </div>
    </div>
  );
}
