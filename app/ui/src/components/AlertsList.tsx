import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Alert } from '../types/ui';

interface AlertsListProps {
  alerts: Alert[];
  onExport: (alert: Alert) => void;
}

export function AlertsList({ alerts, onExport }: AlertsListProps) {
  const { t } = useTranslation();
  const [selected, setSelected] = useState<Alert | null>(null);

  if (!alerts.length) {
    return <p>{t('alerts.empty')}</p>;
  }

  return (
    <div className="alerts-list" aria-live="polite">
      {alerts.map((alert) => (
        <article key={alert.id} className={`alert-card ${alert.severity.toLowerCase()}`}>
          <header>
            <h3>{alert.summary}</h3>
            <span>{new Date(alert.ts).toLocaleString()}</span>
          </header>
          <p>{t('alerts.rationale')}: {alert.rationale}</p>
          {alert.suggested_action && <p>{t('alerts.suggestion')}: {alert.suggested_action}</p>}
          <footer>
            <button onClick={() => setSelected(alert)}>{t('alerts.details')}</button>
            <button onClick={() => onExport(alert)}>{t('alerts.export')}</button>
          </footer>
        </article>
      ))}
      {selected && (
        <div role="dialog" aria-modal="true" className="modal">
          <div className="modal-content">
            <h2>{t('alerts.modal.title')}</h2>
            <p>{selected.summary}</p>
            <p>{t('alerts.rationale')}: {selected.rationale}</p>
            {selected.suggested_action && <p>{t('alerts.suggestion')}: {selected.suggested_action}</p>}
            <div className="modal-actions">
              <button onClick={() => alert(t('alerts.modal.quarantine'))}>{t('alerts.modal.quarantine')}</button>
              <button onClick={() => setSelected(null)}>{t('alerts.modal.cancel')}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
