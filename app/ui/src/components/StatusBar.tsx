import { useTranslation } from 'react-i18next';
import type { DaemonStatus } from '../types/ui';

interface StatusBarProps {
  status: DaemonStatus;
  queuedCount: number;
  theme: 'light' | 'dark';
  isPaused: boolean;
}

export function StatusBar({ status, queuedCount, theme, isPaused }: StatusBarProps) {
  const { t } = useTranslation();
  const captureTime = new Date(status.last_heartbeat).toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });

  return (
    <footer className="status-bar" data-theme={theme}>
      <div>
        <span>{t('statusBar.capturedAt', { time: captureTime })}</span>
        {isPaused && (
          <span className="muted">{t('statusBar.paused')}</span>
        )}
      </div>
      <div className="status-bar-right">
        <span>{t('statusBar.sample', { ratio: status.sample_ratio })}</span>
        <span>{t('statusBar.dropRate', { value: status.drop_rate.toFixed(2) })}</span>
        {queuedCount > 0 && (
          <span className="muted">{t('statusBar.queue', { count: queuedCount })}</span>
        )}
        <span>© 2025 Offline Nets</span>
      </div>
    </footer>
  );
}
