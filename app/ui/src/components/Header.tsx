import { useTranslation } from 'react-i18next';
import type { DaemonStatus } from '../types/ui';

interface HeaderProps {
  status: DaemonStatus;
  locale: string;
  brandLine: string;
  animatedLine: string;
  onChangeLocale: (locale: string) => void;
  onToggleMode: () => void;
  onToggleCapture: () => void;
  onOpenSettings: () => void;
  onShowAbout: () => void;
}

const locales: Array<{ code: 'en' | 'ru'; label: string }> = [
  { code: 'en', label: 'EN' },
  { code: 'ru', label: 'RU' }
];

export function Header({
  status,
  locale,
  brandLine,
  animatedLine,
  onChangeLocale,
  onToggleMode,
  onToggleCapture,
  onOpenSettings,
  onShowAbout
}: HeaderProps) {
  const { t } = useTranslation();
  const cpuPercentage = Math.min(Math.max(status.cpu_load, 0), 100);
  const memoryPercentage = Math.min(Math.max((status.memory_mb / 40) * 100, 0), 100);
  const modeIsGuardian = status.mode === 'Guardian';

  return (
    <header className="header">
      <button className="branding" onClick={onShowAbout} aria-label={t('header.brandAria')}>
        <div>
          <h1>{brandLine}</h1>
          <span className="brand-subline" aria-live="polite">
            {animatedLine}
          </span>
        </div>
      </button>
      <div className="header-groups">
        <section className="header-group" aria-label={t('header.group.status')}>
          <span
            className={`status-indicator ${status.connected ? 'online' : 'offline'}`}
            aria-hidden
          />
          <span>{status.connected ? t('header.status.connected') : t('header.status.disconnected')}</span>
          <button
            className="chip-button"
            role="switch"
            aria-checked={status.capture_enabled}
            onClick={onToggleCapture}
          >
            {status.capture_enabled ? t('header.capture.on') : t('header.capture.off')}
          </button>
          <span className="muted" title={t('header.status.flowsPerSecondHelp')}>
            {t('header.status.flowsPerSecond', { count: status.flows_per_second.toFixed(0) })}
          </span>
        </section>
        <section className="header-group" aria-label={t('header.group.resources')}>
          <label className="meter" title={t('header.status.cpuDetail', { value: status.cpu_load.toFixed(1) })}>
            <span>{t('header.status.cpu')}</span>
            <progress max={100} value={cpuPercentage} aria-valuetext={`${status.cpu_load.toFixed(1)}%`} />
          </label>
          <label className="meter" title={t('header.status.memoryDetail', { value: status.memory_mb.toFixed(1) })}>
            <span>{t('header.status.memory')}</span>
            <progress max={100} value={memoryPercentage} aria-valuetext={`${status.memory_mb.toFixed(1)} MB`} />
          </label>
        </section>
        <section className="header-group" aria-label={t('header.group.mode')}>
          <div className="segment">
            <button
              className={`segment-item ${!modeIsGuardian ? 'active' : ''}`}
              aria-pressed={!modeIsGuardian}
              onClick={!modeIsGuardian ? undefined : onToggleMode}
            >
              {t('header.mode.observer')}
            </button>
            <button
              className={`segment-item ${modeIsGuardian ? 'active' : ''}`}
              aria-pressed={modeIsGuardian}
              onClick={modeIsGuardian ? undefined : onToggleMode}
            >
              {t('header.mode.guardian')}
            </button>
          </div>
        </section>
        <section className="header-group" aria-label={t('header.group.locale')}>
          <div className="segment locale">
            {locales.map((entry) => (
              <button
                key={entry.code}
                className={`segment-item ${locale === entry.code ? 'active' : ''}`}
                aria-pressed={locale === entry.code}
                onClick={() => onChangeLocale(entry.code)}
              >
                {entry.label}
              </button>
            ))}
          </div>
        </section>
        <section className="header-group" aria-label={t('header.group.actions')}>
          <button className="icon-button" onClick={onOpenSettings} aria-label={t('header.actions.openSettings')}>
            ⚙️
          </button>
        </section>
      </div>
    </header>
  );
}
