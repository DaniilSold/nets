import { FormEvent, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { UiSettings } from '../types/ui';

interface SettingsViewProps {
  settings: UiSettings;
  onSave: (settings: UiSettings) => Promise<void>;
  exportsPath: string;
}

export function SettingsView({ settings, onSave, exportsPath }: SettingsViewProps) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState(settings);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDraft(settings);
  }, [settings]);

  if (draft !== settings) {
    // placeholder to satisfy lints; real sync occurs in effect
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    await onSave(draft);
    setSaving(false);
  };

  return (
    <form onSubmit={handleSubmit} className="settings-grid">
      <div className="setting-card">
        <label htmlFor="sample-rate">{t('settings.sampleRate')}</label>
        <input
          id="sample-rate"
          type="range"
          min={1}
          max={20}
          value={draft.sample_rate}
          onChange={(event) => setDraft({ ...draft, sample_rate: Number(event.target.value) })}
        />
        <span>{draft.sample_rate}x</span>
      </div>
      <div className="setting-card">
        <label htmlFor="max-header">{t('settings.maxHeader')}</label>
        <input
          id="max-header"
          type="range"
          min={64}
          max={1024}
          step={32}
          value={draft.max_header_bytes}
          onChange={(event) => setDraft({ ...draft, max_header_bytes: Number(event.target.value) })}
        />
        <span>{draft.max_header_bytes} bytes</span>
      </div>
      <div className="setting-card">
        <label>{t('settings.lanOnly')}</label>
        <div className="toggle-row">
          <span>{draft.lan_only ? t('processes.signed.yes') : t('processes.signed.no')}</span>
          <input
            type="checkbox"
            checked={draft.lan_only}
            onChange={(event) => setDraft({ ...draft, lan_only: event.target.checked })}
          />
        </div>
      </div>
      <div className="setting-card">
        <label>{t('settings.logging')}</label>
        <div className="toggle-row">
          <span>{draft.enable_logging ? t('processes.signed.yes') : t('processes.signed.no')}</span>
          <input
            type="checkbox"
            checked={draft.enable_logging}
            onChange={(event) => setDraft({ ...draft, enable_logging: event.target.checked })}
          />
        </div>
      </div>
      <div className="setting-card">
        <label>{t('settings.animations')}</label>
        <div className="toggle-row">
          <span>{draft.animations_enabled ? t('processes.signed.yes') : t('processes.signed.no')}</span>
          <input
            type="checkbox"
            checked={draft.animations_enabled}
            onChange={(event) => setDraft({ ...draft, animations_enabled: event.target.checked })}
          />
        </div>
        <small>{t('settings.reducedMotion')}</small>
      </div>
      <div className="setting-card">
        <label>{t('settings.exportPath')}</label>
        <p>{exportsPath}</p>
      </div>
      <div className="setting-card">
        <button type="submit" className="settings-button" disabled={saving}>
          {saving ? '…' : t('settings.save')}
        </button>
      </div>
    </form>
  );
}
