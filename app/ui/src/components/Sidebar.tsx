import * as ToggleGroup from '@radix-ui/react-toggle-group';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type {
  FlowDirection,
  Severity,
  SidebarFilters,
  PresetSummary,
  ProcessActivity
} from '../types/ui';

const protocols = ['ARP', 'DNS', 'TCP', 'UDP', 'ICMP'];
const directions: FlowDirection[] = ['Inbound', 'Outbound', 'Lateral'];
const risks: Severity[] = ['Low', 'Medium', 'High'];

interface SidebarStats {
  protocol: Record<string, number>;
  direction: Record<FlowDirection, number>;
  risk: Record<Severity, number>;
}

interface SidebarProps {
  filters: SidebarFilters;
  onChange: (filters: SidebarFilters) => void;
  onPreset: (id: string) => void;
  presets: PresetSummary[];
  stats: SidebarStats;
  processes: ProcessActivity[];
}

export function Sidebar({ filters, onChange, onPreset, presets, stats, processes }: SidebarProps) {
  const { t, i18n } = useTranslation();
  const [processSearch, setProcessSearch] = useState('');
  const presetOptions = useMemo(
    () =>
      presets.map((preset) => ({
        id: preset.id,
        label: preset.label[i18n.language as 'en' | 'ru'] ?? preset.id
      })),
    [presets, i18n.language]
  );

  const filteredProcesses = useMemo(() => {
    if (!processSearch.trim()) return processes;
    return processes.filter((process) =>
      `${process.name}${process.pid}`.toLowerCase().includes(processSearch.toLowerCase())
    );
  }, [processSearch, processes]);

  const toggleProcess = (pid: number) => {
    const hasPid = filters.processes.includes(pid);
    onChange({
      ...filters,
      processes: hasPid ? filters.processes.filter((value) => value !== pid) : [...filters.processes, pid]
    });
  };

  return (
    <aside className="sidebar" aria-label={t('filters.title')}>
      <div className="sidebar-section">
        <h2>{t('filters.presets')}</h2>
        <select
          className="preset-select"
          onChange={(event) => {
            if (event.target.value) {
              onPreset(event.target.value);
              event.target.value = '';
            }
          }}
          defaultValue=""
          aria-label={t('filters.presets')}
        >
          <option value="" disabled>
            {t('filters.choosePreset')}
          </option>
          {presetOptions.map((preset) => (
            <option key={preset.id} value={preset.id}>
              {preset.label}
            </option>
          ))}
        </select>
      </div>
      <div className="sidebar-section">
        <h2>{t('filters.title')}</h2>
        <div className="sidebar-filters">
          <Field label={t('filters.protocol')}>
            <ToggleGroup.Root
              type="multiple"
              value={filters.protocol}
              className="toggle-group"
              onValueChange={(value) => onChange({ ...filters, protocol: value })}
            >
              {protocols.map((item) => (
                <ToggleGroup.Item key={item} value={item} className="toggle-item">
                  <span>{item}</span>
                  <span className="chip-count">{stats.protocol[item] ?? 0}</span>
                </ToggleGroup.Item>
              ))}
            </ToggleGroup.Root>
          </Field>
          <Field label={t('filters.direction')}>
            <ToggleGroup.Root
              type="multiple"
              value={filters.direction}
              className="toggle-group"
              onValueChange={(value) => onChange({ ...filters, direction: value as FlowDirection[] })}
            >
              {directions.map((item) => (
                <ToggleGroup.Item key={item} value={item} className="toggle-item" title={item === 'Lateral' ? t('filters.tooltips.lateral') : undefined}>
                  <span>{t(`filters.directions.${item.toLowerCase()}`)}</span>
                  <span className="chip-count">{stats.direction[item]}</span>
                </ToggleGroup.Item>
              ))}
            </ToggleGroup.Root>
          </Field>
          <Field label={t('filters.risk')}>
            <ToggleGroup.Root
              type="multiple"
              value={filters.risk}
              className="toggle-group"
              onValueChange={(value) => onChange({ ...filters, risk: value as Severity[] })}
            >
              {risks.map((item) => (
                <ToggleGroup.Item key={item} value={item} className={`toggle-item risk-${item.toLowerCase()}`}>
                  <span>{t(`flows.risk.${item.toLowerCase()}`)}</span>
                  <span className="chip-count">{stats.risk[item]}</span>
                </ToggleGroup.Item>
              ))}
            </ToggleGroup.Root>
          </Field>
          <Field label={t('filters.process')}>
            <input
              type="search"
              value={processSearch}
              onChange={(event) => setProcessSearch(event.target.value)}
              placeholder={t('filters.processPlaceholder')}
            />
            <div className="process-list" role="list">
              {filteredProcesses.length === 0 && <span className="muted">{t('filters.noProcess')}</span>}
              {filteredProcesses.slice(0, 10).map((process) => {
                const checked = filters.processes.includes(process.pid);
                return (
                  <label key={process.pid} className={`process-item ${checked ? 'selected' : ''}`}>
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleProcess(process.pid)}
                    />
                    <span>
                      {process.name} <span className="muted">({process.pid})</span>
                    </span>
                    {process.signed !== undefined && (
                      <span className={`signature ${process.signed ? 'signed' : 'unsigned'}`}>
                        {process.signed ? '✓' : '!'}
                      </span>
                    )}
                  </label>
                );
              })}
            </div>
          </Field>
          <Field label={t('filters.port')}>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9,-\s]*"
              value={filters.portExpression}
              onChange={(event) => onChange({ ...filters, portExpression: event.target.value })}
              placeholder={t('filters.portPlaceholder')}
            />
            <small className="muted">{t('filters.portHelp')}</small>
          </Field>
        </div>
        <button
          className="settings-button"
          onClick={() =>
            onChange({ ...filters, protocol: [], direction: [], risk: [], processes: [], portExpression: '' })
          }
        >
          {t('filters.clear')}
        </button>
      </div>
    </aside>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}
