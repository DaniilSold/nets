import { FixedSizeList as List, areEqual } from 'react-window';
import { memo, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { FlowEvent } from '../types/ui';

interface FlowsTableProps {
  flows: FlowEvent[];
  density: 'comfortable' | 'compact';
  onDensityChange: (density: 'comfortable' | 'compact') => void;
  isPaused: boolean;
  onPauseToggle: () => void;
  recentFlowKeys: Record<string, number>;
  selectedFlowKeys: Set<string>;
  onSelectionChange: (selection: Set<string>) => void;
  onExport: (flow: FlowEvent) => void;
  onInspect: (flow: FlowEvent) => void;
  onQuarantine: (flow: FlowEvent) => void;
  onQuickFilter: (type: 'process' | 'port', payload: number) => void;
  onCopy: (value: string) => void;
  animationsEnabled: boolean;
}

interface ItemData {
  flows: FlowEvent[];
  recentFlowKeys: Record<string, number>;
  selectedFlowKeys: Set<string>;
  toggleSelection: (key: string) => void;
  onExport: (flow: FlowEvent) => void;
  onInspect: (flow: FlowEvent) => void;
  onQuarantine: (flow: FlowEvent) => void;
  onQuickFilter: (type: 'process' | 'port', payload: number) => void;
  onCopy: (value: string) => void;
  animationsEnabled: boolean;
  t: ReturnType<typeof useTranslation>['t'];
  confirmingKey: string | null;
}

const timeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit'
});

const FlowRow = memo(({ index, style, data }: { index: number; style: React.CSSProperties; data: ItemData }) => {
  const flow = data.flows[index];
  const key = makeFlowKey(flow);
  const selected = data.selectedFlowKeys.has(key);
  const recent = Boolean(data.recentFlowKeys[key]);
  const isArp = flow.proto.toUpperCase() === 'ARP';
  const riskScore = flow.risk?.score ?? null;
  const riskLevel = flow.risk?.level ?? null;

  const handleQuarantine = () => {
    data.onQuarantine(flow);
  };

  return (
    <div
      className={`table-row ${selected ? 'selected' : ''} ${recent ? 'recent' : ''} ${index % 2 === 0 ? 'even' : 'odd'} ${
        isArp ? 'arp' : ''
      }`}
      style={style}
      data-recent={recent}
    >
      <span>
        <input
          type="checkbox"
          aria-label={data.t('flows.actions.selectRow')}
          checked={selected}
          onChange={() => data.toggleSelection(key)}
        />
      </span>
      <span>{timeFormatter.format(new Date(flow.ts_last))}</span>
      <span className="proto">
        <span className={`proto-indicator proto-${flow.proto.toLowerCase()}`} aria-hidden />
        {flow.proto}
      </span>
      <div className="cell-split">
        <button className="linkish" onClick={() => data.onCopy(`${flow.src_ip}:${flow.src_port}`)}>
          {flow.src_ip}:{flow.src_port}
        </button>
        <button
          className="mini-icon"
          onClick={() => data.onQuickFilter('port', flow.src_port)}
          aria-label={data.t('flows.actions.filterPort')}
        >
          ➕
        </button>
      </div>
      <div className="cell-split">
        <button className="linkish" onClick={() => data.onCopy(`${flow.dst_ip}:${flow.dst_port}`)}>
          {flow.dst_ip}:{flow.dst_port}
        </button>
        <button
          className="mini-icon"
          onClick={() => data.onQuickFilter('port', flow.dst_port)}
          aria-label={data.t('flows.actions.filterPort')}
        >
          ➕
        </button>
      </div>
      <span>{flow.iface ?? 'N/A'}</span>
      <span>{data.t(`flows.directions.${flow.direction.toLowerCase()}`)}</span>
      <button
        className="linkish"
        onClick={() => flow.process && data.onQuickFilter('process', flow.process.pid)}
        disabled={!flow.process}
        title={flow.process ? data.t('flows.processFilterHint') : undefined}
      >
        {flow.process
          ? `${flow.process.name ?? data.t('flows.processUnknown')} (${flow.process.pid})`
          : 'N/A'}
        {flow.process?.signed !== undefined && (
          <span className={`signature ${flow.process.signed ? 'signed' : 'unsigned'}`} aria-hidden>
            {flow.process.signed ? '✓' : '!'}
          </span>
        )}
      </button>
      <span className="numeric" title={data.t('flows.columns.packets')}>
        {flow.packets.toLocaleString(undefined, { useGrouping: true })}
      </span>
      <span className="numeric" title={data.t('flows.columns.bytes')}>
        {flow.bytes.toLocaleString(undefined, { useGrouping: true })}
      </span>
      <span>
        {riskScore !== null && riskLevel ? (
          <span className={`risk-badge risk-${riskLevel.toLowerCase()}`} title={flow.risk?.rationale ?? ''}>
            {riskScore.toFixed(0)} · {data.t(`flows.risk.${riskLevel.toLowerCase()}`)}
          </span>
        ) : (
          <span className="muted">N/A</span>
        )}
      </span>
      <span className="row-actions">
        <button onClick={() => data.onInspect(flow)} aria-label={data.t('flows.actions.inspect')} title={data.t('flows.actions.inspect')}>
          🔍
        </button>
        <button onClick={() => data.onExport(flow)} aria-label={data.t('flows.actions.export')} title={data.t('flows.actions.export')}>
          ⬇️
        </button>
        <button
          onClick={handleQuarantine}
          aria-label={data.t('flows.actions.quarantine')}
          title={
            data.confirmingKey === key
              ? data.t('flows.actions.quarantineConfirm')
              : data.t('flows.actions.quarantine')
          }
          className={data.confirmingKey === key ? 'confirming' : ''}
        >
          🛡
        </button>
      </span>
    </div>
  );
}, areEqual);

FlowRow.displayName = 'FlowRow';

export function FlowsTable({
  flows,
  density,
  onDensityChange,
  isPaused,
  onPauseToggle,
  recentFlowKeys,
  selectedFlowKeys,
  onSelectionChange,
  onExport,
  onInspect,
  onQuarantine,
  onQuickFilter,
  onCopy,
  animationsEnabled
}: FlowsTableProps) {
  const { t } = useTranslation();
  const [confirmingKey, setConfirmingKey] = useState<string | null>(null);

  const toggleSelection = (key: string) => {
    const next = new Set(selectedFlowKeys);
    if (next.has(key)) {
      next.delete(key);
    } else {
      next.add(key);
    }
    onSelectionChange(next);
  };

  const wrappedQuarantine = (flow: FlowEvent) => {
    const key = makeFlowKey(flow);
    if (confirmingKey === key) {
      onQuarantine(flow);
      setConfirmingKey(null);
    } else {
      setConfirmingKey(key);
      window.setTimeout(() => setConfirmingKey((current) => (current === key ? null : current)), 3500);
    }
  };

  const itemSize = density === 'comfortable' ? 60 : 44;

  const itemData = useMemo<ItemData>(
    () => ({
      flows,
      recentFlowKeys,
      selectedFlowKeys,
      toggleSelection,
      onExport,
      onInspect,
      onQuarantine: wrappedQuarantine,
      onQuickFilter,
      onCopy,
      animationsEnabled,
      t,
      confirmingKey
    }),
    [
      flows,
      recentFlowKeys,
      selectedFlowKeys,
      onExport,
      onInspect,
      onQuickFilter,
      onCopy,
      animationsEnabled,
      t,
      confirmingKey
    ]
  );

  if (flows.length === 0) {
    return <p>{t('flows.empty')}</p>;
  }

  return (
    <div className={`table-container ${animationsEnabled ? 'animate' : ''}`} role="table" aria-label={t('flows.title')}>
      <div className="table-controls">
        <div className="segment">
          <button
            className={`segment-item ${density === 'comfortable' ? 'active' : ''}`}
            onClick={() => onDensityChange('comfortable')}
            aria-pressed={density === 'comfortable'}
          >
            {t('flows.density.comfortable')}
          </button>
          <button
            className={`segment-item ${density === 'compact' ? 'active' : ''}`}
            onClick={() => onDensityChange('compact')}
            aria-pressed={density === 'compact'}
          >
            {t('flows.density.compact')}
          </button>
        </div>
        <button className="chip-button" onClick={onPauseToggle} aria-pressed={isPaused}>
          {isPaused ? t('flows.resume') : t('flows.pause')}
        </button>
      </div>
      <div className="table-header" role="row">
        <span />
        <span>{t('flows.columns.time')}</span>
        <span>{t('flows.columns.proto')}</span>
        <span>{t('flows.columns.src')}</span>
        <span>{t('flows.columns.dst')}</span>
        <span>{t('flows.columns.iface')}</span>
        <span>{t('flows.columns.direction')}</span>
        <span>{t('flows.columns.process')}</span>
        <span>{t('flows.columns.packets')}</span>
        <span>{t('flows.columns.bytes')}</span>
        <span>{t('flows.columns.risk')}</span>
        <span>{t('flows.columns.actions')}</span>
      </div>
      <List
        height={380}
        itemCount={flows.length}
        itemSize={itemSize}
        width="100%"
        itemData={itemData}
      >
        {FlowRow}
      </List>
      {confirmingKey && (
        <div className="confirm-hint" role="status">
          {t('flows.confirmQuarantine')}
        </div>
      )}
    </div>
  );
}

function makeFlowKey(flow: FlowEvent) {
  return `${flow.ts_last}|${flow.src_ip}|${flow.src_port}|${flow.dst_ip}|${flow.dst_port}`;
}
