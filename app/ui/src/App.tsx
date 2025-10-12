import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  applyPreset,
  exportPcap,
  exportReport,
  listPresets,
  loadSnapshot,
  setLocale as apiSetLocale,
  startEventStream,
  toggleMode,
  toggleCapture,
  updateSettings
} from './api/client';
import { useTypewriter } from './hooks/useTypewriter';
import { useHotkeys } from './hooks/useHotkeys';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { FlowsTable } from './components/FlowsTable';
import { AlertsList } from './components/AlertsList';
import { DnsView } from './components/DnsView';
import { GraphView } from './components/GraphView';
import { ProcessesView } from './components/ProcessesView';
import { SettingsView } from './components/SettingsView';
import { StatusBar } from './components/StatusBar';
import type {
  Alert,
  FlowEvent,
  SidebarFilters,
  UiEvent,
  UiSettings,
  UiSnapshot,
  PresetSummary,
  NotificationMessage,
  Severity,
  FlowDirection
} from './types/ui';
import './styles/app.css';

const defaultFilters: SidebarFilters = {
  protocol: [],
  direction: [],
  risk: [],
  processes: [],
  portExpression: ''
};

type Tab = 'flows' | 'alerts' | 'dns' | 'graph' | 'processes' | 'settings';

const tabs: Array<{ id: Tab; hotkey: string; translationKey: string }> = [
  { id: 'flows', hotkey: 'F', translationKey: 'navigation.flows' },
  { id: 'alerts', hotkey: 'A', translationKey: 'navigation.alerts' },
  { id: 'dns', hotkey: 'D', translationKey: 'navigation.dns' },
  { id: 'graph', hotkey: 'G', translationKey: 'navigation.graph' },
  { id: 'processes', hotkey: 'P', translationKey: 'navigation.processes' },
  { id: 'settings', hotkey: 'S', translationKey: 'navigation.settings' }
];

const RECENT_HIGHLIGHT_MS = 4000;
const FLOW_CAP = 5000;

const makeFlowKey = (flow: FlowEvent) =>
  `${flow.ts_last}|${flow.src_ip}|${flow.src_port}|${flow.dst_ip}|${flow.dst_port}`;

function matchesPortExpression(flow: FlowEvent, expression: string) {
  if (!expression.trim()) return true;
  const tokens = expression.split(',').map((item) => item.trim()).filter(Boolean);
  if (tokens.length === 0) return true;
  const ports = [flow.src_port, flow.dst_port];
  return tokens.some((token) => {
    if (token.includes('-')) {
      const [start, end] = token.split('-').map((value) => Number(value.trim()));
      if (Number.isNaN(start) || Number.isNaN(end)) return false;
      return ports.some((port) => port >= Math.min(start, end) && port <= Math.max(start, end));
    }
    const numeric = Number(token);
    if (Number.isNaN(numeric)) return false;
    return ports.includes(numeric);
  });
}

function mergePortExpression(expression: string, port: number) {
  if (!expression.trim()) return `${port}`;
  const parts = expression.split(',').map((item) => item.trim());
  if (parts.includes(String(port))) return expression;
  return `${expression}, ${port}`;
}

export default function App() {
  const { t, i18n } = useTranslation();
  const [snapshot, setSnapshot] = useState<UiSnapshot | null>(null);
  const [filters, setFilters] = useState<SidebarFilters>(defaultFilters);
  const [tab, setTab] = useState<Tab>('flows');
  const [presets, setPresets] = useState<PresetSummary[]>([]);
  const [notifications, setNotifications] = useState<NotificationMessage[]>([]);
  const [search, setSearch] = useState('');
  const [locale, setLocale] = useState<'en' | 'ru'>('en');
  const [animationsEnabled, setAnimationsEnabled] = useState(true);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window === 'undefined') return 'light';
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  });
  const [isPaused, setIsPaused] = useState(false);
  const [queuedFlows, setQueuedFlows] = useState<FlowEvent[]>([]);
  const [recentFlowKeys, setRecentFlowKeys] = useState<Record<string, number>>({});
  const [density, setDensity] = useState<'comfortable' | 'compact'>('comfortable');
  const [selectedFlowKeys, setSelectedFlowKeys] = useState<Set<string>>(new Set());
  const searchRef = useRef<HTMLInputElement | null>(null);
  const exportPath = '~/NetMonExports';

  const prefersReducedMotion = useMemo(() => {
    return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }, []);

  const typewriter = useTypewriter(t('typewriter.welcome', { returnObjects: true }) as string[], {
    enabled: animationsEnabled && !prefersReducedMotion,
    once: true
  });

  useEffect(() => {
    loadSnapshot().then((data) => {
      setSnapshot(data);
      setAnimationsEnabled(data.settings.animations_enabled);
      setLocale(i18n.language as 'en' | 'ru');
    });
    listPresets().then(setPresets);
  }, [i18n.language]);

  const handleEvent = useCallback(
    (event: UiEvent) => {
      setSnapshot((previous) => {
        if (!previous) return previous;
        switch (event.type) {
          case 'Flow': {
            const key = makeFlowKey(event.payload);
            setRecentFlowKeys((prev) => ({ ...prev, [key]: Date.now() }));
            if (isPaused) {
              setQueuedFlows((queue) => [event.payload, ...queue].slice(0, FLOW_CAP));
              return previous;
            }
            const nextFlows = [event.payload, ...previous.flows].slice(0, FLOW_CAP);
            return { ...previous, flows: nextFlows };
          }
          case 'Alert':
            return { ...previous, alerts: [event.payload, ...previous.alerts].slice(0, 500) };
          case 'Status':
            return { ...previous, status: event.payload };
          default:
            return previous;
        }
      });
    },
    [isPaused]
  );

  useEffect(() => {
    let cleanup: (() => void) | undefined;
    (async () => {
      const unsub = await startEventStream(handleEvent);
      if (unsub) {
        cleanup = () => unsub();
      }
    })();
    return () => {
      if (cleanup) cleanup();
    };
  }, [handleEvent]);

  useEffect(() => {
    const listener = (event: MediaQueryListEvent) => setAnimationsEnabled((prev) => !event.matches && prev);
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (event: MediaQueryListEvent) => setTheme(event.matches ? 'dark' : 'light');
    media.addEventListener('change', handler);
    return () => media.removeEventListener('change', handler);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('lang', locale);
  }, [locale]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setRecentFlowKeys((prev) => {
        const now = Date.now();
        const next: Record<string, number> = {};
        Object.entries(prev).forEach(([key, value]) => {
          if (now - value < RECENT_HIGHLIGHT_MS) {
            next[key] = value;
          }
        });
        return next;
      });
    }, 2000);
    return () => window.clearInterval(interval);
  }, []);

  useHotkeys({
    '/': () => {
      setTab('flows');
      window.requestAnimationFrame(() => searchRef.current?.focus());
    },
    f: () => setTab('flows'),
    a: () => setTab('alerts'),
    d: () => setTab('dns'),
    g: () => setTab('graph'),
    p: () => setTab('processes'),
    s: () => setTab('settings')
  });

  const filteredFlows = useMemo(() => {
    if (!snapshot) return [];
    return snapshot.flows.filter((flow) => {
      if (filters.protocol.length && !filters.protocol.includes(flow.proto)) return false;
      if (filters.direction.length && !filters.direction.includes(flow.direction)) return false;
      if (filters.risk.length && (!flow.risk || !filters.risk.includes(flow.risk.level))) return false;
      if (filters.processes.length) {
        if (!flow.process || !filters.processes.includes(flow.process.pid)) return false;
      }
      if (!matchesPortExpression(flow, filters.portExpression)) return false;
      if (search) {
        const haystack = `${flow.src_ip}${flow.dst_ip}${flow.process?.name ?? ''}${flow.process?.pid ?? ''}`.toLowerCase();
        if (!haystack.includes(search.toLowerCase())) return false;
      }
      return true;
    });
  }, [snapshot, filters, search]);

  useEffect(() => {
    setSelectedFlowKeys((previous) => {
      const validKeys = new Set(filteredFlows.map((flow) => makeFlowKey(flow)));
      const next = new Set<string>();
      previous.forEach((key) => {
        if (validKeys.has(key)) {
          next.add(key);
        }
      });
      if (next.size === previous.size) {
        let identical = true;
        previous.forEach((key) => {
          if (!next.has(key)) identical = false;
        });
        if (identical) return previous;
      }
      return next;
    });
  }, [filteredFlows]);

  const sidebarStats = useMemo(() => {
    const protocol: Record<string, number> = { ARP: 0, DNS: 0, TCP: 0, UDP: 0, ICMP: 0 };
    const direction: Record<FlowDirection, number> = { Inbound: 0, Outbound: 0, Lateral: 0 };
    const risk: Record<Severity, number> = { Low: 0, Medium: 0, High: 0 };
    if (!snapshot) {
      return { protocol, direction, risk };
    }
    snapshot.flows.forEach((flow) => {
      if (protocol[flow.proto] !== undefined) protocol[flow.proto] += 1;
      direction[flow.direction] += 1;
      if (flow.risk) {
        risk[flow.risk.level] += 1;
      }
    });
    return { protocol, direction, risk };
  }, [snapshot]);

  const pushNotification = (message: string, type: NotificationMessage['type'] = 'info') => {
    const id = typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    const entry: NotificationMessage = { id, message, type };
    setNotifications((items) => [...items, entry]);
    window.setTimeout(() => setNotifications((items) => items.filter((item) => item.id !== entry.id)), 5000);
  };

  const handleLocaleChange = async (value: 'en' | 'ru') => {
    setLocale(value);
    await i18n.changeLanguage(value);
    await apiSetLocale(value);
  };

  const handleSettingsSave = async (settings: UiSettings) => {
    const updated = await updateSettings(settings);
    setSnapshot((previous) => (previous ? { ...previous, settings: updated } : previous));
    setAnimationsEnabled(updated.animations_enabled);
    pushNotification(t('notifications.settingsSaved'), 'success');
  };

  const handleExportFlow = async (flow: FlowEvent) => {
    await exportPcap(`${flow.src_ip}-${flow.dst_ip}`);
    pushNotification(t('notifications.pcapReady'), 'success');
  };

  const handleExportAlert = async (_alert: Alert) => {
    await exportReport();
    pushNotification(t('notifications.reportReady'), 'success');
  };

  const handlePreset = async (presetId: string) => {
    const updated = await applyPreset(presetId);
    setSnapshot((previous) => (previous ? { ...previous, settings: updated } : previous));
    setAnimationsEnabled(updated.animations_enabled);
    pushNotification(t('notifications.presetApplied'), 'info');
  };

  const handleToggleMode = async () => {
    await toggleMode();
    setSnapshot((previous) =>
      previous
        ? {
            ...previous,
            status: {
              ...previous.status,
              mode: previous.status.mode === 'Observer' ? 'Guardian' : 'Observer'
            }
          }
        : previous
    );
    pushNotification(t('header.actions.switchMode'), 'info');
  };

  const handleToggleCapture = async () => {
    await toggleCapture();
    setSnapshot((previous) =>
      previous
        ? {
            ...previous,
            status: {
              ...previous.status,
              capture_enabled: !previous.status.capture_enabled,
              flows_per_second: !previous.status.capture_enabled
                ? 0
                : previous.status.flows_per_second > 0
                ? previous.status.flows_per_second
                : 12
            }
          }
        : previous
    );
    pushNotification(t('header.actions.toggleCapture'), 'info');
  };

  const handleBrandClick = () => {
    pushNotification(t('header.brandAbout'), 'info');
  };

  const handlePauseToggle = () => {
    setIsPaused((prev) => {
      if (prev) {
        setSnapshot((previous) =>
          previous
            ? { ...previous, flows: [...queuedFlows, ...previous.flows].slice(0, FLOW_CAP) }
            : previous
        );
        setQueuedFlows([]);
      }
      return !prev;
    });
  };

  const handleDensityChange = (value: 'comfortable' | 'compact') => {
    setDensity(value);
  };

  const handleSelectionChange = (next: Set<string>) => {
    setSelectedFlowKeys(new Set(next));
  };

  const handleExportSelected = async () => {
    if (!snapshot) return;
    const flowsToExport = snapshot.flows.filter((flow) => selectedFlowKeys.has(makeFlowKey(flow)));
    if (flowsToExport.length === 0) return;
    await exportReport();
    pushNotification(t('notifications.selectionExported', { count: flowsToExport.length }), 'success');
  };

  const handleQuickFilter = (type: 'process' | 'port', payload: number) => {
    if (type === 'process') {
      setFilters((prev) => ({
        ...prev,
        processes: prev.processes.includes(payload) ? prev.processes : [...prev.processes, payload]
      }));
    } else {
      setFilters((prev) => ({
        ...prev,
        portExpression: mergePortExpression(prev.portExpression, payload)
      }));
    }
  };

  const handleCopy = async (value: string) => {
    try {
      if ('clipboard' in navigator) {
        await navigator.clipboard.writeText(value);
        pushNotification(t('notifications.copied'), 'success');
      }
    } catch (error) {
      console.error(error);
      pushNotification(t('notifications.copyFailed'), 'warning');
    }
  };

  const handleSearchReset = () => {
    setSearch('');
  };

  const activeTabContent = useMemo(() => {
    if (!snapshot) return null;
    switch (tab) {
      case 'flows':
        return (
          <FlowsTable
            flows={filteredFlows}
            density={density}
            onDensityChange={handleDensityChange}
            isPaused={isPaused}
            onPauseToggle={handlePauseToggle}
            recentFlowKeys={recentFlowKeys}
            selectedFlowKeys={selectedFlowKeys}
            onSelectionChange={handleSelectionChange}
            onExport={handleExportFlow}
            onInspect={(flow) => console.info(flow)}
            onQuarantine={(flow) => console.info('quarantine', flow)}
            onQuickFilter={handleQuickFilter}
            onCopy={handleCopy}
            animationsEnabled={animationsEnabled && !prefersReducedMotion}
          />
        );
      case 'alerts':
        return <AlertsList alerts={snapshot.alerts} onExport={handleExportAlert} />;
      case 'dns':
        return <DnsView records={snapshot.dns} services={snapshot.services} />;
      case 'graph':
        return <GraphView graph={snapshot.graph} />;
      case 'processes':
        return <ProcessesView processes={snapshot.processes} />;
      case 'settings':
        return <SettingsView settings={snapshot.settings} onSave={handleSettingsSave} exportsPath={exportPath} />;
      default:
        return null;
    }
  }, [
    snapshot,
    tab,
    filteredFlows,
    density,
    isPaused,
    recentFlowKeys,
    selectedFlowKeys,
    animationsEnabled,
    prefersReducedMotion
  ]);

  return (
    <div className="app-shell" data-theme={theme}>
      <Sidebar
        filters={filters}
        onChange={setFilters}
        onPreset={handlePreset}
        presets={presets}
        stats={sidebarStats}
        processes={snapshot?.processes ?? []}
      />
      <div className="main-content">
        {snapshot && (
          <Header
            status={snapshot.status}
            locale={locale}
            brandLine={t('header.brand')}
            animatedLine={typewriter}
            onChangeLocale={handleLocaleChange}
            onToggleMode={handleToggleMode}
            onToggleCapture={handleToggleCapture}
            onOpenSettings={() => setTab('settings')}
            onShowAbout={handleBrandClick}
          />
        )}
        <nav className="tab-bar" role="tablist">
          {tabs.map((entry) => (
            <button
              key={entry.id}
              className={`tab ${tab === entry.id ? 'active' : ''}`}
              role="tab"
              aria-selected={tab === entry.id}
              onClick={() => setTab(entry.id)}
            >
              {t(entry.translationKey)} <span className="tab-hotkey">{entry.hotkey}</span>
            </button>
          ))}
        </nav>
        {tab === 'flows' && (
          <div className="flow-tools">
            <input
              id="flow-search"
              ref={searchRef}
              type="search"
              placeholder={t('flows.search')}
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <button className="ghost-button" onClick={handleSearchReset}>
              {t('flows.resetSearch')}
            </button>
            <span className="queue-indicator" aria-live="polite">
              {isPaused && queuedFlows.length > 0
                ? t('flows.pausedQueue', { count: queuedFlows.length })
                : null}
            </span>
          </div>
        )}
        <main className="content">
          <div className="content-card">{activeTabContent}</div>
        </main>
        {selectedFlowKeys.size > 0 && (
          <div className="selection-bar" aria-live="polite">
            <span>{t('flows.selectionCount', { count: selectedFlowKeys.size })}</span>
            <div className="selection-actions">
              <button onClick={handleExportSelected}>{t('flows.actions.exportSelection')}</button>
              <button onClick={() => setSelectedFlowKeys(new Set())}>{t('flows.actions.clearSelection')}</button>
            </div>
          </div>
        )}
        {snapshot && (
          <StatusBar
            status={snapshot.status}
            queuedCount={queuedFlows.length}
            theme={theme}
            isPaused={isPaused}
          />
        )}
      </div>
      <div className="notification-stack" aria-live="polite">
        {notifications.map((note) => (
          <div key={note.id} className={`notification ${note.type}`}>
            {note.message}
          </div>
        ))}
      </div>
    </div>
  );
}
