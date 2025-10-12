import flows from '../../src-tauri/src/resources/mock_flows.json';
import alerts from '../../src-tauri/src/resources/mock_alerts.json';
import dns from '../../src-tauri/src/resources/mock_dns.json';
import services from '../../src-tauri/src/resources/mock_services.json';
import processes from '../../src-tauri/src/resources/mock_processes.json';
import graph from '../../src-tauri/src/resources/mock_graph.json';
import status from '../../src-tauri/src/resources/mock_status.json';
import settings from '../../src-tauri/src/resources/mock_settings.json';
import type { UiSnapshot, UiSettings, UiEvent, PresetSummary } from '../types/ui';

export const mockSnapshot: UiSnapshot = {
  flows,
  alerts,
  dns,
  services,
  processes,
  graph,
  status,
  settings
};

export const mockPresets: PresetSummary[] = [
  {
    id: 'lan-essentials',
    label: { en: 'LAN essentials', ru: 'LAN базовый' },
    description: {
      en: 'Focus on ARP, DNS, and inbound listeners in the local network',
      ru: 'Контроль ARP, DNS и входящих слушателей'
    }
  },
  {
    id: 'dns-focus',
    label: { en: 'DNS focus', ru: 'DNS фокус' },
    description: {
      en: 'Capture NXDOMAIN bursts and discovery protocols',
      ru: 'Отслеживание всплесков NXDOMAIN и сервис-дискавери'
    }
  },
  {
    id: 'investigation',
    label: { en: 'Investigation', ru: 'Расследование' },
    description: {
      en: 'Maximum retention, verbose logging, quarantine prompts',
      ru: 'Максимальное хранение и подсказки по карантину'
    }
  }
];

export const mockEvents: UiEvent[] = flows.slice(0, 3).map((flow, index) => ({
  type: 'Flow',
  payload: {
    ...flow,
    ts_last: new Date(Date.now() + index * 1000).toISOString()
  }
}));

export const mockSettings: UiSettings = settings;
