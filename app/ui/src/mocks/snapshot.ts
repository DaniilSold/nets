import flows from '../../src-tauri/src/resources/mock_flows.json';
import alerts from '../../src-tauri/src/resources/mock_alerts.json';
import dns from '../../src-tauri/src/resources/mock_dns.json';
import services from '../../src-tauri/src/resources/mock_services.json';
import processes from '../../src-tauri/src/resources/mock_processes.json';
import graph from '../../src-tauri/src/resources/mock_graph.json';
import status from '../../src-tauri/src/resources/mock_status.json';
import settings from '../../src-tauri/src/resources/mock_settings.json';
import type {
  Alert,
  DaemonStatus,
  FlowEvent,
  GraphSnapshot,
  PresetSummary,
  ProcessActivity,
  ServiceRecord,
  UiEvent,
  UiSettings,
  UiSnapshot,
  DnsRecord
} from '../types/ui';

const typedFlows = flows as unknown as FlowEvent[];
const typedAlerts = alerts as unknown as Alert[];
const typedDns = dns as unknown as DnsRecord[];
const typedServices = services as unknown as ServiceRecord[];
const typedProcesses = processes as unknown as ProcessActivity[];
const typedGraph = graph as unknown as GraphSnapshot;
const typedStatus = status as unknown as DaemonStatus;
const typedSettings = settings as unknown as UiSettings;

export const mockSnapshot: UiSnapshot = {
  flows: typedFlows,
  alerts: typedAlerts,
  dns: typedDns,
  services: typedServices,
  processes: typedProcesses,
  graph: typedGraph,
  status: typedStatus,
  settings: typedSettings
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

export const mockEvents: UiEvent[] = typedFlows.slice(0, 3).map((flow, index) => ({
  type: 'Flow',
  payload: {
    ...flow,
    ts_last: new Date(Date.now() + index * 1000).toISOString()
  }
}));

export const mockSettings: UiSettings = typedSettings;
