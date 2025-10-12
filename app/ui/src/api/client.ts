import { invoke } from '@tauri-apps/api/tauri';
import { listen, UnlistenFn } from '@tauri-apps/api/event';
import type {
  UiSnapshot,
  UiSettings,
  UiEvent,
  PresetSummary
} from '../types/ui';
import { mockSnapshot, mockSettings, mockPresets, mockEvents } from '../mocks/snapshot';

const isTauri = typeof window !== 'undefined' && '__TAURI_IPC__' in window;

type EventHandler = (event: UiEvent) => void;

export async function loadSnapshot(): Promise<UiSnapshot> {
  if (isTauri) {
    return invoke<UiSnapshot>('load_snapshot');
  }
  return Promise.resolve(mockSnapshot);
}

export async function updateSettings(settings: UiSettings): Promise<UiSettings> {
  if (isTauri) {
    return invoke<UiSettings>('update_settings', { settings });
  }
  return Promise.resolve(settings);
}

export async function applyPreset(presetId: string): Promise<UiSettings> {
  if (isTauri) {
    return invoke<UiSettings>('apply_preset', { presetId });
  }
  switch (presetId) {
    case 'lan-essentials':
      return Promise.resolve({ ...mockSettings, sample_rate: 10, max_header_bytes: 256, lan_only: true, enable_logging: false, animations_enabled: true });
    case 'dns-focus':
      return Promise.resolve({ ...mockSettings, sample_rate: 5, max_header_bytes: 192, lan_only: false, enable_logging: true, animations_enabled: true });
    case 'investigation':
      return Promise.resolve({ ...mockSettings, sample_rate: 1, max_header_bytes: 512, lan_only: false, enable_logging: true, animations_enabled: false });
    default:
      return Promise.resolve(mockSettings);
  }
}

export async function listPresets(): Promise<PresetSummary[]> {
  if (isTauri) {
    return invoke<PresetSummary[]>('list_presets');
  }
  return Promise.resolve(mockPresets);
}

export async function setLocale(locale: string): Promise<void> {
  if (isTauri) {
    await invoke('set_locale', { locale });
  }
}

export async function toggleMode(): Promise<void> {
  if (isTauri) {
    await invoke('toggle_mode_command');
  }
}

export async function toggleCapture(): Promise<void> {
  if (isTauri) {
    await invoke('toggle_capture_command');
  }
}

export async function exportReport(): Promise<string> {
  if (isTauri) {
    return invoke<string>('export_report');
  }
  const blob = new Blob(['<html><body><h1>Mock report</h1></body></html>'], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  return url;
}

export async function exportPcap(flowId?: string): Promise<string> {
  if (isTauri) {
    return invoke<string>('export_pcap', { flowId });
  }
  const blob = new Blob(['pcap-data'], { type: 'application/vnd.tcpdump.pcap' });
  return URL.createObjectURL(blob);
}

export async function startEventStream(handler: EventHandler): Promise<UnlistenFn | null> {
  if (isTauri) {
    await invoke('start_event_stream');
    const unlisten = await listen<UiEvent>('ui-event', (event) => handler(event.payload));
    return unlisten;
  }
  const timers = mockEvents.map((event, index) =>
    window.setTimeout(() => handler(event), (index + 1) * 2000)
  );
  return () => timers.forEach((timer) => window.clearTimeout(timer));
}
