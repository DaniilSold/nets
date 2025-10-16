export type FlowDirection = 'Inbound' | 'Outbound' | 'Lateral';

export interface ProcessIdentity {
  pid: number;
  ppid?: number | null;
  name?: string | null;
  exe_path?: string | null;
  sha256_16?: string | null;
  user?: string | null;
  signed?: boolean | null;
}

export interface Layer2EventMetadata {
  kind: 'Arp' | 'Nd';
  operation: string;
  mac_src?: string | null;
  ip_src?: string | null;
  mac_dst?: string | null;
  ip_dst?: string | null;
}

export interface FlowRisk {
  score: number;
  level: Severity;
  rule_id?: string | null;
  rationale?: string | null;
}

export interface FlowEvent {
  ts_first: string;
  ts_last: string;
  proto: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  iface?: string | null;
  direction: FlowDirection;
  state?: string | null;
  bytes: number;
  packets: number;
  process?: ProcessIdentity | null;
  layer2?: Layer2EventMetadata | null;
  risk?: FlowRisk | null;
  sni?: string | null;
  alpn?: string | null;
  ja3?: string | null;
  dns_qname?: string | null;
  dns_qtype?: string | null;
  dns_rcode?: string | null;
}

export type Severity = 'Low' | 'Medium' | 'High';

export interface Alert {
  id: string;
  ts: string;
  severity: Severity;
  rule_id: string;
  summary: string;
  flow_refs: string[];
  process_ref?: string | null;
  rationale: string;
  suggested_action?: string | null;
}

export interface DnsRecord {
  id: string;
  qname: string;
  qtype: string;
  rcode: string;
  count: number;
  last_observed: string;
  channel?: string | null;
}

export interface ServiceRecord {
  id: string;
  name: string;
  protocol: string;
  address: string;
  port: number;
  process?: string | null;
  last_seen: string;
}

export interface ProcessActivity {
  pid: number;
  name: string;
  user?: string | null;
  signed?: boolean | null;
  hash?: string | null;
  listening_ports: number[];
  total_flows: number;
  last_active: string;
}

export interface GraphNode {
  id: string;
  kind: 'Process' | 'Endpoint';
  label: string;
  risk?: string | null;
}

export interface GraphLink {
  id: string;
  source: string;
  target: string;
  protocol: string;
  volume: number;
  risk?: string | null;
}

export interface GraphSnapshot {
  nodes: GraphNode[];
  links: GraphLink[];
  generated_at: string;
}

export type Mode = 'Observer' | 'Guardian';

export interface DaemonStatus {
  connected: boolean;
  mode: Mode;
  cpu_load: number;
  memory_mb: number;
  last_heartbeat: string;
  capture_enabled: boolean;
  flows_per_second: number;
  sample_ratio: string;
  drop_rate: number;
}

export interface UiSettings {
  sample_rate: number;
  max_header_bytes: number;
  lan_only: boolean;
  enable_logging: boolean;
  animations_enabled: boolean;
}

export interface UiSnapshot {
  flows: FlowEvent[];
  alerts: Alert[];
  dns: DnsRecord[];
  services: ServiceRecord[];
  processes: ProcessActivity[];
  graph: GraphSnapshot;
  status: DaemonStatus;
  settings: UiSettings;
}

export type UiEvent =
  | { type: 'Flow'; payload: FlowEvent }
  | { type: 'Alert'; payload: Alert }
  | { type: 'Status'; payload: DaemonStatus };

export interface SidebarFilters {
  protocol: string[];
  direction: FlowDirection[];
  risk: Severity[];
  processes: number[];
  portExpression: string;
}

export interface PresetSummary {
  id: string;
  label: Record<string, string>;
  description: Record<string, string>;
}

export interface NotificationMessage {
  id: string;
  message: string;
  type: 'info' | 'success' | 'warning';
}
