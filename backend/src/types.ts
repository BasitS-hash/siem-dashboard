export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type EventCategory =
  | 'authentication'
  | 'network'
  | 'web'
  | 'system'
  | 'firewall';

export type AttackType =
  | 'brute_force'
  | 'port_scan'
  | 'sql_injection'
  | 'xss'
  | 'data_exfiltration'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'c2_communication';

export interface GeoInfo {
  country: string;
  country_code: string;
  city: string;
  lat: number;
  lon: number;
}

export interface LogEvent {
  id: string;
  timestamp: string;
  severity: Severity;
  category: EventCategory;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  user?: string;
  hostname: string;
  message: string;
  raw: string;
  tags: string[];
  geo?: GeoInfo;
  bytes_sent?: number;
  bytes_received?: number;
  status_code?: number;
  url?: string;
  action: string;
}

export interface Alert {
  id: string;
  timestamp: string;
  severity: Severity;
  type: AttackType;
  title: string;
  description: string;
  source_ip: string;
  destination_ips: string[];
  affected_users: string[];
  event_count: number;
  status: 'active' | 'acknowledged' | 'resolved';
  mitre_tactic: string;
  mitre_technique: string;
  mitre_technique_id: string;
  related_event_ids: string[];
  first_seen: string;
  last_seen: string;
}

export interface TimeSeriesPoint {
  time: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Stats {
  total_events: number;
  critical_alerts: number;
  active_threats: number;
  events_per_minute: number;
  unique_ips: number;
  alert_rate: number;
  top_source_ips: { ip: string; count: number; country?: string }[];
  severity_breakdown: { severity: string; count: number; color: string }[];
  events_over_time: TimeSeriesPoint[];
  category_breakdown: { category: string; count: number }[];
  top_ports: { port: number; count: number; service: string }[];
}

export interface InitialData {
  logs: LogEvent[];
  alerts: Alert[];
  stats: Stats;
}
