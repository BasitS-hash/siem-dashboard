import { Alert, LogEvent } from '../types';

function escapeCsv(val: unknown): string {
  const s = String(val ?? '');
  return s.includes(',') || s.includes('"') || s.includes('\n')
    ? `"${s.replace(/"/g, '""')}"`
    : s;
}

function downloadCsv(filename: string, rows: string[][]): void {
  const csv = rows.map(r => r.map(escapeCsv).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportAlertsCsv(alerts: Alert[]): void {
  const header = [
    'ID', 'Timestamp', 'Severity', 'Type', 'Title',
    'Source IP', 'Status', 'MITRE Tactic', 'MITRE Technique ID',
    'Affected Users', 'Event Count',
  ];
  const rows = alerts.map(a => [
    a.id, a.timestamp, a.severity, a.type, a.title,
    a.source_ip, a.status, a.mitre_tactic, a.mitre_technique_id,
    a.affected_users.join('; '), String(a.event_count),
  ]);
  downloadCsv(`siem-alerts-${new Date().toISOString().slice(0, 10)}.csv`, [header, ...rows]);
}

export function exportLogsCsv(logs: LogEvent[]): void {
  const header = [
    'ID', 'Timestamp', 'Severity', 'Category', 'Source IP',
    'Destination IP', 'Destination Port', 'Protocol', 'User',
    'Hostname', 'Action', 'Message',
  ];
  const rows = logs.map(l => [
    l.id, l.timestamp, l.severity, l.category, l.source_ip,
    l.destination_ip, String(l.destination_port), l.protocol,
    l.user ?? '', l.hostname, l.action, l.message,
  ]);
  downloadCsv(`siem-logs-${new Date().toISOString().slice(0, 10)}.csv`, [header, ...rows]);
}
