import { Alert, LogEvent } from '../types';

// Characters that trigger formula evaluation in Excel / Sheets / LibreOffice.
const FORMULA_TRIGGERS = ['=', '+', '-', '@', '\t', '\r'];

/**
 * Escapes a value for safe CSV output.
 *
 * Guards against two classes of issue:
 *  1. CSV structure breakage (commas, quotes, newlines) via RFC 4180 quoting.
 *  2. CSV formula injection (a.k.a. CSV/Excel macro injection) — a cell that
 *     begins with =, +, -, @, tab, or CR is prefixed with a single quote so
 *     spreadsheet software treats it as text, never as an executable formula.
 */
export function escapeCsv(val: unknown): string {
  let s = String(val ?? '');

  // Neutralise formula injection before structural quoting.
  if (s.length > 0 && FORMULA_TRIGGERS.includes(s[0])) {
    s = `'${s}`;
  }

  return s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')
    ? `"${s.replace(/"/g, '""')}"`
    : s;
}

/** Serialises a 2D string matrix into an RFC 4180 / injection-safe CSV string. */
export function buildCsv(rows: string[][]): string {
  return rows.map(r => r.map(escapeCsv).join(',')).join('\n');
}

const ALERT_HEADER = [
  'ID', 'Timestamp', 'Severity', 'Type', 'Title',
  'Source IP', 'Status', 'MITRE Tactic', 'MITRE Technique ID',
  'Affected Users', 'Event Count',
];

const LOG_HEADER = [
  'ID', 'Timestamp', 'Severity', 'Category', 'Source IP',
  'Destination IP', 'Destination Port', 'Protocol', 'User',
  'Hostname', 'Action', 'Message',
];

/** Builds the full alerts CSV (header + rows). Pure — no DOM access. */
export function buildAlertsCsv(alerts: Alert[]): string {
  const rows = alerts.map(a => [
    a.id, a.timestamp, a.severity, a.type, a.title,
    a.source_ip, a.status, a.mitre_tactic, a.mitre_technique_id,
    a.affected_users.join('; '), String(a.event_count),
  ]);
  return buildCsv([ALERT_HEADER, ...rows]);
}

/** Builds the full logs CSV (header + rows). Pure — no DOM access. */
export function buildLogsCsv(logs: LogEvent[]): string {
  const rows = logs.map(l => [
    l.id, l.timestamp, l.severity, l.category, l.source_ip,
    l.destination_ip, String(l.destination_port), l.protocol,
    l.user ?? '', l.hostname, l.action, l.message,
  ]);
  return buildCsv([LOG_HEADER, ...rows]);
}

function triggerDownload(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function todayStamp(): string {
  return new Date().toISOString().slice(0, 10);
}

export function exportAlertsCsv(alerts: Alert[]): void {
  triggerDownload(`siem-alerts-${todayStamp()}.csv`, buildAlertsCsv(alerts));
}

export function exportLogsCsv(logs: LogEvent[]): void {
  triggerDownload(`siem-logs-${todayStamp()}.csv`, buildLogsCsv(logs));
}
