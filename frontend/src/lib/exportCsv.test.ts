import { describe, it, expect } from 'vitest';
import {
  escapeCsv,
  buildCsv,
  buildAlertsCsv,
  buildLogsCsv,
} from './exportCsv';
import { Alert, LogEvent } from '../types';

describe('escapeCsv — structural quoting', () => {
  it('leaves plain values untouched', () => {
    expect(escapeCsv('hello')).toBe('hello');
    expect(escapeCsv(42)).toBe('42');
  });

  it('quotes values containing commas', () => {
    expect(escapeCsv('a,b')).toBe('"a,b"');
  });

  it('escapes embedded double quotes by doubling', () => {
    expect(escapeCsv('say "hi"')).toBe('"say ""hi"""');
  });

  it('quotes values with newlines and carriage returns', () => {
    expect(escapeCsv('line1\nline2')).toBe('"line1\nline2"');
    expect(escapeCsv('a\rb')).toBe('"a\rb"');
  });

  it('renders null/undefined as an empty string', () => {
    expect(escapeCsv(null)).toBe('');
    expect(escapeCsv(undefined)).toBe('');
  });
});

describe('escapeCsv — formula injection defense', () => {
  it.each(['=', '+', '-', '@'])(
    'prefixes a leading "%s" with a single quote',
    (trigger) => {
      const out = escapeCsv(`${trigger}cmd`);
      expect(out.startsWith("'")).toBe(true);
    }
  );

  it('neutralizes a classic Excel command-injection payload', () => {
    const payload = '=cmd|"/c calc"!A1';
    const out = escapeCsv(payload);
    // Must be prefixed so the cell is treated as text, and quoted due to comma/quote.
    expect(out).toContain("'=cmd");
    expect(out.startsWith("'") || out.startsWith('"')).toBe(true);
  });

  it('neutralizes a hyperlink-exfiltration payload', () => {
    const out = escapeCsv('@SUM(1+1)*cmd');
    expect(out.startsWith("'")).toBe(true);
  });

  it('does not prefix a value with an interior trigger char', () => {
    expect(escapeCsv('a=b')).toBe('a=b');
  });
});

describe('buildCsv', () => {
  it('joins rows with newlines and cells with commas', () => {
    const csv = buildCsv([
      ['a', 'b'],
      ['c', 'd'],
    ]);
    expect(csv).toBe('a,b\nc,d');
  });

  it('applies escaping per cell', () => {
    const csv = buildCsv([['=danger', 'safe']]);
    expect(csv.startsWith("'=danger")).toBe(true);
  });
});

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'a1',
    timestamp: '2026-01-01T00:00:00.000Z',
    severity: 'critical',
    type: 'sql_injection',
    title: 'SQL Injection',
    description: 'desc',
    source_ip: '203.0.113.5',
    destination_ips: ['10.0.1.50'],
    affected_users: ['admin', 'root'],
    event_count: 3,
    status: 'active',
    mitre_tactic: 'Initial Access',
    mitre_technique: 'Exploit Public-Facing Application',
    mitre_technique_id: 'T1190',
    related_event_ids: ['e1'],
    first_seen: '2026-01-01T00:00:00.000Z',
    last_seen: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('buildAlertsCsv', () => {
  it('produces a header row plus one row per alert', () => {
    const csv = buildAlertsCsv([makeAlert(), makeAlert({ id: 'a2' })]);
    const lines = csv.split('\n');
    expect(lines).toHaveLength(3); // header + 2 data rows
    expect(lines[0]).toContain('MITRE Tactic');
  });

  it('joins affected users with a semicolon', () => {
    const csv = buildAlertsCsv([makeAlert()]);
    expect(csv).toContain('admin; root');
  });

  it('neutralizes a malicious title that begins with a formula char', () => {
    const csv = buildAlertsCsv([makeAlert({ title: '=HYPERLINK("http://evil")' })]);
    expect(csv).toContain("'=HYPERLINK");
  });

  it('handles an empty alert list (header only)', () => {
    const csv = buildAlertsCsv([]);
    expect(csv.split('\n')).toHaveLength(1);
  });
});

function makeLog(overrides: Partial<LogEvent> = {}): LogEvent {
  return {
    id: 'l1',
    timestamp: '2026-01-01T00:00:00.000Z',
    severity: 'high',
    category: 'web',
    source_ip: '198.51.100.7',
    destination_ip: '10.0.1.50',
    source_port: 50000,
    destination_port: 443,
    protocol: 'HTTP/HTTPS',
    hostname: 'web-srv-01',
    message: 'GET /api/users',
    raw: 'raw',
    tags: ['web'],
    action: 'allow',
    ...overrides,
  };
}

describe('buildLogsCsv', () => {
  it('produces a header plus one row per log', () => {
    const csv = buildLogsCsv([makeLog(), makeLog({ id: 'l2' })]);
    expect(csv.split('\n')).toHaveLength(3);
  });

  it('renders a missing user as an empty cell', () => {
    const csv = buildLogsCsv([makeLog({ user: undefined })]);
    const dataRow = csv.split('\n')[1];
    // user column is between protocol and hostname; ensure no "undefined" leaks
    expect(dataRow).not.toContain('undefined');
  });

  it('quotes a message that contains a comma', () => {
    const csv = buildLogsCsv([makeLog({ message: 'GET /a, POST /b' })]);
    expect(csv).toContain('"GET /a, POST /b"');
  });
});
