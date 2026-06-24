import { describe, it, expect } from 'vitest';
import { generateEvent, generateBurst, pickC2Ip } from './logGenerator';
import { Severity, EventCategory } from './types';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORIES: EventCategory[] = ['authentication', 'network', 'web', 'system', 'firewall'];

describe('generateEvent', () => {
  it('produces a structurally valid LogEvent', () => {
    const e = generateEvent();
    expect(e.id).toBeTruthy();
    expect(e.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(SEVERITIES).toContain(e.severity);
    expect(CATEGORIES).toContain(e.category);
    expect(e.source_ip).toBeTruthy();
    expect(e.destination_ip).toBeTruthy();
    expect(e.destination_port).toBeGreaterThan(0);
    expect(Array.isArray(e.tags)).toBe(true);
    expect(typeof e.message).toBe('string');
    expect(e.message.length).toBeGreaterThan(0);
  });

  it('honors a forced source IP', () => {
    const e = generateEvent('185.220.101.45');
    expect(e.source_ip).toBe('185.220.101.45');
  });

  it('generates unique ids across calls', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateEvent().id));
    expect(ids.size).toBe(100);
  });

  it('produces valid severities across many samples', () => {
    for (let i = 0; i < 500; i++) {
      expect(SEVERITIES).toContain(generateEvent().severity);
    }
  });
});

describe('generateBurst', () => {
  it('returns the requested number of events', () => {
    expect(generateBurst(25)).toHaveLength(25);
  });

  it('returns an empty array for a zero count', () => {
    expect(generateBurst(0)).toEqual([]);
  });

  it('applies a forced source IP to all events in the burst', () => {
    const burst = generateBurst(10, '8.8.8.8');
    expect(burst.every(e => e.source_ip === '8.8.8.8')).toBe(true);
  });
});

describe('pickC2Ip', () => {
  it('returns a non-empty IP string', () => {
    const ip = pickC2Ip();
    expect(typeof ip).toBe('string');
    expect(ip).toMatch(/^\d{1,3}(\.\d{1,3}){3}$/);
  });
});
