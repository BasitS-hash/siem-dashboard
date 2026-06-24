import { describe, it, expect } from 'vitest';
import { validateAlertId, validateAlertStatus, parseLimit } from './validation';

describe('validateAlertId', () => {
  it('accepts a valid UUID', () => {
    const result = validateAlertId('550e8400-e29b-41d4-a716-446655440000');
    expect(result.ok).toBe(true);
    expect(result.value).toBe('550e8400-e29b-41d4-a716-446655440000');
  });

  it('rejects non-string input', () => {
    expect(validateAlertId(123).ok).toBe(false);
    expect(validateAlertId(undefined).ok).toBe(false);
    expect(validateAlertId(null).ok).toBe(false);
  });

  it('rejects empty strings', () => {
    expect(validateAlertId('').ok).toBe(false);
  });

  it('rejects ids longer than 64 chars', () => {
    expect(validateAlertId('a'.repeat(65)).ok).toBe(false);
  });

  it('rejects ids with injection characters', () => {
    expect(validateAlertId('abc; DROP TABLE').ok).toBe(false);
    expect(validateAlertId('../../etc/passwd').ok).toBe(false);
    expect(validateAlertId('<script>').ok).toBe(false);
  });
});

describe('validateAlertStatus', () => {
  it.each(['active', 'acknowledged', 'resolved'])('accepts "%s"', (status) => {
    const result = validateAlertStatus(status);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(status);
  });

  it('rejects unknown statuses', () => {
    expect(validateAlertStatus('deleted').ok).toBe(false);
    expect(validateAlertStatus('ACTIVE').ok).toBe(false);
  });

  it('rejects non-string input', () => {
    expect(validateAlertStatus(true).ok).toBe(false);
    expect(validateAlertStatus(undefined).ok).toBe(false);
  });
});

describe('parseLimit', () => {
  it('returns the default for missing/invalid input', () => {
    expect(parseLimit(undefined)).toBe(200);
    expect(parseLimit('abc')).toBe(200);
    expect(parseLimit(null)).toBe(200);
  });

  it('clamps values above the max', () => {
    expect(parseLimit('99999')).toBe(500);
  });

  it('clamps values below the min', () => {
    expect(parseLimit('0')).toBe(1);
    expect(parseLimit('-50')).toBe(1);
  });

  it('returns valid in-range values unchanged', () => {
    expect(parseLimit('250')).toBe(250);
  });

  it('respects custom bounds', () => {
    expect(parseLimit('1000', { def: 10, min: 5, max: 100 })).toBe(100);
  });
});
