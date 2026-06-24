import { describe, it, expect } from 'vitest';
import { parsePort, parseOrigins, parseRateLimit, loadConfig } from './config';

describe('parsePort', () => {
  it('returns the fallback when unset or blank', () => {
    expect(parsePort(undefined)).toBe(3001);
    expect(parsePort('')).toBe(3001);
    expect(parsePort('   ')).toBe(3001);
  });

  it('parses a valid port', () => {
    expect(parsePort('8080')).toBe(8080);
  });

  it('throws on non-numeric, out-of-range, or fractional ports', () => {
    expect(() => parsePort('abc')).toThrow();
    expect(() => parsePort('0')).toThrow();
    expect(() => parsePort('70000')).toThrow();
    expect(() => parsePort('80.5')).toThrow();
  });
});

describe('parseOrigins', () => {
  it('returns defaults when unset', () => {
    expect(parseOrigins(undefined)).toEqual([
      'http://localhost:5200',
      'http://localhost:3000',
    ]);
  });

  it('splits and trims a comma-separated list', () => {
    expect(parseOrigins(' http://a.com , http://b.com ')).toEqual([
      'http://a.com',
      'http://b.com',
    ]);
  });

  it('rejects the wildcard origin', () => {
    expect(() => parseOrigins('*')).toThrow();
    expect(() => parseOrigins('http://a.com,*')).toThrow();
  });

  it('rejects malformed origins', () => {
    expect(() => parseOrigins('not a url')).toThrow();
  });
});

describe('parseRateLimit', () => {
  it('returns the default when unset', () => {
    expect(parseRateLimit(undefined)).toBe(300);
  });

  it('parses positive integers', () => {
    expect(parseRateLimit('500')).toBe(500);
  });

  it('throws on zero, negatives, or non-integers', () => {
    expect(() => parseRateLimit('0')).toThrow();
    expect(() => parseRateLimit('-1')).toThrow();
    expect(() => parseRateLimit('1.5')).toThrow();
  });
});

describe('loadConfig', () => {
  it('builds a frozen config from a provided env', () => {
    const config = loadConfig({
      PORT: '4000',
      ALLOWED_ORIGINS: 'http://example.com',
      RATE_LIMIT_MAX: '100',
    } as NodeJS.ProcessEnv);

    expect(config.port).toBe(4000);
    expect(config.allowedOrigins).toEqual(['http://example.com']);
    expect(config.rateLimitMax).toBe(100);
    expect(Object.isFrozen(config)).toBe(true);
  });

  it('applies all defaults for an empty env', () => {
    const config = loadConfig({} as NodeJS.ProcessEnv);
    expect(config.port).toBe(3001);
    expect(config.rateLimitMax).toBe(300);
    expect(config.allowedOrigins.length).toBeGreaterThan(0);
  });
});
