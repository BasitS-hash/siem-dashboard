/**
 * Startup configuration & validation.
 *
 * Parses and validates environment variables once at boot. Invalid values
 * fail fast with a clear message rather than producing subtle runtime bugs
 * (e.g. a NaN port silently binding to a random one).
 */

export interface AppConfig {
  port: number;
  allowedOrigins: string[];
  /** Max requests per IP per minute against /api. */
  rateLimitMax: number;
}

const DEFAULT_PORT = 3001;
const DEFAULT_ORIGINS = ['http://localhost:5200', 'http://localhost:3000'];
const DEFAULT_RATE_LIMIT = 300;

const MIN_PORT = 1;
const MAX_PORT = 65535;

/** Parses a port string, returning a validated number or throwing. */
export function parsePort(raw: string | undefined, fallback: number = DEFAULT_PORT): number {
  if (raw === undefined || raw.trim() === '') return fallback;

  const port = Number(raw);
  if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
    throw new Error(`Invalid PORT "${raw}": must be an integer in [${MIN_PORT}, ${MAX_PORT}]`);
  }
  return port;
}

/** Splits a comma-separated origin list, trimming blanks. Falls back to defaults. */
export function parseOrigins(raw: string | undefined): string[] {
  if (raw === undefined || raw.trim() === '') return [...DEFAULT_ORIGINS];

  const origins = raw
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

  if (origins.length === 0) return [...DEFAULT_ORIGINS];

  for (const origin of origins) {
    // Reject wildcard origins — they defeat the purpose of an allowlist.
    if (origin === '*') {
      throw new Error('ALLOWED_ORIGINS must not contain "*"; specify explicit origins');
    }
    try {
      // eslint-disable-next-line no-new
      new URL(origin);
    } catch {
      throw new Error(`Invalid origin in ALLOWED_ORIGINS: "${origin}"`);
    }
  }
  return origins;
}

/** Parses a positive-integer rate-limit value. */
export function parseRateLimit(raw: string | undefined, fallback: number = DEFAULT_RATE_LIMIT): number {
  if (raw === undefined || raw.trim() === '') return fallback;

  const max = Number(raw);
  if (!Number.isInteger(max) || max <= 0) {
    throw new Error(`Invalid RATE_LIMIT_MAX "${raw}": must be a positive integer`);
  }
  return max;
}

/** Reads, validates, and freezes the application config from the environment. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return Object.freeze({
    port: parsePort(env.PORT),
    allowedOrigins: parseOrigins(env.ALLOWED_ORIGINS),
    rateLimitMax: parseRateLimit(env.RATE_LIMIT_MAX),
  });
}
