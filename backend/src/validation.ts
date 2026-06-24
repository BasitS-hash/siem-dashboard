/**
 * Input validation helpers for REST endpoints and socket events.
 * Pure functions — no Express/Socket.io coupling — so they are unit-testable
 * and reusable across transport layers.
 */

export type AlertStatus = 'active' | 'acknowledged' | 'resolved';

const VALID_STATUSES: readonly AlertStatus[] = ['active', 'acknowledged', 'resolved'];

const MAX_ID_LENGTH = 64;
// Alert IDs are UUIDs; allow the broader hyphen/alphanumeric set used by uuid.
const ID_PATTERN = /^[A-Za-z0-9-]{1,64}$/;

export interface ValidationResult<T> {
  ok: boolean;
  value?: T;
  error?: string;
}

/** Validates an alert id from a route parameter. */
export function validateAlertId(raw: unknown): ValidationResult<string> {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_ID_LENGTH) {
    return { ok: false, error: 'Invalid id' };
  }
  if (!ID_PATTERN.test(raw)) {
    return { ok: false, error: 'Invalid id format' };
  }
  return { ok: true, value: raw };
}

/** Validates the `status` field of an alert-update request body. */
export function validateAlertStatus(raw: unknown): ValidationResult<AlertStatus> {
  if (typeof raw !== 'string' || !VALID_STATUSES.includes(raw as AlertStatus)) {
    return { ok: false, error: 'Invalid status' };
  }
  return { ok: true, value: raw as AlertStatus };
}

/** Clamps a `limit` query value into a safe [min, max] range with a default. */
export function parseLimit(
  raw: unknown,
  { def = 200, min = 1, max = 500 }: { def?: number; min?: number; max?: number } = {}
): number {
  const parsed = typeof raw === 'string' ? parseInt(raw, 10) : NaN;
  if (Number.isNaN(parsed)) return def;
  return Math.min(Math.max(parsed, min), max);
}
