/**
 * Time-series bucketing helpers.
 *
 * The dashboard keeps a fixed ring of one-minute buckets ("events over time").
 * Events must be counted into the bucket matching their own timestamp — not
 * blindly into the newest bucket — otherwise back-dated events (e.g. the
 * historical seed) all pile into the current minute and distort the chart.
 */

/**
 * Maps an event timestamp to the index of its one-minute bucket within a ring
 * of `bucketCount` buckets, where the last index represents the current minute.
 *
 * Older events map to lower indices; anything older than the window clamps to
 * bucket 0, and future/now events clamp to the last bucket. Pure and
 * deterministic given `nowMs`.
 */
export function bucketIndexForTimestamp(
  nowMs: number,
  eventIso: string,
  bucketCount: number
): number {
  const eventMs = new Date(eventIso).getTime();
  // Invalid timestamps fall into the current bucket rather than throwing.
  if (Number.isNaN(eventMs)) return bucketCount - 1;

  const minutesAgo = Math.floor((nowMs - eventMs) / 60_000);
  const idx = bucketCount - 1 - minutesAgo;

  if (idx < 0) return 0;
  if (idx > bucketCount - 1) return bucketCount - 1;
  return idx;
}
