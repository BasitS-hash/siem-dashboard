import { describe, it, expect } from 'vitest';
import { bucketIndexForTimestamp } from './timeBuckets';

describe('bucketIndexForTimestamp', () => {
  const COUNT = 30;
  const NOW = Date.UTC(2026, 0, 1, 12, 0, 0); // fixed reference "now"

  const isoMinutesAgo = (mins: number): string =>
    new Date(NOW - mins * 60_000).toISOString();

  it('places a current-minute event in the last bucket', () => {
    // Arrange
    const iso = isoMinutesAgo(0);

    // Act
    const idx = bucketIndexForTimestamp(NOW, iso, COUNT);

    // Assert
    expect(idx).toBe(COUNT - 1);
  });

  it('places an event N minutes old N buckets back from the end', () => {
    expect(bucketIndexForTimestamp(NOW, isoMinutesAgo(1), COUNT)).toBe(COUNT - 2);
    expect(bucketIndexForTimestamp(NOW, isoMinutesAgo(5), COUNT)).toBe(COUNT - 6);
    expect(bucketIndexForTimestamp(NOW, isoMinutesAgo(29), COUNT)).toBe(0);
  });

  it('distributes back-dated seed events across distinct buckets (regression)', () => {
    // Arrange: three events spread across the window must not collapse into one bucket.
    const buckets = [0, 10, 25].map(mins =>
      bucketIndexForTimestamp(NOW, isoMinutesAgo(mins), COUNT)
    );

    // Assert
    expect(new Set(buckets).size).toBe(3);
    expect(buckets).toEqual([29, 19, 4]);
  });

  it('clamps events older than the window to the first bucket', () => {
    expect(bucketIndexForTimestamp(NOW, isoMinutesAgo(90), COUNT)).toBe(0);
  });

  it('clamps future-dated events to the last bucket', () => {
    const future = new Date(NOW + 5 * 60_000).toISOString();
    expect(bucketIndexForTimestamp(NOW, future, COUNT)).toBe(COUNT - 1);
  });

  it('falls back to the current bucket for an unparseable timestamp', () => {
    expect(bucketIndexForTimestamp(NOW, 'not-a-date', COUNT)).toBe(COUNT - 1);
  });
});
