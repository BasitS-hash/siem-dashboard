import { describe, it, expect } from 'vitest';
import {
  parseUrlhausCsv,
  geoFromCountryCode,
  getThreatData,
} from './threatIntelFeed';

describe('parseUrlhausCsv', () => {
  const header =
    '"id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"';

  it('skips comment lines and the header row', () => {
    const csv = ['# This is a comment', '# Another comment', header].join('\n');
    expect(parseUrlhausCsv(csv)).toEqual([]);
  });

  it('parses a well-formed online malware row', () => {
    const csv = [
      header,
      '"123","2024-01-01 00:00:00","http://evil.example/payload.bin","online","2024-01-02","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/123/","reporter1"',
    ].join('\n');

    const result = parseUrlhausCsv(csv);
    expect(result).toHaveLength(1);
    expect(result[0].url).toBe('http://evil.example/payload.bin');
    expect(result[0].status).toBe('online');
    expect(result[0].threat).toBe('malware_download');
    expect(result[0].tags).toEqual(['elf', 'mirai']);
  });

  it('treats "None" tags as an empty array', () => {
    const csv = [
      header,
      '"1","2024-01-01","http://x.example/a","offline","2024","malware","None","link","rep"',
    ].join('\n');
    expect(parseUrlhausCsv(csv)[0].tags).toEqual([]);
  });

  it('discards rows whose URL is not http(s)', () => {
    const csv = [
      header,
      '"1","2024-01-01","ftp://x.example/a","online","2024","malware","tag","link","rep"',
    ].join('\n');
    expect(parseUrlhausCsv(csv)).toEqual([]);
  });

  it('discards malformed rows with too few fields', () => {
    const csv = [header, '"1","2024-01-01","http://x.example/a"'].join('\n');
    expect(parseUrlhausCsv(csv)).toEqual([]);
  });

  it('handles an empty input gracefully', () => {
    expect(parseUrlhausCsv('')).toEqual([]);
  });
});

describe('geoFromCountryCode', () => {
  it('maps a known country code to full geo data', () => {
    const geo = geoFromCountryCode('US');
    expect(geo.country).toBe('United States');
    expect(geo.country_code).toBe('US');
    expect(typeof geo.lat).toBe('number');
    expect(typeof geo.lon).toBe('number');
  });

  it('falls back to a (0,0) placeholder for unknown codes', () => {
    const geo = geoFromCountryCode('ZZ');
    expect(geo.country_code).toBe('ZZ');
    expect(geo.lat).toBe(0);
    expect(geo.lon).toBe(0);
  });
});

describe('getThreatData', () => {
  it('always returns non-empty fallback data without network access', () => {
    const data = getThreatData();
    expect(data.c2Ips.length).toBeGreaterThan(0);
    expect(data.cves.length).toBeGreaterThan(0);
    expect(data.malwareUrls.length).toBeGreaterThan(0);
    expect(typeof data.lastUpdated).toBe('string');
  });
});
