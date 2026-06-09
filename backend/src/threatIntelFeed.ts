/**
 * Threat Intelligence Feed
 *
 * Fetches real-world threat data from three no-auth public sources:
 *  1. abuse.ch Feodo Tracker   — active C2 botnet IPs (QakBot, Emotet, etc.)
 *  2. abuse.ch URLhaus CSV     — recent malware download URLs
 *  3. CISA Known Exploited Vulnerabilities — real CVE IDs + descriptions
 *
 * All fetches are non-blocking. On failure the module falls back to built-in
 * defaults so the dashboard keeps running without network access.
 */

import { GeoInfo } from './types';

// ─── Public interfaces ──────────────────────────────────────────────────────

export interface C2Entry {
  ip: string;
  port: number;
  malware: string;
  country: string;
  asName: string;
  geo: GeoInfo;
  firstSeen: string;
}

export interface MalwareUrlEntry {
  url: string;
  threat: string;
  tags: string[];
  status: 'online' | 'offline';
}

export interface CveEntry {
  id: string;
  vendor: string;
  product: string;
  name: string;
  description: string;
}

export interface ThreatData {
  c2Ips: C2Entry[];
  malwareUrls: MalwareUrlEntry[];
  cves: CveEntry[];
  lastUpdated: string;
}

// ─── Country code → approximate city/lat/lon lookup ────────────────────────

interface GeoDefaults { country: string; city: string; lat: number; lon: number }

const COUNTRY_GEO: Record<string, GeoDefaults> = {
  US: { country: 'United States',  city: 'Ashburn',      lat:  39.04,  lon:  -77.49 },
  GB: { country: 'United Kingdom', city: 'London',        lat:  51.51,  lon:   -0.13 },
  DE: { country: 'Germany',        city: 'Frankfurt',     lat:  50.11,  lon:    8.68 },
  NL: { country: 'Netherlands',    city: 'Amsterdam',     lat:  52.37,  lon:    4.90 },
  FR: { country: 'France',         city: 'Paris',         lat:  48.85,  lon:    2.35 },
  RU: { country: 'Russia',         city: 'Moscow',        lat:  55.75,  lon:   37.62 },
  CN: { country: 'China',          city: 'Beijing',       lat:  39.90,  lon:  116.40 },
  JP: { country: 'Japan',          city: 'Tokyo',         lat:  35.69,  lon:  139.69 },
  BR: { country: 'Brazil',         city: 'São Paulo',     lat: -23.54,  lon:  -46.63 },
  IN: { country: 'India',          city: 'Mumbai',        lat:  19.07,  lon:   72.87 },
  UA: { country: 'Ukraine',        city: 'Kyiv',          lat:  50.45,  lon:   30.52 },
  TR: { country: 'Turkey',         city: 'Istanbul',      lat:  41.01,  lon:   28.96 },
  RO: { country: 'Romania',        city: 'Bucharest',     lat:  44.43,  lon:   26.10 },
  PL: { country: 'Poland',         city: 'Warsaw',        lat:  52.23,  lon:   21.01 },
  HK: { country: 'Hong Kong',      city: 'Hong Kong',     lat:  22.32,  lon:  114.17 },
  SG: { country: 'Singapore',      city: 'Singapore',     lat:   1.35,  lon:  103.82 },
  KR: { country: 'South Korea',    city: 'Seoul',         lat:  37.57,  lon:  126.98 },
  IR: { country: 'Iran',           city: 'Tehran',        lat:  35.69,  lon:   51.42 },
  VN: { country: 'Vietnam',        city: 'Hanoi',         lat:  21.03,  lon:  105.85 },
  ID: { country: 'Indonesia',      city: 'Jakarta',       lat:  -6.21,  lon:  106.85 },
  AU: { country: 'Australia',      city: 'Sydney',        lat: -33.87,  lon:  151.21 },
  CA: { country: 'Canada',         city: 'Toronto',       lat:  43.65,  lon:  -79.38 },
  MX: { country: 'Mexico',         city: 'Mexico City',   lat:  19.43,  lon:  -99.13 },
  ZA: { country: 'South Africa',   city: 'Johannesburg',  lat: -26.20,  lon:   28.04 },
  NG: { country: 'Nigeria',        city: 'Lagos',         lat:   6.52,  lon:    3.38 },
  BG: { country: 'Bulgaria',       city: 'Sofia',         lat:  42.70,  lon:   23.32 },
  CZ: { country: 'Czechia',        city: 'Prague',        lat:  50.08,  lon:   14.43 },
  HU: { country: 'Hungary',        city: 'Budapest',      lat:  47.50,  lon:   19.04 },
  AT: { country: 'Austria',        city: 'Vienna',        lat:  48.21,  lon:   16.37 },
  CH: { country: 'Switzerland',    city: 'Zurich',        lat:  47.38,  lon:    8.54 },
  SE: { country: 'Sweden',         city: 'Stockholm',     lat:  59.33,  lon:   18.07 },
  NO: { country: 'Norway',         city: 'Oslo',          lat:  59.91,  lon:   10.75 },
  FI: { country: 'Finland',        city: 'Helsinki',      lat:  60.17,  lon:   24.94 },
  IT: { country: 'Italy',          city: 'Milan',         lat:  45.46,  lon:    9.19 },
  ES: { country: 'Spain',          city: 'Madrid',        lat:  40.42,  lon:   -3.70 },
  PT: { country: 'Portugal',       city: 'Lisbon',        lat:  38.72,  lon:   -9.14 },
  IL: { country: 'Israel',         city: 'Tel Aviv',      lat:  32.07,  lon:   34.79 },
  SA: { country: 'Saudi Arabia',   city: 'Riyadh',        lat:  24.69,  lon:   46.72 },
  PK: { country: 'Pakistan',       city: 'Karachi',       lat:  24.86,  lon:   67.01 },
  TH: { country: 'Thailand',       city: 'Bangkok',       lat:  13.75,  lon:  100.52 },
  MY: { country: 'Malaysia',       city: 'Kuala Lumpur',  lat:   3.14,  lon:  101.69 },
};

function geoFromCountryCode(code: string): GeoInfo {
  const g = COUNTRY_GEO[code];
  if (g) {
    return { country: g.country, country_code: code, city: g.city, lat: g.lat, lon: g.lon };
  }
  // Unknown country — place at prime meridian / equator
  return { country: code, country_code: code, city: 'Unknown', lat: 0, lon: 0 };
}

// ─── Feodo Tracker ──────────────────────────────────────────────────────────

interface FeodoEntry {
  ip_address: string;
  port: number;
  status: string;
  hostname: string;
  as_number: number;
  as_name: string;
  country: string;
  first_seen: string;
  last_online: string;
  malware: string;
}

async function fetchFeodoTracker(): Promise<C2Entry[]> {
  const url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';
  const res = await fetch(url, {
    headers: { 'User-Agent': 'SIEM-Dashboard/1.0 (research)' },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Feodo HTTP ${res.status}`);

  const raw = (await res.json()) as FeodoEntry[];
  return raw.map((e): C2Entry => ({
    ip:        e.ip_address,
    port:      e.port,
    malware:   e.malware,
    country:   e.country,
    asName:    e.as_name ?? 'Unknown AS',
    geo:       geoFromCountryCode(e.country),
    firstSeen: e.first_seen,
  }));
}

// ─── URLhaus ────────────────────────────────────────────────────────────────

function parseUrlhausCsv(csv: string): MalwareUrlEntry[] {
  const lines = csv.split('\n');
  const results: MalwareUrlEntry[] = [];

  for (const line of lines) {
    // Skip comments and header
    if (line.startsWith('#') || line.startsWith('"id"') || line.trim() === '') continue;

    // CSV fields: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    const parts = line.match(/("(?:[^"]|"")*"|[^,]*)/g);
    if (!parts || parts.length < 7) continue;

    const unquote = (s: string) => s.replace(/^"|"$/g, '').replace(/""/g, '"').trim();
    const urlVal    = unquote(parts[2] ?? '');
    const status    = unquote(parts[3] ?? '') as 'online' | 'offline';
    const threat    = unquote(parts[5] ?? '');
    const tagsRaw   = unquote(parts[6] ?? '');
    const tags      = tagsRaw === 'None' ? [] : tagsRaw.split(',').map(t => t.trim()).filter(Boolean);

    if (!urlVal || !urlVal.startsWith('http')) continue;
    results.push({ url: urlVal, threat, tags, status });
  }

  return results;
}

async function fetchUrlhaus(): Promise<MalwareUrlEntry[]> {
  const url = 'https://urlhaus.abuse.ch/downloads/csv_recent/';
  const res = await fetch(url, {
    headers: { 'User-Agent': 'SIEM-Dashboard/1.0 (research)' },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`URLhaus HTTP ${res.status}`);
  const csv = await res.text();
  return parseUrlhausCsv(csv);
}

// ─── CISA Known Exploited Vulnerabilities ──────────────────────────────────

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
}

async function fetchCisaKev(): Promise<CveEntry[]> {
  const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const res = await fetch(url, {
    headers: { 'User-Agent': 'SIEM-Dashboard/1.0 (research)' },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`CISA KEV HTTP ${res.status}`);

  const body = (await res.json()) as { vulnerabilities: KevEntry[] };
  return (body.vulnerabilities ?? []).map((v): CveEntry => ({
    id:          v.cveID,
    vendor:      v.vendorProject,
    product:     v.product,
    name:        v.vulnerabilityName,
    description: v.shortDescription,
  }));
}

// ─── Fallback data ──────────────────────────────────────────────────────────

const FALLBACK_C2: C2Entry[] = [
  { ip: '185.220.101.45', port: 443, malware: 'QakBot',  country: 'RU', asName: 'Tor Exit', geo: geoFromCountryCode('RU'), firstSeen: '2024-01-01 00:00:00' },
  { ip: '103.214.147.20', port: 443, malware: 'Emotet',  country: 'CN', asName: 'Alibaba',  geo: geoFromCountryCode('CN'), firstSeen: '2024-01-01 00:00:00' },
  { ip: '91.108.4.200',   port: 80,  malware: 'IcedID',  country: 'IR', asName: 'Unknown',  geo: geoFromCountryCode('IR'), firstSeen: '2024-01-01 00:00:00' },
  { ip: '194.165.16.78',  port: 8080, malware: 'Dridex', country: 'UA', asName: 'Unknown',  geo: geoFromCountryCode('UA'), firstSeen: '2024-01-01 00:00:00' },
  { ip: '136.243.154.200',port: 443, malware: 'Cobalt Strike', country: 'DE', asName: 'Hetzner', geo: geoFromCountryCode('DE'), firstSeen: '2024-01-01 00:00:00' },
];

const FALLBACK_MALWARE_URLS: MalwareUrlEntry[] = [
  { url: 'http://192.168.evil.example/payload.bin', threat: 'malware_download', tags: ['elf', 'mirai'], status: 'online' },
];

const FALLBACK_CVES: CveEntry[] = [
  { id: 'CVE-2024-3400', vendor: 'Palo Alto',   product: 'PAN-OS',      name: 'OS Command Injection', description: 'OS command injection in PAN-OS GlobalProtect.' },
  { id: 'CVE-2024-1708', vendor: 'ConnectWise', product: 'ScreenConnect', name: 'Path Traversal',     description: 'Path-traversal vulnerability in ConnectWise ScreenConnect.' },
  { id: 'CVE-2023-46604',vendor: 'Apache',      product: 'ActiveMQ',    name: 'RCE via ClassInfo',    description: 'Remote code execution in Apache ActiveMQ.' },
];

// ─── Module state ────────────────────────────────────────────────────────────

let threatData: ThreatData = {
  c2Ips:        FALLBACK_C2,
  malwareUrls:  FALLBACK_MALWARE_URLS,
  cves:         FALLBACK_CVES,
  lastUpdated:  new Date(0).toISOString(),
};

async function refresh(): Promise<void> {
  const results = await Promise.allSettled([
    fetchFeodoTracker(),
    fetchUrlhaus(),
    fetchCisaKev(),
  ]);

  const [feodoResult, urlhausResult, kevResult] = results;

  const c2Ips = feodoResult.status === 'fulfilled' && feodoResult.value.length > 0
    ? feodoResult.value
    : threatData.c2Ips;

  const malwareUrls = urlhausResult.status === 'fulfilled' && urlhausResult.value.length > 0
    ? urlhausResult.value
    : threatData.malwareUrls;

  const cves = kevResult.status === 'fulfilled' && kevResult.value.length > 0
    ? kevResult.value
    : threatData.cves;

  // Log outcomes
  const feodoStatus  = feodoResult.status  === 'fulfilled' ? `${c2Ips.length} C2 IPs`    : `failed (${(feodoResult.reason as Error).message})`;
  const urlhausStatus= urlhausResult.status === 'fulfilled' ? `${malwareUrls.length} URLs` : `failed (${(urlhausResult.reason as Error).message})`;
  const kevStatus    = kevResult.status    === 'fulfilled' ? `${cves.length} CVEs`        : `failed (${(kevResult.reason as Error).message})`;
  console.log(`[ThreatIntel] Feodo: ${feodoStatus} | URLhaus: ${urlhausStatus} | CISA KEV: ${kevStatus}`);

  threatData = { c2Ips, malwareUrls, cves, lastUpdated: new Date().toISOString() };
}

// ─── Public API ──────────────────────────────────────────────────────────────

/** Returns the latest cached threat data (never throws). */
export function getThreatData(): ThreatData {
  return threatData;
}

/**
 * Initialises the feed and schedules hourly refresh.
 * Call once at startup — non-blocking.
 */
export function initThreatFeed(): void {
  // First fetch — don't await, dashboard starts immediately with fallback data
  refresh().catch(err => console.error('[ThreatIntel] Initial fetch error:', err));

  // Refresh every hour
  setInterval(() => {
    refresh().catch(err => console.error('[ThreatIntel] Refresh error:', err));
  }, 60 * 60 * 1_000);
}
