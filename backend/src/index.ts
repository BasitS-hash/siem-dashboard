import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { generateEvent, generateBurst, pickC2Ip } from './logGenerator';
import { ThreatDetector } from './threatDetector';
import { initThreatFeed, getThreatData } from './threatIntelFeed';
import { LogEvent, Alert, Stats, TimeSeriesPoint } from './types';
import { loadConfig, AppConfig } from './config';
import { validateAlertId, validateAlertStatus, parseLimit } from './validation';

// Validate environment at startup — fail fast on bad config.
function loadConfigOrExit(): AppConfig {
  try {
    return loadConfig();
  } catch (err) {
    console.error('[CONFIG] Invalid configuration:', (err as Error).message);
    process.exit(1);
  }
}
const config = loadConfigOrExit();

const app = express();
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: { origin: config.allowedOrigins, methods: ['GET', 'POST'] },
  maxHttpBufferSize: 1e6, // 1 MB cap on inbound socket payloads
});

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false })); // CSP handled by frontend
app.use(cors({ origin: config.allowedOrigins }));
app.use(express.json({ limit: '10kb' }));

const apiLimiter = rateLimit({
  windowMs: 60_000,
  max: config.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
});
app.use('/api', apiLimiter);

// ─── Threat intel feed ────────────────────────────────────────────────────────
initThreatFeed(); // non-blocking; falls back to built-ins while fetching

// ─── In-memory store ───────────────────────────────────────────────────────────
const MAX_LOGS = 2000;
const logs: LogEvent[] = [];
const alerts: Alert[] = [];
const detector = new ThreatDetector();

const TIME_BUCKETS = 30;
const timeSeries: TimeSeriesPoint[] = Array.from({ length: TIME_BUCKETS }, (_, i) => {
  const d = new Date(Date.now() - (TIME_BUCKETS - 1 - i) * 60_000);
  return { time: d.toISOString(), count: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
});

let totalEvents = 0;
let eventTimestamps: number[] = [];
const ipCounts = new Map<string, number>();
const categoryCounts = new Map<string, number>();
const severityCounts = new Map<string, number>();
const portCounts = new Map<number, number>();

// Module-level constants — not recreated on every computeStats() call
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff4444', high: '#ff8c00', medium: '#ffd700', low: '#00bfff', info: '#6e7681',
};
const PORT_SERVICES: Record<number, string> = {
  22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 3306: 'MySQL',
  1433: 'MSSQL', 445: 'SMB', 21: 'FTP', 23: 'Telnet', 8080: 'HTTP-Alt',
};

function addLog(event: LogEvent): Alert | null {
  logs.unshift(event);
  if (logs.length > MAX_LOGS) logs.pop();

  totalEvents++;
  eventTimestamps.push(Date.now());
  const cutoff = Date.now() - 60_000;
  eventTimestamps = eventTimestamps.filter(t => t > cutoff);

  ipCounts.set(event.source_ip, (ipCounts.get(event.source_ip) ?? 0) + 1);
  categoryCounts.set(event.category, (categoryCounts.get(event.category) ?? 0) + 1);
  severityCounts.set(event.severity, (severityCounts.get(event.severity) ?? 0) + 1);
  portCounts.set(event.destination_port, (portCounts.get(event.destination_port) ?? 0) + 1);

  const bucket = timeSeries[timeSeries.length - 1];
  bucket.count++;
  // Increment the typed severity counter directly — avoids unsafe index cast
  if (event.severity === 'critical') bucket.critical++;
  else if (event.severity === 'high') bucket.high++;
  else if (event.severity === 'medium') bucket.medium++;
  else if (event.severity === 'low') bucket.low++;
  else bucket.info++;

  return detector.processEvent(event);
}

function computeStats(): Stats {
  const topIps = [...ipCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));

  const severityBreakdown = ['critical', 'high', 'medium', 'low', 'info'].map(s => ({
    severity: s, count: severityCounts.get(s) ?? 0, color: SEVERITY_COLORS[s],
  }));

  const categoryBreakdown = [...categoryCounts.entries()].map(([category, count]) => ({ category, count }));

  const topPorts = [...portCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([port, count]) => ({ port, count, service: PORT_SERVICES[port] ?? 'Unknown' }));

  const activeThreats = alerts.filter(a => a.status === 'active').length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical' && a.status === 'active').length;

  return {
    total_events: totalEvents,
    critical_alerts: criticalAlerts,
    active_threats: activeThreats,
    events_per_minute: eventTimestamps.length,
    unique_ips: ipCounts.size,
    alert_rate: totalEvents > 0 ? (alerts.length / totalEvents) * 100 : 0,
    top_source_ips: topIps,
    severity_breakdown: severityBreakdown,
    events_over_time: [...timeSeries],
    category_breakdown: categoryBreakdown,
    top_ports: topPorts,
  };
}

// ─── REST API ──────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  const td = getThreatData();
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    threat_intel: {
      c2_ips:       td.c2Ips.length,
      malware_urls: td.malwareUrls.length,
      cves:         td.cves.length,
      last_updated: td.lastUpdated,
    },
  });
});

app.get('/api/logs', (req, res) => {
  const limit = parseLimit(req.query.limit);
  res.json(logs.slice(0, limit));
});

app.get('/api/alerts', (_req, res) => res.json(alerts));

app.get('/api/stats', (_req, res) => res.json(computeStats()));

app.patch('/api/alerts/:id', (req, res) => {
  const idResult = validateAlertId(req.params.id);
  if (!idResult.ok) {
    return res.status(400).json({ error: idResult.error });
  }

  const statusResult = validateAlertStatus((req.body ?? {}).status);
  if (!statusResult.ok) {
    return res.status(400).json({ error: statusResult.error });
  }

  const idx = alerts.findIndex(a => a.id === idResult.value);
  if (idx === -1) return res.status(404).json({ error: 'Alert not found' });

  // Immutable update — replace element instead of mutating in place
  const updated: Alert = { ...alerts[idx], status: statusResult.value! };
  alerts[idx] = updated;
  io.emit('alert_updated', updated);
  return res.json(updated);
});

// Global error handler — prevents stack traces leaking to clients
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Socket.io ────────────────────────────────────────────────────────────────
io.on('connection', socket => {
  console.log(`[+] Client connected: ${socket.id}`);
  socket.emit('init', {
    logs: logs.slice(0, 200),
    alerts,
    stats: computeStats(),
  });
  socket.on('disconnect', () => {
    console.log(`[-] Client disconnected: ${socket.id}`);
  });
});

// ─── Log Generation Loop ──────────────────────────────────────────────────────
console.log('[*] Seeding historical events...');
const seed = generateBurst(150);
for (const evt of seed) {
  evt.timestamp = new Date(Date.now() - Math.random() * 30 * 60 * 1000).toISOString();
  const alert = addLog(evt);
  if (alert) alerts.unshift(alert);
}

setInterval(() => {
  timeSeries.shift();
  timeSeries.push({
    time: new Date().toISOString(),
    count: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0,
  });
}, 60_000);

let attackWaveCountdown = 0;
let waveIp: string | undefined;

setInterval(() => {
  if (attackWaveCountdown <= 0 && Math.random() < 0.02) {
    waveIp = pickC2Ip(); // real C2 IP from Feodo Tracker (or fallback)
    attackWaveCountdown = 15;
    console.log(`[!] Attack wave from ${waveIp}`);
  }

  const event = generateEvent(attackWaveCountdown > 0 ? waveIp : undefined);
  if (attackWaveCountdown > 0) {
    attackWaveCountdown--;
    if (attackWaveCountdown === 0) waveIp = undefined;
  }

  const alert = addLog(event);
  io.emit('log', event);

  if (alert) {
    alerts.unshift(alert);
    if (alerts.length > 500) alerts.pop();
    io.emit('alert', alert);
    console.log(`[ALERT] ${alert.severity.toUpperCase()} - ${alert.title}`);
  }
}, 800);

setInterval(() => {
  io.emit('stats', computeStats());
}, 5000);

setInterval(() => detector.cleanup(), 5 * 60_000);

// ─── Start Server ──────────────────────────────────────────────────────────────
httpServer.listen(config.port, () => {
  console.log(`[*] SIEM Backend running on http://localhost:${config.port}`);
});
