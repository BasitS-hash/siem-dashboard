import { v4 as uuidv4 } from 'uuid';
import { LogEvent, Alert, AttackType, Severity } from './types';

interface IpTracker {
  failedAuths: { timestamp: number; user?: string; eventId: string }[];
  ports: { port: number; timestamp: number; eventId: string }[];
  sqlAttempts: { timestamp: number; eventId: string }[];
  xssAttempts: { timestamp: number; eventId: string }[];
  bytesSent: number;
  countries: Set<string>;
  dstIps: Set<string>;
  lastSeen: number;
}

const MITRE_MAP: Record<AttackType, { tactic: string; technique: string; id: string }> = {
  brute_force: { tactic: 'Credential Access', technique: 'Brute Force', id: 'T1110' },
  port_scan: { tactic: 'Discovery', technique: 'Network Service Scanning', id: 'T1046' },
  sql_injection: { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', id: 'T1190' },
  xss: { tactic: 'Initial Access', technique: 'Cross-Site Scripting', id: 'T1059.007' },
  data_exfiltration: { tactic: 'Exfiltration', technique: 'Exfiltration Over C2 Channel', id: 'T1041' },
  privilege_escalation: { tactic: 'Privilege Escalation', technique: 'Sudo and Sudo Caching', id: 'T1548.003' },
  lateral_movement: { tactic: 'Lateral Movement', technique: 'Remote Services', id: 'T1021' },
  c2_communication: { tactic: 'Command and Control', technique: 'Application Layer Protocol', id: 'T1071' },
};

export class ThreatDetector {
  private trackers = new Map<string, IpTracker>();
  // Key → expiry timestamp; TTL-evicted on cleanup rather than bulk-cleared
  private alertKeyExpiry = new Map<string, number>();
  private readonly WINDOW_MS = 60_000;
  private readonly KEY_TTL_MS = 120_000; // 2-minute dedup window

  private getTracker(ip: string): IpTracker {
    let tracker = this.trackers.get(ip);
    if (!tracker) {
      tracker = {
        failedAuths: [],
        ports: [],
        sqlAttempts: [],
        xssAttempts: [],
        bytesSent: 0,
        countries: new Set(),
        dstIps: new Set(),
        lastSeen: Date.now(),
      };
      this.trackers.set(ip, tracker);
    }
    return tracker;
  }

  private prune(arr: { timestamp: number }[]): void {
    const cutoff = Date.now() - this.WINDOW_MS;
    while (arr.length > 0 && arr[0].timestamp < cutoff) arr.shift();
  }

  private isSeen(key: string): boolean {
    const expiry = this.alertKeyExpiry.get(key);
    return expiry !== undefined && Date.now() < expiry;
  }

  private markSeen(key: string): void {
    this.alertKeyExpiry.set(key, Date.now() + this.KEY_TTL_MS);
  }

  processEvent(event: LogEvent): Alert | null {
    const tracker = this.getTracker(event.source_ip);
    tracker.lastSeen = Date.now();
    tracker.dstIps.add(event.destination_ip);
    if (event.bytes_sent) tracker.bytesSent += event.bytes_sent;

    if (event.category === 'authentication' && event.action === 'failure') {
      tracker.failedAuths.push({ timestamp: Date.now(), user: event.user, eventId: event.id });
    }
    if (event.category === 'network' || event.category === 'firewall') {
      tracker.ports.push({ port: event.destination_port, timestamp: Date.now(), eventId: event.id });
    }
    if (event.tags.includes('sqli')) {
      tracker.sqlAttempts.push({ timestamp: Date.now(), eventId: event.id });
    }
    if (event.tags.includes('xss')) {
      tracker.xssAttempts.push({ timestamp: Date.now(), eventId: event.id });
    }

    this.prune(tracker.failedAuths);
    this.prune(tracker.ports);
    this.prune(tracker.sqlAttempts);
    this.prune(tracker.xssAttempts);

    return this.runDetections(event, tracker);
  }

  private runDetections(event: LogEvent, tracker: IpTracker): Alert | null {
    const ip = event.source_ip;

    // Brute force: >5 failed logins in 60s
    if (tracker.failedAuths.length >= 5) {
      const key = `brute_force:${ip}:${Math.floor(Date.now() / 30000)}`;
      if (!this.isSeen(key)) {
        this.markSeen(key);
        return this.buildAlert('brute_force', 'high', ip, tracker,
          `Brute Force Attack Detected from ${ip}`,
          `${tracker.failedAuths.length} failed authentication attempts detected within 60 seconds. Accounts targeted: ${[...new Set(tracker.failedAuths.map(f => f.user).filter(Boolean))].join(', ')}`,
          tracker.failedAuths.map(f => f.eventId),
          tracker.failedAuths.map(f => f.user).filter(Boolean) as string[]
        );
      }
    }

    // Port scan: >8 unique ports in 60s
    const uniquePorts = new Set(tracker.ports.map(p => p.port));
    if (uniquePorts.size >= 8) {
      const key = `port_scan:${ip}:${Math.floor(Date.now() / 30000)}`;
      if (!this.isSeen(key)) {
        this.markSeen(key);
        return this.buildAlert('port_scan', 'high', ip, tracker,
          `Network Port Scan Detected from ${ip}`,
          `Host ${ip} scanned ${uniquePorts.size} unique ports in the last 60 seconds targeting ${tracker.dstIps.size} internal hosts.`,
          tracker.ports.map(p => p.eventId)
        );
      }
    }

    // SQL Injection: any attempt
    if (tracker.sqlAttempts.length >= 1) {
      const key = `sql_injection:${ip}:${event.id}`;
      if (!this.isSeen(key)) {
        this.markSeen(key);
        return this.buildAlert('sql_injection', 'critical', ip, tracker,
          `SQL Injection Attempt from ${ip}`,
          `SQL injection payload detected in HTTP request: ${event.url}`,
          [event.id]
        );
      }
    }

    // XSS: any attempt
    if (tracker.xssAttempts.length >= 1) {
      const key = `xss:${ip}:${event.id}`;
      if (!this.isSeen(key)) {
        this.markSeen(key);
        return this.buildAlert('xss', 'high', ip, tracker,
          `Cross-Site Scripting (XSS) Attempt from ${ip}`,
          'XSS payload detected in HTTP request parameter. Attacker may be attempting to inject malicious scripts.',
          [event.id]
        );
      }
    }

    // Data exfiltration: >10MB sent
    if (tracker.bytesSent > 10_000_000) {
      const key = `exfil:${ip}:${Math.floor(Date.now() / 60000)}`;
      if (!this.isSeen(key)) {
        this.markSeen(key);
        const mbTransferred = (tracker.bytesSent / 1_000_000).toFixed(1);
        tracker.bytesSent = 0; // reset after capturing value
        return this.buildAlert('data_exfiltration', 'critical', ip, tracker,
          `Potential Data Exfiltration from ${ip}`,
          `Host ${ip} has transferred ${mbTransferred}MB of data outbound in a short period, exceeding normal thresholds.`,
          []
        );
      }
    }

    // Privilege escalation / reverse shell
    if (event.tags.includes('privilege-escalation') || event.tags.includes('reverse-shell')) {
      const type: AttackType = event.tags.includes('reverse-shell') ? 'c2_communication' : 'privilege_escalation';
      const key = `${type}:${ip}:${event.id}`;
      if (!this.isSeen(key)) {
        this.markSeen(key);
        return this.buildAlert(type, 'critical', ip, tracker,
          type === 'c2_communication'
            ? `Reverse Shell / C2 Beacon Detected on ${event.hostname}`
            : `Privilege Escalation Detected on ${event.hostname}`,
          event.message,
          [event.id],
          event.user ? [event.user] : []
        );
      }
    }

    // Lateral movement: external IP contacting many internal hosts
    if (tracker.dstIps.size >= 5 && !ip.startsWith('10.')) {
      const key = `lateral:${ip}:${Math.floor(Date.now() / 60000)}`;
      if (!this.isSeen(key)) {
        this.markSeen(key);
        return this.buildAlert('lateral_movement', 'high', ip, tracker,
          `Lateral Movement Suspected from ${ip}`,
          `External IP ${ip} has communicated with ${tracker.dstIps.size} internal hosts, suggesting lateral movement or scanning.`,
          []
        );
      }
    }

    return null;
  }

  private buildAlert(
    type: AttackType,
    severity: Severity,
    srcIp: string,
    tracker: IpTracker,
    title: string,
    description: string,
    eventIds: string[],
    affectedUsers: string[] = []
  ): Alert {
    const mitre = MITRE_MAP[type];
    const now = new Date().toISOString();
    return {
      id: uuidv4(),
      timestamp: now,
      severity,
      type,
      title,
      description,
      source_ip: srcIp,
      destination_ips: [...tracker.dstIps].slice(0, 5),
      affected_users: [...new Set(affectedUsers)],
      event_count: eventIds.length || 1,
      status: 'active',
      mitre_tactic: mitre.tactic,
      mitre_technique: mitre.technique,
      mitre_technique_id: mitre.id,
      related_event_ids: eventIds.slice(0, 10),
      first_seen: now,
      last_seen: now,
    };
  }

  cleanup(): void {
    const now = Date.now();
    const trackerCutoff = now - 5 * 60_000;
    for (const [ip, tracker] of this.trackers.entries()) {
      if (tracker.lastSeen < trackerCutoff) this.trackers.delete(ip);
    }
    // TTL-based eviction — no bulk clear, so dedup remains intact
    for (const [key, expiry] of this.alertKeyExpiry.entries()) {
      if (expiry < now) this.alertKeyExpiry.delete(key);
    }
  }
}
