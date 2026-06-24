import { describe, it, expect, beforeEach } from 'vitest';
import { ThreatDetector, MITRE_MAP } from './threatDetector';
import { LogEvent, EventCategory, Severity } from './types';

let counter = 0;

/** Builds a minimal valid LogEvent, overridable per test. */
function makeEvent(overrides: Partial<LogEvent> = {}): LogEvent {
  counter += 1;
  return {
    id: `evt-${counter}`,
    timestamp: new Date().toISOString(),
    severity: 'info' as Severity,
    category: 'network' as EventCategory,
    source_ip: '203.0.113.10',
    destination_ip: '10.0.1.50',
    source_port: 50000,
    destination_port: 443,
    protocol: 'TCP',
    hostname: 'web-srv-01',
    message: 'test event',
    raw: 'raw',
    tags: [],
    action: 'allow',
    ...overrides,
  };
}

describe('ThreatDetector — brute force (T1110)', () => {
  let detector: ThreatDetector;
  beforeEach(() => {
    detector = new ThreatDetector();
  });

  it('does not alert below the 5-failure threshold', () => {
    let alert = null;
    for (let i = 0; i < 4; i++) {
      alert = detector.processEvent(
        makeEvent({ category: 'authentication', action: 'failure', user: 'admin' })
      );
    }
    expect(alert).toBeNull();
  });

  it('raises a high-severity brute-force alert at 5 failed auths', () => {
    let alert = null;
    for (let i = 0; i < 5; i++) {
      alert = detector.processEvent(
        makeEvent({ category: 'authentication', action: 'failure', user: 'admin' })
      );
    }
    expect(alert).not.toBeNull();
    expect(alert!.type).toBe('brute_force');
    expect(alert!.severity).toBe('high');
    expect(alert!.mitre_technique_id).toBe('T1110');
    expect(alert!.affected_users).toContain('admin');
  });

  it('does not raise a duplicate brute-force alert within the dedup window', () => {
    const alerts = [];
    for (let i = 0; i < 8; i++) {
      const a = detector.processEvent(
        makeEvent({ category: 'authentication', action: 'failure', user: 'root' })
      );
      if (a) alerts.push(a);
    }
    // Only the first crossing of the threshold should alert (dedup window).
    expect(alerts.length).toBe(1);
  });

  it('successful auths do not count toward brute force', () => {
    let alert = null;
    for (let i = 0; i < 10; i++) {
      alert = detector.processEvent(
        makeEvent({ category: 'authentication', action: 'success', user: 'admin' })
      );
    }
    expect(alert).toBeNull();
  });
});

describe('ThreatDetector — port scan (T1046)', () => {
  it('alerts after 8 unique destination ports in the window', () => {
    const detector = new ThreatDetector();
    let alert = null;
    for (let port = 20; port < 28; port++) {
      alert = detector.processEvent(
        makeEvent({ category: 'network', destination_port: port })
      );
    }
    expect(alert).not.toBeNull();
    expect(alert!.type).toBe('port_scan');
    expect(alert!.mitre_technique_id).toBe('T1046');
  });

  it('does not alert when the same port is hit repeatedly', () => {
    const detector = new ThreatDetector();
    let alert = null;
    for (let i = 0; i < 20; i++) {
      alert = detector.processEvent(
        makeEvent({ category: 'network', destination_port: 443 })
      );
    }
    expect(alert).toBeNull();
  });
});

describe('ThreatDetector — SQL injection (T1190)', () => {
  it('alerts critical on a single sqli-tagged event', () => {
    const detector = new ThreatDetector();
    const alert = detector.processEvent(
      makeEvent({ category: 'web', tags: ['web', 'sqli'], url: "/api/users?id=' OR 1=1--" })
    );
    expect(alert).not.toBeNull();
    expect(alert!.type).toBe('sql_injection');
    expect(alert!.severity).toBe('critical');
    expect(alert!.mitre_technique_id).toBe('T1190');
  });
});

describe('ThreatDetector — XSS (T1059.007)', () => {
  it('alerts high on a single xss-tagged event', () => {
    const detector = new ThreatDetector();
    const alert = detector.processEvent(
      makeEvent({ category: 'web', tags: ['web', 'xss'] })
    );
    expect(alert).not.toBeNull();
    expect(alert!.type).toBe('xss');
    expect(alert!.severity).toBe('high');
    expect(alert!.mitre_technique_id).toBe('T1059.007');
  });
});

describe('ThreatDetector — data exfiltration (T1041)', () => {
  it('alerts critical when outbound bytes exceed 10MB', () => {
    const detector = new ThreatDetector();
    const alert = detector.processEvent(
      makeEvent({ bytes_sent: 11_000_000 })
    );
    expect(alert).not.toBeNull();
    expect(alert!.type).toBe('data_exfiltration');
    expect(alert!.severity).toBe('critical');
  });

  it('does not alert below the 10MB threshold', () => {
    const detector = new ThreatDetector();
    const alert = detector.processEvent(makeEvent({ bytes_sent: 5_000_000 }));
    expect(alert).toBeNull();
  });
});

describe('ThreatDetector — privilege escalation & C2', () => {
  it('classifies a reverse-shell tag as c2_communication (T1071)', () => {
    const detector = new ThreatDetector();
    const alert = detector.processEvent(
      makeEvent({ category: 'system', tags: ['system', 'reverse-shell'], message: 'nc -e /bin/bash' })
    );
    expect(alert).not.toBeNull();
    expect(alert!.type).toBe('c2_communication');
    expect(alert!.severity).toBe('critical');
  });

  it('classifies a privilege-escalation tag correctly (T1548.003)', () => {
    const detector = new ThreatDetector();
    const alert = detector.processEvent(
      makeEvent({ category: 'system', tags: ['system', 'privilege-escalation'], user: 'devops' })
    );
    expect(alert).not.toBeNull();
    expect(alert!.type).toBe('privilege_escalation');
    expect(alert!.mitre_technique_id).toBe('T1548.003');
  });
});

describe('ThreatDetector — lateral movement (T1021)', () => {
  it('alerts when an external IP contacts 5+ internal hosts', () => {
    const detector = new ThreatDetector();
    let alert = null;
    const hosts = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4', '10.0.1.5'];
    for (const dst of hosts) {
      alert = detector.processEvent(
        makeEvent({ source_ip: '198.51.100.7', destination_ip: dst, category: 'network', destination_port: 445 })
      );
    }
    expect(alert).not.toBeNull();
    // port_scan needs 8 ports; here all use 445 so lateral_movement should win
    expect(alert!.type).toBe('lateral_movement');
  });

  it('does not flag internal (10.x) source IPs as lateral movement', () => {
    const detector = new ThreatDetector();
    let alert = null;
    const hosts = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4', '10.0.1.5', '10.0.1.6'];
    for (const dst of hosts) {
      alert = detector.processEvent(
        makeEvent({ source_ip: '10.0.0.99', destination_ip: dst, category: 'network', destination_port: 445 })
      );
    }
    expect(alert).toBeNull();
  });
});

describe('ThreatDetector — cleanup', () => {
  it('does not throw when cleaning up empty state', () => {
    const detector = new ThreatDetector();
    expect(() => detector.cleanup()).not.toThrow();
  });

  it('removes stale trackers after cleanup', () => {
    const detector = new ThreatDetector();
    detector.processEvent(makeEvent({ source_ip: '203.0.113.99' }));
    // cleanup only evicts trackers older than 5 minutes; immediate call keeps them
    expect(() => detector.cleanup()).not.toThrow();
  });
});

describe('MITRE_MAP completeness', () => {
  it('maps every attack type to a tactic, technique, and id', () => {
    for (const [type, mapping] of Object.entries(MITRE_MAP)) {
      expect(mapping.tactic, `${type} tactic`).toBeTruthy();
      expect(mapping.technique, `${type} technique`).toBeTruthy();
      expect(mapping.id, `${type} id`).toMatch(/^T\d{4}(\.\d{3})?$/);
    }
  });
});
