import { useState } from 'react';
import { BookOpen, Shield, AlertTriangle, Zap } from 'lucide-react';
import { DetectionRule } from '../types';
import SeverityBadge from '../components/SeverityBadge';

const RULES: DetectionRule[] = [
  {
    id: 'r001',
    name: 'SSH Brute Force Detection',
    description: 'Detects multiple failed SSH/authentication attempts from a single source IP within a short window, indicating potential brute-force attack.',
    severity: 'high',
    category: 'authentication',
    enabled: true,
    mitre_tactic: 'Credential Access',
    mitre_technique_id: 'T1110',
    logic: 'COUNT(event.category == "authentication" AND event.action == "failure" AND src_ip == X) >= 5 WITHIN 60s',
    threshold: 5,
    window_seconds: 60,
    tags: ['brute-force', 'authentication', 'ssh', 'rdp'],
  },
  {
    id: 'r002',
    name: 'Network Port Scan Detection',
    description: 'Identifies hosts probing multiple ports in rapid succession, characteristic of reconnaissance and service discovery activities.',
    severity: 'high',
    category: 'network',
    enabled: true,
    mitre_tactic: 'Discovery',
    mitre_technique_id: 'T1046',
    logic: 'COUNT(DISTINCT event.destination_port WHERE src_ip == X) >= 8 WITHIN 60s',
    threshold: 8,
    window_seconds: 60,
    tags: ['port-scan', 'reconnaissance', 'network'],
  },
  {
    id: 'r003',
    name: 'SQL Injection Attack',
    description: 'Detects SQL injection payloads in HTTP request parameters. Any single occurrence triggers an immediate critical alert.',
    severity: 'critical',
    category: 'web',
    enabled: true,
    mitre_tactic: 'Initial Access',
    mitre_technique_id: 'T1190',
    logic: 'event.category == "web" AND event.tags CONTAINS "sqli"',
    tags: ['sql-injection', 'web', 'injection', 'owasp-top10'],
  },
  {
    id: 'r004',
    name: 'Cross-Site Scripting (XSS) Attempt',
    description: 'Identifies XSS payloads in web request parameters including script injection, event handlers, and javascript: URIs.',
    severity: 'high',
    category: 'web',
    enabled: true,
    mitre_tactic: 'Initial Access',
    mitre_technique_id: 'T1059.007',
    logic: 'event.category == "web" AND event.tags CONTAINS "xss"',
    tags: ['xss', 'web', 'injection', 'owasp-top10'],
  },
  {
    id: 'r005',
    name: 'Privilege Escalation via Sudo',
    description: 'Detects sudo privilege escalation events where a non-root user elevates to root privileges, potentially indicating compromise.',
    severity: 'critical',
    category: 'system',
    enabled: true,
    mitre_tactic: 'Privilege Escalation',
    mitre_technique_id: 'T1548.003',
    logic: 'event.category == "system" AND event.tags CONTAINS "privilege-escalation"',
    tags: ['privilege-escalation', 'sudo', 'system'],
  },
  {
    id: 'r006',
    name: 'Reverse Shell / C2 Beacon',
    description: 'Detects execution of known reverse shell commands (nc, bash, python) that may indicate command and control activity.',
    severity: 'critical',
    category: 'system',
    enabled: true,
    mitre_tactic: 'Command and Control',
    mitre_technique_id: 'T1071',
    logic: 'event.category == "system" AND event.tags CONTAINS "reverse-shell"',
    tags: ['c2', 'reverse-shell', 'malware', 'critical'],
  },
  {
    id: 'r007',
    name: 'Data Exfiltration (Volume)',
    description: 'Triggers when a single source IP transmits more than 10MB of data outbound in a 60 second window, suggesting bulk data theft.',
    severity: 'critical',
    category: 'network',
    enabled: true,
    mitre_tactic: 'Exfiltration',
    mitre_technique_id: 'T1041',
    logic: 'SUM(event.bytes_sent WHERE src_ip == X) > 10_000_000 WITHIN 60s',
    window_seconds: 60,
    tags: ['exfiltration', 'data-theft', 'network'],
  },
  {
    id: 'r008',
    name: 'Lateral Movement Detection',
    description: 'Identifies external IPs communicating with 5 or more distinct internal hosts, suggesting lateral movement or internal reconnaissance.',
    severity: 'high',
    category: 'network',
    enabled: true,
    mitre_tactic: 'Lateral Movement',
    mitre_technique_id: 'T1021',
    logic: 'COUNT(DISTINCT event.destination_ip WHERE src_ip == X AND src_ip NOT IN internal_ranges) >= 5',
    threshold: 5,
    tags: ['lateral-movement', 'internal-recon', 'network'],
  },
  {
    id: 'r009',
    name: 'Sensitive File Access',
    description: 'Alerts on access to security-sensitive files like /etc/shadow, /etc/passwd, SSH keys, and credential stores.',
    severity: 'high',
    category: 'system',
    enabled: true,
    mitre_tactic: 'Credential Access',
    mitre_technique_id: 'T1555',
    logic: 'event.category == "system" AND event.tags CONTAINS "credential-access"',
    tags: ['credential-access', 'sensitive-files', 'system'],
  },
  {
    id: 'r010',
    name: 'Persistence via Cron Job',
    description: 'Detects creation or modification of cron jobs which may indicate an attacker establishing persistence on a compromised system.',
    severity: 'critical',
    category: 'system',
    enabled: true,
    mitre_tactic: 'Persistence',
    mitre_technique_id: 'T1053.003',
    logic: 'event.category == "system" AND event.tags CONTAINS "persistence" AND event.tags CONTAINS "cron"',
    tags: ['persistence', 'cron', 'system'],
  },
  {
    id: 'r011',
    name: 'High-Risk Port Access Attempt',
    description: 'Flags connection attempts to sensitive management ports (RDP 3389, SSH 22, DB ports) from external IP addresses.',
    severity: 'medium',
    category: 'firewall',
    enabled: true,
    mitre_tactic: 'Initial Access',
    mitre_technique_id: 'T1133',
    logic: 'event.category == "firewall" AND event.destination_port IN [22, 3389, 1433, 3306, 5432] AND src_ip NOT IN internal_ranges',
    tags: ['firewall', 'external-access', 'management-ports'],
  },
  {
    id: 'r012',
    name: 'Reconnaissance Tool Detected',
    description: 'Identifies installation of known offensive security tools (nmap, metasploit, mimikatz, john) on monitored endpoints.',
    severity: 'medium',
    category: 'system',
    enabled: false,
    mitre_tactic: 'Discovery',
    mitre_technique_id: 'T1592',
    logic: 'event.category == "system" AND event.tags CONTAINS "recon-tool"',
    tags: ['recon', 'offensive-tools', 'system'],
  },
];

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function RulesPage() {
  const [rules, setRules] = useState(RULES);
  const [filter, setFilter] = useState<'all' | 'enabled' | 'disabled'>('all');

  const toggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const filtered = rules
    .filter(r => filter === 'all' || (filter === 'enabled' ? r.enabled : !r.enabled))
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  const enabledCount = rules.filter(r => r.enabled).length;

  return (
    <div className="space-y-4">
      {/* Header stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Total Rules', value: rules.length, icon: BookOpen, color: 'text-accent-cyan' },
          { label: 'Active Rules', value: enabledCount, icon: Shield, color: 'text-accent-green' },
          { label: 'Disabled', value: rules.length - enabledCount, icon: AlertTriangle, color: 'text-gray-500' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="card p-4 flex items-center gap-3">
            <Icon className={`w-5 h-5 ${color}`} />
            <div>
              <div className={`text-xl font-bold font-mono ${color}`}>{value}</div>
              <div className="text-xs text-gray-500">{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="flex items-center gap-2">
        {(['all', 'enabled', 'disabled'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-all
              ${filter === f ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20' : 'text-gray-500 bg-bg-secondary border border-border hover:text-gray-300'}`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)} ({f === 'all' ? rules.length : f === 'enabled' ? enabledCount : rules.length - enabledCount})
          </button>
        ))}
      </div>

      {/* Rules grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
        {filtered.map(rule => (
          <div key={rule.id} className={`card p-4 space-y-3 relative overflow-hidden transition-all ${!rule.enabled ? 'opacity-50' : ''}`}>
            {/* Severity stripe */}
            <div className={`absolute left-0 top-0 bottom-0 w-1
              ${rule.severity === 'critical' ? 'bg-severity-critical' :
                rule.severity === 'high' ? 'bg-severity-high' :
                rule.severity === 'medium' ? 'bg-severity-medium' : 'bg-severity-low'}`}
            />

            <div className="pl-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <SeverityBadge severity={rule.severity} />
                  <span className="text-xs text-gray-500 font-mono bg-bg-elevated px-1.5 py-0.5 rounded">
                    {rule.category.toUpperCase()}
                  </span>
                </div>
                {/* Toggle */}
                <button
                  onClick={() => toggleRule(rule.id)}
                  className={`relative w-10 h-5 rounded-full transition-all flex-shrink-0 ${rule.enabled ? 'bg-accent-green' : 'bg-gray-700'}`}
                >
                  <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-all ${rule.enabled ? 'left-5' : 'left-0.5'}`} />
                </button>
              </div>

              <h3 className="font-semibold text-white text-sm mt-2">{rule.name}</h3>
              <p className="text-xs text-gray-400 mt-1 leading-relaxed">{rule.description}</p>

              {/* Logic */}
              <div className="mt-2 bg-bg-primary rounded px-3 py-2">
                <div className="text-[10px] text-gray-600 uppercase mb-1 font-medium">Detection Logic</div>
                <code className="text-xs text-accent-cyan font-mono break-all">{rule.logic}</code>
              </div>

              {/* Footer */}
              <div className="mt-2 flex items-center gap-3 flex-wrap">
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-gray-600 uppercase">MITRE</span>
                  <span className="text-xs font-mono text-accent-purple bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/20">
                    {rule.mitre_technique_id}
                  </span>
                </div>
                {rule.threshold && (
                  <div className="text-xs text-gray-600 font-mono">
                    Threshold: <span className="text-gray-300">{rule.threshold}</span>
                  </div>
                )}
                {rule.window_seconds && (
                  <div className="text-xs text-gray-600 font-mono">
                    Window: <span className="text-gray-300">{rule.window_seconds}s</span>
                  </div>
                )}
                <div className="ml-auto flex gap-1 flex-wrap">
                  {rule.tags.slice(0, 3).map(t => (
                    <span key={t} className="text-[10px] text-gray-600 bg-bg-elevated px-1.5 py-0.5 rounded font-mono">{t}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
