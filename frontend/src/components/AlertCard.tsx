import { Shield, AlertTriangle, Clock, Globe, Users, Check, Eye } from 'lucide-react';
import { Alert } from '../types';
import SeverityBadge from './SeverityBadge';

interface Props {
  alert: Alert;
  onAction: (id: string, status: 'acknowledged' | 'resolved') => void;
}

const TYPE_LABELS: Record<string, string> = {
  brute_force: 'Brute Force',
  port_scan: 'Port Scan',
  sql_injection: 'SQL Injection',
  xss: 'XSS Attack',
  data_exfiltration: 'Data Exfiltration',
  privilege_escalation: 'Priv. Escalation',
  lateral_movement: 'Lateral Movement',
  c2_communication: 'C2 / Reverse Shell',
};

function timeAgo(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export default function AlertCard({ alert, onAction }: Props) {
  const isActive = alert.status === 'active';

  return (
    <div className={`card p-4 space-y-3 relative overflow-hidden transition-all
      ${alert.severity === 'critical' && isActive ? 'border-red-500/40 bg-red-500/5' : ''}
      ${alert.status === 'resolved' ? 'opacity-50' : ''}
    `}>
      {/* Left severity stripe */}
      <div className={`absolute left-0 top-0 bottom-0 w-1
        ${alert.severity === 'critical' ? 'bg-severity-critical' :
          alert.severity === 'high' ? 'bg-severity-high' :
          alert.severity === 'medium' ? 'bg-severity-medium' : 'bg-severity-low'}`}
      />

      <div className="pl-3">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={alert.severity} />
            <span className="text-xs text-gray-500 bg-bg-elevated px-1.5 py-0.5 rounded font-mono">
              {TYPE_LABELS[alert.type] ?? alert.type}
            </span>
            {alert.status === 'acknowledged' && (
              <span className="text-xs text-yellow-400 bg-yellow-400/10 border border-yellow-400/20 px-1.5 py-0.5 rounded">
                ACKNOWLEDGED
              </span>
            )}
            {alert.status === 'resolved' && (
              <span className="text-xs text-green-400 bg-green-400/10 border border-green-400/20 px-1.5 py-0.5 rounded">
                RESOLVED
              </span>
            )}
          </div>
          <div className="flex items-center gap-1 text-xs text-gray-500 flex-shrink-0">
            <Clock className="w-3 h-3" />
            {timeAgo(alert.timestamp)}
          </div>
        </div>

        {/* Title */}
        <h3 className="font-semibold text-white mt-2 text-sm">{alert.title}</h3>
        <p className="text-xs text-gray-400 mt-1 leading-relaxed">{alert.description}</p>

        {/* Details grid */}
        <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-2">
          <div className="bg-bg-elevated rounded px-2 py-1.5">
            <div className="text-[10px] text-gray-500 uppercase mb-0.5">Source IP</div>
            <div className="text-xs font-mono text-accent-cyan">{alert.source_ip}</div>
          </div>
          <div className="bg-bg-elevated rounded px-2 py-1.5">
            <div className="text-[10px] text-gray-500 uppercase mb-0.5">Event Count</div>
            <div className="text-xs font-mono text-white">{alert.event_count}</div>
          </div>
          {alert.affected_users.length > 0 && (
            <div className="bg-bg-elevated rounded px-2 py-1.5">
              <div className="text-[10px] text-gray-500 uppercase mb-0.5">Affected Users</div>
              <div className="text-xs font-mono text-orange-300 truncate">{alert.affected_users.join(', ')}</div>
            </div>
          )}
          <div className="bg-bg-elevated rounded px-2 py-1.5">
            <div className="text-[10px] text-gray-500 uppercase mb-0.5">MITRE ID</div>
            <div className="text-xs font-mono text-accent-purple">{alert.mitre_technique_id}</div>
          </div>
        </div>

        {/* MITRE ATT&CK */}
        <div className="mt-2 flex items-center gap-2 flex-wrap">
          <span className="text-[10px] text-gray-600 uppercase font-medium">MITRE ATT&CK:</span>
          <span className="text-xs text-gray-400 bg-bg-elevated px-1.5 py-0.5 rounded">{alert.mitre_tactic}</span>
          <span className="text-[10px] text-gray-500">→</span>
          <span className="text-xs text-accent-purple bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/20">
            {alert.mitre_technique}
          </span>
        </div>

        {/* Actions */}
        {isActive && (
          <div className="mt-3 flex items-center gap-2">
            <button
              onClick={() => onAction(alert.id, 'acknowledged')}
              className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 rounded hover:bg-yellow-500/20 transition-colors"
            >
              <Eye className="w-3 h-3" />
              Acknowledge
            </button>
            <button
              onClick={() => onAction(alert.id, 'resolved')}
              className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 bg-green-500/10 text-green-400 border border-green-500/20 rounded hover:bg-green-500/20 transition-colors"
            >
              <Check className="w-3 h-3" />
              Resolve
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
