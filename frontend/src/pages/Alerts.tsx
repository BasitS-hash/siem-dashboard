import { useState } from 'react';
import { AlertTriangle, CheckCircle, Clock, Filter, Download, Search } from 'lucide-react';
import { Alert, Severity } from '../types';
import AlertCard from '../components/AlertCard';
import { exportAlertsCsv } from '../lib/exportCsv';

interface Props {
  alerts: Alert[];
  onAlertAction: (id: string, status: 'acknowledged' | 'resolved') => void;
}

type StatusFilter = 'all' | 'active' | 'acknowledged' | 'resolved';
type SeverityFilter = 'all' | Severity;

export default function AlertsPage({ alerts, onAlertAction }: Props) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [ipSearch, setIpSearch] = useState('');

  const filtered = alerts.filter(a => {
    if (statusFilter !== 'all' && a.status !== statusFilter) return false;
    if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
    if (ipSearch) {
      const q = ipSearch.toLowerCase();
      return (
        a.source_ip.includes(q) ||
        a.title.toLowerCase().includes(q) ||
        a.mitre_technique_id.toLowerCase().includes(q) ||
        a.affected_users.some(u => u.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const counts = {
    all: alerts.length,
    active: alerts.filter(a => a.status === 'active').length,
    acknowledged: alerts.filter(a => a.status === 'acknowledged').length,
    resolved: alerts.filter(a => a.status === 'resolved').length,
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
  };

  const STATUS_TABS: { id: StatusFilter; label: string; icon: typeof AlertTriangle }[] = [
    { id: 'all', label: 'All', icon: Filter },
    { id: 'active', label: 'Active', icon: AlertTriangle },
    { id: 'acknowledged', label: 'Acknowledged', icon: Clock },
    { id: 'resolved', label: 'Resolved', icon: CheckCircle },
  ];

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Total Alerts', value: counts.all, color: 'text-gray-300' },
          { label: 'Active', value: counts.active, color: 'text-red-400' },
          { label: 'Critical', value: counts.critical, color: 'text-red-500' },
          { label: 'High', value: counts.high, color: 'text-orange-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card p-3 text-center">
            <div className={`text-2xl font-bold font-mono ${color}`}>{value}</div>
            <div className="text-xs text-gray-500 mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Search + Export */}
      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search by IP, title, MITRE ID, or user..."
            value={ipSearch}
            onChange={e => setIpSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-bg-elevated border border-border rounded-lg text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-accent-cyan/50 font-mono"
          />
        </div>
        <button
          onClick={() => exportAlertsCsv(filtered)}
          className="flex items-center gap-2 px-3 py-2 bg-bg-elevated border border-border rounded-lg text-sm text-gray-400 hover:text-white hover:border-accent-cyan/40 transition-all flex-shrink-0"
        >
          <Download className="w-4 h-4" />
          <span className="hidden sm:inline">Export CSV</span>
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        {/* Status tabs */}
        <div className="flex gap-1 bg-bg-secondary border border-border rounded-lg p-1">
          {STATUS_TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setStatusFilter(id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all
                ${statusFilter === id
                  ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20'
                  : 'text-gray-500 hover:text-gray-300'}`}
            >
              <Icon className="w-3 h-3" />
              {label}
              <span className={`text-[10px] font-mono ${statusFilter === id ? '' : 'text-gray-600'}`}>
                ({counts[id]})
              </span>
            </button>
          ))}
        </div>

        {/* Severity filter */}
        <div className="flex gap-1 items-center">
          {(['all', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(s => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`px-2.5 py-1.5 rounded text-xs font-mono font-bold transition-all
                ${severityFilter === s
                  ? s === 'all'
                    ? 'bg-gray-600/40 text-gray-300 border border-gray-500/30'
                    : `badge-severity-${s}`
                  : 'text-gray-600 bg-bg-elevated border border-transparent hover:border-border'}`}
            >
              {s.toUpperCase()}
            </button>
          ))}
        </div>

        <span className="ml-auto text-xs font-mono text-gray-600 self-center">
          {filtered.length} alert{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Alert list */}
      <div className="flex-1 overflow-auto space-y-3">
        {filtered.length > 0
          ? filtered.map(a => <AlertCard key={a.id} alert={a} onAction={onAlertAction} />)
          : (
            <div className="card py-16 text-center">
              <CheckCircle className="w-12 h-12 text-gray-700 mx-auto mb-3" />
              <div className="text-gray-500 text-sm">No alerts match the current filters</div>
            </div>
          )
        }
      </div>
    </div>
  );
}
