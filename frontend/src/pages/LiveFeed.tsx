import { useState, useRef, useEffect } from 'react';
import { Search, Pause, Play, Download } from 'lucide-react';
import { exportLogsCsv } from '../lib/exportCsv';
import { LogEvent, Severity, EventCategory } from '../types';
import SeverityBadge from '../components/SeverityBadge';

interface Props { logs: LogEvent[] }

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORIES: EventCategory[] = ['authentication', 'network', 'web', 'system', 'firewall'];

const CAT_COLORS: Record<EventCategory, string> = {
  authentication: 'text-purple-400',
  network: 'text-cyan-400',
  web: 'text-green-400',
  system: 'text-orange-400',
  firewall: 'text-yellow-400',
};

function fmt(iso: string) {
  const d = new Date(iso);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString('en-US', { hour12: false })}`;
}

export default function LiveFeed({ logs }: Props) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [categoryFilter, setCategoryFilter] = useState<Set<EventCategory>>(new Set());
  const [paused, setPaused] = useState(false);
  const [frozenLogs, setFrozenLogs] = useState<LogEvent[]>([]);
  const tableRef = useRef<HTMLDivElement>(null);

  // When paused, freeze the log list
  useEffect(() => {
    if (!paused) setFrozenLogs([]);
  }, [paused]);

  const displayLogs = paused ? frozenLogs : logs;

  const filtered = displayLogs.filter(l => {
    if (severityFilter.size > 0 && !severityFilter.has(l.severity)) return false;
    if (categoryFilter.size > 0 && !categoryFilter.has(l.category)) return false;
    if (search) {
      const q = search.toLowerCase();
      return l.message.toLowerCase().includes(q) ||
        l.source_ip.includes(q) ||
        l.tags.some(t => t.includes(q)) ||
        (l.user?.toLowerCase().includes(q) ?? false);
    }
    return true;
  });

  const toggleSeverity = (s: Severity) => {
    setSeverityFilter(prev => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });
  };

  const toggleCategory = (c: EventCategory) => {
    setCategoryFilter(prev => {
      const next = new Set(prev);
      next.has(c) ? next.delete(c) : next.add(c);
      return next;
    });
  };

  const handlePause = () => {
    if (!paused) setFrozenLogs([...logs]);
    setPaused(p => !p);
  };

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Controls */}
      <div className="card p-3 flex flex-col lg:flex-row gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search message, IP, user, tag..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-bg-elevated border border-border rounded-lg text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-accent-cyan/50 font-mono"
          />
        </div>

        {/* Severity filters */}
        <div className="flex items-center gap-1 flex-wrap">
          {SEVERITIES.map(s => (
            <button
              key={s}
              onClick={() => toggleSeverity(s)}
              className={`px-2 py-1 rounded text-xs font-mono font-bold transition-all
                ${severityFilter.has(s) ? `badge-severity-${s}` : 'text-gray-600 bg-bg-elevated border border-transparent hover:border-border'}`}
            >
              {s.toUpperCase()}
            </button>
          ))}
        </div>

        {/* Pause */}
        <button
          onClick={handlePause}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all flex-shrink-0
            ${paused ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' : 'bg-bg-elevated text-gray-400 border border-border hover:text-white'}`}
        >
          {paused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
          {paused ? 'Resume' : 'Pause'}
        </button>
        {/* Export */}
        <button
          onClick={() => exportLogsCsv(filtered)}
          className="flex items-center gap-2 px-3 py-2 bg-bg-elevated text-gray-400 border border-border rounded-lg text-sm hover:text-white hover:border-accent-cyan/40 transition-all flex-shrink-0"
        >
          <Download className="w-4 h-4" />
          <span className="hidden lg:inline">Export CSV</span>
        </button>
      </div>

      {/* Category filter pills */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-gray-600 uppercase font-medium">Category:</span>
        {CATEGORIES.map(c => (
          <button
            key={c}
            onClick={() => toggleCategory(c)}
            className={`px-2.5 py-1 rounded-full text-xs font-mono transition-all
              ${categoryFilter.has(c)
                ? `${CAT_COLORS[c]} bg-current/10 border border-current/30`
                : 'text-gray-600 border border-border hover:text-gray-400'}`}
          >
            {c}
          </button>
        ))}
        {(severityFilter.size > 0 || categoryFilter.size > 0 || search) && (
          <button
            onClick={() => { setSeverityFilter(new Set()); setCategoryFilter(new Set()); setSearch(''); }}
            className="px-2.5 py-1 rounded-full text-xs text-gray-500 border border-border hover:text-red-400 hover:border-red-400/30 transition-all"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto text-xs font-mono text-gray-600">
          {filtered.length.toLocaleString()} events shown
          {paused && <span className="ml-2 text-yellow-400"> ⏸ PAUSED</span>}
        </span>
      </div>

      {/* Log table */}
      <div ref={tableRef} className="card flex-1 overflow-auto relative">
        <div className="overflow-auto h-full">
          <table className="w-full text-xs font-mono border-collapse min-w-[900px]">
            <thead className="sticky top-0 z-10">
              <tr className="bg-bg-elevated border-b border-border">
                <th className="text-left px-3 py-2.5 text-gray-500 font-medium w-36">Timestamp</th>
                <th className="text-left px-3 py-2.5 text-gray-500 font-medium w-20">Severity</th>
                <th className="text-left px-3 py-2.5 text-gray-500 font-medium w-24">Category</th>
                <th className="text-left px-3 py-2.5 text-gray-500 font-medium w-28">Source IP</th>
                <th className="text-left px-3 py-2.5 text-gray-500 font-medium w-32">Dest IP:Port</th>
                <th className="text-left px-3 py-2.5 text-gray-500 font-medium w-20">User</th>
                <th className="text-left px-3 py-2.5 text-gray-500 font-medium">Message</th>
                <th className="text-left px-3 py-2.5 text-gray-500 font-medium w-16">Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 500).map((log, i) => (
                <tr
                  key={log.id}
                  className={`log-row-${log.severity} border-b border-border/20 hover:bg-white/3 transition-colors
                    ${i === 0 && !paused ? 'animate-slide-in' : ''}`}
                >
                  <td className="px-3 py-1.5 text-gray-600 whitespace-nowrap">{fmt(log.timestamp)}</td>
                  <td className="px-3 py-1.5"><SeverityBadge severity={log.severity} /></td>
                  <td className={`px-3 py-1.5 uppercase text-[10px] font-bold ${CAT_COLORS[log.category]}`}>
                    {log.category}
                  </td>
                  <td className="px-3 py-1.5 text-accent-cyan">{log.source_ip}</td>
                  <td className="px-3 py-1.5 text-gray-500">
                    {log.destination_ip}:{log.destination_port}
                  </td>
                  <td className="px-3 py-1.5 text-gray-400">{log.user ?? '—'}</td>
                  <td className="px-3 py-1.5 text-gray-300 max-w-sm" title={log.message}>
                    <span className="line-clamp-1">{log.message}</span>
                    {log.tags.length > 0 && (
                      <div className="flex gap-1 mt-0.5 flex-wrap">
                        {log.tags.slice(0, 4).map(t => (
                          <span key={t} className="text-[9px] text-gray-600 bg-bg-elevated px-1 rounded">{t}</span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className={`px-3 py-1.5 uppercase text-[10px] font-bold
                    ${log.action === 'block' || log.action === 'failure' ? 'text-red-400' : 'text-gray-600'}`}>
                    {log.action}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-3 py-12 text-center text-gray-600">
                    {logs.length === 0 ? 'Connecting to event stream...' : 'No events match filters'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
