import { LogEvent, Severity, EventCategory } from '../types';
import SeverityBadge from './SeverityBadge';

interface Props {
  logs: LogEvent[];
  maxRows?: number;
  compact?: boolean;
}

const CAT_COLORS: Record<EventCategory, string> = {
  authentication: 'text-purple-400',
  network: 'text-cyan-400',
  web: 'text-green-400',
  system: 'text-orange-400',
  firewall: 'text-yellow-400',
};

function formatTime(iso: string) {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function LogTable({ logs, maxRows = 50, compact = false }: Props) {
  const rows = logs.slice(0, maxRows);

  return (
    <div className="overflow-auto w-full">
      <table className="w-full text-xs font-mono border-collapse min-w-[800px]">
        <thead className="sticky top-0 z-10">
          <tr className="bg-bg-elevated border-b border-border">
            <th className="text-left px-3 py-2 text-gray-500 font-medium w-20">Time</th>
            <th className="text-left px-3 py-2 text-gray-500 font-medium w-20">Severity</th>
            <th className="text-left px-3 py-2 text-gray-500 font-medium w-24">Category</th>
            <th className="text-left px-3 py-2 text-gray-500 font-medium w-28">Source IP</th>
            {!compact && <th className="text-left px-3 py-2 text-gray-500 font-medium w-28">Dest IP:Port</th>}
            <th className="text-left px-3 py-2 text-gray-500 font-medium">Message</th>
            {!compact && <th className="text-left px-3 py-2 text-gray-500 font-medium w-16">Action</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((log, i) => (
            <tr
              key={log.id}
              className={`log-row-${log.severity} border-b border-border/30 hover:bg-white/3 transition-colors
                ${i === 0 ? 'animate-slide-in' : ''}`}
            >
              <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">{formatTime(log.timestamp)}</td>
              <td className="px-3 py-1.5"><SeverityBadge severity={log.severity} /></td>
              <td className={`px-3 py-1.5 ${CAT_COLORS[log.category]} uppercase font-bold text-[10px]`}>
                {log.category.slice(0, 6)}
              </td>
              <td className="px-3 py-1.5 text-gray-300 whitespace-nowrap">{log.source_ip}</td>
              {!compact && (
                <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">
                  {log.destination_ip}:{log.destination_port}
                </td>
              )}
              <td className="px-3 py-1.5 text-gray-300 max-w-xs truncate" title={log.message}>
                {log.message}
              </td>
              {!compact && (
                <td className={`px-3 py-1.5 uppercase font-bold text-[10px] ${log.action === 'block' ? 'text-red-400' : log.action === 'failure' ? 'text-orange-400' : 'text-gray-500'}`}>
                  {log.action}
                </td>
              )}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={7} className="px-3 py-8 text-center text-gray-600">Waiting for events...</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
