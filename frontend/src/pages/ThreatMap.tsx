import { useMemo } from 'react';
import { Globe, Wifi } from 'lucide-react';
import { LogEvent } from '../types';

interface Props {
  logs: LogEvent[];
}

interface AttackerNode {
  ip: string;
  country: string;
  city: string;
  count: number;
  lat: number;
  lon: number;
  topSeverity: string;
}

// Map lon/lat → SVG x/y using equirectangular projection
function project(lon: number, lat: number, w: number, h: number): [number, number] {
  const x = ((lon + 180) / 360) * w;
  const y = ((90 - lat) / 180) * h;
  return [x, y];
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ff4444',
  high: '#ff8c00',
  medium: '#ffd700',
  low: '#00bfff',
  info: '#6e7681',
};

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export default function ThreatMap({ logs }: Props) {
  const W = 900;
  const H = 450;

  const attackers = useMemo<AttackerNode[]>(() => {
    const map = new Map<string, AttackerNode>();
    for (const log of logs) {
      if (!log.geo) continue;
      const existing = map.get(log.source_ip);
      if (existing) {
        existing.count++;
        if (SEV_ORDER.indexOf(log.severity) < SEV_ORDER.indexOf(existing.topSeverity)) {
          existing.topSeverity = log.severity;
        }
      } else {
        map.set(log.source_ip, {
          ip: log.source_ip,
          country: log.geo.country,
          city: log.geo.city,
          count: 1,
          lat: log.geo.lat,
          lon: log.geo.lon,
          topSeverity: log.severity,
        });
      }
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  }, [logs]);

  const topAttackers = attackers.slice(0, 15);
  const maxCount = topAttackers[0]?.count ?? 1;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Globe className="w-5 h-5 text-accent-cyan" />
        <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
          Global Threat Map
        </h2>
        <span className="text-xs text-gray-500 font-mono">
          {attackers.length} active source{attackers.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* SVG world map */}
      <div className="card p-4 relative overflow-hidden">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="w-full rounded"
          style={{ background: 'linear-gradient(180deg, #0a1628 0%, #0d1f3c 100%)', minHeight: 260 }}
        >
          {/* Grid lines */}
          {[-60, -30, 0, 30, 60].map(lat => {
            const [, y] = project(0, lat, W, H);
            return <line key={lat} x1={0} y1={y} x2={W} y2={y} stroke="#ffffff08" strokeWidth={0.5} />;
          })}
          {[-120, -60, 0, 60, 120].map(lon => {
            const [x] = project(lon, 0, W, H);
            return <line key={lon} x1={x} y1={0} x2={x} y2={H} stroke="#ffffff08" strokeWidth={0.5} />;
          })}

          {/* Attack source dots */}
          {topAttackers.map((node) => {
            const [x, y] = project(node.lon, node.lat, W, H);
            const color = SEV_COLOR[node.topSeverity] ?? '#6e7681';
            const r = 4 + (node.count / maxCount) * 10;
            return (
              <g key={node.ip}>
                {/* Pulse ring */}
                <circle cx={x} cy={y} r={r + 4} fill="none" stroke={color} strokeWidth={1} opacity={0.3}>
                  <animate attributeName="r" from={r} to={r + 12} dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" from={0.4} to={0} dur="2s" repeatCount="indefinite" />
                </circle>
                {/* Core dot */}
                <circle cx={x} cy={y} r={r} fill={color} opacity={0.85}>
                  <title>{node.ip} ({node.country}) — {node.count} events</title>
                </circle>
              </g>
            );
          })}

          {/* Equator label */}
          <text x={8} y={H / 2 + 4} fill="#ffffff20" fontSize={9} fontFamily="monospace">0°</text>
        </svg>

        {/* Legend */}
        <div className="mt-3 flex items-center gap-4 flex-wrap">
          {(['critical', 'high', 'medium', 'low'] as const).map(s => (
            <div key={s} className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: SEV_COLOR[s] }} />
              <span className="text-xs text-gray-500 capitalize">{s}</span>
            </div>
          ))}
          <span className="ml-auto text-xs text-gray-600 font-mono">Dot size = event volume</span>
        </div>
      </div>

      {/* Top attacker table */}
      <div className="card p-4">
        <div className="text-xs text-gray-500 uppercase font-medium tracking-wider mb-3 flex items-center gap-2">
          <Wifi className="w-3.5 h-3.5" />
          Top Threat Sources
        </div>
        <div className="overflow-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-2 py-2 text-gray-600 font-medium">#</th>
                <th className="text-left px-2 py-2 text-gray-600 font-medium">IP Address</th>
                <th className="text-left px-2 py-2 text-gray-600 font-medium">Location</th>
                <th className="text-left px-2 py-2 text-gray-600 font-medium">Top Severity</th>
                <th className="text-right px-2 py-2 text-gray-600 font-medium">Events</th>
                <th className="px-2 py-2 w-32">Volume</th>
              </tr>
            </thead>
            <tbody>
              {topAttackers.map((node, i) => (
                <tr key={node.ip} className="border-b border-border/20 hover:bg-white/3">
                  <td className="px-2 py-1.5 text-gray-600">{i + 1}</td>
                  <td className="px-2 py-1.5 text-accent-cyan">{node.ip}</td>
                  <td className="px-2 py-1.5 text-gray-400">{node.city}, {node.country}</td>
                  <td className="px-2 py-1.5">
                    <span
                      className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
                      style={{ color: SEV_COLOR[node.topSeverity], background: `${SEV_COLOR[node.topSeverity]}20` }}
                    >
                      {node.topSeverity}
                    </span>
                  </td>
                  <td className="px-2 py-1.5 text-right text-gray-300">{node.count.toLocaleString()}</td>
                  <td className="px-2 py-1.5">
                    <div className="h-1.5 bg-bg-elevated rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${(node.count / maxCount) * 100}%`,
                          background: SEV_COLOR[node.topSeverity],
                        }}
                      />
                    </div>
                  </td>
                </tr>
              ))}
              {topAttackers.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-2 py-8 text-center text-gray-600">
                    No geo-tagged events yet — connecting...
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
