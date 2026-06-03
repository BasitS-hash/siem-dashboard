import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { TimeSeriesPoint } from '../../types';

interface Props { data: TimeSeriesPoint[] }

const formatTime = (iso: string) => {
  const d = new Date(iso);
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
};

export default function EventsChart({ data }: Props) {
  const visible = data.filter((_, i) => i % 3 === 0 || i === data.length - 1);

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
        <defs>
          {[
            { key: 'critical', color: '#ff4444' },
            { key: 'high', color: '#ff8c00' },
            { key: 'medium', color: '#ffd700' },
            { key: 'low', color: '#00bfff' },
          ].map(({ key, color }) => (
            <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={color} stopOpacity={0.3} />
              <stop offset="95%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
        <XAxis
          dataKey="time"
          tickFormatter={formatTime}
          tick={{ fill: '#6e7681', fontSize: 11, fontFamily: 'JetBrains Mono' }}
          ticks={visible.map(d => d.time)}
          stroke="#30363d"
        />
        <YAxis tick={{ fill: '#6e7681', fontSize: 11 }} stroke="#30363d" />
        <Tooltip
          contentStyle={{ background: '#1c2128', border: '1px solid #30363d', borderRadius: '8px', fontSize: 12 }}
          labelFormatter={formatTime}
          itemStyle={{ color: '#e6edf3' }}
        />
        <Legend wrapperStyle={{ fontSize: 12, color: '#8b949e' }} />
        <Area type="monotone" dataKey="critical" stroke="#ff4444" fill="url(#grad-critical)" strokeWidth={1.5} dot={false} />
        <Area type="monotone" dataKey="high" stroke="#ff8c00" fill="url(#grad-high)" strokeWidth={1.5} dot={false} />
        <Area type="monotone" dataKey="medium" stroke="#ffd700" fill="url(#grad-medium)" strokeWidth={1.5} dot={false} />
        <Area type="monotone" dataKey="low" stroke="#00bfff" fill="url(#grad-low)" strokeWidth={1.5} dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
