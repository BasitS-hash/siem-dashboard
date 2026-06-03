import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

interface Props {
  data: { ip: string; count: number }[];
}

export default function TopAttackersChart({ data }: Props) {
  const top = data.slice(0, 8);
  if (top.length === 0) return <div className="flex items-center justify-center h-full text-gray-600 text-sm">No data</div>;

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={top} layout="vertical" margin={{ top: 5, right: 20, left: 5, bottom: 5 }}>
        <XAxis type="number" tick={{ fill: '#6e7681', fontSize: 11 }} stroke="#30363d" />
        <YAxis
          type="category"
          dataKey="ip"
          width={110}
          tick={{ fill: '#8b949e', fontSize: 10, fontFamily: 'JetBrains Mono' }}
          stroke="#30363d"
        />
        <Tooltip
          contentStyle={{ background: '#1c2128', border: '1px solid #30363d', borderRadius: '8px', fontSize: 12 }}
          cursor={{ fill: '#ffffff08' }}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
          {top.map((_, i) => (
            <Cell key={i} fill={i === 0 ? '#ff4444' : i === 1 ? '#ff8c00' : i === 2 ? '#ffd700' : '#00d2ff'} fillOpacity={0.8} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
