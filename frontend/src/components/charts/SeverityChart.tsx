import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

interface Props {
  data: { severity: string; count: number; color: string }[];
}

const RADIAN = Math.PI / 180;
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }: {
  cx: number; cy: number; midAngle: number; innerRadius: number; outerRadius: number; percent: number;
}) => {
  if (percent < 0.05) return null;
  const r = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + r * Math.cos(-midAngle * RADIAN);
  const y = cy + r * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontFamily="JetBrains Mono" fontWeight="bold">
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

export default function SeverityChart({ data }: Props) {
  const filtered = data.filter(d => d.count > 0);
  if (filtered.length === 0) return <div className="flex items-center justify-center h-full text-gray-600 text-sm">No data</div>;

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={filtered}
          cx="50%"
          cy="50%"
          labelLine={false}
          label={renderCustomLabel}
          outerRadius={80}
          innerRadius={40}
          dataKey="count"
          nameKey="severity"
        >
          {filtered.map((entry, i) => (
            <Cell key={i} fill={entry.color} stroke="transparent" />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: '#1c2128', border: '1px solid #30363d', borderRadius: '8px', fontSize: 12 }}
          formatter={(val, name) => [val, String(name).toUpperCase()]}
        />
        <Legend
          formatter={(val) => <span style={{ color: '#8b949e', fontSize: 12 }}>{String(val).toUpperCase()}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
