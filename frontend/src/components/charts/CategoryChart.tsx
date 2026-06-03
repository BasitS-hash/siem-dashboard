import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, Tooltip } from 'recharts';

interface Props {
  data: { category: string; count: number }[];
}

const CATEGORY_COLORS: Record<string, string> = {
  authentication: '#a371f7',
  network: '#00d2ff',
  web: '#3fb950',
  system: '#ff8c00',
  firewall: '#ffd700',
};

export default function CategoryChart({ data }: Props) {
  if (data.length === 0) return <div className="flex items-center justify-center h-full text-gray-600 text-sm">No data</div>;

  return (
    <ResponsiveContainer width="100%" height="100%">
      <RadarChart data={data}>
        <PolarGrid stroke="#30363d" />
        <PolarAngleAxis
          dataKey="category"
          tick={{ fill: '#8b949e', fontSize: 11, fontFamily: 'JetBrains Mono' }}
          tickFormatter={(v) => v.toUpperCase().slice(0, 4)}
        />
        <Radar name="Events" dataKey="count" stroke="#00d2ff" fill="#00d2ff" fillOpacity={0.15} strokeWidth={2} />
        <Tooltip
          contentStyle={{ background: '#1c2128', border: '1px solid #30363d', borderRadius: '8px', fontSize: 12 }}
          formatter={(val, name) => [val, String(name)]}
        />
      </RadarChart>
    </ResponsiveContainer>
  );
}
