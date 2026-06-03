import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  icon: LucideIcon;
  iconColor?: string;
  trend?: 'up' | 'down' | 'neutral';
  critical?: boolean;
  pulse?: boolean;
}

export default function StatCard({ label, value, subValue, icon: Icon, iconColor = 'text-accent-cyan', critical, pulse }: StatCardProps) {
  return (
    <div className={`card p-4 flex items-start gap-4 relative overflow-hidden
      ${critical ? 'border-red-500/40 bg-red-500/5' : ''}
      ${pulse ? 'animate-glow' : ''}
    `}>
      <div className={`p-2.5 rounded-lg bg-bg-elevated flex-shrink-0 ${critical ? 'bg-red-500/20' : ''}`}>
        <Icon className={`w-5 h-5 ${critical ? 'text-red-400' : iconColor}`} />
      </div>
      <div className="min-w-0">
        <div className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-1">{label}</div>
        <div className={`text-2xl font-bold font-mono tabular-nums ${critical && Number(value) > 0 ? 'text-red-400' : 'text-white'}`}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </div>
        {subValue && <div className="text-xs text-gray-500 mt-0.5">{subValue}</div>}
      </div>
      {critical && Number(value) > 0 && (
        <div className="absolute top-0 right-0 w-1 h-full bg-red-500/60" />
      )}
    </div>
  );
}
