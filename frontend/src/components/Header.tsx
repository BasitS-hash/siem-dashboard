import { useEffect, useState } from 'react';
import { Activity, Zap } from 'lucide-react';
import { Page, Stats } from '../types';

const PAGE_TITLES: Record<Page, string> = {
  dashboard: 'Security Overview',
  livefeed: 'Live Event Feed',
  alerts: 'Alert Management',
  rules: 'Detection Rules',
  threatmap: 'Global Threat Map',
};

interface HeaderProps {
  page: Page;
  isConnected: boolean;
  stats: Stats | null;
}

export default function Header({ page, isConnected, stats }: HeaderProps) {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="flex items-center justify-between px-6 py-3 bg-bg-secondary border-b border-border flex-shrink-0">
      <div className="flex items-center gap-3">
        <h1 className="text-base font-semibold text-white">{PAGE_TITLES[page]}</h1>
        {isConnected && (
          <span className="flex items-center gap-1.5 text-xs font-mono text-accent-cyan bg-accent-cyan/10 border border-accent-cyan/20 px-2 py-0.5 rounded">
            <span className="w-1.5 h-1.5 bg-accent-cyan rounded-full blink" />
            LIVE
          </span>
        )}
      </div>

      <div className="flex items-center gap-4">
        {stats && (
          <div className="hidden md:flex items-center gap-4 text-xs font-mono text-gray-400">
            <div className="flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-accent-green" />
              <span><span className="text-white font-medium">{stats.events_per_minute}</span> evt/min</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-yellow-400" />
              <span><span className="text-white font-medium">{stats.active_threats}</span> active threats</span>
            </div>
          </div>
        )}
        <div className="text-xs font-mono text-gray-500">
          {time.toLocaleTimeString('en-US', { hour12: false })}
        </div>
      </div>
    </header>
  );
}
