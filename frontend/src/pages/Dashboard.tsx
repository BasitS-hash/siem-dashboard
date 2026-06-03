import { Activity, AlertTriangle, Shield, Zap, Globe, TrendingUp } from 'lucide-react';
import { LogEvent, Alert, Stats } from '../types';
import StatCard from '../components/StatCard';
import EventsChart from '../components/charts/EventsChart';
import SeverityChart from '../components/charts/SeverityChart';
import TopAttackersChart from '../components/charts/TopAttackersChart';
import CategoryChart from '../components/charts/CategoryChart';
import LogTable from '../components/LogTable';
import AlertCard from '../components/AlertCard';

interface Props {
  logs: LogEvent[];
  alerts: Alert[];
  stats: Stats | null;
  onAlertAction: (id: string, status: 'acknowledged' | 'resolved') => void;
}

export default function Dashboard({ logs, alerts, stats, onAlertAction }: Props) {
  const recentAlerts = alerts.filter(a => a.status === 'active').slice(0, 3);

  return (
    <div className="space-y-5">
      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <StatCard
          label="Total Events"
          value={stats?.total_events ?? 0}
          icon={Activity}
          iconColor="text-accent-cyan"
          subValue={`${stats?.events_per_minute ?? 0} evt/min`}
        />
        <StatCard
          label="Active Threats"
          value={stats?.active_threats ?? 0}
          icon={AlertTriangle}
          iconColor="text-red-400"
          critical={(stats?.active_threats ?? 0) > 0}
          pulse={(stats?.active_threats ?? 0) > 0}
        />
        <StatCard
          label="Critical Alerts"
          value={stats?.critical_alerts ?? 0}
          icon={Shield}
          iconColor="text-red-400"
          critical={(stats?.critical_alerts ?? 0) > 0}
        />
        <StatCard
          label="Events / Min"
          value={stats?.events_per_minute ?? 0}
          icon={Zap}
          iconColor="text-yellow-400"
          subValue="live rate"
        />
        <StatCard
          label="Unique IPs"
          value={stats?.unique_ips ?? 0}
          icon={Globe}
          iconColor="text-accent-purple"
        />
        <StatCard
          label="Alert Rate"
          value={`${(stats?.alert_rate ?? 0).toFixed(1)}%`}
          icon={TrendingUp}
          iconColor="text-accent-green"
          subValue="of all events"
        />
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 card p-4">
          <div className="text-xs text-gray-500 uppercase font-medium tracking-wider mb-3">
            Events Over Time — Last 30 Minutes
          </div>
          <div className="h-48">
            {stats ? <EventsChart data={stats.events_over_time} /> : <ChartSkeleton />}
          </div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-gray-500 uppercase font-medium tracking-wider mb-3">
            Severity Distribution
          </div>
          <div className="h-48">
            {stats ? <SeverityChart data={stats.severity_breakdown} /> : <ChartSkeleton />}
          </div>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="card p-4">
          <div className="text-xs text-gray-500 uppercase font-medium tracking-wider mb-3">
            Top Attackers by Event Volume
          </div>
          <div className="h-44">
            {stats ? <TopAttackersChart data={stats.top_source_ips} /> : <ChartSkeleton />}
          </div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-gray-500 uppercase font-medium tracking-wider mb-3">
            Event Category Breakdown
          </div>
          <div className="h-44">
            {stats ? <CategoryChart data={stats.category_breakdown} /> : <ChartSkeleton />}
          </div>
        </div>
      </div>

      {/* Bottom Row: Recent Alerts + Recent Logs */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="card p-4">
          <div className="text-xs text-gray-500 uppercase font-medium tracking-wider mb-3">
            Active Alerts ({recentAlerts.length})
          </div>
          <div className="space-y-3">
            {recentAlerts.length > 0
              ? recentAlerts.map(a => <AlertCard key={a.id} alert={a} onAction={onAlertAction} />)
              : <div className="py-6 text-center text-gray-600 text-sm">No active alerts</div>
            }
          </div>
        </div>
        <div className="card p-4 overflow-hidden">
          <div className="text-xs text-gray-500 uppercase font-medium tracking-wider mb-3">
            Recent Events
          </div>
          <LogTable logs={logs} maxRows={15} compact />
        </div>
      </div>
    </div>
  );
}

function ChartSkeleton() {
  return (
    <div className="h-full flex items-center justify-center">
      <div className="text-gray-600 text-sm animate-pulse">Loading data...</div>
    </div>
  );
}
