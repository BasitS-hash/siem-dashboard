import { Shield, LayoutDashboard, Radio, Bell, BookOpen, Globe, Wifi, WifiOff } from 'lucide-react';
import { Page } from '../types';

interface SidebarProps {
  currentPage: Page;
  onNavigate: (page: Page) => void;
  activeAlertCount: number;
  newCritical: number;
  isConnected: boolean;
}

const NAV_ITEMS: { id: Page; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { id: 'livefeed', label: 'Live Feed', icon: Radio },
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'threatmap', label: 'Threat Map', icon: Globe },
  { id: 'rules', label: 'Detection Rules', icon: BookOpen },
];

export default function Sidebar({ currentPage, onNavigate, activeAlertCount, newCritical, isConnected }: SidebarProps) {
  return (
    <aside className="w-16 lg:w-56 flex flex-col bg-bg-secondary border-r border-border flex-shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-border">
        <div className="relative">
          <Shield className="w-8 h-8 text-accent-cyan" />
          {isConnected && (
            <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-accent-green rounded-full blink" />
          )}
        </div>
        <div className="hidden lg:block">
          <div className="text-sm font-bold text-white tracking-wide">SentinelView</div>
          <div className="text-xs text-gray-500">SIEM Dashboard</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 space-y-1 px-2">
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
          const active = currentPage === id;
          const isAlerts = id === 'alerts';
          const badge = isAlerts && activeAlertCount > 0 ? activeAlertCount : 0;
          const hasCritical = isAlerts && newCritical > 0;

          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group relative
                ${active
                  ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20'
                  : 'text-gray-400 hover:text-gray-100 hover:bg-bg-elevated'
                }`}
            >
              <Icon className={`w-4 h-4 flex-shrink-0 ${isAlerts && hasCritical ? 'text-red-400' : ''}`} />
              <span className="hidden lg:block">{label}</span>
              {badge > 0 && (
                <span className={`hidden lg:flex ml-auto items-center justify-center min-w-[20px] h-5 px-1 rounded-full text-xs font-bold
                  ${hasCritical ? 'bg-red-500 text-white animate-pulse' : 'bg-gray-600 text-gray-200'}`}>
                  {badge > 99 ? '99+' : badge}
                </span>
              )}
              {/* Mobile badge dot */}
              {badge > 0 && (
                <span className={`lg:hidden absolute top-1 right-1 w-2 h-2 rounded-full ${hasCritical ? 'bg-red-500' : 'bg-gray-400'}`} />
              )}
            </button>
          );
        })}
      </nav>

      {/* Connection status */}
      <div className="px-4 py-4 border-t border-border">
        <div className="flex items-center gap-2">
          {isConnected
            ? <Wifi className="w-4 h-4 text-accent-green flex-shrink-0" />
            : <WifiOff className="w-4 h-4 text-red-400 flex-shrink-0" />
          }
          <span className={`hidden lg:block text-xs font-mono ${isConnected ? 'text-accent-green' : 'text-red-400'}`}>
            {isConnected ? 'CONNECTED' : 'OFFLINE'}
          </span>
        </div>
        <div className="hidden lg:block text-xs text-gray-600 mt-1 font-mono">ws://localhost:3001</div>
      </div>
    </aside>
  );
}
