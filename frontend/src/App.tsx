import { useState, useCallback, useRef } from 'react';
import { useSocket } from './hooks/useSocket';
import { useToast } from './hooks/useToast';
import { LogEvent, Alert, Stats, Page } from './types';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import ToastContainer from './components/ToastContainer';
import Dashboard from './pages/Dashboard';
import LiveFeed from './pages/LiveFeed';
import AlertsPage from './pages/Alerts';
import RulesPage from './pages/Rules';
import ThreatMap from './pages/ThreatMap';

const MAX_LOGS = 1000;
const MAX_ALERTS = 200;

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [isConnected, setIsConnected] = useState(false);
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [newCritical, setNewCritical] = useState(0);
  const logsRef = useRef<LogEvent[]>([]);
  const { toasts, addToast, dismiss } = useToast();

  const { updateAlertStatus } = useSocket({
    onConnect: useCallback(() => {
      setIsConnected(true);
      addToast('Connected to SIEM backend', 'info');
    }, [addToast]),
    onDisconnect: useCallback(() => {
      setIsConnected(false);
      addToast('Lost connection to backend — reconnecting...', 'high');
    }, [addToast]),

    onInit: useCallback((data) => {
      logsRef.current = data.logs;
      setLogs(data.logs);
      setAlerts(data.alerts);
      setStats(data.stats);
    }, []),

    onLog: useCallback((event) => {
      logsRef.current = [event, ...logsRef.current].slice(0, MAX_LOGS);
      setLogs(prev => [event, ...prev].slice(0, MAX_LOGS));
    }, []),

    onAlert: useCallback((alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, MAX_ALERTS));
      if (alert.severity === 'critical') {
        setNewCritical(c => c + 1);
        addToast(`CRITICAL: ${alert.title}`, 'critical');
      } else if (alert.severity === 'high') {
        addToast(`HIGH: ${alert.title}`, 'high');
      }
    }, [addToast]),

    onAlertUpdated: useCallback((updated) => {
      setAlerts(prev => prev.map(a => a.id === updated.id ? updated : a));
    }, []),

    onStats: useCallback((s) => setStats(s), []),
  });

  const handleAlertAction = async (id: string, status: 'acknowledged' | 'resolved') => {
    try {
      await updateAlertStatus(id, status);
    } catch (err) {
      addToast(`Failed to update alert: ${err instanceof Error ? err.message : 'Unknown error'}`, 'high');
    }
  };

  const activeAlertCount = alerts.filter(a => a.status === 'active').length;
  const pageProps = { logs, alerts, stats, onAlertAction: handleAlertAction };

  return (
    <div className="flex h-screen overflow-hidden bg-bg-primary">
      <Sidebar
        currentPage={page}
        onNavigate={(p) => { setPage(p); if (p === 'alerts') setNewCritical(0); }}
        activeAlertCount={activeAlertCount}
        newCritical={newCritical}
        isConnected={isConnected}
      />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Header page={page} isConnected={isConnected} stats={stats} />
        <main className="flex-1 overflow-auto p-4 lg:p-6">
          {page === 'dashboard' && <Dashboard {...pageProps} />}
          {page === 'livefeed' && <LiveFeed logs={logs} />}
          {page === 'alerts' && <AlertsPage alerts={alerts} onAlertAction={handleAlertAction} />}
          {page === 'rules' && <RulesPage />}
          {page === 'threatmap' && <ThreatMap logs={logs} />}
        </main>
      </div>
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </div>
  );
}
