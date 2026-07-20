import { useEffect, useRef, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import { LogEvent, Alert, Stats } from '../types';

// Shared base URL for the socket connection and REST calls. When unset, REST
// calls stay same-origin so the dev Vite proxy (and any prod reverse proxy)
// can route /api and /socket.io to the backend consistently.
const BACKEND_BASE = import.meta.env.VITE_BACKEND_URL ?? '';

interface SocketHandlers {
  onLog: (event: LogEvent) => void;
  onAlert: (alert: Alert) => void;
  onAlertUpdated: (alert: Alert) => void;
  onStats: (stats: Stats) => void;
  onInit: (data: { logs: LogEvent[]; alerts: Alert[]; stats: Stats }) => void;
  onConnect: () => void;
  onDisconnect: () => void;
}

export function useSocket(handlers: SocketHandlers) {
  const socketRef = useRef<Socket | null>(null);
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    // Empty base ⇒ same-origin (dev uses the Vite proxy). A dev fallback host is
    // only applied to the socket connection, which cannot go through the proxy.
    const socket = io(BACKEND_BASE || 'http://localhost:3001', { transports: ['websocket', 'polling'] });
    socketRef.current = socket;

    socket.on('connect', () => handlersRef.current.onConnect());
    socket.on('disconnect', () => handlersRef.current.onDisconnect());
    socket.on('init', (data) => handlersRef.current.onInit(data));
    socket.on('log', (event) => handlersRef.current.onLog(event));
    socket.on('alert', (alert) => handlersRef.current.onAlert(alert));
    socket.on('alert_updated', (alert) => handlersRef.current.onAlertUpdated(alert));
    socket.on('stats', (stats) => handlersRef.current.onStats(stats));

    return () => { socket.disconnect(); };
  }, []);

  const updateAlertStatus = useCallback(async (id: string, status: 'acknowledged' | 'resolved'): Promise<void> => {
    const res = await fetch(`${BACKEND_BASE}/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(err.error ?? `HTTP ${res.status}`);
    }
  }, []);

  return { updateAlertStatus };
}
