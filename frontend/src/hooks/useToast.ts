import { useState, useCallback } from 'react';

export interface Toast {
  id: string;
  message: string;
  severity: 'critical' | 'high' | 'info';
}

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((message: string, severity: Toast['severity'] = 'info') => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts(prev => [...prev, { id, message, severity }].slice(-5));
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, severity === 'critical' ? 8000 : 4000);
  }, []);

  const dismiss = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return { toasts, addToast, dismiss };
}
