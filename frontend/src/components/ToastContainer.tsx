import { X, AlertTriangle, Info } from 'lucide-react';
import { Toast } from '../hooks/useToast';

interface Props {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}

const SEV_STYLES: Record<Toast['severity'], string> = {
  critical: 'border-red-500/50 bg-red-500/10 text-red-300',
  high: 'border-orange-500/50 bg-orange-500/10 text-orange-300',
  info: 'border-border bg-bg-card text-gray-300',
};

export default function ToastContainer({ toasts, onDismiss }: Props) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`pointer-events-auto flex items-start gap-3 px-4 py-3 rounded-lg border text-sm max-w-sm shadow-lg backdrop-blur-sm ${SEV_STYLES[t.severity]}`}
        >
          {t.severity === 'critical' || t.severity === 'high'
            ? <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            : <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
          }
          <span className="flex-1 leading-snug">{t.message}</span>
          <button onClick={() => onDismiss(t.id)} className="flex-shrink-0 opacity-60 hover:opacity-100 transition-opacity">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}
