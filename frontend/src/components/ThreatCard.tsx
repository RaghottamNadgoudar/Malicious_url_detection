import type { MLPrediction, ThreatLevel } from '../types/analysis';
import { Shield, AlertTriangle, XCircle, HelpCircle } from 'lucide-react';

interface Props {
  prediction: MLPrediction;
  analysisTimeMs: number;
}

const CONFIG: Record<ThreatLevel, {
  icon: React.ReactNode;
  gradient: string;
  border: string;
  badge: string;
  textColor: string;
  description: string;
}> = {
  Safe: {
    icon: <Shield size={32} />,
    gradient: 'from-green-500/20 to-emerald-500/5',
    border: 'border-green-500/40',
    badge: 'bg-green-500/20 text-green-300 border-green-500/40',
    textColor: 'text-green-300',
    description: 'This URL appears safe. No threats detected.',
  },
  Suspicious: {
    icon: <AlertTriangle size={32} />,
    gradient: 'from-amber-500/20 to-yellow-500/5',
    border: 'border-amber-500/40',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    textColor: 'text-amber-300',
    description: 'This URL exhibits suspicious patterns. Proceed with caution.',
  },
  Malicious: {
    icon: <XCircle size={32} />,
    gradient: 'from-red-500/20 to-rose-500/5',
    border: 'border-red-500/40',
    badge: 'bg-red-500/20 text-red-300 border-red-500/40',
    textColor: 'text-red-300',
    description: 'This URL is classified as malicious. Do not visit.',
  },
  Unknown: {
    icon: <HelpCircle size={32} />,
    gradient: 'from-slate-500/20 to-slate-700/5',
    border: 'border-slate-600/40',
    badge: 'bg-slate-700/40 text-slate-300 border-slate-600/40',
    textColor: 'text-slate-300',
    description: 'Unable to determine threat level.',
  },
};

export default function ThreatCard({ prediction, analysisTimeMs }: Props) {
  const cfg = CONFIG[prediction.label] || CONFIG.Unknown;
  const confidencePct = Math.round(prediction.confidence * 100);
  const threatPct = Math.round(prediction.threat_probability * 100);

  return (
    <div className={`rounded-2xl bg-gradient-to-br ${cfg.gradient} border ${cfg.border} p-6`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className={`${cfg.textColor}`}>{cfg.icon}</div>
        <span className={`text-xs font-medium px-3 py-1 rounded-full border ${cfg.badge}`}>
          {analysisTimeMs}ms
        </span>
      </div>

      {/* Verdict */}
      <div className="mt-4">
        <div className={`text-3xl font-black ${cfg.textColor}`}>{prediction.label}</div>
        <p className="text-slate-400 text-sm mt-1">{cfg.description}</p>
      </div>

      {/* Confidence bar */}
      <div className="mt-5 space-y-3">
        <div>
          <div className="flex justify-between text-xs mb-1.5">
            <span className="text-slate-400">Model Confidence</span>
            <span className={`font-semibold ${cfg.textColor}`}>{confidencePct}%</span>
          </div>
          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${confidencePct}%`,
                background: prediction.label === 'Safe'
                  ? '#22c55e'
                  : prediction.label === 'Suspicious'
                  ? '#f59e0b'
                  : '#ef4444',
              }}
            />
          </div>
        </div>

        <div>
          <div className="flex justify-between text-xs mb-1.5">
            <span className="text-slate-400">Threat Probability</span>
            <span className="font-semibold text-slate-300">{threatPct}%</span>
          </div>
          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-green-500 via-amber-500 to-red-500 transition-all duration-700"
              style={{ width: `${threatPct}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
