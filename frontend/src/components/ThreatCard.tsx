import type { MLPrediction, ThreatLevel } from '../types/analysis';
import { Shield, AlertTriangle, XCircle, HelpCircle, Clock } from 'lucide-react';

interface Props {
  prediction: MLPrediction;
  analysisTimeMs: number;
}

const CONFIG: Record<ThreatLevel, {
  icon: React.ReactNode;
  bg: string;
  border: string;
  badge: string;
  heading: string;
  iconColor: string;
  barColor: string;
  description: string;
}> = {
  Safe: {
    icon: <Shield size={28} />,
    bg: 'bg-green-50',
    border: 'border-green-200',
    badge: 'bg-green-100 text-green-700 border-green-200',
    heading: 'text-green-700',
    iconColor: 'text-green-600',
    barColor: '#16a34a',
    description: 'This URL passed all detection checks. No phishing indicators were detected.',
  },
  Suspicious: {
    icon: <AlertTriangle size={28} />,
    bg: 'bg-amber-50',
    border: 'border-amber-200',
    badge: 'bg-amber-100 text-amber-700 border-amber-200',
    heading: 'text-amber-700',
    iconColor: 'text-amber-600',
    barColor: '#d97706',
    description: 'This URL exhibits suspicious patterns. Exercise caution before visiting.',
  },
  Malicious: {
    icon: <XCircle size={28} />,
    bg: 'bg-red-50',
    border: 'border-red-200',
    badge: 'bg-red-100 text-red-700 border-red-200',
    heading: 'text-red-700',
    iconColor: 'text-red-600',
    barColor: '#dc2626',
    description: 'This URL is classified as malicious. Do not visit or share this link.',
  },
  Unknown: {
    icon: <HelpCircle size={28} />,
    bg: 'bg-gray-50',
    border: 'border-gray-200',
    badge: 'bg-gray-100 text-gray-600 border-gray-200',
    heading: 'text-gray-700',
    iconColor: 'text-gray-500',
    barColor: '#6b7280',
    description: 'Unable to determine the threat level for this URL.',
  },
};

export default function ThreatCard({ prediction, analysisTimeMs }: Props) {
  const cfg = CONFIG[prediction.label] ?? CONFIG.Unknown;
  const confidencePct = Math.round(prediction.confidence * 100);
  const threatPct = Math.round(prediction.threat_probability * 100);

  return (
    <div className={`rounded-xl border ${cfg.bg} ${cfg.border} p-6 shadow-sm`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className={cfg.iconColor}>{cfg.icon}</div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full border ${cfg.badge}`}>
            {prediction.label}
          </span>
          <span className="inline-flex items-center gap-1 text-xs text-gray-400 bg-white border border-gray-200 px-2.5 py-1 rounded-full font-medium">
            <Clock size={11} />
            {analysisTimeMs}ms
          </span>
        </div>
      </div>

      {/* Verdict */}
      <div className={`text-2xl font-black mb-1 ${cfg.heading}`}>
        {prediction.label === 'Safe' ? 'URL is Safe' :
         prediction.label === 'Malicious' ? 'Malicious URL' :
         prediction.label === 'Suspicious' ? 'Suspicious URL' : 'Unknown'}
      </div>
      <p className="text-sm text-gray-500 mb-5">{cfg.description}</p>

      {/* Progress bars */}
      <div className="space-y-4">
        {/* Model Confidence */}
        <div>
          <div className="flex justify-between items-center mb-1.5">
            <span className="text-xs font-semibold text-gray-500">Model Confidence</span>
            <span className="text-xs font-bold text-gray-700">{confidencePct}%</span>
          </div>
          <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-1000"
              style={{ width: `${confidencePct}%`, backgroundColor: cfg.barColor }}
            />
          </div>
        </div>

        {/* Threat Probability */}
        <div>
          <div className="flex justify-between items-center mb-1.5">
            <span className="text-xs font-semibold text-gray-500">Threat Probability</span>
            <span className="text-xs font-bold text-gray-700">{threatPct}%</span>
          </div>
          <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-1000"
              style={{
                width: `${threatPct}%`,
                background: 'linear-gradient(90deg, #22c55e 0%, #f59e0b 50%, #ef4444 100%)',
                backgroundSize: '300px 8px',
                backgroundPosition: `${-((100 - threatPct) / 100) * 200}px 0`,
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
