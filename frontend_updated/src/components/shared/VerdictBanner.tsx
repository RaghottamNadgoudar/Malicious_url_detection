import { CheckCircle, AlertTriangle, XCircle, Zap, Clock, Tag } from 'lucide-react';
import type { Verdict, ExitTier } from '../../types/daaApi';

interface VerdictBannerProps {
  verdict:    Verdict;
  confidence: number;
  exitTier:   ExitTier;
  latencyMs:  number;
  reasoning:  string;
  url:        string;
}

const VERDICT_CONFIG = {
  safe: {
    label:     'SAFE',
    Icon:      CheckCircle,
    colorText: 'text-safe',
    colorBg:   'bg-safe/10',
    colorBdr:  'border-safe/30',
    glow:      '0 0 30px rgba(34,197,94,0.2)',
    barColor:  'bg-safe',
  },
  suspicious: {
    label:     'SUSPICIOUS',
    Icon:      AlertTriangle,
    colorText: 'text-suspicious',
    colorBg:   'bg-suspicious/10',
    colorBdr:  'border-suspicious/30',
    glow:      '0 0 30px rgba(245,158,11,0.2)',
    barColor:  'bg-suspicious',
  },
  malicious: {
    label:     'MALICIOUS',
    Icon:      XCircle,
    colorText: 'text-malicious',
    colorBg:   'bg-malicious/10',
    colorBdr:  'border-malicious/30',
    glow:      '0 0 30px rgba(239,68,68,0.2)',
    barColor:  'bg-malicious',
  },
  error: {
    label:     'ERROR',
    Icon:      XCircle,
    colorText: 'text-white/40',
    colorBg:   'bg-white/5',
    colorBdr:  'border-white/10',
    glow:      'none',
    barColor:  'bg-white/20',
  },
} as const;

const TIER_LABELS: Record<ExitTier, string> = {
  'T0-PageRank':   'Tier 0 — Open PageRank',
  'T0-URLhaus':    'Tier 0 — URLhaus Threat Intel',
  'T0-Umbrella':   'Tier 0 — Cisco Umbrella',
  'T1-Whitelist':  'Tier 1 — Whitelist',
  'T2-DistilBERT': 'Tier 2 — DistilBERT',
  'T3-HardSignal': 'Tier 3 — Hard Signal',
};

export default function VerdictBanner({
  verdict, confidence, exitTier, latencyMs, reasoning, url,
}: VerdictBannerProps) {
  const cfg = VERDICT_CONFIG[verdict] ?? VERDICT_CONFIG.error;
  const { label, Icon, colorText, colorBg, colorBdr, glow, barColor } = cfg;
  const pct = Math.round(confidence * 100);

  return (
    <div
      className={`glass border ${colorBdr} p-6 rounded-2xl animate-fade-in`}
      style={{ boxShadow: glow }}
    >
      <div className="flex flex-col sm:flex-row sm:items-center gap-4">
        {/* Left: icon + verdict label */}
        <div className={`flex items-center gap-3 ${colorBg} rounded-xl px-5 py-4 min-w-[180px]`}>
          <Icon size={32} className={`${colorText} shrink-0`} />
          <div>
            <div className={`text-xl font-bold tracking-widest ${colorText}`}>{label}</div>
            <div className="text-xs text-white/40 mt-0.5">{pct}% confidence</div>
          </div>
        </div>

        {/* Right: URL + meta */}
        <div className="flex-1 min-w-0">
          <p className="font-mono text-xs text-white/50 truncate mb-1" title={url}>{url}</p>

          {/* Confidence bar */}
          <div className="score-bar-track mb-3">
            <div
              className={`score-bar-fill ${barColor}`}
              style={{ width: `${pct}%` }}
            />
          </div>

          <div className="flex flex-wrap gap-3 text-xs text-white/50">
            <span className="flex items-center gap-1.5">
              <Tag size={11} />
              <span className="font-mono text-white/70">{TIER_LABELS[exitTier]}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <Clock size={11} />
              <span>{latencyMs.toFixed(0)} ms</span>
            </span>
            <span className="flex items-center gap-1.5">
              <Zap size={11} />
              <span className="italic text-white/40">{reasoning.slice(0, 100)}{reasoning.length > 100 ? '…' : ''}</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
