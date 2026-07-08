import { HelpCircle, Database } from 'lucide-react';
import type { DaaUmbrellaResult } from '../../types/daaApi';

interface UmbrellaTierCardProps {
  umbrella:    DaaUmbrellaResult | null;
  isDeciding:  boolean;   // true if this tier produced the final verdict
}

const STATUS_LABELS: Record<number, string> = {
  '-1': 'MALICIOUS — Umbrella threat DB match',
  '0':  'UNDETERMINED — No Umbrella record',
  '1':  'SAFE — Umbrella cleared',
};

export default function UmbrellaTierCard({ umbrella, isDeciding }: UmbrellaTierCardProps) {
  const available = umbrella && umbrella.source !== 'unavailable';
  const verdict   = umbrella?.verdict ?? 'unavailable';

  const borderColor = isDeciding
    ? verdict === 'malicious' ? 'border-malicious/40' : 'border-safe/40'
    : 'border-white/[0.08]';

  return (
    <div className={`glass border ${borderColor} p-5 rounded-2xl animate-slide-up`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center
            ${isDeciding ? 'bg-brand/20 border border-brand/30' : 'bg-white/5'}`}>
            <Database size={15} className={isDeciding ? 'text-brand-light' : 'text-white/30'} />
          </div>
          <div>
            <div className="text-xs font-mono text-white/40">Tier 0</div>
            <div className="text-sm font-semibold text-white">Cisco Umbrella Investigate</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isDeciding && (
            <span className="tier-badge bg-brand/20 border-brand/30 text-brand-light border">
              DECIDED
            </span>
          )}
          <span className={`tier-badge border ${
            !available
              ? 'bg-white/5 border-white/10 text-white/30'
              : verdict === 'malicious' ? 'bg-malicious/10 border-malicious/20 text-malicious'
              : verdict === 'safe'      ? 'bg-safe/10 border-safe/20 text-safe'
              : 'bg-white/5 border-white/10 text-white/50'
          }`}>
            {!available ? 'NOT CONFIGURED' : verdict.toUpperCase()}
          </span>
        </div>
      </div>

      {!available ? (
        <div className="text-xs text-white/30 flex items-center gap-2 py-3">
          <HelpCircle size={13}/>
          Set <span className="font-mono text-white/50">UMBRELLA_INVESTIGATE_TOKEN</span> env var to enable Tier 0.
          DistilBERT handles all URLs.
        </div>
      ) : (
        <div className="space-y-3">
          {/* Domain + source */}
          <div className="flex items-center gap-3 text-xs text-white/50">
            <span className="font-mono text-white/70">{umbrella.domain}</span>
            <span className="tier-badge bg-white/5 border-white/10 text-white/30 border">
              {umbrella.source}
            </span>
            <span>{umbrella.latency_ms.toFixed(0)} ms</span>
          </div>

          {/* Status indicator */}
          {umbrella.status !== null && (
            <div className="text-xs text-white/40 font-mono">
              status = {umbrella.status} &nbsp;—&nbsp; {STATUS_LABELS[umbrella.status.toString() as any] ?? 'Unknown'}
            </div>
          )}

          {/* Confidence bar */}
          <div>
            <div className="flex justify-between text-xs text-white/40 mb-1">
              <span>Confidence</span>
              <span className="font-mono">{Math.round(umbrella.confidence * 100)}%</span>
            </div>
            <div className="score-bar-track">
              <div
                className={`score-bar-fill ${verdict === 'malicious' ? 'bg-malicious' : verdict === 'safe' ? 'bg-safe' : 'bg-white/20'}`}
                style={{ width: `${umbrella.confidence * 100}%` }}
              />
            </div>
          </div>

          {/* Security indicators */}
          {umbrella.security && (
            <div className="grid grid-cols-2 gap-2">
              {([
                { label: 'DGA Score',  val: umbrella.security.dga_score, fmt: (v: number) => v.toFixed(3),       warn: (v: number) => v > 0.80 },
                { label: 'Spam Score', val: umbrella.security.spam,       fmt: (v: number) => v.toFixed(3),       warn: (v: number) => v > 0.60 },
                { label: 'Fastflux',   val: umbrella.security.fastflux,   fmt: (v: boolean) => v ? 'YES' : 'NO', warn: (v: boolean) => Boolean(v) },
                { label: 'Botnet',     val: umbrella.security.botnet,     fmt: (v: boolean) => v ? 'YES' : 'NO', warn: (v: boolean) => Boolean(v) },
              ] as { label: string; val: number | boolean; fmt: (v: any) => string; warn: (v: any) => boolean }[]).map(({ label, val, fmt, warn }) => (
                <div key={label} className="flex justify-between text-xs p-2 rounded-lg bg-white/[0.03] border border-white/[0.05]">
                  <span className="text-white/40">{label}</span>
                  <span className={`font-mono ${warn(val as any) ? 'text-malicious' : 'text-white/60'}`}>
                    {fmt(val as any)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Categories */}
          {Object.keys(umbrella.categories).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {Object.keys(umbrella.categories).slice(0, 6).map(cat => (
                <span key={cat} className="text-[10px] px-2 py-0.5 rounded-full bg-malicious/10 border border-malicious/20 text-malicious">
                  {cat}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
