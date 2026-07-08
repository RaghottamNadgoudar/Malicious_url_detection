import { Brain } from 'lucide-react';

interface DistilBertTierCardProps {
  bertScore:  number | null;   // expert_scores.distilbert
  finalConf:  number;
  isDeciding: boolean;
  skipped:    boolean;         // true when T0/T1 short-circuited
}

const SAFE_THRESHOLD       = 0.35;
const SUSPICIOUS_THRESHOLD = 0.60;

function getZoneLabel(score: number | null): { label: string; color: string } {
  if (score === null) return { label: 'Skipped', color: 'text-white/30' };
  if (score < SAFE_THRESHOLD)       return { label: 'Safe zone',       color: 'text-safe' };
  if (score < SUSPICIOUS_THRESHOLD) return { label: 'Suspicious zone', color: 'text-suspicious' };
  return { label: 'Malicious zone', color: 'text-malicious' };
}

export default function DistilBertTierCard({ bertScore, finalConf, isDeciding, skipped }: DistilBertTierCardProps) {
  const zone    = getZoneLabel(bertScore);
  const pctBert = bertScore !== null ? Math.round(bertScore * 100) : null;
  const pctConf = Math.round(finalConf * 100);

  return (
    <div className={`glass border p-5 rounded-2xl animate-slide-up delay-200
      ${isDeciding ? 'border-brand/40' : 'border-white/[0.08]'} ${skipped ? 'opacity-50' : ''}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center
            ${isDeciding ? 'bg-brand/20 border border-brand/30' : 'bg-white/5'}`}>
            <Brain size={15} className={isDeciding ? 'text-brand-light' : 'text-white/30'} />
          </div>
          <div>
            <div className="text-xs font-mono text-white/40">Tier 2</div>
            <div className="text-sm font-semibold text-white">DistilBERT [CLS] Classifier</div>
          </div>
        </div>
        {skipped
          ? <span className="tier-badge bg-white/5 border-white/10 text-white/30 border">SKIPPED</span>
          : isDeciding && <span className="tier-badge bg-brand/20 border-brand/30 text-brand-light border">DECIDED</span>
        }
      </div>

      {skipped ? (
        <div className="text-xs text-white/25 italic">Short-circuited by earlier tier — DistilBERT not invoked.</div>
      ) : (
        <div className="space-y-4">
          {/* Threshold ruler */}
          <div>
            <div className="text-xs text-white/40 mb-2">P(malicious) with decision thresholds</div>
            <div className="relative h-6 rounded-full overflow-hidden bg-white/[0.06]">
              {/* Zone bands */}
              <div className="absolute inset-y-0 left-0"  style={{ width: '35%', background: 'rgba(34,197,94,0.15)' }} />
              <div className="absolute inset-y-0 left-[35%]" style={{ width: '25%', background: 'rgba(245,158,11,0.15)' }} />
              <div className="absolute inset-y-0 left-[60%]" style={{ right: 0, background: 'rgba(239,68,68,0.15)' }} />
              {/* Score marker */}
              {pctBert !== null && (
                <div className="absolute top-1 bottom-1 w-1 rounded-full bg-white/80 shadow-lg"
                     style={{ left: `calc(${pctBert}% - 2px)`, transition: 'left 0.5s ease-out' }} />
              )}
              {/* Threshold lines */}
              <div className="absolute top-0 bottom-0 w-px bg-safe/60"     style={{ left: '35%' }} />
              <div className="absolute top-0 bottom-0 w-px bg-suspicious/60" style={{ left: '60%' }} />
            </div>
            <div className="flex justify-between text-[10px] text-white/25 mt-1 font-mono">
              <span>0%</span>
              <span className="text-safe absolute" style={{ left: '35%', transform: 'translateX(-50%)', position: 'relative' }}>35%</span>
              <span className="text-suspicious absolute" style={{ left: '60%', transform: 'translateX(-50%)', position: 'relative' }}>60%</span>
              <span>100%</span>
            </div>
          </div>

          {/* Score display */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-white/[0.03] rounded-xl p-3 border border-white/[0.06]">
              <div className="text-xs text-white/40 mb-1">Raw DistilBERT score</div>
              <div className={`text-xl font-bold font-mono ${zone.color}`}>
                {pctBert !== null ? `${pctBert}%` : '—'}
              </div>
              <div className={`text-xs ${zone.color}`}>{zone.label}</div>
            </div>
            <div className="bg-white/[0.03] rounded-xl p-3 border border-white/[0.06]">
              <div className="text-xs text-white/40 mb-1">Calibrated confidence</div>
              <div className="text-xl font-bold font-mono text-white/80">{pctConf}%</div>
              <div className="text-xs text-white/30">After Tier 3 adjustment</div>
            </div>
          </div>

          <div className="text-xs text-white/30 leading-relaxed">
            Architecture: DistilBERT [CLS] → LayerNorm → Dropout(0.2) → Linear(1).
            Logit de-saturation scale: 15.0. Tokenizer max length: 128.
          </div>
        </div>
      )}
    </div>
  );
}
