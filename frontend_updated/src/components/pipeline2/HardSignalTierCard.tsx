import { Sliders } from 'lucide-react';
import type { HardSignalBreakdown } from '../../types/daaApi';

interface HardSignalTierCardProps {
  hardScore:         number;
  breakdown:         HardSignalBreakdown;
  isDeciding:        boolean;
}

const COMPONENTS = [
  { key: 'suspicious_tld'    as const, label: 'Suspicious TLD',    max: 0.40, desc: 'TLD in blocklist (.tk/.ml/.xyz…)' },
  { key: 'has_ip'            as const, label: 'IP Address Host',   max: 0.30, desc: 'Numeric IP as hostname' },
  { key: 'has_at'            as const, label: '@ Symbol',          max: 0.25, desc: 'Credential-stuffing indicator' },
  { key: 'brand_in_subdomain'as const, label: 'Brand Spoof',       max: 0.35, desc: 'Known brand in subdomain/path' },
  { key: 'keyword_boost'     as const, label: 'Phishing Keywords',  max: 0.20, desc: 'Horspool keyword × 0.20 boost' },
  { key: 'double_slash_path' as const, label: 'Double-Slash Path', max: 0.15, desc: '// in URL path' },
  { key: 'high_entropy'      as const, label: 'High Entropy',      max: 0.10, desc: 'URL entropy > 5.0' },
];

// Override threshold: total hard score >= 0.40 → verdict override
// Moderate threshold:  total hard score >= 0.20 → +0.12 boost
const OVERRIDE_THRESHOLD  = 0.40;
const MODERATE_THRESHOLD  = 0.20;

export default function HardSignalTierCard({ hardScore, breakdown, isDeciding }: HardSignalTierCardProps) {
  const pct            = Math.round(hardScore * 100);
  const isOverride     = hardScore >= OVERRIDE_THRESHOLD;
  const isModerate     = hardScore >= MODERATE_THRESHOLD && !isOverride;
  const effectiveColor = isOverride ? 'text-malicious' : isModerate ? 'text-suspicious' : 'text-white/50';

  return (
    <div className={`glass border p-5 rounded-2xl animate-slide-up delay-300
      ${isDeciding ? 'border-malicious/40' : 'border-white/[0.08]'}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center
            ${isDeciding ? 'bg-malicious/10 border border-malicious/30' : 'bg-white/5'}`}>
            <Sliders size={15} className={isDeciding ? 'text-malicious' : 'text-white/30'} />
          </div>
          <div>
            <div className="text-xs font-mono text-white/40">Tier 3</div>
            <div className="text-sm font-semibold text-white">Hard Signal Supplement</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isDeciding && <span className="tier-badge bg-malicious/10 border-malicious/20 text-malicious border">DECIDED</span>}
          <span className={`text-lg font-bold font-mono ${effectiveColor}`}>{pct}%</span>
        </div>
      </div>

      {/* Threshold indicators */}
      <div className="flex gap-3 mb-4">
        <div className={`text-xs px-2 py-1 rounded-lg border font-mono
          ${isOverride ? 'bg-malicious/10 border-malicious/20 text-malicious' : 'bg-white/5 border-white/10 text-white/30'}`}>
          ≥0.40 Override
        </div>
        <div className={`text-xs px-2 py-1 rounded-lg border font-mono
          ${isModerate ? 'bg-suspicious/10 border-suspicious/20 text-suspicious' : 'bg-white/5 border-white/10 text-white/30'}`}>
          ≥0.20 +0.12 Boost
        </div>
      </div>

      {/* Stacked bar */}
      <div className="space-y-2">
        {COMPONENTS.map(({ key, label, max, desc }) => {
          const val  = breakdown[key] ?? 0;
          const barW = max > 0 ? (val / max) * 100 : 0;
          const active = val > 0;

          return (
            <div key={key} className={`transition-opacity ${active ? '' : 'opacity-35'}`}>
              <div className="flex justify-between text-xs mb-1">
                <span className={active ? 'text-white/70' : 'text-white/30'}>{label}</span>
                <span className={`font-mono ${active ? 'text-malicious' : 'text-white/30'}`}>
                  {active ? `+${val.toFixed(2)}` : '0'}
                </span>
              </div>
              <div className="score-bar-track h-1.5">
                <div
                  className={`score-bar-fill ${active ? 'bg-malicious/70' : 'bg-white/10'}`}
                  style={{ width: `${barW}%` }}
                  title={desc}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Total */}
      <div className="mt-4 pt-4 border-t border-white/[0.07] flex justify-between items-center">
        <span className="text-xs text-white/40">Total hard score (capped at 1.0)</span>
        <span className={`font-mono font-bold ${effectiveColor}`}>{hardScore.toFixed(4)}</span>
      </div>
    </div>
  );
}
