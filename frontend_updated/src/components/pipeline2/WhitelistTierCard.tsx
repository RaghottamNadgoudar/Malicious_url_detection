import { List, CheckCircle } from 'lucide-react';

interface WhitelistTierCardProps {
  reasoning:  string;
  isDeciding: boolean;
}

export default function WhitelistTierCard({ reasoning, isDeciding }: WhitelistTierCardProps) {
  const matched = isDeciding;
  return (
    <div className={`glass border p-5 rounded-2xl animate-slide-up delay-100
      ${matched ? 'border-safe/40' : 'border-white/[0.08]'}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center
            ${matched ? 'bg-safe/15 border border-safe/30' : 'bg-white/5'}`}>
            <List size={15} className={matched ? 'text-safe' : 'text-white/30'} />
          </div>
          <div>
            <div className="text-xs font-mono text-white/40">Tier 1</div>
            <div className="text-sm font-semibold text-white">Local Whitelist + Trusted Suffixes</div>
          </div>
        </div>
        {matched && (
          <span className="tier-badge bg-safe/10 border-safe/20 text-safe border flex items-center gap-1">
            <CheckCircle size={10}/> DECIDED
          </span>
        )}
      </div>

      <div className="text-xs text-white/40 mb-3 leading-relaxed">
        Hash-set lookup O(1). Checks domain against ~60 whitelisted domains and
        trusted institutional suffixes (.gov.in, .ac.in, .edu, etc.)
      </div>

      {matched ? (
        <div className="bg-safe/5 border border-safe/20 rounded-xl p-3">
          <div className="text-xs text-safe font-medium mb-1">Matched — URL is whitelisted</div>
          <div className="text-xs text-white/50 font-mono">{reasoning}</div>
        </div>
      ) : (
        <div className="text-xs text-white/25 italic">URL did not match whitelist — passed to Tier 2</div>
      )}
    </div>
  );
}
