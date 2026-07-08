import { Zap, TrendingDown, Archive } from 'lucide-react';

interface SpeedupCalloutProps {
  totalInput:   number;
  reductionPct: number;
  elapsedMs:    number;
  huffmanRatio: number;
}

export default function SpeedupCallout({
  totalInput, reductionPct, elapsedMs, huffmanRatio,
}: SpeedupCalloutProps) {
  const naiveMs    = totalInput * 25;          // ~25ms per URL through DistilBERT
  const speedup    = (naiveMs / Math.max(elapsedMs, 1)).toFixed(1);
  const bertCallsAvoided = Math.round((reductionPct / 100) * totalInput);

  const stats = [
    {
      icon:  Zap,
      value: `${speedup}×`,
      label: 'Faster than naive',
      sub:   `${naiveMs.toLocaleString()} ms → ${Math.round(elapsedMs).toLocaleString()} ms`,
      color: 'text-brand-light',
    },
    {
      icon:  TrendingDown,
      value: `${reductionPct.toFixed(0)}%`,
      label: 'DistilBERT calls avoided',
      sub:   `${bertCallsAvoided} of ${totalInput} URLs pre-classified`,
      color: 'text-safe',
    },
    {
      icon:  Archive,
      value: `${((1 - huffmanRatio) * 100).toFixed(0)}%`,
      label: 'Huffman log compression',
      sub:   `Ratio ${huffmanRatio.toFixed(3)} (Unit IV — Greedy)`,
      color: 'text-suspicious',
    },
  ];

  return (
    <div className="grid sm:grid-cols-3 gap-4">
      {stats.map(({ icon: Icon, value, label, sub, color }, i) => (
        <div key={label} className="glass p-5 animate-slide-up" style={{ animationDelay: `${i * 100}ms` }}>
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-lg bg-white/5 flex items-center justify-center shrink-0">
              <Icon size={16} className={color} />
            </div>
            <div>
              <div className={`text-2xl font-bold ${color} font-mono`}>{value}</div>
              <div className="text-xs font-medium text-white/70 mt-0.5">{label}</div>
              <div className="text-xs text-white/35 mt-1">{sub}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
