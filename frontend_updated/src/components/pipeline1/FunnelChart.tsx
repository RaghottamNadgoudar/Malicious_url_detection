import type { DaaStageCount } from '../../types/daaApi';

interface FunnelChartProps {
  stageCounts: DaaStageCount;
}

const STAGES = [
  { key: 'input',           label: 'Input',         algo: 'Raw URLs',              color: '#6366f1' },
  { key: 'after_dedup',     label: 'After Dedup',   algo: 'Quicksort + Hashing',   color: '#8b5cf6' },
  { key: 'after_whitelist', label: 'After Whitelist',algo: 'Hash Set Lookup',       color: '#a78bfa' },
  { key: 'after_horspool',  label: 'After Horspool', algo: 'Boyer-Moore-Horspool',  color: '#c4b5fd' },
  { key: 'after_greedy',    label: 'After Greedy',   algo: 'Greedy Scoring',        color: '#ddd6fe' },
  { key: 'to_distilbert',   label: '→ DistilBERT',   algo: 'Neural Inference',     color: '#7c3aed' },
] as const;

type StageKey = typeof STAGES[number]['key'];

export default function FunnelChart({ stageCounts }: FunnelChartProps) {
  const total = stageCounts.input || 1;

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold text-white/70 mb-4">6-Stage DAA Funnel</h3>
      {STAGES.map(({ key, label, algo, color }, i) => {
        const count = stageCounts[key as StageKey] ?? 0;
        const pct   = (count / total) * 100;
        const reduced = i > 0 ? (stageCounts[STAGES[i-1].key as StageKey] ?? 0) - count : 0;

        return (
          <div key={key} className="space-y-1 animate-fade-in" style={{ animationDelay: `${i * 80}ms` }}>
            <div className="flex items-center justify-between text-xs text-white/50">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-md flex items-center justify-center text-[10px] font-mono font-bold"
                      style={{ background: `${color}22`, color }}>
                  {i}
                </span>
                <span className="font-medium text-white/80">{label}</span>
                <span className="text-white/30 font-mono hidden sm:block">{algo}</span>
              </div>
              <div className="flex items-center gap-3">
                {reduced > 0 && (
                  <span className="text-safe text-[10px]">−{reduced}</span>
                )}
                <span className="font-mono text-white/70">{count}</span>
              </div>
            </div>
            <div className="score-bar-track h-3">
              <div
                className="h-full rounded-full animate-fill-bar"
                style={{
                  width:      `${pct}%`,
                  background: `linear-gradient(90deg, ${color}88, ${color})`,
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
