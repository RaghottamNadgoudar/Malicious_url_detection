interface VerdictCounts {
  safe:       number;
  suspicious: number;
  malicious:  number;
  total:      number;
}

interface VerdictDonutProps {
  counts: VerdictCounts;
}

const SEGMENTS = [
  { key: 'safe'       as const, label: 'Safe',       color: '#22c55e', stroke: '#22c55e' },
  { key: 'suspicious' as const, label: 'Suspicious',  color: '#f59e0b', stroke: '#f59e0b' },
  { key: 'malicious'  as const, label: 'Malicious',   color: '#ef4444', stroke: '#ef4444' },
];

export default function VerdictDonut({ counts }: VerdictDonutProps) {
  const total = counts.total || 1;
  const r = 54, cx = 72, cy = 72;
  const circ = 2 * Math.PI * r;

  // Build strokes
  let cumulative = 0;
  const arcs = SEGMENTS.map(seg => {
    const frac   = (counts[seg.key] || 0) / total;
    const dash   = frac * circ;
    const offset = circ - cumulative * circ;
    cumulative += frac;
    return { ...seg, dash, gap: circ - dash, offset };
  });

  return (
    <div className="flex items-center gap-6">
      {/* SVG donut */}
      <svg width={144} height={144} viewBox="0 0 144 144" className="shrink-0">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={20} />
        {arcs.map(arc => (
          <circle
            key={arc.key}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={arc.stroke}
            strokeWidth={20}
            strokeDasharray={`${arc.dash} ${arc.gap}`}
            strokeDashoffset={arc.offset}
            strokeLinecap="butt"
            transform="rotate(-90 72 72)"
            style={{ transition: 'stroke-dasharray 0.8s ease-out' }}
            opacity={arc.dash > 0 ? 1 : 0}
          />
        ))}
        {/* Center label */}
        <text x={cx} y={cy - 8} textAnchor="middle" fill="white" fontSize={22} fontWeight="700" fontFamily="Inter">
          {counts.total}
        </text>
        <text x={cx} y={cy + 10} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize={10} fontFamily="Inter">
          URLs
        </text>
      </svg>

      {/* Legend */}
      <div className="space-y-3">
        {SEGMENTS.map(seg => {
          const n   = counts[seg.key] || 0;
          const pct = Math.round((n / total) * 100);
          return (
            <div key={seg.key} className="flex items-center gap-3">
              <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: seg.color }} />
              <div>
                <div className="text-sm font-medium text-white/80">{seg.label}</div>
                <div className="text-xs text-white/40 font-mono">{n} ({pct}%)</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
