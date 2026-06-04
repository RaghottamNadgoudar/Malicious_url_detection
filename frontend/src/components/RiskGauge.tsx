import { useEffect, useRef } from 'react';
import type { RiskScore as RiskScoreType } from '../types/analysis';

interface Props {
  riskScore: RiskScoreType;
}

const COLORS = {
  Safe:       { stroke: '#16a34a', glow: '#16a34a', text: 'text-green-700',  badge: 'bg-green-100 text-green-700 border-green-200' },
  Suspicious: { stroke: '#d97706', glow: '#d97706', text: 'text-amber-700',  badge: 'bg-amber-100 text-amber-700 border-amber-200' },
  Malicious:  { stroke: '#dc2626', glow: '#dc2626', text: 'text-red-700',    badge: 'bg-red-100 text-red-700 border-red-200' },
  Unknown:    { stroke: '#6b7280', glow: '#6b7280', text: 'text-gray-600',   badge: 'bg-gray-100 text-gray-600 border-gray-200' },
};

export default function RiskGauge({ riskScore }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const colors = COLORS[riskScore.level] ?? COLORS.Unknown;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const W = canvas.width;
    const H = canvas.height;
    const cx = W / 2;
    const cy = H * 0.62;
    const r = W * 0.37;
    const startAngle = Math.PI;
    const totalAngle = Math.PI;

    const target = riskScore.score / 100;
    const duration = 1400;
    const startTime = performance.now();

    const draw = (progress: number) => {
      ctx.clearRect(0, 0, W, H);

      // Track bg arc
      ctx.beginPath();
      ctx.arc(cx, cy, r, startAngle, startAngle + totalAngle);
      ctx.strokeStyle = 'rgba(0,0,0,0.08)';
      ctx.lineWidth = 14;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Tick marks
      for (let i = 0; i <= 10; i++) {
        const angle = startAngle + (i / 10) * totalAngle;
        const inner = r - 18;
        const outer = r - 10;
        ctx.beginPath();
        ctx.moveTo(cx + inner * Math.cos(angle), cy + inner * Math.sin(angle));
        ctx.lineTo(cx + outer * Math.cos(angle), cy + outer * Math.sin(angle));
        ctx.strokeStyle = 'rgba(0,0,0,0.12)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      if (progress > 0) {
        // Glow arc
        ctx.save();
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, startAngle + totalAngle * progress);
        ctx.strokeStyle = colors.glow;
        ctx.lineWidth = 20;
        ctx.lineCap = 'round';
        ctx.shadowBlur = 16;
        ctx.shadowColor = colors.glow;
        ctx.globalAlpha = 0.2;
        ctx.stroke();
        ctx.restore();

        // Main arc
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, startAngle + totalAngle * progress);
        ctx.strokeStyle = colors.stroke;
        ctx.lineWidth = 14;
        ctx.lineCap = 'round';
        ctx.stroke();
      }

      // Needle
      const needleAngle = startAngle + totalAngle * progress;
      const nx = cx + (r - 6) * Math.cos(needleAngle);
      const ny = cy + (r - 6) * Math.sin(needleAngle);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(nx, ny);
      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 2.5;
      ctx.lineCap = 'round';
      ctx.shadowBlur = 0;
      ctx.stroke();

      // Center dot
      ctx.beginPath();
      ctx.arc(cx, cy, 6, 0, Math.PI * 2);
      ctx.fillStyle = '#1e293b';
      ctx.fill();
    };

    const animate = (now: number) => {
      const elapsed = now - startTime;
      const t = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      draw(eased * target);
      if (t < 1) animRef.current = requestAnimationFrame(animate);
    };

    animRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animRef.current);
  }, [riskScore.score, riskScore.level]);

  return (
    <div className="flex flex-col items-center">
      <div className="relative">
        <canvas ref={canvasRef} width={220} height={140} className="w-[220px] h-[140px]" />
        {/* Score overlay */}
        <div className="absolute inset-x-0 bottom-0 flex flex-col items-center pointer-events-none">
          <span className={`text-5xl font-black tabular-nums ${colors.text}`}>
            {riskScore.score}
          </span>
          <span className="text-gray-400 text-xs -mt-1">/ 100</span>
        </div>
      </div>

      {/* Level badge */}
      <div className={`mt-3 px-5 py-1.5 rounded-full border text-sm font-bold tracking-wide ${colors.badge}`}>
        {riskScore.level}
      </div>

      {/* Score breakdown */}
      {riskScore.breakdown && (
        <div className="mt-5 w-full space-y-3">
          {[
            { label: 'ML Model',   value: riskScore.breakdown.ml_contribution,        max: 55 },
            { label: 'Redirects',  value: riskScore.breakdown.redirect_contribution,  max: 25 },
            { label: 'Heuristics', value: riskScore.breakdown.heuristic_contribution, max: 20 },
          ].map(({ label, value, max }) => (
            <div key={label} className="flex items-center gap-3">
              <span className="text-xs text-gray-400 w-20 text-right font-medium">{label}</span>
              <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden border border-gray-200">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${(value / max) * 100}%`,
                    backgroundColor: colors.stroke,
                  }}
                />
              </div>
              <span className="text-xs text-gray-600 font-semibold w-6 text-right tabular-nums">{value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
