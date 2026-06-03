import { useEffect, useRef } from 'react';
import type { RiskScore as RiskScoreType } from '../types/analysis';

interface Props {
  riskScore: RiskScoreType;
}

const COLORS = {
  Safe: { stroke: '#22c55e', glow: '#16a34a', text: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30' },
  Suspicious: { stroke: '#f59e0b', glow: '#d97706', text: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  Malicious: { stroke: '#ef4444', glow: '#dc2626', text: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' },
  Unknown: { stroke: '#6b7280', glow: '#4b5563', text: 'text-slate-400', bg: 'bg-slate-700/30 border-slate-600/30' },
};

export default function RiskGauge({ riskScore }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const colors = COLORS[riskScore.level] || COLORS.Unknown;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const W = canvas.width;
    const H = canvas.height;
    const cx = W / 2;
    const cy = H * 0.62;
    const r = W * 0.38;
    const startAngle = Math.PI;       // 180° (left)
    const totalAngle = Math.PI;       // semi-circle

    let current = 0;
    const target = riskScore.score / 100;
    const duration = 1200; // ms
    const startTime = performance.now();

    const draw = (progress: number) => {
      ctx.clearRect(0, 0, W, H);

      // Track background arc
      ctx.beginPath();
      ctx.arc(cx, cy, r, startAngle, startAngle + totalAngle);
      ctx.strokeStyle = 'rgba(255,255,255,0.07)';
      ctx.lineWidth = 14;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Tick marks
      for (let i = 0; i <= 10; i++) {
        const angle = startAngle + (i / 10) * totalAngle;
        const inner = r - 20;
        const outer = r - 10;
        ctx.beginPath();
        ctx.moveTo(cx + inner * Math.cos(angle), cy + inner * Math.sin(angle));
        ctx.lineTo(cx + outer * Math.cos(angle), cy + outer * Math.sin(angle));
        ctx.strokeStyle = 'rgba(255,255,255,0.15)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      if (progress > 0) {
        // Glow effect
        ctx.save();
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, startAngle + totalAngle * progress);
        ctx.strokeStyle = colors.glow;
        ctx.lineWidth = 20;
        ctx.lineCap = 'round';
        ctx.shadowBlur = 18;
        ctx.shadowColor = colors.glow;
        ctx.globalAlpha = 0.35;
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
      const nx = cx + (r - 4) * Math.cos(needleAngle);
      const ny = cy + (r - 4) * Math.sin(needleAngle);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(nx, ny);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2.5;
      ctx.lineCap = 'round';
      ctx.shadowBlur = 8;
      ctx.shadowColor = '#ffffff';
      ctx.stroke();

      // Center dot
      ctx.beginPath();
      ctx.arc(cx, cy, 6, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.shadowBlur = 0;
      ctx.fill();
    };

    const animate = (now: number) => {
      const elapsed = now - startTime;
      const t = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - t, 3);
      current = eased * target;
      draw(current);
      if (t < 1) {
        animRef.current = requestAnimationFrame(animate);
      }
    };

    animRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animRef.current);
  }, [riskScore.score, riskScore.level]);

  return (
    <div className="flex flex-col items-center">
      <div className="relative">
        <canvas ref={canvasRef} width={220} height={140} className="w-[220px] h-[140px]" />
        {/* Score overlay */}
        <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
          <span className={`text-5xl font-black tabular-nums ${colors.text}`}>
            {riskScore.score}
          </span>
          <span className="text-slate-500 text-xs -mt-1">/ 100</span>
        </div>
      </div>

      {/* Level badge */}
      <div className={`mt-3 px-5 py-1.5 rounded-full border text-sm font-bold tracking-wide ${colors.bg} ${colors.text}`}>
        {riskScore.level}
      </div>

      {/* Score breakdown */}
      {riskScore.breakdown && (
        <div className="mt-4 w-full space-y-2">
          {[
            { label: 'ML Model', value: riskScore.breakdown.ml_contribution, max: 55 },
            { label: 'Redirects', value: riskScore.breakdown.redirect_contribution, max: 25 },
            { label: 'Heuristics', value: riskScore.breakdown.heuristic_contribution, max: 20 },
          ].map(({ label, value, max }) => (
            <div key={label} className="flex items-center gap-3">
              <span className="text-xs text-slate-500 w-20 text-right">{label}</span>
              <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${(value / max) * 100}%`,
                    backgroundColor: colors.stroke,
                  }}
                />
              </div>
              <span className="text-xs text-slate-400 w-6 text-right">{value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
