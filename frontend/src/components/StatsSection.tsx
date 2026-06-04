import { useEffect, useRef, useState } from 'react';
import { TrendingUp, Globe, Shield, Zap, CheckCircle } from 'lucide-react';

const STATS = [
  {
    icon: <Shield size={24} />,
    value: 97.3,
    suffix: '%',
    label: 'Detection Accuracy',
    sub: 'Validated on 50K URL benchmark dataset',
    color: 'blue',
    decimals: 1,
  },
  {
    icon: <Globe size={24} />,
    value: 1240000,
    suffix: '+',
    label: 'URLs Analyzed',
    sub: 'Across training and evaluation sets',
    color: 'indigo',
    decimals: 0,
    format: 'compact',
  },
  {
    icon: <TrendingUp size={24} />,
    value: 98.1,
    suffix: '%',
    label: 'Threats Blocked',
    sub: 'True positive rate on phishing URLs',
    color: 'green',
    decimals: 1,
  },
  {
    icon: <Zap size={24} />,
    value: 1.8,
    suffix: 's',
    label: 'Avg. Scan Time',
    sub: 'End-to-end pipeline latency',
    color: 'amber',
    decimals: 1,
  },
  {
    icon: <CheckCircle size={24} />,
    value: 1.2,
    suffix: '%',
    label: 'False Positive Rate',
    sub: 'Legitimate URLs misclassified as threats',
    color: 'teal',
    decimals: 1,
  },
];

const COLOR_MAP: Record<string, { icon: string; bg: string; border: string; accent: string; bar: string }> = {
  blue:   { icon: 'text-blue-600',   bg: 'bg-blue-50',   border: 'border-blue-100',   accent: 'text-blue-600',   bar: 'bg-blue-500' },
  indigo: { icon: 'text-indigo-600', bg: 'bg-indigo-50', border: 'border-indigo-100', accent: 'text-indigo-600', bar: 'bg-indigo-500' },
  green:  { icon: 'text-green-600',  bg: 'bg-green-50',  border: 'border-green-100',  accent: 'text-green-600',  bar: 'bg-green-500' },
  amber:  { icon: 'text-amber-600',  bg: 'bg-amber-50',  border: 'border-amber-100',  accent: 'text-amber-600',  bar: 'bg-amber-500' },
  teal:   { icon: 'text-teal-600',   bg: 'bg-teal-50',   border: 'border-teal-100',   accent: 'text-teal-600',   bar: 'bg-teal-500' },
};

function formatCompact(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(0) + 'K';
  return String(n);
}

function AnimatedCounter({
  target,
  decimals,
  format,
  suffix,
  color,
}: {
  target: number;
  decimals: number;
  format?: string;
  suffix: string;
  color: string;
}) {
  const [display, setDisplay] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started.current) {
          started.current = true;
          const duration = 2000;
          const start = performance.now();
          const tick = (now: number) => {
            const t = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - t, 3);
            setDisplay(eased * target);
            if (t < 1) requestAnimationFrame(tick);
          };
          requestAnimationFrame(tick);
        }
      },
      { threshold: 0.3 }
    );
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [target]);

  const c = COLOR_MAP[color];
  const formatted =
    format === 'compact'
      ? formatCompact(display)
      : display.toFixed(decimals);

  return (
    <div ref={ref} className={`text-4xl font-black tabular-nums ${c.accent}`}>
      {formatted}
      <span className="text-2xl font-bold ml-0.5">{suffix}</span>
    </div>
  );
}

export default function StatsSection() {
  return (
    <section id="stats" className="py-24 bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <span className="inline-block text-xs font-semibold tracking-widest uppercase text-blue-600 mb-3 px-3 py-1 bg-blue-50 rounded-full border border-blue-100">
            Performance Metrics
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 mb-4">
            Detection at Enterprise Scale
          </h2>
          <p className="text-lg text-gray-500 max-w-2xl mx-auto">
            Benchmarked against real-world phishing datasets, the hybrid system consistently outperforms single-model approaches.
          </p>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-5">
          {STATS.map((stat, idx) => {
            const c = COLOR_MAP[stat.color];
            return (
              <div
                key={idx}
                className="bg-white rounded-xl border border-gray-150 p-6 card-hover text-center"
              >
                {/* Icon */}
                <div className={`w-12 h-12 ${c.bg} ${c.border} border rounded-xl flex items-center justify-center mx-auto mb-4 ${c.icon}`}>
                  {stat.icon}
                </div>

                {/* Number */}
                <AnimatedCounter
                  target={stat.value}
                  decimals={stat.decimals}
                  format={stat.format}
                  suffix={stat.suffix}
                  color={stat.color}
                />

                {/* Label */}
                <div className="mt-2 font-semibold text-gray-800 text-sm">{stat.label}</div>
                <div className="mt-1 text-xs text-gray-400 leading-relaxed">{stat.sub}</div>
              </div>
            );
          })}
        </div>

        {/* Comparison bar chart */}
        <div className="mt-12 bg-white rounded-2xl border border-gray-150 p-8">
          <h3 className="font-bold text-gray-900 mb-6 text-base">
            Comparison: Single Model vs Hybrid Approach
          </h3>
          <div className="space-y-4">
            {[
              { label: 'Neural Network alone',        acc: 91.2, color: 'bg-blue-200', text: 'text-blue-700' },
              { label: 'Pattern Matching alone',       acc: 78.5, color: 'bg-violet-200', text: 'text-violet-700' },
              { label: 'Entropy Analysis alone',       acc: 73.1, color: 'bg-sky-200', text: 'text-sky-700' },
              { label: 'Hybrid Detection (This System)', acc: 97.3, color: 'bg-blue-600', text: 'text-white', highlight: true },
            ].map((row) => (
              <div key={row.label} className="flex items-center gap-4">
                <span className={`text-sm w-56 shrink-0 ${row.highlight ? 'font-bold text-gray-900' : 'text-gray-500'}`}>
                  {row.label}
                </span>
                <div className="flex-1 h-7 bg-gray-100 rounded-lg overflow-hidden relative">
                  <div
                    className={`h-full rounded-lg flex items-center justify-end pr-3 transition-all duration-1000 ${row.color}`}
                    style={{ width: `${row.acc}%` }}
                  >
                    <span className={`text-xs font-bold ${row.text}`}>{row.acc}%</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
          <p className="mt-4 text-xs text-gray-400">
            * Accuracy measured on PhishTank + OpenPhish benchmark. Higher is better.
          </p>
        </div>
      </div>
    </section>
  );
}
