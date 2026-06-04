import { ChevronRight } from 'lucide-react';

const PIPELINE = [
  {
    step: '01',
    label: 'URL Input',
    description: 'Raw URL submitted for analysis — shortened, obfuscated, or plain',
    color: 'blue',
    icon: '⌨️',
  },
  {
    step: '02',
    label: 'URL Expansion',
    description: 'Bloom Filter lookup + HTTP resolution to unroll shortened domains',
    color: 'indigo',
    icon: '🔗',
  },
  {
    step: '03',
    label: 'Graph Analysis',
    description: 'BFS/DFS traversal maps the redirect chain as a weighted directed graph',
    color: 'violet',
    icon: '🕸️',
  },
  {
    step: '04',
    label: 'Pattern Detection',
    description: 'Boyer-Moore & Horspool scan for phishing keywords + brand impersonation',
    color: 'purple',
    icon: '🔍',
  },
  {
    step: '05',
    label: 'Entropy & Features',
    description: 'Shannon entropy + 25 structural URL features extracted for ML input',
    color: 'sky',
    icon: '📊',
  },
  {
    step: '06',
    label: 'Neural Network',
    description: 'Trained classifier produces threat probability with confidence score',
    color: 'teal',
    icon: '🤖',
  },
  {
    step: '07',
    label: 'Threat Scoring',
    description: "Dijkstra's algorithm computes composite risk score (0–100) across graph edges",
    color: 'amber',
    icon: '⚡',
  },
  {
    step: '08',
    label: 'Heapsort Ranking',
    description: 'Max-heap sorts threat indicators by severity for prioritized reporting',
    color: 'orange',
    icon: '📋',
  },
  {
    step: '09',
    label: 'Final Classification',
    description: 'Verdict: Safe / Suspicious / Malicious with full audit trail',
    color: 'rose',
    icon: '🛡️',
  },
];

const COLOR_MAP: Record<string, { dot: string; line: string; badge: string; stepBg: string }> = {
  blue:   { dot: 'bg-blue-600',   line: 'border-blue-200',   badge: 'bg-blue-50 text-blue-700 border-blue-200',   stepBg: 'bg-blue-600' },
  indigo: { dot: 'bg-indigo-600', line: 'border-indigo-200', badge: 'bg-indigo-50 text-indigo-700 border-indigo-200', stepBg: 'bg-indigo-600' },
  violet: { dot: 'bg-violet-600', line: 'border-violet-200', badge: 'bg-violet-50 text-violet-700 border-violet-200', stepBg: 'bg-violet-600' },
  purple: { dot: 'bg-purple-600', line: 'border-purple-200', badge: 'bg-purple-50 text-purple-700 border-purple-200', stepBg: 'bg-purple-600' },
  sky:    { dot: 'bg-sky-500',    line: 'border-sky-200',    badge: 'bg-sky-50 text-sky-700 border-sky-200',    stepBg: 'bg-sky-500' },
  teal:   { dot: 'bg-teal-600',   line: 'border-teal-200',   badge: 'bg-teal-50 text-teal-700 border-teal-200',   stepBg: 'bg-teal-600' },
  amber:  { dot: 'bg-amber-500',  line: 'border-amber-200',  badge: 'bg-amber-50 text-amber-700 border-amber-200',  stepBg: 'bg-amber-500' },
  orange: { dot: 'bg-orange-500', line: 'border-orange-200', badge: 'bg-orange-50 text-orange-700 border-orange-200', stepBg: 'bg-orange-500' },
  rose:   { dot: 'bg-rose-600',   line: 'border-rose-200',   badge: 'bg-rose-50 text-rose-700 border-rose-200',   stepBg: 'bg-rose-600' },
};

export default function MethodologySection() {
  return (
    <section id="methodology" className="py-24 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <span className="inline-block text-xs font-semibold tracking-widest uppercase text-blue-600 mb-3 px-3 py-1 bg-blue-50 rounded-full border border-blue-100">
            Methodology
          </span>
          <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 mb-4">
            Hybrid Detection Pipeline
          </h2>
          <p className="text-lg text-gray-500 max-w-2xl mx-auto">
            Every URL passes through a 9-stage analysis pipeline combining classical algorithms with neural network inference for maximum detection accuracy.
          </p>
        </div>

        {/* Pipeline — horizontal scroll on mobile, grid on desktop */}
        {/* Desktop: 3-col timeline */}
        <div className="hidden lg:block">
          {/* Row 1: steps 1-3 */}
          <div className="flex items-start gap-0 mb-8">
            {PIPELINE.slice(0, 3).map((stage, idx) => {
              const c = COLOR_MAP[stage.color];
              const isLast = idx === 2;
              return (
                <div key={stage.step} className="flex-1 flex items-start gap-0">
                  <div className="flex-1">
                    <PipelineCard stage={stage} c={c} />
                  </div>
                  {!isLast && (
                    <div className="flex items-center mt-8 px-2">
                      <ChevronRight size={20} className="text-gray-300" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Curved connector */}
          <div className="flex justify-end pr-8 mb-2">
            <div className="flex items-center gap-1 text-gray-300">
              <span className="text-2xl leading-none">↓</span>
            </div>
          </div>

          {/* Row 2: steps 4-6 (reversed for snake layout) */}
          <div className="flex items-start gap-0 mb-8 flex-row-reverse">
            {PIPELINE.slice(3, 6).map((stage, idx) => {
              const c = COLOR_MAP[stage.color];
              const isLast = idx === 2;
              return (
                <div key={stage.step} className="flex-1 flex items-start gap-0 flex-row-reverse">
                  <div className="flex-1">
                    <PipelineCard stage={stage} c={c} />
                  </div>
                  {!isLast && (
                    <div className="flex items-center mt-8 px-2">
                      <ChevronRight size={20} className="text-gray-300 rotate-180" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Curved connector */}
          <div className="flex justify-start pl-8 mb-2">
            <span className="text-2xl text-gray-300 leading-none">↓</span>
          </div>

          {/* Row 3: steps 7-9 */}
          <div className="flex items-start gap-0">
            {PIPELINE.slice(6, 9).map((stage, idx) => {
              const c = COLOR_MAP[stage.color];
              const isLast = idx === 2;
              return (
                <div key={stage.step} className="flex-1 flex items-start gap-0">
                  <div className="flex-1">
                    <PipelineCard stage={stage} c={c} highlight={isLast} />
                  </div>
                  {!isLast && (
                    <div className="flex items-center mt-8 px-2">
                      <ChevronRight size={20} className="text-gray-300" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Mobile: vertical list */}
        <div className="lg:hidden space-y-3">
          {PIPELINE.map((stage) => {
            const c = COLOR_MAP[stage.color];
            return (
              <div key={stage.step} className="flex items-start gap-4 p-4 bg-gray-50 rounded-xl border border-gray-100">
                <div className={`w-8 h-8 rounded-lg ${c.stepBg} flex items-center justify-center text-white text-xs font-bold flex-shrink-0`}>
                  {stage.step}
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm">{stage.icon}</span>
                    <span className="font-semibold text-gray-900 text-sm">{stage.label}</span>
                  </div>
                  <p className="text-xs text-gray-500">{stage.description}</p>
                </div>
              </div>
            );
          })}
        </div>

        {/* Bottom note */}
        <div className="mt-12 text-center">
          <p className="text-sm text-gray-400">
            Average total processing time &lt;{' '}
            <span className="font-semibold text-gray-600">2 seconds</span> per URL.
            Results include full audit trail with per-stage confidence scores.
          </p>
        </div>
      </div>
    </section>
  );
}

function PipelineCard({
  stage,
  c,
  highlight = false,
}: {
  stage: typeof PIPELINE[0];
  c: ReturnType<typeof Object.values<typeof COLOR_MAP>>[0];
  highlight?: boolean;
}) {
  return (
    <div
      className={`relative p-5 rounded-xl border transition-all card-hover mx-1 ${
        highlight
          ? 'bg-blue-600 border-blue-600 text-white shadow-lg shadow-blue-200'
          : 'bg-white border-gray-150 hover:border-blue-200'
      }`}
    >
      {/* Step badge */}
      <div className="flex items-center justify-between mb-3">
        <span
          className={`text-xs font-bold px-2 py-0.5 rounded-md border ${
            highlight ? 'bg-white/20 text-white border-white/30' : c.badge
          }`}
        >
          STEP {stage.step}
        </span>
        <span className="text-lg">{stage.icon}</span>
      </div>

      <h3 className={`font-bold text-sm mb-2 ${highlight ? 'text-white' : 'text-gray-900'}`}>
        {stage.label}
      </h3>
      <p className={`text-xs leading-relaxed ${highlight ? 'text-blue-100' : 'text-gray-500'}`}>
        {stage.description}
      </p>
    </div>
  );
}
