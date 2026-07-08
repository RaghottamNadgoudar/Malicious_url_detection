import { useEffect, useState } from 'react';
import { Layers } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function FeatureExtractionSection({ data, active, done }: Props) {
  const [staggerCount, setStaggerCount] = useState(0);

  useEffect(() => {
    if (active || done) {
      if (done) {
        setStaggerCount(data.featureCards.length);
        return;
      }
      setStaggerCount(0);
      const interval = setInterval(() => {
        setStaggerCount(prev => {
          if (prev >= data.featureCards.length) {
            clearInterval(interval);
            return prev;
          }
          return prev + 1;
        });
      }, 150);
      return () => clearInterval(interval);
    }
  }, [active, done, data.featureCards.length]);

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Layers className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 4: LEXICAL & TOPOLOGICAL FEATURE EXTRACTION
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">COMPLETED</span>}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {data.featureCards.slice(0, staggerCount).map((card, idx) => {
          const statusColors = {
            safe: 'border-green-500/20 text-green-400 bg-green-950/10',
            warning: 'border-amber-500/20 text-amber-400 bg-amber-950/10',
            danger: 'border-red-500/20 text-red-400 bg-red-950/10',
          };

          return (
            <div 
              key={idx}
              className={`bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-between h-36 font-mono text-xs transition-all duration-300 transform translate-y-0 opacity-100`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className="text-slate-400 font-bold uppercase tracking-wider text-[9px] truncate">
                    {card.name}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[8px] font-black border ${statusColors[card.status]}`}>
                    {card.status.toUpperCase()}
                  </span>
                </div>
                <p className="text-[10px] text-slate-500 leading-tight">
                  {card.description}
                </p>
              </div>

              <div className="text-lg font-black text-white mt-3 font-mono border-t border-[#1a2740] pt-2">
                {card.value}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
