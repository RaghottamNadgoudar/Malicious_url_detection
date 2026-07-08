import { useEffect, useState } from 'react';
import { Link2, ArrowRight, Shield, AlertTriangle } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

const getHostname = (urlString: string) => {
  try {
    const hasProtocol = urlString.startsWith('http://') || urlString.startsWith('https://');
    const cleanUrl = hasProtocol ? urlString : `https://${urlString}`;
    return new URL(cleanUrl).hostname;
  } catch {
    return urlString;
  }
};

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function URLExpansionSection({ data, active, done }: Props) {
  const [visibleCount, setVisibleCount] = useState(0);

  useEffect(() => {
    if (active || done) {
      if (done) {
        setVisibleCount(data.expansionHops.length);
        return;
      }
      setVisibleCount(0);
      const interval = setInterval(() => {
        setVisibleCount((prev) => {
          if (prev >= data.expansionHops.length) {
            clearInterval(interval);
            return prev;
          }
          return prev + 1;
        });
      }, 500);
      return () => clearInterval(interval);
    }
  }, [active, done, data.expansionHops.length]);

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Link2 className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 1: URL EXPANSION & REDIRECTS TRACING
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">VERIFIED</span>}
      </div>

      <div className="space-y-6">
        <div className="flex flex-col items-center gap-4 py-4 overflow-x-auto">
          {data.expansionHops.slice(0, visibleCount).map((hop, index) => {
            const isLast = index === data.expansionHops.length - 1;
            return (
              <div key={index} className="flex flex-col items-center w-full max-w-2xl animate-fade-in">
                {index > 0 && (
                  <div className="flex flex-col items-center py-2 animate-pulse">
                    <div className="w-0.5 h-6 bg-gradient-to-b from-blue-500 to-indigo-500" />
                    <ArrowRight className="w-4 h-4 text-indigo-400 rotate-90" />
                  </div>
                )}

                <div className={`w-full flex items-center justify-between gap-4 p-4 rounded-xl border font-mono text-xs ${
                  hop.isSuspicious 
                    ? 'bg-red-950/20 border-red-500/30 text-red-300' 
                    : isLast && done
                    ? 'bg-green-950/20 border-green-500/30 text-green-300'
                    : 'bg-[#070d1a] border-[#1e2e4a] text-slate-300'
                }`}>
                  <div className="flex items-center gap-3">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center font-bold text-[10px] ${
                      hop.isSuspicious ? 'bg-red-500/20 text-red-400' : 'bg-[#1a2740] text-slate-400'
                    }`}>
                      {hop.hop}
                    </div>
                    <span className="break-all font-semibold">{hop.url}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    {hop.statusCode && (
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        hop.statusCode >= 400 
                          ? 'bg-red-900/40 text-red-300' 
                          : hop.statusCode >= 300 
                          ? 'bg-amber-900/40 text-amber-300' 
                          : 'bg-green-900/40 text-green-300'
                      }`}>
                        HTTP {hop.statusCode}
                      </span>
                    )}
                    {hop.isSuspicious && (
                      <span className="flex items-center gap-1 text-[10px] text-red-400 font-bold bg-red-950/40 border border-red-500/20 px-1.5 py-0.5 rounded">
                        <AlertTriangle size={10} /> SUSPICIOUS
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-[#1a2740] text-center font-mono text-xs">
          <div>
            <span className="text-slate-400 block mb-1">REDIRECT COUNT</span>
            <span className="text-lg font-bold text-white">{data.redirectCount}</span>
          </div>
          <div>
            <span className="text-slate-400 block mb-1">ORIGINAL HOST</span>
            <span className="text-lg font-bold text-blue-400 truncate max-w-[150px] inline-block">
              {getHostname(data.originalUrl)}
            </span>
          </div>
          <div>
            <span className="text-slate-400 block mb-1">FINAL HOST</span>
            <span className="text-lg font-bold text-green-400 truncate max-w-[150px] inline-block">
              {getHostname(data.expandedUrl || data.originalUrl)}
            </span>
          </div>
          <div>
            <span className="text-slate-400 block mb-1">MAX LIMIT HOPS</span>
            <span className="text-lg font-bold text-slate-500">10 (DAA Bound)</span>
          </div>
        </div>
      </div>
    </div>
  );
}
