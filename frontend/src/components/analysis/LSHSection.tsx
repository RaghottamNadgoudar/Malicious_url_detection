import { Layers } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function LSHSection({ data, active, done }: Props) {
  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Layers className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 11: LSH SIMILARITY (LOCALITY-SENSITIVE HASHING)
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">MATCHED</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 font-mono text-xs">
        {/* 3-Gram Generation */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4">
          <span className="text-slate-400 font-bold uppercase tracking-wider text-[9px] block border-b border-[#1a2740] pb-1.5 mb-2">
            CHARACTER 3-GRAMS
          </span>
          <div className="flex flex-wrap gap-1">
            {data.lshTrigrams.map((tg, idx) => (
              <span key={idx} className="bg-[#0c1322] border border-[#1e2e4a] text-blue-400 font-bold px-1.5 py-0.5 rounded text-[9px]">
                "{tg}"
              </span>
            ))}
          </div>
        </div>

        {/* MinHash Signatures */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4">
          <span className="text-slate-400 font-bold uppercase tracking-wider text-[9px] block border-b border-[#1a2740] pb-1.5 mb-3">
            MINHASH VECTOR SIGNATURES
          </span>
          <div className="flex flex-col gap-2">
            {data.lshMinHashes.map((val, idx) => (
              <div key={idx} className="flex justify-between items-center text-[10px]">
                <span className="text-slate-500">SIGNATURE K={idx + 1}:</span>
                <span className="text-white font-bold bg-[#1a2740] px-2 py-0.5 rounded">{active || done ? val : '--'}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Similarity Score */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-between">
          <div>
            <span className="text-slate-400 font-bold uppercase tracking-wider text-[9px] block border-b border-[#1a2740] pb-1.5 mb-2">
              JACCARD SIMILARITY MATCH
            </span>
            <div className="text-2xl font-black text-white">
              {active || done ? `${Math.round(data.lshSimilarityScore * 100)}%` : '0%'}
            </div>
          </div>
          <div className="w-full h-1.5 bg-[#0c1322] border border-[#1e2e4a] rounded-full overflow-hidden">
            <div 
              className="h-full bg-blue-500 transition-all duration-1000" 
              style={{ width: `${active || done ? data.lshSimilarityScore * 100 : 0}%` }}
            />
          </div>
        </div>

        {/* Nearest Similar Malicious URL List */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col">
          <span className="text-slate-400 font-bold uppercase tracking-wider text-[9px] block border-b border-[#1a2740] pb-1.5 mb-2">
            NEAREST BLACKLIST MATCHES
          </span>
          <div className="flex-1 overflow-y-auto space-y-1">
            {active || done ? (
              data.lshMatches.length > 0 ? (
                data.lshMatches.map((m, idx) => (
                  <div key={idx} className="bg-red-950/20 border border-red-500/20 rounded p-1 text-[8px] text-red-400 font-bold truncate">
                    {m}
                  </div>
                ))
              ) : (
                <div className="text-slate-600 text-[10px] italic">No close matches found.</div>
              )
            ) : (
              <div className="text-slate-600 text-[10px] italic">Awaiting calculation...</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
