import { useEffect, useState } from 'react';
import { ShieldAlert, Cpu, Layers } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function BloomFilterSection({ data, active, done }: Props) {
  const [pulseIndices, setPulseIndices] = useState<number[]>([]);

  useEffect(() => {
    if (active && !done) {
      const interval = setInterval(() => {
        setPulseIndices(data.bloomHashes);
        setTimeout(() => setPulseIndices([]), 400);
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [active, done, data.bloomHashes]);

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <ShieldAlert className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 9: LEARNED BLOOM FILTER & LSH SIMILARITY
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">MATCHED</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 font-mono text-xs">
        {/* 1. Bloom Hash Engines */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 space-y-3">
          <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5">
            HASH ENGINES (K=3)
          </span>
          <div className="space-y-2">
            {[
              { name: 'H1 (MD5 Seed 0)', val: data.bloomHashes[0] },
              { name: 'H2 (MD5 Seed 1)', val: data.bloomHashes[1] },
              { name: 'H3 (MD5 Seed 2)', val: data.bloomHashes[2] },
            ].map((h, i) => (
              <div key={i} className="p-2 bg-[#0c1322] border border-[#1a2740] rounded-lg">
                <span className="text-[9px] text-slate-500 block">{h.name}</span>
                <span className="font-bold text-white text-[10px]">Index Map: </span>
                <span className="text-blue-400 font-bold">{active || done ? h.val : '--'}</span>
              </div>
            ))}
          </div>
        </div>

        {/* 2. Bloom Bit Array */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-between">
          <div>
            <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5 mb-3">
              VECTOR STATE (M=32)
            </span>
            <div className="grid grid-cols-8 gap-1.5">
              {data.bloomBitArray.map((bit, idx) => {
                const isPulsing = pulseIndices.includes(idx);
                const isSet = bit && (active || done);

                return (
                  <div
                    key={idx}
                    className={`h-7 rounded flex items-center justify-center font-bold text-[9px] border transition-all duration-300 ${
                      isPulsing
                        ? 'bg-blue-600 border-blue-400 text-white scale-110 shadow-lg shadow-blue-500/50'
                        : isSet
                        ? 'bg-indigo-950/40 border-indigo-500/50 text-indigo-400'
                        : 'bg-[#0c1322] border-slate-900 text-slate-600'
                    }`}
                  >
                    {isSet ? '1' : '0'}
                  </div>
                );
              })}
            </div>
          </div>
          <p className="text-[8px] text-slate-500 mt-2.5 leading-tight">
            Probabilistic membership vector query matches known threat URL footprints.
          </p>
        </div>

        {/* 3. LSH MinHash & Signatures */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 space-y-3">
          <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5">
            LSH TRIGRAM SIGNATURES
          </span>
          <div className="space-y-1.5">
            <div className="flex flex-wrap gap-1 mb-2 max-h-12 overflow-y-auto pr-0.5">
              {data.lshTrigrams.map((tg, idx) => (
                <span key={idx} className="bg-[#0c1322] border border-[#1e2e4a] text-indigo-400 text-[8px] px-1 py-0.5 rounded">
                  "{tg}"
                </span>
              ))}
            </div>
            <div className="flex justify-between items-center text-[9px]">
              <span className="text-slate-500">MINHASH SIGNATURES:</span>
              <span className="text-white font-bold">{active || done ? `[ ${data.lshMinHashes.join(', ')} ]` : '--'}</span>
            </div>
            <div className="flex justify-between items-center text-[9px]">
              <span className="text-slate-500">JACCARD SIMILARITY:</span>
              <span className="text-blue-400 font-bold">{active || done ? `${Math.round(data.lshSimilarityScore * 100)}%` : '--'}</span>
            </div>
          </div>
        </div>

        {/* 4. Verified Blacklist Decision */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-between">
          <div>
            <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5 mb-2.5">
              DECISION VERIFICATION
            </span>
            <div className="space-y-1.5">
              <div className="flex justify-between items-center text-[9px]">
                <span className="text-slate-500">BLOOM RESULT:</span>
                <span className={data.bloomResult === 'Definitely Safe' ? 'text-green-400 font-bold' : 'text-red-400 font-bold'}>
                  {active || done ? data.bloomResult : 'PENDING'}
                </span>
              </div>
              <div className="flex justify-between items-center text-[9px]">
                <span className="text-slate-500">LSH CLOSEST HITS:</span>
                <span className="text-white font-bold">{active || done ? `${data.lshMatches.length} Matches` : '0'}</span>
              </div>
            </div>
          </div>

          <div className={`p-2 rounded text-[9px] font-semibold border mt-2 ${
            data.bloomResult === 'Definitely Safe' 
              ? 'bg-green-950/15 border-green-500/20 text-green-400' 
              : 'bg-red-950/15 border-red-500/20 text-red-400'
          }`}>
            {data.bloomResult === 'Definitely Safe' 
              ? '✓ Safe: Indices checked out to 0. No matching signature found.'
              : '⚠️ Blacklist match candidate. Evaluated Jaccard similarity bounds.'}
          </div>
        </div>
      </div>
    </div>
  );
}
