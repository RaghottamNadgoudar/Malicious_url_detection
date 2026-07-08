import { useEffect, useState } from 'react';
import { Layers, ShieldAlert, Cpu } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function HeapsortSection({ data, active, done }: Props) {
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    if (active && !done) {
      const interval = setInterval(() => {
        setCurrentStep(s => (s + 1) % data.heapsortSteps.length);
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [active, done, data.heapsortSteps.length]);

  const activeStep = data.heapsortSteps[currentStep] || data.heapsortSteps[0];
  const stepToDisplay = done ? data.heapsortSteps[data.heapsortSteps.length - 1] : activeStep;

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Layers className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 10: HEAPSORT RANKING & HUFFMAN ANOMALY DETECTION
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">VERIFIED</span>}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* 1. Heapsort Array */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-between h-64">
          <div>
            <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5 mb-3">
              MAX-HEAP BINARY ARRAY
            </span>
            <div className="flex items-center gap-2 flex-wrap mb-4">
              {stepToDisplay.array.map((val, idx) => {
                const isSwapping = stepToDisplay.swap?.includes(idx);
                return (
                  <div
                    key={idx}
                    className={`w-10 h-10 rounded border flex items-center justify-center font-bold font-mono transition-all duration-300 ${
                      isSwapping
                        ? 'bg-amber-950/40 border-amber-500 text-amber-400 heap-swap-active'
                        : 'bg-[#0c1322] border-[#1e2e4a] text-slate-300'
                    }`}
                  >
                    {val}
                  </div>
                );
              })}
            </div>
            <p className="text-[9px] text-slate-500 leading-tight">
              Extracts high threat ranks recursively using max-heap structure to rank scanned targets with O(n log n) efficiency.
            </p>
          </div>
          <div className="text-[10px] text-slate-500 border-t border-[#1a2740] pt-2">
            Phase: <span className="text-blue-400 font-bold uppercase">{stepToDisplay.phase} max-heap</span>
          </div>
        </div>

        {/* 2. Huffman Tree Baseline Visualizer */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-between h-64">
          <div>
            <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5 mb-3">
              HUFFMAN BASELINE CODE TREE
            </span>
            <div className="flex flex-col gap-1 items-center justify-center h-28 border border-[#1a2740] rounded-lg bg-[#050912] p-2">
              {/* Simplified visual representation of the Huffman Tree structure */}
              <div className="text-[10px] text-slate-300 font-bold border border-slate-700 bg-slate-800/20 px-2 py-0.5 rounded">root (1.00)</div>
              <div className="w-12 h-3 border-x border-slate-700 border-t-0" />
              <div className="flex gap-4">
                <span className="text-[9px] text-slate-400 border border-slate-800 bg-slate-900/40 px-1 py-0.5 rounded">L (0.42)</span>
                <span className="text-[9px] text-slate-400 border border-slate-800 bg-slate-900/40 px-1 py-0.5 rounded">R (0.58)</span>
              </div>
              <div className="flex gap-6 mt-1 text-[8px] text-slate-500">
                <span>e / o</span>
                <span>a / t</span>
              </div>
            </div>
            <p className="text-[9px] text-slate-500 mt-2.5 leading-tight">
              Calibrates standard character weight code trees from benign URLs for lexical complexity matching.
            </p>
          </div>
        </div>

        {/* 3. Huffman Anomaly Detection Output */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-between h-64">
          <div>
            <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5 mb-3">
              ENTROPY DEVIATION LOGS
            </span>
            <div className="space-y-2">
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-500">BASELINE ENTROPY:</span>
                <span className="text-white font-bold">3.25</span>
              </div>
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-500">ACTUAL ENTROPY:</span>
                <span className="text-blue-400 font-bold">{data.entropyValue}</span>
              </div>
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-500">DEVIATION MEASUREMENT:</span>
                <span className="text-white font-bold">{data.huffmanDeviation}</span>
              </div>
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-500">COMPLEXITY ANOMALY:</span>
                <span className={`font-bold ${data.isHuffmanAnomaly ? 'text-red-400' : 'text-green-400'}`}>
                  {active || done ? (data.isHuffmanAnomaly ? 'WARNING: ANOMALY' : '✓ NORMAL') : 'WAITING'}
                </span>
              </div>
            </div>
          </div>

          <div className={`p-2.5 rounded border text-[9px] font-semibold ${
            data.isHuffmanAnomaly 
              ? 'bg-red-950/15 border-red-500/20 text-red-400' 
              : 'bg-green-950/15 border-green-500/20 text-green-400'
          }`}>
            {data.isHuffmanAnomaly 
              ? '⚠️ Warning: String length/entropy deviates significantly from Huffman baseline. Indication of obfuscation.'
              : '✓ Lexical complexity conforms to standard baseline expectation patterns.'}
          </div>
        </div>
      </div>
    </div>
  );
}
