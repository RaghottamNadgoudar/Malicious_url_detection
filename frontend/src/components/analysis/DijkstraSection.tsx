import { useEffect, useState } from 'react';
import { Target, Layers } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function DijkstraSection({ data, active, done }: Props) {
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    if (active && !done) {
      const interval = setInterval(() => {
        setCurrentStep(s => {
          if (s >= data.dijkstraSteps.length - 1) {
            return s;
          }
          return s + 1;
        });
      }, 700);
      return () => clearInterval(interval);
    }
  }, [active, done, data.dijkstraSteps.length]);

  const activeStep = data.dijkstraSteps[currentStep] || data.dijkstraSteps[0];
  const stepToDisplay = done ? data.dijkstraSteps[data.dijkstraSteps.length - 1] : activeStep;

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Target className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 7: DIJKSTRA SHORTEST THREAT PATH ANALYSIS
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">ROUTED</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
        {/* Priority Queue State */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col h-64">
          <span className="text-slate-400 font-bold mb-3 uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5">
            PRIORITY QUEUE (min-heap)
          </span>
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            <div className="grid grid-cols-2 text-slate-500 font-bold border-b border-slate-900 pb-1">
              <span>NODE ID</span>
              <span className="text-right">WEIGHT DISTANCE</span>
            </div>
            {stepToDisplay.queue.map((item, idx) => (
              <div key={idx} className="grid grid-cols-2 text-white font-bold bg-[#0c1322] px-2 py-1 rounded">
                <span>{item.node}</span>
                <span className="text-right text-blue-400">{item.dist} ms</span>
              </div>
            ))}
          </div>
        </div>

        {/* Visited & Distance Metrics */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col h-64">
          <span className="text-slate-400 font-bold mb-3 uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5">
            REACHED SET & VISITED DIST
          </span>
          <div className="flex-1 overflow-y-auto space-y-3">
            <div>
              <span className="text-slate-500 block mb-1 text-[9px]">SET OF VISITED NODES (S):</span>
              <div className="flex flex-wrap gap-1.5">
                {stepToDisplay.visited.map((n, idx) => (
                  <span key={idx} className="bg-[#1a2740] text-slate-200 px-2 py-0.5 rounded text-[10px]">
                    {n}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span className="text-slate-500 block mb-1 text-[9px]">CURRENT NODE WEIGHT DIST:</span>
              <div className="text-2xl font-black text-white">
                {stepToDisplay.distance} ms
              </div>
            </div>
          </div>
        </div>

        {/* Dijkstra shortest path results */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col h-64">
          <span className="text-slate-400 font-bold mb-3 uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5">
            OPTIMAL SHORTEST THREAT PATH
          </span>
          <div className="flex-1 flex flex-col justify-between">
            <div className="space-y-2">
              <span className="text-slate-500 block text-[9px]">SHORTEST DETECTED ROUTE:</span>
              <div className="bg-[#0c1322] border border-[#1a2740] p-2.5 rounded-lg text-green-400 font-bold break-all leading-relaxed">
                {active || done ? data.shortestPath.join(' → ') : 'node_0'}
              </div>
            </div>

            <div className="bg-[#10b981]/10 border border-[#10b981]/25 p-3 rounded-lg text-[10px] text-green-400 mt-3 font-semibold">
              💡 Dijkstra traversal reveals the lowest total propagation latency to threat nodes, ensuring efficient real-time threat blocking.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
