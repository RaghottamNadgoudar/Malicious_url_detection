import { useEffect, useState } from 'react';
import { Network, Activity, Layers, ArrowDown } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function GraphAlgorithmsSection({ data, active, done }: Props) {
  const [step, setStep] = useState(0);

  // We can cycle step from 0 to 4 to animate BFS, DFS, Topo, and Branch & Bound steps.
  useEffect(() => {
    if (active && !done) {
      const interval = setInterval(() => {
        setStep(s => (s + 1) % 4);
      }, 1500);
      return () => clearInterval(interval);
    }
  }, [active, done]);

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Network className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 3: GRAPH ALGORITHMS PIPELINE
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">SOLVED</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        {/* BFS Panel */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3 border-b border-[#1a2740] pb-2 text-blue-400">
            <Layers size={14} />
            <span className="font-bold">BFS TRAVERSAL (QUEUE-BASED)</span>
          </div>
          
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">QUEUE STATE:</span>
              <span className="text-white bg-[#1a2740] px-2 py-0.5 rounded text-[10px]">
                {active && step === 0 ? `[ ${data.bfsPath[0] ?? '-'}, ${data.bfsPath[1] ?? '-'} ]` : active && step === 1 ? `[ ${data.bfsPath[1] ?? '-'}, ${data.bfsPath[2] ?? '-'} ]` : '[]'}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-slate-400">VISITED SET:</span>
              <span className="text-green-400">
                {'{ '}{data.bfsPath.slice(0, active ? step + 1 : data.bfsPath.length).join(', ')}{' }'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400">CURRENT TARGET:</span>
              <span className="text-amber-400 font-bold">
                {active ? data.bfsPath[step] : data.bfsPath[0]}
              </span>
            </div>

            <div className="h-2 bg-[#0c1322] border border-[#1e2e4a] rounded-full overflow-hidden relative">
              <div 
                className="h-full bg-blue-500 transition-all duration-500" 
                style={{ width: `${((active ? step + 1 : data.bfsPath.length) / data.bfsPath.length) * 100}%` }}
              />
            </div>
          </div>
        </div>

        {/* DFS Panel */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3 border-b border-[#1a2740] pb-2 text-indigo-400">
            <Activity size={14} />
            <span className="font-bold">DFS TRAVERSAL (STACK-BASED)</span>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">STACK FRAME:</span>
              <span className="text-white bg-[#1a2740] px-2 py-0.5 rounded text-[10px]">
                {active && step === 0 ? `[ ${data.dfsPath[0] ?? '-'} ]` : active && step === 1 ? `[ ${data.dfsPath[0] ?? '-'}, ${data.dfsPath[1] ?? '-'} ]` : `[ ${data.dfsPath[0] ?? '-'} ]`}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400">RECURSION EXPLORED:</span>
              <span className="text-indigo-400">
                {'{ '}{data.dfsPath.slice(0, active ? step + 1 : data.dfsPath.length).join(' → ')}{' }'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-400">BACKTRACK NODE:</span>
              <span className="text-slate-500">
                {active && step > 2 ? data.dfsPath[0] : 'NONE'}
              </span>
            </div>

            <div className="h-2 bg-[#0c1322] border border-[#1e2e4a] rounded-full overflow-hidden relative">
              <div 
                className="h-full bg-indigo-500 transition-all duration-500" 
                style={{ width: `${((active ? step + 1 : data.dfsPath.length) / data.dfsPath.length) * 100}%` }}
              />
            </div>
          </div>
        </div>

        {/* Topological Sort Panel */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3 border-b border-[#1a2740] pb-2 text-green-400">
            <Layers size={14} />
            <span className="font-bold">TOPOLOGICAL SORT (KAHN'S ALGO)</span>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">IN-DEGREES EQUALS ZERO:</span>
              <span className="text-green-400">
                {active && step === 0 ? `[ ${data.topoOrder[0] ?? '-'} ]` : `[ ${data.topoOrder[1] ?? data.topoOrder[0] ?? '-'} ]`}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-slate-400">PROCESSING NODE ORDER:</span>
              <span className="text-white block bg-[#0c1322] px-2 py-1 rounded truncate">
                {data.topoOrder.slice(0, active ? step + 1 : data.topoOrder.length).join(' → ')}
              </span>
            </div>
          </div>
        </div>

        {/* Branch and Bound Panel */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3 border-b border-[#1a2740] pb-2 text-amber-400">
            <Layers size={14} />
            <span className="font-bold">BRANCH & BOUND PRUNING</span>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">ACTIVE SEARCH PATHS:</span>
              <span className="text-green-400 font-bold">Node 0 → Node 1</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">PRUNED LOW ENTROPY:</span>
              <span className="text-red-400 font-bold">
                {data.prunedBranches.length > 0 ? data.prunedBranches.join(', ') : 'NONE'}
              </span>
            </div>
            <p className="text-[10px] text-slate-500 mt-1">
              Branches where Shannons Entropy &lt; 3.0 are pruned (deemed too low randomness for complex redirect routing).
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
