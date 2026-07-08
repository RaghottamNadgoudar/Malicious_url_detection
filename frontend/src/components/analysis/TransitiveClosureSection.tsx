import { useEffect, useState } from 'react';
import { Network } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function TransitiveClosureSection({ data, active, done }: Props) {
  const [revealRow, setRevealRow] = useState(-1);
  const [revealCol, setRevealCol] = useState(-1);

  useEffect(() => {
    if (active && !done) {
      setRevealRow(0);
      setRevealCol(0);
      
      const interval = setInterval(() => {
        setRevealCol(c => {
          const maxCols = data.closureMatrix[0].length;
          if (c < maxCols - 1) {
            return c + 1;
          } else {
            setRevealRow(r => {
              const maxRows = data.closureMatrix.length;
              if (r < maxRows - 1) {
                return r + 1;
              } else {
                clearInterval(interval);
                return r;
              }
            });
            return 0;
          }
        });
      }, 250);
      return () => clearInterval(interval);
    } else if (done) {
      setRevealRow(data.closureMatrix.length);
      setRevealCol(data.closureMatrix[0].length);
    }
  }, [active, done, data.closureMatrix]);

  const isCellRevealed = (rowIdx: number, colIdx: number) => {
    if (done) return true;
    if (!active) return false;
    if (rowIdx < revealRow) return true;
    if (rowIdx === revealRow && colIdx <= revealCol) return true;
    return false;
  };

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Network className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 8: TRANSITIVE CLOSURE (WARSHALL / BFS CLOSURE)
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">SOLVED</span>}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        {/* Reachability Matrix */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-center items-center overflow-x-auto">
          <span className="text-slate-400 font-bold mb-3 uppercase tracking-wider text-[10px] block w-full text-left border-b border-[#1a2740] pb-1.5">
            REACHABILITY ADJACENCIES MATRIX
          </span>
          <table className="border-collapse">
            <thead>
              <tr>
                <th className="p-2 border border-slate-900 text-slate-500 text-[9px]">Node</th>
                {data.matrixLabels.map((_, idx) => (
                  <th key={idx} className="p-2 border border-slate-900 text-slate-500 font-bold">N{idx}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.closureMatrix.map((row, rowIdx) => {
                const isCurrentRow = active && rowIdx === revealRow;
                return (
                  <tr key={rowIdx} className={isCurrentRow ? 'bg-blue-950/10' : ''}>
                    <td className="p-2 border border-slate-900 text-slate-400 font-bold">N{rowIdx}</td>
                    {row.map((cell, colIdx) => {
                      const revealed = isCellRevealed(rowIdx, colIdx);
                      const isConnected = cell === 1 && revealed;
                      
                      return (
                        <td
                          key={colIdx}
                          className={`p-3 border border-slate-900 text-center font-bold font-mono transition-all duration-300 ${
                            isConnected
                              ? 'text-green-400 bg-green-950/15'
                              : revealed
                              ? 'text-slate-600 bg-[#0c1322]'
                              : 'text-slate-800 bg-transparent'
                          }`}
                        >
                          {revealed ? (cell === 1 ? '1' : '0') : '--'}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Closure metrics and labels */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 flex flex-col justify-between h-56">
          <div className="space-y-3">
            <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block border-b border-[#1a2740] pb-1.5">
              GRAPH TOPOLOGICAL ISSUES
            </span>
            <div className="space-y-2">
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-500">REDIRECT LOOPS DETECTED:</span>
                <span className={`font-bold ${data.loopsDetected ? 'text-red-400' : 'text-green-400'}`}>
                  {data.loopsDetected ? 'WARNING: LOOP FOUND' : '✓ NORMAL (DAG)'}
                </span>
              </div>
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-500">SINKHOLE ROUTING NODE:</span>
                <span className="text-amber-400 font-bold">None</span>
              </div>
              <div className="flex justify-between items-center text-[10px]">
                <span className="text-slate-500">INDIRECT REDIRECT HOPS:</span>
                <span className="text-blue-400 font-bold">
                  {data.redirectCount > 1 ? `${data.redirectCount} Transitive Hops` : 'Direct Path Only'}
                </span>
              </div>
            </div>
          </div>

          <div className="p-3 bg-[#0c1322] border border-[#1a2740] rounded-lg text-[9px] text-slate-400 leading-relaxed font-semibold">
            💡 Warshall closure detects if a node is self-reachable (redirect loop) or transitively reaches a flagged blacklisted node (indirect propagation).
          </div>
        </div>
      </div>
    </div>
  );
}
