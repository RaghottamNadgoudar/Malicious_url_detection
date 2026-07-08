import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, LineChart, Line, ScatterChart, Scatter, ZAxis } from 'recharts';
import { BarChart3 } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';


interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function BottomAnalytics({ data, active, done }: Props) {
  if (!active && !done) {
    return (
      <div className="bg-[#0c1322] border border-[#1a2740] rounded-2xl p-6 text-center text-slate-500 font-mono text-xs">
        Awaiting analysis completion to compile visual analytics charts...
      </div>
    );
  }

  // 1. Pie Chart Data: Verdict probabilities
  const pieData = [
    { name: 'Safe', value: Math.round(data.neuronOutputs[0] * 100), color: '#10b981' },
    { name: 'Suspicious', value: Math.round(data.neuronOutputs[1] * 100), color: '#f59e0b' },
    { name: 'Malicious', value: Math.round(data.neuronOutputs[2] * 100), color: '#ef4444' },
  ];

  // 2. Bar Chart Data: Execution time of algorithms
  const barData = Object.keys(data.executionTimes).map(key => ({
    name: key.replace(' Analysis', '').replace(' Matching', ''),
    time: data.executionTimes[key],
  }));

  // 3. Line Chart Data: Threat detection progress across redirect hops
  const lineData = data.expansionHops.map((h, idx) => ({
    hop: `Hop ${h.hop}`,
    threat: h.isSuspicious ? 80 : idx === data.expansionHops.length - 1 && data.verdict === 'Malicious' ? 95 : 15,
  }));

  // 4. Scatter Plot Data: Entropy vs Threat Probability
  const scatterData = [
    { entropy: data.entropyValue, threat: data.threatScore },
    { entropy: 2.1, threat: 5 },
    { entropy: 4.8, threat: 92 },
    { entropy: 3.6, threat: 45 },
    { entropy: 5.2, threat: 98 },
    { entropy: 1.8, threat: 2 },
  ];

  return (
    <div className="bg-[#0c1322] border border-[#1a2740] rounded-2xl p-6 space-y-6">
      <div className="flex items-center gap-3 border-b border-[#1a2740] pb-3">
        <BarChart3 className="w-5 h-5 text-blue-500" />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          PIPELINE METRIC DIAGNOSTICS & ANALYTICS
        </h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        {/* Pie Chart: Softmax Verdicts */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 h-72">
          <span className="text-slate-400 font-bold mb-4 uppercase tracking-wider block text-[10px]">
            SOFTMAX VERDICT PROBABILITIES (%)
          </span>
          <div className="w-full h-48 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#0c1322', borderColor: '#1e2e4a', fontSize: '10px' }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex flex-col gap-2 shrink-0">
              {pieData.map(item => (
                <div key={item.name} className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-400">{item.name}:</span>
                  <span className="text-white font-bold">{item.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Bar Chart: Execution Times */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 h-72">
          <span className="text-slate-400 font-bold mb-4 uppercase tracking-wider block text-[10px]">
            ALGORITHM EXECUTION LATENCIES (ms)
          </span>
          <div className="w-full h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={8} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={8} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0c1322', borderColor: '#1e2e4a', fontSize: '10px' }} />
                <Bar dataKey="time" fill="#3b82f6" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Line Chart: Threat Progress */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 h-72">
          <span className="text-slate-400 font-bold mb-4 uppercase tracking-wider block text-[10px]">
            HOP-BY-HOP THREAT PROGRESSION
          </span>
          <div className="w-full h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={lineData}>
                <XAxis dataKey="hop" stroke="#64748b" fontSize={9} />
                <YAxis stroke="#64748b" fontSize={9} />
                <Tooltip contentStyle={{ backgroundColor: '#0c1322', borderColor: '#1e2e4a', fontSize: '10px' }} />
                <Line type="monotone" dataKey="threat" stroke="#ef4444" strokeWidth={2} dot={{ fill: '#ef4444' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Scatter Chart: Entropy vs Threat Probability */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 h-72">
          <span className="text-slate-400 font-bold mb-4 uppercase tracking-wider block text-[10px]">
            SHANNONS ENTROPY VS THREAT RISK
          </span>
          <div className="w-full h-48">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 10 }}>
                <XAxis type="number" dataKey="entropy" name="Entropy" stroke="#64748b" fontSize={9} label={{ value: 'Entropy', position: 'bottom', fill: '#64748b', fontSize: '9px' }} />
                <YAxis type="number" dataKey="threat" name="Threat" stroke="#64748b" fontSize={9} label={{ value: 'Threat %', angle: -90, position: 'insideLeft', fill: '#64748b', fontSize: '9px' }} />
                <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ backgroundColor: '#0c1322', borderColor: '#1e2e4a', fontSize: '10px' }} />
                <Scatter name="URLs" data={scatterData} fill="#ef4444" />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Heatmap: Redirect Reachability Matrix */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 md:col-span-2">
          <span className="text-slate-400 font-bold mb-4 uppercase tracking-wider block text-[10px]">
            TRANSITIVE REACHABILITY HEATMAP MATRIX
          </span>
          <div className="flex flex-col gap-2 items-center justify-center p-4">
            <div className="grid grid-cols-5 gap-2 max-w-sm w-full">
              <span className="text-[9px] text-slate-500 font-bold">Node</span>
              {data.matrixLabels.map((_, idx) => (
                <span key={idx} className="text-[9px] text-slate-500 font-bold text-center">N{idx}</span>
              ))}

              {data.closureMatrix.map((row, rowIdx) => (
                <React.Fragment key={rowIdx}>
                  <span className="text-[9px] text-slate-400 font-bold self-center">N{rowIdx}</span>
                  {row.map((cell, colIdx) => (
                    <div
                      key={colIdx}
                      className={`h-8 rounded transition-all duration-300 flex items-center justify-center font-bold text-[10px] ${
                        cell === 1 
                          ? 'bg-red-500/25 border border-red-500/40 text-red-300' 
                          : 'bg-green-500/10 border border-green-500/25 text-green-400'
                      }`}
                    >
                      {cell === 1 ? 'TRAV' : 'SAFE'}
                    </div>
                  ))}
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
