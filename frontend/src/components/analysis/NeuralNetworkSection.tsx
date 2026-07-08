import { useEffect, useState } from 'react';
import { Cpu } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function NeuralNetworkSection({ data, active, done }: Props) {
  const [pulsePhase, setPulsePhase] = useState(0);

  useEffect(() => {
    if (active && !done) {
      const interval = setInterval(() => {
        setPulsePhase(p => (p + 1) % 4); // cycles through layers 0 to 3
      }, 800);
      return () => clearInterval(interval);
    }
  }, [active, done]);

  // SVG Layer configurations
  const layers = [
    { name: 'Input', nodes: data.neuronInputs.length, label: 'Features' },
    { name: 'Hidden 1', nodes: data.neuronHidden1.length, label: 'Weights 1' },
    { name: 'Hidden 2', nodes: data.neuronHidden2.length, label: 'Weights 2' },
    { name: 'Output', nodes: data.neuronOutputs.length, label: 'Verdicts' },
  ];

  // Coordinates calculation
  const width = 600;
  const height = 240;
  const paddingX = 140;
  
  const layerCoordinates = layers.map((layer, layerIdx) => {
    const x = 50 + layerIdx * paddingX;
    const verticalGap = height / (layer.nodes + 1);
    
    return Array.from({ length: layer.nodes }, (_, nodeIdx) => ({
      x,
      y: verticalGap * (nodeIdx + 1),
    }));
  });

  const getActivationColor = (layerIdx: number, nodeIdx: number) => {
    if (!active && !done) return '#1e2e4a';
    if (done) {
      if (layerIdx === 3 && nodeIdx === 2 && data.verdict === 'Malicious') return '#ef4444';
      if (layerIdx === 3 && nodeIdx === 1 && data.verdict === 'Suspicious') return '#f59e0b';
      if (layerIdx === 3 && nodeIdx === 0 && data.verdict === 'Safe') return '#10b981';
      return '#3b82f6';
    }
    
    // Cycle animation highlight
    if (layerIdx === pulsePhase) {
      return '#60a5fa';
    }
    return '#1e2e4a';
  };

  const getProbabilityColor = (index: number) => {
    if (index === 0) return 'bg-green-500 text-green-400';
    if (index === 1) return 'bg-amber-500 text-amber-400';
    return 'bg-red-500 text-red-400';
  };

  const labels = ['Safe', 'Suspicious', 'Malicious'];

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Cpu className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 6: DEEP LEARNING NEURAL CLASSIFIER
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">CLASSIFIED</span>}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
        {/* Network diagram */}
        <div className="lg:col-span-2 bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-4 overflow-x-auto flex justify-center">
          <svg width={width} height={height} className="min-w-[500px]">
            {/* Draw connecting lines (Edges) */}
            {layerCoordinates.map((layer, layerIdx) => {
              if (layerIdx === layerCoordinates.length - 1) return null;
              const nextLayer = layerCoordinates[layerIdx + 1];
              
              return layer.map((node, nodeIdx) => 
                nextLayer.map((nextNode, nextNodeIdx) => {
                  const isFlowing = active && layerIdx === pulsePhase;
                  return (
                    <g key={`${layerIdx}-${nodeIdx}-${nextNodeIdx}`}>
                      <line
                        x1={node.x}
                        y1={node.y}
                        x2={nextNode.x}
                        y2={nextNode.y}
                        stroke={isFlowing ? '#3b82f6' : '#101b2e'}
                        strokeWidth={isFlowing ? '1.5' : '1'}
                        opacity={isFlowing ? 0.7 : 0.3}
                        className={isFlowing ? 'animate-draw-path' : ''}
                      />
                    </g>
                  );
                })
              );
            })}

            {/* Draw nodes */}
            {layerCoordinates.map((layer, layerIdx) => 
              layer.map((node, nodeIdx) => {
                const color = getActivationColor(layerIdx, nodeIdx);
                const isPulsing = active && layerIdx === pulsePhase;
                
                return (
                  <g key={`${layerIdx}-${nodeIdx}`}>
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={isPulsing ? 8 : 6}
                      fill={color}
                      className={isPulsing ? 'neuron-pulse' : ''}
                      style={{ transition: 'all 0.3s' }}
                    />
                    
                    {/* Node labels for input / outputs */}
                    {layerIdx === 0 && (
                      <text x={node.x - 10} y={node.y + 4} fill="#64748b" fontSize="8" fontFamily="monospace" textAnchor="end">
                        F{nodeIdx + 1}
                      </text>
                    )}
                    {layerIdx === 3 && (
                      <text x={node.x + 12} y={node.y + 4} fill="#94a3b8" fontSize="8" fontWeight="bold" fontFamily="monospace" textAnchor="start">
                        {labels[nodeIdx]}
                      </text>
                    )}
                  </g>
                );
              })
            )}

            {/* Layer Titles */}
            {layers.map((layer, layerIdx) => (
              <text
                key={layerIdx}
                x={50 + layerIdx * paddingX}
                y={15}
                fill="#475569"
                fontSize="8"
                fontWeight="black"
                fontFamily="monospace"
                textAnchor="middle"
              >
                {layer.name.toUpperCase()}
              </text>
            ))}
          </svg>
        </div>

        {/* Probabilities Output Panel */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 space-y-4 font-mono text-xs h-64 flex flex-col justify-center">
          <span className="text-slate-400 font-bold mb-2 uppercase tracking-wider text-[10px]">
            SOFTMAX PROBABILITIES
          </span>

          {data.neuronOutputs.map((prob, idx) => {
            const colors = getProbabilityColor(idx).split(' ');
            return (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between items-center text-[10px]">
                  <span className="text-slate-300 font-bold uppercase">{labels[idx]}</span>
                  <span className={`font-bold ${colors[1]}`}>{Math.round(prob * 100)}%</span>
                </div>
                <div className="w-full h-2 bg-[#0c1322] border border-[#1e2e4a] rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${colors[0]} transition-all duration-1000 ease-out`}
                    style={{ width: `${active || done ? prob * 100 : 0}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
