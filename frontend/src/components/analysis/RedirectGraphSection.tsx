import React, { useState, useRef } from 'react';
import { GitBranch, ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function RedirectGraphSection({ data, active, done }: Props) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [hoverNode, setHoverNode] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const zoomFactor = 1.1;
    if (e.deltaY < 0) {
      setZoom(z => Math.min(2.5, z * zoomFactor));
    } else {
      setZoom(z => Math.max(0.5, z / zoomFactor));
    }
  };

  const resetZoomPan = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  // Generate positioning for nodes horizontally
  const nodeCount = data.graphNodes.length;
  const paddingX = 180;
  const paddingY = 80;
  
  const nodesWithPositions = data.graphNodes.map((node, index) => {
    // Horizontal alignment with slight offset for secondary nodes
    const isPrimaryChain = index < data.redirectCount + 1;
    let x = 100 + index * paddingX;
    let y = 150;
    
    if (!isPrimaryChain) {
      // Offset secondary mock nodes upwards/downwards
      x = 100 + (index - 1) * paddingX;
      y = index % 2 === 0 ? 150 - paddingY : 150 + paddingY;
    }
    return { ...node, x, y };
  });

  const getEdgePoints = (sourceId: string, targetId: string) => {
    const sNode = nodesWithPositions.find(n => n.id === sourceId);
    const tNode = nodesWithPositions.find(n => n.id === targetId);
    if (!sNode || !tNode) return { x1: 0, y1: 0, x2: 0, y2: 0 };
    return { x1: sNode.x, y1: sNode.y, x2: tNode.x, y2: tNode.y };
  };

  const getNodeColor = (type: 'safe' | 'suspicious' | 'malicious') => {
    if (type === 'malicious') return '#ef4444';
    if (type === 'suspicious') return '#f59e0b';
    return '#10b981';
  };

  const hasRedirects = data.graphNodes.length > 1;

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <GitBranch className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 2: REDIRECT NODE-EDGE MAP
        </h2>
        
        {(active || done) && (
          <div className="flex items-center gap-2 ml-auto">
            {/* Real redirect count badge */}
            <span className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded-full border ${
              hasRedirects
                ? 'bg-amber-950/20 border-amber-500/30 text-amber-400'
                : 'bg-green-950/20 border-green-500/30 text-green-400'
            }`}>
              {data.redirectCount} redirect{data.redirectCount !== 1 ? 's' : ''}
            </span>
            <button onClick={() => setZoom(z => Math.min(2.5, z + 0.1))} className="p-1.5 hover:bg-[#1a2740] rounded text-slate-400 hover:text-white transition-colors" title="Zoom In"><ZoomIn size={14} /></button>
            <button onClick={() => setZoom(z => Math.max(0.5, z - 0.1))} className="p-1.5 hover:bg-[#1a2740] rounded text-slate-400 hover:text-white transition-colors" title="Zoom Out"><ZoomOut size={14} /></button>
            <button onClick={resetZoomPan} className="p-1.5 hover:bg-[#1a2740] rounded text-slate-400 hover:text-white transition-colors" title="Reset view"><RotateCcw size={14} /></button>
          </div>
        )}
      </div>

      {/* No-redirect informational banner */}
      {(active || done) && !hasRedirects && (
        <div className="mb-4 flex items-center gap-2 text-xs font-mono bg-green-950/10 border border-green-500/20 rounded-xl px-4 py-3 text-green-400">
          <span className="font-black text-green-500">✓</span>
          <span>
            <strong>Direct URL — No HTTP Redirects Detected.</strong> The backend URL expander followed the request chain and found no redirect hops for this URL. The graph shows a single terminal node.
          </span>
        </div>
      )}

      <div className="relative">
        <div 
          ref={containerRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onWheel={handleWheel}
          className="w-full h-80 bg-[#070d1a] border border-[#1a2740] rounded-xl overflow-hidden cursor-grab active:cursor-grabbing relative"
        >
          {/* Legend */}
          <div className="absolute top-3 left-3 bg-[#0c1322]/80 backdrop-blur-md px-3 py-2 rounded-lg border border-[#1a2740] text-[10px] font-mono flex gap-4 z-10 select-none">
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-green-500" /> SAFE</div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> SUSPICIOUS</div>
            <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500" /> MALICIOUS</div>
          </div>

          {/* SVG Canvas */}
          <svg className="w-full h-full select-none pointer-events-none">
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#3b82f6" />
              </marker>
            </defs>

            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`} className="pointer-events-auto">
              {/* Edges */}
              {data.graphEdges.map((edge, index) => {
                const { x1, y1, x2, y2 } = getEdgePoints(edge.source, edge.target);
                return (
                  <g key={index}>
                    <line
                      x1={x1}
                      y1={y1}
                      x2={x2}
                      y2={y2}
                      stroke="#1e2e4a"
                      strokeWidth="2"
                    />
                    <line
                      x1={x1}
                      y1={y1}
                      x2={x2}
                      y2={y2}
                      stroke="#3b82f6"
                      strokeWidth="2"
                      markerEnd="url(#arrow)"
                      className="animate-draw-path"
                    />
                    {/* Weight Label */}
                    <rect
                      x={(x1 + x2) / 2 - 8}
                      y={(y1 + y2) / 2 - 8}
                      width="16"
                      height="16"
                      rx="4"
                      fill="#0c1322"
                      stroke="#1e2e4a"
                      strokeWidth="1"
                    />
                    <text
                      x={(x1 + x2) / 2}
                      y={(y1 + y2) / 2 + 3}
                      fill="#3b82f6"
                      fontSize="9"
                      fontWeight="bold"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {edge.weight}
                    </text>
                  </g>
                );
              })}

              {/* Nodes */}
              {nodesWithPositions.map((node) => {
                const color = getNodeColor(node.type);
                const isHovered = hoverNode === node.id;
                
                return (
                  <g 
                    key={node.id} 
                    transform={`translate(${node.x}, ${node.y})`}
                    className="cursor-pointer"
                    onMouseEnter={() => setHoverNode(node.id)}
                    onMouseLeave={() => setHoverNode(null)}
                  >
                    {/* Ring for active states */}
                    <circle
                      r="22"
                      fill="none"
                      stroke={color}
                      strokeWidth="2"
                      opacity={isHovered ? 0.8 : 0.2}
                      className={isHovered ? 'animate-ping' : ''}
                    />
                    {/* Core node */}
                    <circle
                      r="16"
                      fill="#0d1526"
                      stroke={color}
                      strokeWidth="2.5"
                    />
                    
                    <text
                      y="4"
                      fill={color}
                      fontSize="9"
                      fontWeight="black"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {node.id.split('_')[1]}
                    </text>

                    {/* Node text label below */}
                    <text
                      y="32"
                      fill="#94a3b8"
                      fontSize="9"
                      fontWeight="semibold"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {node.label}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Node Hover Tooltip info */}
          {hoverNode && (
            <div className="absolute bottom-3 right-3 bg-[#0c1322] border border-[#1a2740] p-3 rounded-lg text-[10px] font-mono shadow-xl max-w-xs animate-fade-in pointer-events-none">
              <span className="text-blue-500 font-bold block mb-1">NODE DETAIL PROFILES</span>
              <span className="text-white font-bold block truncate">ID: {hoverNode}</span>
              <span className="text-slate-400 block truncate">Host: {nodesWithPositions.find(n => n.id === hoverNode)?.label}</span>
              <span className="block mt-1 font-bold" style={{ color: getNodeColor(nodesWithPositions.find(n => n.id === hoverNode)?.type || 'safe') }}>
                Status: {nodesWithPositions.find(n => n.id === hoverNode)?.type.toUpperCase()}
              </span>
            </div>
          )}
        </div>
        <p className="text-[10px] font-mono text-slate-400 mt-2">
          💡 Click and drag to pan the graph. Use mouse wheel or buttons to zoom. Hover over nodes to inspect details.
        </p>
      </div>
    </div>
  );
}
