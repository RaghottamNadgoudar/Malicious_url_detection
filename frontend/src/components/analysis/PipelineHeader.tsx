import React from 'react';
import { Shield, AlertTriangle, CheckCircle, HelpCircle } from 'lucide-react';
import { PIPELINE_STEPS } from '../../utils/analysisEngine';

interface Props {
  url: string;
  status: 'loading' | 'success' | 'error';
  currentPhaseIndex: number;
  threatScore: number;
  verdict: 'Safe' | 'Suspicious' | 'Malicious';
}

export default function PipelineHeader({ url, status, currentPhaseIndex, threatScore, verdict }: Props) {
  const getProgressPercent = () => {
    if (status === 'loading' && currentPhaseIndex === -1) return 5;
    if (currentPhaseIndex === -1) return 0;
    return Math.round(((currentPhaseIndex + 1) / PIPELINE_STEPS.length) * 100);
  };

  const getVerdictBadge = () => {
    switch (verdict) {
      case 'Safe':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-black bg-green-500/10 text-green-400 border border-green-500/20">
            <CheckCircle size={14} /> SAFE
          </span>
        );
      case 'Suspicious':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-black bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle size={14} /> SUSPICIOUS
          </span>
        );
      case 'Malicious':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-black bg-red-500/10 text-red-400 border border-red-500/20">
            <Shield size={14} /> MALICIOUS
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-black bg-gray-500/10 text-gray-400 border border-gray-500/20">
            <HelpCircle size={14} /> UNKNOWN
          </span>
        );
    }
  };

  return (
    <div className="bg-[#0c1322] border border-[#1a2740] rounded-2xl p-6 mb-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        {/* Left Side: URL & Status */}
        <div className="flex-1 min-w-0">
          <span className="text-xs font-mono font-bold text-blue-500 uppercase tracking-wider block mb-1">
            TARGET SCAN PROFILE
          </span>
          <h1 className="text-lg md:text-xl font-bold text-white truncate font-mono select-all mb-3 bg-[#070d1a] border border-[#1e2e4a] px-3.5 py-2.5 rounded-xl">
            {url}
          </h1>
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${status === 'loading' ? 'bg-blue-400' : 'bg-green-400'}`}></span>
                <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${status === 'loading' ? 'bg-blue-500' : 'bg-green-500'}`}></span>
              </span>
              <span className="text-xs font-semibold text-slate-300 capitalize">
                {status === 'loading' ? `Analyzing Stage: ${PIPELINE_STEPS[Math.max(0, currentPhaseIndex)]?.name || 'Initializing'}` : 'Scan Completed'}
              </span>
            </div>
            {status === 'success' && getVerdictBadge()}
          </div>
        </div>

        {/* Right Side: Score Gauge */}
        <div className="flex items-center gap-6 self-start lg:self-center">
          <div className="text-right">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider block">
              OVERALL THREAT
            </span>
            <span className="text-4xl md:text-5xl font-black font-mono text-white tracking-tight">
              {status === 'success' ? `${threatScore}%` : '--'}
            </span>
          </div>
          
          <div className="relative w-16 h-16 flex-shrink-0">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
              <circle
                cx="18"
                cy="18"
                r="16"
                fill="none"
                stroke="#1a2740"
                strokeWidth="3.5"
              />
              <circle
                cx="18"
                cy="18"
                r="16"
                fill="none"
                stroke={threatScore > 70 ? '#ef4444' : threatScore > 40 ? '#f59e0b' : '#10b981'}
                strokeWidth="3.5"
                strokeDasharray={`${status === 'success' ? threatScore : 10}, 100`}
                className="transition-all duration-1000 ease-out"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <Shield className={`w-6 h-6 ${threatScore > 70 ? 'text-red-500' : threatScore > 40 ? 'text-amber-500' : 'text-green-500'}`} />
            </div>
          </div>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mt-6">
        <div className="flex justify-between items-center text-xs font-mono text-slate-400 mb-1.5">
          <span>PIPELINE INTEGRITY CHECK</span>
          <span className="font-bold text-blue-400">{getProgressPercent()}% COMPLETE</span>
        </div>
        <div className="w-full h-2 bg-[#070d1a] border border-[#1e2e4a] rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-blue-600 via-indigo-500 to-green-500 transition-all duration-500 ease-out"
            style={{ width: `${getProgressPercent()}%` }}
          />
        </div>
      </div>

      {/* Animated Pipeline Stage Flow Map */}
      <div className="mt-6 pt-5 border-t border-[#1a2740] overflow-x-auto">
        <div className="flex items-center min-w-[700px] justify-between text-[11px] font-mono font-bold tracking-wider">
          {PIPELINE_STEPS.map((step, idx) => {
            const isActive = idx === currentPhaseIndex;
            const isDone = idx < currentPhaseIndex || status === 'success';
            
            return (
              <React.Fragment key={step.name}>
                <div className={`flex flex-col items-center transition-colors duration-300 ${
                  isActive ? 'text-blue-400' : isDone ? 'text-green-500' : 'text-slate-600'
                }`}>
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center border-2 mb-1.5 transition-all duration-300 ${
                    isActive
                      ? 'border-blue-500 bg-blue-950/40 text-blue-400 scale-110 shadow-lg shadow-blue-500/20'
                      : isDone
                      ? 'border-green-500 bg-green-950/20 text-green-500'
                      : 'border-slate-800 bg-[#070d1a] text-slate-600'
                  }`}>
                    {isDone ? '✓' : idx + 1}
                  </div>
                  <span className="text-center max-w-[80px] leading-tight select-none">
                    {step.name.split(' ')[0]}
                  </span>
                </div>
                {idx < PIPELINE_STEPS.length - 1 && (
                  <div className={`flex-1 h-0.5 border-t border-dashed mx-2 transition-colors duration-300 ${
                    isDone ? 'border-green-500/40' : 'border-slate-800'
                  }`} />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
}
