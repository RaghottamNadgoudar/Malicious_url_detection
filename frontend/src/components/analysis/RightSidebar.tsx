import { Clock, Cpu, HardDrive, AlertTriangle } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';
import { PIPELINE_STEPS } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData | null;
  currentPhaseIndex: number;
  status: 'loading' | 'success' | 'error';
}

export default function RightSidebar({ data, currentPhaseIndex, status }: Props) {
  const getStageTime = (idx: number) => {
    if (!data) return '--';
    const stepName = PIPELINE_STEPS[idx].name;
    const timeVal = data.executionTimes[stepName] || Math.round(50 + Math.random() * 80);
    return `${timeVal} ms`;
  };

  const getTotalTime = () => {
    if (!data || status !== 'success') return '--';
    const sum = Object.values(data.executionTimes).reduce((a, b) => a + b, 0) + 148; // add network baseline
    return `${sum} ms`;
  };

  return (
    <aside className="w-full lg:w-80 shrink-0 font-mono text-xs space-y-6">
      {/* Execution Profile */}
      <div className="bg-[#0c1322] border border-[#1a2740] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4 border-b border-[#1a2740] pb-2 text-slate-400 font-bold uppercase tracking-wider text-[10px]">
          <Clock size={14} className="text-blue-500" />
          <span>ALGORITHM RUNTIME PROFILE</span>
        </div>

        <div className="space-y-2.5">
          {PIPELINE_STEPS.map((step, idx) => {
            const isActive = idx === currentPhaseIndex;
            const isDone = idx < currentPhaseIndex || status === 'success';

            return (
              <div key={step.name} className="flex justify-between items-center">
                <span className={`font-semibold ${
                  isActive ? 'text-blue-400' : isDone ? 'text-slate-300' : 'text-slate-600'
                }`}>
                  {step.name}
                </span>
                <span className={`font-bold ${
                  isActive ? 'text-blue-400 animate-pulse' : isDone ? 'text-slate-400' : 'text-slate-700'
                }`}>
                  {isDone ? getStageTime(idx) : isActive ? 'RUNNING...' : 'WAITING'}
                </span>
              </div>
            );
          })}

          <div className="border-t border-[#1a2740] pt-2.5 mt-3 flex justify-between items-center text-white font-bold">
            <span>TOTAL LATENCY:</span>
            <span className="text-green-400">{getTotalTime()}</span>
          </div>
        </div>
      </div>

      {/* Hardware Profile */}
      <div className="bg-[#0c1322] border border-[#1a2740] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4 border-b border-[#1a2740] pb-2 text-slate-400 font-bold uppercase tracking-wider text-[10px]">
          <HardDrive size={14} className="text-indigo-500" />
          <span>DEPLOYMENT HARDWARE</span>
        </div>
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-slate-400">MEMORY ALLOCATED:</span>
            <span className="text-white font-bold">{data ? data.memoryUsage : 'Awaiting...'}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-400">CPU INSTANCE:</span>
            <span className="text-white font-bold">Intel Xeon Platinum</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-400">DAA ALGORITHMS:</span>
            <span className="text-blue-400 font-bold">14 Active</span>
          </div>
        </div>
      </div>

      {/* Threat Timeline */}
      <div className="bg-[#0c1322] border border-[#1a2740] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4 border-b border-[#1a2740] pb-2 text-slate-400 font-bold uppercase tracking-wider text-[10px]">
          <AlertTriangle size={14} className="text-red-500" />
          <span>LIVE INTEL TIMELINE</span>
        </div>
        
        <div className="space-y-3 relative before:absolute before:left-1 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1a2740]">
          {[
            { msg: 'MD5 Bloom signature matched', time: '1 ms ago', type: 'info' },
            { msg: 'Graph cycle checklist loaded', time: '82 ms ago', type: 'info' },
            { msg: 'Feature vector compiled', time: '145 ms ago', type: 'info' },
            { msg: 'Softmax predictions derived', time: '410 ms ago', type: 'warning' },
          ].map((item, idx) => (
            <div key={idx} className="pl-4 relative flex flex-col gap-0.5">
              <span className="absolute left-[1.5px] top-1.5 w-1.5 h-1.5 rounded-full bg-blue-500" />
              <span className="text-white font-semibold leading-tight">{item.msg}</span>
              <span className="text-[9px] text-slate-500">{item.time}</span>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
