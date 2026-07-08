import { ShieldAlert, Award, FileText, CheckCircle } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function FinalReportSection({ data, active, done }: Props) {
  const getVerdictStyle = () => {
    if (data.verdict === 'Malicious') return 'text-red-500 border-red-500/25 bg-red-950/20';
    if (data.verdict === 'Suspicious') return 'text-amber-500 border-amber-500/25 bg-amber-950/20';
    return 'text-green-500 border-green-500/25 bg-green-950/20';
  };

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <FileText className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 11: PIPELINE CYBERSECURITY THREAT REPORT
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">GENERATED</span>}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* Core Verdict Card */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 flex flex-col justify-between items-center text-center">
          <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider mb-2">OVERALL VERDICT</span>
          <div className={`px-4 py-2 rounded-xl text-lg font-black border ${getVerdictStyle()} animate-pulse`}>
            {data.verdict.toUpperCase()}
          </div>
          <div className="mt-4 space-y-1.5 w-full">
            <div className="flex justify-between text-[10px]">
              <span className="text-slate-500">THREAT RISK:</span>
              <span className="text-white font-bold">{data.threatScore}%</span>
            </div>
            <div className="flex justify-between text-[10px]">
              <span className="text-slate-500">MODEL CONFIDENCE:</span>
              <span className="text-white font-bold">{data.confidence}%</span>
            </div>
          </div>
        </div>

        {/* Technical Metrics Summary */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 space-y-3 lg:col-span-2">
          <span className="text-slate-500 text-[10px] uppercase font-bold tracking-wider block border-b border-[#1a2740] pb-1.5 mb-2">
            TECHNICAL RUNTIME PROFILE METRICS
          </span>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <div>
              <span className="text-slate-500 block mb-0.5 text-[10px]">REDIRECT HOPS</span>
              <span className="text-white font-bold text-sm">{data.redirectCount} Hops</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5 text-[10px]">SHANNONS ENTROPY</span>
              <span className="text-white font-bold text-sm">{data.entropyValue}</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5 text-[10px]">PATTERN MATCHES</span>
              <span className="text-white font-bold text-sm">{data.phishingKeywords.length} Found</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5 text-[10px]">ALGORITHMS RUN</span>
              <span className="text-blue-400 font-bold text-sm">14 Engines</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5 text-[10px]">TOTAL SCAN TIMER</span>
              <span className="text-green-400 font-bold text-sm">736 ms</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5 text-[10px]">MEMORY DEPLOYED</span>
              <span className="text-indigo-400 font-bold text-sm">{data.memoryUsage}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Suggested Action Box */}
      <div className={`mt-5 p-4 rounded-xl border flex items-start gap-3 ${
        data.verdict === 'Malicious'
          ? 'bg-red-950/15 border-red-500/25 text-red-400'
          : data.verdict === 'Suspicious'
          ? 'bg-amber-950/15 border-amber-500/25 text-amber-400'
          : 'bg-green-950/15 border-green-500/25 text-green-400'
      }`}>
        {data.verdict === 'Safe' ? (
          <CheckCircle size={18} className="shrink-0 mt-0.5" />
        ) : (
          <ShieldAlert size={18} className="shrink-0 mt-0.5" />
        )}
        <div className="font-mono text-xs">
          <span className="font-bold block mb-1 text-[10px] uppercase">SUGGESTED ACTION PROTOCOL</span>
          <p className="leading-relaxed font-semibold">{data.suggestedAction}</p>
        </div>
      </div>
    </div>
  );
}
