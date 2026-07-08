import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { Percent, ShieldAlert } from 'lucide-react';
import type { AnalysisSimulationData } from '../../utils/analysisEngine';

interface Props {
  data: AnalysisSimulationData;
  active: boolean;
  done: boolean;
}

export default function EntropySection({ data, active, done }: Props) {
  const getThresholdColor = () => {
    if (data.entropyValue > 4.5) return 'text-red-500 border-red-500/20 bg-red-950/20';
    if (data.entropyValue > 3.5) return 'text-amber-500 border-amber-500/20 bg-amber-950/20';
    return 'text-green-500 border-green-500/20 bg-green-950/20';
  };

  const getPointerRotation = () => {
    // Math mapping: entropy from 0 to 8 translates to -90 to 90 degrees
    const percentage = Math.min(100, (data.entropyValue / 8) * 100);
    return -90 + (percentage / 100) * 180;
  };

  return (
    <div className={`stage-card border border-[#1a2740] bg-[#0c1322] rounded-2xl p-6 ${
      !active && !done ? 'stage-card-locked' : active ? 'stage-card-active' : 'stage-card-done'
    }`}>
      <div className="flex items-center gap-3 mb-5 border-b border-[#1a2740] pb-3">
        <Percent className={`w-5 h-5 ${done ? 'text-green-500' : 'text-blue-500'}`} />
        <h2 className="text-sm font-bold tracking-wider text-white uppercase font-mono">
          SECTION 5: SHANNON ENTROPY ASSESSMENT
        </h2>
        {done && <span className="text-xs bg-green-950 text-green-400 font-bold border border-green-500/20 px-2.5 py-0.5 rounded-full ml-auto">COMPUTED</span>}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
        {/* Gauge & Value Panel */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 flex flex-col items-center justify-center h-64 font-mono text-xs">
          <span className="text-slate-400 font-bold mb-4 uppercase tracking-wider text-[10px]">
            SHANNON ENTROPY METER
          </span>
          
          <div className="relative w-36 h-20 overflow-hidden flex items-end justify-center">
            {/* Gauge Arch */}
            <div className="absolute inset-x-0 bottom-0 h-36 rounded-full border-[10px] border-slate-800" />
            <div className="absolute inset-x-0 bottom-0 h-36 rounded-full border-[10px] border-gradient-to-r from-green-500 via-amber-500 to-red-500 clip-semi" style={{
              clipPath: 'polygon(0% 50%, 100% 50%, 100% 100%, 0% 100%)'
            }} />
            
            {/* Pointer needle */}
            <div 
              className="absolute bottom-0 w-1.5 h-16 bg-blue-500 origin-bottom rounded-full transition-transform duration-1000 ease-out"
              style={{ transform: `rotate(${active || done ? getPointerRotation() : -90}deg)` }}
            />
            {/* Pointer center hub */}
            <div className="absolute bottom-0 w-5 h-5 bg-[#0c1322] border border-[#1e2e4a] rounded-full z-10 -mb-2.5" />
          </div>

          <div className="text-center mt-4">
            <span className="text-2xl font-black font-mono text-white block">
              {active || done ? data.entropyValue : '0.00'}
            </span>
            <span className={`inline-block px-2.5 py-1 mt-2.5 text-[10px] font-black border rounded-full ${getThresholdColor()}`}>
              {data.entropyLevel.toUpperCase()} RISK
            </span>
          </div>
        </div>

        {/* Character Frequency Chart */}
        <div className="bg-[#070d1a] border border-[#1e2e4a] rounded-xl p-5 h-64 font-mono text-[10px] lg:col-span-2">
          <span className="text-slate-400 font-bold mb-4 uppercase tracking-wider block text-[10px]">
            CHARACTER FREQUENCY HISTOGRAM
          </span>
          {active || done ? (
            <div className="w-full h-44">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.charFrequencies.slice(0, 15)}>
                  <XAxis dataKey="char" stroke="#64748b" fontSize={9} />
                  <YAxis stroke="#64748b" fontSize={9} width={15} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0c1322', borderColor: '#1e2e4a', fontSize: '9px' }}
                    labelStyle={{ color: '#3b82f6', fontWeight: 'bold' }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="w-full h-44 flex items-center justify-center text-slate-600">
              Awaiting data...
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 flex items-start gap-3 bg-[#070d1a]/55 border border-[#1a2740] rounded-xl p-4 text-xs font-mono">
        <ShieldAlert size={16} className="text-blue-400 shrink-0 mt-0.5" />
        <div>
          <span className="text-slate-200 font-bold block mb-1">ALGORITHMIC EXPLANATION</span>
          <p className="text-slate-400 leading-relaxed">
            Shannon entropy measures the uncertainty or unpredictability of characters in the URL string. High entropy values (&gt;4.5) indicate complex, randomly-generated, or heavily randomized strings typical of domain generation algorithms (DGA) or credential harvesting forms designed to bypass traditional keyword blocklists.
          </p>
        </div>
      </div>
    </div>
  );
}
