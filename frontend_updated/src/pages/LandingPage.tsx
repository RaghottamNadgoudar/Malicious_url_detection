import { useNavigate } from 'react-router-dom';
import { Layers, Search, Cpu, Zap, Shield, ChevronRight } from 'lucide-react';

const FEATURES = [
  { icon: Cpu,    text: 'DistilBERT fine-tuned on malicious URL corpus' },
  { icon: Layers, text: '6-stage DAA preprocessing (Quicksort, Horspool, Greedy, Backtrack)' },
  { icon: Shield, text: 'Cisco Umbrella threat intelligence (Tier 0)' },
  { icon: Zap,    text: 'Real-time SSE streaming for large batch scans' },
];

export default function LandingPage() {
  const nav = useNavigate();

  return (
    <div className="relative min-h-[calc(100vh-4rem)] grid-bg flex flex-col">
      {/* Hero */}
      <div className="flex-1 flex flex-col items-center justify-center px-6 py-20 text-center animate-fade-in">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-brand/30
                        bg-brand/10 text-brand-light text-xs font-medium mb-8">
          <div className="live-dot" />
          DistilBERT · 4-Tier Pipeline · Port 8002
        </div>

        <h1 className="text-4xl sm:text-6xl font-bold tracking-tight leading-tight mb-6">
          <span className="text-white">Malicious URL</span>
          <br />
          <span className="bg-gradient-to-r from-brand-light to-violet-300 bg-clip-text text-transparent">
            Neural Detection
          </span>
        </h1>

        <p className="max-w-xl text-white/50 text-lg mb-12 leading-relaxed">
          Two analysis modes. One powerful pipeline. Detect phishing, malware,
          and brand-spoofing URLs using a fine-tuned DistilBERT model reinforced
          by six algorithmic preprocessing stages.
        </p>

        {/* Pipeline cards */}
        <div className="grid sm:grid-cols-2 gap-6 w-full max-w-2xl mb-16">
          {/* Pipeline 1 */}
          <button
            onClick={() => nav('/pipeline1')}
            className="glass-hover p-7 text-left group cursor-pointer"
          >
            <div className="w-12 h-12 rounded-xl bg-brand/20 border border-brand/30 flex items-center justify-center mb-4
                            group-hover:bg-brand/30 transition-all">
              <Layers size={22} className="text-brand-light" />
            </div>
            <h2 className="text-lg font-semibold text-white mb-2">Pipeline 1</h2>
            <h3 className="text-base font-medium text-brand-light mb-3">Batch DAA Mode</h3>
            <p className="text-sm text-white/45 leading-relaxed mb-4">
              Upload a .txt file or paste URLs. Watch the 6-stage funnel filter
              your batch before DistilBERT — with live SSE progress streaming.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {['Quicksort','Horspool','Greedy','Backtrack'].map(t => (
                <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded
                                         bg-white/5 border border-white/10 text-white/40">{t}</span>
              ))}
            </div>
            <div className="flex items-center gap-1 text-brand-light text-xs mt-4
                            group-hover:gap-2 transition-all">
              Launch <ChevronRight size={14} />
            </div>
          </button>

          {/* Pipeline 2 */}
          <button
            onClick={() => nav('/pipeline2')}
            className="glass-hover p-7 text-left group cursor-pointer"
          >
            <div className="w-12 h-12 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center mb-4
                            group-hover:bg-violet-500/20 transition-all">
              <Search size={22} className="text-violet-300" />
            </div>
            <h2 className="text-lg font-semibold text-white mb-2">Pipeline 2</h2>
            <h3 className="text-base font-medium text-violet-300 mb-3">Single URL Deep Scan</h3>
            <p className="text-sm text-white/45 leading-relaxed mb-4">
              Trace exactly how one URL is processed through each tier — from
              Umbrella threat intel to DistilBERT inference and hard-signal scoring.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {['T0-Umbrella','T1-Whitelist','T2-DistilBERT','T3-HardSignal'].map(t => (
                <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded
                                         bg-white/5 border border-white/10 text-white/40">{t}</span>
              ))}
            </div>
            <div className="flex items-center gap-1 text-violet-300 text-xs mt-4
                            group-hover:gap-2 transition-all">
              Launch <ChevronRight size={14} />
            </div>
          </button>
        </div>

        {/* Feature strip */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 w-full max-w-4xl">
          {FEATURES.map(({ icon: Icon, text }) => (
            <div key={text} className="glass p-4 text-left text-sm text-white/50 flex items-start gap-3">
              <Icon size={16} className="text-brand-light shrink-0 mt-0.5" />
              <span className="leading-relaxed">{text}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
