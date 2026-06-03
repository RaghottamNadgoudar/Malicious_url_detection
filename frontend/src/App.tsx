import { useState } from 'react';
import type { AnalysisState } from './types/analysis';
import URLScanner from './components/URLScanner';
import ResultsDashboard from './components/ResultsDashboard';
import { Shield, Github } from 'lucide-react';

export default function App() {
  const [state, setState] = useState<AnalysisState>({ status: 'idle' });

  const handleReset = () => setState({ status: 'idle' });

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {/* Ambient background glows */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-[-20%] left-[-10%] w-[500px] h-[500px] bg-indigo-600/10 rounded-full blur-[120px]" />
        <div className="absolute bottom-[-20%] right-[-10%] w-[600px] h-[600px] bg-cyan-600/8 rounded-full blur-[140px]" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[400px] bg-purple-600/5 rounded-full blur-[100px]" />
      </div>

      {/* Nav */}
      <nav className="relative z-10 border-b border-slate-800/60 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 bg-gradient-to-br from-indigo-500 to-cyan-500 rounded-lg flex items-center justify-center shadow-lg shadow-indigo-500/30">
              <Shield size={16} className="text-white" />
            </div>
            <span className="font-bold text-white tracking-tight">
              URLShield
            </span>
            <span className="text-xs text-slate-600 ml-1">v1.0</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-xs text-slate-500 hidden sm:block">
              Powered by ML + Classical Algorithms
            </span>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-500 hover:text-white transition-colors"
            >
              <Github size={18} />
            </a>
          </div>
        </div>
      </nav>

      {/* Main */}
      <main className="relative z-10 px-4 py-12">
        {state.status === 'idle' || state.status === 'loading' || state.status === 'error' ? (
          <div className="flex flex-col items-center gap-8">
            <URLScanner onResult={setState} analysisState={state} />

            {state.status === 'error' && (
              <div className="w-full max-w-3xl bg-red-500/10 border border-red-500/30 rounded-2xl px-6 py-4 text-red-400 text-sm">
                <strong className="font-semibold">Error: </strong>
                {state.message}
              </div>
            )}
          </div>
        ) : (
          <ResultsDashboard data={state.data} onReset={handleReset} />
        )}
      </main>

      {/* Footer */}
      <footer className="relative z-10 mt-16 border-t border-slate-800/40 py-6">
        <div className="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-600">
          <span>© 2024 URLShield · DAA Project · RVCE</span>
          <span>FastAPI · React · TypeScript · Tailwind CSS</span>
        </div>
      </footer>
    </div>
  );
}
