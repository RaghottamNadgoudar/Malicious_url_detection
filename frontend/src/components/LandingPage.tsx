import type { AnalysisState } from '../types/analysis';
import URLScanner from './URLScanner';
import FeaturesSection from './FeaturesSection';
import MethodologySection from './MethodologySection';
import StatsSection from './StatsSection';
import { Shield, ChevronDown, Lock, Cpu, GitBranch } from 'lucide-react';

interface Props {
  onResult: (state: AnalysisState) => void;
  analysisState: AnalysisState;
}

export default function LandingPage({ onResult, analysisState }: Props) {
  return (
    <div className="min-h-screen bg-white">
      {/* ─── HERO ───────────────────────────────────────────────── */}
      <section
        id="hero"
        className="relative min-h-screen flex flex-col justify-center overflow-hidden bg-[#060d1f]"
        style={{
          backgroundImage: `url('/images/cyber-hero.png')`,
          backgroundSize: 'cover',
          backgroundPosition: 'center top',
          backgroundBlendMode: 'luminosity',
        }}
      >
        {/* Dark overlay gradient */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#060d1f]/85 via-[#060d1f]/70 to-[#060d1f]" />

        {/* Grid pattern */}
        <div className="absolute inset-0 bg-grid-dark opacity-40" />

        {/* Accent glow spots */}
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-1/3 right-1/4 w-80 h-80 bg-indigo-600/8 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-16">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            {/* Left: headline + badges */}
            <div className="animate-fade-up">
              {/* Badge row */}
              <div className="flex flex-wrap gap-2 mb-6">
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-300 bg-blue-900/40 border border-blue-700/50 rounded-full px-3 py-1">
                  <Cpu size={12} /> AI + DAA Hybrid Engine
                </span>
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-green-300 bg-green-900/30 border border-green-700/40 rounded-full px-3 py-1">
                  <span className="w-1.5 h-1.5 bg-green-400 rounded-full status-live" />
                  Live System
                </span>
              </div>

              {/* Main heading */}
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black leading-tight mb-6">
                <span className="text-gradient-hero">Hybrid URL</span>
                <br />
                <span className="text-white">Detection System</span>
              </h1>

              {/* Subheading */}
              <p className="text-lg text-slate-300 max-w-xl mb-8 leading-relaxed">
                Enterprise-grade phishing URL detection powered by Neural Networks
                + 8 classical Design & Analysis of Algorithms — including BFS/DFS Graph
                Traversal, Boyer-Moore Pattern Matching, Shannon Entropy, and Dijkstra
                Threat Path Analysis.
              </p>

              {/* Tech stack pills */}
              <div className="flex flex-wrap gap-2 mb-8">
                {[
                  { icon: <GitBranch size={12} />, label: 'BFS / DFS' },
                  { icon: <Shield size={12} />, label: 'Neural Network' },
                  { icon: <Lock size={12} />, label: 'Bloom Filter' },
                  { icon: <Cpu size={12} />, label: 'Dijkstra Path' },
                ].map(({ icon, label }) => (
                  <span
                    key={label}
                    className="inline-flex items-center gap-1.5 text-xs text-slate-400 bg-white/5 border border-white/10 rounded-full px-3 py-1.5 font-medium"
                  >
                    {icon} {label}
                  </span>
                ))}
              </div>

              {/* Stats strip */}
              <div className="flex flex-wrap gap-6">
                {[
                  { value: '97.3%', label: 'Accuracy' },
                  { value: '< 2s', label: 'Scan Time' },
                  { value: '9', label: 'Algorithms' },
                ].map(({ value, label }) => (
                  <div key={label}>
                    <div className="text-2xl font-black text-white">{value}</div>
                    <div className="text-xs text-slate-400 font-medium">{label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: URL Scanner card */}
            <div className="animate-fade-up-delay-2">
              {/* Error message above card */}
              {analysisState.status === 'error' && (
                <div className="mb-4 flex items-start gap-3 bg-red-900/40 border border-red-500/40 rounded-xl px-4 py-3 text-red-300 text-sm">
                  <Shield size={16} className="shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold">Analysis Error: </span>
                    {analysisState.message}
                  </div>
                </div>
              )}
              <URLScanner onResult={onResult} analysisState={analysisState} />
            </div>
          </div>

          {/* Scroll indicator */}
          <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-1 text-slate-500 animate-bounce">
            <span className="text-xs font-medium">Scroll to explore</span>
            <ChevronDown size={18} />
          </div>
        </div>
      </section>

      {/* ─── TRUSTED BY strip ──────────────────────────────────── */}
      <div className="bg-white border-y border-gray-100 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-wrap items-center justify-center gap-10 text-gray-300">
            <span className="text-xs font-semibold uppercase tracking-widest text-gray-400">
              Built with technologies trusted by
            </span>
            {['FastAPI', 'React 18', 'TypeScript', 'Python 3.11', 'scikit-learn', 'Tailwind CSS'].map((tech) => (
              <span key={tech} className="text-sm font-semibold text-gray-400 hover:text-gray-600 transition-colors">
                {tech}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ─── FEATURES ──────────────────────────────────────────── */}
      <FeaturesSection />

      {/* ─── METHODOLOGY ───────────────────────────────────────── */}
      <MethodologySection />

      {/* ─── STATS ─────────────────────────────────────────────── */}
      <StatsSection />

      {/* ─── CTA BANNER ────────────────────────────────────────── */}
      <section className="py-20 bg-blue-600">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl sm:text-4xl font-black text-white mb-4">
            Ready to scan a suspicious URL?
          </h2>
          <p className="text-blue-100 text-lg mb-8 max-w-xl mx-auto">
            Paste any URL above to get an instant hybrid threat assessment — free, private, and fast.
          </p>
          <button
            onClick={() => document.getElementById('hero')?.scrollIntoView({ behavior: 'smooth' })}
            className="inline-flex items-center gap-2 bg-white text-blue-600 font-bold px-8 py-4 rounded-xl text-base hover:bg-blue-50 transition-all shadow-lg hover:shadow-xl"
            id="cta-scan-btn"
          >
            <Shield size={18} />
            Start Scanning
          </button>
        </div>
      </section>

      {/* ─── FOOTER ────────────────────────────────────────────── */}
      <footer className="bg-[#060d1f] border-t border-white/5 py-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 bg-blue-600 rounded-lg flex items-center justify-center">
                <Shield size={14} className="text-white" />
              </div>
              <div>
                <span className="text-white font-bold text-sm">Hybrid URL Detection System</span>
                <span className="text-slate-500 text-xs ml-2">v1.0 · Final Year Project · RVCE</span>
              </div>
            </div>
            <div className="flex flex-wrap gap-x-6 gap-y-1 justify-center text-xs text-slate-500">
              <span>FastAPI · React · TypeScript</span>
              <span>scikit-learn · Python</span>
              <span>DAA Algorithms</span>
            </div>
            <p className="text-xs text-slate-600">
              © 2024 · RVCE Department of CSE
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
