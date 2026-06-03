import React, { useState, useRef } from 'react';
import { Search, Link2, Shield, Zap, AlertTriangle } from 'lucide-react';
import type { AnalysisState } from '../types/analysis';
import { analyzeUrl } from '../services/api';

interface Props {
  onResult: (state: AnalysisState) => void;
  analysisState: AnalysisState;
}

const STEPS = [
  '🔗 Expanding URL...',
  '🔍 Tracing redirect chain...',
  '⚙️  Extracting features...',
  '🤖 Running ML analysis...',
  '🎯 Computing risk score...',
];

const SAMPLE_URLS = [
  'https://bit.ly/3example',
  'http://paypal-secure-login.xyz/verify',
  'https://github.com',
  'http://192.168.1.100/admin',
];

export default function URLScanner({ onResult, analysisState }: Props) {
  const [url, setUrl] = useState('');
  const [stepIdx, setStepIdx] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isLoading = analysisState.status === 'loading';

  const startStepCycle = () => {
    let i = 0;
    setStepIdx(0);
    intervalRef.current = setInterval(() => {
      i = (i + 1) % STEPS.length;
      setStepIdx(i);
    }, 900);
  };

  const stopStepCycle = () => {
    if (intervalRef.current) clearInterval(intervalRef.current);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || isLoading) return;

    startStepCycle();
    onResult({ status: 'loading', step: STEPS[0] });

    try {
      const data = await analyzeUrl({ url: url.trim(), follow_redirects: true });
      stopStepCycle();
      onResult({ status: 'success', data });
    } catch (err: any) {
      stopStepCycle();
      const message =
        err?.response?.data?.detail ||
        err?.message ||
        'Analysis failed. Please try again.';
      onResult({ status: 'error', message });
    }
  };

  const pasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setUrl(text.trim());
    } catch {
      // Clipboard access denied — silently ignore
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto">
      {/* Hero heading */}
      <div className="text-center mb-10">
        <div className="inline-flex items-center gap-2 bg-indigo-500/10 border border-indigo-500/30 rounded-full px-4 py-1.5 text-indigo-400 text-sm font-medium mb-6">
          <Zap size={14} />
          ML-Powered · Real-time · Production Grade
        </div>
        <h1 className="text-5xl font-bold bg-gradient-to-r from-white via-indigo-200 to-cyan-300 bg-clip-text text-transparent mb-4 leading-tight">
          URL Security Scanner
        </h1>
        <p className="text-slate-400 text-lg max-w-xl mx-auto">
          Paste any URL — shortened, suspicious, or unknown — and get an instant
          threat assessment powered by machine learning.
        </p>
      </div>

      {/* Scanner card */}
      <div className="relative rounded-2xl bg-slate-900/60 border border-slate-700/60 backdrop-blur-sm p-6 shadow-2xl">
        {/* Animated gradient border */}
        <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-indigo-500/20 via-cyan-500/10 to-purple-500/20 blur-sm -z-10" />

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* URL input row */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Link2
                size={18}
                className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none"
              />
              <input
                id="url-input"
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://bit.ly/suspicious-link or paste any URL..."
                disabled={isLoading}
                className="w-full bg-slate-800 border border-slate-600 rounded-xl pl-11 pr-4 py-4 text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-all text-sm disabled:opacity-60"
              />
            </div>
            <button
              type="button"
              onClick={pasteFromClipboard}
              disabled={isLoading}
              className="px-4 py-4 bg-slate-800 border border-slate-600 rounded-xl text-slate-400 hover:text-white hover:border-slate-500 transition-all text-sm font-medium disabled:opacity-50"
              title="Paste from clipboard"
            >
              Paste
            </button>
          </div>

          {/* Analyze button */}
          <button
            id="analyze-btn"
            type="submit"
            disabled={isLoading || !url.trim()}
            className="w-full py-4 rounded-xl font-semibold text-base transition-all duration-200 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed
              bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white shadow-lg shadow-indigo-500/25 hover:shadow-indigo-500/40 hover:scale-[1.01] active:scale-100"
          >
            {isLoading ? (
              <>
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span className="animate-pulse">
                  {STEPS[stepIdx]}
                </span>
              </>
            ) : (
              <>
                <Search size={18} />
                Analyze URL
              </>
            )}
          </button>
        </form>

        {/* Quick samples */}
        <div className="mt-5 pt-4 border-t border-slate-700/50">
          <p className="text-xs text-slate-500 mb-3 font-medium uppercase tracking-wide">
            Try a sample URL
          </p>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_URLS.map((s) => (
              <button
                key={s}
                onClick={() => setUrl(s)}
                disabled={isLoading}
                className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white hover:border-slate-500 transition-all font-mono disabled:opacity-50"
              >
                {s.length > 35 ? s.slice(0, 35) + '…' : s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Feature pills */}
      <div className="flex flex-wrap justify-center gap-3 mt-8">
        {[
          { icon: <Shield size={14} />, label: 'Phishing Detection' },
          { icon: <Link2 size={14} />, label: 'URL Expansion' },
          { icon: <AlertTriangle size={14} />, label: 'Redirect Tracing' },
          { icon: <Zap size={14} />, label: 'ML Risk Score' },
        ].map(({ icon, label }) => (
          <span
            key={label}
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 bg-slate-800/60 border border-slate-700/60 rounded-full px-3 py-1.5"
          >
            {icon} {label}
          </span>
        ))}
      </div>
    </div>
  );
}
