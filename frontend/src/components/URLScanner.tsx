import React, { useState } from 'react';
import { Search, Link2, Shield, Zap, AlertTriangle, Clipboard, ChevronRight } from 'lucide-react';
import type { AnalysisState } from '../types/analysis';
import { useNavigate } from 'react-router-dom';

interface Props {
  onResult: (state: AnalysisState) => void;
  analysisState: AnalysisState;
}

const SAMPLE_URLS = [
  { url: 'https://github.com', label: 'Safe — GitHub', type: 'safe' },
  { url: 'http://paypal-secure-login.xyz/verify', label: 'Phishing', type: 'danger' },
  { url: 'https://bit.ly/3xAbCdE', label: 'Shortened', type: 'warning' },
  { url: 'http://192.168.1.100/admin', label: 'IP-based', type: 'warning' },
];

export default function URLScanner({ onResult, analysisState }: Props) {
  const [url, setUrl] = useState('');
  const navigate = useNavigate();
  const isLoading = false;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    navigate(`/analysis?url=${encodeURIComponent(url.trim())}`);
  };



  const pasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setUrl(text.trim());
    } catch { /* silently ignore */ }
  };

  const sampleTypeClasses = {
    safe: 'border-green-200 bg-green-50 text-green-700 hover:bg-green-100 hover:border-green-300',
    danger: 'border-red-200 bg-red-50 text-red-700 hover:bg-red-100 hover:border-red-300',
    warning: 'border-amber-200 bg-amber-50 text-amber-700 hover:bg-amber-100 hover:border-amber-300',
  };

  return (
    <div className="w-full max-w-2xl mx-auto" id="hero">
      {/* Scanner card — white elevated card on dark hero bg */}
      <div className="bg-white rounded-2xl shadow-2xl border border-gray-100 overflow-hidden">
        {/* Card header bar */}
        <div className="bg-gray-50 border-b border-gray-100 px-5 py-3 flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-400" />
            <span className="w-3 h-3 rounded-full bg-amber-400" />
            <span className="w-3 h-3 rounded-full bg-green-400" />
          </div>
          <span className="text-xs font-mono text-gray-400 ml-2 flex-1 text-center">
            URL Threat Intelligence Scanner
          </span>
          <span className="flex items-center gap-1 text-xs text-green-600 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 status-live inline-block" />
            LIVE
          </span>
        </div>

        <div className="p-6">
          <form onSubmit={handleSubmit} className="space-y-3">
            {/* URL input */}
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Link2
                  size={16}
                  className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none"
                />
                <input
                  id="url-input"
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://suspicious-domain.xyz/verify-account"
                  disabled={isLoading}
                  className="w-full bg-gray-50 border border-gray-200 rounded-xl pl-10 pr-4 py-3.5 text-gray-900 placeholder-gray-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all text-sm font-mono disabled:opacity-60 disabled:cursor-not-allowed"
                />
              </div>
              <button
                type="button"
                onClick={pasteFromClipboard}
                disabled={isLoading}
                title="Paste from clipboard"
                className="px-3.5 py-3.5 bg-gray-50 border border-gray-200 rounded-xl text-gray-500 hover:text-gray-800 hover:bg-gray-100 hover:border-gray-300 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                id="paste-btn"
              >
                <Clipboard size={16} />
              </button>
            </div>

            {/* Scan button */}
            <button
              id="analyze-btn"
              type="submit"
              disabled={isLoading || !url.trim()}
              className="w-full py-3.5 rounded-xl font-semibold text-sm transition-all duration-200 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white shadow-md hover:shadow-lg"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin flex-shrink-0" />
                  <span className="truncate">{STEPS[stepIdx].icon} {STEPS[stepIdx].text}</span>
                </>
              ) : (
                <>
                  <Search size={16} />
                  Analyze URL
                  <ChevronRight size={14} className="ml-auto" />
                </>
              )}
            </button>
          </form>

          {/* Sample URLs */}
          <div className="mt-5 pt-4 border-t border-gray-100">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
              Try a sample URL
            </p>
            <div className="flex flex-wrap gap-2">
              {SAMPLE_URLS.map((s) => (
                <button
                  key={s.url}
                  onClick={() => setUrl(s.url)}
                  disabled={isLoading}
                  className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition-all disabled:opacity-50 ${sampleTypeClasses[s.type as keyof typeof sampleTypeClasses]}`}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          {/* Feature pills */}
          <div className="mt-4 pt-4 border-t border-gray-100 flex flex-wrap gap-2">
            {[
              { icon: <Shield size={12} />, label: 'Neural Network' },
              { icon: <Zap size={12} />, label: 'BFS/DFS Analysis' },
              { icon: <AlertTriangle size={12} />, label: 'Redirect Tracing' },
              { icon: <Search size={12} />, label: 'Pattern Matching' },
            ].map(({ icon, label }) => (
              <span
                key={label}
                className="inline-flex items-center gap-1.5 text-xs text-gray-500 bg-gray-50 border border-gray-200 rounded-full px-3 py-1"
              >
                {icon} {label}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Trust indicators below card */}
      <div className="mt-4 flex items-center justify-center gap-6 text-xs text-white/60">
        <span className="flex items-center gap-1.5">
          <Shield size={12} className="text-green-400" />
          Privacy Safe — URLs not stored
        </span>
        <span className="flex items-center gap-1.5">
          <Zap size={12} className="text-blue-400" />
          Avg. response &lt; 2s
        </span>
      </div>
    </div>
  );
}
