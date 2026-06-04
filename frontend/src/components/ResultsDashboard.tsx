import type { AnalyzeResponse } from '../types/analysis';
import RiskGauge from './RiskGauge';
import ThreatCard from './ThreatCard';
import RedirectChainGraph from './RedirectChainGraph';
import FeatureTable from './FeatureTable';
import { ExternalLink, Link2, ArrowRight, RefreshCw, Shield, AlertTriangle } from 'lucide-react';

interface Props {
  data: AnalyzeResponse;
  onReset: () => void;
}

export default function ResultsDashboard({ data, onReset }: Props) {
  const isMalicious = data.prediction.label === 'Malicious';
  const isSuspicious = data.prediction.label === 'Suspicious';

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Results header bar */}
      <div className={`border-b py-3 ${
        isMalicious
          ? 'bg-red-600'
          : isSuspicious
          ? 'bg-amber-500'
          : 'bg-green-600'
      }`}>
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
          <div className="flex items-center gap-2.5 text-white">
            <Shield size={18} />
            <span className="font-bold text-sm">
              Analysis Complete — {data.prediction.label === 'Safe' ? '✓ URL Appears Safe' : data.prediction.label === 'Malicious' ? '⚠ Malicious URL Detected' : '⚠ Suspicious URL'}
            </span>
          </div>
          <button
            onClick={onReset}
            className="flex items-center gap-1.5 bg-white/20 hover:bg-white/30 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-all"
            id="new-scan-btn"
          >
            <RefreshCw size={13} />
            New Scan
          </button>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 animate-fade-in">
        {/* ── URL Summary card ── */}
        <div className="bg-white rounded-xl border border-gray-150 shadow-sm px-5 py-4">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Analyzed URL</p>
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-sm text-gray-700 break-all">{data.original_url}</span>
            {data.is_shortened && data.expanded_url !== data.original_url && (
              <>
                <ArrowRight size={14} className="text-gray-300 shrink-0" />
                <span className="font-mono text-sm text-blue-600 break-all">{data.expanded_url}</span>
                {data.shortener_domain && (
                  <span className="text-xs bg-blue-50 border border-blue-100 text-blue-600 px-2 py-0.5 rounded-full font-medium shrink-0">
                    via {data.shortener_domain}
                  </span>
                )}
              </>
            )}
            <a
              href={data.expanded_url}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-auto text-gray-400 hover:text-gray-600 transition-colors shrink-0"
              title="Open URL (proceed with caution)"
            >
              <ExternalLink size={15} />
            </a>
          </div>
        </div>

        {/* ── Main grid: Risk gauge + Threat card ── */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Risk Gauge */}
          <div className="bg-white rounded-xl border border-gray-150 shadow-sm p-6">
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-5">
              Risk Score
            </h2>
            <RiskGauge riskScore={data.risk_score} />
          </div>

          {/* Threat card + quick stats */}
          <div className="space-y-4">
            <ThreatCard prediction={data.prediction} analysisTimeMs={data.analysis_time_ms} />

            {/* Quick stats */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Redirect Hops', value: String(data.redirect_count) },
                { label: 'Shortened', value: data.is_shortened ? 'Yes' : 'No' },
                { label: 'Loop', value: data.loop_detected ? '⚠ Yes' : 'No' },
              ].map(({ label, value }) => (
                <div
                  key={label}
                  className="bg-white rounded-xl border border-gray-150 shadow-sm p-4 text-center"
                >
                  <div className={`text-lg font-black ${
                    (label === 'Loop' && data.loop_detected) || (label === 'Shortened' && data.is_shortened)
                      ? 'text-amber-600' : 'text-gray-900'
                  }`}>
                    {value}
                  </div>
                  <div className="text-xs text-gray-400 mt-0.5 font-medium">{label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Redirect chain ── */}
        <div className="bg-white rounded-xl border border-gray-150 shadow-sm p-6">
          <div className="flex items-center gap-2 mb-5">
            <Link2 size={16} className="text-blue-500" />
            <h2 className="text-xs font-semibold text-gray-700 uppercase tracking-wider">
              Redirect Chain
            </h2>
            <span className="ml-auto text-xs font-medium text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full">
              {data.redirect_count} hop{data.redirect_count !== 1 ? 's' : ''}
            </span>
          </div>
          <RedirectChainGraph
            chain={data.redirect_chain}
            loopDetected={data.loop_detected}
            originalUrl={data.original_url}
          />
        </div>

        {/* ── Feature table ── */}
        <div className="bg-white rounded-xl border border-gray-150 shadow-sm p-6">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-xs font-semibold text-gray-700 uppercase tracking-wider">
              Extracted Features
            </h2>
            <span className="text-xs text-gray-400 bg-gray-50 border border-gray-200 px-2.5 py-0.5 rounded-full">
              25 features · suspicious values highlighted
            </span>
          </div>
          <FeatureTable features={data.features} />
        </div>

        {/* ── Warnings ── */}
        {data.errors && data.errors.length > 0 && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={16} className="text-amber-600" />
              <p className="text-xs font-bold text-amber-700 uppercase tracking-wide">
                Non-fatal Analysis Warnings
              </p>
            </div>
            <ul className="space-y-1">
              {data.errors.map((e, i) => (
                <li key={i} className="text-xs text-amber-700 font-mono">{e}</li>
              ))}
            </ul>
          </div>
        )}

        {/* ── Scan another ── */}
        <div className="flex justify-center pt-4 pb-8">
          <button
            onClick={onReset}
            id="bottom-new-scan-btn"
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6 py-3 rounded-xl transition-all shadow-md hover:shadow-lg"
          >
            <RefreshCw size={16} />
            Scan Another URL
          </button>
        </div>
      </div>
    </div>
  );
}
