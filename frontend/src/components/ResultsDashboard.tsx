import type { AnalyzeResponse } from '../types/analysis';
import RiskGauge from './RiskGauge';
import ThreatCard from './ThreatCard';
import RedirectChainGraph from './RedirectChainGraph';
import FeatureTable from './FeatureTable';
import { ExternalLink, Link2, ArrowRight, RefreshCw } from 'lucide-react';

interface Props {
  data: AnalyzeResponse;
  onReset: () => void;
}

export default function ResultsDashboard({ data, onReset }: Props) {
  return (
    <div className="w-full max-w-5xl mx-auto space-y-6 animate-fade-in">
      {/* URL summary bar */}
      <div className="flex items-center gap-3 bg-slate-900/60 border border-slate-700/60 rounded-2xl px-5 py-4 backdrop-blur-sm">
        <div className="flex-1 min-w-0">
          <p className="text-xs text-slate-500 mb-1">Analyzed URL</p>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-slate-300 font-mono text-sm truncate max-w-md">
              {data.original_url}
            </span>
            {data.is_shortened && data.expanded_url !== data.original_url && (
              <>
                <ArrowRight size={14} className="text-slate-600 shrink-0" />
                <span className="text-indigo-300 font-mono text-sm truncate max-w-md">
                  {data.expanded_url}
                </span>
                {data.shortener_domain && (
                  <span className="text-xs bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 px-2 py-0.5 rounded-full">
                    via {data.shortener_domain}
                  </span>
                )}
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <a
            href={data.expanded_url}
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 text-slate-500 hover:text-slate-300 transition-colors"
          >
            <ExternalLink size={16} />
          </a>
          <button
            onClick={onReset}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg px-3 py-2 transition-all"
          >
            <RefreshCw size={13} />
            New Scan
          </button>
        </div>
      </div>

      {/* Main grid: Risk gauge + Threat card */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Risk Gauge */}
        <div className="bg-slate-900/60 border border-slate-700/60 rounded-2xl p-6 backdrop-blur-sm">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wide mb-4">
            Risk Score
          </h2>
          <RiskGauge riskScore={data.risk_score} />
        </div>

        {/* Threat card */}
        <div>
          <ThreatCard prediction={data.prediction} analysisTimeMs={data.analysis_time_ms} />

          {/* Quick stats */}
          <div className="mt-4 grid grid-cols-3 gap-3">
            {[
              { label: 'Hops', value: data.redirect_count },
              { label: 'Shortened', value: data.is_shortened ? 'Yes' : 'No' },
              { label: 'Loop', value: data.loop_detected ? '⚠️ Yes' : 'No' },
            ].map(({ label, value }) => (
              <div
                key={label}
                className="bg-slate-800/60 border border-slate-700/60 rounded-xl p-3 text-center"
              >
                <div className="text-lg font-bold text-white">{value}</div>
                <div className="text-xs text-slate-500 mt-0.5">{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Redirect chain */}
      <div className="bg-slate-900/60 border border-slate-700/60 rounded-2xl p-6 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-5">
          <Link2 size={16} className="text-indigo-400" />
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">
            Redirect Chain
          </h2>
          <span className="ml-auto text-xs text-slate-500">
            {data.redirect_count} redirect{data.redirect_count !== 1 ? 's' : ''}
          </span>
        </div>
        <RedirectChainGraph
          chain={data.redirect_chain}
          loopDetected={data.loop_detected}
          originalUrl={data.original_url}
        />
      </div>

      {/* Feature table */}
      <div className="bg-slate-900/60 border border-slate-700/60 rounded-2xl p-6 backdrop-blur-sm">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wide mb-4">
          Extracted Features
          <span className="ml-2 text-xs font-normal text-slate-600 normal-case">
            (25 features · suspicious values highlighted)
          </span>
        </h2>
        <FeatureTable features={data.features} />
      </div>

      {/* Errors */}
      {data.errors && data.errors.length > 0 && (
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-2xl p-4">
          <p className="text-xs font-semibold text-amber-400 mb-2 uppercase tracking-wide">
            Non-fatal warnings
          </p>
          <ul className="space-y-1">
            {data.errors.map((e, i) => (
              <li key={i} className="text-xs text-amber-300/70 font-mono">{e}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
