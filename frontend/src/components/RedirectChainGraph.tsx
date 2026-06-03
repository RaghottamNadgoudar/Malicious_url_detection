import type { RedirectHop } from '../types/analysis';
import { AlertTriangle, CheckCircle, ArrowDown, ExternalLink } from 'lucide-react';

interface Props {
  chain: RedirectHop[];
  loopDetected: boolean;
  originalUrl: string;
}

export default function RedirectChainGraph({ chain, loopDetected, originalUrl }: Props) {
  if (chain.length === 0) {
    return (
      <div className="text-center text-slate-500 py-8 text-sm">
        No redirect chain data available.
      </div>
    );
  }

  return (
    <div className="space-y-0">
      {loopDetected && (
        <div className="mb-4 flex items-center gap-2 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 text-red-400 text-sm">
          <AlertTriangle size={16} />
          <span className="font-medium">Redirect loop detected!</span>
        </div>
      )}

      {chain.map((hop, idx) => {
        const isLast = idx === chain.length - 1;
        const isSuspicious = hop.is_suspicious;

        return (
          <div key={idx} className="flex flex-col items-start">
            {/* Hop node */}
            <div
              className={`w-full flex items-start gap-3 rounded-xl px-4 py-3 border transition-all
                ${isSuspicious
                  ? 'bg-red-500/10 border-red-500/30'
                  : isLast
                  ? 'bg-green-500/10 border-green-500/30'
                  : 'bg-slate-800/60 border-slate-700/60'
                }`}
            >
              {/* Hop index */}
              <div className={`shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold
                ${isSuspicious
                  ? 'bg-red-500/20 text-red-400'
                  : isLast
                  ? 'bg-green-500/20 text-green-400'
                  : 'bg-slate-700 text-slate-400'
                }`}
              >
                {hop.hop}
              </div>

              {/* URL */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-sm font-mono break-all
                    ${isSuspicious ? 'text-red-300' : isLast ? 'text-green-300' : 'text-slate-300'}`}
                  >
                    {hop.url}
                  </span>
                  <a
                    href={hop.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-slate-600 hover:text-slate-400 transition-colors shrink-0"
                  >
                    <ExternalLink size={12} />
                  </a>
                </div>
                <div className="flex items-center gap-3 mt-1">
                  {hop.status_code && (
                    <span className="text-xs text-slate-500">
                      HTTP {hop.status_code}
                    </span>
                  )}
                  {isSuspicious && (
                    <span className="inline-flex items-center gap-1 text-xs text-red-400 font-medium">
                      <AlertTriangle size={10} /> Suspicious hop
                    </span>
                  )}
                  {isLast && !isSuspicious && (
                    <span className="inline-flex items-center gap-1 text-xs text-green-400 font-medium">
                      <CheckCircle size={10} /> Final destination
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Connector arrow */}
            {!isLast && (
              <div className="ml-[22px] flex items-center py-0.5">
                <div className="w-px h-4 bg-slate-700" />
                <ArrowDown size={12} className="text-slate-600 -ml-[5px]" />
              </div>
            )}
          </div>
        );
      })}

      {chain.length === 1 && (
        <p className="text-xs text-slate-500 mt-3 text-center">
          No redirects — URL goes directly to destination.
        </p>
      )}
    </div>
  );
}
