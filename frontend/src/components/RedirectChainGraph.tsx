import type { RedirectHop } from '../types/analysis';
import { AlertTriangle, CheckCircle, ArrowDown, ExternalLink, Info } from 'lucide-react';

interface Props {
  chain: RedirectHop[];
  loopDetected: boolean;
  originalUrl: string;
}

export default function RedirectChainGraph({ chain, loopDetected, originalUrl }: Props) {
  if (chain.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 gap-2 text-gray-400">
        <Info size={20} className="text-gray-300" />
        <span className="text-sm">No redirect chain data available.</span>
      </div>
    );
  }

  return (
    <div className="space-y-0">
      {loopDetected && (
        <div className="mb-4 flex items-center gap-2.5 bg-red-50 border border-red-200 rounded-xl px-4 py-3 text-red-700 text-sm font-medium">
          <AlertTriangle size={16} className="shrink-0" />
          Redirect loop detected — this URL circularly redirects back to itself.
        </div>
      )}

      {chain.map((hop, idx) => {
        const isLast = idx === chain.length - 1;
        const isSuspicious = hop.is_suspicious;

        return (
          <div key={idx} className="flex flex-col items-start">
            {/* Hop node */}
            <div
              className={`w-full flex items-start gap-3 rounded-xl px-4 py-3.5 border transition-colors ${
                isSuspicious
                  ? 'bg-red-50 border-red-200'
                  : isLast
                  ? 'bg-green-50 border-green-200'
                  : 'bg-gray-50 border-gray-200'
              }`}
            >
              {/* Hop badge */}
              <div
                className={`shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${
                  isSuspicious
                    ? 'bg-red-100 text-red-600'
                    : isLast
                    ? 'bg-green-100 text-green-700'
                    : 'bg-gray-200 text-gray-600'
                }`}
              >
                {hop.hop}
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={`text-sm font-mono break-all leading-snug ${
                      isSuspicious ? 'text-red-700' : isLast ? 'text-green-700' : 'text-gray-700'
                    }`}
                  >
                    {hop.url}
                  </span>
                  <a
                    href={hop.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-gray-300 hover:text-gray-500 transition-colors shrink-0"
                    title="Open URL (caution)"
                  >
                    <ExternalLink size={12} />
                  </a>
                </div>

                <div className="flex items-center gap-3 mt-1 flex-wrap">
                  {hop.status_code && (
                    <span
                      className={`text-xs font-mono font-medium px-1.5 py-0.5 rounded ${
                        hop.status_code >= 400
                          ? 'bg-red-100 text-red-600'
                          : hop.status_code >= 300
                          ? 'bg-amber-100 text-amber-600'
                          : 'bg-gray-100 text-gray-500'
                      }`}
                    >
                      HTTP {hop.status_code}
                    </span>
                  )}
                  {isSuspicious && (
                    <span className="inline-flex items-center gap-1 text-xs text-red-600 font-semibold">
                      <AlertTriangle size={10} /> Suspicious hop
                    </span>
                  )}
                  {isLast && !isSuspicious && (
                    <span className="inline-flex items-center gap-1 text-xs text-green-700 font-semibold">
                      <CheckCircle size={10} /> Final destination
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Connector */}
            {!isLast && (
              <div className="ml-[22px] flex flex-col items-center py-0.5">
                <div className="w-px h-3 bg-gray-200" />
                <ArrowDown size={12} className="text-gray-300 -mt-0.5" />
              </div>
            )}
          </div>
        );
      })}

      {chain.length === 1 && (
        <p className="text-xs text-gray-400 mt-3 text-center">
          No redirects — URL points directly to its destination.
        </p>
      )}
    </div>
  );
}
