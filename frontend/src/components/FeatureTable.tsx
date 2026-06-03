import { useState } from 'react';
import type { FeatureSet } from '../types/analysis';
import { ChevronDown, ChevronUp } from 'lucide-react';

interface Props {
  features: FeatureSet;
}

const formatValue = (v: unknown): string => {
  if (typeof v === 'boolean') return v ? '✓ Yes' : '✗ No';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : v.toFixed(4);
  return String(v);
};

const isFlagBad = (key: string, value: unknown): boolean => {
  const badBools: (keyof FeatureSet)[] = [
    'tld_suspicious', 'has_ip', 'has_at_symbol',
    'double_slash_path', 'has_suspicious_port',
    'brand_in_subdomain', 'has_homograph',
  ];
  if (badBools.includes(key as keyof FeatureSet) && value === true) return true;
  if (key === 'keyword_score' && typeof value === 'number' && value > 0.1) return true;
  if (key === 'url_entropy' && typeof value === 'number' && value > 4.5) return true;
  if (key === 'url_length' && typeof value === 'number' && value > 100) return true;
  return false;
};

const LABEL_MAP: Record<string, string> = {
  url_length: 'URL Length',
  domain_length: 'Domain Length',
  subdomain_depth: 'Subdomain Depth',
  path_depth: 'Path Depth',
  query_length: 'Query String Length',
  num_query_params: 'Query Params Count',
  dot_count: 'Dot Count',
  hyphen_count: 'Hyphen Count',
  digit_ratio: 'Digit Ratio',
  uppercase_ratio: 'Uppercase Ratio',
  special_char_ratio: 'Special Char Ratio',
  url_entropy: 'URL Entropy',
  domain_entropy: 'Domain Entropy',
  has_https: 'Uses HTTPS',
  tld_suspicious: 'Suspicious TLD',
  has_ip: 'IP Address in URL',
  has_at_symbol: '@ Symbol Present',
  double_slash_path: 'Double Slash in Path',
  has_suspicious_port: 'Suspicious Port',
  redirect_depth: 'Redirect Depth',
  keyword_score: 'Phishing Keyword Score',
  brand_in_subdomain: 'Brand in Subdomain',
  has_homograph: 'Typosquatting Detected',
  domain_age_proxy: 'Domain Age Proxy',
  chain_length: 'Redirect Chain Length',
};

export default function FeatureTable({ features }: Props) {
  const [expanded, setExpanded] = useState(false);
  const entries = Object.entries(features);
  const visible = expanded ? entries : entries.slice(0, 10);

  return (
    <div>
      <div className="overflow-hidden rounded-xl border border-slate-700/60">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-800/80">
              <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wide">Feature</th>
              <th className="text-right px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wide">Value</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/40">
            {visible.map(([key, value]) => {
              const bad = isFlagBad(key, value);
              return (
                <tr
                  key={key}
                  className={`transition-colors ${bad ? 'bg-red-500/5' : 'hover:bg-slate-800/40'}`}
                >
                  <td className="px-4 py-2.5 text-slate-300 font-medium">
                    {LABEL_MAP[key] || key}
                  </td>
                  <td className={`px-4 py-2.5 text-right font-mono font-semibold
                    ${bad ? 'text-red-400' : 'text-slate-300'}`}
                  >
                    {formatValue(value)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <button
        onClick={() => setExpanded(!expanded)}
        className="mt-3 w-full flex items-center justify-center gap-2 text-xs text-slate-500 hover:text-slate-300 transition-colors py-2"
      >
        {expanded ? (
          <><ChevronUp size={14} /> Show less</>
        ) : (
          <><ChevronDown size={14} /> Show all {entries.length} features</>
        )}
      </button>
    </div>
  );
}
