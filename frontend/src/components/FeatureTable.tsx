import React, { useState } from 'react';
import type { FeatureSet } from '../types/analysis';
import { ChevronDown, ChevronUp, AlertTriangle, CheckCircle } from 'lucide-react';

interface Props {
  features: FeatureSet;
}

const formatValue = (v: unknown): string => {
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
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

// Group features by category
const CATEGORIES: Record<string, string[]> = {
  'URL Structure': ['url_length', 'domain_length', 'subdomain_depth', 'path_depth', 'dot_count', 'hyphen_count'],
  'Content Analysis': ['digit_ratio', 'uppercase_ratio', 'special_char_ratio', 'query_length', 'num_query_params', 'keyword_score'],
  'Entropy & Encoding': ['url_entropy', 'domain_entropy'],
  'Security Indicators': ['has_https', 'tld_suspicious', 'has_ip', 'has_at_symbol', 'double_slash_path', 'has_suspicious_port', 'has_homograph', 'brand_in_subdomain'],
  'Redirect Metadata': ['redirect_depth', 'chain_length', 'domain_age_proxy'],
};

export default function FeatureTable({ features }: Props) {
  const [expanded, setExpanded] = useState(false);
  const entries = Object.entries(features);
  const badCount = entries.filter(([k, v]) => isFlagBad(k, v)).length;

  // Build categorised display
  const categorisedRows: { category: string; rows: [string, unknown][] }[] = [];
  const usedKeys = new Set<string>();

  for (const [cat, keys] of Object.entries(CATEGORIES)) {
    const rows = keys
      .filter((k) => features.hasOwnProperty(k))
      .map((k) => [k, (features as any)[k]] as [string, unknown]);
    rows.forEach(([k]) => usedKeys.add(k));
    if (rows.length) categorisedRows.push({ category: cat, rows });
  }

  // Any uncategorised
  const misc = entries.filter(([k]) => !usedKeys.has(k));
  if (misc.length) categorisedRows.push({ category: 'Other', rows: misc });

  const allRows = categorisedRows.flatMap((c) => c.rows);
  const visibleRows = expanded ? allRows : allRows.slice(0, 10);

  // Figure out which categories/rows to show
  let shown = 0;
  const displayCats = categorisedRows
    .map((cat) => {
      if (!expanded && shown >= 10) return null;
      const catRows = cat.rows.filter(() => {
        if (!expanded && shown >= 10) return false;
        shown++;
        return true;
      });
      return catRows.length ? { ...cat, rows: catRows } : null;
    })
    .filter(Boolean) as typeof categorisedRows;

  return (
    <div>
      {/* Summary row */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <span className="text-xs text-gray-500 font-medium">{entries.length} features extracted</span>
        {badCount > 0 ? (
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-600 bg-red-50 border border-red-200 rounded-full px-2.5 py-0.5">
            <AlertTriangle size={11} /> {badCount} suspicious indicator{badCount !== 1 ? 's' : ''}
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-green-700 bg-green-50 border border-green-200 rounded-full px-2.5 py-0.5">
            <CheckCircle size={11} /> No suspicious indicators
          </span>
        )}
      </div>

      {/* Categorised table */}
      <div className="overflow-hidden rounded-xl border border-gray-200">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200">
              <th className="text-left px-4 py-2.5 text-xs font-semibold text-gray-500 uppercase tracking-wider">Feature</th>
              <th className="text-right px-4 py-2.5 text-xs font-semibold text-gray-500 uppercase tracking-wider">Value</th>
              <th className="text-center px-4 py-2.5 text-xs font-semibold text-gray-500 uppercase tracking-wider w-20">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {displayCats.map((cat) => (
              <React.Fragment key={cat.category}>
                {/* Category header */}
                <tr className="bg-gray-50/70">
                  <td colSpan={3} className="px-4 py-1.5 text-xs font-bold text-gray-400 uppercase tracking-widest">
                    {cat.category}
                  </td>
                </tr>
                {cat.rows.map(([key, value]) => {
                  const bad = isFlagBad(key, value);
                  return (
                    <tr
                      key={key}
                      className={`transition-colors ${bad ? 'bg-red-50/60' : 'hover:bg-gray-50'}`}
                    >
                      <td className="px-4 py-2.5 text-gray-700 font-medium text-sm">
                        {LABEL_MAP[key] || key}
                      </td>
                      <td className={`px-4 py-2.5 text-right font-mono text-sm font-semibold ${bad ? 'text-red-600' : 'text-gray-700'}`}>
                        {formatValue(value)}
                      </td>
                      <td className="px-4 py-2.5 text-center">
                        {bad ? (
                          <span className="inline-flex items-center gap-1 text-xs text-red-600 font-semibold">
                            <AlertTriangle size={11} /> Flag
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-green-600">
                            <CheckCircle size={11} /> OK
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {/* Expand button */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="mt-3 w-full flex items-center justify-center gap-2 text-xs text-gray-400 hover:text-gray-700 transition-colors py-2.5 border border-gray-200 rounded-lg hover:bg-gray-50 font-medium"
      >
        {expanded ? (
          <><ChevronUp size={14} /> Show fewer features</>
        ) : (
          <><ChevronDown size={14} /> Show all {entries.length} features</>
        )}
      </button>
    </div>
  );
}
