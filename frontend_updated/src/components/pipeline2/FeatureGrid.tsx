import type { DaaFeatures } from '../../types/daaApi';

interface FeatureGridProps {
  features: DaaFeatures;
}

function BoolBadge({ val }: { val: boolean }) {
  return (
    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold
      ${val ? 'bg-malicious/15 text-malicious border border-malicious/20'
             : 'bg-safe/10 text-safe border border-safe/20'}`}>
      {val ? 'YES' : 'NO'}
    </span>
  );
}

function NumBadge({ val, warn }: { val: number; warn?: boolean }) {
  return (
    <span className={`font-mono text-xs ${warn ? 'text-suspicious' : 'text-white/70'}`}>
      {typeof val === 'number' ? val.toFixed(val % 1 === 0 ? 0 : 4) : val}
    </span>
  );
}

const ROWS = [
  { key: 'url_length',         label: 'URL Length',         render: (f: DaaFeatures) => <NumBadge val={f.url_length} warn={f.url_length > 80} /> },
  { key: 'domain_length',      label: 'Domain Length',      render: (f: DaaFeatures) => <NumBadge val={f.domain_length} /> },
  { key: 'subdomain_depth',    label: 'Subdomain Depth',    render: (f: DaaFeatures) => <NumBadge val={f.subdomain_depth} warn={f.subdomain_depth > 2} /> },
  { key: 'dot_count',          label: 'Dot Count',          render: (f: DaaFeatures) => <NumBadge val={f.dot_count} warn={f.dot_count > 5} /> },
  { key: 'hyphen_count',       label: 'Hyphen Count',       render: (f: DaaFeatures) => <NumBadge val={f.hyphen_count} warn={f.hyphen_count > 4} /> },
  { key: 'url_entropy',        label: 'URL Entropy',        render: (f: DaaFeatures) => <NumBadge val={f.url_entropy} warn={f.url_entropy > 5.0} /> },
  { key: 'keyword_score',      label: 'Keyword Score',      render: (f: DaaFeatures) => <NumBadge val={f.keyword_score} warn={f.keyword_score > 0.05} /> },
  { key: 'tld',                label: 'TLD',                render: (f: DaaFeatures) => <span className="font-mono text-xs text-white/70">.{f.tld}</span> },
  { key: 'registrable_domain', label: 'Registrable Domain', render: (f: DaaFeatures) => <span className="font-mono text-xs text-white/70 truncate max-w-[120px]">{f.registrable_domain}</span> },
  { key: 'has_https',          label: 'HTTPS',              render: (f: DaaFeatures) => <BoolBadge val={f.has_https} /> },
  { key: 'tld_suspicion',      label: 'Suspicious TLD',     render: (f: DaaFeatures) => <BoolBadge val={f.tld_suspicion} /> },
  { key: 'has_ip',             label: 'IP as Host',         render: (f: DaaFeatures) => <BoolBadge val={f.has_ip} /> },
  { key: 'has_at_symbol',      label: '@ Symbol',           render: (f: DaaFeatures) => <BoolBadge val={f.has_at_symbol} /> },
  { key: 'brand_in_subdomain', label: 'Brand in Subdomain', render: (f: DaaFeatures) => <BoolBadge val={f.brand_in_subdomain} /> },
] as const;

export default function FeatureGrid({ features }: FeatureGridProps) {
  const alertCount = [
    features.url_length > 80,
    features.subdomain_depth > 2,
    features.dot_count > 5,
    features.hyphen_count > 4,
    features.url_entropy > 5.0,
    features.keyword_score > 0.05,
    features.tld_suspicion,
    features.has_ip,
    features.has_at_symbol,
    features.brand_in_subdomain,
    !features.has_https,
  ].filter(Boolean).length;

  return (
    <div className="glass border border-white/[0.08] p-5 rounded-2xl animate-slide-up delay-400">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">URL Feature Vector</h3>
        <div className="flex items-center gap-2">
          {alertCount > 0 && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-suspicious/10 border border-suspicious/20 text-suspicious">
              {alertCount} signal{alertCount > 1 ? 's' : ''} triggered
            </span>
          )}
          <span className="text-xs text-white/30 font-mono">{ROWS.length} features</span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-px bg-white/[0.04] rounded-xl overflow-hidden border border-white/[0.05]">
        {ROWS.map(({ key, label, render }, i) => (
          <div key={key} className="flex items-center justify-between px-3 py-2.5 bg-bg-card
                                    hover:bg-white/[0.03] transition-colors animate-fade-in"
               style={{ animationDelay: `${i * 30}ms` }}>
            <span className="text-xs text-white/45">{label}</span>
            {render(features)}
          </div>
        ))}
      </div>
    </div>
  );
}
