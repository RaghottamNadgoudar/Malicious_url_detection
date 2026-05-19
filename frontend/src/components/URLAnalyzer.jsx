import React, { useState, useEffect, useRef } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Loader, ChevronDown, ChevronUp } from 'lucide-react';
import { analyzeURL } from '../services/api';

/* ─── Pipeline phases ──────────────────────────────── */
const PHASES = [
  { key: 'url_expansion',  label: 'URL Expansion',     desc: 'Resolve shorteners & redirects' },
  { key: 'phase1_graph',   label: 'Graph Traversal',   desc: 'BFS/DFS redirect-chain · O(V+E)' },
  { key: 'phase3_neural',  label: 'Neural Classifier', desc: '25-feature deep network' },
  { key: 'phase4_greedy',  label: 'Greedy Optimizer',  desc: 'Dijkstra path analysis' },
  { key: 'phase5_bloom',   label: 'Bloom Filter',      desc: 'Probabilistic membership' },
  { key: 'phase6_ranking', label: 'Heapsort Ranking',  desc: 'Threat score sorting' },
];

const VERDICT = {
  safe:       { color: '#16a34a', bg: '#f0fdf4', border: '#bbf7d0', Icon: CheckCircle,   text: 'Safe' },
  uncertain:  { color: '#d97706', bg: '#fffbeb', border: '#fde68a', Icon: AlertTriangle, text: 'Uncertain' },
  suspicious: { color: '#d97706', bg: '#fff7ed', border: '#fed7aa', Icon: AlertTriangle, text: 'Suspicious' },
  malicious:  { color: '#dc2626', bg: '#fff1f2', border: '#fecdd3', Icon: XCircle,       text: 'Malicious' },
};

const clamp = (v) => Math.max(0, Math.min(1, v));

/* ─── Phase row accordion ──────────────────────────── */
const PhaseRow = ({ ph, data, idx }) => {
  const [open, setOpen] = useState(false);
  if (!data) return null;

  const summaries = {
    url_expansion:  data.is_shortened ? `Expanded → ${data.final_url} (${data.redirect_count} redirect${data.redirect_count!==1?'s':''})` : 'Direct URL, no expansion needed',
    phase1_graph:   `Entropy ${(data.entropy||0).toFixed(2)} · Redirect depth ${data.redirect_depth??0}`,
    phase3_neural:  `Threat probability ${((data.threat_probability||0)*100).toFixed(1)}% · ${data.verdict}`,
    phase4_greedy:  data.verdict || data.status || 'Analyzed',
    phase5_bloom:   data.bloom_result ? `In blacklist: ${data.bloom_result.in_bloom_filter?'Yes':'No'} · LSH similarity ${((data.bloom_result.lsh_similarity||0)*100).toFixed(0)}%` : 'Checked',
    phase6_ranking: `Threat rank score: ${(data.threat_rank||0).toFixed(4)}`,
  };

  return (
    <div style={{ borderBottom: '1px solid #f3f4f6' }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: '100%', display: 'flex', alignItems: 'center', gap: 12,
        padding: '11px 0', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left',
      }}>
        <span style={{ width: 20, height: 20, borderRadius: '50%', background: '#e5e7eb', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: '#6b7280', flexShrink: 0 }}>
          {idx + 1}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: '#111827' }}>{ph.label}</div>
          <div style={{ fontSize: 11, color: '#9ca3af', marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {summaries[ph.key]}
          </div>
        </div>
        <span style={{ fontSize: 11, color: '#16a34a', fontWeight: 600, flexShrink: 0 }}>✓</span>
        {open ? <ChevronUp size={13} color="#9ca3af" /> : <ChevronDown size={13} color="#9ca3af" />}
      </button>
      {open && (
        <div style={{ paddingBottom: 12, paddingLeft: 32 }}>
          <pre style={{ margin: 0, fontSize: 10, color: '#6b7280', fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', background: '#f9fafb', padding: '8px 10px', borderRadius: 6 }}>
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

/* ─── Feature row ──────────────────────────────────── */
const FeatureRow = ({ label, value, warn }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid #f9fafb' }}>
    <span style={{ fontSize: 12, color: '#6b7280' }}>{label}</span>
    <span style={{ fontSize: 12, fontWeight: 600, color: warn ? '#dc2626' : '#111827' }}>{value}</span>
  </div>
);

/* ─── Main ─────────────────────────────────────────── */
const URLAnalyzer = () => {
  const [url, setUrl]           = useState('');
  const [loading, setLoading]   = useState(false);
  const [phase, setPhase]       = useState(-1);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState(null);
  const timer = useRef(null);

  const runPhases = (onDone) => {
    let i = 0; setPhase(0);
    timer.current = setInterval(() => {
      i++;
      if (i >= PHASES.length) { clearInterval(timer.current); onDone(); }
      else setPhase(i);
    }, 380);
  };

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!url.trim()) { setError('Enter a URL'); return; }
    setLoading(true); setError(null); setResult(null); setPhase(0);
    const api = analyzeURL(url);
    runPhases(() => {});
    try {
      const data = await api;
      clearInterval(timer.current);
      setPhase(PHASES.length - 1);
      setTimeout(() => { setResult(data); setLoading(false); setPhase(-1); }, 250);
    } catch (err) {
      clearInterval(timer.current);
      setError(err.response?.data?.error || 'Analysis failed');
      setLoading(false); setPhase(-1);
    }
  };

  useEffect(() => () => clearInterval(timer.current), []);

  const verdict = result?.final_verdict?.verdict;
  const vm = VERDICT[verdict] || VERDICT.uncertain;
  const VIcon = vm.Icon;

  const neural = result?.phase3_neural || {};
  const fi = neural.feature_names || [];
  const fv = neural.features || [];
  const f = (name) => fv[fi.indexOf(name)] ?? 0;

  const featuresLoaded = fi.length > 0 && fv.length > 0;

  const signals = featuresLoaded ? [
    f('keyword_score') > 0.05   && `Phishing keywords (${(f('keyword_score')*100).toFixed(0)}%)`,
    f('brand_in_subdomain')      && 'Brand name in subdomain',
    f('has_homograph')           && 'Homograph / typosquatting',
    f('has_ip')                  && 'IP address as domain',
    f('tld_suspicion')           && 'Suspicious TLD',
    f('has_at_symbol')           && '@ symbol in URL',
    !f('has_https')              && 'No HTTPS',
  ].filter(Boolean) : [];


  return (
    <div style={{ fontFamily: 'Inter, system-ui, sans-serif', maxWidth: 900, margin: '0 auto' }}>

      {/* Input */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <Shield size={18} color="#2563eb" />
          <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: '#111827' }}>URL Analyzer</h2>
          <span style={{ fontSize: 11, color: '#9ca3af' }}>· 7-phase neural detection pipeline</span>
        </div>
        <form onSubmit={handleAnalyze} style={{ display: 'flex', gap: 8 }}>
          <input
            type="text" value={url} onChange={e => setUrl(e.target.value)}
            placeholder="https://example.com"
            style={{ flex: 1, padding: '9px 13px', borderRadius: 7, fontSize: 13, border: '1.5px solid #d1d5db', outline: 'none', fontFamily: 'monospace', color: '#374151' }}
            onFocus={e => e.target.style.borderColor = '#2563eb'}
            onBlur={e => e.target.style.borderColor = '#d1d5db'}
          />
          <button type="submit" disabled={loading}
            style={{ padding: '9px 18px', borderRadius: 7, background: loading ? '#6b7280' : '#2563eb', color: '#fff', border: 'none', fontSize: 13, fontWeight: 600, cursor: loading ? 'default' : 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
            {loading ? <><Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> Analyzing</> : 'Analyze'}
          </button>
        </form>
        {error && <p style={{ fontSize: 12, color: '#dc2626', marginTop: 8 }}>{error}</p>}
      </div>

      {/* Progress while loading */}
      {loading && (
        <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 10, padding: '16px 18px', marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 10 }}>Running pipeline…</div>
          {PHASES.map((ph, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 0', opacity: i > phase ? 0.35 : 1, transition: 'opacity 0.2s' }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: i < phase ? '#16a34a' : i === phase ? '#2563eb' : '#e5e7eb', transition: 'background 0.3s', flexShrink: 0 }} />
              <span style={{ fontSize: 12, color: i === phase ? '#2563eb' : i < phase ? '#374151' : '#9ca3af', fontWeight: i === phase ? 600 : 400 }}>
                {ph.label}
                {i === phase && <span style={{ marginLeft: 6, fontSize: 10, color: '#9ca3af' }}>running…</span>}
                {i < phase && <span style={{ marginLeft: 6, fontSize: 10, color: '#16a34a' }}>✓</span>}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Results */}
      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr', gap: 14 }}>

          {/* Left column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* Verdict */}
            <div style={{ background: vm.bg, border: `1.5px solid ${vm.border}`, borderRadius: 10, padding: '16px 18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <VIcon size={20} color={vm.color} />
                <span style={{ fontSize: 18, fontWeight: 800, color: vm.color }}>{vm.text}</span>
                <span style={{ marginLeft: 'auto', fontSize: 22, fontWeight: 800, color: vm.color }}>
                  {((result.final_verdict?.threat_probability || 0) * 100).toFixed(1)}%
                </span>
              </div>
              {/* Threat bar */}
              <div style={{ height: 6, borderRadius: 999, background: '#e5e7eb', overflow: 'hidden', marginBottom: 8 }}>
                <div style={{ height: '100%', borderRadius: 999, background: vm.color, width: `${clamp(result.final_verdict?.threat_probability||0)*100}%`, transition: 'width 0.7s ease' }} />
              </div>
              <div style={{ fontSize: 11, color: '#6b7280' }}>{result.final_verdict?.recommendation}</div>
              {result.final_verdict?.warning && (
                <div style={{ fontSize: 11, color: vm.color, marginTop: 6, fontWeight: 600 }}>⚠ {result.final_verdict.warning}</div>
              )}
            </div>

            {/* URL expansion info */}
            {result.url_expansion?.is_shortened && (
              <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 10, padding: '12px 14px' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>URL Shortener</div>
                <div style={{ fontSize: 12, color: '#374151', lineHeight: 1.7 }}>
                  <div><span style={{ color: '#9ca3af' }}>Original:</span> {result.url}</div>
                  <div><span style={{ color: '#9ca3af' }}>Destination:</span> <span style={{ fontFamily: 'monospace' }}>{result.url_expansion.final_url}</span></div>
                  <div><span style={{ color: '#9ca3af' }}>Redirects:</span> {result.url_expansion.redirect_count}</div>
                  {neural.original_prob !== undefined && (
                    <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid #f3f4f6', color: '#6b7280' }}>
                      Blended score: {(neural.original_prob*100).toFixed(0)}% path + {(neural.expanded_prob*100).toFixed(0)}% destination → <b style={{ color: '#374151' }}>{(neural.threat_probability*100).toFixed(0)}%</b>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Threat signals */}
            {signals.length > 0 && (
              <div style={{ background: '#fff', border: '1px solid #fecdd3', borderRadius: 10, padding: '12px 14px' }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#dc2626', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Threat Signals</div>
                {signals.map((s, i) => (
                  <div key={i} style={{ fontSize: 12, color: '#374151', padding: '3px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: '#ef4444', fontSize: 10 }}>●</span> {s}
                  </div>
                ))}
              </div>
            )}

            {/* Pipeline steps */}
            <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 10, padding: '12px 14px' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Pipeline Results</div>
              {PHASES.map((ph, i) => (
                <PhaseRow key={i} ph={ph} data={result[ph.key]} idx={i} />
              ))}
            </div>
          </div>

          {/* Right column — features */}
          <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 10, padding: '14px 16px' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Neural Feature Analysis</div>
            {!featuresLoaded ? (
              <div style={{ fontSize: 12, color: '#9ca3af', padding: '8px 0' }}>Feature vector not available.</div>
            ) : (<>
            <FeatureRow label="URL Length"         value={`${f('url_length').toFixed(0)} chars`}          warn={f('url_length') > 100} />
            <FeatureRow label="URL Entropy"         value={f('url_entropy').toFixed(3)}                   warn={f('url_entropy') > 4} />
            <FeatureRow label="Domain Entropy"      value={f('domain_entropy').toFixed(3)}                warn={f('domain_entropy') > 3.5} />
            <FeatureRow label="Digit Ratio"         value={`${(f('digit_ratio')*100).toFixed(1)}%`}       warn={f('digit_ratio') > 0.3} />
            <FeatureRow label="Special Char Ratio"  value={`${(f('special_char_ratio')*100).toFixed(1)}%`} warn={f('special_char_ratio') > 0.2} />
            <FeatureRow label="Keyword Score"       value={`${(f('keyword_score')*100).toFixed(1)}%`}     warn={f('keyword_score') > 0.05} />
            <FeatureRow label="HTTPS"               value={f('has_https') ? 'Yes' : 'No'}                warn={!f('has_https')} />
            <FeatureRow label="Suspicious TLD"      value={f('tld_suspicion') ? 'Yes' : 'No'}            warn={!!f('tld_suspicion')} />
            <FeatureRow label="IP as Domain"        value={f('has_ip') ? 'Yes' : 'No'}                   warn={!!f('has_ip')} />
            <FeatureRow label="@ Symbol"            value={f('has_at_symbol') ? 'Yes' : 'No'}            warn={!!f('has_at_symbol')} />
            <FeatureRow label="Double Slash Path"   value={f('double_slash_path') ? 'Yes' : 'No'}        warn={!!f('double_slash_path')} />
            <FeatureRow label="Suspicious Port"     value={f('has_suspicious_port') ? 'Yes' : 'No'}     warn={!!f('has_suspicious_port')} />
            <FeatureRow label="Subdomain Depth"     value={f('subdomain_depth').toFixed(0)}              warn={f('subdomain_depth') > 3} />
            <FeatureRow label="Path Depth"          value={f('path_depth').toFixed(0)}                   warn={f('path_depth') > 6} />
            <FeatureRow label="Dot Count"           value={f('dot_count').toFixed(0)}                    warn={f('dot_count') > 5} />
            <FeatureRow label="Hyphen Count"        value={f('hyphen_count').toFixed(0)}                 warn={f('hyphen_count') > 3} />
            <FeatureRow label="Brand Spoofing"      value={f('brand_in_subdomain') ? 'Detected' : 'None'} warn={!!f('brand_in_subdomain')} />
            <FeatureRow label="Homograph"           value={f('has_homograph') ? 'Detected' : 'None'}     warn={!!f('has_homograph')} />
            <FeatureRow label="Redirect Depth"      value={f('redirect_depth').toFixed(0)}               warn={f('redirect_depth') > 2} />
            <FeatureRow label="Chain Length"        value={f('chain_length').toFixed(0)}                 warn={f('chain_length') > 4} />
            </>)}

            {/* Threat probability bar */}
            <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid #f3f4f6' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#6b7280', marginBottom: 5 }}>
                <span>Threat Probability</span>
                <span style={{ fontWeight: 700, color: vm.color }}>{((neural.threat_probability||0)*100).toFixed(1)}%</span>
              </div>
              <div style={{ height: 6, borderRadius: 999, background: '#f3f4f6', overflow: 'hidden' }}>
                <div style={{ height: '100%', borderRadius: 999, background: vm.color, width: `${clamp(neural.threat_probability||0)*100}%`, transition: 'width 0.7s ease' }} />
              </div>
            </div>
          </div>
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
};

export default URLAnalyzer;
