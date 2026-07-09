import { useEffect, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  AreaChart, Area, CartesianGrid,
} from 'recharts';
import { BarChart2, Zap, ShieldCheck, ShieldAlert, AlertTriangle, Clock, Activity, RefreshCw } from 'lucide-react';

const API = 'http://localhost:8002';

// ── colour system ──────────────────────────────────────────────────────────────
const C = {
  safe:       '#22c55e',
  malicious:  '#ef4444',
  suspicious: '#f59e0b',
  pending:    '#6366f1',
  brand:      '#7c3aed',
  brandLight: '#a78bfa',
  text:       'rgba(255,255,255,0.7)',
  textDim:    'rgba(255,255,255,0.35)',
  grid:       'rgba(255,255,255,0.06)',
};

type DatasetKey = 'original' | 'optimized';

interface FunnelData {
  input: number; after_dedup: number; after_whitelist: number;
  after_horspool: number; after_greedy: number; to_distilbert: number;
}

interface DatasetStats {
  dataset: string;
  total_urls: number;
  elapsed_ms: number;
  funnel: FunnelData;
  reduction_pct: number;
  pre_classified: number;
  sent_to_distilbert: number;
  verdict_dist: { safe: number; malicious: number; suspicious: number; pending: number };
  stage_dist: Record<string, number>;
  top_safe_tlds: Record<string, number>;
  top_mal_tlds: Record<string, number>;
  len_histogram: Record<string, number>;
  conf_histogram: Record<string, number>;
  keyword_freq: Record<string, number>;
  protocol: { https: number; http: number };
  suspicious_tld_count: number;
}

interface AnalysisData {
  original: DatasetStats;
  optimized: DatasetStats;
}

// ── tiny helpers ────────────────────────────────────────────────────────────────
const Spinner = () => (
  <div className="flex items-center justify-center gap-3 py-24 text-white/40">
    <div className="w-6 h-6 border-2 border-white/10 border-t-brand rounded-full animate-spin" />
    Running DAA funnel analysis on 2 × 1000 URLs…
  </div>
);

const StatCard = ({ icon: Icon, label, value, sub, colour = '#a78bfa' }: {
  icon: any; label: string; value: string | number; sub?: string; colour?: string;
}) => (
  <div className="glass rounded-xl p-4 flex items-start gap-3">
    <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
         style={{ background: `${colour}22`, border: `1px solid ${colour}44` }}>
      <Icon size={16} style={{ color: colour }} />
    </div>
    <div className="min-w-0">
      <div className="text-xs text-white/40 mb-0.5">{label}</div>
      <div className="text-xl font-bold text-white">{value}</div>
      {sub && <div className="text-[11px] text-white/30 mt-0.5">{sub}</div>}
    </div>
  </div>
);

const SectionTitle = ({ children }: { children: React.ReactNode }) => (
  <h2 className="text-sm font-semibold text-white/50 uppercase tracking-widest mb-4">{children}</h2>
);

// ── custom tooltip ───────────────────────────────────────────────────────────────
const DarkTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass rounded-lg px-3 py-2 text-xs text-white/80 shadow-xl">
      <div className="font-medium mb-1">{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.color }}>
          {p.name}: <span className="font-bold">{p.value}</span>
        </div>
      ))}
    </div>
  );
};

// ── main component ────────────────────────────────────────────────────────────────
export default function AnalysisView() {
  const [data, setData]       = useState<AnalysisData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const [active, setActive]   = useState<DatasetKey>('original');

  const load = async (bust = false) => {
    setLoading(true); setError('');
    try {
      if (bust) await fetch(`${API}/analysis/cache`, { method: 'DELETE' });
      const res = await fetch(`${API}/analysis`);
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      setData(await res.json());
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const ds = data?.[active];

  // ── Funnel bar data ─────────────────────────────────────────────────────────
  const funnelData = (d: DatasetStats) => [
    { stage: 'Input',      original: d.funnel.input,           opt: d.funnel.input },
    { stage: 'Dedup',      count: d.funnel.after_dedup },
    { stage: 'Whitelist',  count: d.funnel.after_whitelist },
    { stage: 'Horspool',   count: d.funnel.after_horspool },
    { stage: 'Greedy',     count: d.funnel.after_greedy },
    { stage: '→ DistilBERT', count: d.funnel.to_distilbert },
  ].map((x, i) => ({ ...x, fill: i === 5 ? C.pending : C.brandLight }));

  // ── Comparison funnel data ──────────────────────────────────────────────────
  const compFunnel = data ? [
    { stage: 'Dedup',      original: data.original.funnel.after_dedup, optimized: data.optimized.funnel.after_dedup },
    { stage: 'Whitelist',  original: data.original.funnel.after_whitelist, optimized: data.optimized.funnel.after_whitelist },
    { stage: 'Horspool',   original: data.original.funnel.after_horspool, optimized: data.optimized.funnel.after_horspool },
    { stage: 'Greedy',     original: data.original.funnel.after_greedy, optimized: data.optimized.funnel.after_greedy },
    { stage: '→ DistilBERT', original: data.original.funnel.to_distilbert, optimized: data.optimized.funnel.to_distilbert },
  ] : [];

  // ── Verdict pie data ────────────────────────────────────────────────────────
  const verdictPie = (d: DatasetStats) => [
    { name: 'Safe',       value: d.verdict_dist.safe,       color: C.safe },
    { name: 'Malicious',  value: d.verdict_dist.malicious,  color: C.malicious },
    { name: 'Suspicious', value: d.verdict_dist.suspicious, color: C.suspicious },
    { name: 'Pending→T2', value: d.verdict_dist.pending,    color: C.pending },
  ].filter(x => x.value > 0);

  // ── Keyword bar data ────────────────────────────────────────────────────────
  const kwData = (d: DatasetStats) => Object.entries(d.keyword_freq)
    .map(([k, v]) => ({ kw: k, count: v }))
    .sort((a, b) => b.count - a.count);

  // ── TLD data ─────────────────────────────────────────────────────────────────
  const tldData = (d: DatasetStats) => {
    const merged: Record<string, { tld: string; safe: number; malicious: number }> = {};
    Object.entries(d.top_safe_tlds).forEach(([t, v]) => {
      merged[t] = { tld: t, safe: v, malicious: 0 };
    });
    Object.entries(d.top_mal_tlds).forEach(([t, v]) => {
      if (!merged[t]) merged[t] = { tld: t, safe: 0, malicious: 0 };
      merged[t].malicious = v;
    });
    return Object.values(merged).sort((a, b) => (b.safe + b.malicious) - (a.safe + a.malicious)).slice(0, 12);
  };

  // ── URL length area data ─────────────────────────────────────────────────────
  const lenData = (d: DatasetStats) => Object.entries(d.len_histogram)
    .map(([range, count]) => ({ range, count }));

  // ── Radar comparison data ─────────────────────────────────────────────────────
  const radarData = data ? [
    { metric: 'Pre-class %', original: data.original.reduction_pct, optimized: data.optimized.reduction_pct },
    { metric: 'Safe %',   original: data.original.verdict_dist.safe / 10, optimized: data.optimized.verdict_dist.safe / 10 },
    { metric: 'Mal %',    original: data.original.verdict_dist.malicious / 10, optimized: data.optimized.verdict_dist.malicious / 10 },
    { metric: 'HTTPS %',  original: data.original.protocol.https / 10, optimized: data.optimized.protocol.https / 10 },
    { metric: 'Susp-TLD', original: data.original.suspicious_tld_count / 10, optimized: data.optimized.suspicious_tld_count / 10 },
  ] : [];

  return (
    <div className="min-h-screen px-4 py-8 max-w-7xl mx-auto">

      {/* ── Page header ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-xl bg-brand/20 border border-brand/30 flex items-center justify-center">
              <BarChart2 size={18} className="text-brand-light" />
            </div>
            <h1 className="text-2xl font-bold text-white">Analysis Dashboard</h1>
          </div>
          <p className="text-sm text-white/40 ml-12">
            DAA funnel metrics on two URL datasets of 1000 URLs each · No DistilBERT inference
          </p>
        </div>
        <button
          onClick={() => load(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/[0.06] hover:bg-white/[0.10] text-white/60 hover:text-white text-sm transition-all"
        >
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {loading && <Spinner />}
      {error && (
        <div className="glass rounded-xl p-6 text-malicious text-center">
          {error} — Make sure the backend is running at {API}
        </div>
      )}

      {data && !loading && (
        <>
          {/* ── Dataset selector ─────────────────────────────────────────────── */}
          <div className="flex gap-2 mb-8">
            {(['original', 'optimized'] as DatasetKey[]).map(k => (
              <button
                key={k}
                onClick={() => setActive(k)}
                className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${
                  active === k
                    ? 'bg-brand/20 text-brand-light border border-brand/30'
                    : 'bg-white/[0.04] text-white/40 border border-white/[0.08] hover:bg-white/[0.07]'
                }`}
              >
                {k === 'original' ? '📂 urls_1000.txt' : '✨ urls_1000_optimized.txt'}
              </button>
            ))}
          </div>

          {ds && (
            <>
              {/* ── Stat cards ────────────────────────────────────────────────── */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
                <StatCard icon={Activity} label="Total URLs" value={ds.total_urls.toLocaleString()} sub="in dataset" colour={C.brandLight} />
                <StatCard icon={Zap} label="Pre-classified" value={`${ds.reduction_pct}%`} sub={`${ds.pre_classified} URLs, skipped DistilBERT`} colour={C.safe} />
                <StatCard icon={ShieldAlert} label="→ DistilBERT" value={ds.sent_to_distilbert} sub="uncertain URLs" colour={C.pending} />
                <StatCard icon={Clock} label="Funnel time" value={`${ds.elapsed_ms} ms`} sub="BatchOptimizer only" colour={C.suspicious} />
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-10">
                <StatCard icon={ShieldCheck} label="Safe (pre-class)" value={ds.verdict_dist.safe} colour={C.safe} />
                <StatCard icon={ShieldAlert} label="Malicious (pre-class)" value={ds.verdict_dist.malicious} colour={C.malicious} />
                <StatCard icon={AlertTriangle} label="Suspicious (pre-class)" value={ds.verdict_dist.suspicious} colour={C.suspicious} />
                <StatCard icon={Activity} label="HTTPS URLs" value={`${Math.round(ds.protocol.https / ds.total_urls * 100)}%`} sub={`${ds.protocol.https} / ${ds.total_urls}`} colour={C.brandLight} />
              </div>

              {/* ── Row 1: Verdict Pie + DAA Funnel ────────────────────────────── */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">

                {/* Verdict donut */}
                <div className="glass rounded-2xl p-5">
                  <SectionTitle>Verdict Distribution (Pre-classified)</SectionTitle>
                  <ResponsiveContainer width="100%" height={240}>
                    <PieChart>
                      <Pie data={verdictPie(ds)} cx="50%" cy="50%" innerRadius={65} outerRadius={95}
                           dataKey="value" nameKey="name" paddingAngle={2}>
                        {verdictPie(ds).map((entry, i) => (
                          <Cell key={i} fill={entry.color} stroke="transparent" />
                        ))}
                      </Pie>
                      <Tooltip content={<DarkTooltip />} />
                      <Legend iconType="circle" iconSize={8}
                              formatter={(v) => <span style={{ color: C.text, fontSize: 12 }}>{v}</span>} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                {/* DAA Funnel bar */}
                <div className="glass rounded-2xl p-5">
                  <SectionTitle>DAA Funnel — Remaining URLs per Stage</SectionTitle>
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart data={funnelData(ds)} layout="vertical" margin={{ left: 10 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={C.grid} horizontal={false} />
                      <XAxis type="number" tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis type="category" dataKey="stage" width={90} tick={{ fill: C.text, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip content={<DarkTooltip />} />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                        {funnelData(ds).map((entry, i) => (
                          <Cell key={i} fill={entry.fill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* ── Row 2: TLD chart + keyword freq ─────────────────────────── */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">

                {/* TLD grouped bar */}
                <div className="glass rounded-2xl p-5">
                  <SectionTitle>Top TLDs — Safe vs Malicious</SectionTitle>
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={tldData(ds)} margin={{ left: -10 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={C.grid} vertical={false} />
                      <XAxis dataKey="tld" tick={{ fill: C.textDim, fontSize: 10 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip content={<DarkTooltip />} />
                      <Legend formatter={(v) => <span style={{ color: C.text, fontSize: 11 }}>{v}</span>} />
                      <Bar dataKey="safe"      fill={C.safe}      radius={[3,3,0,0]} name="Safe" />
                      <Bar dataKey="malicious" fill={C.malicious} radius={[3,3,0,0]} name="Malicious" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* Keyword frequency */}
                <div className="glass rounded-2xl p-5">
                  <SectionTitle>Phishing Keyword Frequency</SectionTitle>
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={kwData(ds)} layout="vertical" margin={{ left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={C.grid} horizontal={false} />
                      <XAxis type="number" tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis type="category" dataKey="kw" width={72} tick={{ fill: C.text, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip content={<DarkTooltip />} />
                      <Bar dataKey="count" fill={C.malicious} radius={[0,4,4,0]} name="Hits" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* ── Row 3: URL Length area chart + Protocol pie ──────────────── */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">

                {/* URL length area */}
                <div className="glass rounded-2xl p-5">
                  <SectionTitle>URL Length Distribution</SectionTitle>
                  <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={lenData(ds)}>
                      <defs>
                        <linearGradient id="lenGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor={C.brandLight} stopOpacity={0.4} />
                          <stop offset="95%" stopColor={C.brandLight} stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={C.grid} />
                      <XAxis dataKey="range" tick={{ fill: C.textDim, fontSize: 9 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip content={<DarkTooltip />} />
                      <Area type="monotone" dataKey="count" stroke={C.brandLight} fill="url(#lenGrad)" strokeWidth={2} name="URLs" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>

                {/* Protocol pie */}
                <div className="glass rounded-2xl p-5">
                  <SectionTitle>Protocol Distribution</SectionTitle>
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'HTTPS', value: ds.protocol.https, color: C.safe },
                          { name: 'HTTP',  value: ds.protocol.http,  color: C.malicious },
                        ]}
                        cx="50%" cy="50%" innerRadius={60} outerRadius={90}
                        dataKey="value" nameKey="name" paddingAngle={3}
                      >
                        <Cell fill={C.safe}      stroke="transparent" />
                        <Cell fill={C.malicious} stroke="transparent" />
                      </Pie>
                      <Tooltip content={<DarkTooltip />} />
                      <Legend iconType="circle" iconSize={8}
                              formatter={(v) => <span style={{ color: C.text, fontSize: 12 }}>{v}</span>} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </>
          )}

          {/* ── Section 2: Dataset Comparison ────────────────────────────────── */}
          <div className="mt-12 mb-4">
            <div className="flex items-center gap-2 mb-6">
              <div className="w-1 h-6 rounded-full bg-brand" />
              <h2 className="text-lg font-bold text-white">Dataset Comparison</h2>
              <span className="text-xs text-white/30 ml-1">urls_1000.txt vs urls_1000_optimized.txt</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">

            {/* Comparison funnel */}
            <div className="glass rounded-2xl p-5">
              <SectionTitle>Funnel Reduction — Side by Side</SectionTitle>
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={compFunnel}>
                  <CartesianGrid strokeDasharray="3 3" stroke={C.grid} vertical={false} />
                  <XAxis dataKey="stage" tick={{ fill: C.textDim, fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: C.textDim, fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<DarkTooltip />} />
                  <Legend formatter={(v) => <span style={{ color: C.text, fontSize: 11 }}>{v === 'original' ? '📂 Original' : '✨ Optimized'}</span>} />
                  <Bar dataKey="original"  fill={C.pending}   radius={[3,3,0,0]} name="original" />
                  <Bar dataKey="optimized" fill={C.brandLight} radius={[3,3,0,0]} name="optimized" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Radar comparison */}
            <div className="glass rounded-2xl p-5">
              <SectionTitle>Multi-Metric Radar</SectionTitle>
              <ResponsiveContainer width="100%" height={260}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke={C.grid} />
                  <PolarAngleAxis dataKey="metric" tick={{ fill: C.text, fontSize: 11 }} />
                  <Radar name="Original"  dataKey="original"  stroke={C.pending}   fill={C.pending}   fillOpacity={0.2} />
                  <Radar name="Optimized" dataKey="optimized" stroke={C.brandLight} fill={C.brandLight} fillOpacity={0.2} />
                  <Legend formatter={(v) => <span style={{ color: C.text, fontSize: 11 }}>{v}</span>} />
                  <Tooltip content={<DarkTooltip />} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* ── Key numbers comparison table ─────────────────────────────────── */}
          <div className="glass rounded-2xl p-6 mb-8">
            <SectionTitle>Summary Comparison Table</SectionTitle>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-white/40 text-xs uppercase tracking-wider border-b border-white/[0.08]">
                    <th className="text-left pb-3 font-medium">Metric</th>
                    <th className="text-right pb-3 font-medium">📂 Original</th>
                    <th className="text-right pb-3 font-medium">✨ Optimized</th>
                    <th className="text-right pb-3 font-medium">Δ Change</th>
                  </tr>
                </thead>
                <tbody className="text-white/70">
                  {[
                    ['Total URLs', data.original.total_urls, data.optimized.total_urls, ''],
                    ['Pre-classified', data.original.pre_classified, data.optimized.pre_classified, '↑ better'],
                    ['→ DistilBERT', data.original.sent_to_distilbert, data.optimized.sent_to_distilbert, '↓ better'],
                    ['Reduction %', `${data.original.reduction_pct}%`, `${data.optimized.reduction_pct}%`, '↑ better'],
                    ['Safe (pre)', data.original.verdict_dist.safe, data.optimized.verdict_dist.safe, ''],
                    ['Malicious (pre)', data.original.verdict_dist.malicious, data.optimized.verdict_dist.malicious, ''],
                    ['Funnel ms', `${data.original.elapsed_ms}ms`, `${data.optimized.elapsed_ms}ms`, ''],
                    ['HTTPS', `${Math.round(data.original.protocol.https/10)}%`, `${Math.round(data.optimized.protocol.https/10)}%`, ''],
                    ['Suspicious TLDs', data.original.suspicious_tld_count, data.optimized.suspicious_tld_count, ''],
                  ].map(([metric, orig, opt, note]) => {
                    const origN = typeof orig === 'number' ? orig : parseFloat(String(orig));
                    const optN  = typeof opt  === 'number' ? opt  : parseFloat(String(opt));
                    const delta = !isNaN(origN) && !isNaN(optN) ? optN - origN : null;
                    return (
                      <tr key={String(metric)} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                        <td className="py-2.5 font-medium text-white/80">{metric}</td>
                        <td className="text-right py-2.5 font-mono">{String(orig)}</td>
                        <td className="text-right py-2.5 font-mono">{String(opt)}</td>
                        <td className="text-right py-2.5">
                          {delta !== null && delta !== 0 && (
                            <span className={`text-xs font-medium ${delta > 0 ? 'text-safe' : 'text-malicious'}`}>
                              {delta > 0 ? '+' : ''}{delta.toFixed(0)} {String(note)}
                            </span>
                          )}
                          {delta === 0 && <span className="text-white/20 text-xs">—</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
