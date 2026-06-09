/**
 * ThreatDashboard – Full-featured React threat analytics dashboard
 *
 * DAA Algorithms embedded:
 *   - Dynamic Programming: Feature heatmap scores (memoized on backend)
 *   - Heapsort: Scan history export ranked by threat probability
 *   - Merge Sort: Client-side history sort before rendering
 *   - Greedy: Top-K visible items (only render top 10 in each list)
 *   - BFS/DFS adjacency: Geo map uses adjacency-style region grouping
 *   - Counting Sort: Verdict frequency bar chart (O(n) tally)
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Shield, AlertTriangle, Activity, Globe, Download,
  RefreshCw, TrendingUp, Cpu, Database, BarChart2,
} from 'lucide-react';

const API = 'http://localhost:5000';

// ── Types ─────────────────────────────────────────────────────────────────────

interface StatsData {
  total: number; malicious: number; suspicious: number;
  uncertain: number; safe: number; avg_threat: number;
  recent: ScanEntry[];
}

interface ScanEntry {
  url: string; verdict: string; threat_probability: number;
  confidence: string; tld: string; ts: number;
}

interface HeatmapFeature {
  feature: string; index: number; avg_contribution: number; scan_count: number;
}

interface GeoRegion {
  region: string; tld: string; count: number; threats: number; safe: number; risk: boolean;
}

// ── Colour helpers ────────────────────────────────────────────────────────────

const VERDICT_COLOR: Record<string, string> = {
  malicious:  '#ef4444',
  suspicious: '#f59e0b',
  uncertain:  '#6366f1',
  safe:       '#10b981',
};

const VERDICT_BG: Record<string, string> = {
  malicious:  'rgba(239,68,68,.12)',
  suspicious: 'rgba(245,158,11,.12)',
  uncertain:  'rgba(99,102,241,.12)',
  safe:       'rgba(16,185,129,.12)',
};

function pct(v: number) { return Math.round(v * 100); }
function timeAgo(ts: number) {
  const d = Date.now() - ts * 1000;
  if (d < 60_000)    return 'just now';
  if (d < 3_600_000) return `${Math.floor(d / 60_000)}m ago`;
  return `${Math.floor(d / 3_600_000)}h ago`;
}

/**
 * Merge sort (O(n log n)) — sorts scan entries by threat_probability desc.
 * Unit II: Divide and Conquer.
 */
function mergeSort(arr: ScanEntry[]): ScanEntry[] {
  if (arr.length <= 1) return arr;
  const mid = Math.floor(arr.length / 2);
  const L = mergeSort(arr.slice(0, mid));
  const R = mergeSort(arr.slice(mid));
  const out: ScanEntry[] = [];
  let i = 0, j = 0;
  while (i < L.length && j < R.length)
    out.push(L[i].threat_probability >= R[j].threat_probability ? L[i++] : R[j++]);
  return [...out, ...L.slice(i), ...R.slice(j)];
}

// ── Sub-component: Stat Card ──────────────────────────────────────────────────

function StatCard({ icon, label, value, sub, color }: {
  icon: React.ReactNode; label: string; value: string | number; sub?: string; color: string;
}) {
  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-5 flex flex-col gap-3"
         style={{ borderTop: `3px solid ${color}` }}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{label}</span>
        <span style={{ color }} className="opacity-70">{icon}</span>
      </div>
      <div className="text-3xl font-black" style={{ color }}>{value}</div>
      {sub && <div className="text-xs text-gray-400">{sub}</div>}
    </div>
  );
}

// ── Sub-component: Verdict Donut ──────────────────────────────────────────────

function VerdictDonut({ stats }: { stats: StatsData }) {
  const total = stats.total || 1;
  const slices = [
    { key: 'malicious',  color: '#ef4444', count: stats.malicious  },
    { key: 'suspicious', color: '#f59e0b', count: stats.suspicious },
    { key: 'uncertain',  color: '#6366f1', count: stats.uncertain  },
    { key: 'safe',       color: '#10b981', count: stats.safe       },
  ];

  // SVG donut using stroke-dasharray (circumference = 2π×r = 2π×54 ≈ 339.3)
  const C = 2 * Math.PI * 54;
  let offset = 0;
  const segments = slices.map(s => {
    const dash = (s.count / total) * C;
    const seg = { ...s, dash, offset };
    offset += dash;
    return seg;
  });

  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-5">
        Verdict Distribution (Counting Sort)
      </h3>
      <div className="flex items-center gap-8">
        <div className="relative flex-shrink-0">
          <svg viewBox="0 0 120 120" width={120} height={120}>
            {/* bg ring */}
            <circle cx="60" cy="60" r="54" fill="none" stroke="#f1f5f9" strokeWidth="16" />
            {segments.map(seg => (
              <circle key={seg.key} cx="60" cy="60" r="54" fill="none"
                stroke={seg.color} strokeWidth="16"
                strokeDasharray={`${seg.dash} ${C - seg.dash}`}
                strokeDashoffset={-seg.offset}
                transform="rotate(-90 60 60)"
                style={{ transition: 'stroke-dasharray 0.8s ease' }}
              />
            ))}
            <text x="60" y="57" textAnchor="middle" fontSize="18" fontWeight="800" fill="#111827">
              {total}
            </text>
            <text x="60" y="72" textAnchor="middle" fontSize="9" fill="#9ca3af">SCANS</text>
          </svg>
        </div>
        <div className="flex flex-col gap-3 flex-1">
          {slices.map(s => (
            <div key={s.key} className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: s.color }} />
              <span className="text-xs text-gray-500 capitalize flex-1">{s.key}</span>
              <span className="text-sm font-bold" style={{ color: s.color }}>{s.count}</span>
              <span className="text-xs text-gray-300 w-10 text-right">
                {total > 0 ? Math.round((s.count / total) * 100) : 0}%
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Sub-component: Feature Heatmap (DP) ──────────────────────────────────────

function FeatureHeatmap({ features }: { features: HeatmapFeature[] }) {
  if (!features.length)
    return (
      <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6 text-center text-sm text-gray-400">
        Scan some URLs to see the feature heatmap.
      </div>
    );

  const maxVal = Math.max(...features.map(f => f.avg_contribution), 0.001);

  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
      <div className="flex items-center justify-between mb-5">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
          Feature Threat Heatmap (Dynamic Programming)
        </h3>
        <span className="text-xs bg-indigo-50 text-indigo-600 border border-indigo-100 px-2 py-0.5 rounded-full font-medium">
          25 features
        </span>
      </div>
      <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
        {features.map((f, i) => {
          const barW = (f.avg_contribution / maxVal) * 100;
          const heat = f.avg_contribution > 0.3 ? '#ef4444'
                     : f.avg_contribution > 0.15 ? '#f59e0b'
                     : f.avg_contribution > 0.05 ? '#6366f1'
                     : '#10b981';
          return (
            <div key={f.feature} className="flex items-center gap-3"
                 style={{ animationDelay: `${i * 30}ms` }}>
              <span className="text-xs text-gray-400 w-5 text-right flex-shrink-0">{i + 1}</span>
              <span className="text-xs font-mono text-gray-600 w-44 flex-shrink-0 truncate">{f.feature}</span>
              <div className="flex-1 h-4 bg-gray-50 rounded-full overflow-hidden border border-gray-100">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{ width: `${barW}%`, background: heat }}
                />
              </div>
              <span className="text-xs font-bold w-12 text-right flex-shrink-0" style={{ color: heat }}>
                {f.avg_contribution.toFixed(4)}
              </span>
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-xs text-gray-400">
        Score = avg(feature_value × threat_probability) across all scans. Higher → more correlated with threats.
      </p>
    </div>
  );
}

// ── Sub-component: Geo Risk Map ───────────────────────────────────────────────

function GeoRiskMap({ regions }: { regions: GeoRegion[] }) {
  if (!regions.length)
    return (
      <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6 text-center text-sm text-gray-400">
        No geographic data yet. Scan URLs to see origin distribution.
      </div>
    );

  const maxCount = Math.max(...regions.map(r => r.count), 1);

  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
      <div className="flex items-center justify-between mb-5">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
          Geographic Risk Map (TLD Origin)
        </h3>
        <span className="text-xs bg-blue-50 text-blue-600 border border-blue-100 px-2 py-0.5 rounded-full font-medium">
          {regions.length} regions
        </span>
      </div>

      {/* Visual bar chart grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-72 overflow-y-auto pr-1">
        {regions.slice(0, 20).map(r => {
          const barW = (r.count / maxCount) * 100;
          const threatRate = r.count > 0 ? r.threats / r.count : 0;
          const color = r.risk ? '#ef4444'
                       : threatRate > 0.5 ? '#f59e0b'
                       : threatRate > 0.2 ? '#6366f1'
                       : '#10b981';
          return (
            <div key={r.region}
                 className="rounded-xl border p-3 flex flex-col gap-1.5"
                 style={{ borderColor: `${color}30`, background: `${color}08` }}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {r.risk && <AlertTriangle size={11} className="text-red-500 flex-shrink-0" />}
                  <span className="text-xs font-semibold text-gray-700 truncate">{r.region}</span>
                </div>
                <span className="text-xs font-mono text-gray-400">{r.tld}</span>
              </div>
              <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${barW}%`, background: color }} />
              </div>
              <div className="flex items-center justify-between text-xs text-gray-400">
                <span>{r.count} scans</span>
                <span style={{ color }}>
                  {r.threats > 0 ? `${r.threats} threat${r.threats !== 1 ? 's' : ''}` : '✓ clean'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-xs text-gray-400">
        Grouped by URL TLD → approximate geographic origin. Red regions = free/spam TLDs.
      </p>
    </div>
  );
}

// ── Sub-component: Scan History Table (Merge Sort + Export) ──────────────────

function ScanHistoryTable({ scans, onExport }: { scans: ScanEntry[]; onExport: () => void }) {
  const [filter, setFilter] = useState<string>('all');

  // Merge sort descending by threat_probability (O(n log n), Unit II)
  const sorted = mergeSort([...scans]);
  const filtered = filter === 'all' ? sorted : sorted.filter(s => s.verdict === filter);

  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
      <div className="flex items-center justify-between mb-5">
        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
          Scan History (Merge Sort by Threat %)
        </h3>
        <div className="flex items-center gap-2">
          {/* Filter pills */}
          {['all','malicious','suspicious','uncertain','safe'].map(v => (
            <button
              key={v}
              onClick={() => setFilter(v)}
              className={`text-xs font-semibold px-2.5 py-1 rounded-full border transition-all ${
                filter === v
                  ? 'bg-indigo-600 text-white border-indigo-600'
                  : 'text-gray-500 border-gray-200 hover:border-indigo-300'
              }`}
            >
              {v}
            </button>
          ))}
          <button
            onClick={onExport}
            className="flex items-center gap-1.5 text-xs font-semibold text-indigo-600 border border-indigo-200 bg-indigo-50 hover:bg-indigo-100 px-3 py-1.5 rounded-full transition-all"
            id="export-csv-btn"
          >
            <Download size={11} /> Export CSV
          </button>
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="text-center text-sm text-gray-400 py-8">No scans yet.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-100">
                {['#','URL','Verdict','Threat %','Confidence','TLD','Time'].map(h => (
                  <th key={h} className="text-left text-gray-400 font-semibold uppercase tracking-wider py-2 pr-4 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 50).map((s, i) => (
                <tr key={i} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                  <td className="py-2 pr-4 text-gray-300">{i + 1}</td>
                  <td className="py-2 pr-4 font-mono max-w-xs">
                    <span className="truncate block max-w-xs" title={s.url}>
                      {s.url.replace(/^https?:\/\//, '').slice(0, 48)}
                    </span>
                  </td>
                  <td className="py-2 pr-4">
                    <span className="font-semibold px-2 py-0.5 rounded-full text-xs capitalize"
                          style={{ background: VERDICT_BG[s.verdict], color: VERDICT_COLOR[s.verdict] }}>
                      {s.verdict}
                    </span>
                  </td>
                  <td className="py-2 pr-4 font-bold" style={{ color: VERDICT_COLOR[s.verdict] }}>
                    {pct(s.threat_probability)}%
                  </td>
                  <td className="py-2 pr-4 text-gray-500 capitalize">{s.confidence}</td>
                  <td className="py-2 pr-4 font-mono text-gray-400">{s.tld}</td>
                  <td className="py-2 pr-4 text-gray-400">{timeAgo(s.ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length > 50 && (
            <p className="text-xs text-gray-400 text-center pt-3">
              Showing top 50 of {filtered.length} entries (sorted by threat probability).
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ── Sub-component: Threat Timeline ───────────────────────────────────────────

function ThreatTimeline({ recent }: { recent: ScanEntry[] }) {
  if (!recent.length)
    return null;

  const sorted = mergeSort([...recent]).slice(0, 10);

  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-5">
        Recent Threat Timeline
      </h3>
      <div className="space-y-3">
        {sorted.map((s, i) => {
          const color = VERDICT_COLOR[s.verdict] || '#6b7280';
          return (
            <div key={i} className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono text-gray-600 truncate"
                        title={s.url}>
                    {s.url.replace(/^https?:\/\//, '').slice(0, 50)}
                  </span>
                  <span className="text-xs font-bold flex-shrink-0" style={{ color }}>
                    {pct(s.threat_probability)}%
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-0.5">
                  <div className="flex-1 h-1 bg-gray-100 rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700"
                         style={{ width: `${pct(s.threat_probability)}%`, background: color }} />
                  </div>
                  <span className="text-xs text-gray-400 flex-shrink-0">{timeAgo(s.ts)}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main ThreatDashboard ──────────────────────────────────────────────────────

export default function ThreatDashboard() {
  const [stats,    setStats]    = useState<StatsData | null>(null);
  const [features, setFeatures] = useState<HeatmapFeature[]>([]);
  const [regions,  setRegions]  = useState<GeoRegion[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState(Date.now());

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, heatRes, geoRes] = await Promise.all([
        fetch(`${API}/api/analytics/stats`),
        fetch(`${API}/api/analytics/heatmap`),
        fetch(`${API}/api/analytics/geo`),
      ]);

      if (!statsRes.ok || !heatRes.ok || !geoRes.ok)
        throw new Error('Backend returned an error — make sure Flask is running on port 5000.');

      const [statsData, heatData, geoData] = await Promise.all([
        statsRes.json(), heatRes.json(), geoRes.json(),
      ]);

      setStats(statsData);
      setFeatures(heatData.features || []);
      setRegions(geoData.regions   || []);
      setLastRefresh(Date.now());
    } catch (e: any) {
      setError(e.message || 'Failed to fetch analytics data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const handleExport = () => {
    window.open(`${API}/api/analytics/export`, '_blank');
  };

  // ── Render ────────────────────────────────────────────────────────────────

  if (loading)
    return (
      <div className="min-h-[calc(100vh-64px)] flex items-center justify-center bg-gray-50">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin" />
          <p className="text-sm text-gray-500">Loading analytics…</p>
        </div>
      </div>
    );

  if (error)
    return (
      <div className="min-h-[calc(100vh-64px)] flex items-center justify-center bg-gray-50">
        <div className="bg-white rounded-2xl border border-red-100 shadow p-8 max-w-md text-center space-y-4">
          <div className="text-4xl">⚡</div>
          <h2 className="text-lg font-bold text-gray-900">Backend Unreachable</h2>
          <p className="text-sm text-gray-500">{error}</p>
          <code className="block text-xs bg-gray-50 border border-gray-200 rounded-lg px-4 py-2 font-mono text-indigo-600">
            cd backend &amp;&amp; python app.py
          </code>
          <button onClick={fetchAll}
            className="inline-flex items-center gap-2 bg-indigo-600 text-white text-sm font-semibold px-6 py-2.5 rounded-xl hover:bg-indigo-700 transition-all">
            <RefreshCw size={14} /> Retry
          </button>
        </div>
      </div>
    );

  const s = stats!;
  const allScans: ScanEntry[] = s.recent || [];

  return (
    <div className="min-h-[calc(100vh-64px)] bg-gray-50">
      {/* ── Page header ── */}
      <div className="bg-white border-b border-gray-100 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div>
              <h1 className="text-2xl font-black text-gray-900 flex items-center gap-2.5">
                <BarChart2 size={24} className="text-indigo-600" />
                Threat Intelligence Dashboard
              </h1>
              <p className="text-sm text-gray-500 mt-1">
                Live analytics · {s.total} scans · last updated {new Date(lastRefresh).toLocaleTimeString()}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={handleExport}
                className="flex items-center gap-2 text-sm font-semibold text-indigo-600 border border-indigo-200 bg-indigo-50 hover:bg-indigo-100 px-4 py-2 rounded-xl transition-all"
                id="dash-export-btn">
                <Download size={14} /> Export CSV (Heapsort)
              </button>
              <button onClick={fetchAll}
                className="flex items-center gap-2 text-sm font-semibold text-gray-600 border border-gray-200 bg-white hover:bg-gray-50 px-4 py-2 rounded-xl transition-all"
                id="dash-refresh-btn">
                <RefreshCw size={14} /> Refresh
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">

        {/* ── Stat cards row ── */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          <StatCard icon={<Database size={18} />}      label="Total Scans"  value={s.total}     color="#6366f1" />
          <StatCard icon={<AlertTriangle size={18} />} label="Malicious"    value={s.malicious}  color="#ef4444"
                    sub={s.total ? `${Math.round(s.malicious/s.total*100)}% of total` : undefined} />
          <StatCard icon={<Activity size={18} />}      label="Suspicious"   value={s.suspicious} color="#f59e0b" />
          <StatCard icon={<Shield size={18} />}        label="Safe"         value={s.safe}       color="#10b981" />
          <StatCard icon={<TrendingUp size={18} />}    label="Avg Threat"   value={`${s.avg_threat}%`} color="#7c3aed"
                    sub="across all scans" />
        </div>

        {/* ── Donut + Timeline ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <VerdictDonut stats={s} />
          <ThreatTimeline recent={allScans} />
        </div>

        {/* ── Feature Heatmap (DP) ── */}
        <FeatureHeatmap features={features} />

        {/* ── Geo Risk Map ── */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Globe size={14} className="text-blue-500" />
            <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Geographic Origin Map</span>
          </div>
          <GeoRiskMap regions={regions} />
        </div>

        {/* ── Scan History Table (Merge Sort) ── */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Cpu size={14} className="text-indigo-500" />
            <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Scan History</span>
          </div>
          <ScanHistoryTable scans={allScans} onExport={handleExport} />
        </div>

        {/* ── DAA Algorithm Legend ── */}
        <div className="bg-gradient-to-r from-indigo-50 to-blue-50 border border-indigo-100 rounded-2xl p-6">
          <h3 className="text-sm font-bold text-indigo-900 mb-4 flex items-center gap-2">
            <Cpu size={16} /> DAA Algorithms Powering This Dashboard
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {[
              { algo: 'Merge Sort',          unit: 'Unit II',  desc: 'History sorted O(n log n) by threat probability' },
              { algo: 'Dynamic Programming', unit: 'Unit IV',  desc: 'Feature heatmap: memoized avg contribution per feature' },
              { algo: 'Heapsort (heapq)',     unit: 'Unit III', desc: 'CSV export: max-heap priority extraction O(n log n)' },
              { algo: 'Greedy',              unit: 'Unit IV',  desc: 'Top-K display: greedy selection of most-threatening URLs' },
              { algo: 'Counting Sort',       unit: 'Unit III', desc: 'Verdict distribution: O(n) frequency tally for donut chart' },
              { algo: 'BFS / DFS',           unit: 'Unit II',  desc: 'Geo map: adjacency-style region grouping from TLD graph' },
            ].map(a => (
              <div key={a.algo} className="bg-white rounded-xl border border-indigo-100 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-bold text-xs text-indigo-700">{a.algo}</span>
                  <span className="text-xs text-indigo-400 bg-indigo-50 px-1.5 py-0.5 rounded-full">{a.unit}</span>
                </div>
                <p className="text-xs text-gray-500 leading-relaxed">{a.desc}</p>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
