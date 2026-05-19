import { useState, useEffect } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line, Legend, AreaChart, Area
} from 'recharts';
import { Activity, RefreshCw, TrendingUp, Clock, Zap, BarChart3, Cpu, Database } from 'lucide-react';
import { getPerformanceMetrics, refreshPerformanceBenchmark } from '../services/api';

const COLORS = ['#6366f1','#0ea5e9','#8b5cf6','#f59e0b','#ec4899','#10b981','#f97316','#14b8a6'];

const fmt = (ms) => {
  if (ms == null || isNaN(ms)) return '—';
  if (ms < 1)    return `${(ms * 1000).toFixed(0)} μs`;
  if (ms < 1000) return `${ms.toFixed(2)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
};

const StatTile = ({ icon: Icon, label, value, sub, color }) => (
  <div style={{ padding:'14px 16px', borderRadius:12, background:color+'18', border:`1.5px solid ${color}33`, display:'flex', alignItems:'center', gap:14 }}>
    <div style={{ width:40, height:40, borderRadius:10, background:color, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
      <Icon size={18} color="#fff" />
    </div>
    <div>
      <div style={{ fontSize:11, color:'#6b7280', fontWeight:700, textTransform:'uppercase', letterSpacing:'0.04em' }}>{label}</div>
      <div style={{ fontSize:20, fontWeight:800, color:'#111827' }}>{value}</div>
      {sub && <div style={{ fontSize:11, color:'#9ca3af' }}>{sub}</div>}
    </div>
  </div>
);

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:'#fff', border:'1px solid #e5e7eb', borderRadius:8, padding:'8px 12px', boxShadow:'0 4px 12px rgba(0,0,0,0.1)', fontSize:12 }}>
      <div style={{ fontWeight:700, color:'#374151', marginBottom:4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color }}>{p.name}: <b>{fmt(p.value)}</b></div>
      ))}
    </div>
  );
};

const PerformanceAnalytics = () => {
  const [metrics, setMetrics]       = useState(null);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError]           = useState(null);

  const load = async () => {
    try { setLoading(true); setError(null);
      setMetrics(await getPerformanceMetrics());
    } catch { setError('Failed to load performance metrics'); }
    finally   { setLoading(false); }
  };

  const refresh = async () => {
    try { setRefreshing(true); setError(null);
      await refreshPerformanceBenchmark(10000);
      await load();
    } catch { setError('Failed to refresh'); }
    finally   { setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  if (loading) return (
    <div className="card" style={{ padding:48, textAlign:'center' }}>
      <RefreshCw size={32} color="#6366f1" style={{ animation:'spin 1s linear infinite', margin:'0 auto 12px' }} />
      <div style={{ fontSize:15, fontWeight:600 }}>Running benchmark…</div>
      <div style={{ fontSize:12, color:'#9ca3af', marginTop:4 }}>Testing all 8 pipeline phases</div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );

  if (error) return (
    <div className="card" style={{ padding:48, textAlign:'center' }}>
      <div style={{ color:'#dc2626', marginBottom:14 }}>{error}</div>
      <button onClick={load} className="btn btn-primary">Retry</button>
    </div>
  );

  const algos = (metrics?.algorithms || []).map((a, i) => ({
    ...a,
    short: a.name.replace(' (Neural)','').replace(' (Shorteners)','').replace('BFS/DFS ','').replace(' Lookup','').replace(' Ranking','').replace('Expansion ',''),
    color: COLORS[i % COLORS.length],
  }));

  // Latency comparison data (avg / p95 / p99)
  const latencyData = algos.map(a => ({
    name: a.short,
    avg:  a.avg_time_ms,
    p95:  a.p95_time_ms,
    p99:  a.p99_time_ms,
  }));

  // Efficiency data for area chart
  const effData = algos.map(a => ({ name: a.short, efficiency: a.efficiency ?? 0 }));

  return (
    <div style={{ fontFamily:'Inter,system-ui,sans-serif', display:'flex', flexDirection:'column', gap:18 }}>

      {/* Header */}
      <div className="card" style={{ display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <div style={{ width:44, height:44, borderRadius:10, background:'linear-gradient(135deg,#6366f1,#8b5cf6)', display:'flex', alignItems:'center', justifyContent:'center' }}>
            <Activity size={22} color="#fff" />
          </div>
          <div>
            <h2 style={{ fontSize:20, fontWeight:800, margin:0 }}>Algorithm Performance</h2>
            <p style={{ fontSize:12, color:'#6b7280', margin:0 }}>
              {algos.length} algorithms · {metrics?.sample_size?.toLocaleString() ?? 0} URLs tested
              {metrics?.cache_info?.cached && <span style={{ color:'#6366f1', marginLeft:8 }}>· cached</span>}
            </p>
          </div>
        </div>
        <button onClick={refresh} disabled={refreshing} className="btn btn-secondary" style={{ display:'flex', alignItems:'center', gap:6 }}>
          <RefreshCw size={14} style={refreshing?{animation:'spin 1s linear infinite'}:{}} />
          {refreshing ? 'Running…' : 'Re-run Benchmark'}
        </button>
      </div>

      {/* 4 stat tiles */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
        <StatTile icon={Clock}      label="Avg Pipeline"  value={fmt(metrics?.overall_pipeline_time_ms)} color="#6366f1" />
        <StatTile icon={Zap}        label="Throughput"    value={`${(metrics?.throughput_urls_per_sec??0).toFixed(0)}`} sub="URLs/second" color="#10b981" />
        <StatTile icon={TrendingUp} label="P95 Latency"   value={fmt(metrics?.pipeline_p95_ms)} color="#f59e0b" />
        <StatTile icon={Database}   label="Sample Size"   value={(metrics?.sample_size??0).toLocaleString()} sub="URLs tested" color="#0ea5e9" />
      </div>

      {/* Two charts side by side */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>

        {/* Grouped bar chart: avg / p95 / p99 */}
        <div className="card">
          <div style={{ fontWeight:700, fontSize:14, marginBottom:14, display:'flex', alignItems:'center', gap:7 }}>
            <BarChart3 size={15} color="#6366f1" /> Execution Time per Algorithm (log scale)
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={latencyData} margin={{ bottom:65, left:15, top:20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" vertical={false} />
              <XAxis dataKey="name" angle={-35} textAnchor="end" tick={{ fontSize:9 }} interval={0} />
              <YAxis scale="log" domain={['auto','auto']} tick={{ fontSize:9 }}
                tickFormatter={v => v < 1 ? `${(v*1000).toFixed(0)}μs` : `${v.toFixed(1)}ms`} />
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize:11, paddingTop:8 }} />
              <Bar dataKey="avg" name="Avg" fill="#6366f1" radius={[3,3,0,0]}
                label={{ position:'top', fontSize:7, formatter: v => v<1?`${(v*1000).toFixed(0)}μs`:`${v.toFixed(1)}ms` }} />
              <Bar dataKey="p95" name="P95" fill="#f59e0b" radius={[3,3,0,0]}
                label={{ position:'top', fontSize:7, formatter: v => v<1?`${(v*1000).toFixed(0)}μs`:`${v.toFixed(1)}ms` }} />
              <Bar dataKey="p99" name="P99" fill="#ef4444" radius={[3,3,0,0]}
                label={{ position:'top', fontSize:7, formatter: v => v<1?`${(v*1000).toFixed(0)}μs`:`${v.toFixed(1)}ms` }} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Area chart: efficiency */}
        <div className="card">
          <div style={{ fontWeight:700, fontSize:14, marginBottom:14, display:'flex', alignItems:'center', gap:7 }}>
            <Cpu size={15} color="#8b5cf6" /> Algorithm Efficiency (%)
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={effData} margin={{ bottom:55, left:5 }}>
              <defs>
                <linearGradient id="effGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#6366f1" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0.02}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
              <XAxis dataKey="name" angle={-35} textAnchor="end" tick={{ fontSize:9 }} interval={0} />
              <YAxis domain={[0,100]} tick={{ fontSize:10 }} label={{ value:'%', angle:-90, position:'insideLeft', style:{fontSize:10} }} />
              <Tooltip formatter={v => [`${v}%`, 'Efficiency']} />
              <Area type="monotone" dataKey="efficiency" stroke="#6366f1" strokeWidth={2.5}
                fill="url(#effGrad)" dot={{ r:4, fill:'#6366f1', strokeWidth:2, stroke:'#fff' }} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Pipeline timeline proportional */}
      <div className="card">
        <div style={{ fontWeight:700, fontSize:14, marginBottom:12, display:'flex', alignItems:'center', gap:7 }}>
          <Activity size={15} color="#6366f1" /> Pipeline Time Distribution (proportional)
        </div>
        <div style={{ display:'flex', height:28, borderRadius:8, overflow:'hidden', gap:2 }}>
          {(() => {
            const total = algos.reduce((s,a) => s+(a.avg_time_ms||0), 0)||1;
            return algos.map((a, i) => {
              const pct = ((a.avg_time_ms||0)/total*100).toFixed(1);
              return (
                <div key={i} title={`${a.name}: ${fmt(a.avg_time_ms)} (${pct}%)`}
                  style={{ flex:a.avg_time_ms||0, background:a.color, display:'flex', alignItems:'center', justifyContent:'center', minWidth:4, cursor:'default' }}>
                  {parseFloat(pct)>6 && <span style={{ color:'#fff', fontSize:9, fontWeight:700, padding:'0 3px' }}>{pct}%</span>}
                </div>
              );
            });
          })()}
        </div>
        <div style={{ display:'flex', flexWrap:'wrap', gap:'6px 14px', marginTop:10 }}>
          {algos.map((a,i) => (
            <div key={i} style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, color:'#6b7280' }}>
              <div style={{ width:10, height:10, borderRadius:2, background:a.color }} />
              {a.short}
            </div>
          ))}
        </div>
      </div>

      {/* Full detail table */}
      <div className="card" style={{ padding:0, overflow:'hidden' }}>
        <div style={{ padding:'14px 18px', borderBottom:'1px solid #e5e7eb', fontWeight:700, fontSize:14, display:'flex', alignItems:'center', gap:7 }}>
          <BarChart3 size={15} color="#6366f1" /> Detailed Benchmarks
        </div>
        <div style={{ overflowX:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse' }}>
            <thead>
              <tr style={{ background:'#f9fafb', borderBottom:'2px solid #e5e7eb' }}>
                {['Algorithm','Complexity','Avg Time','P95','P99','Efficiency','Samples'].map(h => (
                  <th key={h} style={{ padding:'10px 14px', fontSize:11, fontWeight:700, color:'#6b7280', textTransform:'uppercase', letterSpacing:'0.04em',
                    textAlign: ['Avg Time','P95','P99','Samples'].includes(h)?'right':'Efficiency'===h?'center':'left' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {algos.map((a,i) => (
                <tr key={i} style={{ background:i%2===1?'#f9fafb':'#fff', borderBottom:'1px solid #f3f4f6' }}>
                  <td style={{ padding:'10px 14px' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                      <div style={{ width:10, height:10, borderRadius:'50%', background:a.color }} />
                      <div>
                        <div style={{ fontWeight:600, fontSize:13 }}>{a.name}</div>
                        {a.note && <div style={{ fontSize:10, color:'#9ca3af' }}>{a.note}</div>}
                      </div>
                    </div>
                  </td>
                  <td style={{ padding:'10px 14px' }}>
                    <code style={{ fontSize:11, background:'#f3f4f6', padding:'2px 7px', borderRadius:4, color:'#4b5563' }}>{a.complexity}</code>
                  </td>
                  <td style={{ padding:'10px 14px', textAlign:'right', fontFamily:'monospace', fontWeight:700, fontSize:13 }}>{fmt(a.avg_time_ms)}</td>
                  <td style={{ padding:'10px 14px', textAlign:'right', fontFamily:'monospace', fontSize:12, color:'#6b7280' }}>{fmt(a.p95_time_ms)}</td>
                  <td style={{ padding:'10px 14px', textAlign:'right', fontFamily:'monospace', fontSize:12, color:'#6b7280' }}>{fmt(a.p99_time_ms)}</td>
                  <td style={{ padding:'10px 14px', textAlign:'center' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:7, justifyContent:'center' }}>
                      <div style={{ width:50, height:6, borderRadius:999, background:'#e5e7eb', overflow:'hidden' }}>
                        <div style={{ height:'100%', width:`${a.efficiency}%`, background: a.efficiency>=90?'#10b981':a.efficiency>=70?'#6366f1':'#f59e0b', borderRadius:999 }} />
                      </div>
                      <span style={{ fontSize:12, fontWeight:700, color: a.efficiency>=90?'#10b981':a.efficiency>=70?'#6366f1':'#f59e0b' }}>{a.efficiency}%</span>
                    </div>
                  </td>
                  <td style={{ padding:'10px 14px', textAlign:'right', fontSize:12, color:'#9ca3af' }}>{a.samples?.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
};

export default PerformanceAnalytics;
