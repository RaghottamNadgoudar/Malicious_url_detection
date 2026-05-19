import React, { useState, useEffect } from 'react';
import { Database, Activity, Shield, TrendingUp, Cpu, Filter, Network, Brain, Zap } from 'lucide-react';
import { getDatasetStats, getSystemStats } from '../services/api';

/* ── Stat tile ─────────────────────────────────────────────── */
const StatTile = ({ icon: Icon, label, value, sub, color }) => (
  <div style={{ padding:'14px 16px', borderRadius:12, background:color+'15', border:`1.5px solid ${color}30` }}>
    <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:6 }}>
      <div style={{ width:30, height:30, borderRadius:8, background:color, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
        <Icon size={15} color="#fff" />
      </div>
      <span style={{ fontSize:11, fontWeight:700, color, textTransform:'uppercase', letterSpacing:'0.04em' }}>{label}</span>
    </div>
    <div style={{ fontSize:20, fontWeight:800, color:'#111827' }}>{value}</div>
    {sub && <div style={{ fontSize:11, color:'#9ca3af', marginTop:2 }}>{sub}</div>}
  </div>
);

/* ── Fill bar ──────────────────────────────────────────────── */
const FillBar = ({ value, max, color }) => (
  <div style={{ height:8, borderRadius:999, background:'#f3f4f6', overflow:'hidden' }}>
    <div style={{ height:'100%', borderRadius:999, background:color,
      width:`${Math.min((value/max)*100,100)}%`, transition:'width 0.8s ease' }} />
  </div>
);

/* ── Algorithm card ────────────────────────────────────────── */
const AlgoCard = ({ icon: Icon, name, desc, complexity, color }) => (
  <div style={{ padding:'12px 14px', borderRadius:10, background:color+'10', border:`1.5px solid ${color}30`, display:'flex', gap:10 }}>
    <div style={{ width:32, height:32, borderRadius:8, background:color, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
      <Icon size={15} color="#fff" />
    </div>
    <div>
      <div style={{ fontWeight:700, fontSize:12, color:'#1f2937' }}>{name}</div>
      <div style={{ fontSize:10, color:'#6b7280', marginTop:1 }}>{desc}</div>
      <code style={{ fontSize:10, background:'#f3f4f6', padding:'1px 5px', borderRadius:3, color:'#4b5563', marginTop:3, display:'inline-block' }}>
        {complexity}
      </code>
    </div>
  </div>
);

/* ── Main ──────────────────────────────────────────────────── */
const SystemStats = () => {
  const [dataset, setDataset] = useState(null);
  const [system,  setSystem]  = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getDatasetStats(), getSystemStats()])
      .then(([d, s]) => { setDataset(d); setSystem(s); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div className="card" style={{ padding:48, textAlign:'center', color:'#6b7280' }}>
      <div style={{ fontSize:14 }}>Loading system stats…</div>
    </div>
  );

  const bloom = system?.bloom_filter?.standard_bloom;

  return (
    <div style={{ fontFamily:'Inter,system-ui,sans-serif', display:'flex', flexDirection:'column', gap:18 }}>

      {/* Header */}
      <div style={{ padding:'18px 20px', borderRadius:14, background:'linear-gradient(135deg,#0ea5e9,#6366f1)', color:'#fff', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div>
          <h2 style={{ fontSize:20, fontWeight:800, margin:0 }}>System Statistics</h2>
          <p style={{ fontSize:12, margin:'4px 0 0', opacity:0.8 }}>Live metrics · 7-phase pipeline · 830K dataset</p>
        </div>
        <Activity size={48} color="rgba(255,255,255,0.2)" />
      </div>

      {/* Dataset tiles */}
      {dataset && (
        <div>
          <div style={{ fontWeight:700, fontSize:14, marginBottom:10, display:'flex', alignItems:'center', gap:7 }}>
            <Database size={15} color="#0ea5e9" /> Dataset Statistics
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:10, marginBottom:14 }}>
            <StatTile icon={Database} label="Total URLs"     value={dataset.total_urls?.toLocaleString()}    color="#6366f1" />
            <StatTile icon={Shield}   label="Benign URLs"    value={dataset.benign_count?.toLocaleString()}  sub={`${((dataset.benign_count/dataset.total_urls)*100).toFixed(1)}% of dataset`} color="#10b981" />
            <StatTile icon={Activity} label="Malicious URLs" value={dataset.malicious_count?.toLocaleString()} sub={`${((dataset.malicious_count/dataset.total_urls)*100).toFixed(1)}% of dataset`} color="#ef4444" />
          </div>
          {/* Visual split bar */}
          <div style={{ padding:'14px 16px', borderRadius:12, background:'#f9fafb', border:'1px solid #e5e7eb' }}>
            <div style={{ fontSize:12, fontWeight:600, color:'#374151', marginBottom:8 }}>Dataset Class Balance</div>
            <div style={{ display:'flex', height:16, borderRadius:999, overflow:'hidden', gap:2 }}>
              <div style={{ flex: dataset.benign_count, background:'#10b981', display:'flex', alignItems:'center', justifyContent:'center' }}>
                <span style={{ fontSize:10, color:'#fff', fontWeight:700 }}>Benign {((dataset.benign_count/dataset.total_urls)*100).toFixed(0)}%</span>
              </div>
              <div style={{ flex: dataset.malicious_count, background:'#ef4444', display:'flex', alignItems:'center', justifyContent:'center' }}>
                <span style={{ fontSize:10, color:'#fff', fontWeight:700 }}>Malicious {((dataset.malicious_count/dataset.total_urls)*100).toFixed(0)}%</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* System stats */}
      {system && (
        <div>
          <div style={{ fontWeight:700, fontSize:14, marginBottom:10, display:'flex', alignItems:'center', gap:7 }}>
            <Cpu size={15} color="#8b5cf6" /> System Components
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:10, marginBottom:10 }}>
            <StatTile icon={Network}  label="Graph Nodes"        value={system.graph_nodes?.toLocaleString()}               color="#0ea5e9" />
            <StatTile icon={TrendingUp} label="Redirect Paths"   value={system.redirect_depths_tracked?.toLocaleString()}   color="#6366f1" />
            <StatTile icon={Shield}   label="Registered Threats" value={system.malicious_urls_registered?.toLocaleString()} color="#ef4444" />
          </div>

          {/* Bloom filter card */}
          {bloom && (
            <div style={{ padding:'14px 16px', borderRadius:12, background:'#fdf2f8', border:'1.5px solid #fbcfe8', marginBottom:10 }}>
              <div style={{ fontWeight:700, fontSize:13, color:'#9d174d', marginBottom:12, display:'flex', alignItems:'center', gap:7 }}>
                <Filter size={14} color="#ec4899" /> Learned Bloom Filter
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:10 }}>
                {[
                  { label:'Size',            value:`${bloom.size_kb?.toFixed(2)} KB` },
                  { label:'Hash Functions',  value: bloom.hash_functions },
                  { label:'Elements Added',  value: bloom.elements_added?.toLocaleString() },
                  { label:'Load Factor',     value:`${((bloom.load_factor||0)*100).toFixed(1)}%` },
                ].map((s, i) => (
                  <div key={i} style={{ textAlign:'center' }}>
                    <div style={{ fontSize:11, color:'#9d174d', marginBottom:3 }}>{s.label}</div>
                    <div style={{ fontSize:16, fontWeight:800, color:'#831843' }}>{s.value}</div>
                  </div>
                ))}
              </div>
              <div style={{ marginTop:10 }}>
                <div style={{ display:'flex', justifyContent:'space-between', fontSize:11, color:'#9d174d', marginBottom:3 }}>
                  <span>Load Factor</span>
                  <span>{((bloom.load_factor||0)*100).toFixed(1)}%</span>
                </div>
                <FillBar value={bloom.load_factor||0} max={1} color="#ec4899" />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Algorithm coverage */}
      <div>
        <div style={{ fontWeight:700, fontSize:14, marginBottom:10, display:'flex', alignItems:'center', gap:7 }}>
          <Zap size={15} color="#f59e0b" /> Algorithm Coverage (7-Phase Pipeline)
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(2,1fr)', gap:8 }}>
          {[
            { icon:Network, name:'BFS / DFS Graph Traversal',   desc:'Redirect chain analysis',       complexity:'O(V + E)',        color:'#0ea5e9' },
            { icon:Brain,   name:'Deep Neural Network',         desc:'25-feature threat classification', complexity:'O(1) inference', color:'#8b5cf6' },
            { icon:Zap,     name:'Dijkstra Shortest Path',      desc:'Greedy path optimization',       complexity:'O((V+E) log V)',  color:'#f59e0b' },
            { icon:Filter,  name:'Learned Bloom Filter + LSH',  desc:'Fast membership lookup',         complexity:'O(k)',            color:'#ec4899' },
            { icon:TrendingUp,name:'Heapsort Ranking',          desc:'Threat priority scoring',        complexity:'O(n log n)',      color:'#10b981' },
            { icon:Network, name:'BFS Transitive Closure',      desc:'Reachability analysis',          complexity:'O(V·E)',          color:'#6366f1' },
            { icon:Activity,name:'25-Feature Extraction',       desc:'Self-contained signal extraction',complexity:'O(n)',           color:'#f97316' },
            { icon:Cpu,     name:'URL Expansion / Unshortening',desc:'Multi-hop redirect following',   complexity:'O(k) net calls',  color:'#14b8a6' },
          ].map((a, i) => <AlgoCard key={i} {...a} />)}
        </div>
      </div>
    </div>
  );
};

export default SystemStats;
