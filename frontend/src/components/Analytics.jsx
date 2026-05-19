import { useState, useEffect } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis
} from 'recharts';
import { Brain, Database, Zap, TrendingUp, Cpu, Layers, CheckCircle } from 'lucide-react';

const COLORS = ['#6366f1','#0ea5e9','#8b5cf6','#f59e0b','#ec4899','#10b981','#f97316','#14b8a6'];

const Tile = ({ icon: Icon, label, value, sub, color }) => (
  <div style={{ padding:'14px 16px', borderRadius:12, background:color+'18', border:`1.5px solid ${color}33` }}>
    <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:6 }}>
      <div style={{ width:30, height:30, borderRadius:8, background:color, display:'flex', alignItems:'center', justifyContent:'center' }}>
        <Icon size={15} color="#fff" />
      </div>
      <span style={{ fontSize:11, fontWeight:700, color, textTransform:'uppercase', letterSpacing:'0.04em' }}>{label}</span>
    </div>
    <div style={{ fontSize:20, fontWeight:800, color:'#111827' }}>{value}</div>
    {sub && <div style={{ fontSize:11, color:'#9ca3af', marginTop:2 }}>{sub}</div>}
  </div>
);

const Badge = ({ num, label }) => (
  <div style={{ display:'flex', alignItems:'center', gap:7, padding:'5px 9px', borderRadius:8, background:'#f9fafb', border:'1px solid #e5e7eb' }}>
    <div style={{ width:20, height:20, borderRadius:5, background:'#6366f1', display:'flex', alignItems:'center', justifyContent:'center', fontSize:9, fontWeight:800, color:'#fff', flexShrink:0 }}>
      {num}
    </div>
    <span style={{ fontSize:11, color:'#374151' }}>{label.replace(/_/g,' ')}</span>
  </div>
);

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:'#fff', border:'1px solid #e5e7eb', borderRadius:8, padding:'8px 12px', boxShadow:'0 4px 12px rgba(0,0,0,0.1)', fontSize:12 }}>
      <div style={{ fontWeight:700, color:'#374151', marginBottom:4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color }}>
          {p.name}: <b>{typeof p.value === 'number' && p.value < 1 ? `${(p.value*1000).toFixed(0)}μs` : `${Number(p.value).toFixed(2)}ms`}</b>
        </div>
      ))}
    </div>
  );
};

const FEATURES_25 = [
  'url_length','domain_length','subdomain_depth','path_depth','query_length',
  'num_query_params','dot_count','hyphen_count','digit_ratio','uppercase_ratio',
  'special_char_ratio','url_entropy','domain_entropy','has_https','tld_suspicion',
  'has_ip','has_at_symbol','double_slash_path','has_suspicious_port','redirect_depth',
  'keyword_score','brand_in_subdomain','has_homograph','domain_age_proxy','chain_length',
];

const Analytics = () => {
  const [modelInfo, setModelInfo]       = useState(null);
  const [performance, setPerformance]   = useState(null);
  const [datasetStats, setDatasetStats] = useState(null);
  const [loading, setLoading]           = useState(true);

  useEffect(() => {
    Promise.all([
      fetch('http://localhost:5000/api/model/info').then(r => r.json()),
      fetch('http://localhost:5000/api/analytics/performance').then(r => r.json()),
      fetch('http://localhost:5000/api/dataset/stats').then(r => r.json()),
    ]).then(([m, p, d]) => { setModelInfo(m); setPerformance(p); setDatasetStats(d); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div className="card" style={{ padding:48, textAlign:'center', color:'#6b7280', fontSize:14 }}>
      Loading analytics…
    </div>
  );

  const algos = (performance?.algorithms || []).map((a, i) => ({
    ...a,
    shortName: a.name.replace(' (Neural)','').replace(' (Shorteners)','').replace('BFS/DFS ','').replace(' Lookup','').replace(' Ranking',''),
    fill: COLORS[i % COLORS.length],
  }));

  const distData = datasetStats ? [
    { name:'Benign',    value: datasetStats.benign_count,    fill:'#10b981' },
    { name:'Malicious', value: datasetStats.malicious_count, fill:'#ef4444' },
  ] : [];

  const radarData = algos.map(a => ({ subject: a.shortName, efficiency: a.efficiency ?? 0 }));

  return (
    <div style={{ fontFamily:'Inter,system-ui,sans-serif', display:'flex', flexDirection:'column', gap:20 }}>

      {/* Header */}
      <div style={{ padding:'20px 24px', borderRadius:14, background:'linear-gradient(135deg,#6366f1,#8b5cf6)', color:'#fff', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div>
          <h2 style={{ fontSize:22, fontWeight:800, margin:0 }}>System Analytics Dashboard</h2>
          <p style={{ fontSize:12, margin:'4px 0 0', opacity:0.8 }}>Neural pipeline · 830K training URLs · 96.4% accuracy · AUC 0.9938</p>
        </div>
        <TrendingUp size={52} color="rgba(255,255,255,0.2)" />
      </div>

      {/* Model info */}
      {modelInfo && (
        <div className="card">
          <div style={{ fontWeight:700, fontSize:15, marginBottom:14, display:'flex', alignItems:'center', gap:8 }}>
            <Brain size={17} color="#8b5cf6" /> Neural Network Model
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:10, marginBottom:16 }}>
            <Tile icon={Cpu}       label="Architecture"    value={modelInfo.architecture || '25→128→64→32→1'} color="#8b5cf6" />
            <Tile icon={Layers}    label="Input Features"  value={modelInfo.input_features ?? 25} sub="Self-contained signals" color="#6366f1" />
            <Tile icon={Database}  label="Model Size"      value={`${(modelInfo.model_size_mb||0).toFixed(2)} MB`}
              sub={modelInfo.model_exists ? '✓ Trained & Active' : '✗ Untrained'} color="#0ea5e9" />
          </div>

          {/* Layer diagram */}
          <div style={{ background:'#f9fafb', borderRadius:10, padding:'14px 16px', marginBottom:16 }}>
            <div style={{ fontSize:11, fontWeight:700, color:'#6b7280', marginBottom:10, letterSpacing:'0.05em' }}>NETWORK ARCHITECTURE</div>
            <div style={{ display:'flex', alignItems:'center', gap:6, flexWrap:'wrap' }}>
              {[
                { l:'Input',     s:'25 features', c:'#6366f1' },
                { l:'Dense 128', s:'ReLU + BN + Drop(0.3)', c:'#8b5cf6' },
                { l:'Dense 64',  s:'ReLU + BN + Drop(0.25)', c:'#8b5cf6' },
                { l:'Dense 32',  s:'ReLU + BN + Drop(0.2)', c:'#8b5cf6' },
                { l:'Output',    s:'Sigmoid', c:'#10b981' },
              ].map((n, i, arr) => (
                <div key={i} style={{ display:'flex', alignItems:'center', gap:6 }}>
                  <div style={{ padding:'8px 12px', borderRadius:8, background:n.c+'22', border:`1.5px solid ${n.c}55`, textAlign:'center', minWidth:88 }}>
                    <div style={{ fontSize:12, fontWeight:700, color:n.c }}>{n.l}</div>
                    <div style={{ fontSize:9, color:'#9ca3af', marginTop:2 }}>{n.s}</div>
                  </div>
                  {i < arr.length-1 && <span style={{ color:'#d1d5db', fontSize:18 }}>→</span>}
                </div>
              ))}
            </div>
          </div>

          {/* 25 features */}
          <div style={{ background:'#f9fafb', borderRadius:10, padding:'14px 16px' }}>
            <div style={{ fontSize:11, fontWeight:700, color:'#6b7280', marginBottom:10, letterSpacing:'0.05em' }}>25 EXTRACTED FEATURES</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(155px,1fr))', gap:5 }}>
              {FEATURES_25.map((f, i) => <Badge key={i} num={i+1} label={f} />)}
            </div>
          </div>
        </div>
      )}

      {/* Dataset + Distribution */}
      {datasetStats && (
        <div className="card">
          <div style={{ fontWeight:700, fontSize:15, marginBottom:14, display:'flex', alignItems:'center', gap:8 }}>
            <Database size={17} color="#0ea5e9" /> Training Dataset Statistics
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, alignItems:'center' }}>
            <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
              {[
                { label:'Total URLs',    value: datasetStats.total_urls,    color:'#6366f1' },
                { label:'Benign URLs',   value: datasetStats.benign_count,  color:'#10b981', pct:((datasetStats.benign_count/datasetStats.total_urls)*100).toFixed(1)+'%' },
                { label:'Malicious URLs',value: datasetStats.malicious_count, color:'#ef4444', pct:((datasetStats.malicious_count/datasetStats.total_urls)*100).toFixed(1)+'%' },
              ].map((r, i) => (
                <div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'10px 14px', borderRadius:8, background:r.color+'12', border:`1px solid ${r.color}30` }}>
                  <span style={{ fontSize:13, fontWeight:600, color:'#374151' }}>{r.label}</span>
                  <div style={{ textAlign:'right' }}>
                    <div style={{ fontSize:17, fontWeight:800, color:r.color }}>{r.value?.toLocaleString()}</div>
                    {r.pct && <div style={{ fontSize:10, color:'#9ca3af' }}>{r.pct}</div>}
                  </div>
                </div>
              ))}
            </div>
            {/* Recharts Pie */}
            <div>
              <div style={{ fontSize:12, fontWeight:600, color:'#374151', marginBottom:6, textAlign:'center' }}>Class Distribution</div>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={distData} cx="50%" cy="50%" outerRadius={80} innerRadius={45}
                    dataKey="value" paddingAngle={3}
                    label={({ name, percent }) => `${name}: ${(percent*100).toFixed(1)}%`}
                    labelLine={false}
                  >
                    {distData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Pie>
                  <Tooltip formatter={v => v.toLocaleString()} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Algorithm performance graphs */}
      {algos.length > 0 && (
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>

          {/* Bar chart – execution time */}
          <div className="card">
            <div style={{ fontWeight:700, fontSize:14, marginBottom:14, display:'flex', alignItems:'center', gap:7 }}>
              <Zap size={15} color="#f59e0b" /> Execution Time by Algorithm
            </div>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={algos} margin={{ left:10, bottom:65, top:20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" vertical={false} />
                <XAxis dataKey="shortName" angle={-35} textAnchor="end" tick={{ fontSize:9 }} interval={0} />
                <YAxis scale="log" domain={['auto','auto']} tick={{ fontSize:9 }}
                  tickFormatter={v => v < 1 ? `${(v*1000).toFixed(0)}μs` : `${v.toFixed(1)}ms`}
                  label={{ value:'Time (log)', angle:-90, position:'insideLeft', style:{fontSize:9} }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="avg_time_ms" name="Avg Time" radius={[5,5,0,0]}
                  label={{ position:'top', fontSize:8, formatter: v => v<1?`${(v*1000).toFixed(0)}μs`:`${v.toFixed(1)}ms` }}>
                  {algos.map((a, i) => <Cell key={i} fill={a.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Radar chart – efficiency */}
          <div className="card">
            <div style={{ fontWeight:700, fontSize:14, marginBottom:14, display:'flex', alignItems:'center', gap:7 }}>
              <CheckCircle size={15} color="#10b981" /> Algorithm Efficiency Radar
            </div>
            <ResponsiveContainer width="100%" height={280}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="#e5e7eb" />
                <PolarAngleAxis dataKey="subject" tick={{ fontSize:9 }} />
                <PolarRadiusAxis angle={30} domain={[0,100]} tick={{ fontSize:9 }} />
                <Radar name="Efficiency %" dataKey="efficiency" stroke="#6366f1" fill="#6366f1" fillOpacity={0.25} strokeWidth={2} />
                <Tooltip formatter={v => `${v}%`} />
                <Legend />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Pipeline stats */}
      {performance && algos.length > 0 && (
        <div className="card">
          <div style={{ fontWeight:700, fontSize:14, marginBottom:14, display:'flex', alignItems:'center', gap:7 }}>
            <TrendingUp size={15} color="#6366f1" /> Pipeline Performance Summary
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:10 }}>
            <Tile icon={Zap}         label="Throughput"    value={`${(performance.throughput_urls_per_sec||0).toFixed(0)}`} sub="URLs/second" color="#10b981" />
            <Tile icon={TrendingUp}  label="Avg Pipeline"  value={`${(performance.overall_pipeline_time_ms||0).toFixed(1)}ms`} color="#f59e0b" />
            <Tile icon={CheckCircle} label="Model AUC"     value="0.9938" sub="96.4% accuracy" color="#8b5cf6" />
            <Tile icon={Database}    label="Dataset"       value="830K" sub="Training URLs" color="#0ea5e9" />
          </div>
        </div>
      )}
    </div>
  );
};

export default Analytics;
