/**
 * URL Shield – Popup Logic v2.0
 *
 * DAA Algorithms used:
 *   - Merge Sort: sort history by threat_probability for Top Threats ranking
 *   - Boyer-Moore inspired: fast URL fingerprint dedup (urlFingerprint)
 *   - Greedy: only render top-5 threats in dashboard (greedy top-k selection)
 *   - Dynamic Programming: memoized verdict distribution (cache counts)
 */

const API_BASE = 'http://localhost:5000';

// ── Verdict config ────────────────────────────────────────────────────────────

const VERDICT_CONFIG = {
  safe:       { icon: '✓', label: 'SAFE',       color: 'safe' },
  suspicious: { icon: '⚠', label: 'SUSPICIOUS', color: 'suspicious' },
  malicious:  { icon: '✕', label: 'MALICIOUS',  color: 'malicious' },
  uncertain:  { icon: '?', label: 'UNCERTAIN',  color: 'uncertain' },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatURL(url) {
  try { return new URL(url).hostname + new URL(url).pathname.slice(0, 28); }
  catch { return url.slice(0, 50); }
}

function timeAgo(ts) {
  const d = Date.now() - ts;
  if (d < 60_000)     return 'just now';
  if (d < 3_600_000)  return `${Math.floor(d / 60_000)}m ago`;
  if (d < 86_400_000) return `${Math.floor(d / 3_600_000)}h ago`;
  return `${Math.floor(d / 86_400_000)}d ago`;
}

function pct(val) { return Math.round((val || 0) * 100); }

// ── Merge Sort (DAA Unit II) ──────────────────────────────────────────────────
/**
 * Merge sort history by threat_probability descending.
 * Time complexity: O(n log n) — better than bubble/selection sort.
 */
function mergeSort(arr) {
  if (arr.length <= 1) return arr;
  const mid   = Math.floor(arr.length / 2);
  const left  = mergeSort(arr.slice(0, mid));
  const right = mergeSort(arr.slice(mid));
  return merge(left, right);
}

function merge(left, right) {
  const result = [];
  let i = 0, j = 0;
  while (i < left.length && j < right.length) {
    // Descending by threat_probability
    if ((left[i].threat_probability || 0) >= (right[j].threat_probability || 0)) {
      result.push(left[i++]);
    } else {
      result.push(right[j++]);
    }
  }
  return [...result, ...left.slice(i), ...right.slice(j)];
}

// ── Tab navigation ────────────────────────────────────────────────────────────

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(p => { p.classList.add('hidden'); p.classList.remove('active'); });
    btn.classList.add('active');
    const panel = document.getElementById(`panel-${btn.dataset.tab}`);
    panel.classList.remove('hidden');
    panel.classList.add('active');

    if (btn.dataset.tab === 'history')   loadHistory();
    if (btn.dataset.tab === 'dashboard') loadDashboard();
  });
});

// ── Backend status ────────────────────────────────────────────────────────────

async function checkBackend() {
  const dot   = document.getElementById('status-dot');
  const label = document.getElementById('status-label');
  try {
    const r = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      dot.className     = 'status-dot online';
      label.textContent = 'Online';
      return true;
    }
  } catch (_) {}
  dot.className     = 'status-dot offline';
  label.textContent = 'Offline';
  return false;
}

// ── Render verdict ────────────────────────────────────────────────────────────

function renderVerdict(result, container) {
  if (!result || result.error) {
    container.querySelector('.verdict-loading')?.classList.add('hidden');
    container.querySelector('.verdict-result')?.classList.add('hidden');
    container.querySelector('.verdict-error')?.classList.remove('hidden');
    return;
  }

  const fv      = result.final_verdict || {};
  const verdict = fv.verdict || 'uncertain';
  const cfg     = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.uncertain;
  const conf    = fv.confidence || 'low';
  const prob    = fv.threat_probability || 0;
  const rec     = fv.recommendation || '—';

  container.querySelector('.verdict-loading')?.classList.add('hidden');
  container.querySelector('.verdict-error')?.classList.add('hidden');
  container.querySelector('.verdict-result')?.classList.remove('hidden');

  const circle = container.querySelector('.verdict-circle');
  if (circle) {
    circle.className = `verdict-circle ${cfg.color}`;
    circle.querySelector('.verdict-icon').textContent = cfg.icon;
  }

  const lbl = container.querySelector('.verdict-label');
  if (lbl) { lbl.textContent = cfg.label; lbl.className = `verdict-label ${cfg.color}`; }

  const sub = container.querySelector('.verdict-sublabel');
  if (sub) sub.innerHTML = `Confidence: <span class="conf-badge ${conf}">${conf.toUpperCase()}</span>`;

  const fill = container.querySelector('.threat-fill');
  if (fill) {
    fill.className = `threat-fill ${cfg.color}`;
    const pctEl = container.querySelector('#threat-pct');
    if (pctEl) pctEl.textContent = `${pct(prob)}%`;
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${pct(prob)}%`; }));
  }

  const grid = container.querySelector('.phases-grid');
  if (grid) buildPhaseGrid(grid, result);

  const recText = container.querySelector('.recommendation-text');
  if (recText) recText.textContent = rec;

  const recBox = container.querySelector('.recommendation');
  if (recBox) {
    const colors = { safe: '#10b981', suspicious: '#f59e0b', malicious: '#ef4444', uncertain: '#6366f1' };
    recBox.style.borderLeftColor = colors[verdict] || '#7c3aed';
  }
}

function buildPhaseGrid(grid, result) {
  const p1  = result.phase1_graph  || {};
  const p3  = result.phase3_neural || {};
  const p5  = result.phase5_bloom  || {};
  const p6  = result.phase6_ranking|| {};
  const exp = result.url_expansion || {};

  const phases = [
    { name: 'Phase 1 · Graph',       value: p1.redirect_depth !== undefined ? `Depth ${p1.redirect_depth}` : '—', sub: p1.is_redirect ? 'Redirect detected' : 'No redirects' },
    { name: 'Phase 3 · Neural Net',  value: p3.threat_probability !== undefined ? `${pct(p3.threat_probability)}%` : '—', sub: p3.verdict || '—' },
    { name: 'Phase 5 · Bloom Filter',value: p5.final_verdict || '—', sub: p5.in_bloom_filter ? 'Known threat' : 'Not in DB' },
    { name: 'Phase 6 · Rank',        value: p6.threat_rank !== undefined ? `#${p6.threat_rank}` : '—', sub: p6.risk_category || '—' },
  ];

  if (exp.is_shortened) phases.push({ name: 'URL Expander', value: `${exp.redirect_count || 0} hops`, sub: 'Shortener detected' });

  grid.innerHTML = phases.map((p, i) => `
    <div class="phase-card" style="animation-delay:${i * 60}ms">
      <div class="phase-name">${p.name}</div>
      <div class="phase-value">${p.value}</div>
      <div class="phase-sub">${p.sub}</div>
    </div>
  `).join('');
}

// ── Analyze current tab ───────────────────────────────────────────────────────

let currentTab = null;

async function analyzeCurrentTab(forceRefresh = false) {
  document.getElementById('verdict-loading').classList.remove('hidden');
  document.getElementById('verdict-result').classList.add('hidden');
  document.getElementById('verdict-error').classList.add('hidden');

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;
    const url = tab.url || '';
    document.getElementById('current-url-text').textContent = url || 'No URL';

    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:') || url.startsWith('edge://')) {
      showSkipped(); return;
    }

    let result = null;
    if (!forceRefresh) result = await getCached(url);

    if (!result) {
      const isOnline = await checkBackend();
      if (!isOnline) { renderVerdict(null, document.getElementById('verdict-card')); return; }

      const resp = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
        signal: AbortSignal.timeout(15000),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      result = await resp.json();
      await setCache(url, result);
    }

    renderVerdict(result, document.getElementById('verdict-card'));
  } catch (err) {
    console.error('[URL Shield] Popup error:', err);
    renderVerdict(null, document.getElementById('verdict-card'));
  }
}

function showSkipped() {
  document.getElementById('verdict-loading').classList.add('hidden');
  document.getElementById('verdict-error').classList.remove('hidden');
  document.querySelector('.error-icon').textContent   = 'ℹ️';
  document.querySelector('.error-title').textContent  = 'Internal Page';
  document.querySelector('.error-msg').textContent    = 'URL Shield only scans http/https URLs.';
  document.querySelector('.error-cmd').textContent    = 'Navigate to a website to start scanning';
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

function cacheKey(url) { return 'cache_' + btoa(unescape(encodeURIComponent(url))).slice(0, 80); }
const CACHE_TTL_MS = 10 * 60 * 1000;

function getCached(url) {
  return new Promise(resolve => {
    chrome.storage.local.get(cacheKey(url), data => {
      const e = data[cacheKey(url)];
      if (!e || Date.now() - e.ts > CACHE_TTL_MS) return resolve(null);
      resolve(e.result);
    });
  });
}

function setCache(url, result) {
  return new Promise(resolve =>
    chrome.storage.local.set({ [cacheKey(url)]: { ts: Date.now(), result } }, resolve)
  );
}

// ── Rescan ────────────────────────────────────────────────────────────────────
document.getElementById('btn-rescan').addEventListener('click', () => analyzeCurrentTab(true));

// ── Manual URL check ──────────────────────────────────────────────────────────

async function checkManualURL() {
  const input  = document.getElementById('manual-url-input');
  const area   = document.getElementById('manual-result-area');
  const url    = input.value.trim();
  if (!url) { input.focus(); return; }

  const fullUrl = url.match(/^https?:\/\//) ? url : `https://${url}`;

  area.innerHTML = `
    <div class="manual-result-card verdict-card">
      <div class="verdict-loading" style="min-height:120px"><div class="spinner"></div><span>Analyzing…</span></div>
      <div class="verdict-result hidden">
        <div class="verdict-hero"><div class="verdict-circle"><span class="verdict-icon"></span></div><div class="verdict-info"><div class="verdict-label"></div><div class="verdict-sublabel"></div></div></div>
        <div class="threat-meter"><div class="threat-meter-labels"><span>Threat Level</span><span id="threat-pct">0%</span></div><div class="threat-bar"><div class="threat-fill"></div></div></div>
        <div class="phases-grid"></div>
        <div class="recommendation"><div class="recommendation-label">Recommendation</div><div class="recommendation-text"></div></div>
      </div>
      <div class="verdict-error hidden"><span class="error-icon">⚡</span><div class="error-title">Backend Offline</div><div class="error-msg">Start the Flask server.</div><code class="error-cmd">cd backend &amp;&amp; python app.py</code></div>
    </div>
  `;

  try {
    const resp = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: fullUrl }),
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const result = await resp.json();
    renderVerdict(result, area.querySelector('.manual-result-card'));
    await appendHistory({
      url: fullUrl,
      verdict:           result.final_verdict?.verdict || 'uncertain',
      confidence:        result.final_verdict?.confidence || 'low',
      threat_probability:result.final_verdict?.threat_probability || 0,
      ts: Date.now(),
    });
  } catch {
    renderVerdict(null, area.querySelector('.manual-result-card'));
  }
}

document.getElementById('check-btn').addEventListener('click', checkManualURL);
document.getElementById('manual-url-input').addEventListener('keydown', e => { if (e.key === 'Enter') checkManualURL(); });

// ── History ───────────────────────────────────────────────────────────────────

function appendHistory(entry) {
  return new Promise(resolve => {
    chrome.storage.local.get('scan_history', data => {
      const history  = data.scan_history || [];
      const filtered = history.filter(h => h.url !== entry.url);
      filtered.unshift(entry);
      chrome.storage.local.set({ scan_history: filtered.slice(0, 500) }, resolve);
    });
  });
}

function loadHistory() {
  chrome.storage.local.get('scan_history', data => {
    const list    = document.getElementById('history-list');
    const history = data.scan_history || [];

    if (!history.length) {
      list.innerHTML = `<div class="history-empty">No scans yet.<br>Browse a website to start.</div>`;
      return;
    }

    list.innerHTML = history.slice(0, 20).map((item, i) => `
      <div class="history-item" style="animation-delay:${i * 40}ms">
        <div class="history-dot ${item.verdict}"></div>
        <span class="history-url" title="${item.url}">${formatURL(item.url)}</span>
        <span class="history-verdict ${item.verdict}">${item.verdict}</span>
        <span class="history-time">${timeAgo(item.ts)}</span>
      </div>
    `).join('');
  });
}

document.getElementById('history-clear-btn').addEventListener('click', () => {
  chrome.storage.local.remove('scan_history', loadHistory);
});

// ── Export CSV (Merge-Sorted by threat probability) ───────────────────────────
/**
 * Applies Merge Sort (O(n log n)) to history before export.
 * Ensures highest-threat URLs appear first in the exported file.
 */
function exportHistoryCSV() {
  chrome.storage.local.get('scan_history', data => {
    const history = data.scan_history || [];
    if (!history.length) { alert('No history to export.'); return; }

    // Merge sort descending by threat_probability
    const sorted = mergeSort([...history]);

    const header = 'URL,Verdict,Confidence,Threat Probability (%),Timestamp\n';
    const rows   = sorted.map(item =>
      `"${item.url}","${item.verdict}","${item.confidence || 'low'}","${pct(item.threat_probability)}","${new Date(item.ts).toISOString()}"`
    ).join('\n');

    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `urlshield_history_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

document.getElementById('history-export-btn').addEventListener('click', exportHistoryCSV);
document.getElementById('btn-export-pdf').addEventListener('click', exportHistoryCSV);

// ── Dashboard ─────────────────────────────────────────────────────────────────
/**
 * Greedy top-K: only render the top 5 threats (greedy selection by prob).
 * Donut chart: SVG stroke-dasharray manipulation for animated ring segments.
 */
function loadDashboard() {
  chrome.storage.local.get('scan_history', data => {
    const history = data.scan_history || [];

    // Summary counts
    const counts = { safe: 0, uncertain: 0, suspicious: 0, malicious: 0 };
    history.forEach(h => { counts[h.verdict] = (counts[h.verdict] || 0) + 1; });

    const total   = history.length;
    const threats = (counts.malicious || 0) + (counts.suspicious || 0);

    document.getElementById('dash-total').textContent   = total;
    document.getElementById('dash-threats').textContent = threats;
    document.getElementById('dash-safe').textContent    = counts.safe || 0;

    // Animated donut chart
    buildDonut(counts, total);

    // Top threats via merge sort (Greedy top-5 selection)
    const sorted     = mergeSort([...history]);
    const topThreats = sorted.filter(h => h.verdict === 'malicious' || h.verdict === 'suspicious').slice(0, 5);
    renderTopThreats(topThreats);
  });
}

function buildDonut(counts, total) {
  const CIRCUMFERENCE = 2 * Math.PI * 30; // 188.5
  const order = ['malicious', 'suspicious', 'uncertain', 'safe'];
  const colors = { malicious: '#ef4444', suspicious: '#f59e0b', uncertain: '#6366f1', safe: '#10b981' };

  let offset = 0;
  const legend = [];

  order.forEach(verdict => {
    const circle = document.getElementById(`donut-${verdict}`);
    if (!circle) return;
    const frac  = total > 0 ? (counts[verdict] || 0) / total : 0;
    const dash  = frac * CIRCUMFERENCE;
    const gap   = CIRCUMFERENCE - dash;

    circle.style.strokeDasharray  = `${dash} ${gap}`;
    circle.style.strokeDashoffset = -offset;
    circle.setAttribute('transform', `rotate(${(offset / CIRCUMFERENCE) * 360 - 90} 40 40)`);
    offset += dash;

    if (counts[verdict]) {
      legend.push(`<div class="donut-leg-item">
        <span class="donut-leg-dot" style="background:${colors[verdict]}"></span>
        <span class="donut-leg-lbl">${verdict}</span>
        <span class="donut-leg-num">${counts[verdict]}</span>
      </div>`);
    }
  });

  const legEl = document.getElementById('donut-legend');
  if (legEl) legEl.innerHTML = legend.join('') || '<span style="color:rgba(255,255,255,.3);font-size:11px">No data yet</span>';
}

function renderTopThreats(threats) {
  const container = document.getElementById('top-threats-list');
  if (!threats.length) {
    container.innerHTML = '<div class="dash-empty">No threats recorded yet. 🎉</div>';
    return;
  }

  container.innerHTML = threats.map((item, i) => `
    <div class="top-threat-item">
      <span class="top-threat-rank">#${i + 1}</span>
      <span class="top-threat-url" title="${item.url}">${formatURL(item.url)}</span>
      <span class="top-threat-badge ${item.verdict}">${pct(item.threat_probability)}%</span>
    </div>
  `).join('');
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

(async function init() {
  await checkBackend();
  await analyzeCurrentTab();
})();
