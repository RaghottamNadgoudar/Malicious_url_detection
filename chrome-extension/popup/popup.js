/**
 * URL Shield – Popup Logic
 * Handles tab navigation, current-tab analysis, manual checks, and history.
 */

const API_BASE = 'http://localhost:5000';

// ── Verdict config ────────────────────────────────────────────────────────────

const VERDICT_CONFIG = {
  safe: {
    icon: '✓', label: 'SAFE', color: 'safe',
    emoji: '🛡️',
  },
  suspicious: {
    icon: '⚠', label: 'SUSPICIOUS', color: 'suspicious',
    emoji: '⚠️',
  },
  malicious: {
    icon: '✕', label: 'MALICIOUS', color: 'malicious',
    emoji: '🚫',
  },
  uncertain: {
    icon: '?', label: 'UNCERTAIN', color: 'uncertain',
    emoji: '🔍',
  },
};

// ── Helper utilities ──────────────────────────────────────────────────────────

function formatURL(url) {
  try { return new URL(url).hostname + new URL(url).pathname.slice(0, 30); }
  catch { return url.slice(0, 50); }
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60_000)  return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function pct(val) { return Math.round((val || 0) * 100); }

// ── Tab navigation ────────────────────────────────────────────────────────────

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(p => p.classList.add('hidden'));
    btn.classList.add('active');
    const panel = document.getElementById(`panel-${btn.dataset.tab}`);
    panel.classList.remove('hidden');

    if (btn.dataset.tab === 'history') loadHistory();
  });
});

// ── Backend status check ──────────────────────────────────────────────────────

async function checkBackend() {
  const dot   = document.getElementById('status-dot');
  const label = document.getElementById('status-label');
  try {
    const r = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      dot.className   = 'status-dot online';
      label.textContent = 'Online';
      return true;
    }
  } catch (_) {}
  dot.className   = 'status-dot offline';
  label.textContent = 'Offline';
  return false;
}

// ── Render verdict into a container ──────────────────────────────────────────

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

  // Show result section
  container.querySelector('.verdict-loading')?.classList.add('hidden');
  container.querySelector('.verdict-error')?.classList.add('hidden');
  const resultEl = container.querySelector('.verdict-result');
  resultEl?.classList.remove('hidden');

  // Verdict circle
  const circle = container.querySelector('.verdict-circle');
  if (circle) {
    circle.className = `verdict-circle ${cfg.color}`;
    circle.querySelector('.verdict-icon').textContent = cfg.icon;
  }

  // Label
  const lbl = container.querySelector('.verdict-label');
  if (lbl) {
    lbl.textContent = cfg.label;
    lbl.className   = `verdict-label ${cfg.color}`;
  }

  // Sublabel
  const sub = container.querySelector('.verdict-sublabel');
  if (sub) {
    sub.innerHTML = `
      Confidence: <span class="conf-badge ${conf}">${conf.toUpperCase()}</span>
    `;
  }

  // Threat meter
  const fill = container.querySelector('.threat-fill');
  if (fill) {
    fill.className = `threat-fill ${cfg.color}`;
    const threatPctEl = container.querySelector('#threat-pct');
    if (threatPctEl) threatPctEl.textContent = `${pct(prob)}%`;
    // Animate after paint
    requestAnimationFrame(() => {
      requestAnimationFrame(() => { fill.style.width = `${pct(prob)}%`; });
    });
  }

  // Phase breakdown
  const grid = container.querySelector('.phases-grid');
  if (grid) buildPhaseGrid(grid, result);

  // Recommendation
  const recText = container.querySelector('.recommendation-text');
  if (recText) recText.textContent = rec;

  // Recommendation border color
  const recBox = container.querySelector('.recommendation');
  if (recBox) {
    const colors = { safe: '#10b981', suspicious: '#f59e0b', malicious: '#ef4444', uncertain: '#6366f1' };
    recBox.style.borderLeftColor = colors[verdict] || '#7c3aed';
  }
}

function buildPhaseGrid(grid, result) {
  const p1 = result.phase1_graph || {};
  const p3 = result.phase3_neural || {};
  const p5 = result.phase5_bloom || {};
  const p6 = result.phase6_ranking || {};
  const exp = result.url_expansion || {};

  const phases = [
    {
      name: 'Phase 1 · Graph',
      value: p1.redirect_depth !== undefined ? `Depth ${p1.redirect_depth}` : '—',
      sub:   p1.is_redirect ? 'Redirect detected' : 'No redirects',
    },
    {
      name: 'Phase 3 · Neural Net',
      value: p3.threat_probability !== undefined ? `${pct(p3.threat_probability)}%` : '—',
      sub:   p3.verdict || '—',
    },
    {
      name: 'Phase 5 · Bloom Filter',
      value: p5.final_verdict || '—',
      sub:   p5.in_bloom_filter ? 'Known threat' : 'Not in DB',
    },
    {
      name: 'Phase 6 · Rank',
      value: p6.threat_rank !== undefined ? `#${p6.threat_rank}` : '—',
      sub:   p6.risk_category || '—',
    },
  ];

  if (exp.is_shortened) {
    phases.push({
      name: 'URL Expander',
      value: `${exp.redirect_count || 0} hops`,
      sub: 'Shortener detected',
    });
  }

  grid.innerHTML = phases.map((p, i) => `
    <div class="phase-card" style="animation-delay: ${i * 60}ms">
      <div class="phase-name">${p.name}</div>
      <div class="phase-value">${p.value}</div>
      <div class="phase-sub">${p.sub}</div>
    </div>
  `).join('');
}

// ── Analyze current tab ───────────────────────────────────────────────────────

let currentTab = null;

async function analyzeCurrentTab(forceRefresh = false) {
  // Reset UI
  document.getElementById('verdict-loading').classList.remove('hidden');
  document.getElementById('verdict-result').classList.add('hidden');
  document.getElementById('verdict-error').classList.add('hidden');

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;

    const url = tab.url || '';
    document.getElementById('current-url-text').textContent = url || 'No URL';

    // Skip internal pages
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
        url.startsWith('about:') || url.startsWith('edge://')) {
      showSkipped();
      return;
    }

    // If force refresh, skip cache; else try cache first
    let result = null;
    if (!forceRefresh) {
      result = await getCached(url);
    }

    if (!result) {
      // Call API directly from popup
      const isOnline = await checkBackend();
      if (!isOnline) {
        renderVerdict(null, document.getElementById('verdict-card'));
        return;
      }

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
  document.querySelector('.error-icon').textContent = 'ℹ️';
  document.querySelector('.error-title').textContent = 'Internal Page';
  document.querySelector('.error-msg').textContent = 'URL Shield only scans http/https URLs.';
  document.querySelector('.error-cmd').textContent = 'Navigate to a website to start scanning';
}

// ── Cache helpers (popup-side) ────────────────────────────────────────────────

function cacheKey(url) { return 'cache_' + btoa(url).slice(0, 80); }
const CACHE_TTL_MS = 10 * 60 * 1000;

function getCached(url) {
  return new Promise(resolve => {
    chrome.storage.local.get(cacheKey(url), data => {
      const entry = data[cacheKey(url)];
      if (!entry || Date.now() - entry.ts > CACHE_TTL_MS) return resolve(null);
      resolve(entry.result);
    });
  });
}

function setCache(url, result) {
  return new Promise(resolve => {
    chrome.storage.local.set({ [cacheKey(url)]: { ts: Date.now(), result } }, resolve);
  });
}

// ── Rescan button ─────────────────────────────────────────────────────────────

document.getElementById('btn-rescan').addEventListener('click', () => {
  analyzeCurrentTab(true);
});

// ── Manual URL check ──────────────────────────────────────────────────────────

async function checkManualURL() {
  const input = document.getElementById('manual-url-input');
  const area  = document.getElementById('manual-result-area');
  const url   = input.value.trim();

  if (!url) { input.focus(); return; }

  // Add https:// if missing
  const fullUrl = url.match(/^https?:\/\//) ? url : `https://${url}`;

  // Show skeleton
  area.innerHTML = `
    <div class="manual-result-card verdict-card">
      <div class="verdict-loading" style="min-height:120px">
        <div class="spinner"></div>
        <span>Analyzing…</span>
      </div>
      <div class="verdict-result hidden">
        <div class="verdict-hero">
          <div class="verdict-circle"><span class="verdict-icon"></span></div>
          <div class="verdict-info">
            <div class="verdict-label"></div>
            <div class="verdict-sublabel"></div>
          </div>
        </div>
        <div class="threat-meter">
          <div class="threat-meter-labels"><span>Threat Level</span><span id="threat-pct">0%</span></div>
          <div class="threat-bar"><div class="threat-fill"></div></div>
        </div>
        <div class="phases-grid"></div>
        <div class="recommendation">
          <div class="recommendation-label">Recommendation</div>
          <div class="recommendation-text recommendation-text"></div>
        </div>
      </div>
      <div class="verdict-error hidden">
        <span class="error-icon">⚡</span>
        <div class="error-title">Backend Offline</div>
        <div class="error-msg">Start the Flask server to enable URL analysis.</div>
        <code class="error-cmd">cd backend && python app.py</code>
      </div>
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
      verdict: result.final_verdict?.verdict || 'uncertain',
      confidence: result.final_verdict?.confidence || 'low',
      threat_probability: result.final_verdict?.threat_probability || 0,
      ts: Date.now(),
    });
  } catch (err) {
    renderVerdict(null, area.querySelector('.manual-result-card'));
  }
}

document.getElementById('check-btn').addEventListener('click', checkManualURL);
document.getElementById('manual-url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') checkManualURL();
});

// ── History ───────────────────────────────────────────────────────────────────

function appendHistory(entry) {
  return new Promise(resolve => {
    chrome.storage.local.get('scan_history', data => {
      const history = data.scan_history || [];
      const filtered = history.filter(h => h.url !== entry.url);
      filtered.unshift(entry);
      chrome.storage.local.set({ scan_history: filtered.slice(0, 20) }, resolve);
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

    list.innerHTML = history.slice(0, 15).map((item, i) => `
      <div class="history-item" style="animation-delay: ${i * 40}ms">
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

// ── Bootstrap ─────────────────────────────────────────────────────────────────

(async function init() {
  await checkBackend();
  await analyzeCurrentTab();
})();
