/* ───────────────────────────────────────────────────────────
   popup.js — DAA Shield Chrome Extension
   Features:
   1. Auto-scan current tab URL on popup open
   2. Manual URL scan with optional redirect expansion
   3. Page link batch scanner (via content script)
   4. Scan history (localStorage via chrome.storage)
   5. Settings panel (API base URL override)
─────────────────────────────────────────────────────────── */

const DEFAULT_API = 'http://localhost:8002';

// ── State ─────────────────────────────────────────────────
let API_BASE = DEFAULT_API;
let currentScanResult = null;

// ── DOM refs ───────────────────────────────────────────────
const $ = id => document.getElementById(id);

// Tabs
const tabs       = document.querySelectorAll('.tab');
const tabPanes   = document.querySelectorAll('.tab-content');

// Scan tab
const currentUrlText  = $('currentUrlText');
const scanCurrentBtn  = $('scanCurrentBtn');
const resultCard      = $('resultCard');
const verdictBadge    = $('verdictBadge');
const verdictUrl      = $('verdictUrl');
const verdictDetail   = $('verdictDetail');
const confArc         = $('confArc');
const confPct         = $('confPct');
const tierChip        = $('tierChip');
const latencyBadge    = $('latencyBadge');
const redirectSection = $('redirectSection');
const redirectChain   = $('redirectChain');
const featureGrid     = $('featureGrid');
const urlInput        = $('urlInput');
const manualScanBtn   = $('manualScanBtn');
const expandFirst     = $('expandFirst');
const spinner         = $('spinner');
const spinnerText     = $('spinnerText');
const errorBox        = $('errorBox');

// Page tab
const scanPageBtn   = $('scanPageBtn');
const pageLinkCount = $('pageLinkCount');
const summaryPills  = $('summaryPills');
const safeCount     = $('safeCount');
const susCount      = $('susCount');
const malCount      = $('malCount');
const linkList      = $('linkList');

// History tab
const historyList   = $('historyList');
const clearHistoryBtn = $('clearHistoryBtn');
const historyEmpty  = $('historyEmpty');

// Settings
const settingsBtn     = $('settingsBtn');
const settingsPanel   = $('settingsPanel');
const closeSettingsBtn= $('closeSettingsBtn');
const apiUrlInput     = $('apiUrlInput');
const saveSettingsBtn = $('saveSettingsBtn');
const settingsSaved   = $('settingsSaved');

// ── Init ───────────────────────────────────────────────────
(async () => {
  const stored = await chrome.storage.local.get(['apiBase']);
  if (stored.apiBase) API_BASE = stored.apiBase;
  apiUrlInput.value = API_BASE;

  // Load current tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    const rootDomain = getRootDomain(tab.url);
    currentUrlText.textContent = rootDomain;
    currentUrlText.title = tab.url; // full URL in tooltip
    // Auto-scan current page (root domain only)
    await runScan(rootDomain, false);
  }

  renderHistory();
})();

// ── Tab switching ──────────────────────────────────────────
tabs.forEach(btn => {
  btn.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    tabPanes.forEach(p => { p.classList.add('hidden'); p.classList.remove('active'); });
    btn.classList.add('active');
    $(`tab-${btn.dataset.tab}`).classList.remove('hidden');
    $(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

// ── Scan current page button ───────────────────────────────
scanCurrentBtn.addEventListener('click', async () => {
  const url = currentUrlText.textContent;
  if (url && url !== 'Loading...') await runScan(getRootDomain(url), false);
});

// ── Manual scan button ─────────────────────────────────────
manualScanBtn.addEventListener('click', async () => {
  const raw = urlInput.value.trim();
  if (!raw) return;
  // For shortened URLs we must expand first to find the real root domain
  const doExpand = expandFirst.checked && isShortened(raw);
  const url = doExpand ? raw : getRootDomain(raw);
  await runScan(url, doExpand);
});
urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') manualScanBtn.click();
});

// ── Core scan function ─────────────────────────────────────
async function runScan(url, expand) {
  showSpinner(expand ? 'Expanding URL...' : 'Scanning...');
  hideError();
  resultCard.classList.add('hidden');

  try {
    let finalUrl = url;
    let chain = null;

    // Step 1: expand if needed (shortened URLs only), then extract root domain
    if (expand) {
      try {
        const expRes = await apiFetch('/expand-url', { url });
        if (expRes.expansion_successful) {
          finalUrl = getRootDomain(expRes.final_url);
          chain = expRes.redirect_chain;
        }
        spinnerText.textContent = 'Scanning expanded URL...';
      } catch (_) { /* fall through to original url */ }
    }

    // Step 2: classify-detail
    const result = await apiFetch('/classify-detail', { url: finalUrl });
    currentScanResult = result;

    // Render result card
    renderResult(result, url, chain);
    saveHistory(result, url);
    renderHistory();

  } catch (err) {
    showError(`Request failed: ${err.message}\nEnsure the backend is running at ${API_BASE}`);
  } finally {
    hideSpinner();
  }
}

// ── Render result card ─────────────────────────────────────
function renderResult(result, originalUrl, chain) {
  resultCard.classList.remove('hidden');

  const v = result.verdict || 'unknown';
  const conf = Math.round((result.confidence ?? 0) * 100);
  const tier = result.exit_tier || 'T2-DistilBERT';
  const ms   = result.latency_ms ?? '—';

  // Badge
  verdictBadge.className = 'verdict-badge';
  verdictBadge.classList.add(`badge-${v}`);
  verdictBadge.textContent = v.toUpperCase();

  // URL text
  const displayUrl = result.url || originalUrl;
  verdictUrl.textContent = displayUrl;
  verdictUrl.title = displayUrl;
  verdictDetail.textContent = result.reasoning || '';

  // Confidence ring
  const colour = v === 'safe' ? '#22c55e' : v === 'malicious' ? '#ef4444' : '#f59e0b';
  confArc.setAttribute('stroke', colour);
  confArc.setAttribute('stroke-dasharray', `${conf} ${100 - conf}`);
  confPct.textContent = `${conf}%`;

  // Tier
  tierChip.textContent = tier;
  latencyBadge.textContent = `${ms} ms`;

  // Redirect chain
  if (chain && chain.length > 1) {
    redirectSection.classList.remove('hidden');
    redirectChain.innerHTML = chain.map(u =>
      `<li title="${u}">${truncate(u, 48)}</li>`).join('');
  } else {
    redirectSection.classList.add('hidden');
  }

  // Features
  const feats = result.features || {};
  featureGrid.innerHTML = '';
  const featDefs = [
    ['HTTPS',     feats.has_https,          v => v ? 'Yes' : 'No',  v => v ? 'good' : 'bad'],
    ['Length',    feats.url_length,          v => v,                  v => v > 100 ? 'bad' : ''],
    ['Entropy',   feats.url_entropy,         v => v?.toFixed(2),      v => v > 4.5 ? 'bad' : ''],
    ['TLD Susp.', feats.tld_suspicion,       v => v ? 'Yes' : 'No',  v => v ? 'bad' : 'good'],
    ['IP Host',   feats.has_ip,              v => v ? 'Yes' : 'No',  v => v ? 'bad' : 'good'],
    ['@ Symbol',  feats.has_at_symbol,       v => v ? 'Yes' : 'No',  v => v ? 'bad' : ''],
    ['Keyword',   feats.keyword_score,       v => (v*100).toFixed(0)+'%', v => v > .1 ? 'bad' : ''],
    ['Subdomain', feats.subdomain_depth,     v => v,                  v => v > 2 ? 'bad' : ''],
  ];
  featDefs.forEach(([key, val, fmt, cls]) => {
    if (val === undefined) return;
    const el = document.createElement('div');
    el.className = 'feat-pill';
    const c = cls(val);
    el.innerHTML = `<span class="feat-key">${key}</span><span class="feat-val ${c}">${fmt(val)}</span>`;
    featureGrid.appendChild(el);
  });
}

// ── Page Link Scanner ──────────────────────────────────────
scanPageBtn.addEventListener('click', async () => {
  linkList.innerHTML = '';
  summaryPills.classList.add('hidden');

  // Ask content script for all links on the page
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let links = [];
  try {
    const resp = await chrome.tabs.sendMessage(tab.id, { type: 'GET_LINKS' });
    links = resp?.links || [];
  } catch (_) {
    // Content script might not be injected yet — inject manually
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content/content.js'] });
    try {
      const resp = await chrome.tabs.sendMessage(tab.id, { type: 'GET_LINKS' });
      links = resp?.links || [];
    } catch (e) { showError('Cannot read links on this page.'); return; }
  }

  if (!links.length) { pageLinkCount.textContent = 'No links found on this page.'; return; }
  pageLinkCount.textContent = `Found ${links.length} link${links.length > 1 ? 's' : ''} — scanning...`;

  let safe = 0, sus = 0, mal = 0;

  // Render placeholders
  const items = links.slice(0, 50).map(url => {
    const div = document.createElement('div');
    div.className = 'link-item';
    div.innerHTML = `
      <span class="link-dot dot-pend"></span>
      <span class="link-url" title="${url}">${truncate(url, 45)}</span>
      <span class="link-conf">…</span>`;
    linkList.appendChild(div);
    return { url, div };
  });

  summaryPills.classList.remove('hidden');

  // Scan each (root domain only)
  for (const { url, div } of items) {
    try {
      const r = await apiFetch('/classify', { url: getRootDomain(url) });
      const v = r.verdict || 'unknown';
      const c = Math.round((r.confidence ?? 0) * 100);
      const dot = div.querySelector('.link-dot');
      const conf = div.querySelector('.link-conf');
      dot.className = `link-dot dot-${v === 'safe' ? 'safe' : v === 'malicious' ? 'mal' : 'sus'}`;
      conf.textContent = `${c}%`;
      if (v === 'safe') safe++;
      else if (v === 'malicious') { mal++; div.classList.add('mal'); }
      else { sus++; div.classList.add('sus'); }
      safeCount.textContent = safe;
      susCount.textContent  = sus;
      malCount.textContent  = mal;
    } catch (_) {
      div.querySelector('.link-conf').textContent = 'err';
    }
  }

  pageLinkCount.textContent =
    `Scanned ${items.length} link${items.length > 1 ? 's' : ''}`;
});

// ── History ────────────────────────────────────────────────
function saveHistory(result, originalUrl) {
  chrome.storage.local.get(['history'], ({ history = [] }) => {
    const entry = {
      url: originalUrl,
      verdict: result.verdict,
      confidence: result.confidence,
      time: Date.now(),
    };
    history.unshift(entry);
    if (history.length > 30) history.length = 30;
    chrome.storage.local.set({ history });
  });
}

function renderHistory() {
  chrome.storage.local.get(['history'], ({ history = [] }) => {
    historyList.innerHTML = '';
    if (!history.length) {
      historyEmpty.classList.remove('hidden');
      return;
    }
    historyEmpty.classList.add('hidden');
    history.forEach(entry => {
      const v = entry.verdict || 'unknown';
      const conf = Math.round((entry.confidence ?? 0) * 100);
      const div = document.createElement('div');
      div.className = 'history-item';
      div.innerHTML = `
        <span class="history-verdict badge-${v}">${v.toUpperCase()}</span>
        <span class="history-url" title="${entry.url}">${truncate(entry.url, 36)}</span>
        <span class="history-time">${timeAgo(entry.time)}</span>`;
      div.addEventListener('click', () => {
        urlInput.value = entry.url;
        // Switch to scan tab
        tabs.forEach(t => t.classList.remove('active'));
        tabPanes.forEach(p => { p.classList.add('hidden'); p.classList.remove('active'); });
        document.querySelector('[data-tab="scan"]').classList.add('active');
        $('tab-scan').classList.remove('hidden');
        $('tab-scan').classList.add('active');
        manualScanBtn.click();
      });
      historyList.appendChild(div);
    });
  });
}

clearHistoryBtn.addEventListener('click', () => {
  chrome.storage.local.set({ history: [] }, renderHistory);
});

// ── Settings ───────────────────────────────────────────────
settingsBtn.addEventListener('click', () => settingsPanel.classList.remove('hidden'));
closeSettingsBtn.addEventListener('click', () => settingsPanel.classList.add('hidden'));

saveSettingsBtn.addEventListener('click', () => {
  const val = apiUrlInput.value.trim().replace(/\/$/, '');
  if (!val) return;
  API_BASE = val;
  chrome.storage.local.set({ apiBase: val }, () => {
    settingsSaved.classList.remove('hidden');
    setTimeout(() => settingsSaved.classList.add('hidden'), 1500);
  });
});

// ── Helpers ────────────────────────────────────────────────
async function apiFetch(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`${res.status} ${t.slice(0, 80)}`);
  }
  return res.json();
}

const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'adf.ly','bit.do','lnkd.in','short.link','rb.gy','cutt.ly','v.gd',
  'shorturl.at','tiny.cc','bl.ink','snip.ly','clk.sh','yourls.org',
]);
function isShortened(url) {
  try {
    const host = new URL(url.startsWith('http') ? url : 'https://'+url).hostname.replace('www.','');
    return SHORTENERS.has(host);
  } catch { return false; }
}

/**
 * Extract root domain from a URL: strips path, query, and fragment.
 * e.g. "https://claude.ai/chat/abc?x=1" → "https://claude.ai"
 */
function getRootDomain(url) {
  try {
    const parsed = new URL(url.startsWith('http') ? url : 'https://' + url);
    return `${parsed.protocol}//${parsed.hostname}`;
  } catch {
    return url; // return as-is if parsing fails
  }
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
  return `${Math.floor(diff/86400000)}d ago`;
}

function showSpinner(msg) {
  spinnerText.textContent = msg;
  spinner.classList.remove('hidden');
}
function hideSpinner() { spinner.classList.add('hidden'); }
function showError(msg) { errorBox.textContent = msg; errorBox.classList.remove('hidden'); }
function hideError() { errorBox.classList.add('hidden'); }
