/**
 * URL Shield – Background Service Worker v2.0 (Manifest V3)
 *
 * DAA Algorithms used:
 *   - Greedy: cache-first decision (skip scan if fresh result exists)
 *   - BFS-style queue: batch URL analysis order
 *   - Boyer-Moore inspired: history deduplication by URL fingerprint
 *   - Decision Tree: verdict → action mapping (warning page / notification)
 */

const API_BASE = 'http://localhost:5000';
const CACHE_TTL_MS = 10 * 60 * 1000;   // 10 minutes
const MAX_HISTORY = 500;                 // enlarged for dashboard & export
const WARNING_PAGE = chrome.runtime.getURL('warning.html');

// Domains/URLs where we NEVER analyze or show warnings
const BYPASS_DOMAINS = new Set([
  'localhost', '127.0.0.1', '::1', '0.0.0.0',
  'chrome.google.com',
]);
// Prefixes that should always be skipped entirely (no API call, no badge)
const SKIP_PREFIXES = [
  'chrome://', 'chrome-extension://', 'about:', 'edge://',
  'moz-extension://', 'file://',
  'http://localhost', 'https://localhost',
  'http://127.0.0.1', 'https://127.0.0.1',
  'http://0.0.0.0', 'https://0.0.0.0',
  'http://[::1]', 'https://[::1]',
];

// ── Badge helpers ─────────────────────────────────────────────────────────────

const BADGE_CONFIG = {
  safe:       { text: '✓', color: '#10b981' },
  suspicious: { text: '!', color: '#f59e0b' },
  uncertain:  { text: '?', color: '#6366f1' },
  malicious:  { text: '✕', color: '#ef4444' },
  scanning:   { text: '…', color: '#7c3aed' },
  error:      { text: 'E', color: '#6b7280' },
  offline:    { text: '—', color: '#374151' },
};

async function setBadge(tabId, status) {
  const cfg = BADGE_CONFIG[status] || BADGE_CONFIG.error;
  try {
    await chrome.action.setBadgeText({ tabId, text: cfg.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
    await chrome.action.setBadgeTextColor({ tabId, color: '#ffffff' });
  } catch (_) { /* tab closed */ }
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

function cacheKey(url) { return 'cache_' + btoa(unescape(encodeURIComponent(url))).slice(0, 80); }

async function getCached(url) {
  const key = cacheKey(url);
  return new Promise(resolve => {
    chrome.storage.local.get(key, data => {
      const entry = data[key];
      if (!entry) return resolve(null);
      if (Date.now() - entry.ts > CACHE_TTL_MS) {
        chrome.storage.local.remove(key);
        return resolve(null);
      }
      resolve(entry.result);
    });
  });
}

async function setCache(url, result) {
  const key = cacheKey(url);
  return new Promise(resolve =>
    chrome.storage.local.set({ [key]: { ts: Date.now(), result } }, resolve)
  );
}

// ── History helpers (Boyer-Moore-inspired dedup by URL fingerprint) ───────────

/**
 * Simple rolling hash fingerprint for fast dedup — analogous to
 * Boyer-Moore's bad-character pre-processing: we pre-process the URL
 * into a fixed-size key before doing O(1) lookup.
 */
function urlFingerprint(url) {
  let h = 0;
  for (let i = 0; i < Math.min(url.length, 64); i++) {
    h = (Math.imul(31, h) + url.charCodeAt(i)) | 0;
  }
  return h >>> 0;
}

async function appendHistory(entry) {
  return new Promise(resolve => {
    chrome.storage.local.get('scan_history', data => {
      const history = data.scan_history || [];
      const fp = urlFingerprint(entry.url);
      // Dedup: remove existing entry with same fingerprint (Boyer-Moore skip)
      const filtered = history.filter(h => urlFingerprint(h.url) !== fp);
      filtered.unshift({ ...entry, fp });
      const trimmed = filtered.slice(0, MAX_HISTORY);
      chrome.storage.local.set({ scan_history: trimmed }, resolve);
    });
  });
}

// ── Proceed-anyway exceptions ─────────────────────────────────────────────────

async function isExcepted(url) {
  return new Promise(resolve => {
    chrome.storage.local.get('proceed_exceptions', data => {
      const exc = data.proceed_exceptions || {};
      const key = cacheKey(url);
      const ts = exc[key];
      // Exception valid for 1 hour
      resolve(ts && (Date.now() - ts) < 60 * 60 * 1000);
    });
  });
}

async function addException(url) {
  return new Promise(resolve => {
    chrome.storage.local.get('proceed_exceptions', data => {
      const exc = data.proceed_exceptions || {};
      exc[cacheKey(url)] = Date.now();
      chrome.storage.local.set({ proceed_exceptions: exc }, resolve);
    });
  });
}

// ── Core analysis ─────────────────────────────────────────────────────────────

async function analyzeURL(url, tabId) {
  // Skip browser-internal, extension & local dev URLs
  if (!url) { await setBadge(tabId, 'offline'); return null; }

  const isSkipped = SKIP_PREFIXES.some(p => url.startsWith(p)) ||
                    url === WARNING_PAGE ||
                    url.startsWith(chrome.runtime.getURL(''));
  if (isSkipped) {
    await setBadge(tabId, 'safe');
    return null;
  }

  // Greedy: cache-first – skip API call if fresh result exists
  const cached = await getCached(url);
  if (cached) {
    const verdict = cached.final_verdict?.verdict || 'uncertain';
    await setBadge(tabId, verdict);
    notifyContentScript(tabId, cached);
    return cached;
  }

  await setBadge(tabId, 'scanning');

  try {
    const response = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const result = await response.json();
    const verdict = result.final_verdict?.verdict || 'uncertain';

    await setBadge(tabId, verdict);
    await setCache(url, result);

    await appendHistory({
      url,
      verdict,
      confidence:         result.final_verdict?.confidence || 'low',
      threat_probability: result.final_verdict?.threat_probability || 0,
      ts: Date.now(),
    });

    notifyContentScript(tabId, result);

    // Decision Tree: malicious → redirect to warning page
    if (verdict === 'malicious') {
      const excepted = await isExcepted(url);
      if (!excepted) {
        try {
          const hostname = new URL(url).hostname;
          if (!BYPASS_DOMAINS.has(hostname)) {
            const prob = Math.round((result.final_verdict?.threat_probability || 0) * 100);
            const warningUrl = `${WARNING_PAGE}?target=${encodeURIComponent(url)}&prob=${prob}&conf=${result.final_verdict?.confidence || 'low'}`;
            await chrome.tabs.update(tabId, { url: warningUrl });
          }
        } catch (_) {}
      }
    }

    return result;

  } catch (err) {
    const isNetwork = err.name === 'TypeError' || err.name === 'AbortError';
    await setBadge(tabId, isNetwork ? 'offline' : 'error');
    console.error('[URL Shield] Analysis failed:', err.message);
    return null;
  }
}

// ── Content script messaging ──────────────────────────────────────────────────

async function notifyContentScript(tabId, result) {
  const verdict = result?.final_verdict?.verdict;
  if (!verdict || verdict === 'safe') return;
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: 'URL_SHIELD_RESULT',
      verdict,
      confidence:         result.final_verdict?.confidence,
      threat_probability: result.final_verdict?.threat_probability,
      recommendation:     result.final_verdict?.recommendation,
      url:                result.url,
    });
  } catch (_) {}
}

// ── Context Menu ──────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id:       'urlshield-check-link',
    title:    '🛡️ Check with URL Shield',
    contexts: ['link'],
  });
  chrome.contextMenus.create({
    id:       'urlshield-check-page',
    title:    '🛡️ Scan this page with URL Shield',
    contexts: ['page'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.linkUrl || info.pageUrl || tab?.url;
  if (!url) return;

  // Show scanning notification
  chrome.notifications.create(`scan-${Date.now()}`, {
    type:     'basic',
    iconUrl:  'icons/icon48.png',
    title:    'URL Shield – Scanning…',
    message:  url.slice(0, 80),
    priority: 0,
  });

  const result = await analyzeURL(url, tab?.id || 0);
  const verdict = result?.final_verdict?.verdict || 'error';

  const NOTIF_STYLE = {
    safe:       { emoji: '✅', title: 'Safe URL' },
    uncertain:  { emoji: '🔍', title: 'Uncertain URL' },
    suspicious: { emoji: '⚠️', title: 'Suspicious URL' },
    malicious:  { emoji: '🚫', title: 'MALICIOUS URL DETECTED' },
    error:      { emoji: '⚡', title: 'Scan Failed' },
  };
  const style = NOTIF_STYLE[verdict] || NOTIF_STYLE.error;
  const prob = Math.round((result?.final_verdict?.threat_probability || 0) * 100);

  chrome.notifications.create(`result-${Date.now()}`, {
    type:     'basic',
    iconUrl:  'icons/icon48.png',
    title:    `${style.emoji} ${style.title}`,
    message:  `${url.slice(0, 60)} — Threat: ${prob}%`,
    priority: verdict === 'malicious' ? 2 : 1,
  });
});

// ── Tab event listeners ───────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url) return;
  await analyzeURL(tab.url, tabId);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url) return;
  const cached = await getCached(tab.url);
  if (cached) {
    await setBadge(tabId, cached.final_verdict?.verdict || 'uncertain');
  } else {
    await analyzeURL(tab.url, tabId);
  }
});

// ── Message handler ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'ANALYZE_URL') {
    const { url, tabId } = msg;
    analyzeURL(url, tabId || 0).then(result => sendResponse({ result }));
    return true;
  }

  if (msg.type === 'ANALYZE_BATCH') {
    // BFS-queue batch analysis for content script link scanner
    const { urls } = msg;
    fetch(`${API_BASE}/api/batch-analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ urls, top_k: urls.length }),
      signal:  AbortSignal.timeout(20000),
    })
      .then(r => r.json())
      .then(data => sendResponse({ data }))
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  if (msg.type === 'GET_HISTORY') {
    chrome.storage.local.get('scan_history', data =>
      sendResponse({ history: data.scan_history || [] })
    );
    return true;
  }

  if (msg.type === 'CLEAR_HISTORY') {
    chrome.storage.local.remove('scan_history', () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'CHECK_BACKEND') {
    fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(3000) })
      .then(r => sendResponse({ online: r.ok }))
      .catch(() => sendResponse({ online: false }));
    return true;
  }

  if (msg.type === 'PROCEED_ANYWAY') {
    addException(msg.url).then(() => sendResponse({ ok: true }));
    return true;
  }
});
