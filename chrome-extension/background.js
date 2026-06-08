/**
 * URL Shield – Background Service Worker (Manifest V3)
 * Handles auto-scanning on tab updates, badge management, and local cache.
 */

const API_BASE = 'http://localhost:5000';
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_HISTORY = 20;

// ── Badge helpers ─────────────────────────────────────────────────────────────

const BADGE_CONFIG = {
  safe:      { text: '✓',  color: '#10b981' },
  suspicious:{ text: '!',  color: '#f59e0b' },
  uncertain: { text: '?',  color: '#6366f1' },
  malicious: { text: '✕',  color: '#ef4444' },
  scanning:  { text: '…',  color: '#7c3aed' },
  error:     { text: 'E',  color: '#6b7280' },
  offline:   { text: '—',  color: '#374151' },
};

async function setBadge(tabId, status) {
  const cfg = BADGE_CONFIG[status] || BADGE_CONFIG.error;
  try {
    await chrome.action.setBadgeText({ tabId, text: cfg.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
    await chrome.action.setBadgeTextColor({ tabId, color: '#ffffff' });
  } catch (_) { /* tab may have closed */ }
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

function cacheKey(url) {
  return 'cache_' + btoa(url).slice(0, 80);
}

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
  return new Promise(resolve => {
    chrome.storage.local.set({ [key]: { ts: Date.now(), result } }, resolve);
  });
}

// ── History helpers ───────────────────────────────────────────────────────────

async function appendHistory(entry) {
  return new Promise(resolve => {
    chrome.storage.local.get('scan_history', data => {
      const history = data.scan_history || [];
      // Prevent duplicates for same URL within session
      const filtered = history.filter(h => h.url !== entry.url);
      filtered.unshift(entry);
      const trimmed = filtered.slice(0, MAX_HISTORY);
      chrome.storage.local.set({ scan_history: trimmed }, resolve);
    });
  });
}

// ── Core analysis function ────────────────────────────────────────────────────

async function analyzeURL(url, tabId) {
  // Skip browser-internal URLs
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
      url.startsWith('about:') || url.startsWith('edge://') || url.startsWith('moz-extension://')) {
    await setBadge(tabId, 'offline');
    return null;
  }

  // Check cache first
  const cached = await getCached(url);
  if (cached) {
    const verdict = cached.final_verdict?.verdict || 'uncertain';
    await setBadge(tabId, verdict);
    // Notify content script from cache
    notifyContentScript(tabId, cached);
    return cached;
  }

  // Show scanning badge
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

    // Update badge
    await setBadge(tabId, verdict);

    // Cache result
    await setCache(url, result);

    // Save to history
    await appendHistory({
      url,
      verdict,
      confidence: result.final_verdict?.confidence || 'low',
      threat_probability: result.final_verdict?.threat_probability || 0,
      ts: Date.now(),
    });

    // Notify content script to show banner if needed
    notifyContentScript(tabId, result);

    return result;

  } catch (err) {
    const isNetworkError = err.name === 'TypeError' || err.name === 'AbortError';
    await setBadge(tabId, isNetworkError ? 'offline' : 'error');
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
      confidence: result.final_verdict?.confidence,
      threat_probability: result.final_verdict?.threat_probability,
      recommendation: result.final_verdict?.recommendation,
      url: result.url,
    });
  } catch (_) {
    // Content script may not be injected yet (e.g., extension pages) — silently ignore
  }
}

// ── Tab event listeners ───────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url) return;
  await analyzeURL(tab.url, tabId);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url) return;

  // Check if we already have a cached result for this tab
  const cached = await getCached(tab.url);
  if (cached) {
    const verdict = cached.final_verdict?.verdict || 'uncertain';
    await setBadge(tabId, verdict);
  } else {
    await analyzeURL(tab.url, tabId);
  }
});

// ── Message handler (from popup) ─────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'ANALYZE_URL') {
    const { url, tabId } = msg;
    analyzeURL(url, tabId || 0).then(result => sendResponse({ result }));
    return true; // Keep channel open for async response
  }

  if (msg.type === 'GET_HISTORY') {
    chrome.storage.local.get('scan_history', data => {
      sendResponse({ history: data.scan_history || [] });
    });
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
});
