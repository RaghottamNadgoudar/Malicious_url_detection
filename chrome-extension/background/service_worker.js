/* ──────────────────────────────────────────────────────────────
   service_worker.js — DAA Shield Background Service Worker
   Responsibilities:
   - Context menu: right-click any link → "Check with DAA Shield"
   - Extension badge: colored dot for current tab verdict
   - Message relay for popup ↔ content script
────────────────────────────────────────────────────────────── */

const DEFAULT_API = 'http://localhost:8002';

// ── Context Menu Setup ─────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id:       'daa-check-link',
    title:    '🔍 Check Link Safety',
    contexts: ['link'],
  });
  chrome.contextMenus.create({
    id:       'daa-check-page',
    title:    '🔍 Check This Page',
    contexts: ['page'],
  });
});

// ── Context Menu Click Handler ─────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.menuItemId === 'daa-check-link'
    ? info.linkUrl
    : info.pageUrl;

  if (!url) return;

  const { apiBase = DEFAULT_API } = await chrome.storage.local.get(['apiBase']);

  // Open the popup with the URL pre-filled by sending a message
  // (Popups can't be opened programmatically in MV3 — we store it for the popup to pick up)
  await chrome.storage.local.set({ pendingUrl: url });

  // Optionally show a notification badge
  await classifyAndBadge(url, tab.id, apiBase);
});

// ── Tab Update: badge current page ─────────────────────────
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) await classifyAndBadge(tab.url, tabId);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    await classifyAndBadge(tab.url, tabId);
  }
});

// ── Badge Helper ───────────────────────────────────────────
async function classifyAndBadge(url, tabId, apiBase) {
  if (!apiBase) {
    const stored = await chrome.storage.local.get(['apiBase']);
    apiBase = stored.apiBase || DEFAULT_API;
  }

  // Skip chrome:// and extension pages
  if (!url.startsWith('http')) {
    setBadge(tabId, '', '#94a3b8');
    return;
  }

  try {
    const res = await fetch(`${apiBase}/classify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error('API error');
    const data = await res.json();

    const colours = {
      safe:       '#22c55e',
      suspicious: '#f59e0b',
      malicious:  '#ef4444',
    };
    const labels = { safe: '✓', suspicious: '!', malicious: '✕' };

    setBadge(
      tabId,
      labels[data.verdict] || '?',
      colours[data.verdict] || '#94a3b8'
    );

    // Cache verdict for this tab
    await chrome.storage.local.set({ [`badge_${tabId}`]: data.verdict });

  } catch (_) {
    setBadge(tabId, '', '#94a3b8');
  }
}

function setBadge(tabId, text, colour) {
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: colour, tabId });
}
