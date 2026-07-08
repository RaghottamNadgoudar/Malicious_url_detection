/* ──────────────────────────────────────────────────────────────
   content.js — DAA Shield Content Script
   Responsibilities:
   - Respond to GET_LINKS messages from the popup (page scanner)
   - Highlight malicious links inline on the page (after page scan)
   - Respond to HIGHLIGHT_LINKS message with results
────────────────────────────────────────────────────────────── */

// Listen for messages from popup
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'GET_LINKS') {
    const anchors = Array.from(document.querySelectorAll('a[href]'));
    const links = anchors
      .map(a => a.href)
      .filter(href => href.startsWith('http'))
      .filter((v, i, arr) => arr.indexOf(v) === i) // unique
      .slice(0, 50);
    sendResponse({ links });
  }

  if (msg.type === 'HIGHLIGHT_LINKS') {
    // results: { url, verdict }[]
    const results = msg.results || [];
    const map = Object.fromEntries(results.map(r => [r.url, r.verdict]));

    document.querySelectorAll('a[href]').forEach(a => {
      const v = map[a.href];
      if (!v) return;
      if (v === 'malicious') {
        a.style.outline = '2px solid #ef4444';
        a.style.borderRadius = '3px';
        a.title = `⚠️ DAA Shield: MALICIOUS — ${a.href}`;
      } else if (v === 'suspicious') {
        a.style.outline = '2px solid #f59e0b';
        a.style.borderRadius = '3px';
        a.title = `⚠️ DAA Shield: SUSPICIOUS — ${a.href}`;
      }
    });

    // Add a small summary bar at the top of the page
    const existing = document.getElementById('daa-shield-bar');
    if (existing) existing.remove();

    const malCount = results.filter(r => r.verdict === 'malicious').length;
    const susCount = results.filter(r => r.verdict === 'suspicious').length;

    if (malCount > 0 || susCount > 0) {
      const bar = document.createElement('div');
      bar.id = 'daa-shield-bar';
      bar.style.cssText = `
        position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
        background: #fef2f2; border-bottom: 2px solid #fca5a5;
        color: #991b1b; font-family: system-ui, sans-serif;
        font-size: 13px; font-weight: 600;
        padding: 8px 16px; display: flex; align-items: center;
        justify-content: space-between; box-shadow: 0 2px 8px rgba(0,0,0,.15);
      `;
      bar.innerHTML = `
        <span>🛡️ DAA Shield: ${malCount} malicious link${malCount !== 1 ? 's' : ''}, 
        ${susCount} suspicious link${susCount !== 1 ? 's' : ''} found on this page.</span>
        <button id="daa-shield-close" style="background:none;border:none;font-size:16px;cursor:pointer;color:#991b1b;">✕</button>
      `;
      document.body.prepend(bar);
      document.getElementById('daa-shield-close').addEventListener('click', () => bar.remove());
    }

    sendResponse({ ok: true });
  }

  return true; // keep message channel open for async
});
