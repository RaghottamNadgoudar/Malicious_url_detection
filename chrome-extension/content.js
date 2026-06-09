/**
 * URL Shield – Content Script v2.0
 *
 * DAA Algorithms used:
 *   - BFS (Breadth-First Search): DOM traversal to collect all <a> links layer by layer
 *   - Greedy Selection: pick top-N links by heuristic suspicion score before sending batch
 *   - Heapsort (simulated via sort): prioritise most-suspicious links in UI chip
 *   - MutationObserver: handle SPA dynamic DOM changes (BFS re-trigger)
 */

(function () {
  'use strict';
  if (window.__urlShieldInjected) return;
  window.__urlShieldInjected = true;

  // ── Constants ──────────────────────────────────────────────────────────────

  const MAX_LINKS_PER_SCAN = 50;   // Greedy cap — scan top-50 links only
  const SCAN_DELAY_MS      = 1500; // Wait for page to settle

  const RISK_COLORS = {
    safe:       '#10b981',
    uncertain:  '#6366f1',
    suspicious: '#f59e0b',
    malicious:  '#ef4444',
  };

  const RISK_BG = {
    safe:       'rgba(16, 185, 129, 0.08)',
    uncertain:  'rgba(99, 102, 241, 0.08)',
    suspicious: 'rgba(245, 158, 11, 0.12)',
    malicious:  'rgba(239, 68, 68, 0.12)',
  };

  // ── State ──────────────────────────────────────────────────────────────────

  let bannerEl        = null;
  let scanChipEl      = null;
  let scanResults     = {};   // url → verdict
  let scanInProgress  = false;
  let pendingMutation = null;

  // ── Warning banner (page verdict) ─────────────────────────────────────────

  function createBanner(verdict, confidence, threatProb, recommendation) {
    if (bannerEl) bannerEl.remove();

    const threatPct  = Math.round((threatProb || 0) * 100);
    const confLabel  = (confidence || 'unknown').charAt(0).toUpperCase() + (confidence || '').slice(1);
    const isMalicious = verdict === 'malicious';
    const icon  = isMalicious ? '🚫' : '⚠️';
    const title = isMalicious ? 'Malicious URL Detected' : 'Suspicious URL Warning';
    const sub   = isMalicious
      ? `Our AI detected this page as dangerous (${threatPct}% threat probability).`
      : `This page shows suspicious characteristics (${threatPct}% threat probability).`;

    const banner = document.createElement('div');
    banner.id = 'url-shield-banner';
    banner.setAttribute('data-verdict', verdict);
    banner.innerHTML = `
      <div class="usb-inner">
        <div class="usb-left">
          <span class="usb-icon">${icon}</span>
          <div class="usb-text">
            <strong class="usb-title">${title}</strong>
            <span class="usb-subtitle">${sub}</span>
            <span class="usb-rec">${recommendation || ''}</span>
          </div>
        </div>
        <div class="usb-right">
          <div class="usb-badge">
            <span class="usb-badge-label">Confidence</span>
            <span class="usb-badge-value">${confLabel}</span>
          </div>
          <div class="usb-badge">
            <span class="usb-badge-label">Threat</span>
            <span class="usb-badge-value">${threatPct}%</span>
          </div>
          <button class="usb-dismiss" id="usb-dismiss-btn" title="Dismiss">✕</button>
        </div>
      </div>
      <div class="usb-progress">
        <div class="usb-progress-fill" style="width: ${threatPct}%"></div>
      </div>
    `;

    document.body.prepend(banner);
    bannerEl = banner;

    document.getElementById('usb-dismiss-btn').addEventListener('click', () => {
      banner.classList.add('usb-dismissed');
      setTimeout(() => banner.remove(), 400);
      bannerEl = null;
    });

    requestAnimationFrame(() => requestAnimationFrame(() => banner.classList.add('usb-visible')));
  }

  // ── BFS DOM link collector ─────────────────────────────────────────────────
  /**
   * BFS traversal of the DOM starting from document.body.
   * Collects all <a href> elements level by level.
   * Stops once MAX_LINKS_PER_SCAN unique http/https URLs are found.
   *
   * BFS is preferred over DFS here because links near the top of the page
   * (nav, main content) are more important than deeply nested footer links —
   * BFS naturally processes them first.
   */
  function bfsCollectLinks() {
    const queue     = [document.body];
    const visited   = new Set();
    const urls      = new Set();
    const linkEls   = new Map(); // url → [elements]

    while (queue.length > 0 && urls.size < MAX_LINKS_PER_SCAN * 3) {
      const node = queue.shift();
      if (!node || visited.has(node)) continue;
      visited.add(node);

      if (node.tagName === 'A') {
        const href = node.href;
        if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
          try {
            const clean = new URL(href).origin + new URL(href).pathname;
            if (!linkEls.has(clean)) linkEls.set(clean, []);
            linkEls.get(clean).push(node);
            urls.add(clean);
          } catch (_) {}
        }
      }

      for (const child of node.children) {
        if (!visited.has(child)) queue.push(child);
      }
    }

    return { urls: [...urls], linkEls };
  }

  // ── Greedy link prioritiser ────────────────────────────────────────────────
  /**
   * Greedy heuristic: score each URL and take top MAX_LINKS_PER_SCAN.
   * This avoids sending 500+ URLs to the API — a classic Greedy optimisation
   * (Greedy Technique, Unit IV of DAA syllabus).
   *
   * Scoring: +points for suspicious signals, pick highest-score first.
   */
  function greedyPrioritise(urls) {
    const SUSPICIOUS_TLDS = new Set(['.tk','.ml','.ga','.cf','.xyz','.top','.click','.loan','.work']);
    const KEYWORDS = ['login','verify','secure','update','bank','paypal','account','password','free','prize'];

    function heuristicScore(url) {
      let score = 0;
      const lower = url.toLowerCase();
      if (!lower.startsWith('https')) score += 20;
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) score += 40;
      if (url.includes('@')) score += 30;
      if (url.length > 100) score += 10;
      KEYWORDS.forEach(kw => { if (lower.includes(kw)) score += 15; });
      SUSPICIOUS_TLDS.forEach(tld => { if (lower.includes(tld)) score += 25; });
      const dots = (url.match(/\./g) || []).length;
      if (dots > 4) score += 10;
      return score;
    }

    // Sort descending by score (simulates heapsort priority-queue extraction)
    return urls
      .map(url => ({ url, score: heuristicScore(url) }))
      .sort((a, b) => b.score - a.score)
      .slice(0, MAX_LINKS_PER_SCAN)
      .map(x => x.url);
  }

  // ── Link highlighting ─────────────────────────────────────────────────────

  function highlightLink(el, verdict) {
    const color = RISK_COLORS[verdict] || '#6b7280';
    const bg    = RISK_BG[verdict]    || 'transparent';

    el.style.setProperty('outline',          `1.5px solid ${color}`,  'important');
    el.style.setProperty('border-radius',    '3px',                   'important');
    el.style.setProperty('background-color', bg,                      'important');
    el.style.setProperty('padding',          '0 2px',                 'important');
    el.dataset.urlshieldVerdict = verdict;

    // Tooltip
    el.title = `🛡️ URL Shield: ${verdict.toUpperCase()}${el.title ? ` | ${el.title}` : ''}`;
  }

  function applyHighlights(linkEls) {
    for (const [url, els] of linkEls.entries()) {
      const verdict = scanResults[url];
      if (verdict) {
        els.forEach(el => highlightLink(el, verdict));
      }
    }
  }

  // ── Scan summary chip ─────────────────────────────────────────────────────

  function showScanChip(counts, total) {
    if (scanChipEl) scanChipEl.remove();

    const threats = (counts.malicious || 0) + (counts.suspicious || 0);
    const safe    = counts.safe      || 0;
    const unc     = counts.uncertain || 0;

    const chip = document.createElement('div');
    chip.id = 'url-shield-scan-chip';
    chip.innerHTML = `
      <div class="ussc-header">
        <span class="ussc-logo">🛡️</span>
        <span class="ussc-title">URL Shield</span>
        <button class="ussc-close" id="ussc-close">✕</button>
      </div>
      <div class="ussc-stats">
        <div class="ussc-stat malicious" title="Malicious + Suspicious">
          <span class="ussc-num">${threats}</span>
          <span class="ussc-lbl">threats</span>
        </div>
        <div class="ussc-stat safe" title="Safe">
          <span class="ussc-num">${safe}</span>
          <span class="ussc-lbl">safe</span>
        </div>
        <div class="ussc-stat uncertain" title="Uncertain">
          <span class="ussc-num">${unc}</span>
          <span class="ussc-lbl">uncertain</span>
        </div>
      </div>
      <div class="ussc-footer">${total} links scanned</div>
    `;

    document.body.appendChild(chip);
    scanChipEl = chip;

    setTimeout(() => chip.classList.add('ussc-visible'), 50);

    document.getElementById('ussc-close').addEventListener('click', () => {
      chip.classList.remove('ussc-visible');
      setTimeout(() => chip.remove(), 350);
      scanChipEl = null;
    });
  }

  // ── Main scan flow ────────────────────────────────────────────────────────

  async function scanPageLinks() {
    if (scanInProgress) return;
    scanInProgress = true;

    try {
      // Step 1: BFS collect all links
      const { urls: allUrls, linkEls } = bfsCollectLinks();
      if (allUrls.length === 0) { scanInProgress = false; return; }

      // Step 2: Greedy select top URLs to scan
      const toScan = greedyPrioritise(allUrls);

      // Step 3: Batch request via background service worker
      const response = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(
          { type: 'ANALYZE_BATCH', urls: toScan },
          reply => {
            if (chrome.runtime.lastError) return reject(chrome.runtime.lastError);
            resolve(reply);
          }
        );
      });

      // Step 4: Parse results — top_threats is heapsort-ranked by backend
      const data = response?.data;
      if (!data) { scanInProgress = false; return; }

      const threats = data.top_threats || [];
      const counts  = { safe: 0, uncertain: 0, suspicious: 0, malicious: 0 };

      threats.forEach(item => {
        const url     = item.url || '';
        const verdict = item.verdict || item.final_verdict?.verdict || 'uncertain';
        // Normalise URL to pathname-only key (same as bfsCollectLinks)
        try {
          const clean = new URL(url).origin + new URL(url).pathname;
          scanResults[clean] = verdict;
        } catch (_) {
          scanResults[url] = verdict;
        }
        counts[verdict] = (counts[verdict] || 0) + 1;
      });

      // Mark unscanned links as uncertain
      allUrls.forEach(url => {
        if (!scanResults[url]) {
          scanResults[url] = 'uncertain';
          counts.uncertain = (counts.uncertain || 0) + 1;
        }
      });

      // Step 5: Apply highlights
      applyHighlights(linkEls);

      // Step 6: Show chip
      showScanChip(counts, toScan.length);

    } catch (err) {
      console.warn('[URL Shield] Link scan failed:', err.message);
    }

    scanInProgress = false;
  }

  // ── MutationObserver – re-scan on SPA navigation ──────────────────────────
  // (BFS re-trigger when new links are added to DOM)

  const mutationObs = new MutationObserver(() => {
    clearTimeout(pendingMutation);
    pendingMutation = setTimeout(() => {
      scanResults = {};       // clear stale results
      scanInProgress = false;
      scanPageLinks();
    }, 2000);
  });

  mutationObs.observe(document.body, { childList: true, subtree: true });

  // ── Message listener (from background) ───────────────────────────────────

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'URL_SHIELD_RESULT') {
      const { verdict, confidence, threat_probability, recommendation } = msg;
      if (verdict === 'malicious' || verdict === 'suspicious') {
        createBanner(verdict, confidence, threat_probability, recommendation);
      }
    }
  });

  // ── Bootstrap ──────────────────────────────────────────────────────────────

  setTimeout(scanPageLinks, SCAN_DELAY_MS);

})();
