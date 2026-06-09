/**
 * URL Shield – Warning Page Logic
 *
 * DAA: Decision Tree pattern — each branch maps to a clear action:
 *   malicious + confirmed → Block (default)
 *   user chooses "proceed" → add exception, navigate
 *   user chooses "back"    → history.back()
 *   user chooses "report"  → flag as false-positive
 */

(function () {
  'use strict';

  // Parse query params
  const params  = new URLSearchParams(window.location.search);
  const target  = params.get('target') || '';
  const prob    = parseInt(params.get('prob') || '0', 10);
  const conf    = params.get('conf') || 'low';

  // Populate UI
  document.getElementById('target-url').textContent = target || 'Unknown URL';
  document.getElementById('stat-prob').textContent   = `${prob}%`;
  document.getElementById('stat-conf').textContent   = conf.charAt(0).toUpperCase() + conf.slice(1);

  // ── Decision Tree: Action handlers ──────────────────────────────────────

  // Branch 1: Go Back (safe – default recommended action)
  document.getElementById('btn-back').addEventListener('click', () => {
    history.back();
    // Fallback if no history
    setTimeout(() => { window.location.href = 'chrome://newtab'; }, 500);
  });

  // Branch 2: Proceed Anyway (user accepts risk)
  document.getElementById('btn-proceed').addEventListener('click', () => {
    if (!target) return;

    const confirmed = window.confirm(
      `⚠️ You are about to visit a URL classified as MALICIOUS (${prob}% threat probability).\n\n${target}\n\nAre you absolutely sure?`
    );
    if (!confirmed) return;

    // Notify background to add exception (valid 1 hour)
    chrome.runtime.sendMessage({ type: 'PROCEED_ANYWAY', url: target }, () => {
      window.location.href = target;
    });
  });

  // Branch 3: Report False Positive
  document.getElementById('btn-report').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'REPORT_FALSE_POSITIVE', url: target }, () => {
      document.getElementById('btn-report').style.display = 'none';
      const thanks = document.createElement('p');
      thanks.className = 'report-thanks';
      thanks.textContent = '✅ Thank you! This URL has been flagged for review.';
      document.querySelector('.actions').insertAdjacentElement('afterend', thanks);
    });
  });

})();
