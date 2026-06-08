/**
 * URL Shield – Content Script
 * Injected into all pages. Listens for analysis results from the background
 * service worker and shows warning banners for suspicious/malicious pages.
 */

(function () {
  'use strict';

  // Prevent double-injection
  if (window.__urlShieldInjected) return;
  window.__urlShieldInjected = true;

  let bannerEl = null;

  function createBanner(verdict, confidence, threatProb, recommendation, url) {
    // Remove existing banner
    if (bannerEl) bannerEl.remove();

    const isMalicious = verdict === 'malicious';
    const isSuspicious = verdict === 'suspicious';

    const id = 'url-shield-banner';
    const banner = document.createElement('div');
    banner.id = id;
    banner.setAttribute('data-verdict', verdict);

    const threatPct = Math.round((threatProb || 0) * 100);
    const confLabel = confidence ? confidence.charAt(0).toUpperCase() + confidence.slice(1) : 'Unknown';

    const icon = isMalicious ? '🚫' : '⚠️';
    const title = isMalicious ? 'Malicious URL Detected' : 'Suspicious URL Warning';
    const subtitle = isMalicious
      ? `Our AI detected this page as dangerous (${threatPct}% threat probability).`
      : `This page shows suspicious characteristics (${threatPct}% threat probability).`;

    banner.innerHTML = `
      <div class="usb-inner">
        <div class="usb-left">
          <span class="usb-icon">${icon}</span>
          <div class="usb-text">
            <strong class="usb-title">${title}</strong>
            <span class="usb-subtitle">${subtitle}</span>
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
          <button class="usb-dismiss" id="usb-dismiss-btn" title="Dismiss warning">✕</button>
        </div>
      </div>
      <div class="usb-progress">
        <div class="usb-progress-fill" style="width: ${threatPct}%"></div>
      </div>
    `;

    document.body.prepend(banner);
    bannerEl = banner;

    // Dismiss button
    document.getElementById('usb-dismiss-btn').addEventListener('click', () => {
      banner.classList.add('usb-dismissed');
      setTimeout(() => banner.remove(), 400);
      bannerEl = null;
    });

    // Animate in
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        banner.classList.add('usb-visible');
      });
    });
  }

  // Listen for messages from background service worker
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type !== 'URL_SHIELD_RESULT') return;

    const { verdict, confidence, threat_probability, recommendation, url } = msg;

    if (verdict === 'malicious' || verdict === 'suspicious') {
      createBanner(verdict, confidence, threat_probability, recommendation, url);
    }
  });
})();
