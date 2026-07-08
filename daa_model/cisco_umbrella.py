"""
cisco_umbrella.py — Cisco Umbrella Investigate API v2 Client
=============================================================
Used as the FIRST preprocessing tier in pipeline_bert.py.

Pipeline position:
    URL → [Umbrella Investigate] → [Whitelist] → [DistilBERT] → verdict

What Umbrella returns per domain:
  • status  : -1 = malicious, 1 = safe, 0 = undetermined
  • categories : e.g. {"Malware":68, "Command and Control":150}
  • security indicators: dga_score, fastflux, spam, botnet, etc.

Key design decisions:
  1. NEVER blocks inference on network failure — all errors return UmbrellaResult(source="unavailable")
  2. TTL-based in-process LRU cache (default 600s) — same domain = one API call per 10 minutes
  3. Configurable timeout (default 2.5s) — latency budget for preprocessing
  4. Reads token from env var UMBRELLA_INVESTIGATE_TOKEN (set in .env or shell)

Setup:
  1. Log into Cisco Umbrella dashboard → Investigate → API Access → Generate Token
  2. export UMBRELLA_INVESTIGATE_TOKEN="your-token-here"
     (or add to daa_model/.env and load via python-dotenv)

Umbrella API references:
  Base URL : https://api.umbrella.com/investigate/v2
  Auth     : Authorization: Bearer <token>
  Endpoints used:
    GET /domains/categorization/{domain}?showLabels   → status + categories
    GET /security/name/{domain}                       → DGA / spam / botnet scores
"""

from __future__ import annotations
import os
import time
import logging
import threading
import functools
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests
import tldextract

logger = logging.getLogger(__name__)

# ── API constants ─────────────────────────────────────────────────────────────
_BASE_URL = "https://api.umbrella.com/investigate/v2"
_TOKEN_ENV = "UMBRELLA_INVESTIGATE_TOKEN"
_DEFAULT_TIMEOUT = 2.5        # seconds — fail fast to not stall DistilBERT
_CACHE_TTL = 600              # seconds — 10-minute TTL per domain

# Umbrella status values
_STATUS_MALICIOUS = -1
_STATUS_SAFE      =  1
_STATUS_UNKNOWN   =  0

# Umbrella security-score thresholds for DGA / spam heuristics
_DGA_THRESHOLD   = 0.80
_SPAM_THRESHOLD  = 0.60


# ── Result dataclass ──────────────────────────────────────────────────────────
@dataclass
class UmbrellaResult:
    """
    Normalised result from the Umbrella Investigate API.

    Attributes
    ----------
    domain      : bare registrable domain queried
    status      : -1 malicious | 0 unknown | 1 safe | None = not queried
    categories  : dict of category_name → category_id  (e.g. {"Malware": 68})
    security    : raw security indicators dict (DGA, spam, botnet, fastflux …)
    verdict     : "malicious" | "safe" | "unknown" | "unavailable"
    confidence  : float 0–1 derived from status + security scores
    source      : "umbrella" | "unavailable" | "cached"
    latency_ms  : round-trip time in milliseconds
    error       : error message if unavailable
    """
    domain:      str     = ""
    status:      Optional[int] = None
    categories:  dict    = field(default_factory=dict)
    security:    dict    = field(default_factory=dict)
    verdict:     str     = "unknown"
    confidence:  float   = 0.0
    source:      str     = "unavailable"
    latency_ms:  float   = 0.0
    error:       str     = ""


# ── In-process LRU cache with TTL ────────────────────────────────────────────
class _TTLCache:
    """Thread-safe dict with per-entry expiry."""
    def __init__(self, ttl: float = _CACHE_TTL):
        self._store: dict[str, tuple[UmbrellaResult, float]] = {}
        self._ttl  = ttl
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[UmbrellaResult]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            result, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            r = UmbrellaResult(**result.__dict__)
            r.source = "cached"
            return r

    def set(self, key: str, value: UmbrellaResult) -> None:
        with self._lock:
            self._store[key] = (value, time.monotonic() + self._ttl)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


_cache = _TTLCache()


# ── Main client class ─────────────────────────────────────────────────────────
class UmbrellaClient:
    """
    Thin client for the Cisco Umbrella Investigate v2 API.

    Usage:
        client = UmbrellaClient()          # reads UMBRELLA_INVESTIGATE_TOKEN
        result = client.lookup("http://paypal-secure.tk/login")
        print(result.verdict, result.confidence)
    """

    def __init__(
        self,
        token:   Optional[str] = None,
        timeout: float = _DEFAULT_TIMEOUT,
        cache_ttl: float = _CACHE_TTL,
    ):
        self._token   = token or os.getenv(_TOKEN_ENV, "")
        self._timeout = timeout
        self._cache   = _TTLCache(ttl=cache_ttl)
        self._session = requests.Session()
        if self._token:
            self._session.headers.update({
                "Authorization": f"Bearer {self._token}",
                "Accept":        "application/json",
            })
        else:
            logger.warning(
                "[Umbrella] %s not set — Umbrella lookups will be skipped. "
                "Set this env var to enable the Tier-0 reputation gate.", _TOKEN_ENV
            )

    @property
    def available(self) -> bool:
        """True if an API token is configured."""
        return bool(self._token)

    # ── Public API ────────────────────────────────────────────────────────────
    def lookup(self, url: str) -> UmbrellaResult:
        """
        Query Umbrella Investigate for the domain in `url`.
        Always returns an UmbrellaResult — never raises.
        On any error → source="unavailable", verdict="unknown".
        """
        if not self.available:
            return UmbrellaResult(source="unavailable",
                                  error=f"{_TOKEN_ENV} not configured")

        domain = self._extract_domain(url)
        if not domain:
            return UmbrellaResult(source="unavailable",
                                  error="Could not extract domain")

        # Cache hit
        cached = self._cache.get(domain)
        if cached is not None:
            return cached

        # Live lookup
        result = self._fetch(domain)
        if result.source == "umbrella":          # only cache successful results
            self._cache.set(domain, result)
        return result

    def lookup_batch(self, urls: list[str]) -> list[UmbrellaResult]:
        """Look up multiple URLs (sequential, respects cache)."""
        return [self.lookup(u) for u in urls]

    # ── Internal helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract bare registrable domain using tldextract (handles edu.in etc.)."""
        try:
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            if ext.domain:
                return ext.domain
            # Fall back to urlparse netloc
            host = urlparse(url).netloc.split(':')[0]
            return host.lstrip('www.') if host.startswith('www.') else host
        except Exception:
            return ""

    def _fetch(self, domain: str) -> UmbrellaResult:
        """
        Call both Umbrella endpoints and merge results into one UmbrellaResult.

          1. GET /domains/categorization/{domain}?showLabels
             → { domain: { status, security_categories, content_categories } }

          2. GET /security/name/{domain}
             → { dga_score, popularity, fastflux, spam, … }
        """
        t0 = time.monotonic()
        try:
            cat_data = self._get_categorization(domain)
            sec_data = self._get_security(domain)
        except requests.exceptions.Timeout:
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error="Umbrella API timeout",
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )
        except requests.exceptions.ConnectionError as e:
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error=f"Connection error: {e}",
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )
        except Exception as e:
            logger.debug("[Umbrella] Unexpected error for %s: %s", domain, e)
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error=str(e),
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )

        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        return self._build_result(domain, cat_data, sec_data, latency_ms)

    def _get_categorization(self, domain: str) -> dict:
        url = f"{_BASE_URL}/domains/categorization/{domain}?showLabels"
        resp = self._session.get(url, timeout=self._timeout)
        resp.raise_for_status()
        data = resp.json()
        # API returns { "domain": { "status": int, "security_categories": [...], ... } }
        # or just { "status": int, ... } depending on API version
        if domain in data:
            return data[domain]
        return data   # fallback: whole body is the domain record

    def _get_security(self, domain: str) -> dict:
        url = f"{_BASE_URL}/security/name/{domain}"
        resp = self._session.get(url, timeout=self._timeout)
        if resp.status_code == 404:
            return {}        # domain not in threat intel DB — not necessarily safe
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _build_result(
        domain: str,
        cat_data: dict,
        sec_data: dict,
        latency_ms: float,
    ) -> UmbrellaResult:
        """
        Merge categorization + security data → UmbrellaResult with verdict.

        Scoring logic
        ─────────────
        status == -1  → immediately malicious (Umbrella has blocked this domain)
        status ==  1  → candidate for safe, but still check security scores
        status ==  0  → unknown, use security scores only

        Security score boosting:
          dga_score > 0.80   → +0.35 (algorithmically generated domain)
          spam       > 0.60  → +0.20
          fastflux   present → +0.25 (IP changes rapidly — bot infra pattern)
          botnet     present → +0.40
        """
        # --- Extract status ---
        status = cat_data.get("status", _STATUS_UNKNOWN)

        # --- Extract categories ---
        sec_cats    = cat_data.get("security_categories", [])
        cont_cats   = cat_data.get("content_categories", [])
        all_cats    = {}
        for c in sec_cats:
            if isinstance(c, str):
                all_cats[c] = -1          # label only (showLabels=true)
            elif isinstance(c, dict):
                all_cats.update(c)

        # --- Security indicator scores ---
        dga_score  = float(sec_data.get("dga_score",  0) or 0)
        spam_score = float(sec_data.get("spam",        0) or 0)
        fastflux   = bool(sec_data.get("fastflux",  False))
        botnet     = bool(sec_data.get("botnet",     False))
        # Newer API versions call it "securerank2" (higher = more malicious)
        securerank = float(sec_data.get("securerank2", 0) or 0)

        # --- Derive base confidence from status ---
        if status == _STATUS_MALICIOUS:
            conf = 0.92
        elif status == _STATUS_SAFE:
            conf = 0.08            # lean safe but still check security signals
        else:
            conf = 0.45            # undetermined — rely on security scores

        # --- Boost confidence from security indicators ---
        if abs(dga_score) > _DGA_THRESHOLD:
            conf += 0.35
        if spam_score > _SPAM_THRESHOLD:
            conf += 0.20
        if fastflux:
            conf += 0.25
        if botnet:
            conf += 0.40
        if securerank > 70:        # 0–100 scale, higher = riskier
            conf += 0.15

        conf = float(min(max(conf, 0.0), 1.0))

        # --- Final verdict ---
        if status == _STATUS_MALICIOUS or conf >= 0.60:
            verdict = "malicious"
        elif status == _STATUS_SAFE and conf < 0.35:
            verdict = "safe"
        else:
            verdict = "unknown"      # let DistilBERT decide

        return UmbrellaResult(
            domain     = domain,
            status     = status,
            categories = all_cats,
            security   = {
                "dga_score":   dga_score,
                "spam":        spam_score,
                "fastflux":    fastflux,
                "botnet":      botnet,
                "securerank2": securerank,
            },
            verdict    = verdict,
            confidence = round(conf, 4),
            source     = "umbrella",
            latency_ms = latency_ms,
        )


# ── Module-level singleton ────────────────────────────────────────────────────
# pipeline_bert.py imports this directly — one client, one session, one cache.
_client: Optional[UmbrellaClient] = None
_client_lock = threading.Lock()


def get_client() -> UmbrellaClient:
    """Return the module-level singleton UmbrellaClient (lazy-init)."""
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = UmbrellaClient()
    return _client


def lookup(url: str) -> UmbrellaResult:
    """Convenience wrapper — call Umbrella for `url` using the singleton client."""
    return get_client().lookup(url)


# ── CLI smoke-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys, json

    token = os.getenv(_TOKEN_ENV)
    if not token:
        print(f"\n  [!] {_TOKEN_ENV} is not set.")
        print(f"  To use Umbrella lookups, run:")
        print(f"    export {_TOKEN_ENV}=your-token-here\n")

    client = UmbrellaClient()
    urls = sys.argv[1:] or [
        "https://rvce.edu.in",
        "https://google.com",
        "http://paypal-secure.tk",
        "http://phishing-login.ml",
        "http://192.168.1.1",
    ]

    print(f"\n{'Domain':<40} {'Status':>7}  {'Verdict':<12} {'Conf':>6}  {'Src':<12}  {'ms':>6}")
    print("─" * 95)
    for url in urls:
        r = client.lookup(url)
        status_str = {-1:"MALICIOUS", 1:"SAFE", 0:"UNKNOWN", None:"–"}[r.status]
        print(f"{r.domain:<40} {status_str:>9}  {r.verdict:<12} {r.confidence:>6.1%}"
              f"  {r.source:<12}  {r.latency_ms:>6.1f}ms")
        if r.categories:
            print(f"  Categories: {list(r.categories.keys())[:5]}")
        if r.error:
            print(f"  Error: {r.error}")
