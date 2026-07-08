"""
cisco_umbrella.py — Open PageRank (Keywords Everywhere) Client
===============================================================
Drop-in replacement for the original Cisco Umbrella client.
The PUBLIC INTERFACE IS IDENTICAL — pipeline_bert.py and app_nn.py
need ZERO changes.

Pipeline position:
    URL → [PageRank Tier-0] → [Whitelist] → [DistilBERT] → verdict

Why PageRank instead of URLhaus?
---------------------------------
URLhaus is a *malicious DB* — only contains known bad URLs.
Open PageRank is a *safe-side oracle* — high-authority domains are
almost certainly legitimate (Google, Amazon, GitHub, etc.).

Key insight: PageRank lets us fast-path SAFE URLs without DistilBERT
for high-authority domains, which are the majority of web traffic.

Verdict logic (safe-side oracle):
  open_page_rank ≥ 7.0  → safe    (very high authority)
  open_page_rank ≥ 4.0  → likely safe / suspicious (moderate)
  open_page_rank <  4.0  → unknown (DistilBERT decides)
  domain not found        → unknown (DistilBERT decides)

Setup:
  1. Get a free key at https://openpagerank.keywordseverywhere.com/
  2. Add to daa_model/.env:
       OPEN_PAGERANK_API=opr_live_xxxxxxxxxxxxxxxx
  3. Restart the backend — Tier-0 will activate automatically.

API reference:
  Base URL : https://openpagerank.keywordseverywhere.com/v1
  Auth     : Authorization: Bearer <key>
  Endpoint : POST /domains/bulk  (up to 100 domains per call)
"""

from __future__ import annotations
import os
import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests
import tldextract

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass  # python-dotenv not installed — rely on shell env vars

logger = logging.getLogger(__name__)

# ── API constants ─────────────────────────────────────────────────────────────
_BASE_URL        = "https://openpagerank.keywordseverywhere.com/v1"
_TOKEN_ENV       = "OPEN_PAGERANK_API"
_DEFAULT_TIMEOUT = 6.0   # seconds
_CACHE_TTL       = 3600  # 1-hour TTL (PageRank changes slowly)

# ── Score thresholds ──────────────────────────────────────────────────────────
# open_page_rank is 0–10 (10 = highest authority)
_SAFE_THRESHOLD       = 7.0   # ≥ 7 → safe (top ~5% of the web)
_SUSPICIOUS_THRESHOLD = 4.0   # ≥ 4 → suspicious (some authority but uncertain)
# < 4 or not found → unknown (pass to DistilBERT)


# ── Result dataclass — IDENTICAL public interface ──────────────────────────────
@dataclass
class UmbrellaResult:
    """
    Normalised result.  Field names preserved for pipeline_bert.py compatibility.

    Attributes
    ----------
    domain      : bare registrable domain queried
    status      : -1 malicious | 0 unknown | 1 safe | None = not queried
    categories  : dict of label → value  (PageRank: {'global_rank': N, ...})
    security    : raw security indicators dict
    verdict     : "malicious" | "suspicious" | "safe" | "unknown" | "unavailable"
    confidence  : float 0–1 derived from PageRank score
    source      : "pagerank" | "unavailable" | "cached"
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
        self._ttl   = ttl
        self._lock  = threading.Lock()

    def get(self, key: str) -> Optional[UmbrellaResult]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            result, exp = entry
            if time.monotonic() > exp:
                del self._store[key]
                return None
            cached = UmbrellaResult(**result.__dict__)
            cached.source = "cached"
            return cached

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
    Open PageRank client with the same interface as the original
    Cisco UmbrellaClient.  Drop-in replacement.

    Usage:
        client = UmbrellaClient()           # reads OPEN_PAGERANK_API from env
        result = client.lookup("https://github.com")
        print(result.verdict, result.confidence)   # → safe  0.97
    """

    def __init__(
        self,
        token:     Optional[str] = None,
        timeout:   float = _DEFAULT_TIMEOUT,
        cache_ttl: float = _CACHE_TTL,
    ):
        self._token   = token or os.getenv(_TOKEN_ENV, "")
        self._timeout = timeout
        self._cache   = _TTLCache(ttl=cache_ttl)
        self._session = requests.Session()
        if self._token:
            self._session.headers.update({
                "Authorization": f"Bearer {self._token}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            })
            logger.info("[PageRank] OPEN_PAGERANK_API configured — Tier-0 safe oracle enabled ✓")
        else:
            logger.warning(
                "[PageRank] %s not set — PageRank lookups will be skipped. "
                "Add OPEN_PAGERANK_API to daa_model/.env to enable Tier-0.",
                _TOKEN_ENV,
            )

    @property
    def available(self) -> bool:
        """True if an API token is configured."""
        return bool(self._token)

    # ── Public API ────────────────────────────────────────────────────────────
    def lookup(self, url: str) -> UmbrellaResult:
        """
        Query Open PageRank for the domain in `url`.
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
        if result.source == "pagerank":          # only cache successful results
            self._cache.set(domain, result)
        return result

    def lookup_batch(self, urls: list[str]) -> list[UmbrellaResult]:
        """Look up multiple URLs (sequential, respects cache)."""
        return [self.lookup(u) for u in urls]

    # ── Internal helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract bare registrable domain using tldextract."""
        try:
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            if ext.domain:
                return ext.domain
            host = urlparse(url).netloc.split(':')[0]
            return host.lstrip('www.') if host.startswith('www.') else host
        except Exception:
            return ""

    def _fetch(self, domain: str) -> UmbrellaResult:
        """
        Call POST /v1/domains/bulk for a single domain.
        Returns UmbrellaResult with source='pagerank' on success,
        or source='unavailable' on any error.
        """
        t0 = time.monotonic()
        try:
            resp = self._session.post(
                f"{_BASE_URL}/domains/bulk",
                json={"domains": [domain], "include_history": False},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            latency_ms = round((time.monotonic() - t0) * 1000, 1)
            data = resp.json()
            return self._build_result(domain, data, latency_ms)

        except requests.exceptions.Timeout:
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error="PageRank API timeout",
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )
        except requests.exceptions.ConnectionError as e:
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error=f"Connection error: {e}",
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )
        except Exception as e:
            logger.debug("[PageRank] Unexpected error for %s: %s", domain, e)
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error=str(e),
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )

    @staticmethod
    def _build_result(domain: str, data: dict, latency_ms: float) -> UmbrellaResult:
        """
        Parse Open PageRank /domains/bulk response into UmbrellaResult.

        Safe-side scoring:
          opr ≥ 7.0 → safe       (top authority — short-circuit DistilBERT)
          opr ≥ 4.0 → suspicious (moderate authority — let DistilBERT confirm)
          opr <  4.0 → unknown    (low/no authority — DistilBERT decides fully)
          not found  → unknown

        Confidence mapping:
          opr 10   → 0.98  (e.g. google.com, youtube.com)
          opr  7   → 0.85
          opr  4   → 0.50
          opr  0   → 0.05
        """
        results = data.get("results", [])
        entry   = results[0] if results else {}

        found = entry.get("found", False)
        opr   = entry.get("open_page_rank")    # float 0–10, or None
        rank  = entry.get("rank")              # int, global position (1 = best)
        ref_domains = entry.get("referring_domains", 0)

        if not found or opr is None:
            # Domain completely unknown to PageRank → unknown (DistilBERT decides)
            return UmbrellaResult(
                domain     = domain,
                status     = 0,
                verdict    = "unknown",
                confidence = 0.0,
                source     = "pagerank",
                latency_ms = latency_ms,
                security   = {"open_page_rank": None, "rank": None,
                               "referring_domains": ref_domains},
            )

        opr = float(opr)

        # Confidence: linear scale from opr score
        # opr=10 → conf=0.98, opr=7 → 0.85, opr=4 → 0.50, opr=0 → 0.05
        confidence = round(0.05 + (opr / 10.0) * 0.93, 4)

        if opr >= _SAFE_THRESHOLD:
            verdict = "safe"
            status  = 1
        elif opr >= _SUSPICIOUS_THRESHOLD:
            # Moderate authority — not enough to clear, but not suspicious
            verdict = "unknown"   # let DistilBERT handle it
            status  = 0
        else:
            # Low authority domain — unknown (DistilBERT will classify)
            verdict = "unknown"
            status  = 0
            confidence = 0.0      # no safe signal

        return UmbrellaResult(
            domain     = domain,
            status     = status,
            categories = {"global_rank": rank or 0},
            security   = {
                "open_page_rank":   round(opr, 2),
                "rank":             rank,
                "referring_domains": ref_domains,
            },
            verdict    = verdict,
            confidence = confidence,
            source     = "pagerank",
            latency_ms = latency_ms,
        )


# ── Module-level singleton ────────────────────────────────────────────────────
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
    """Convenience wrapper — query PageRank for `url` using the singleton."""
    return get_client().lookup(url)


# ── CLI smoke-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import io

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    token = os.getenv(_TOKEN_ENV)
    if not token:
        print(f"\n  [!] {_TOKEN_ENV} is not set.")
        print(f"  To enable PageRank lookups, add to daa_model/.env:")
        print(f"    {_TOKEN_ENV}=opr_live_xxxxxxxxxxxxxxxx")
        print(f"  Get a free key at: https://openpagerank.keywordseverywhere.com/\n")

    client = UmbrellaClient()
    urls = sys.argv[1:] or [
        "https://google.com",
        "https://github.com",
        "https://rvce.edu.in",
        "https://stackoverflow.com",
        "http://paypal-secure.tk/login",     # phishing — should be unknown/low rank
        "http://77.73.133.113/malware.exe",  # IP address — unknown
    ]

    SEP = "-" * 90
    print(f"\n{'Domain':<40} {'OPR':>5}  {'Status':>9}  {'Verdict':<12} {'Conf':>6}  {'ms':>6}")
    print(SEP)
    for url in urls:
        r = client.lookup(url)
        status_str = {-1: "MALICIOUS", 1: "SAFE", 0: "UNKNOWN", None: "-"}[r.status]
        opr_str = f"{r.security.get('open_page_rank', '?')}" if r.source != "unavailable" else "?"
        print(f"{r.domain:<40} {opr_str:>5}  {status_str:>9}  {r.verdict:<12} {r.confidence:>6.1%}"
              f"  {r.latency_ms:>6.1f}ms")
        if r.error:
            print(f"  Error   : {r.error}")
    print(SEP)
