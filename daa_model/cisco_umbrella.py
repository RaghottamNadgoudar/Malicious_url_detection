"""
cisco_umbrella.py — URLhaus (abuse.ch) API Client
===================================================
Drop-in replacement for the original Cisco Umbrella client.
The PUBLIC INTERFACE IS IDENTICAL — pipeline_bert.py and app_nn.py
need ZERO changes.

Pipeline position:
    URL → [URLhaus Investigate] → [Whitelist] → [DistilBERT] → verdict

What URLhaus returns per URL/host:
  • url_status   : "online" (active malware) | "offline" | "unknown"
  • blacklists   : spamhaus_dbl label + surbl "listed"/"not listed"
  • threat       : "malware_download" (only kind in URLhaus)
  • tags         : e.g. ["emotet", "exe", "elf"]

Key design decisions (preserved from original):
  1. NEVER blocks inference on network failure — all errors return
     UmbrellaResult(source="unavailable")
  2. TTL-based in-process LRU cache (default 600 s)
  3. Configurable timeout (default 3 s)
  4. Reads token from env var URLHAUS_AUTH_KEY
     (put in daa_model/.env and loaded via python-dotenv)

Verdict mapping from URLhaus data:
  url_status == "online"   → malicious  (actively serving malware)
  url_status == "offline"  → suspicious (was malicious, now down)
  no_results               → unknown    (DistilBERT decides)
  blacklist hits           → boost malicious confidence

Setup:
  1. Go to https://auth.abuse.ch/ and create a free account
  2. Copy your Auth-Key
  3. Add to daa_model/.env:
       URLHAUS_AUTH_KEY=your-key-here
  4. Restart the backend — Tier-0 will activate automatically.

URLhaus API reference:
  Base URL : https://urlhaus-api.abuse.ch/v1
  Auth     : "Auth-Key" HTTP header
  Endpoint used:
    POST /host/   → host reputation (domain/IP lookup)
    POST /url/    → exact URL lookup (as fallback)
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
_BASE_URL   = "https://urlhaus-api.abuse.ch/v1"
_TOKEN_ENV  = "URL_HAUS_API"
_DEFAULT_TIMEOUT = 8.0   # seconds — increased from 3s (URLhaus can be slow)
_CACHE_TTL  = 600        # seconds — 10-minute TTL per domain

# ── Spamhaus DBL labels that are definitively bad ─────────────────────────────
_SPAMHAUS_MALICIOUS = {
    "spammer_domain",
    "phishing_domain",
    "botnet_cc_domain",
    "abused_legit_spam",
    "abused_legit_malware",
    "abused_legit_phishing",
    "abused_legit_botnetcc",
    "abused_redirector",
}


# ── Result dataclass — IDENTICAL to original cisco_umbrella.py ────────────────
@dataclass
class UmbrellaResult:
    """
    Normalised result.  Field names preserved for pipeline_bert.py compatibility.

    Attributes
    ----------
    domain      : bare registrable domain queried
    status      : -1 malicious | 0 unknown | 1 safe | None = not queried
    categories  : dict of label → id  (repurposed: URLhaus tags here)
    security    : raw security indicators dict
    verdict     : "malicious" | "suspicious" | "safe" | "unknown" | "unavailable"
    confidence  : float 0–1 derived from URLhaus signals
    source      : "urlhaus" | "unavailable" | "cached"
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
    URLhaus (abuse.ch) client with the same interface as the original
    Cisco UmbrellaClient.  Drop-in replacement.

    Usage:
        client = UmbrellaClient()          # reads URLHAUS_AUTH_KEY from env/.env
        result = client.lookup("http://paypal-secure.tk/login")
        print(result.verdict, result.confidence)
    """

    def __init__(
        self,
        token:    Optional[str] = None,
        timeout:  float = _DEFAULT_TIMEOUT,
        cache_ttl: float = _CACHE_TTL,
    ):
        self._token   = token or os.getenv(_TOKEN_ENV, "")
        self._timeout = timeout
        self._cache   = _TTLCache(ttl=cache_ttl)
        self._session = requests.Session()
        if self._token:
            self._session.headers.update({
                "Auth-Key":      self._token,
                "Content-Type":  "application/x-www-form-urlencoded",
                "Accept":        "application/json",
            })
            logger.info("[URLhaus] Auth-Key configured — Tier-0 threat intel enabled ✓")
        else:
            logger.warning(
                "[URLhaus] %s not set — URLhaus lookups will be skipped. "
                "Add URLHAUS_AUTH_KEY to daa_model/.env to enable Tier-0.",
                _TOKEN_ENV,
            )

    @property
    def available(self) -> bool:
        """True if an API token is configured."""
        return bool(self._token)

    # ── Public API ────────────────────────────────────────────────────────────
    def lookup(self, url: str) -> UmbrellaResult:
        """
        Query URLhaus for the domain/host in `url`.
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
        result = self._fetch(domain, url)
        if result.source == "urlhaus":          # only cache successful results
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

    def _fetch(self, domain: str, original_url: str) -> UmbrellaResult:
        """
        Call URLhaus /host/ endpoint for the domain.
        Falls back to /url/ endpoint for the exact URL if host lookup
        returns no_results.
        """
        t0 = time.monotonic()
        try:
            host_data = self._query_host(domain)
            latency_ms = round((time.monotonic() - t0) * 1000, 1)

            # URLhaus /host/ returns "is_host" (not "ok") when the domain/IP is found
            if host_data.get("query_status") == "is_host":
                return self._build_result_from_host(domain, host_data, latency_ms)

            # host not in URLhaus — try exact URL lookup as secondary check
            url_data = self._query_url(original_url)
            latency_ms = round((time.monotonic() - t0) * 1000, 1)

            # URLhaus /url/ returns "ok" when the URL is found
            if url_data.get("query_status") == "ok":
                return self._build_result_from_url(domain, url_data, latency_ms)

            # Not found in URLhaus at all — unknown (DistilBERT will decide)
            return UmbrellaResult(
                domain=domain,
                status=0,
                verdict="unknown",
                confidence=0.0,
                source="urlhaus",
                latency_ms=latency_ms,
            )

        except requests.exceptions.Timeout:
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error="URLhaus API timeout",
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )
        except requests.exceptions.ConnectionError as e:
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error=f"Connection error: {e}",
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )
        except Exception as e:
            logger.debug("[URLhaus] Unexpected error for %s: %s", domain, e)
            return UmbrellaResult(
                domain=domain, source="unavailable",
                error=str(e),
                latency_ms=round((time.monotonic() - t0) * 1000, 1),
            )

    def _query_host(self, host: str) -> dict:
        """POST /host/ — domain/IP reputation."""
        resp = self._session.post(
            f"{_BASE_URL}/host/",
            data={"host": host},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def _query_url(self, url: str) -> dict:
        """POST /url/ — exact URL lookup."""
        resp = self._session.post(
            f"{_BASE_URL}/url/",
            data={"url": url},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Result builders ───────────────────────────────────────────────────────
    @staticmethod
    def _build_result_from_host(
        domain: str,
        data: dict,
        latency_ms: float,
    ) -> UmbrellaResult:
        """
        Parse URLhaus /host/ response.

        Scoring logic:
            url_count > 0 with online URLs  → high confidence malicious
            url_count > 0 but all offline   → moderate suspicious (was malicious)
            spamhaus_dbl hit                → boost
            surbl listed                    → boost
        """
        urls        = data.get("urls", [])
        url_count   = int(data.get("url_count", 0))
        blacklists  = data.get("blacklists", {})
        spamhaus    = blacklists.get("spamhaus_dbl", "not listed")
        surbl       = blacklists.get("surbl", "not listed")

        # Gather all tags from associated URLs (max 8)
        tag_set: set[str] = set()
        online_count = 0
        for u in urls:
            tag_set.update(u.get("tags") or [])
            if u.get("url_status") == "online":
                online_count += 1

        categories = {tag: 1 for tag in list(tag_set)[:8]}

        # --- Base confidence from live malware URLs ---
        if online_count > 0:
            conf    = min(0.75 + 0.05 * online_count, 0.97)
            status  = -1
            verdict = "malicious"
        elif url_count > 0:
            conf    = 0.55           # was malicious host, now offline
            status  = 0
            verdict = "suspicious"
        else:
            conf    = 0.30
            status  = 0
            verdict = "unknown"

        # --- Blacklist boosts ---
        if spamhaus in _SPAMHAUS_MALICIOUS:
            conf += 0.20
        if surbl == "listed":
            conf += 0.15

        conf = float(min(max(conf, 0.0), 1.0))

        # Reclassify after boosts
        if conf >= 0.60:
            verdict = "malicious"
            status  = -1
        elif conf >= 0.35:
            verdict = "suspicious"

        # Map URLhaus fields to the standard security interface expected by
        # pipeline_bert.py and the frontend (UmbrellaTierCard.tsx).
        # Fields without a URLhaus equivalent get safe-defaults.
        botnet_flag = "botnet_cc_domain" in spamhaus
        spam_score  = 1.0 if spamhaus in _SPAMHAUS_MALICIOUS else 0.0

        return UmbrellaResult(
            domain     = domain,
            status     = status,
            categories = categories,
            security   = {
                # Standard interface fields (consumed by frontend + pipeline_bert)
                "dga_score":    round(conf * 0.6, 4) if verdict == "malicious" else 0.0,
                "spam":         spam_score,
                "fastflux":     False,           # not reported by URLhaus
                "botnet":       botnet_flag,
                "securerank2":  round((1.0 - conf) * 100, 1),
                # URLhaus-specific extras (informational)
                "url_count":    url_count,
                "online_count": online_count,
                "spamhaus_dbl": spamhaus,
                "surbl":        surbl,
            },
            verdict    = verdict,
            confidence = round(conf, 4),
            source     = "urlhaus",
            latency_ms = latency_ms,
        )

    @staticmethod
    def _build_result_from_url(
        domain: str,
        data: dict,
        latency_ms: float,
    ) -> UmbrellaResult:
        """Parse URLhaus /url/ response (single URL match)."""
        url_status  = data.get("url_status", "unknown")
        blacklists  = data.get("blacklists", {})
        spamhaus    = blacklists.get("spamhaus_dbl", "not listed")
        surbl       = blacklists.get("surbl", "not listed")
        tags        = data.get("tags") or []
        categories  = {t: 1 for t in tags[:8]}

        if url_status == "online":
            conf   = 0.90
            status = -1
            verdict = "malicious"
        elif url_status == "offline":
            conf   = 0.55
            status = 0
            verdict = "suspicious"
        else:
            conf   = 0.40
            status = 0
            verdict = "unknown"

        if spamhaus in _SPAMHAUS_MALICIOUS:
            conf += 0.15
        if surbl == "listed":
            conf += 0.10

        conf = float(min(max(conf, 0.0), 1.0))
        if conf >= 0.60:
            verdict = "malicious"
            status  = -1

        botnet_flag = "botnet_cc_domain" in spamhaus
        spam_score  = 1.0 if spamhaus in _SPAMHAUS_MALICIOUS else 0.0

        return UmbrellaResult(
            domain     = domain,
            status     = status,
            categories = categories,
            security   = {
                # Standard interface fields
                "dga_score":    round(conf * 0.6, 4) if verdict == "malicious" else 0.0,
                "spam":         spam_score,
                "fastflux":     False,
                "botnet":       botnet_flag,
                "securerank2":  round((1.0 - conf) * 100, 1),
                # URLhaus-specific extras
                "url_status":   url_status,
                "spamhaus_dbl": spamhaus,
                "surbl":        surbl,
            },
            verdict    = verdict,
            confidence = round(conf, 4),
            source     = "urlhaus",
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
    """Convenience wrapper — call URLhaus for `url` using the singleton client."""
    return get_client().lookup(url)


# ── CLI smoke-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import io

    # Force UTF-8 output on Windows so box-drawing / emoji chars don't crash.
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    token = os.getenv(_TOKEN_ENV)
    if not token:
        print(f"\n  [!] {_TOKEN_ENV} is not set.")
        print(f"  To enable URLhaus lookups, add to daa_model/.env:")
        print(f"    {_TOKEN_ENV}=your-auth-key-here")
        print(f"  Get a free key at: https://auth.abuse.ch/\n")

    client = UmbrellaClient()
    urls = sys.argv[1:] or [
        "https://rvce.edu.in",
        "https://google.com",
        "http://paypal-secure.tk",
        "http://phishing-login.ml",
        "http://77.73.133.113/lego/mine.exe",   # known URLhaus malware URL
    ]

    SEP = "-" * 90
    print(f"\n{'Domain':<40} {'Status':>9}  {'Verdict':<12} {'Conf':>6}  {'Src':<10}  {'ms':>6}")
    print(SEP)
    for url in urls:
        r = client.lookup(url)
        status_str = {-1: "MALICIOUS", 1: "SAFE", 0: "UNKNOWN", None: "-"}[r.status]
        print(f"{r.domain:<40} {status_str:>9}  {r.verdict:<12} {r.confidence:>6.1%}"
              f"  {r.source:<10}  {r.latency_ms:>6.1f}ms")
        if r.categories:
            print(f"  Tags    : {list(r.categories.keys())[:5]}")
        if r.security:
            sec = r.security
            print(f"  Security: dga={sec.get('dga_score',0):.3f}  "
                  f"spam={sec.get('spam',0):.2f}  "
                  f"botnet={sec.get('botnet',False)}  "
                  f"fastflux={sec.get('fastflux',False)}  "
                  f"spamhaus='{sec.get('spamhaus_dbl','?')}'")
        if r.error:
            print(f"  Error   : {r.error}")
    print(SEP)
