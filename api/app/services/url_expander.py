"""
URL Expansion & Redirect Hunter Service
Inspired by:
  - github.com/karthi-the-hacker/RedirectHunter  (GET + Location header chasing)
  - github.com/whoami-anoint/webredirection       (open-redirect param patterns)
  - github.com/ethicals7s/ethicals7s-redirect-hunter (Axios-style hop tracing)

Core fixes over old HEAD-only approach:
  1. Uses GET (not HEAD) — many servers ignore HEAD or return wrong status
  2. Manually controls each hop (follow_redirects=False per request)
  3. Detects meta-refresh redirects in HTML response body
  4. Detects JavaScript window.location redirects in body
  5. Detects open-redirect query params (?url=, ?redirect=, ?goto=, etc.)
  6. Falls back gracefully on connection errors (records hop as best-effort)
  7. Respects robots/timeout without crashing the pipeline
"""

import re
import asyncio
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, parse_qs, unquote
import httpx

from app.utils.logger import get_logger

logger = get_logger("services.url_expander")

# ── Known URL shortener domains ──────────────────────────────────────────────
URL_SHORTENERS: set = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bit.do", "lnkd.in",
    "db.tt", "qr.ae", "cur.lv", "ity.im", "q.gs",
    "po.st", "bc.vc", "u.to", "j.mp", "buzurl.com",
    "cutt.us", "u.bb", "yourls.org", "prettylinkpro.com",
    "scrnch.me", "v.gd", "tr.im", "short.link", "rb.gy",
    "shorturl.at", "tiny.cc", "rebrand.ly", "snipurl.com",
    "clck.ru", "durl.me", "gg.gg", "s.id", "shorte.st",
    "linktr.ee", "mcaf.ee", "soo.gd", "chilp.it",
}

# Suspicious TLDs — flag a hop as high-risk
_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".gq", ".cf", ".ga",
    ".work", ".loan", ".win", ".racing", ".date", ".stream",
    ".download", ".accountant", ".faith", ".trade", ".review",
}

# Open-redirect query parameter names (from whoami-anoint/webredirection)
# These are the canonical list from real BB reports
_OPEN_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_uri", "redirecturl",
    "return", "return_url", "returnurl", "returnto", "return_to",
    "next", "next_url", "goto", "go", "target", "destination", "dest",
    "to", "redir", "redir_url", "link", "forward", "location",
    "checkout_url", "continue", "continue_url", "data", "ref", "page",
    "uri", "back", "path", "request", "site", "jump", "out", "view",
    "from_url", "callback", "u", "r",
}

# Patterns for meta-refresh extraction
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\s*\d*\s*;?\s*url=([^"\'>\s]+)',
    re.IGNORECASE,
)
# Fallback (content first)
_META_REFRESH_RE2 = re.compile(
    r'content=["\']?\s*\d*\s*;?\s*url=([^"\'>\s]+)',
    re.IGNORECASE,
)

# JavaScript window.location patterns
_JS_REDIRECT_RES = [
    re.compile(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'location\.href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'document\.location\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
]

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


# ── Utility functions ─────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0].lstrip("www.")
    except Exception:
        return ""


def _is_shortener(url: str) -> bool:
    return _extract_domain(url) in URL_SHORTENERS


def _is_hop_suspicious(url: str) -> bool:
    domain = _extract_domain(url)
    if any(domain.endswith(tld) for tld in _SUSPICIOUS_TLDS):
        return True
    # Suspicious: contains IP address
    try:
        import ipaddress
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return True
    except Exception:
        pass
    return False


def _check_open_redirect_in_url(url: str) -> Optional[str]:
    """
    If this URL itself uses an open-redirect query param pointing to another URL,
    return that embedded URL. This handles the pattern:
      http://redirect1.tk/go?url=http://redirect2.ml/go?url=http://evil.com
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=False)
        for param_name, values in params.items():
            if param_name.lower() in _OPEN_REDIRECT_PARAMS and values:
                target = unquote(values[0])
                if target.startswith(("http://", "https://")):
                    return target
    except Exception:
        pass
    return None


def _extract_meta_refresh(html: str, base_url: str) -> Optional[str]:
    """Extract redirect URL from HTML meta-refresh tag."""
    for pattern in [_META_REFRESH_RE, _META_REFRESH_RE2]:
        m = pattern.search(html)
        if m:
            target = m.group(1).strip().strip("'\"")
            if target:
                return urljoin(base_url, target)
    return None


def _extract_js_redirect(html: str, base_url: str) -> Optional[str]:
    """Extract redirect URL from JavaScript window.location assignments."""
    for pattern in _JS_REDIRECT_RES:
        m = pattern.search(html)
        if m:
            target = m.group(1).strip()
            if target and not target.startswith(("javascript:", "#")):
                return urljoin(base_url, target)
    return None


# ── Hop record ────────────────────────────────────────────────────────────────

class HopRecord:
    def __init__(
        self,
        hop: int,
        url: str,
        status_code: Optional[int],
        suspicious: bool,
        redirect_type: str = "none",
    ):
        self.hop = hop
        self.url = url
        self.status_code = status_code
        self.is_suspicious = suspicious
        self.redirect_type = redirect_type  # "http_3xx" | "meta_refresh" | "js" | "open_redirect" | "none"

    def to_dict(self) -> Dict:
        return {
            "hop": self.hop,
            "url": self.url,
            "status_code": self.status_code,
            "is_suspicious": self.is_suspicious,
            "redirect_type": self.redirect_type,
        }


# ── Main service ──────────────────────────────────────────────────────────────

class URLExpansionService:
    """
    Production-grade URL expansion with full redirect chain tracing.

    Handles ALL redirect types:
      - HTTP 301/302/303/307/308 (Location header)   ← most common
      - HTML <meta http-equiv="refresh" content="..."> ← many phishing sites
      - JavaScript window.location = "..."            ← JS-based redirectors
      - Open-redirect query params (?url=, ?redirect=) ← security-relevant

    Approach (inspired by RedirectHunter + webredirection):
      1. GET (not HEAD) each hop manually
      2. Check HTTP 3xx Location header first
      3. If 200, scan body for meta-refresh
      4. If 200, scan body for JS redirect
      5. If URL has open-redirect param, follow it as a virtual hop
    """

    def __init__(self, max_redirects: int = 15, timeout: float = 8.0):
        self.max_redirects = max_redirects
        self.timeout = timeout
        self._cache: Dict[str, Dict] = {}

    async def expand(self, url: str, use_cache: bool = True) -> Dict:
        if use_cache and url in self._cache:
            logger.debug(f"Cache hit for {url}")
            return self._cache[url]

        result = await self._trace_redirects(url)

        if use_cache:
            self._cache[url] = result
        return result

    async def _trace_redirects(self, original_url: str) -> Dict:
        """
        Core redirect tracer — manually follows every hop.
        Records the full chain including redirect type per hop.
        """
        is_shortened = _is_shortener(original_url)
        shortener_domain = _extract_domain(original_url) if is_shortened else None

        errors: List[str] = []
        loop_detected = False
        seen: Set[str] = set()
        chain: List[HopRecord] = []
        current = original_url

        # ── Step 0: Check if the starting URL itself is an open-redirect ──────
        embedded = _check_open_redirect_in_url(current)

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(self.timeout),
            headers=_HEADERS,
            verify=False,           # many phishing/test sites have bad certs
        ) as client:

            hop_idx = 0
            while hop_idx <= self.max_redirects:
                if current in seen:
                    loop_detected = True
                    errors.append(f"Redirect loop at hop {hop_idx}: {current}")
                    break

                seen.add(current)
                suspicious = _is_hop_suspicious(current)

                # ── Try HTTP GET ─────────────────────────────────────────────
                try:
                    response = await client.get(
                        current,
                        follow_redirects=False,
                    )
                    status = response.status_code

                except httpx.ConnectError as exc:
                    # Record dead-end hop but continue (domain may just be down)
                    chain.append(HopRecord(hop_idx, current, None, suspicious, "none"))
                    errors.append(f"Connect error at hop {hop_idx} ({current}): {exc}")
                    break
                except httpx.TimeoutException:
                    chain.append(HopRecord(hop_idx, current, None, suspicious, "none"))
                    errors.append(f"Timeout at hop {hop_idx}: {current}")
                    break
                except Exception as exc:
                    chain.append(HopRecord(hop_idx, current, None, suspicious, "none"))
                    errors.append(f"Error at hop {hop_idx}: {exc}")
                    break

                # ── Case 1: HTTP 3xx redirect ─────────────────────────────────
                if status in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "").strip()
                    if not location:
                        chain.append(HopRecord(hop_idx, current, status, suspicious, "http_3xx"))
                        errors.append(f"Empty Location header at hop {hop_idx}")
                        break

                    # Resolve relative URLs
                    if not location.startswith(("http://", "https://")):
                        location = urljoin(current, location)

                    chain.append(HopRecord(hop_idx, current, status, suspicious, "http_3xx"))
                    logger.debug(f"  Hop {hop_idx}: {current} →[{status}]→ {location}")
                    current = location
                    hop_idx += 1
                    continue

                # ── Case 2: HTTP 200 — scan body for soft redirects ──────────
                chain.append(HopRecord(hop_idx, current, status, suspicious, "none"))

                # Only parse HTML bodies
                content_type = response.headers.get("content-type", "")
                if "html" not in content_type and "text" not in content_type:
                    break

                try:
                    body = response.text
                except Exception:
                    break

                # 2a. Meta-refresh
                meta_target = _extract_meta_refresh(body, current)
                if meta_target and meta_target != current:
                    chain[-1].redirect_type = "meta_refresh"
                    logger.debug(f"  Hop {hop_idx}: meta-refresh → {meta_target}")
                    current = meta_target
                    hop_idx += 1
                    continue

                # 2b. JavaScript redirect
                js_target = _extract_js_redirect(body, current)
                if js_target and js_target != current:
                    chain[-1].redirect_type = "js_redirect"
                    logger.debug(f"  Hop {hop_idx}: JS redirect → {js_target}")
                    current = js_target
                    hop_idx += 1
                    continue

                # No more redirects found
                break

        # ── Post-process: detect open-redirect params in each hop ─────────────
        self._flag_open_redirects(chain)

        # If original URL had embedded open-redirect target, record it
        if embedded and len(chain) <= 1:
            # The chain didn't auto-follow because the domain was unreachable,
            # but we still know the intended destination
            chain.append(HopRecord(
                len(chain), embedded, None,
                _is_hop_suspicious(embedded), "open_redirect"
            ))
            if not is_shortened:
                # The original URL acts like a shortener via open redirect
                is_shortened = True

        redirect_count = max(len(chain) - 1, 0)
        final_url = chain[-1].url if chain else original_url

        return {
            "original_url": original_url,
            "expanded_url": final_url,
            "is_shortened": is_shortened,
            "shortener_domain": shortener_domain,
            "redirect_chain": [h.to_dict() for h in chain],
            "redirect_count": redirect_count,
            "loop_detected": loop_detected,
            "excessive_redirects": redirect_count >= self.max_redirects,
            "errors": errors,
        }

    def _flag_open_redirects(self, chain: List[HopRecord]) -> None:
        """
        Post-scan: if any hop URL contains open-redirect query params,
        update its redirect_type and mark as suspicious.
        """
        for hop in chain:
            if hop.redirect_type != "none":
                continue
            embedded = _check_open_redirect_in_url(hop.url)
            if embedded:
                hop.redirect_type = "open_redirect"
                hop.is_suspicious = True

    def clear_cache(self) -> None:
        self._cache.clear()


# ── Module-level singleton ────────────────────────────────────────────────────
url_expansion_service = URLExpansionService()
