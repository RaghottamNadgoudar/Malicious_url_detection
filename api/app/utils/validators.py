"""URL validation utilities."""

import re
from urllib.parse import urlparse
from typing import Tuple


# Regex: rough but fast URL sanity check
_URL_RE = re.compile(
    r"^(https?|ftp)://"
    r"([a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)$",
    re.IGNORECASE,
)

# IPs that are obviously private / loopback / link-local
_PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|::1|localhost)"
)


def is_valid_url(url: str) -> Tuple[bool, str]:
    """
    Basic structural validation of a URL.

    Returns (valid: bool, reason: str).
    """
    if not url or len(url) > 2048:
        return False, "URL is empty or too long"

    if not _URL_RE.match(url):
        return False, "URL failed structural regex check"

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "URL has no host/netloc"
    except Exception as exc:
        return False, f"URL parse error: {exc}"

    return True, "ok"


def is_private_ip(url: str) -> bool:
    """Return True if the URL's host is a private/loopback IP."""
    try:
        host = urlparse(url).hostname or ""
        return bool(_PRIVATE_IP_RE.match(host))
    except Exception:
        return False
