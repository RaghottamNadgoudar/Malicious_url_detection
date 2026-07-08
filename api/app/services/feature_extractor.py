"""
Feature Extractor Service
Self-contained 25-feature vector extraction for URL security analysis.
Mirrors the feature set in backend/phase3_neural_classifier.py.
"""

import re
import math
from collections import Counter
from typing import Dict, List, Optional
from urllib.parse import urlparse, unquote
import tldextract

from app.utils.logger import get_logger

logger = get_logger("services.feature_extractor")

# ── Constants ────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top",
    "work", "click", "loan", "win", "racing", "date",
    "download", "stream", "gdn", "accountant", "trade",
}

PHISHING_KEYWORDS: List[str] = [
    "login", "verify", "secure", "update", "bank", "paypal", "apple",
    "amazon", "confirm", "account", "signin", "ebay", "password",
    "suspended", "locked", "urgent", "support", "billing",
    "invoice", "expire", "validate", "credential", "recovery", "reset",
    "authentication", "wallet", "crypto", "security", "alert",
    "click", "free", "prize", "winner", "download", "install",
    "offer", "discount", "limited", "claim", "reward", "gift",
]

SPOOFED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon",
    "facebook", "netflix", "instagram", "twitter", "ebay",
    "wellsfargo", "bankofamerica", "chase", "citibank",
]

SUSPICIOUS_PORTS = {8080, 8443, 9090, 3333, 4444, 5555, 7777, 8888, 9999}

TRUSTED_TLDS = {"com", "edu.in", "org", "net", "edu", "gov"}

FEATURE_NAMES = [
    "url_length", "domain_length", "subdomain_depth", "path_depth",
    "query_length", "num_query_params", "dot_count", "hyphen_count",
    "digit_ratio", "uppercase_ratio", "special_char_ratio",
    "url_entropy", "domain_entropy", "has_https", "tld_suspicious",
    "has_ip", "has_at_symbol", "double_slash_path", "has_suspicious_port",
    "redirect_depth", "keyword_score", "brand_in_subdomain",
    "has_homograph", "domain_age_proxy", "chain_length",
]

def parse_domain(url: str) -> dict:
    ext = tldextract.extract(url)
    return {
        "subdomain": ext.subdomain,
        "registrable_domain": ext.domain,
        "suffix": ext.suffix,
        "full_registrable": f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain,
        "subdomain_depth": len(ext.subdomain.split(".")) if ext.subdomain else 0,
    }

# ── Pure helpers ─────────────────────────────────────────────────────────────

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _domain_length(parsed, ext_info) -> int:
    host = parsed.netloc.lower().split(":")[0].lstrip("www.")
    return len(host)


def _subdomain_depth(ext_info) -> int:
    return ext_info["subdomain_depth"]


def _query_length(parsed) -> int:
    return len(parsed.query)


def _num_query_params(parsed) -> int:
    q = parsed.query
    return len(q.split("&")) if q else 0


def _has_ip(url: str) -> bool:
    return bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url))


def _domain_entropy(ext_info) -> float:
    return _entropy(ext_info["subdomain"])


def _keyword_score(url: str) -> float:
    try:
        decoded = unquote(url).lower()
    except Exception:
        decoded = url.lower()
    hits = sum(1 for kw in PHISHING_KEYWORDS if kw in decoded)
    return min(hits / max(len(PHISHING_KEYWORDS), 1), 1.0)


def _brand_in_subdomain(url: str, parsed, ext_info) -> bool:
    subdomain = ext_info["subdomain"].lower()
    domain = ext_info["registrable_domain"].lower()
    path = (parsed.path or "").lower()
    for brand in SPOOFED_BRANDS:
        if (brand in subdomain or brand in path) and brand not in domain:
            return True
    return False


def _has_homograph(url: str, ext_info) -> bool:
    domain = ext_info["registrable_domain"].lower()
    leet = domain.translate(str.maketrans("01345", "oieAs"))
    for brand in SPOOFED_BRANDS:
        if brand in leet and brand not in domain:
            return True
    return False


def _has_suspicious_port(parsed) -> bool:
    try:
        return bool(parsed.port and parsed.port in SUSPICIOUS_PORTS)
    except Exception:
        return False


def _tld_suspicious(ext_info) -> bool:
    suffix = ext_info["suffix"].lower()
    # sometimes suffix could be multi-level, we can check parts or whole
    return any(suffix.endswith(tld) or suffix == tld for tld in SUSPICIOUS_TLDS)


def _domain_age_proxy(ext_info) -> float:
    """Trusted TLDs = 1.0, unknown = 0.3."""
    suffix = ext_info["suffix"].lower()
    return 1.0 if any(suffix.endswith(t) for t in TRUSTED_TLDS) else 0.3


# ── Feature extraction ───────────────────────────────────────────────────────

class FeatureExtractorService:
    """
    Extracts a 25-dimensional feature vector from a URL.
    Accepts optional redirect analysis data to fill chain-level features.
    """

    def extract(self, url: str, redirect_data: Optional[Dict] = None) -> Dict:
        """
        Returns a dict matching the FeatureSet schema.
        `redirect_data` should be the output of RedirectAnalyzerService.analyze().
        """
        rd = redirect_data or {}
        redirect_depth = rd.get("redirect_depth", 0)
        chain_length = rd.get("chain_length", 1)

        try:
            parsed = urlparse(url)
        except Exception:
            parsed = urlparse("")
            
        ext_info = parse_domain(url)

        features: Dict = {
            "url_length": len(url),
            "domain_length": _domain_length(parsed, ext_info),
            "subdomain_depth": _subdomain_depth(ext_info),
            "path_depth": url.count("/"),
            "query_length": _query_length(parsed),
            "num_query_params": _num_query_params(parsed),
            "dot_count": url.count("."),
            "hyphen_count": url.count("-"),
            "digit_ratio": round(
                sum(c.isdigit() for c in url) / max(len(url), 1), 4
            ),
            "uppercase_ratio": round(
                sum(c.isupper() for c in url) / max(len(url), 1), 4
            ),
            "special_char_ratio": round(
                sum(1 for c in url if c in "@%=&?#") / max(len(url), 1), 4
            ),
            "url_entropy": round(_entropy(url), 4),
            "domain_entropy": round(_domain_entropy(ext_info), 4),
            "has_https": url.startswith("https://"),
            "tld_suspicious": _tld_suspicious(ext_info),
            "has_ip": _has_ip(url),
            "has_at_symbol": "@" in url,
            "double_slash_path": "//" in parsed.path,
            "has_suspicious_port": _has_suspicious_port(parsed),
            "redirect_depth": redirect_depth,
            "keyword_score": round(_keyword_score(url), 4),
            "brand_in_subdomain": _brand_in_subdomain(url, parsed, ext_info),
            "has_homograph": _has_homograph(url, ext_info),
            "domain_age_proxy": _domain_age_proxy(ext_info),
            "chain_length": chain_length,
        }

        return features

    def to_vector(self, features: Dict) -> list:
        """Convert feature dict to ordered list for ML inference."""
        return [
            features["url_length"],
            features["domain_length"],
            features["subdomain_depth"],
            features["path_depth"],
            features["query_length"],
            features["num_query_params"],
            features["dot_count"],
            features["hyphen_count"],
            features["digit_ratio"],
            features["uppercase_ratio"],
            features["special_char_ratio"],
            features["url_entropy"],
            features["domain_entropy"],
            float(features["has_https"]),
            float(features["tld_suspicious"]),
            float(features["has_ip"]),
            float(features["has_at_symbol"]),
            float(features["double_slash_path"]),
            float(features["has_suspicious_port"]),
            features["redirect_depth"],
            features["keyword_score"],
            float(features["brand_in_subdomain"]),
            float(features["has_homograph"]),
            features["domain_age_proxy"],
            features["chain_length"],
        ]

# ── Module-level singleton ────────────────────────────────────────────────────
feature_extractor_service = FeatureExtractorService()
