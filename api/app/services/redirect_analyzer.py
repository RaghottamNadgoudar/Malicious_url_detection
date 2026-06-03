"""
Redirect Analyzer Service
Wraps the BFS/DFS redirect graph logic from backend/phase1_graph_traversal.py.
Adds: loop detection flag, suspicious-hop scoring, open-redirect detection.
"""

import re
from typing import Dict, List
from urllib.parse import urlparse
from collections import Counter
import math

from app.utils.logger import get_logger

logger = get_logger("services.redirect_analyzer")

# ── Helpers from phase1_graph_traversal (inlined to avoid sys.path hacks) ────

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".gq", ".cf",
                    ".ga", ".work", ".loan", ".win", ".racing", ".date", ".stream"}
_SUSPICIOUS_KEYWORDS = ["login", "verify", "account", "secure", "banking",
                        "update", "confirm", "paypal", "password", "suspended"]


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        return host.split(":")[0].lstrip("www.")
    except Exception:
        return ""


def _hop_risk_score(url: str) -> float:
    """
    Score a single hop URL for suspiciousness (0-1).
    Used to highlight dangerous intermediate hops.
    """
    score = 0.0
    domain = _extract_domain(url)

    # Suspicious TLD
    if any(domain.endswith(tld) for tld in _SUSPICIOUS_TLDS):
        score += 0.35

    # IP address in host
    if _IP_RE.match(domain):
        score += 0.30

    # High entropy
    if _entropy(url) > 4.5:
        score += 0.15

    # Suspicious keywords
    lower = url.lower()
    kw_hits = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in lower)
    score += min(kw_hits / len(_SUSPICIOUS_KEYWORDS), 0.20)

    return min(score, 1.0)


# ── Main service ─────────────────────────────────────────────────────────────

class RedirectAnalyzerService:
    """
    Analyzes a pre-built redirect chain (from URLExpansionService)
    and computes redirect-level security signals.
    """

    def analyze(self, expansion_result: Dict) -> Dict:
        """
        Consume the output of URLExpansionService.expand() and return
        enriched redirect analysis.
        """
        chain: List[Dict] = expansion_result.get("redirect_chain", [])
        loop_detected: bool = expansion_result.get("loop_detected", False)
        redirect_count: int = expansion_result.get("redirect_count", 0)

        # Annotate each hop with a risk score
        annotated_chain = []
        suspicious_hops = 0
        for hop in chain:
            risk = _hop_risk_score(hop["url"])
            suspicious = risk > 0.3
            if suspicious:
                suspicious_hops += 1
            annotated_chain.append({
                **hop,
                "is_suspicious": hop.get("is_suspicious", False) or suspicious,
                "hop_risk_score": round(risk, 3),
            })

        # Compute chain-level signals
        max_hop_risk = max((h["hop_risk_score"] for h in annotated_chain), default=0.0)
        domains_in_chain = [_extract_domain(h["url"]) for h in annotated_chain]
        unique_domains = len(set(domains_in_chain))

        # Open redirect: final domain differs from original domain
        original_domain = _extract_domain(expansion_result.get("original_url", ""))
        final_domain = _extract_domain(expansion_result.get("expanded_url", ""))
        cross_domain_redirect = (
            bool(original_domain and final_domain)
            and original_domain != final_domain
        )

        return {
            "redirect_chain": annotated_chain,
            "redirect_count": redirect_count,
            "loop_detected": loop_detected,
            "excessive_redirects": expansion_result.get("excessive_redirects", False),
            "suspicious_hops": suspicious_hops,
            "max_hop_risk": round(max_hop_risk, 3),
            "unique_domains_in_chain": unique_domains,
            "cross_domain_redirect": cross_domain_redirect,
            # Phase 1 signals passed downstream to feature extraction
            "redirect_depth": redirect_count,
            "chain_length": len(annotated_chain),
        }


# ── Module-level singleton ────────────────────────────────────────────────────
redirect_analyzer_service = RedirectAnalyzerService()
