"""
Stage 1 — Structural Heuristics
Two algorithms:
  1. Boyer-Moore string search  — keyword scanning (bad-char + good-suffix shift)
  2. Shannon entropy calculator — high-entropy URL = obfuscated/random = suspicious

DAA Mapping
-----------
  Unit-III : Transform & Conquer
    - Boyer-Moore: preprocessing (bad-char table) + transformed search
    - Shannon entropy: information-theoretic transformation of string
  Complexity:
    Boyer-Moore: O(n/m) best, O(nm) worst (but fast in practice via bad-char)
    Entropy:     O(n) — single pass counter
"""

import math
from collections import Counter
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# 1. Boyer-Moore String Search (Bad Character + Good Suffix heuristic)
# ─────────────────────────────────────────────────────────────────────────────

class BoyerMoore:
    """
    Classic Boyer-Moore pattern matching with:
      - Bad Character table   (skip on mismatch)
      - Good Suffix table     (skip on partial match)

    Preprocesses the pattern at construction time — O(m + |Σ|).
    Search runs in O(n/m) best-case, O(nm) worst-case.

    Used here to scan URLs for phishing keywords efficiently.
    """

    def __init__(self, pattern: str):
        self.pattern = pattern.lower()
        self.m = len(pattern)
        self._bad_char = self._build_bad_char()
        self._good_suffix, self._shift = self._build_good_suffix()

    # ── Pre-processing ────────────────────────────────────────────────────────

    def _build_bad_char(self) -> Dict[str, int]:
        """
        Bad Character Table.
        For each character c, store the rightmost position of c in pattern.
        On mismatch at position i, shift = i - bad_char.get(text[i], -1)
        """
        table: Dict[str, int] = {}
        for i, ch in enumerate(self.pattern):
            table[ch] = i
        return table

    def _build_good_suffix(self) -> Tuple[List[int], List[int]]:
        """
        Good Suffix Table (simplified — border array approach).
        border[i] = length of longest proper suffix of pattern[i..m-1]
                    that is also a prefix of pattern.
        shift[i]  = how much to shift when mismatch occurs at position i.
        """
        m = self.m
        border = [0] * (m + 1)
        shift  = [m] * (m + 1)

        # Phase 1: compute border array (suffix-prefix matching)
        i, j = m, m + 1
        border[i] = j
        while i > 0:
            while j <= m and self.pattern[i - 1] != self.pattern[j - 1]:
                if shift[j] == m:
                    shift[j] = j - i
                j = border[j]
            i -= 1
            j -= 1
            border[i] = j

        # Phase 2: fill remaining shifts
        j = border[0]
        for i in range(m + 1):
            if shift[i] == m:
                shift[i] = j
            if i == j:
                j = border[j]

        return border, shift

    # ── Search ────────────────────────────────────────────────────────────────

    def search(self, text: str) -> List[int]:
        """
        Find all occurrences of pattern in text.
        Returns list of start indices (0-based).

        Boyer-Moore right-to-left comparison with bad-char + good-suffix shift.
        """
        text = text.lower()
        n, m = len(text), self.m
        if m == 0 or n < m:
            return []

        positions: List[int] = []
        s = 0   # shift index in text

        while s <= n - m:
            j = m - 1   # right-to-left scan

            while j >= 0 and self.pattern[j] == text[s + j]:
                j -= 1

            if j < 0:
                # Full match found
                positions.append(s)
                s += self._shift[0]
            else:
                # Compute both shifts, take max (skip further)
                bad_shift  = j - self._bad_char.get(text[s + j], -1)
                good_shift = self._shift[j + 1]
                s += max(bad_shift, good_shift, 1)

        return positions

    def found_in(self, text: str) -> bool:
        """Quick existence check."""
        return bool(self.search(text))

    def __repr__(self):
        return f"BoyerMoore(pattern={self.pattern!r}, m={self.m})"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Multi-Pattern Boyer-Moore Keyword Scanner
# ─────────────────────────────────────────────────────────────────────────────

# Phishing keyword taxonomy (categorised by threat type)
PHISHING_KEYWORDS: Dict[str, List[str]] = {
    "credential": [
        "login", "signin", "password", "passwd", "credential",
        "username", "userid", "auth", "authenticate",
    ],
    "account": [
        "account", "verify", "confirm", "validate", "update",
        "suspended", "locked", "restore", "reactivate", "expire",
    ],
    "finance": [
        "paypal", "bank", "banking", "billing", "invoice",
        "payment", "transfer", "wallet", "crypto", "bitcoin",
        "refund", "claim", "reward", "prize", "winner",
    ],
    "brand": [
        "apple", "google", "microsoft", "amazon", "netflix",
        "ebay", "instagram", "facebook", "twitter", "linkedin",
        "wellsfargo", "chase", "citibank", "barclays",
    ],
    "urgency": [
        "urgent", "immediate", "alert", "warning", "attention",
        "action", "required", "important", "critical",
    ],
    "download": [
        "download", "install", "setup", "update", "upgrade",
        "exe", "apk", "dmg", "payload",
    ],
}

# Weighted scores per category (urgency + finance = highest risk)
CATEGORY_WEIGHTS: Dict[str, float] = {
    "credential": 0.25,
    "account":    0.20,
    "finance":    0.25,
    "brand":      0.20,
    "urgency":    0.15,
    "download":   0.15,
}


class KeywordScanner:
    """
    Scans a URL for phishing keywords using Boyer-Moore per pattern.
    Returns a threat score 0.0–1.0 and which categories fired.
    """

    def __init__(self):
        # Pre-compile a BM searcher per keyword (preprocessing at startup)
        self._searchers: Dict[str, Tuple[str, BoyerMoore]] = {}
        for category, keywords in PHISHING_KEYWORDS.items():
            for kw in keywords:
                self._searchers[kw] = (category, BoyerMoore(kw))

    def scan(self, url: str) -> Dict:
        """
        Scan `url` for all phishing keywords using Boyer-Moore.

        Returns
        -------
        {
          score      : float 0.0–1.0
          hits       : { keyword: [positions] }
          categories : { category: hit_count }
        }
        """
        url_lower = url.lower()
        hits: Dict[str, List[int]] = {}
        categories: Dict[str, int] = {}

        for kw, (cat, searcher) in self._searchers.items():
            positions = searcher.search(url_lower)
            if positions:
                hits[kw] = positions
                categories[cat] = categories.get(cat, 0) + 1

        # Score = weighted sum of category contributions (capped at 1.0)
        score = 0.0
        for cat, count in categories.items():
            weight = CATEGORY_WEIGHTS.get(cat, 0.1)
            score += weight * min(count, 3) / 3.0   # diminishing returns

        return {
            "score": round(min(score, 1.0), 4),
            "hits": hits,
            "categories": categories,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 3. Shannon Entropy Calculator
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """
    H(X) = -Σ p(x) * log2(p(x))

    High entropy → random-looking string → DGA domain / obfuscated URL.
    Typical ranges:
      English words  : 3.0 – 4.0 bits
      Base64 payload : 5.5 – 6.0 bits
      Random hex     : 4.0 bits
      DGA domain     : > 4.0 bits
    """
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def url_entropy_score(url: str) -> Dict:
    """
    Compute entropy of:
      - Full URL
      - Hostname only
      - Path only

    Returns suspicious flag if any component exceeds threshold.
    """
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path = parsed.path
    except Exception:
        host, path = "", ""

    h_url  = shannon_entropy(url)
    h_host = shannon_entropy(host)
    h_path = shannon_entropy(path) if path else 0.0

    URL_THRESHOLD  = 4.5
    HOST_THRESHOLD = 4.0

    suspicious = h_url > URL_THRESHOLD or h_host > HOST_THRESHOLD

    return {
        "url_entropy":  round(h_url, 4),
        "host_entropy": round(h_host, 4),
        "path_entropy": round(h_path, 4),
        "suspicious":   suspicious,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4. Unified Heuristics Engine
# ─────────────────────────────────────────────────────────────────────────────

class HeuristicsEngine:
    """
    Combines keyword scanning + entropy analysis into a single
    heuristic signal used by the filter pipeline.
    """

    def __init__(self):
        self._scanner = KeywordScanner()

    def analyze(self, url: str) -> Dict:
        """
        Returns:
          heuristic_score  : float 0.0–1.0 (combined signal)
          keyword_result   : dict from KeywordScanner.scan()
          entropy_result   : dict from url_entropy_score()
          is_suspicious    : bool (quick flag for pipeline)
        """
        kw  = self._scanner.scan(url)
        ent = url_entropy_score(url)

        # Combine: 60% keyword score + 40% entropy signal
        ent_score = 1.0 if ent["suspicious"] else (ent["url_entropy"] / 6.0)
        combined  = round(0.60 * kw["score"] + 0.40 * ent_score, 4)

        return {
            "heuristic_score": combined,
            "keyword_result":  kw,
            "entropy_result":  ent,
            "is_suspicious":   combined > 0.35 or kw["score"] > 0.25,
        }

    def __repr__(self):
        return f"HeuristicsEngine(keywords={len(self._scanner._searchers)})"


# ── Module-level singleton ────────────────────────────────────────────────────
heuristics_engine = HeuristicsEngine()
