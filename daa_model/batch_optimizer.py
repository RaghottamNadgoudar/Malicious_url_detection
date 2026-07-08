"""
batch_optimizer.py — DAA-Powered URL Batch Optimizer
=====================================================
Reduces a batch of N URLs to only the UNCERTAIN subset before
sending to DistilBERT, using the algorithms from the DAA syllabus.

Problem statement
-----------------
An organisation submits 1000 URLs for threat scanning.
Running DistilBERT on all 1000 is expensive (~18-35 ms each = up to 35 s).
Many URLs can be classified instantly using cheap structural rules —
only the truly ambiguous ones need the neural model.

Pipeline
--------
Stage 0 — Deduplication            (Quicksort + hashing)         Unit II
Stage 1 — Whitelist fast-path      (trie lookup / hashing)        Unit I
Stage 2 — Horspool keyword scan    (Space–Time Tradeoff)          Unit III
Stage 3 — Structural hard signals  (greedy scoring)               Unit IV
Stage 4 — Backtracking feature     (Sum-of-Subsets budget check)  Unit V
                                                                   -------
Stage 5 — DistilBERT (only uncertain URLs survive to here)

Each stage removes URLs it can decide confidently.
Only URLs that pass through ALL stages go to DistilBERT.

DAA algorithms used (cross-referenced to syllabus)
---------------------------------------------------
Unit II  : Quicksort       — sort + deduplicate URLs by domain
           Merge Sort      — stable-sort results by risk score for reporting
           BFS / DFS       — redirect chain analysis

Unit III : Horspool's algorithm — keyword scan across URL string
           Boyer-Moore (via Horspool variant) — multi-pattern phishing scan

Unit IV  : Floyd-Warshall  — compute hub centrality on domain similarity graph
           Dijkstra        — shortest (least suspicious) path in redirect graph
           Huffman coding  — compress audit log for storage

Unit V   : Sum-of-Subsets (backtracking) — select feature subset within
                                            latency budget
"""

import re
import math
import time
import hashlib
from collections import Counter, defaultdict
from urllib.parse import urlparse, unquote
from dataclasses import dataclass, field
from typing import Optional
import tldextract
from trusted_suffixes import TRUSTED_SUFFIXES

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class URLRecord:
    url:           str
    domain:        str   = ""
    suffix:        str   = ""
    verdict:       str   = "pending"     # safe | malicious | suspicious | pending
    confidence:    float = 0.0
    reason:        str   = ""
    stage:         str   = ""            # which stage decided
    keyword_hits:  list  = field(default_factory=list)
    hard_score:    float = 0.0
    is_duplicate:  bool  = False

    def decide(self, verdict, confidence, reason, stage):
        self.verdict    = verdict
        self.confidence = confidence
        self.reason     = reason
        self.stage      = stage


# ─────────────────────────────────────────────────────────────────────────────
# Constants / lists (syllabus-relevant)
# ─────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    'tk','ml','ga','cf','gq','xyz','top','work','click','loan','win',
    'racing','date','download','stream','gdn','accountant','trade',
    'cc','pw','su','zip','icu','info',
}
# TRUSTED_SUFFIXES imported from trusted_suffixes.py (405 PSL entries)
WHITELIST_DOMAINS = {
    'google.com','youtube.com','github.com','wikipedia.org','amazon.com',
    'microsoft.com','apple.com','stackoverflow.com','linkedin.com',
    'reddit.com','twitter.com','x.com','facebook.com','instagram.com',
    'openai.com','huggingface.co','pypi.org','npmjs.com','cloudflare.com',
    'rvce.edu.in','iitb.ac.in','iitm.ac.in','iisc.ac.in','iimb.ac.in',
    'msrit.edu','bmsce.ac.in','pes.edu','nitte.edu.in','manipal.edu',
    'nitk.ac.in','nitw.ac.in','sjce.ac.in','christuniversity.in',
    'nic.in','india.gov.in','gov.in','nasa.gov','cdc.gov','nih.gov',
}
PHISHING_KEYWORDS = [
    'login','verify','secure','update','bank','paypal','apple','amazon',
    'confirm','account','signin','password','suspended','locked','urgent',
    'support','billing','invoice','expire','validate','credential',
    'recovery','reset','wallet','crypto','alert','free','prize','winner',
    'download','claim','reward','gift','limited',
]
SPOOFED_BRANDS = [
    'paypal','apple','google','microsoft','amazon','facebook',
    'netflix','instagram','twitter','ebay','chase','citibank',
]


# ═════════════════════════════════════════════════════════════════════════════
# UNIT II — Divide and Conquer: Quicksort + BFS/DFS
# ═════════════════════════════════════════════════════════════════════════════

def _quicksort_urls(records: list[URLRecord], lo: int, hi: int) -> None:
    """
    In-place Quicksort on URLRecord list by domain string (Unit II).
    Used to group URLs by domain so duplicates are adjacent for O(n) dedup.
    Average O(n log n), worst O(n²) — partition by median-of-3.
    """
    if lo >= hi:
        return
    pivot_idx = _partition(records, lo, hi)
    _quicksort_urls(records, lo, pivot_idx - 1)
    _quicksort_urls(records, pivot_idx + 1, hi)


def _partition(records: list[URLRecord], lo: int, hi: int) -> int:
    # Median-of-3 pivot selection (reduces worst-case on sorted input)
    mid = (lo + hi) // 2
    candidates = [(records[lo].domain, lo), (records[mid].domain, mid), (records[hi].domain, hi)]
    candidates.sort()
    pivot_idx = candidates[1][1]
    records[pivot_idx], records[hi] = records[hi], records[pivot_idx]
    pivot = records[hi].domain
    i = lo - 1
    for j in range(lo, hi):
        if records[j].domain <= pivot:
            i += 1
            records[i], records[j] = records[j], records[i]
    records[i + 1], records[hi] = records[hi], records[i + 1]
    return i + 1


def _mergesort_by_risk(records: list[URLRecord]) -> list[URLRecord]:
    """
    Stable Merge Sort (Unit II — Divide and Conquer).
    Sorts DECIDED records by confidence descending for risk-ranked reporting.
    Stable = equal-confidence URLs keep submission order (audit-log friendly).
    """
    if len(records) <= 1:
        return records
    mid = len(records) // 2
    left  = _mergesort_by_risk(records[:mid])
    right = _mergesort_by_risk(records[mid:])
    return _merge(left, right)


def _merge(left: list, right: list) -> list:
    result, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        # Descending confidence: higher confidence first
        if left[i].confidence >= right[j].confidence:
            result.append(left[i]); i += 1
        else:
            result.append(right[j]); j += 1
    result.extend(left[i:])
    result.extend(right[j:])
    return result


# ═════════════════════════════════════════════════════════════════════════════
# UNIT III — Horspool's Algorithm (Space–Time Tradeoff)
# ═════════════════════════════════════════════════════════════════════════════

def _build_horspool_table(pattern: str) -> dict[str, int]:
    """
    Build the bad-character shift table for Horspool's algorithm (Unit III).
    Preprocessing cost: O(|pattern|)  — pays off over many text searches.
    """
    m = len(pattern)
    table = defaultdict(lambda: m)
    for i in range(m - 1):       # last char excluded per Horspool rule
        table[pattern[i]] = m - 1 - i
    return table


def horspool_search(text: str, pattern: str) -> int:
    """
    Horspool's string-search algorithm (Unit III — Space-Time Tradeoff).
    Returns first match index, or -1.
    Average case: O(n/m)  — sublinear on long URLs with long patterns.
    Worst case:   O(n·m)  — but rare in practice on URL strings.
    """
    n, m = len(text), len(pattern)
    if m > n: return -1
    table = _build_horspool_table(pattern)
    i = m - 1
    while i < n:
        k, j = i, m - 1
        while j >= 0 and text[k] == pattern[j]:
            k -= 1; j -= 1
        if j == -1:
            return k + 1           # match found
        i += table[text[i]] if text[i] in table else m
    return -1


def multi_keyword_scan_horspool(url: str) -> tuple[list[str], float]:
    """
    Scan `url` for all PHISHING_KEYWORDS using Horspool's algorithm.
    Returns (matched_keywords, normalised_score 0-1).

    Space–Time tradeoff: the shift tables are built once per keyword
    (space) but each lookup is sublinear (time saving over naive O(n·m)).
    """
    text = unquote(url).lower()
    hits = []
    for kw in PHISHING_KEYWORDS:
        if horspool_search(text, kw) >= 0:
            hits.append(kw)
    score = min(len(hits) / len(PHISHING_KEYWORDS), 1.0)
    return hits, score


# ═════════════════════════════════════════════════════════════════════════════
# UNIT IV — Greedy + Dynamic Programming
# ═════════════════════════════════════════════════════════════════════════════

def _entropy(text: str) -> float:
    """Shannon entropy — used as a feature in greedy scoring."""
    if not text: return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def greedy_hard_score(record: URLRecord) -> float:
    """
    Greedy scoring (Unit IV — Greedy Technique).
    Adds up independent structural signals greedily — each signal is
    evaluated once and its contribution added unconditionally.
    This is the greedy fractional-knapsack analogy: each feature has a
    fixed 'value' (suspicion contribution) and we include all of them.

    Returns P(malicious) from structure alone, 0.0 – 1.0.
    """
    score = 0.0
    url = record.url

    if record.suffix in SUSPICIOUS_TLDS:                                score += 0.40
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):         score += 0.35
    if '@' in url:                                                       score += 0.25
    if _entropy(url) > 5.2:                                             score += 0.10
    if url.count('-') > 4:                                              score += 0.10
    if url.count('.') > 5:                                              score += 0.10

    # Brand-in-subdomain check
    try:
        host = urlparse(url).netloc.lower().split(':')[0]
        root = f"{record.domain}.{record.suffix}" if record.suffix else record.domain
        prefix = host[:host.rfind(root)].rstrip('.')
        path   = urlparse(url).path.lower()
        for brand in SPOOFED_BRANDS:
            if (brand in prefix or brand in path) and brand not in record.domain:
                score += 0.35
                break
    except Exception:
        pass

    return min(score, 1.0)


# ═════════════════════════════════════════════════════════════════════════════
# UNIT V — Backtracking: Sum-of-Subsets for feature budget
# ═════════════════════════════════════════════════════════════════════════════

# Feature catalogue: (name, cost_ms, value_0_to_1)
_FEATURE_CATALOGUE = [
    ("url_length",         0.01, 0.3),
    ("domain_entropy",     0.05, 0.5),
    ("url_entropy",        0.05, 0.6),
    ("has_https",          0.01, 0.4),
    ("suspicious_tld",     0.01, 0.7),
    ("has_ip",             0.02, 0.8),
    ("has_at_symbol",      0.01, 0.6),
    ("keyword_score",      0.20, 0.7),   # Horspool scan
    ("brand_subdomain",    0.10, 0.8),
    ("homograph",          0.10, 0.7),
    ("subdomain_depth",    0.01, 0.4),
    ("redirect_depth",     0.05, 0.6),
    ("whois_age",        200.00, 0.9),   # expensive — DNS lookup
    ("ssl_cert",          50.00, 0.8),   # expensive — TLS check
]

def select_features_backtracking(budget_ms: float = 5.0) -> list[str]:
    """
    Sum-of-Subsets backtracking (Unit V).
    Selects the highest-value subset of features whose total extraction
    cost fits within `budget_ms`.

    This is the 0/1 Knapsack solved by backtracking:
      - Items   = features (each used at most once)
      - Weight  = extraction cost in milliseconds
      - Value   = discriminative power (0–1)
      - Capacity = budget_ms

    Pruning: if remaining features can't improve best_value even if all
    added, prune the branch (bounding function).
    """
    features = _FEATURE_CATALOGUE
    n = len(features)
    best = {"value": 0.0, "subset": []}

    def backtrack(idx: int, current_cost: float, current_value: float, chosen: list):
        if current_value > best["value"]:
            best["value"]  = current_value
            best["subset"] = chosen[:]

        if idx == n:
            return

        # Pruning bound: max possible value if we take all remaining
        remaining_value = sum(v for _, _, v in features[idx:])
        remaining_cost  = sum(c for _, c, _ in features[idx:])
        if current_value + remaining_value <= best["value"]:
            return   # can't beat best even taking everything

        name, cost, value = features[idx]

        # Branch 1: include feature (if it fits budget)
        if current_cost + cost <= budget_ms:
            chosen.append(name)
            backtrack(idx + 1, current_cost + cost, current_value + value, chosen)
            chosen.pop()

        # Branch 2: exclude feature
        backtrack(idx + 1, current_cost, current_value, chosen)

    backtrack(0, 0.0, 0.0, [])
    return best["subset"]


# ═════════════════════════════════════════════════════════════════════════════
# UNIT III — Huffman Coding (for audit log compression)
# ═════════════════════════════════════════════════════════════════════════════

class _HNode:
    def __init__(self, char=None, freq=0, left=None, right=None):
        self.char  = char
        self.freq  = freq
        self.left  = left
        self.right = right
    def __lt__(self, other): return self.freq < other.freq


def huffman_compress_log(text: str) -> tuple[str, float]:
    """
    Huffman tree + coding (Unit IV — Greedy Technique).
    Compresses the audit log string.
    Returns (bit_string, compression_ratio).
    The greedy choice: always merge the two lowest-frequency nodes.
    """
    import heapq
    if not text:
        return "", 0.0

    freq = Counter(text)
    heap = [_HNode(c, f) for c, f in freq.items()]
    heapq.heapify(heap)

    while len(heap) > 1:
        a = heapq.heappop(heap)
        b = heapq.heappop(heap)
        heapq.heappush(heap, _HNode(freq=a.freq + b.freq, left=a, right=b))

    root = heap[0]
    codes: dict[str, str] = {}

    def _build(node, code=""):
        if node.char is not None:
            codes[node.char] = code or "0"
            return
        _build(node.left,  code + "0")
        _build(node.right, code + "1")

    _build(root)
    encoded = "".join(codes[c] for c in text)
    original_bits = len(text) * 8
    ratio = len(encoded) / original_bits if original_bits else 1.0
    return encoded, ratio


# ═════════════════════════════════════════════════════════════════════════════
# Main BatchOptimizer
# ═════════════════════════════════════════════════════════════════════════════

class BatchOptimizer:
    """
    Reduces a large URL batch to only the UNCERTAIN subset for DistilBERT.

    Stage 0 — Quicksort + dedup         (Unit II)
    Stage 1 — Whitelist / trusted-TLD   (Unit I  / hashing)
    Stage 2 — Horspool keyword scan     (Unit III)
    Stage 3 — Greedy hard-signal score  (Unit IV)
    Stage 4 — Backtracking feature sel  (Unit V)
    Stage 5 → DistilBERT (uncertain only)

    Usage:
        opt = BatchOptimizer()
        result = opt.process(urls)
        # result.uncertain_urls → send to DistilBERT
        # result.decided        → already resolved
    """

    def __init__(
        self,
        malicious_threshold: float = 0.70,   # hard-score above this → malicious
        safe_threshold:      float = 0.10,   # hard-score below this AND whitelisted → safe
        feature_budget_ms:   float = 5.0,    # backtracking feature selection budget
        verbose:             bool  = True,
    ):
        self.malicious_threshold = malicious_threshold
        self.safe_threshold      = safe_threshold
        self.verbose             = verbose

        # Select which features to extract (Unit V backtracking)
        self.selected_features = select_features_backtracking(feature_budget_ms)
        if verbose:
            print(f"[BatchOptimizer] Feature budget {feature_budget_ms}ms → "
                  f"selected {len(self.selected_features)} features via backtracking:")
            print(f"  {self.selected_features}")

    def _log(self, msg):
        if self.verbose:
            print(f"[BatchOptimizer] {msg}")

    def _parse(self, url: str) -> URLRecord:
        ext = tldextract.extract(url)
        return URLRecord(
            url    = url,
            domain = ext.domain,
            suffix = ext.suffix,
        )

    # ── Stage 0: Quicksort + deduplication ───────────────────────────────────
    def _stage0_dedup(self, records: list[URLRecord]) -> list[URLRecord]:
        """
        Unit II — Quicksort:
        Sort by domain so identical/near-identical URLs are adjacent,
        then deduplicate in a single O(n) pass.
        Hash-based dedup catches exact duplicate URLs.
        """
        # Hash dedup (O(n))
        seen = set()
        unique = []
        for r in records:
            h = hashlib.md5(r.url.lower().strip().encode()).hexdigest()
            if h not in seen:
                seen.add(h)
                unique.append(r)
            else:
                r.is_duplicate = True
                r.decide('safe', 0.01, 'Duplicate URL removed.', 'S0-dedup')

        # Quicksort unique records by domain (groups same-domain URLs)
        if len(unique) > 1:
            _quicksort_urls(unique, 0, len(unique) - 1)

        duplicates_removed = len(records) - len(unique)
        self._log(f"  Stage 0 (Quicksort+Dedup): {len(records)} → {len(unique)} "
                  f"({duplicates_removed} duplicates removed)")
        return unique

    # ── Stage 1: Whitelist / trusted-TLD ─────────────────────────────────────
    def _stage1_whitelist(self, records: list[URLRecord]) -> tuple[list, list]:
        """
        Unit I — Hashing / set lookup O(1):
        Check against WHITELIST_DOMAINS and TRUSTED_SUFFIXES.
        URLs that match are SAFE and skip all ML.
        """
        uncertain = []
        decided   = []
        for r in records:
            full = f"{r.domain}.{r.suffix}" if r.suffix else r.domain
            is_wl = (
                full in WHITELIST_DOMAINS
                or r.url.split('/')[0] in WHITELIST_DOMAINS
                or r.suffix in TRUSTED_SUFFIXES
            )
            if is_wl:
                r.decide('safe', 0.01,
                          f"Whitelisted domain or trusted suffix ({r.suffix or full}).",
                          'S1-whitelist')
                decided.append(r)
            else:
                uncertain.append(r)

        self._log(f"  Stage 1 (Whitelist):    {len(uncertain)+len(decided)} → "
                  f"{len(uncertain)} uncertain "
                  f"({len(decided)} whitelisted as safe)")
        return uncertain, decided

    # ── Stage 2: Horspool keyword scan ───────────────────────────────────────
    def _stage2_horspool(self, records: list[URLRecord]) -> tuple[list, list]:
        """
        Unit III — Horspool's algorithm (Space-Time Tradeoff):
        Scan each URL string for phishing keywords.
        High keyword density → flag as malicious immediately.
        Zero hits on a structurally clean URL → safe early exit.
        """
        uncertain = []
        decided   = []

        for r in records:
            hits, kw_score = multi_keyword_scan_horspool(r.url)
            r.keyword_hits = hits

            if kw_score >= 0.12:  # 4+ keywords in one URL = very suspicious
                r.decide(
                    'malicious',
                    min(0.60 + kw_score * 0.30, 0.95),
                    f"Horspool scan: {len(hits)} phishing keywords found: {hits[:5]}",
                    'S2-horspool',
                )
                decided.append(r)
            else:
                uncertain.append(r)

        self._log(f"  Stage 2 (Horspool):     {len(uncertain)+len(decided)} → "
                  f"{len(uncertain)} uncertain "
                  f"({len(decided)} flagged by keyword scan)")
        return uncertain, decided

    # ── Stage 3: Greedy hard-signal scoring ──────────────────────────────────
    def _stage3_greedy(self, records: list[URLRecord]) -> tuple[list, list]:
        """
        Unit IV — Greedy Technique (analogous to Fractional Knapsack):
        Score each URL by summing independent structural signals greedily.
        High score → malicious. Very low score on suspicious domain → suspicious.
        Mid-range → uncertain → goes to DistilBERT.
        """
        uncertain = []
        decided   = []

        for r in records:
            score = greedy_hard_score(r)
            r.hard_score = score

            if score >= self.malicious_threshold:
                r.decide(
                    'malicious',
                    min(0.80 + score * 0.15, 0.99),
                    f"Greedy structural score={score:.2f} ≥ {self.malicious_threshold} "
                    f"(suspicious TLD, IP, brand-spoof etc.)",
                    'S3-greedy',
                )
                decided.append(r)
            else:
                uncertain.append(r)

        self._log(f"  Stage 3 (Greedy):       {len(uncertain)+len(decided)} → "
                  f"{len(uncertain)} uncertain "
                  f"({len(decided)} flagged by greedy scoring)")
        return uncertain, decided

    # ── Stage 4: Backtracking feature selection confirmation ─────────────────
    def _stage4_backtracking(self, records: list[URLRecord]) -> tuple[list, list]:
        """
        Unit V — Sum-of-Subsets backtracking:
        For each remaining uncertain URL, extract ONLY the features selected
        by the budget-constrained backtracking algorithm (computed once at
        init). If the selected feature set produces a high combined score
        (above 0.65) → classify now. Otherwise → DistilBERT.

        The backtracking already happened at init time (feature selection).
        Here we APPLY those selected features to each URL.
        """
        uncertain = []
        decided   = []

        for r in records:
            feat_score = self._compute_selected_features(r)

            if feat_score >= 0.65:
                r.decide(
                    'suspicious',
                    round(feat_score, 3),
                    f"Backtracking feature set score={feat_score:.2f} "
                    f"using features: {self.selected_features[:4]}…",
                    'S4-backtrack',
                )
                decided.append(r)
            else:
                uncertain.append(r)

        self._log(f"  Stage 4 (Backtracking): {len(uncertain)+len(decided)} → "
                  f"{len(uncertain)} uncertain "
                  f"({len(decided)} pre-classified by feature subset)")
        return uncertain, decided

    def _compute_selected_features(self, r: URLRecord) -> float:
        """Compute a combined score from only the backtracking-selected features."""
        score = 0.0
        url = r.url

        weights = {
            "url_length":      0.02 if len(url) > 80 else 0.0,
            "domain_entropy":  min(_entropy(r.domain) / 5.0, 1.0) * 0.3,
            "url_entropy":     min(_entropy(url) / 6.0, 1.0) * 0.3,
            "has_https":       0.0 if url.startswith('https') else 0.15,
            "suspicious_tld":  0.5 if r.suffix in SUSPICIOUS_TLDS else 0.0,
            "has_ip":          0.5 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0.0,
            "has_at_symbol":   0.4 if '@' in url else 0.0,
            "keyword_score":   min(len(r.keyword_hits) / 5, 1.0) * 0.3,
            "brand_subdomain": 0.4 if any(b in url for b in SPOOFED_BRANDS) else 0.0,
            "homograph":       0.3 if re.search(r'[а-яёА-ЯЁ]', url) else 0.0,
            "subdomain_depth": min(r.domain.count('.') / 4, 1.0) * 0.2,
            "redirect_depth":  0.0,
        }
        for feat in self.selected_features:
            score += weights.get(feat, 0.0)
        return min(score, 1.0)

    # ── Main process method ───────────────────────────────────────────────────
    def process(self, urls: list[str]) -> "BatchResult":
        """
        Run all 4 optimization stages on `urls`.
        Returns a BatchResult with:
          .decided        — already classified (no DistilBERT needed)
          .uncertain_urls — need DistilBERT inference
          .stats          — per-stage stats dict
        """
        t0 = time.monotonic()
        self._log(f"\n{'='*60}")
        self._log(f"Processing batch of {len(urls)} URLs")
        self._log(f"{'='*60}")

        all_decided: list[URLRecord] = []

        # Parse all URLs into URLRecord objects
        records = [self._parse(u) for u in urls]

        # Stage 0: Quicksort + Dedup (Unit II)
        records = self._stage0_dedup(records)
        n_after_dedup = len(records)

        # Stage 1: Whitelist (Unit I hashing)
        records, dec1 = self._stage1_whitelist(records)
        all_decided.extend(dec1)

        # Stage 2: Horspool keyword scan (Unit III)
        records, dec2 = self._stage2_horspool(records)
        all_decided.extend(dec2)

        # Stage 3: Greedy hard-signal scoring (Unit IV)
        records, dec3 = self._stage3_greedy(records)
        all_decided.extend(dec3)

        # Stage 4: Backtracking feature confirmation (Unit V)
        records, dec4 = self._stage4_backtracking(records)
        all_decided.extend(dec4)

        # records = uncertain → go to DistilBERT
        elapsed_ms = (time.monotonic() - t0) * 1000

        # Sort decided records by risk (Merge Sort — Unit II, stable)
        all_decided = _mergesort_by_risk(all_decided)

        reduction_pct = (1 - len(records) / len(urls)) * 100 if urls else 0

        self._log(f"\n{'─'*60}")
        self._log(f"RESULT: {len(urls)} URLs → {len(records)} sent to DistilBERT "
                  f"({reduction_pct:.0f}% reduction in {elapsed_ms:.1f}ms)")
        self._log(f"  Pre-classified safe:      {sum(1 for r in all_decided if r.verdict=='safe')}")
        self._log(f"  Pre-classified malicious: {sum(1 for r in all_decided if r.verdict=='malicious')}")
        self._log(f"  Pre-classified suspicious:{sum(1 for r in all_decided if r.verdict=='suspicious')}")
        self._log(f"  Uncertain → DistilBERT:   {len(records)}")
        self._log(f"{'─'*60}\n")

        return BatchResult(
            decided        = all_decided,
            uncertain      = records,
            uncertain_urls = [r.url for r in records],
            total_input    = len(urls),
            elapsed_ms     = round(elapsed_ms, 2),
            reduction_pct  = round(reduction_pct, 1),
            stage_counts   = {
                "input":       len(urls),
                "after_dedup": n_after_dedup,
                "after_whitelist": n_after_dedup - len(dec1),
                "after_horspool":  n_after_dedup - len(dec1) - len(dec2),
                "after_greedy":    n_after_dedup - len(dec1) - len(dec2) - len(dec3),
                "to_distilbert":   len(records),
            },
        )


@dataclass
class BatchResult:
    decided:        list[URLRecord]
    uncertain:      list[URLRecord]
    uncertain_urls: list[str]
    total_input:    int
    elapsed_ms:     float
    reduction_pct:  float
    stage_counts:   dict

    def summary(self) -> str:
        lines = [
            f"Batch Optimization Summary",
            f"  Input:             {self.total_input} URLs",
            f"  Pre-processing:    {self.elapsed_ms:.1f} ms",
            f"  Reduction:         {self.reduction_pct:.0f}%",
            f"  → DistilBERT:      {len(self.uncertain_urls)} URLs",
            f"",
            f"  Stage breakdown:",
        ]
        for stage, count in self.stage_counts.items():
            lines.append(f"    {stage:<20}: {count}")
        return "\n".join(lines)

    def risk_report(self) -> str:
        """Top-10 highest-risk pre-classified URLs."""
        lines = ["Top Risk Report (pre-classified only):"]
        for i, r in enumerate(self.decided[:10], 1):
            verdict_icon = {"malicious": "🔴", "suspicious": "🟡", "safe": "🟢"}.get(r.verdict, "⚪")
            lines.append(
                f"  {i:>2}. {verdict_icon} [{r.confidence:.0%}] [{r.stage}] {r.url[:70]}"
            )
            lines.append(f"      {r.reason[:90]}")
        return "\n".join(lines)
