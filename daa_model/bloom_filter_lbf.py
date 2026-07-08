"""
bloom_filter_lbf.py — Learned Bloom Filter built on top of DistilBERT
======================================================================
Implements the "sandwiched" Learned Bloom Filter (Mitzenmacher 2018):

    URL → [DistilBERT (learned filter)] → confident safe → safe ✓
                                        → confident malicious → malicious ✗
                                        → uncertain → [Backup Bloom Filter]
                                                           ↓
                                                    in BF? → malicious ✗
                                                    not in BF? → safe ✓

The backup Bloom Filter is built from DistilBERT's FALSE NEGATIVES:
malicious URLs that the model scored below the safety threshold.
This gives the guarantee: False Negative Rate = 0.

Dataset (auto-fetched, balanced):
  MALICIOUS  : URLhaus recent URLs feed (live, ~1000 entries/day)
  SAFE       : Tranco Top-1M list (most visited legitimate domains)
  Balance    : Equal-size undersampling of the majority class

Usage:
    python bloom_filter_lbf.py build          # builds + saves the filter
    python bloom_filter_lbf.py query <url>    # query a single URL
    python bloom_filter_lbf.py stats          # print filter stats
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import pickle
import random
import sys
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

import requests

logging.basicConfig(level=logging.INFO, format="[LBF] %(message)s")
logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_DIR        = os.path.dirname(os.path.abspath(__file__))
BF_PATH     = os.path.join(_DIR, "backup_bloom_filter.pkl")
STATS_PATH  = os.path.join(_DIR, "lbf_stats.json")

# ── Bloom Filter parameters ────────────────────────────────────────────────────
# Target false-positive rate for the backup filter.
# Lower = more memory; 0.1% is a good balance.
TARGET_FPR  = 0.001   # 0.1%

# ── DistilBERT safety threshold — MUST match pipeline_bert.py ─────────────────
# A URL scoring BELOW this is classified as "safe" by DistilBERT.
# We need the backup BF to catch malicious URLs that fall below this.
SAFE_THRESHOLD = 0.35   # same as pipeline_bert.py SAFE_THRESHOLD

# ── Dataset sizes ──────────────────────────────────────────────────────────────
MAX_MALICIOUS   = 5000   # cap on malicious URLs to fetch
MAX_SAFE        = 5000   # balanced — same size as malicious


# ══════════════════════════════════════════════════════════════════════════════
# 1.  BLOOM FILTER
# ══════════════════════════════════════════════════════════════════════════════

class BloomFilter:
    """
    Space-efficient probabilistic set membership tester.

    Uses k independent MurmurHash-derived seeds over a bit-array of size m.

    Properties:
      - No false negatives  (if item was added, always returns True)
      - Controllable false positive rate via target_fpr
      - O(k) insert and query time
      - O(m/8) bytes memory (bit-array)

    Parameters:
        n           : expected number of elements to insert
        target_fpr  : desired false-positive rate (e.g. 0.001 = 0.1%)
    """

    def __init__(self, n: int, target_fpr: float = TARGET_FPR):
        if n == 0:
            n = 1
        # Optimal bit-array size: m = -n * ln(p) / (ln 2)^2
        self.m = max(1, int(-n * math.log(target_fpr) / (math.log(2) ** 2)))
        # Optimal number of hash functions: k = (m/n) * ln 2
        self.k = max(1, int((self.m / n) * math.log(2)))
        self._bits = bytearray(math.ceil(self.m / 8))
        self.n_inserted = 0
        self.target_fpr = target_fpr
        logger.info(
            "BloomFilter: n=%d, m=%d bits (%.1f KB), k=%d hashes, target_fpr=%.3f%%",
            n, self.m, self.m / 8 / 1024, self.k, target_fpr * 100,
        )

    # ── Hash functions ────────────────────────────────────────────────────────
    def _hashes(self, item: str):
        """Generate k independent hash positions using double-hashing."""
        data = item.encode("utf-8")
        h1 = int(hashlib.md5(data).hexdigest(), 16)
        h2 = int(hashlib.sha1(data).hexdigest(), 16)
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    # ── Core operations ───────────────────────────────────────────────────────
    def add(self, item: str) -> None:
        """Insert item into the filter."""
        for pos in self._hashes(item):
            byte_idx, bit_idx = divmod(pos, 8)
            self._bits[byte_idx] |= (1 << bit_idx)
        self.n_inserted += 1

    def __contains__(self, item: str) -> bool:
        """Test membership. Returns True if item *might* be in set."""
        return all(
            self._bits[byte_idx] & (1 << bit_idx)
            for pos in self._hashes(item)
            for byte_idx, bit_idx in [divmod(pos, 8)]
        )

    # ── Persistence ───────────────────────────────────────────────────────────
    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            pickle.dump(self, f)
        size_kb = os.path.getsize(path) / 1024
        logger.info("BloomFilter saved to %s (%.1f KB)", path, size_kb)

    @staticmethod
    def load(path: str) -> "BloomFilter":
        with open(path, "rb") as f:
            bf = pickle.load(f)
        logger.info(
            "BloomFilter loaded: %d items, %.1f KB",
            bf.n_inserted, os.path.getsize(path) / 1024,
        )
        return bf

    @property
    def actual_fpr(self) -> float:
        """Estimate current false-positive rate based on fill level."""
        if self.n_inserted == 0:
            return 0.0
        fill_ratio = self.n_inserted / (self.m / self.k)
        return (1 - math.exp(-self.k * self.n_inserted / self.m)) ** self.k

    def __repr__(self) -> str:
        return (
            f"BloomFilter(n={self.n_inserted}, m={self.m} bits, "
            f"k={self.k} hashes, actual_fpr={self.actual_fpr:.4%})"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 2.  DATASET FETCHER
# ══════════════════════════════════════════════════════════════════════════════

def fetch_malicious_urls(max_count: int = MAX_MALICIOUS) -> list[str]:
    """
    Fetch recent malicious URLs from URLhaus (abuse.ch).

    Uses the unauthenticated recent-URLs CSV feed — no API key needed here
    because we only need the URL strings for building the filter.

    Returns a list of malicious URL strings.
    """
    logger.info("Fetching malicious URLs from URLhaus feed...")
    # URLhaus provides a plain-text CSV dump — no auth needed for this feed
    feed_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        resp = requests.get(feed_url, timeout=30)
        resp.raise_for_status()
        urls = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                url = parts[2].strip().strip('"')  # CSV column 3 = url
                if url.startswith("http"):
                    urls.append(url)
            if len(urls) >= max_count:
                break
        logger.info("  Fetched %d malicious URLs from URLhaus", len(urls))
        return urls
    except Exception as e:
        logger.warning("URLhaus feed failed: %s — trying backup source", e)
        return _fetch_malicious_fallback(max_count)


def _fetch_malicious_fallback(max_count: int) -> list[str]:
    """Fallback: use URLhaus API /urls/recent/ endpoint."""
    try:
        resp = requests.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            headers={"Auth-Key": os.getenv("URL_HAUS_API", "")},
            timeout=20,
        )
        data = resp.json()
        urls = [e["url"] for e in data.get("urls", []) if e.get("url")]
        logger.info("  Fallback: fetched %d malicious URLs via API", len(urls))
        return urls[:max_count]
    except Exception as e:
        logger.error("Both malicious URL sources failed: %s", e)
        return []


def fetch_safe_urls(max_count: int = MAX_SAFE) -> list[str]:
    """
    Fetch safe URLs from the Tranco Top-1M list.

    Tranco (tranco-list.eu) aggregates Alexa, Cisco Umbrella, Majestic,
    and Quantcast — the most visited legitimate domains worldwide.

    Returns a list of safe URL strings (https://domain).
    """
    logger.info("Fetching safe URLs from Tranco Top-1M...")
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        import zipfile, io as _io
        resp = requests.get(tranco_url, timeout=60, stream=True)
        resp.raise_for_status()
        content = b""
        for chunk in resp.iter_content(chunk_size=65536):
            content += chunk
            if len(content) > 15 * 1024 * 1024:   # 15 MB cap
                break
        with zipfile.ZipFile(_io.BytesIO(content)) as zf:
            name = zf.namelist()[0]
            lines = zf.read(name).decode("utf-8").splitlines()

        urls = []
        random.shuffle(lines)   # randomise before taking slice
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                domain = parts[1].strip()
                if domain:
                    urls.append(f"https://{domain}")
            if len(urls) >= max_count:
                break
        logger.info("  Fetched %d safe URLs from Tranco", len(urls))
        return urls
    except Exception as e:
        logger.warning("Tranco fetch failed: %s — using Alexa fallback", e)
        return _fetch_safe_fallback(max_count)


def _fetch_safe_fallback(max_count: int) -> list[str]:
    """Fallback: hardcoded well-known safe domains."""
    well_known = [
        "https://google.com", "https://youtube.com", "https://facebook.com",
        "https://wikipedia.org", "https://amazon.com", "https://twitter.com",
        "https://instagram.com", "https://linkedin.com", "https://reddit.com",
        "https://github.com", "https://stackoverflow.com", "https://microsoft.com",
        "https://apple.com", "https://netflix.com", "https://cloudflare.com",
    ]
    logger.warning("Using %d hardcoded safe domains as fallback", len(well_known))
    return well_known[:max_count]


def balance_dataset(
    malicious: list[str],
    safe: list[str],
    seed: int = 42,
) -> tuple[list[str], list[str]]:
    """
    Undersample the majority class to produce a balanced dataset.

    Uses stratified random sampling so the balanced set is representative
    of the full distribution (not just the first N entries).
    """
    random.seed(seed)
    n = min(len(malicious), len(safe))
    if len(malicious) > n:
        malicious = random.sample(malicious, n)
    if len(safe) > n:
        safe = random.sample(safe, n)
    logger.info(
        "Balanced dataset: %d malicious + %d safe = %d total",
        len(malicious), len(safe), len(malicious) + len(safe),
    )
    return malicious, safe


# ══════════════════════════════════════════════════════════════════════════════
# 3.  LBF BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_lbf(
    bert_pipeline,
    malicious_urls: list[str],
    safe_urls: list[str],
    target_fpr: float = TARGET_FPR,
) -> tuple[BloomFilter, dict]:
    """
    Build the backup Bloom Filter from DistilBERT's false negatives.

    Algorithm:
      For each MALICIOUS URL:
        score = distilbert(url)
        if score < SAFE_THRESHOLD:   ← model MISSED this (false negative)
            backup_bloom.add(url)    ← BF will catch it

    This gives:
      - All malicious URLs the model catches → caught by model alone
      - All malicious URLs the model misses  → caught by backup BF
      - Combined: 0 false negatives guaranteed

    Returns:
        (bloom_filter, stats_dict)
    """
    t0 = time.monotonic()

    false_negatives = []   # malicious URLs model missed
    true_positives  = []   # malicious URLs model caught
    false_positives = []   # safe URLs model flagged as malicious
    true_negatives  = []   # safe URLs model correctly cleared

    total = len(malicious_urls) + len(safe_urls)
    logger.info("Running DistilBERT over %d URLs to find false negatives...", total)

    # ── Score all MALICIOUS URLs ──────────────────────────────────────────────
    for i, url in enumerate(malicious_urls):
        if i % 100 == 0:
            logger.info("  Malicious: %d/%d", i, len(malicious_urls))
        try:
            score = bert_pipeline._bert_score(url)
            if score < SAFE_THRESHOLD:
                false_negatives.append(url)   # model said safe, but it's malicious
            else:
                true_positives.append(url)
        except Exception:
            false_negatives.append(url)       # conservative: add to BF on error

    # ── Score all SAFE URLs ───────────────────────────────────────────────────
    for i, url in enumerate(safe_urls):
        if i % 100 == 0:
            logger.info("  Safe: %d/%d", i, len(safe_urls))
        try:
            score = bert_pipeline._bert_score(url)
            if score >= SAFE_THRESHOLD:
                false_positives.append(url)   # model flagged safe URL as malicious
            else:
                true_negatives.append(url)
        except Exception:
            pass

    elapsed = round((time.monotonic() - t0) * 1000)
    logger.info(
        "Scoring complete in %.1fs: %d TP, %d FN, %d TN, %d FP",
        elapsed / 1000,
        len(true_positives), len(false_negatives),
        len(true_negatives), len(false_positives),
    )

    # ── Build backup Bloom Filter from false negatives ────────────────────────
    n_fn = max(len(false_negatives), 1)
    bf = BloomFilter(n=n_fn, target_fpr=target_fpr)
    for url in false_negatives:
        bf.add(url)

    total_mal = len(malicious_urls)
    total_safe = len(safe_urls)

    stats = {
        "built_at":         time.strftime("%Y-%m-%d %Human:%M:%S UTC", time.gmtime()),
        "distilbert_threshold": SAFE_THRESHOLD,
        "dataset": {
            "malicious_total":  total_mal,
            "safe_total":       total_safe,
            "balanced":         total_mal == total_safe,
        },
        "model_performance": {
            "true_positives":   len(true_positives),
            "false_negatives":  len(false_negatives),
            "true_negatives":   len(true_negatives),
            "false_positives":  len(false_positives),
            "sensitivity":      round(len(true_positives) / max(total_mal, 1), 4),
            "specificity":      round(len(true_negatives) / max(total_safe, 1), 4),
            "fpr_model":        round(len(false_positives) / max(total_safe, 1), 4),
            "fnr_model":        round(len(false_negatives) / max(total_mal, 1), 4),
        },
        "bloom_filter": {
            "n_inserted":       bf.n_inserted,
            "m_bits":           bf.m,
            "k_hashes":         bf.k,
            "target_fpr":       bf.target_fpr,
            "actual_fpr_est":   round(bf.actual_fpr, 6),
            "size_kb":          round(bf.m / 8 / 1024, 2),
        },
        "lbf_guarantees": {
            "false_negative_rate": 0.0,   # guaranteed — BF catches all FNs
            "false_positive_rate": round(
                len(false_positives) / max(total_safe, 1) +
                bf.actual_fpr * (len(false_negatives) / max(total_mal, 1)),
                4,
            ),
        },
        "elapsed_ms": elapsed,
    }
    return bf, stats


# ══════════════════════════════════════════════════════════════════════════════
# 4.  RUNTIME QUERY  (used by pipeline_bert.py)
# ══════════════════════════════════════════════════════════════════════════════

_backup_bf: Optional[BloomFilter] = None
_bf_lock_flag = False


def get_backup_filter() -> Optional[BloomFilter]:
    """Lazy-load the persisted backup Bloom Filter."""
    global _backup_bf
    if _backup_bf is None and os.path.exists(BF_PATH):
        try:
            _backup_bf = BloomFilter.load(BF_PATH)
        except Exception as e:
            logger.warning("Could not load backup filter: %s", e)
    return _backup_bf


def lbf_query(url: str, bert_score: float) -> tuple[str, str]:
    """
    Apply the Learned Bloom Filter decision rule.

    Args:
        url        : the URL being classified
        bert_score : P(malicious) from DistilBERT (0–1)

    Returns:
        (verdict, source) where source is one of:
          "lbf_model"     — DistilBERT was confident
          "lbf_backup_bf" — backup Bloom Filter caught a false negative
          "lbf_passthrough" — no backup filter loaded; use bert_score as-is
    """
    bf = get_backup_filter()

    if bf is None:
        return "passthrough", "lbf_passthrough"

    # DistilBERT confident malicious → trust the model
    from pipeline_bert import SUSPICIOUS_THRESHOLD
    if bert_score >= SUSPICIOUS_THRESHOLD:
        return "malicious", "lbf_model"

    # DistilBERT says safe → check backup BF for false negatives
    if bert_score < SAFE_THRESHOLD:
        if url in bf:
            return "malicious", "lbf_backup_bf"
        return "safe", "lbf_model"

    # Uncertain zone (SAFE_THRESHOLD ≤ score < SUSPICIOUS_THRESHOLD) →
    # check BF as extra signal but don't override model's uncertainty
    if url in bf:
        return "malicious", "lbf_backup_bf"
    return "suspicious", "lbf_model"


# ══════════════════════════════════════════════════════════════════════════════
# 5.  CLI  (python bloom_filter_lbf.py build / query / stats)
# ══════════════════════════════════════════════════════════════════════════════

def _cmd_build():
    logger.info("═" * 60)
    logger.info("LEARNED BLOOM FILTER — BUILD PHASE")
    logger.info("═" * 60)

    # ── Fetch and balance dataset ─────────────────────────────────────────────
    malicious = fetch_malicious_urls(MAX_MALICIOUS)
    safe      = fetch_safe_urls(MAX_SAFE)

    if not malicious:
        logger.error("No malicious URLs fetched — aborting.")
        sys.exit(1)

    malicious, safe = balance_dataset(malicious, safe)

    # ── Load pipeline (DistilBERT) ────────────────────────────────────────────
    logger.info("Loading DistilBERT pipeline...")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
    from pipeline_bert import BertPipeline
    pipe = BertPipeline(quiet=True)

    # ── Build the Learned Bloom Filter ───────────────────────────────────────
    bf, stats = build_lbf(pipe, malicious, safe)

    # ── Save ──────────────────────────────────────────────────────────────────
    bf.save(BF_PATH)
    stats["built_at"] = stats["built_at"].replace("Human", "H")  # formatting fix
    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)
    logger.info("Stats saved to %s", STATS_PATH)

    # ── Summary ───────────────────────────────────────────────────────────────
    logger.info("")
    logger.info("═" * 60)
    logger.info("BUILD COMPLETE — Learned Bloom Filter Summary")
    logger.info("═" * 60)
    mp = stats["model_performance"]
    logger.info("  Dataset:          %d malicious + %d safe (balanced)",
                stats["dataset"]["malicious_total"], stats["dataset"]["safe_total"])
    logger.info("  DistilBERT FNR:   %.2f%% (%d missed malicious URLs → inserted in BF)",
                mp["fnr_model"] * 100, stats["bloom_filter"]["n_inserted"])
    logger.info("  DistilBERT FPR:   %.2f%%", mp["fpr_model"] * 100)
    logger.info("  BF size:          %.1f KB (%d bits, %d hashes)",
                stats["bloom_filter"]["size_kb"],
                stats["bloom_filter"]["m_bits"],
                stats["bloom_filter"]["k_hashes"])
    logger.info("  LBF guarantee:    FNR = 0.0%%  (zero missed malicious URLs)")
    logger.info("  LBF combined FPR: %.4f%%", stats["lbf_guarantees"]["false_positive_rate"] * 100)


def _cmd_query(url: str):
    bf = get_backup_filter()
    if bf is None:
        print(f"No backup filter found at {BF_PATH}. Run: python bloom_filter_lbf.py build")
        sys.exit(1)

    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
    from pipeline_bert import BertPipeline
    pipe = BertPipeline(quiet=True)

    score = pipe._bert_score(url)
    verdict, source = lbf_query(url, score)
    in_bf = url in bf

    print(f"\nURL:         {url}")
    print(f"BERT score:  {score:.4f} ({score:.1%})")
    print(f"In backup BF:{in_bf}")
    print(f"Verdict:     {verdict.upper()}")
    print(f"Source:      {source}")


def _cmd_stats():
    if not os.path.exists(STATS_PATH):
        print(f"No stats file found. Run: python bloom_filter_lbf.py build")
        sys.exit(1)
    with open(STATS_PATH) as f:
        stats = json.load(f)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "build"

    if cmd == "build":
        _cmd_build()
    elif cmd == "query":
        if len(sys.argv) < 3:
            print("Usage: python bloom_filter_lbf.py query <url>")
            sys.exit(1)
        _cmd_query(sys.argv[2])
    elif cmd == "stats":
        _cmd_stats()
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: python bloom_filter_lbf.py [build|query <url>|stats]")
        sys.exit(1)
