"""
Stage 1 — Bloom Filter Ensemble
Weighted voting across three filter variants:
  Cuckoo Filter     — 50% weight (lowest FP, supports delete)
  Counting BF       — 25% weight (supports delete, aging)
  Scalable BF       — 25% weight (handles dataset growth)

Decision rule:
  weighted_score ≥ threshold  →  KNOWN_MALICIOUS (block, skip ML)
  weighted_score = 0.0        →  KNOWN_SAFE (pass, skip ML)
  else                        →  UNCERTAIN (forward to ML pipeline)

DAA mapping: Algorithm combination, weighted ensemble voting
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List
from urllib.parse import urlparse

from .bloom_layer import CountingBloomFilter, ScalableBloomFilter, CuckooFilter


# ── Decision labels ───────────────────────────────────────────────────────────

class FilterDecision(str, Enum):
    KNOWN_MALICIOUS = "KNOWN_MALICIOUS"   # blocked by filter — skip ML
    KNOWN_SAFE      = "KNOWN_SAFE"        # whitelisted — skip ML
    UNCERTAIN       = "UNCERTAIN"         # forward to ML core


@dataclass
class EnsembleResult:
    decision: FilterDecision
    weighted_score: float
    votes: Dict[str, bool]
    domain: str


# ── Helper: domain extraction ─────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower().split(":")[0].lstrip("www.")
        return host
    except Exception:
        return url.lower()[:100]


# ── Bloom Filter Ensemble ─────────────────────────────────────────────────────

class BloomFilterEnsemble:
    """
    Three-filter ensemble with weighted voting.
    Maintains separate blacklist and whitelist filters.

    Weights
    -------
    Cuckoo    : 0.50
    Counting  : 0.25
    Scalable  : 0.25

    Threshold : weighted_score >= 0.50 → KNOWN_MALICIOUS
    """

    WEIGHTS = {
        "cuckoo":   0.50,
        "counting": 0.25,
        "scalable": 0.25,
    }
    THRESHOLD = 0.50   # min weighted score to classify as malicious

    def __init__(
        self,
        capacity: int = 200_000,
        fp_rate: float = 0.01,
    ):
        # ── Blacklist filters (malicious domains) ─────────────────────────
        self._bl_cuckoo  = CuckooFilter(capacity=capacity)
        self._bl_counting = CountingBloomFilter(capacity=capacity, fp_rate=fp_rate)
        self._bl_scalable = ScalableBloomFilter(initial_capacity=capacity, fp_rate=fp_rate)

        # ── Whitelist filter (known-safe domains) — single CBF ────────────
        self._wl = CountingBloomFilter(capacity=50_000, fp_rate=0.001)

        self._bl_count = 0
        self._wl_count = 0

    # ── Population API ────────────────────────────────────────────────────────

    def add_malicious(self, domain: str) -> None:
        """Add a domain to all three blacklist filters."""
        d = domain.lower().strip()
        self._bl_cuckoo.add(d)
        self._bl_counting.add(d)
        self._bl_scalable.add(d)
        self._bl_count += 1

    def add_safe(self, domain: str) -> None:
        """Add a domain to the whitelist filter."""
        self._wl.add(domain.lower().strip())
        self._wl_count += 1

    def remove_malicious(self, domain: str) -> None:
        """Remove a domain from the blacklist (CBF + Cuckoo support deletion)."""
        d = domain.lower().strip()
        self._bl_cuckoo.remove(d)
        self._bl_counting.remove(d)
        # ScalableBF doesn't support deletion — left as-is

    # ── Query API ─────────────────────────────────────────────────────────────

    def query(self, url: str) -> EnsembleResult:
        """
        Query all filters and return an EnsembleResult with decision.

        Algorithm
        ---------
        1. Extract domain from URL.
        2. Check whitelist first (fast-path KNOWN_SAFE).
        3. Query all three blacklist filters.
        4. Compute weighted vote score.
        5. score >= THRESHOLD → KNOWN_MALICIOUS, else UNCERTAIN.
        """
        domain = _extract_domain(url)

        # Fast-path: whitelist check
        if self._wl.contains(domain):
            return EnsembleResult(
                decision=FilterDecision.KNOWN_SAFE,
                weighted_score=0.0,
                votes={"cuckoo": False, "counting": False, "scalable": False,
                       "whitelist": True},
                domain=domain,
            )

        # Query each blacklist filter
        votes = {
            "cuckoo":   self._bl_cuckoo.contains(domain),
            "counting": self._bl_counting.contains(domain),
            "scalable": self._bl_scalable.contains(domain),
        }

        # Weighted score
        score = sum(
            self.WEIGHTS[name] for name, hit in votes.items() if hit
        )

        decision = (
            FilterDecision.KNOWN_MALICIOUS if score >= self.THRESHOLD
            else FilterDecision.UNCERTAIN
        )

        return EnsembleResult(
            decision=decision,
            weighted_score=round(score, 3),
            votes=votes,
            domain=domain,
        )

    # ── Bulk loading ──────────────────────────────────────────────────────────

    def load_malicious_domains(self, domains: List[str]) -> int:
        """Bulk-load a list of malicious domain strings. Returns count added."""
        added = 0
        for d in domains:
            d = d.strip().lower()
            if d:
                self.add_malicious(d)
                added += 1
        return added

    def load_safe_domains(self, domains: List[str]) -> int:
        """Bulk-load a list of safe/whitelisted domain strings."""
        added = 0
        for d in domains:
            d = d.strip().lower()
            if d:
                self.add_safe(d)
                added += 1
        return added

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> Dict:
        return {
            "blacklist_entries": self._bl_count,
            "whitelist_entries": self._wl_count,
            "cuckoo_load":   round(self._bl_cuckoo.load_factor, 3),
            "counting_load": round(self._bl_counting.load_factor, 3),
            "scalable_slices": self._bl_scalable.num_slices,
            "threshold": self.THRESHOLD,
            "weights": self.WEIGHTS,
        }

    def __repr__(self):
        return (f"BloomFilterEnsemble(bl={self._bl_count}, "
                f"wl={self._wl_count})")


# ── Module-level singleton (populated by filter_pipeline.py) ──────────────────
bloom_ensemble = BloomFilterEnsemble(capacity=200_000, fp_rate=0.01)
