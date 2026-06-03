"""
Stage 1 — Filter Pipeline (Decision Gate)
Orchestrates the full pre-filter layer before any URL reaches the ML core.

Pipeline order:
  1. Trie Matcher        — O(|domain|) exact + prefix lookup
  2. Bloom Ensemble      — O(k) probabilistic blacklist/whitelist
  3. Heuristics Engine   — O(n) Boyer-Moore + entropy scan

Decision gate:
  BLOCK   — confirmed malicious by trie or ensemble (skip ML entirely)
  PASS    — confirmed safe by trie or ensemble    (skip ML entirely)
  FORWARD — uncertain → route to ML core

This is the core optimization: 60-70% of benign URLs are cleared here
without ever touching the expensive ML pipeline.

DAA Mapping
-----------
  Pipeline architecture: staged algorithm composition
  Gate logic: greedy decision (commit as soon as confident)
  Complexity: O(|domain| + k) before touching ML
"""

import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .ensemble import BloomFilterEnsemble, FilterDecision, bloom_ensemble
from .trie_matcher import DomainTrieMatcher, domain_trie_matcher
from .heuristics import HeuristicsEngine, heuristics_engine


# ── Gate decisions ────────────────────────────────────────────────────────────

class PipelineDecision(str, Enum):
    BLOCK   = "BLOCK"    # confirmed malicious → no ML call
    PASS    = "PASS"     # confirmed safe → no ML call
    FORWARD = "FORWARD"  # uncertain → send to ML core


@dataclass
class PipelineResult:
    decision:        PipelineDecision
    url:             str
    domain:          str
    # Stage results
    trie_result:     Optional[str] = None       # "malicious" / "safe" / "unknown"
    bloom_result:    Optional[str] = None       # FilterDecision value
    bloom_score:     float = 0.0
    heuristic_score: float = 0.0
    heuristic_data:  Dict = field(default_factory=dict)
    # Meta
    ml_skipped:      bool = False
    reason:          str = ""
    elapsed_ms:      float = 0.0

    def to_dict(self) -> Dict:
        return {
            "decision":        self.decision.value,
            "url":             self.url,
            "domain":          self.domain,
            "trie_result":     self.trie_result,
            "bloom_result":    self.bloom_result,
            "bloom_score":     self.bloom_score,
            "heuristic_score": self.heuristic_score,
            "ml_skipped":      self.ml_skipped,
            "reason":          self.reason,
            "elapsed_ms":      self.elapsed_ms,
        }


# ── Built-in domain datasets ──────────────────────────────────────────────────

# Whitelisted safe domains (top Alexa/Tranco sites)
_SAFE_DOMAINS: List[str] = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "reddit.com", "github.com", "wikipedia.org",
    "amazon.com", "apple.com", "microsoft.com", "netflix.com", "spotify.com",
    "stackoverflow.com", "mozilla.org", "cloudflare.com", "dropbox.com",
    "adobe.com", "salesforce.com", "oracle.com", "ibm.com", "zoom.us",
    "slack.com", "notion.so", "twitch.tv", "discord.com", "telegram.org",
    "whatsapp.com", "bbc.com", "cnn.com", "reuters.com", "theguardian.com",
    "nytimes.com", "washingtonpost.com", "forbes.com", "medium.com",
    "mit.edu", "stanford.edu", "harvard.edu", "nasa.gov", "nih.gov",
    "python.org", "nodejs.org", "rust-lang.org", "golang.org",
    "docker.com", "kubernetes.io", "pytorch.org", "tensorflow.org",
    "paypal.com", "ebay.com", "visa.com", "mastercard.com",
]

# Known malicious domain prefixes/patterns
_MALICIOUS_DOMAINS: List[str] = [
    # Typosquat patterns
    "paypa1.com", "paypa1-secure.xyz", "paypa1-login.xyz",
    "g00gle.com", "g00gle-secure.xyz", "g0ogle.com",
    "micros0ft.com", "micros0ft-account.xyz", "microsoft-support.top",
    "app1e.com", "app1e-id.xyz", "apple-id-verify.click",
    "amaz0n.com", "arnazon.com", "amazon-security.xyz",
    # Phishing patterns
    "secure-paypal.xyz", "paypal-secure-login.xyz", "paypal-verify.top",
    "secure-banking-update.xyz", "bank-secure-login.top",
    "account-verify-login.xyz", "login-verify-account.click",
    "free-prize-winner.top", "claim-reward-now.xyz",
    "crypto-wallet-recovery.tk", "bitcoin-recovery.xyz",
    # Malware delivery
    "malware-download.top", "exploit-kit.xyz", "ransomware-unlock.click",
    "trojan-install.xyz", "virus-payload.top",
]

# Malicious keyword prefixes (for trie prefix matching)
_MALICIOUS_PREFIXES: List[str] = [
    "secure-paypal.",
    "paypal-secure.",
    "login-verify.",
    "account-suspended.",
    "secure-banking.",
    "free-prize.",
    "crypto-wallet.",
    "bitcoin-recovery.",
    "malware-download.",
    "exploit-kit.",
]


# ── Filter Pipeline ───────────────────────────────────────────────────────────

class FilterPipeline:
    """
    The Stage 1 Decision Gate.
    Sits in front of the ML core and pre-screens all incoming URLs.

    Configuration
    -------------
    heuristic_block_threshold : float
        If heuristic_score >= this AND bloom also hits → BLOCK (default 0.70)
    heuristic_flag_threshold : float
        If heuristic_score >= this → adds to FORWARD signal even without bloom
    """

    def __init__(
        self,
        bloom: BloomFilterEnsemble,
        trie:  DomainTrieMatcher,
        heuristics: HeuristicsEngine,
        heuristic_block_threshold: float = 0.70,
        heuristic_flag_threshold:  float = 0.35,
    ):
        self._bloom = bloom
        self._trie  = trie
        self._heur  = heuristics
        self._block_threshold = heuristic_block_threshold
        self._flag_threshold  = heuristic_flag_threshold

        # Stats
        self._total     = 0
        self._blocked   = 0
        self._passed    = 0
        self._forwarded = 0

    def run(self, url: str) -> PipelineResult:
        """
        Execute the 3-stage filter pipeline.

        Stage 1 — Trie Matcher (fastest: O(|domain|))
          safe     → PASS  immediately
          malicious→ BLOCK immediately
          unknown  → continue

        Stage 2 — Bloom Ensemble (O(k) hash operations)
          KNOWN_SAFE      → PASS  immediately
          KNOWN_MALICIOUS → check heuristics before blocking
          UNCERTAIN       → continue

        Stage 3 — Heuristics (O(n) keyword + entropy)
          score ≥ block_threshold AND bloom hit → BLOCK
          score ≥ flag_threshold               → FORWARD (suspicious)
          else                                 → FORWARD (uncertain)
        """
        t0 = time.perf_counter()
        self._total += 1

        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc.lower().split(":")[0].lstrip("www.")
        except Exception:
            domain = ""

        # ── Stage 1: Trie ────────────────────────────────────────────────────
        trie_result = self._trie.query(url)

        if trie_result == "safe":
            self._passed += 1
            return PipelineResult(
                decision=PipelineDecision.PASS,
                url=url, domain=domain,
                trie_result=trie_result,
                ml_skipped=True,
                reason="Trie whitelist exact/parent match",
                elapsed_ms=_ms(t0),
            )

        if trie_result == "malicious":
            self._blocked += 1
            return PipelineResult(
                decision=PipelineDecision.BLOCK,
                url=url, domain=domain,
                trie_result=trie_result,
                ml_skipped=True,
                reason="Trie blacklist exact/prefix match",
                elapsed_ms=_ms(t0),
            )

        # ── Stage 2: Bloom Ensemble ───────────────────────────────────────────
        bloom_res = self._bloom.query(url)

        if bloom_res.decision == FilterDecision.KNOWN_SAFE:
            self._passed += 1
            return PipelineResult(
                decision=PipelineDecision.PASS,
                url=url, domain=domain,
                trie_result=trie_result,
                bloom_result=bloom_res.decision.value,
                bloom_score=bloom_res.weighted_score,
                ml_skipped=True,
                reason="Bloom ensemble whitelist hit",
                elapsed_ms=_ms(t0),
            )

        # ── Stage 3: Heuristics ───────────────────────────────────────────────
        heur = self._heur.analyze(url)
        h_score = heur["heuristic_score"]

        if bloom_res.decision == FilterDecision.KNOWN_MALICIOUS:
            if h_score >= self._block_threshold:
                # High confidence block: bloom + heuristics both flag it
                self._blocked += 1
                return PipelineResult(
                    decision=PipelineDecision.BLOCK,
                    url=url, domain=domain,
                    trie_result=trie_result,
                    bloom_result=bloom_res.decision.value,
                    bloom_score=bloom_res.weighted_score,
                    heuristic_score=h_score,
                    heuristic_data=heur,
                    ml_skipped=True,
                    reason=(
                        f"Bloom blacklist ({bloom_res.weighted_score:.2f}) "
                        f"+ heuristic ({h_score:.2f} ≥ {self._block_threshold})"
                    ),
                    elapsed_ms=_ms(t0),
                )
            else:
                # Bloom says malicious but heuristics are not definitive
                # → forward to ML with elevated suspicion flag
                self._forwarded += 1
                return PipelineResult(
                    decision=PipelineDecision.FORWARD,
                    url=url, domain=domain,
                    trie_result=trie_result,
                    bloom_result=bloom_res.decision.value,
                    bloom_score=bloom_res.weighted_score,
                    heuristic_score=h_score,
                    heuristic_data=heur,
                    ml_skipped=False,
                    reason="Bloom hit but heuristics inconclusive → ML review",
                    elapsed_ms=_ms(t0),
                )

        # Bloom UNCERTAIN — let heuristics decide forwarding priority
        self._forwarded += 1
        reason = (
            "Heuristic flag (suspicious signals)" if h_score >= self._flag_threshold
            else "No strong signal — standard ML forward"
        )
        return PipelineResult(
            decision=PipelineDecision.FORWARD,
            url=url, domain=domain,
            trie_result=trie_result,
            bloom_result=bloom_res.decision.value,
            bloom_score=bloom_res.weighted_score,
            heuristic_score=h_score,
            heuristic_data=heur,
            ml_skipped=False,
            reason=reason,
            elapsed_ms=_ms(t0),
        )

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> Dict:
        total = max(self._total, 1)
        return {
            "total_queries":   self._total,
            "blocked":         self._blocked,
            "passed":          self._passed,
            "forwarded_to_ml": self._forwarded,
            "ml_skip_rate":    round((self._blocked + self._passed) / total, 3),
            "bloom_stats":     self._bloom.stats(),
            "trie_stats":      self._trie.stats(),
        }

    def __repr__(self):
        return (f"FilterPipeline(total={self._total}, "
                f"blocked={self._blocked}, passed={self._passed}, "
                f"forwarded={self._forwarded})")


# ── Helper ────────────────────────────────────────────────────────────────────

def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


# ── Bootstrap: load built-in domain lists ────────────────────────────────────

def _bootstrap_pipeline(pipeline: FilterPipeline) -> None:
    """Seed the trie and bloom ensemble with built-in domain lists."""
    # Trie
    pipeline._trie.bulk_load_safe(_SAFE_DOMAINS)
    pipeline._trie.bulk_load_malicious(_MALICIOUS_DOMAINS)
    for prefix in _MALICIOUS_PREFIXES:
        pipeline._trie.add_malicious_domain(prefix)

    # Bloom ensemble
    pipeline._bloom.load_safe_domains(_SAFE_DOMAINS)
    pipeline._bloom.load_malicious_domains(_MALICIOUS_DOMAINS)


# ── Module-level singleton ────────────────────────────────────────────────────

filter_pipeline = FilterPipeline(
    bloom=bloom_ensemble,
    trie=domain_trie_matcher,
    heuristics=heuristics_engine,
)
_bootstrap_pipeline(filter_pipeline)
