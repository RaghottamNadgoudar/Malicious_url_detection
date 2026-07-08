# Malicious URL Detection Pipeline — Comprehensive Methodology

This document outlines the detailed working, mathematical logic, algorithms, and architectural flow of the **Hybrid Malicious URL Detection System**. The system processes URLs through a multi-tier decision cascade designed to balance speed, cost, and accuracy.

---

## 1. High-Level Architectural Flow

```text
                  ┌──────────────────────────────┐
                  │       Incoming URL(s)        │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │  Tier 0: Open PageRank Oracle │
                 │   (Domain Authority Check)    │
                 └───────────────┬───────────────┘
                     │           │
              [Safe] │           │ [Unknown/Low Authority]
                     ▼           ▼
             ┌───────┴───────┐   ┌───────────────────────────────┐
             │               │   │ Tier 1: Local Whitelist &     │
             │   Exit Safe   │◄──┤ Trusted Suffix Rules          │
             │               │   └───────────────┬───────────────┘
             └───────────────┘                   │
                                                 │ [Not Whitelisted]
                                                 ▼
                 ┌───────────────────────────────┐
                 │ Tier 2: Neural Classifier     │
                 │ (DistilBERT [CLS] scoring)    │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │ Tier 3: Hard Signal Supplement│
                 │ (Structural Heuristics Boost) │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
                         ┌───────┴───────┐
                         │ Final Verdict │
                         └───────────────┘
```

---

## 2. Multi-Tier Classification Engine

Every URL is evaluated through a 4-tier decision cascade. The system exits early at the first tier that produces a definitive safe verdict or proceeds to deeper analysis.

### 2.1 Tier 0: Open PageRank Safe Oracle
- **Module:** `cisco_umbrella.py` (interfacing with Open PageRank API) & `pipeline_bert.py`
- **Objective:** Fast-path highly authoritative, trusted domains (e.g., google.com, github.com, amazon.com) without running expensive neural inference. PageRank acts as a **safe-side oracle**.
- **Shortener Resolution (`_resolve_for_pagerank`):**
  - PageRank only indexes main domains. Shortened URLs (e.g., `fkrt.it`, `amzn.to`, `bit.ly`) inherently have near-zero PageRank because they are redirecting services, not real content hosts.
  - If a known shortener is detected (via `url_expander.py`), the pipeline follows HTTP redirects (up to 5 hops) to find the **final destination domain** before querying PageRank.
  - *Note: This expanded URL is ONLY used to verify domain authority with PageRank. DistilBERT always evaluates the original, raw URL to catch obfuscation tricks and tracking garbage.*
- **Algorithm & Verdict Mapping:**
  - Extracts the registrable domain and queries Open PageRank.
  - **OPR $\ge$ 7.0 (Top Authority):** Short-circuits as **SAFE**. DistilBERT is skipped.
  - **OPR $<$ 7.0 or Not Found:** **UNKNOWN**. Falls through to Tier 1.
- **Caching:** Results are cached in a thread-safe LRU cache with a 1-hour TTL, as domain authority changes slowly.

### 2.2 Tier 1: Local Whitelist & Trusted Suffixes
- **Module:** `pipeline_bert.py` (`is_whitelisted`), `trusted_suffixes.py`
- **Objective:** Instantly pass highly popular or institutionally trusted domains offline (~0 ms).
- **Algorithm:** $O(1)$ Hash Set lookup on domain names and suffix matching.
- **Rules:**
  - Exact or subdomain matches against a hardcoded set of top domains (`google.com`, `rvce.edu.in`, `github.com`, etc.).
  - Institutional suffix matching: Automatically passes trusted global education and government suffixes based on the Mozilla Public Suffix List (e.g., `.gov.in`, `.ac.uk`, `.edu`, `.mil`).
  - Matched URLs exit immediately as **SAFE**.

### 2.3 Tier 2: Neural Transformer (DistilBERT Classifier)
- **Module:** `pipeline_bert.py` (`_bert_score`)
- **Objective:** Evaluate arbitrary URL strings for lexical, semantic, and structure-spoofing patterns. Catches zero-day phishing and algorithmic DGA domains that bypass static rules.
- **Model Details:**
  - **Architecture:** Fine-tuned DistilBERT base uncased. Maps the `[CLS]` token sequence representation into a 1-dimensional output logit.
  - **Input:** The **original, unexpanded URL** string (up to 128 tokens).
  - **Logit Calibration:** Raw logits are scaled to de-saturate probabilities before applying the sigmoid function:
    $$\text{Prob} = \frac{1}{1 + e^{-\text{logit} / 15.0}}$$
  - **Decision Thresholds (Base):**
    - $\text{Score} < 0.35 \rightarrow$ **SAFE**
    - $0.35 \le \text{Score} \le 0.60 \rightarrow$ **SUSPICIOUS**
    - $\text{Score} > 0.60 \rightarrow$ **MALICIOUS**

### 2.4 Tier 3: Rule-based Hard Signal Supplement
- **Module:** `pipeline_bert.py` (`_hard_signal`)
- **Objective:** Act as a structural guardrail. It boosts confidence when DistilBERT is uncertain by analyzing physical URL anomalies.
- **Contributions (accumulated score capped at 1.0):**
  - **Suspicious TLD:** $+0.40$ (e.g., `.tk`, `.ml`, `.xyz`).
  - **IP Host:** $+0.30$ (IP address used instead of a hostname).
  - **@ Symbol:** $+0.25$ (often used in credential stuffing/obfuscation).
  - **Brand Spoof:** $+0.35$ (popular brand name matched in subdomain or path, but not the root domain).
  - **Phishing Keywords:** $+ (\text{Keyword Hit Ratio} \times 0.20)$ (e.g., 'login', 'secure', 'banking').
  - **Double-Slash Path:** $+0.15$ (presence of `//` inside the URL path).
  - **High Entropy:** $+0.10$ (Shannon entropy $> 5.0$).
- **Calibration Engine:**
  - Modifies the DistilBERT probability (`bert_prob`) based on the accumulated `hard_score`.
  - **Override (`hard_score >= 0.40`):** Strong structural anomalies force a high probability:
    $$\text{Final Prob} = \max(\text{bert\_prob}, 0.80 + \text{hard\_score} \times 0.15)$$
  - **Boost (`0.20 <= hard_score < 0.40`):** Moderate anomalies slightly boost the probability:
    $$\text{Final Prob} = \min(1.0, \text{bert\_prob} + 0.12)$$
  - The final verdict is then decided using the base thresholds ($0.35$ and $0.60$) on this calibrated `Final Prob`.

---

## 3. Batch Optimization Logic (DAA Funnel)

For bulk URL scans (Batch DAA Mode), invoking DistilBERT on every URL is computationally expensive. The system runs a multi-stage preprocessing funnel (the DAA Funnel) to filter out known safe or definitively malicious URLs before they reach the neural model.

```text
[Input URLs] ──► [Stage 0: Quicksort + Dedup] 
               └──► [Stage 1: Whitelist Set] ──► [Exit Safe]
                     └──► [Stage 2: Horspool Keyword] ──► [Exit Malicious]
                           └──► [Stage 3: Greedy Knapsack] ──► [Exit Malicious]
                                 └──► [Stage 4: Backtracking] ──► [Exit Safe/Mal/Susp]
                                       └──► [DistilBERT (Remaining Uncertain URLs)]
```

*Note: The batch funnel implements optimized algorithmic techniques (Sorting, Hashing, Boyer-Moore-Horspool, Greedy, Backtracking) to rapidly reduce the workload for the heavy ML inference stage.*

### 3.1 Stage 0: Divide-and-Conquer Deduplication
- **Algorithm:** Quicksort (Median-of-three pivot) sorts URLs by domain.
- **Deduplication:** A linear scan removes duplicate domains/URLs, ensuring adjacent records are not scanned twice.

### 3.2 Stage 1: Whitelist Verification
- **Algorithm:** $O(1)$ Hash Set lookup against local whitelists. Matched URLs exit immediately as **SAFE**.

### 3.3 Stage 2: Boyer-Moore-Horspool Keyword Scan
- Searches the URL for dangerous keywords using precomputed Horspool character shift tables. High-frequency keyword hits trigger an immediate exit as **MALICIOUS**.

### 3.4 Stage 3: Greedy Knapsack Anomaly Scan
- Accumulates structural anomaly scores greedily. If the accumulated score exceeds a threshold ($\ge 0.70$), the URL is classified as **MALICIOUS** without reaching the transformer.

### 3.5 Stage 4: Backtracking Feature Selection (Sum-of-Subsets)
- Solves a 0/1 knapsack constraint to find the most predictive subset of features that fit within a latency budget. Features exceeding the budget are pruned.

### 3.6 Lossless Logging Compression (Huffman)
- Batch logs sent to the client are compressed using greedy **Huffman Coding**. Character frequencies are built into a min-priority queue to yield prefix-free codes, reducing payload size and network latency.
