# Malicious URL Detection Pipeline — Comprehensive Methodology

This document outlines the detailed working, mathematical logic, algorithms, and architectural flow of the **Hybrid Malicious URL Detection System**. The system is split into two logical phases: **Phase A (Redirect Resolution)** and **Phase B (Multi-Tier Classification)**.

---

## 1. High-Level Architectural Flow

```
                  ┌──────────────────────────────┐
                  │       Incoming URL(s)        │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │ Phase A: Redirect Resolution │
                  │  (url_expander.py / hops)    │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │ Phase B: Multi-Tier Engine   │
                  │  (cisco_umbrella / app_nn)   │
                  └──────────────┬───────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Tier 0: Threat  │     │  Tier 1: Local  │     │ Tier 2: Neural  │
│      Intel      │     │    Whitelist    │     │   Classifier    │
│ (URLhaus Cache) │     │ (O(1) Set Check)│     │  (DistilBERT)   │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         ▼                       ▼                       ▼
         ├───────────────────────┴───────────────────────┤
         ▼
┌─────────────────┐
│  Tier 3: Hard   │ ◄── Override / Boost (Capped 0.0 - 1.0)
│   Structure     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Final Verdict   │ ──► [Safe | Suspicious | Malicious]
└─────────────────┘
```

---

## 2. Phase A: Redirect Resolution & Graph Traversal

Shortened or obfuscated URLs (e.g., `t.co`, `bit.ly`) bypass direct scans by resolving to target sites at client execution time. Phase A follows this redirect chain to ensure the final payload is analyzed.

### 2.1 HTTP Redirect Following
- **Module:** `url_expander.py`
- **Execution:** Follows HTTP redirects sequentially using a stateful request session.
- **Constraints & Parameters:**
  - **Connection Mode:** `GET` request (not `HEAD`, to catch JavaScript & Meta-refresh redirects).
  - **Redirect Depth:** Maximum 15 hops.
  - **Timeout:** 2.5 seconds per hop.
  - **Loop Detection:** Uses a hash set containing all visited URLs. If a duplicate is hit, the traversal aborts immediately to prevent stack overflows.

### 2.2 Redirect Types Detected
1.  **HTTP Redirects:** Status codes `301`, `302`, `303`, `307`, and `308`.
2.  **HTML Meta-Refresh:** Parsed using Regex searching for `<meta http-equiv="refresh" content="... url=...">`.
3.  **JavaScript Redirects:** Scans HTML bodies for location overrides (`window.location.href`, `document.location.href`).
4.  **Open Redirect Parameters:** Scans query strings for redirect indicators (`?url=`, `?goto=`, `?redirect=`, `?next=`).

---

## 3. Phase B: The Multi-Tier Classifier

Every resolved URL is evaluated through a 4-tier decision cascade. The system exits early at the first tier that produces a high-confidence verdict.

### 3.1 Tier 0: Live Threat Intel (URLhaus / Cisco Umbrella)
- **Module:** `cisco_umbrella.py` (interfacing with abuse.ch URLhaus API)
- **Objective:** Check if the domain or exact URL matches a registry of active malware distributors.
- **Verification Cache:** To prevent slowing the classification loop, results are saved in a thread-safe LRU cache dictionary (`_TTLCache`) with a 600-second TTL.
- **Verdict Mapping:**
  - `url_status == "online"` (active malware) $\rightarrow$ **MALICIOUS** (Confidence $\ge 75\%$).
  - `url_status == "offline"` (inactive threat history) $\rightarrow$ **SUSPICIOUS** (Confidence $= 55\%$).
  - `no_results` $\rightarrow$ **UNKNOWN** (pass through to subsequent tiers).

### 3.2 Tier 1: Local Whitelist
- **Module:** `pipeline_bert.py` (using `is_whitelisted`)
- **Objective:** Instantly pass highly popular, trusted institutional domain structures.
- **Algorithm:** $O(1)$ Hash Set lookup on domain names.
- **Institutional Rule:** Automatically passes Indian, UK, and Australian government/educational suffixes: `.gov.in`, `.ac.in`, `.edu.in`, `.gov.uk`, `.ac.uk`, `.gov.au`, `.ac.au`.

### 3.3 Tier 2: Neural Transformer (DistilBERT Classifier)
- **Module:** `pipeline_bert.py` (via `BertPipeline`)
- **Objective:** Evaluate arbitrary URL strings for lexical, semantic, and structure-spoofing patterns.
- **Model details:**
  - **Architecture:** DistilBERT model mapping the `[CLS]` token sequence representation into a 1-dimensional output logit.
  - **Tokenizer Configuration:** Maximum sequence length set to 128 characters.
  - **Logit Calibration:** The raw logits are scaled to de-saturate probabilities:
    $$\text{Prob} = \frac{1}{1 + e^{-\text{logit} / 15.0}}$$
  - **Decision Thresholds:**
    - $\text{Score} < 0.35 \rightarrow$ **SAFE**
    - $0.35 \le \text{Score} < 0.60 \rightarrow$ **SUSPICIOUS**
    - $\text{Score} \ge 0.60 \rightarrow$ **MALICIOUS**

### 3.4 Tier 3: Hard Signal Supplement
- **Module:** `pipeline_bert.py` (via `_hard_signal`)
- **Objective:** Act as a guardrail against false negatives by analyzing the physical URL layout.
- **Contributions (capped at 1.0):**
  - **Suspicious TLD:** $+0.40$ (e.g., `.tk`, `.ml`, `.xyz`, `.work`).
  - **IP Host:** $+0.30$ (IP address used as hostname).
  - **@ Symbol:** $+0.25$ (credential stuffing obfuscation).
  - **Brand Spoof:** $+0.35$ (popular brand name matched in subdomain/path but not the root domain).
  - **Phishing Keywords:** $+ (\text{Keyword Score} \times 0.20)$ (via Horspool table hits).
  - **Double-Slash Path:** $+0.15$ (presence of `//` inside URL path).
  - **High Entropy:** $+0.10$ (Shannon entropy $> 5.0$).
- **Calibration Engine:**
  - **Override (`score >= 0.40`):** Forces malicious status:
    $$\text{Final Prob} = \max(\text{bert\_prob}, 0.80 + \text{score} \times 0.15)$$
  - **Boost (`0.20 <= score < 0.40`):** Boosts classifier threshold:
    $$\text{Final Prob} = \min(1.0, \text{bert\_prob} + 0.12)$$

---

## 4. Batch Optimization Logic (DAA Funnel)

For bulk URL scans, invoking DistilBERT is computationally expensive. The system runs a 5-stage DAA preprocessing pipeline to minimize neural model execution.

```
[Input URLs] ──► [Stage 0: Quicksort + Dedup] 
               └──► [Stage 1: Whitelist Set] ──► [Exit Safe]
                     └──► [Stage 2: Horspool Keyword] ──► [Exit Malicious]
                           └──► [Stage 3: Greedy Knapsack] ──► [Exit Malicious]
                                 └──► [Stage 4: Backtracking] ──► [Exit Safe/Mal/Susp]
                                       └──► [DistilBERT (Remaining Uncertain URLs)]
```

### 4.1 Stage 0: Divide-and-Conquer Deduplication
- **Algorithm:** Quicksort (Median-of-three pivot) sorts URLs by domain.
- **Deduplication:** A linear scan removes duplicate domains/URLs, ensuring adjacent records are not scanned twice.

### 4.2 Stage 1: Whitelist Verification
- Checks the $O(1)$ whitelisted hash-set. Matched URLs exit immediately as **SAFE**.

### 4.3 Stage 2: Boyer-Moore-Horspool Keyword Scan
- Searches the URL for dangerous keywords using precomputed Horspool character shift tables. High-frequency keyword hits trigger an immediate exit as **MALICIOUS**.

### 4.4 Stage 3: Greedy Knapsack Anomaly Scan
- Accumulates structural flags greedily. If the accumulated score is $\ge 0.70$, the URL is immediately classified as **MALICIOUS** without reaching the transformer.

### 4.5 Stage 4: Backtracking Feature Selection (Sum-of-Subsets)
- Solves a 0/1 knapsack constraint to find the most predictive subset of features that fit within a latency budget (e.g. 5ms). Features that exceed the remaining execution budget are pruned.

### 4.6 Lossless Logging Compression
- The final batch logs are compressed using greedy **Huffman Coding**. The character occurrences are built into a min-priority queue to yield prefix-free code tables, reducing server disk footprint.
