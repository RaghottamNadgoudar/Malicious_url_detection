# DAA Shield — Code Structure & File Reference

> **Project:** Malicious URL Detection using Design & Analysis of Algorithms  
> **Course:** 4th Semester DAA Lab, RVCE  
> **Stack:** Python (FastAPI + PyTorch) · React + TypeScript (Vite) · Chrome Extension (MV3)

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Repository Layout](#repository-layout)
3. [Backend — `daa_model/`](#backend--daa_model)
4. [Frontend — `frontend_updated/`](#frontend--frontend_updated)
5. [Chrome Extension — `chrome-extension/`](#chrome-extension--chrome-extension)
6. [Documentation — `Documentation/`](#documentation--documentation)
7. [Root-Level Files](#root-level-files)
8. [Data Files](#data-files)
9. [Algorithm Index (DAA Units I–V)](#algorithm-index-daa-units-iv)
10. [API Reference](#api-reference)
11. [How to Run](#how-to-run)

---

## Project Overview

DAA Shield classifies URLs as **Safe / Suspicious / Malicious** using a two-tier hybrid pipeline:

```
URL Input
   │
   ▼
┌─────────────────────────────────────────────────────┐
│  Tier 1 — BatchOptimizer (DAA Funnel, no ML)        │
│                                                     │
│  S0  Hash-based deduplication  (Unit I)             │
│  S1  Whitelist lookup          (Unit I — hash set)  │
│  S2  Horspool keyword scan     (Unit III)           │
│  S3  Greedy structural score   (Unit IV)            │
│  S4  Backtracking feature sel  (Unit V)             │
│       +  Huffman log compress  (Unit IV)            │
└───────────────────┬─────────────────────────────────┘
                    │ uncertain URLs only (~14–50%)
                    ▼
┌─────────────────────────────────────────────────────┐
│  Tier 2 — DistilBERT Neural Inference               │
│  Fine-tuned 66M-param transformer, MPS/CPU          │
└─────────────────────────────────────────────────────┘
```

**Key numbers (on `urls_1000.txt`):**
- 377× faster than naïve (all-DistilBERT) processing
- 14 % of URLs pre-classified before DistilBERT
- 46 % Huffman log compression ratio

---

## Repository Layout

```
Malicious_url_detection/
│
├── daa_model/                  ← Python backend (FastAPI + PyTorch)
│   ├── app_nn.py               ← FastAPI app, all REST endpoints
│   ├── pipeline_bert.py        ← Single-URL inference pipeline (Tier 2)
│   ├── batch_optimizer.py      ← 6-stage DAA BatchOptimizer (Tier 1)
│   ├── bloom_filter_lbf.py     ← Learned Bloom Filter (Unit I)
│   ├── url_expander.py         ← Redirect chain follower / URL unshortener
│   ├── cisco_umbrella.py       ← Tier-0 reputation gate (Cisco Umbrella API)
│   ├── trusted_suffixes.py     ← 405 gov/edu/mil/ac TLDs (Mozilla PSL)
│   ├── demo_batch.py           ← CLI batch demo script
│   ├── expert2_distilbert.pt/  ← Fine-tuned DistilBERT model weights
│   ├── requirements.txt        ← Python dependencies
│   └── .env                    ← Secrets (API keys) — not committed
│
├── frontend_updated/           ← React + TypeScript + Vite frontend
│   ├── src/
│   │   ├── App.tsx             ← Root component, React Router setup
│   │   ├── main.tsx            ← Vite entry point
│   │   ├── index.css           ← Global Tailwind + custom CSS
│   │   ├── pages/
│   │   │   ├── LandingPage.tsx         ← Home / hero page
│   │   │   ├── AnalysisView.tsx        ← /analysis — charts dashboard
│   │   │   ├── pipeline1/
│   │   │   │   └── PipelineOneView.tsx ← /pipeline1 — Batch DAA mode
│   │   │   └── pipeline2/
│   │   │       └── PipelineTwoView.tsx ← /pipeline2 — Deep Scan mode
│   │   ├── components/
│   │   │   ├── shared/
│   │   │   │   ├── Navbar.tsx          ← Top navigation bar
│   │   │   │   └── VerdictBanner.tsx   ← Reusable verdict chip
│   │   │   ├── pipeline1/
│   │   │   │   ├── BatchResultsTable.tsx   ← URL results table
│   │   │   │   ├── FileUploader.tsx         ← Drag-drop .txt uploader
│   │   │   │   ├── FunnelChart.tsx          ← DAA funnel bar chart
│   │   │   │   ├── SpeedupCallout.tsx       ← "377× faster" stat card
│   │   │   │   └── VerdictDonut.tsx         ← Safe/Sus/Mal donut chart
│   │   │   └── pipeline2/
│   │   │       ├── DistilBertTierCard.tsx   ← T2 result card
│   │   │       ├── FeatureGrid.tsx           ← URL feature breakdown
│   │   │       ├── HardSignalTierCard.tsx    ← T3 hard-signal card
│   │   │       ├── UmbrellaTierCard.tsx      ← T0 Umbrella rep card
│   │   │       └── WhitelistTierCard.tsx     ← T1 whitelist card
│   │   ├── services/
│   │   │   └── daaApi.ts       ← Axios API client (all fetch calls)
│   │   └── types/
│   │       └── daaApi.ts       ← TypeScript interfaces for API responses
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.ts
│
├── chrome-extension/           ← Chrome Extension (Manifest V3)
│   ├── manifest.json           ← Extension metadata, permissions
│   ├── icons/                  ← 16/32/48/128px PNG icons
│   ├── popup/
│   │   ├── popup.html          ← Extension popup UI (3 tabs)
│   │   ├── popup.css           ← Professional white-theme styles
│   │   └── popup.js            ← All popup logic (scan, history, settings)
│   ├── background/
│   │   └── service_worker.js   ← Badge updates, context menu
│   └── content/
│       └── content.js          ← Page link extractor + inline highlighter
│
├── Documentation/              ← Reference docs
│   ├── README.md               ← Quick-start guide
│   ├── ALGORITHMS_EXPLAINED.md ← DAA unit-by-unit algorithm walkthrough
│   ├── WORKFLOW_PIPELINE.md    ← End-to-end data flow diagram
│   ├── TRAINING_GUIDE.md       ← How the DistilBERT model was trained
│   ├── TEST_URLS.md            ← Curated test URL sets
│   └── architecture_flowchart_report.pdf
│
├── PIPELINE_ARCHITECTURE.md    ← Architecture overview
├── CODE_STRUCTURE.md           ← This file
├── model_methodology.md        ← Academic methodology write-up
├── README.md                   ← Top-level project README
├── run.sh                      ← One-command startup script
├── urls_1000.txt               ← Original benchmark dataset (1000 URLs)
├── urls_1000_optimized.txt     ← Optimised dataset (>50% pre-classified)
└── .gitignore
```

---

## Backend — `daa_model/`

### `app_nn.py` — FastAPI Application
**Role:** The single entry point for all HTTP traffic. Runs on port **8002**.

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check — returns model load status |
| `/classify` | POST | Single URL → `{verdict, confidence, reasoning}` |
| `/classify-detail` | POST | Single URL → full breakdown including hard-signal scores per component, exit tier |
| `/batch` | POST | Up to 10 URLs classified in sequence |
| `/batch-optimize/stream` | POST | SSE stream — runs full 6-stage DAA funnel then DistilBERT on uncertain URLs |
| `/expand-url` | POST | Follow redirects, return full hop chain |
| `/analysis` | GET | Pre-computed metrics for both URL datasets (funnel, TLDs, keyword freq, etc.) |
| `/analysis/cache` | DELETE | Clear in-process analysis cache to force recompute |

**Key design choices:**
- `_pipeline` is a module-level singleton — DistilBERT loads once, stays in memory
- `/batch-optimize/stream` uses `asyncio.to_thread()` so the optimizer never blocks the event loop
- `/analysis` caches results in `_ANALYSIS_CACHE` dict — instant on re-render

---

### `pipeline_bert.py` — Single-URL Inference (Tier 2)
**Role:** Classifies **one URL** using DistilBERT. Also implements Tier 1 whitelist and Tier 3 hard-signal override.

**Class: `BertPipeline`**

```
BertPipeline.classify(url)
    │
    ├── T0: Cisco Umbrella reputation lookup (if API key set)
    ├── T1: is_whitelisted(url) → uses trusted_suffixes.py
    │         Returns "safe" immediately for .edu/.gov/.mil/major brands
    ├── T2: DistilBERT tokenize → model forward pass → softmax
    └── T3: _hard_signal(url) → override if structural score ≥ 0.75
```

**Key functions:**

| Function | Purpose |
|---|---|
| `is_whitelisted(url)` | Hash-set + PSL suffix lookup; exits before any ML |
| `_hard_signal(url)` | Computes composite suspicion score (IP, @, brand-spoof, entropy, TLD) |
| `_keyword_score(url)` | Keyword density in URL string |
| `_brand_in_subdomain(url, ext)` | Checks if a brand name appears as a subdomain (phishing signal) |
| `_entropy(s)` | Shannon entropy — high entropy → randomised/obfuscated URL |
| `_parse_domain(url)` | Wraps `tldextract` for consistent domain/suffix extraction |

**Model:** `expert2_distilbert.pt` — DistilBERT fine-tuned on ~700k URL dataset.  
**Device:** Auto-selects `mps` (Apple Silicon) → `cuda` → `cpu`.

---

### `batch_optimizer.py` — 6-Stage DAA Funnel (Tier 1)
**Role:** Reduces a large URL batch to only the **uncertain** subset for expensive DistilBERT inference. Implements 5 DAA units.

#### Algorithms by Unit

**Unit I — Hashing & Deduplication (`_quicksort_urls`, `_deduplicate_hash`)**
- Quicksort (median-of-3 pivot) sorts URLs by domain → adjacent duplicates
- SHA-256 hash set eliminates exact duplicates in O(n)
- Whitelist: Python `frozenset` O(1) average lookup

**Unit II — Divide and Conquer (`_quicksort_urls`, `_mergesort_by_risk`)**
- `_quicksort_urls()` — in-place Quicksort on `URLRecord` list by domain string  
- `_mergesort_by_risk()` — stable Merge Sort on decided records by confidence (descending) for risk-ranked output

**Unit III — Space-Time Tradeoff (`horspool_search`, `multi_keyword_scan_horspool`)**
- `_build_horspool_table(pattern)` — builds bad-character shift table O(|pattern|)
- `horspool_search(text, pattern)` — Boyer-Moore-Horspool, average O(n/m)
- `multi_keyword_scan_horspool(url)` — scans for all 40+ `PHISHING_KEYWORDS`, returns (hits, score)

**Unit IV — Greedy + Huffman (`greedy_hard_score`, `huffman_compress_log`)**
- `greedy_hard_score(record)` — greedy fractional-knapsack analogy: each structural signal has fixed weight; sum up all that fire
  - suspicious TLD: +0.40, IP in URL: +0.35, `@` symbol: +0.25, brand-spoof: +0.35, high entropy: +0.10, many hyphens: +0.10
  - **Threshold ≥ 0.70 → classified as malicious immediately**
- `huffman_compress_log(text)` — builds Huffman tree via min-heap, encodes audit log; returns (bit_string, compression_ratio)

**Unit V — Backtracking (`select_features_backtracking`)**
- Sum-of-subsets backtracking: selects highest-value feature subset within `budget_ms` time constraint
- Pruning: if remaining features can't beat current best even if all included, prune the branch
- Feature catalogue: 14 features with (name, cost_ms, discriminative_value)

#### Processing Pipeline

```python
BatchOptimizer.process(urls: list[str]) -> BatchResult:
    S0: Quicksort + hash-set dedup        # Unit I/II
    S1: Whitelist frozenset lookup        # Unit I
    S2: Horspool keyword scan             # Unit III
    S3: Greedy structural score ≥ 0.70   # Unit IV
    S4: select_features_backtracking()   # Unit V (runs once per batch)
    → decided[]       — pre-classified with verdict + confidence
    → uncertain_urls[]— forwarded to DistilBERT
```

**Data Classes:**

| Class | Fields |
|---|---|
| `URLRecord` | `url, domain, suffix, full_domain, verdict, confidence, stage, reason, keyword_hits, hard_score` |
| `BatchResult` | `decided[], uncertain_urls[], stage_counts{}, reduction_pct, elapsed_ms, total_input` |

---

### `bloom_filter_lbf.py` — Learned Bloom Filter
**Role:** Probabilistic membership test for known-malicious URLs. Augments the whitelist with a space-efficient false-positive-free reject filter.

**Implementation:**
- Classical Bloom filter: k hash functions over a bit array
- "Learned" layer: a tiny neural threshold trained on URL features adjusts the filter boundary
- False positive rate configurable (default 0.1%)
- Used as a pre-filter before DistilBERT in high-throughput scenarios

---

### `url_expander.py` — Redirect Chain Follower
**Role:** Expands shortened/redirected URLs to their final destination before classification.

**Key capabilities:**
- Follows up to 10 hops (configurable `max_redirects`)
- Detects 30+ known URL shorteners (bit.ly, t.co, tinyurl, etc.) via `URL_SHORTENERS` set
- Falls back from HTTPS → HTTP if SSL fails
- Returns full `redirect_chain[]`, `status_codes[]`, `redirect_count`

**`is_shortened_url(url)`** — O(1) check against `URL_SHORTENERS` frozenset  
**`expand_url(url)`** — iterative hop-following with timeout + error handling

---

### `cisco_umbrella.py` — Tier-0 Reputation Gate
**Role:** Optional Tier-0 lookup against Cisco Umbrella's threat intelligence API before any local computation.

- Requires `UMBRELLA_INVESTIGATE_TOKEN` in `.env`
- Returns domain reputation: `malicious / suspicious / safe / unavailable`
- If verdict is definitive (malicious/safe), pipeline exits immediately — no ML needed
- Gracefully degrades: if token missing or API unreachable, returns `source: "unavailable"` and pipeline continues

---

### `trusted_suffixes.py` — Mozilla PSL Trusted Domains
**Role:** Auto-generated file containing 405 institutional TLD suffixes from the Mozilla Public Suffix List.

- Covers `edu`, `edu.*`, `gov`, `gov.*`, `ac.*`, `mil`, `mil.*`, `sch.*`, `res.*` globally
- Used by `is_whitelisted()` in `pipeline_bert.py` and `TRUSTED_SUFFIXES` in `batch_optimizer.py`
- Provides `is_trusted_suffix(suffix: str) -> bool` and `TRUSTED_SUFFIXES: frozenset`

**Why PSL?** The same database used by Chrome, Firefox, and Safari to understand domain ownership boundaries.

---

### `demo_batch.py` — CLI Demo Script
**Role:** Stand-alone script to test the BatchOptimizer from the command line without the web server.

```bash
python demo_batch.py urls_1000.txt
```

Prints: funnel reduction, stage counts, speedup vs naïve, sample decided/uncertain URLs.

---

## Frontend — `frontend_updated/`

### Technology Stack
- **React 19** + **TypeScript** + **Vite 8**
- **Tailwind CSS** — dark glass-morphism design system
- **Recharts** — all charts (donut, bar, area, radar)
- **D3** — available for custom visualisations
- **Lucide React** — icon library
- **React Router v7** — client-side routing
- **Axios** — HTTP client

### Routing

| Route | Page | Description |
|---|---|---|
| `/` | `LandingPage` | Hero landing with live single-URL scan |
| `/pipeline1` | `PipelineOneView` | Batch DAA mode — upload .txt file, watch SSE stream |
| `/pipeline2` | `PipelineTwoView` | Deep Scan — single URL with full tier breakdown |
| `/analysis` | `AnalysisView` | Dataset metrics dashboard with 8 charts |

---

### Pages

#### `LandingPage.tsx`
- Hero section with animated background
- Inline single-URL input → calls `/classify`
- Shows live verdict badge
- Links to pipeline pages

#### `PipelineOneView.tsx` — Batch DAA Mode
- Drag-and-drop file uploader (`.txt` with one URL per line)
- Connects to `/batch-optimize/stream` via SSE (`EventSource`)
- Live-updates as events arrive: `start → optimizer_done → url_classified → complete`
- Shows:
  - 6-stage funnel bar chart (FunnelChart)
  - Verdict donut (VerdictDonut)
  - Speedup stat (SpeedupCallout)
  - Full results table sorted by confidence (BatchResultsTable)

#### `PipelineTwoView.tsx` — Deep Scan Mode
- Single URL input → calls `/classify-detail`
- Shows tier cards in order: Umbrella (T0) → Whitelist (T1) → HardSignal (T3) → DistilBERT (T2)
- FeatureGrid shows all URL features with colour-coded risk indicators

#### `AnalysisView.tsx` — Analysis Dashboard
Fetches `GET /analysis` and renders **8 Recharts visualisations**:

| Chart | Type | Shows |
|---|---|---|
| Verdict Distribution | Pie/Donut | Safe / Malicious / Suspicious / Pending per dataset |
| DAA Funnel | Horizontal Bar | Remaining URL count per funnel stage |
| Top TLDs | Grouped Bar | Safe vs Malicious TLD frequency |
| Keyword Frequency | Horizontal Bar | Phishing keyword hit counts |
| URL Length | Area Chart | Distribution of URL lengths |
| Protocol Split | Donut | HTTPS vs HTTP ratio |
| Dataset Comparison | Grouped Bar | Original vs Optimized side-by-side |
| Multi-Metric Radar | Radar | 5-metric comparison across both datasets |

Plus: **stat cards** and a **comparison table** with Δ delta column.

---

### Components

#### Shared
| Component | Purpose |
|---|---|
| `Navbar.tsx` | Fixed top bar with links: Home / Batch DAA / Deep Scan / Analysis |
| `VerdictBanner.tsx` | Reusable safe/suspicious/malicious verdict chip |

#### Pipeline 1
| Component | Purpose |
|---|---|
| `FileUploader.tsx` | Drag-and-drop `.txt` file input |
| `FunnelChart.tsx` | Recharts horizontal bar showing S0→S1→S2→S3→DistilBERT reduction |
| `VerdictDonut.tsx` | Recharts donut for verdict split |
| `SpeedupCallout.tsx` | Big "377×" speedup stat card |
| `BatchResultsTable.tsx` | Sortable table of all URL results |

#### Pipeline 2
| Component | Purpose |
|---|---|
| `UmbrellaTierCard.tsx` | Shows Cisco Umbrella T0 reputation result |
| `WhitelistTierCard.tsx` | Shows T1 whitelist match |
| `HardSignalTierCard.tsx` | Shows T3 structural score breakdown |
| `DistilBertTierCard.tsx` | Shows T2 DistilBERT confidence, top token attributions |
| `FeatureGrid.tsx` | Grid of URL features: HTTPS, length, entropy, TLD, IP, @, etc. |

---

### Services & Types

#### `services/daaApi.ts`
Axios client wrapping every backend call:
```typescript
classify(url)            → POST /classify
classifyDetail(url)      → POST /classify-detail
batchOptimizeStream(urls, onEvent)  → SSE /batch-optimize/stream
expandUrl(url)           → POST /expand-url
getAnalysis()            → GET /analysis
```

#### `types/daaApi.ts`
TypeScript interfaces:
```typescript
ClassifyResult          // verdict, confidence, reasoning, features
ClassifyDetailResult    // + hard_score, exit_tier, hard_signal_breakdown
BatchStreamEvent        // SSE event union: start | optimizer_done | url_classified | complete
AnalysisData            // full /analysis response shape
```

---

## Chrome Extension — `chrome-extension/`

### `manifest.json` — Extension Manifest (MV3)
- Manifest Version 3 (current Chrome standard)
- Permissions: `activeTab`, `tabs`, `storage`, `contextMenus`, `scripting`
- Host permissions: `http://localhost:8002/*` + `<all_urls>` (for page scanning)

### `popup/popup.html` + `popup.css` + `popup.js`

The popup has **3 tabs**:

| Tab | Feature |
|---|---|
| **Scan URL** | Auto-scans current tab on open; manual URL input; optional redirect expansion; shows verdict card with confidence ring, tier chip, redirect chain, feature grid |
| **Page Links** | Scans up to 50 links on current page; live Safe/Suspicious/Malicious count pills |
| **History** | Last 30 scans stored in `chrome.storage.local`; click any to re-run |

Plus a **Settings panel** (⚙) to configure the API base URL.

**Verdict card features:**
- Confidence ring (animated SVG arc)
- Tier chip (T1-Whitelist / T2-DistilBERT / T3-HardSignal)
- Redirect chain list (for shortened URLs)
- Expandable feature grid (HTTPS, length, entropy, TLD, IP, @, etc.)

### `background/service_worker.js`
- Registers two context menus: "Check Link Safety" + "Check This Page"
- On `chrome.tabs.onActivated` / `onUpdated`: calls `/classify` and sets badge
  - 🟢 `✓` green = safe
  - 🟡 `!` yellow = suspicious  
  - 🔴 `✕` red = malicious

### `content/content.js`
- Listens for `GET_LINKS` message → returns all unique `http(s)://` hrefs on the page
- Listens for `HIGHLIGHT_LINKS` → outlines malicious links in red, suspicious in yellow; injects a warning banner at top of page if threats found

---

## Documentation — `Documentation/`

| File | Contents |
|---|---|
| `README.md` | Quick-start: install, run, test |
| `ALGORITHMS_EXPLAINED.md` | Unit-by-unit deep dive: Quicksort, Horspool, Greedy, Huffman, Backtracking with pseudocode |
| `WORKFLOW_PIPELINE.md` | End-to-end data flow from URL input to final verdict |
| `TRAINING_GUIDE.md` | How `expert2_distilbert.pt` was trained: dataset, tokenizer config, fine-tuning hyperparameters |
| `TEST_URLS.md` | Curated test cases: safe, suspicious, malicious, shortened, edge cases |
| `architecture_flowchart_report.pdf` | Formal architecture diagram (PDF) |

---

## Root-Level Files

| File | Purpose |
|---|---|
| `run.sh` | Kills stale processes on ports 8002/5173, starts backend + frontend |
| `README.md` | Project README with badges and quick overview |
| `PIPELINE_ARCHITECTURE.md` | Architecture overview (system design level) |
| `CODE_STRUCTURE.md` | This file |
| `model_methodology.md` | Academic-style methodology write-up for the report |
| `GIT_SETUP.md` | Git setup instructions |
| `CHANGES.md` | Changelog of major feature additions |
| `.gitignore` | Excludes: `.env`, `__pycache__`, `node_modules`, `*.pyc` |

---

## Data Files

### `urls_1000.txt`
- 1000 URLs from real-world traffic
- Lines 1–500: legitimate/popular domains (Google, GitHub, .edu, .gov, CDNs)
- Lines 501–1000: confirmed phishing/malicious samples (wixstudio phishing, allegro scams, crypto drainers, etc.)
- **Benchmark result:** 14% pre-classified before DistilBERT

### `urls_1000_optimized.txt`
- 1000 URLs engineered for demonstration
- ~280 trusted .edu/.gov/major brand domains → caught at S1 whitelist
- ~250 structurally obvious malicious URLs (brand.phish-site.tk pattern) → caught at S3 greedy
- ~470 ambiguous URLs → go to DistilBERT
- **Target:** >50% pre-classified

---

## Algorithm Index (DAA Units I–V)

| Unit | Algorithm | File | Function | Complexity |
|---|---|---|---|---|
| I | Hash-set deduplication | `batch_optimizer.py` | `_deduplicate_hash()` | O(n) average |
| I | Whitelist frozenset lookup | `batch_optimizer.py` | `BatchOptimizer._stage1_whitelist()` | O(1) per URL |
| I | Bloom Filter | `bloom_filter_lbf.py` | `BloomFilter.check()` | O(k) per URL |
| II | Quicksort (median-of-3) | `batch_optimizer.py` | `_quicksort_urls()` | O(n log n) avg |
| II | Merge Sort | `batch_optimizer.py` | `_mergesort_by_risk()` | O(n log n) |
| III | Boyer-Moore-Horspool | `batch_optimizer.py` | `horspool_search()` | O(n/m) avg |
| III | Huffman Coding | `batch_optimizer.py` | `huffman_compress_log()` | O(n log n) |
| IV | Greedy scoring | `batch_optimizer.py` | `greedy_hard_score()` | O(1) per URL |
| V | Backtracking (sum-of-subsets) | `batch_optimizer.py` | `select_features_backtracking()` | O(2^14) pruned |

---

## API Reference

All endpoints run at `http://localhost:8002`.

### POST `/classify`
```json
Request:  { "url": "https://example.com" }
Response: { "url": "...", "verdict": "safe|suspicious|malicious",
            "confidence": 0.97, "reasoning": "Whitelisted domain.",
            "latency_ms": 42 }
```

### POST `/classify-detail`
```json
Response: { ...classify fields...,
  "hard_score": 0.41,
  "exit_tier": "T1-Whitelist|T2-DistilBERT|T3-HardSignal",
  "hard_signal_breakdown": {
    "suspicious_tld": 0.40, "has_ip": 0.0, "has_at": 0.0,
    "brand_in_subdomain": 0.0, "keyword_boost": 0.01,
    "double_slash_path": 0.0, "high_entropy": 0.0
  }
}
```

### POST `/batch-optimize/stream` (SSE)
Events in order:
```
start           → { event, total }
optimizer_done  → { event, stage_counts, decided[], uncertain_count, reduction_pct }
url_classified  → { event, index, total, result }   (one per uncertain URL)
url_error       → { event, index, url, error }
complete        → { event, total_input, decided[], uncertain_results[], huffman_ratio }
```

### POST `/expand-url`
```json
Request:  { "url": "https://bit.ly/3VsGxFZ" }
Response: { "original_url": "...", "final_url": "...",
            "redirect_chain": [...], "redirect_count": 2,
            "is_shortened": true, "expansion_successful": true }
```

### GET `/analysis`
```json
Response: {
  "original":  { "funnel": {...}, "verdict_dist": {...}, "top_mal_tlds": {...}, ... },
  "optimized": { "funnel": {...}, "verdict_dist": {...}, ... }
}
```

---

## How to Run

### Prerequisites
```bash
conda activate tf-metal   # Python env with PyTorch + transformers
cd frontend_updated && npm install
```

### Start Everything
```bash
chmod +x run.sh
./run.sh
```

This script:
1. Kills any existing processes on ports 8002, 5173, 5174
2. Starts `uvicorn app_nn:app` (backend) in background
3. Starts `npm run dev` (frontend) in background

### URLs
| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8002 |
| API Docs (Swagger) | http://localhost:8002/docs |
| Analysis Dashboard | http://localhost:5173/analysis |

### Load Chrome Extension
1. Open `chrome://extensions`
2. Enable **Developer Mode**
3. Click **Load Unpacked**
4. Select the `chrome-extension/` folder
