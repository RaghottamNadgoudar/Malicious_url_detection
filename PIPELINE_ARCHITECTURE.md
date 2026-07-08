# Malicious URL Detection: Complete System Architecture Report

This report describes the full architecture of the optimized Malicious URL Detection pipeline — from how a raw URL (including shortened/redirected URLs) first enters the system, to how the DAA preprocessing layers filter 80% of a large batch before sending only the uncertain remainder to the DistilBERT neural model.

---

## 🌐 Part 1: URL Ingestion — Handling Shortened & Redirected URLs

Before any classification can begin, the system must know **what URL it is actually classifying**. Shortened URLs like `bit.ly/abc123` are opaque — the shortener is meaningless; only the final destination matters. Similarly, phishing attacks commonly use redirect chains to disguise their true destination through layers of benign-looking intermediate hops.

### The Problem: Redirect Chains as an Attack Vector

A classic phishing chain looks like this:

```
bit.ly/aBc9z  →  legit-sounding.com/go?url=redirect1.tk  →  paypal-login.ml/verify
 (shortener)          (open redirect param)                    (actual phishing site)
```

If the system only checks `bit.ly/aBc9z`, it looks completely harmless. The system must **follow the chain to the final destination**, and also flag any suspicious intermediate hops along the way.

---

### Step 1: URL Expansion Service (`url_expander.py`)

The first thing that runs is the `URLExpansionService`. It handles **40+ known URL shortener domains** (including `bit.ly`, `tinyurl.com`, `t.co`, `rb.gy`, `linktr.ee`, etc.) and detects **all 4 types of redirects**:

| Redirect Type | How it Works | Example |
|---|---|---|
| **HTTP 301/302/303/307/308** | Server returns a `Location:` header | Standard web redirects |
| **HTML Meta-Refresh** | `<meta http-equiv="refresh" content="0; url=...">` | Common in phishing pages |
| **JavaScript Redirect** | `window.location = "..."` or `document.location.href` | Dynamic JS-based redirectors |
| **Open Redirect Params** | `?url=`, `?redirect=`, `?goto=`, `?next=` (40+ param names) | Security vulnerability exploited in chains |

The service uses `GET` requests (not `HEAD`) because many phishing/redirect servers ignore `HEAD`. It manually controls each hop with `follow_redirects=False` to build the chain step by step.

**Key Output (HopRecord per step):**
```python
{
  "hop": 2,
  "url": "http://paypal-login.ml/verify",
  "status_code": 200,
  "is_suspicious": True,          # Suspicious TLD: .ml
  "redirect_type": "meta_refresh" # How we got here
}
```

**Safeguards:**
- **Max 15 hops** — stops runaway infinite redirect chains
- **Loop Detection** — tracks `seen` URL set; circular redirects are flagged
- **2.5s timeout per hop** — non-blocking; records dead hops and continues
- **Result caching** — same URL is only traced once per session

---

### Step 2: Redirect Graph Construction & Traversal (`phase1_graph_traversal.py`)
**DAA Algorithm: Graph Traversal — Unit II (BFS/DFS)**

Once the HTTP trace produces a chain, the system models **all URLs in the current batch** as a **Directed Graph**, where an edge `A → B` means "URL A redirects to URL B".

```
Graph Example:
  bit.ly/abc   →   redir1.tk  →   paypal.ml
  google.com   (no edges)
  github.com   (no edges)
```

#### DFS — Iterative Depth-First Search (with Branch & Bound)

```python
def iterative_dfs(start, graph, max_depth=10):
    stack = [(start, 0)]
    while stack:
        node, depth = stack.pop()
        if entropy(node) < 3.0:
            continue   # ← Branch & Bound: prune low-entropy (trivially simple) URLs
        visited.add(node)
        chain.append(node)
        for neighbor in graph[node]:
            stack.append((neighbor, depth + 1))
```

**Why DFS here?** DFS explores a redirect chain to its deepest point first, making it ideal to find the **final destination** (the leaf node) of any chain. It also naturally detects **redirect loops** — if DFS hits a node already in the `visited` set, a loop exists.

**Branch & Bound Pruning:** URLs with Shannon entropy below 3.0 are pruned. Entropy measures character randomness — a legitimate URL like `google.com` has moderate entropy, while a random-looking URL like `x7q2.ml/g3kp` has very high entropy. Low-entropy URLs are likely test or synthetic patterns that waste traversal time.

#### BFS — Iterative Breadth-First Search

```python
def iterative_bfs(start, graph, max_depth=10):
    queue = deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        # ... same entropy pruning
        for neighbor in graph[node]:
            queue.append((neighbor, depth + 1))
```

**Why BFS here?** BFS is used to calculate the **redirect depth** (maximum shortest-path distance from the original URL to any reachable hop). A very high redirect depth (e.g., > 5 hops) is itself a strong signal of a malicious redirect chain, because legitimate websites rarely redirect more than 2-3 times.

#### Topological Sort — Kahn's Algorithm (Unit II: Decrease and Conquer)

```python
def topological_sort(graph):
    # 1. Calculate in-degrees for all nodes
    in_degree = {node: 0 for node in graph}
    for node in graph:
        for neighbor in graph[node]:
            in_degree[neighbor] += 1

    # 2. Start from nodes with no incoming edges (original/root URLs)
    queue = deque([node for node in in_degree if in_degree[node] == 0])
    while queue:
        node = queue.popleft()
        result.append(node)
        for neighbor in graph[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
```

**Why Topological Sort?** The redirect graph is a **DAG** (Directed Acyclic Graph) in the absence of loops. Topological Sort using Kahn's algorithm gives us the **correct processing order**: original/root URLs (those that are not destinations of any other redirect) are processed first, and the final destinations last. This ensures that when we analyze a URL, its redirect ancestor has already been processed and any threat signals can be propagated down the chain.

> [!IMPORTANT]
> If Kahn's algorithm does **not** produce an ordering that covers all nodes, it means there is a **cycle in the redirect graph** — a confirmed redirect loop, which is a strong malicious indicator.

---

### Step 3: Redirect Chain Risk Annotation (`redirect_analyzer.py`)

After BFS/DFS builds the chain, the `RedirectAnalyzerService` annotates each hop with a risk score using the same **Greedy scoring** used in Stage 3:

```python
def _hop_risk_score(url) -> float:
    score = 0.0
    if suspicious_tld:   score += 0.35
    if ip_as_host:       score += 0.30
    if high_entropy:     score += 0.15
    if keyword_hits:     score += keyword_hits / total * 0.20
    return min(score, 1.0)
```

It also detects **cross-domain redirects**: if the domain of the final destination URL is different from the domain of the original URL, it is flagged as a potential open redirect attack (`cross_domain_redirect = True`).

**Output signals passed to classification:**
- `redirect_depth` — number of hops
- `loop_detected` — boolean
- `suspicious_hops` — count of hops with risk score > 0.3
- `max_hop_risk` — highest individual hop risk score
- `cross_domain_redirect` — final domain ≠ original domain
- `is_shortened` — was the original URL a known shortener?

The **final expanded URL** (the leaf of the redirect chain) is what gets passed into the main 6-tier preprocessing pipeline for classification — not the original shortened/masked URL.

---

## 🏗️ Part 2: The 6-Tier Classification Pipeline

Once the true destination URL is known, it enters the batch optimizer pipeline.

````mermaid
graph TD
    A["Incoming URL / Expanded from Redirect"] --> B{"Tier 0: Cisco Umbrella API"}
    B -- "Known Malicious" --> C["🔴 Verdict: MALICIOUS"]
    B -- "Known Safe" --> D["🟢 Verdict: SAFE"]
    B -- "Unknown / Timeout" --> E{"Tier 1: Quicksort + Dedup + Whitelist"}
    E -- "Trusted Domain" --> D
    E -- "Untrusted" --> F{"Tier 2: Horspool Keyword Scan"}
    F -- ">4 phishing keywords" --> C
    F -- "Clean" --> G{"Tier 3: Greedy Hard-Signal Score"}
    G -- "Score > 0.70" --> C
    G -- "Score < 0.70" --> H{"Tier 4: Backtracking Feature Subset"}
    H -- "Feature score > 0.65" --> I["🟡 Verdict: SUSPICIOUS"]
    H -- "Uncertain" --> J["Tier 5: DistilBERT"]
    J --> K["Final Verdict"]
````

### Tier 0: Cisco Umbrella Investigate API
Real-time DNS-layer threat intelligence. Checks the domain against Cisco's global threat database. Known-bad → immediate block. Known-good → immediate safe clearance. Unknown → fall through. Non-blocking 2.5s timeout ensures the pipeline never stalls.

### Tier 1: Deduplication + Whitelisting
- **Quicksort** (Unit II): Sorts 1000 URLs by domain in `O(n log n)` so identical URLs are adjacent, enabling `O(n)` deduplication in one pass.
- **Hash Set Lookup** (Unit I): `O(1)` check against trusted domain list (google.com, rvce.edu.in, .gov.in, etc.)

### Tier 2: Horspool Keyword Scan
- **Horspool's Algorithm** (Unit III – Space-Time Tradeoff): Pre-computes shift tables for 34 phishing keywords. Scans each URL in `O(n/m)` average time. High keyword density → instant malicious flag.

### Tier 3: Greedy Hard-Signal Scoring
- **Greedy Technique** (Unit IV): Analogous to Fractional Knapsack. Independently evaluates structural signals (suspicious TLD, IP host, high entropy, brand-in-subdomain, excess hyphens) and sums them. Score ≥ 0.70 → malicious.

### Tier 4: Backtracking Feature Selection
- **Sum-of-Subsets** (Unit V): At init time, backtracking finds the optimal subset of 12 features (from 14 candidates) that maximizes discriminative power within a 5ms latency budget, by treating feature extraction cost as a 0/1 Knapsack with branch-and-bound pruning.

### Tier 5: DistilBERT (Neural Inference)
Only the uncertain URLs reach here (~20% of the original batch). DistilBERT catches zero-day phishing, subtle semantic brand impersonation, and context-aware patterns that no structural rule can detect.

---

## 📊 Result Aggregation

- **Merge Sort** (Unit II): Stable sort of all classified URLs by confidence score for the risk report. Stable ensures submission order is preserved for equal-confidence URLs.
- **Huffman Coding** (Unit IV): Greedy optimal prefix codes compress the final JSON audit log by ~37%, losslessly.

---

## 🚀 Performance Results (1000-URL Batch)

| Stage | Algorithm | URLs In | URLs Out | Decided |
|---|---|---|---|---|
| Shortener Expansion | BFS/DFS Redirect Graph | 1000 | 1000* | — |
| Dedup + Whitelist | Quicksort + Hash Set | 1000 | 229 | 771 |
| Horspool Keyword | Horspool's Algorithm | 229 | 226 | 3 |
| Greedy Scoring | Greedy (Fractional Knapsack) | 226 | 226 | 0 |
| Backtracking Feats | Sum-of-Subsets | 226 | 198 | 28 |
| **DistilBERT** | Transformer Neural Net | **198** | **198** | **198** |

> [!TIP]
> **Total time: ~3.4 seconds** vs ~25 seconds naive. **7.3× speedup. 80% reduction** in neural network calls. The redirect expansion adds ~50-200ms per unique shortened URL but is fully cached after the first resolve.

---

## 🗂️ File Reference

| File | Role |
|---|---|
| [url_expander.py](file:///Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/api/app/services/url_expander.py) | HTTP redirect chain tracer (all 4 redirect types) |
| [redirect_analyzer.py](file:///Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/api/app/services/redirect_analyzer.py) | Per-hop risk scoring + open redirect detection |
| [phase1_graph_traversal.py](file:///Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/backend/phase1_graph_traversal.py) | DFS, BFS, Topological Sort implementations |
| [batch_optimizer.py](file:///Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/daa_model/batch_optimizer.py) | Quicksort, Horspool, Greedy, Backtracking, Huffman |
| [pipeline_bert.py](file:///Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/daa_model/pipeline_bert.py) | 4-tier DistilBERT pipeline with Umbrella |
| [cisco_umbrella.py](file:///Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/daa_model/cisco_umbrella.py) | Tier-0 real-time threat intelligence client |
| [demo_batch.py](file:///Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/daa_model/demo_batch.py) | End-to-end demo: 1000 URLs → batch optimizer → DistilBERT |
