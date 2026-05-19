# Algorithms Explained - Hybrid URL Detection System

## Table of Contents
1. [Phase 0: URL Expansion](#phase-0-url-expansion)
2. [Phase 1: Graph Traversal (BFS/DFS)](#phase-1-graph-traversal)
3. [Phase 2: Pattern Matching (Boyer-Moore)](#phase-2-pattern-matching)
4. [Phase 3: Neural Network](#phase-3-neural-network)
5. [Phase 4: Greedy Optimization (Dijkstra)](#phase-4-greedy-optimization)
6. [Phase 5: Bloom Filter](#phase-5-bloom-filter)
7. [Phase 6: Heapsort Ranking](#phase-6-heapsort-ranking)
8. [Phase 7: Transitive Closure (BFS)](#phase-7-transitive-closure)

---

## Phase 0: URL Expansion

### Algorithm: HTTP Redirect Following
**File:** `url_expander.py`

### Purpose
Expands shortened URLs (bit.ly, tinyurl.com, etc.) to their final destination before analysis.

### How It Works

```python
def expand_url(url: str, max_redirects: int = 10, timeout: int = 5) -> Dict:
    """
    Follow HTTP redirects to find final destination.
    """
    current_url = url
    redirect_chain = [url]
    
    for i in range(max_redirects):
        response = session.head(current_url, allow_redirects=False, timeout=timeout)
        
        # Check for redirect status codes
        if response.status_code in [301, 302, 303, 307, 308]:
            next_url = response.headers.get('Location')
            redirect_chain.append(next_url)
            current_url = next_url
        else:
            break  # No more redirects
    
    return {
        'final_url': current_url,
        'redirect_chain': redirect_chain,
        'redirect_count': len(redirect_chain) - 1
    }
```

### Key Concepts


1. **HTTP Status Codes:**
   - `301`: Permanent redirect
   - `302`: Temporary redirect
   - `303`: See other
   - `307`: Temporary redirect (method preserved)
   - `308`: Permanent redirect (method preserved)

2. **HEAD Request:** Fetches only headers (no body), making it faster

3. **Timeout Protection:** Prevents hanging on slow servers

### Complexity
- **Time:** O(k) where k = number of redirects (typically k ≤ 10)
- **Space:** O(k) for storing redirect chain

### Example
```
Input:  https://bit.ly/abc123
Step 1: HEAD request → 301 redirect to tracker.com
Step 2: HEAD request → 302 redirect to evil.com
Output: https://evil.com (analyzed instead of bit.ly)
```

---

## Phase 1: Graph Traversal (BFS/DFS)

### Algorithms: Breadth-First Search & Depth-First Search
**File:** `phase1_graph_traversal.py`

### Purpose
Build and traverse redirect graphs to detect redirect chains and calculate URL entropy.


### 1.1 Shannon Entropy Calculation

```python
def entropy(url: str) -> float:
    """
    Calculate Shannon entropy of a URL string.
    Measures randomness/unpredictability.
    """
    if not url:
        return 0.0
    
    freq = Counter(url)  # Count character frequencies
    total = len(url)
    
    # Shannon entropy formula: H = -Σ(p(x) * log2(p(x)))
    return -sum((c/total) * math.log2(c/total) for c in freq.values())
```

**Explanation:**
- High entropy (>4.5): Random-looking URLs (suspicious)
- Low entropy (<3.0): Simple, repetitive URLs (often legitimate)
- Formula: H(X) = -Σ P(xi) × log₂P(xi)

**Example:**
```
URL: "https://google.com" → Entropy ≈ 3.2 (low, legitimate)
URL: "http://x7k2m9p.tk/a8f3" → Entropy ≈ 4.8 (high, suspicious)
```

### 1.2 Iterative DFS (Depth-First Search)

```python
def iterative_dfs(start: str, graph: Dict[str, List[str]], max_depth: int = 10) -> List[str]:
    """
    DFS with entropy-based Branch & Bound pruning.
    """
    stack = [(start, 0)]  # (node, depth)
    visited = set()
    chain = []
    
    while stack:
        node, depth = stack.pop()
        
        if node in visited or depth > max_depth:
            continue
        
        # Branch & Bound: prune low-entropy URLs
        if entropy(node) < 3.0:
            continue
        
        visited.add(node)
        chain.append(node)
        
        # Add neighbors to stack (LIFO)
        for neighbor in graph.get(node, []):
            stack.append((neighbor, depth + 1))
    
    return chain
```


**Key Features:**
- **Stack-based:** Uses LIFO (Last In, First Out)
- **Branch & Bound:** Prunes subtrees with entropy < 3.0
- **Depth limiting:** Prevents infinite loops

**Complexity:**
- **Time:** O(V + E) where V = vertices, E = edges
- **Space:** O(V) for visited set and stack

### 1.3 Iterative BFS (Breadth-First Search)

```python
def iterative_bfs(start: str, graph: Dict[str, List[str]], max_depth: int = 10) -> List[str]:
    """
    BFS for redirect chain exploration.
    """
    queue = deque([(start, 0)])  # (node, depth)
    visited = set()
    chain = []
    
    while queue:
        node, depth = queue.popleft()  # FIFO
        
        if node in visited or depth > max_depth:
            continue
        
        if entropy(node) < 3.0:
            continue
        
        visited.add(node)
        chain.append(node)
        
        # Add neighbors to queue (FIFO)
        for neighbor in graph.get(node, []):
            queue.append((neighbor, depth + 1))
    
    return chain
```

**Key Features:**
- **Queue-based:** Uses FIFO (First In, First Out)
- **Level-order traversal:** Explores all nodes at depth d before depth d+1
- **Shortest path:** Finds shortest redirect chain

**Complexity:**
- **Time:** O(V + E)
- **Space:** O(V) for queue and visited set


### 1.4 Topological Sort (Kahn's Algorithm)

```python
def topological_sort(graph: Dict[str, List[str]]) -> List[str]:
    """
    Topological sort for DAG processing order.
    """
    # Calculate in-degrees
    in_degree = {node: 0 for node in graph}
    for node in graph:
        for neighbor in graph[node]:
            in_degree[neighbor] = in_degree.get(neighbor, 0) + 1
    
    # Queue of nodes with no incoming edges
    queue = deque([node for node in in_degree if in_degree[node] == 0])
    result = []
    
    while queue:
        node = queue.popleft()
        result.append(node)
        
        # Reduce in-degree of neighbors
        for neighbor in graph.get(node, []):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
    
    return result
```

**Purpose:** Determines optimal processing order for URLs in a redirect graph

**Complexity:**
- **Time:** O(V + E)
- **Space:** O(V)

---

## Phase 2: Pattern Matching (Boyer-Moore)

### Algorithm: Boyer-Moore String Search
**File:** `phase2_pattern_matching.py`

### Purpose
Efficiently search for phishing keywords in URLs using the Boyer-Moore algorithm.


### 2.1 Bad Character Table

```python
def build_bad_char_table(pattern: str) -> Dict[str, int]:
    """
    Build bad character table for Boyer-Moore.
    Maps each character to its rightmost position (excluding last char).
    """
    table = {}
    for i, ch in enumerate(pattern[:-1]):
        table[ch] = len(pattern) - 1 - i
    return table
```

**Example:**
```
Pattern: "login"
Table: {'l': 4, 'o': 3, 'g': 2, 'i': 1}
```

### 2.2 Boyer-Moore Search

```python
def boyer_moore_search(text: str, pattern: str) -> int:
    """
    Boyer-Moore string search - searches from right to left.
    Returns index of first occurrence, or -1 if not found.
    """
    if not pattern or not text:
        return -1
    
    m, n = len(pattern), len(text)
    if m > n:
        return -1
    
    bad_char = build_bad_char_table(pattern)
    
    s = 0  # Shift of the pattern
    while s <= n - m:
        j = m - 1  # Start from rightmost character
        
        # Keep reducing j while characters match
        while j >= 0 and pattern[j] == text[s + j]:
            j -= 1
        
        if j < 0:
            return s  # Pattern found!
        
        # Shift pattern based on bad character rule
        shift = bad_char.get(text[s + j], m)
        s += max(1, shift)
    
    return -1
```


**How It Works:**

1. **Right-to-left comparison:** Unlike naive search, compares from right
2. **Bad character rule:** When mismatch occurs, shift pattern based on bad character table
3. **Skip unnecessary comparisons:** Can skip multiple characters at once

**Example:**
```
Text:    "https://secure-paypal-login.com"
Pattern: "login"

Step 1: Compare from right
        "https://secure-paypal-login.com"
                                 "login"
                                      ↑ Match!

Step 2: Found at index 24
```

**Complexity:**
- **Best case:** O(n/m) - can skip m characters at a time
- **Worst case:** O(n×m) - rare in practice
- **Average case:** O(n) - much faster than naive O(n×m)

### 2.3 Horspool Algorithm (Simplified Boyer-Moore)

```python
def horspool_search(text: str, pattern: str) -> int:
    """
    Horspool algorithm - simplified Boyer-Moore.
    Only uses bad character rule, no good suffix rule.
    """
    m, n = len(pattern), len(text)
    
    # Build shift table
    shift = {ch: m for ch in set(text)}
    for i in range(m - 1):
        shift[pattern[i]] = m - 1 - i
    
    i = 0
    while i <= n - m:
        j = m - 1
        while j >= 0 and pattern[j] == text[i + j]:
            j -= 1
        
        if j < 0:
            return i
        
        # Shift based on rightmost character
        i += shift.get(text[i + m - 1], m)
    
    return -1
```


### 2.4 Input Enhancement (Adversarial Normalization)

```python
def normalize_url(url: str) -> str:
    """
    Apply transformations to expose obfuscated patterns.
    """
    # 1. Percent decode: %6C%6F%67%69%6E → login
    url = unquote(url)
    
    # 2. Lowercase
    url = url.lower()
    
    # 3. Leetspeak expansion: p4yp4l → paypal
    leet_map = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b'}
    url = ''.join(leet_map.get(ch, ch) for ch in url)
    
    # 4. Collapse hyphens: pay-pal → paypal
    url = url.replace('-', '').replace('_', '')
    
    return url
```

**Example:**
```
Original: "https://p4y-p4l-l0g1n.com/%6C%6F%67%69%6E"
Step 1:   "https://p4y-p4l-l0g1n.com/login" (percent decode)
Step 2:   "https://p4y-p4l-l0g1n.com/login" (lowercase)
Step 3:   "https://pay-pal-login.com/login" (leetspeak)
Step 4:   "https://paypallogin.com/login" (collapse hyphens)
Result:   Now "paypal" and "login" keywords are detectable!
```

---

## Phase 3: Neural Network

### Algorithm: Feedforward Neural Network with Backpropagation
**File:** `phase3_neural_classifier.py`

### Purpose
Deep learning model for URL classification using extracted features.


### 3.1 Network Architecture

```python
model = Sequential([
    # Input layer: 15 features
    Dense(64, activation='relu', input_shape=(15,)),
    BatchNormalization(),
    Dropout(0.3),
    
    # Hidden layer
    Dense(32, activation='relu'),
    BatchNormalization(),
    Dropout(0.2),
    
    # Output layer: binary classification
    Dense(1, activation='sigmoid')
])
```

**Architecture:**
```
Input (15 features)
    ↓
Dense Layer (64 neurons, ReLU)
    ↓
Batch Normalization
    ↓
Dropout (30%)
    ↓
Dense Layer (32 neurons, ReLU)
    ↓
Batch Normalization
    ↓
Dropout (20%)
    ↓
Output (1 neuron, Sigmoid) → Probability [0, 1]
```

### 3.2 Feature Extraction

```python
def extract_features(url: str, phase1_result: Dict, phase2_result: Dict) -> np.array:
    """
    Extract 15 features from URL and previous phase results.
    """
    features = [
        len(url),                              # 1. URL length
        phase1_result['entropy'],              # 2. Shannon entropy
        phase2_result['digit_ratio'],          # 3. Digit ratio
        phase2_result['dot_count'],            # 4. Dot count
        phase2_result['hyphen_count'],         # 5. Hyphen count
        int(phase2_result['has_ip_address']),  # 6. Has IP address
        url.count('/') - 2,                    # 7. Subdomain depth
        url.count('/') - 2,                    # 8. Path depth
        int(url.startswith('https')),          # 9. Has HTTPS
        get_tld_suspicion(url),                # 10. TLD suspicion
        phase2_result['pattern_score'],        # 11. Pattern score
        phase1_result['redirect_depth'],       # 12. Redirect depth
        phase2_result['special_char_ratio'],   # 13. Special char ratio
        abs(phase1_result['entropy'] - 4.0),   # 14. Entropy delta
        estimate_domain_age(url)               # 15. Domain age proxy
    ]
    return np.array(features).reshape(1, -1)
```


### 3.3 Forward Propagation

```python
# Simplified forward pass
def forward_pass(X, weights, biases):
    """
    Forward propagation through network.
    """
    # Layer 1
    z1 = np.dot(X, weights[0]) + biases[0]
    a1 = relu(z1)  # ReLU activation
    
    # Layer 2
    z2 = np.dot(a1, weights[1]) + biases[1]
    a2 = relu(z2)
    
    # Output layer
    z3 = np.dot(a2, weights[2]) + biases[2]
    output = sigmoid(z3)  # Sigmoid for probability
    
    return output

def relu(x):
    """ReLU: max(0, x)"""
    return np.maximum(0, x)

def sigmoid(x):
    """Sigmoid: 1 / (1 + e^(-x))"""
    return 1 / (1 + np.exp(-x))
```

### 3.4 Training (Backpropagation)

```python
model.compile(
    optimizer=Adam(learning_rate=0.001),
    loss='binary_crossentropy',
    metrics=['accuracy', AUC(name='auc')]
)

history = model.fit(
    X_train, y_train,
    validation_data=(X_val, y_val),
    epochs=50,
    batch_size=32,
    callbacks=[early_stopping, reduce_lr]
)
```

**Key Concepts:**
- **Binary Cross-Entropy Loss:** L = -[y log(ŷ) + (1-y) log(1-ŷ)]
- **Adam Optimizer:** Adaptive learning rate optimization
- **Dropout:** Randomly drops neurons to prevent overfitting
- **Batch Normalization:** Normalizes layer inputs for stable training

**Complexity:**
- **Training:** O(n × e × f) where n=samples, e=epochs, f=features
- **Inference:** O(1) - constant time for single prediction

---


## Phase 4: Greedy Optimization (Dijkstra)

### Algorithm: Dijkstra's Shortest Path
**File:** `phase4_greedy_optimization.py`

### Purpose
Find shortest path to known malicious URLs in the redirect graph using greedy approach.

### 4.1 Dijkstra's Algorithm

```python
def dijkstra_shortest_path(graph: Dict, start: str, malicious_urls: Set[str]) -> Dict:
    """
    Find shortest path from start to any malicious URL.
    Uses min-heap for greedy selection.
    """
    # Initialize distances
    distances = {node: float('inf') for node in graph}
    distances[start] = 0
    
    # Priority queue: (distance, node)
    pq = [(0, start)]
    visited = set()
    parent = {start: None}
    
    while pq:
        current_dist, current = heapq.heappop(pq)
        
        if current in visited:
            continue
        
        visited.add(current)
        
        # Found malicious URL?
        if current in malicious_urls:
            return {
                'found': True,
                'distance': current_dist,
                'path': reconstruct_path(parent, start, current)
            }
        
        # Explore neighbors
        for neighbor in graph.get(current, []):
            distance = current_dist + 1  # Edge weight = 1
            
            if distance < distances.get(neighbor, float('inf')):
                distances[neighbor] = distance
                parent[neighbor] = current
                heapq.heappush(pq, (distance, neighbor))
    
    return {'found': False, 'distance': float('inf'), 'path': []}
```


**How It Works:**

1. **Greedy Selection:** Always picks node with smallest distance (min-heap)
2. **Relaxation:** Updates distances if shorter path found
3. **Optimal Substructure:** Shortest path contains shortest subpaths

**Example:**
```
Graph:
  A → B → C (malicious)
  A → D → C

Start: A
Malicious: {C}

Step 1: Visit A (dist=0)
Step 2: Visit B (dist=1), D (dist=1)
Step 3: Visit C (dist=2) ← Found malicious!
Result: Path A→B→C, distance=2
```

**Complexity:**
- **Time:** O((V + E) log V) with min-heap
- **Space:** O(V) for distances and priority queue

### 4.2 Greedy Feature Selection

```python
def calculate_threat_score(url_data: Dict, weights: Dict) -> float:
    """
    Greedy weighted sum of features.
    """
    score = 0.0
    
    # Greedily add highest-weight features first
    if url_data.get('in_malicious_set'):
        score += weights['malicious'] * 1.0  # Highest weight
    
    if url_data.get('redirect_depth', 0) > 3:
        score += weights['redirect'] * 0.8
    
    if url_data.get('pattern_score', 0) > 0.5:
        score += weights['pattern'] * 0.6
    
    return min(score, 1.0)
```

---

## Phase 5: Bloom Filter

### Algorithm: Bloom Filter with LSH
**File:** `phase5_bloom_filter.py`

### Purpose
Probabilistic data structure for fast malicious URL lookup with minimal memory.


### 5.1 Bloom Filter Implementation

```python
class BloomFilter:
    def __init__(self, size: int = 1000000, num_hashes: int = 7):
        """
        Initialize Bloom filter.
        size: bit array size
        num_hashes: number of hash functions
        """
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)
    
    def _hash(self, item: str, seed: int) -> int:
        """Generate hash using MurmurHash3."""
        return mmh3.hash(item, seed) % self.size
    
    def add(self, item: str):
        """Add item to Bloom filter."""
        for i in range(self.num_hashes):
            index = self._hash(item, i)
            self.bit_array[index] = 1
    
    def contains(self, item: str) -> bool:
        """Check if item might be in set (probabilistic)."""
        for i in range(self.num_hashes):
            index = self._hash(item, i)
            if self.bit_array[index] == 0:
                return False  # Definitely not in set
        return True  # Probably in set
```

**How It Works:**

1. **Add:** Hash item k times, set k bits to 1
2. **Query:** Hash item k times, check if all k bits are 1
3. **False positives possible:** Bits might be set by other items
4. **False negatives impossible:** If item was added, all bits are guaranteed to be 1

**Example:**
```
Bloom Filter (size=10, k=3 hashes)
Initial: [0,0,0,0,0,0,0,0,0,0]

Add "evil.com":
  hash1("evil.com") = 2 → [0,0,1,0,0,0,0,0,0,0]
  hash2("evil.com") = 5 → [0,0,1,0,0,1,0,0,0,0]
  hash3("evil.com") = 8 → [0,0,1,0,0,1,0,0,1,0]

Query "evil.com":
  Check bits 2,5,8 → All 1 → Probably in set ✓

Query "good.com":
  hash1("good.com") = 3 → bit[3]=0 → Definitely not in set ✗
```


**Complexity:**
- **Time:** O(k) for add/query where k = number of hash functions
- **Space:** O(m) where m = bit array size
- **False positive rate:** ≈ (1 - e^(-kn/m))^k

### 5.2 Locality-Sensitive Hashing (LSH)

```python
def lsh_similarity(url1: str, url2: str, num_hashes: int = 10) -> float:
    """
    Calculate similarity using MinHash LSH.
    """
    # Create shingles (character n-grams)
    shingles1 = set(url1[i:i+3] for i in range(len(url1)-2))
    shingles2 = set(url2[i:i+3] for i in range(len(url2)-2))
    
    # MinHash signatures
    sig1 = [min(hash(s + str(i)) for s in shingles1) for i in range(num_hashes)]
    sig2 = [min(hash(s + str(i)) for s in shingles2) for i in range(num_hashes)]
    
    # Jaccard similarity estimate
    matches = sum(1 for i in range(num_hashes) if sig1[i] == sig2[i])
    return matches / num_hashes
```

**Purpose:** Find similar URLs even if not exact match

---

## Phase 6: Heapsort Ranking

### Algorithm: Heapsort + Huffman Coding
**File:** `phase6_heapsort_ranking.py`

### 6.1 Heapsort

```python
def heapify(arr: List, n: int, i: int, key_func=None):
    """
    Heapify subtree rooted at index i.
    """
    largest = i
    left = 2 * i + 1
    right = 2 * i + 2
    
    if left < n and key_func(arr[left]) > key_func(arr[largest]):
        largest = left
    
    if right < n and key_func(arr[right]) > key_func(arr[largest]):
        largest = right
    
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]
        heapify(arr, n, largest, key_func)

def heapsort(arr: List, key_func=None, reverse=False):
    """
    Heapsort - O(n log n) in-place sorting.
    """
    n = len(arr)
    
    # Build max heap
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i, key_func)
    
    # Extract elements
    for i in range(n - 1, 0, -1):
        arr[0], arr[i] = arr[i], arr[0]
        heapify(arr, i, 0, key_func)
    
    if reverse:
        arr.reverse()
```

**Complexity:**
- **Time:** O(n log n) - always, no best/worst case
- **Space:** O(1) - in-place sorting

### 6.2 Huffman Coding

```python
def build_huffman_tree(text: str) -> HuffmanNode:
    """
    Build Huffman tree for entropy baseline.
    """
    freq_map = Counter(text)
    heap = [HuffmanNode(char, freq) for char, freq in freq_map.items()]
    heapq.heapify(heap)
    
    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        merged = HuffmanNode(None, left.freq + right.freq)
        merged.left = left
        merged.right = right
        heapq.heappush(heap, merged)
    
    return heap[0]
```

**Purpose:** Calculate expected code length for anomaly detection

---

## Phase 7: Transitive Closure (BFS)

### Algorithm: BFS-based Transitive Closure
**File:** `phase4_greedy_optimization.py`

```python
def build_transitive_closure(graph: Dict[str, List[str]]) -> Dict[str, Set[str]]:
    """
    Build transitive closure using BFS.
    Optimized replacement for Warshall's O(V³) algorithm.
    """
    closure = {node: set() for node in graph}
    
    for start in graph:
        # BFS from each node
        queue = deque([start])
        visited = set()
        
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            
            if node != start:
                closure[start].add(node)
            
            for neighbor in graph.get(node, []):
                queue.append(neighbor)
    
    return closure
```

**Complexity:**
- **Time:** O(V × E) - BFS from each vertex
- **Space:** O(V²) for closure matrix
- **Improvement:** Much faster than Warshall's O(V³) for sparse graphs

---

## Summary Table

| Phase | Algorithm | Time Complexity | Space Complexity | Purpose |
|-------|-----------|----------------|------------------|---------|
| 0 | HTTP Redirect Following | O(k) | O(k) | Expand shortened URLs |
| 1 | BFS/DFS | O(V + E) | O(V) | Graph traversal |
| 1 | Shannon Entropy | O(n) | O(1) | Measure randomness |
| 1 | Topological Sort | O(V + E) | O(V) | Processing order |
| 2 | Boyer-Moore | O(n/m) avg | O(m) | Pattern matching |
| 2 | Horspool | O(n) avg | O(m) | Simplified Boyer-Moore |
| 3 | Neural Network | O(1) inference | O(w) | Classification |
| 4 | Dijkstra | O((V+E) log V) | O(V) | Shortest path |
| 5 | Bloom Filter | O(k) | O(m) | Membership test |
| 5 | LSH MinHash | O(n) | O(k) | Similarity search |
| 6 | Heapsort | O(n log n) | O(1) | Ranking |
| 6 | Huffman Coding | O(n log n) | O(n) | Entropy baseline |
| 7 | BFS Transitive Closure | O(V × E) | O(V²) | Reachability |

---

## Key Takeaways

1. **Graph Algorithms:** BFS/DFS for traversal, Dijkstra for optimization
2. **String Algorithms:** Boyer-Moore for efficient pattern matching
3. **Probabilistic:** Bloom filters for space-efficient lookups
4. **Machine Learning:** Neural networks for learned classification
5. **Sorting:** Heapsort for guaranteed O(n log n) performance
6. **Optimization:** Greedy algorithms for feature selection
7. **Information Theory:** Shannon entropy and Huffman coding for anomaly detection

Each algorithm is chosen for its specific strengths in the URL detection pipeline!
