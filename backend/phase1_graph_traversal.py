"""
Phase 1: URL Ingestion & Redirect Graph Construction
BFS/DFS traversal · Topological Sort · Entropy pruning
"""

from collections import Counter, deque
import math
from typing import List, Dict, Set, Tuple


def entropy(url: str) -> float:
    """Calculate Shannon entropy of a URL string."""
    if not url:
        return 0.0
    freq = Counter(url)
    total = len(url)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())


def iterative_dfs(start: str, graph: Dict[str, List[str]], max_depth: int = 10) -> List[str]:
    """
    Iterative DFS with entropy-based Branch & Bound pruning.
    Prunes subtrees where entropy < 3.0 (too simple/repetitive).
    """
    stack = [(start, 0)]
    visited = set()
    chain = []
    
    while stack:
        node, depth = stack.pop()
        
        # Skip if already visited or max depth exceeded
        if node in visited or depth > max_depth:
            continue
        
        # Branch & Bound: prune low-entropy URLs
        if entropy(node) < 3.0:
            continue
        
        visited.add(node)
        chain.append(node)
        
        # Add neighbors to stack
        for nbr in graph.get(node, []):
            stack.append((nbr, depth + 1))
    
    return chain


def iterative_bfs(start: str, graph: Dict[str, List[str]], max_depth: int = 10) -> List[str]:
    """
    Iterative BFS for redirect chain exploration.
    """
    queue = deque([(start, 0)])
    visited = set()
    chain = []
    
    while queue:
        node, depth = queue.popleft()
        
        if node in visited or depth > max_depth:
            continue
        
        # Entropy pruning
        if entropy(node) < 3.0:
            continue
        
        visited.add(node)
        chain.append(node)
        
        for nbr in graph.get(node, []):
            queue.append((nbr, depth + 1))
    
    return chain


def topological_sort(graph: Dict[str, List[str]]) -> List[str]:
    """
    Topological sort using Kahn's algorithm for DAG processing order.
    """
    # Calculate in-degrees
    in_degree = {node: 0 for node in graph}
    for node in graph:
        for neighbor in graph[node]:
            if neighbor not in in_degree:
                in_degree[neighbor] = 0
            in_degree[neighbor] += 1
    
    # Queue of nodes with no incoming edges
    queue = deque([node for node in in_degree if in_degree[node] == 0])
    result = []
    
    while queue:
        node = queue.popleft()
        result.append(node)
        
        for neighbor in graph.get(node, []):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
    
    return result


def calculate_redirect_depth(url: str, graph: Dict[str, List[str]]) -> int:
    """
    Calculate the redirect depth for a URL using BFS.
    Returns the maximum depth in the redirect chain.
    """
    if url not in graph or not graph[url]:
        return 0
    
    max_depth = 0
    queue = deque([(url, 0)])
    visited = set()
    
    while queue:
        node, depth = queue.popleft()
        
        if node in visited:
            continue
        
        visited.add(node)
        max_depth = max(max_depth, depth)
        
        for neighbor in graph.get(node, []):
            queue.append((neighbor, depth + 1))
    
    return max_depth


def build_redirect_graph(urls: List[str], simulate_redirects: bool = True) -> Dict[str, List[str]]:
    """
    Build a redirect graph from URLs.
    In offline mode, simulates redirects for demonstration.
    """
    graph = {url: [] for url in urls}
    
    if simulate_redirects:
        # Simulate 5-10% of URLs having redirect chains
        import random
        random.seed(42)
        
        for i, url in enumerate(urls):
            if random.random() < 0.07:  # 7% have redirects
                # Create a simple redirect chain
                if i + 1 < len(urls):
                    graph[url].append(urls[i + 1])
    
    return graph


class RedirectGraphAnalyzer:
    """Main class for Phase 1 redirect graph analysis."""
    
    def __init__(self):
        self.graph = {}
        self.redirect_depths = {}
    
    def build_graph(self, urls: List[str]):
        """Build the redirect graph from URL list."""
        self.graph = build_redirect_graph(urls)
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyze a single URL and return redirect chain information.
        """
        if url not in self.graph:
            self.graph[url] = []
        
        # Calculate redirect depth
        redirect_depth = calculate_redirect_depth(url, self.graph)
        self.redirect_depths[url] = redirect_depth
        
        # Get redirect chain using DFS
        chain = iterative_dfs(url, self.graph)
        
        # Calculate entropy
        url_entropy = entropy(url)
        
        return {
            'url': url,
            'entropy': url_entropy,
            'redirect_depth': redirect_depth,
            'redirect_chain': chain,
            'chain_length': len(chain)
        }
    
    def get_processing_order(self) -> List[str]:
        """Get topological sort order for processing URLs."""
        return topological_sort(self.graph)
