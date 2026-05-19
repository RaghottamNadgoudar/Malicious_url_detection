"""
Phase 4: Greedy Safe-Skip + Fractional Knapsack Scheduler
Compute budget allocation · Dijkstra-inspired selection · Warshall closure
"""

from typing import List, Dict, Tuple
import heapq


def fractional_knapsack(urls: List[Dict], budget_ms: float = 100) -> List[Dict]:
    """
    Fractional Knapsack algorithm for URL scheduling.
    
    Items: URLs awaiting deep inspection
    Capacity: Compute budget per time window
    Value: threat_prob × entropy_score
    Weight: Lookup cost
    
    Returns: List of URLs to process, sorted by priority
    """
    # Calculate value/weight ratio for each URL
    items = []
    for url_data in urls:
        threat_prob = url_data.get('threat_probability', 0.5)
        entropy = url_data.get('entropy', 3.0)
        lookup_cost = url_data.get('lookup_cost', 1.0)  # milliseconds
        
        value = threat_prob * entropy
        ratio = value / lookup_cost if lookup_cost > 0 else 0
        
        items.append({
            'url_data': url_data,
            'value': value,
            'weight': lookup_cost,
            'ratio': ratio
        })
    
    # Sort by ratio (descending)
    items.sort(key=lambda x: x['ratio'], reverse=True)
    
    # Greedily select items until budget exhausted
    scheduled = []
    remaining_budget = budget_ms
    
    for item in items:
        if remaining_budget <= 0:
            break
        
        if item['weight'] <= remaining_budget:
            scheduled.append(item['url_data'])
            remaining_budget -= item['weight']
        else:
            # Fractional: take partial item
            # In URL context, we either process or skip (0-1 knapsack in practice)
            # But we track that we could partially process
            item['url_data']['partial_processing'] = True
            scheduled.append(item['url_data'])
            break
    
    return scheduled


def bfs_transitive_closure(graph: Dict[str, List[str]]) -> Dict[str, set]:
    """
    BFS-based transitive closure (FASTER than Warshall for sparse graphs).
    
    Complexity: O(V·E) instead of O(V³)
    For sparse graphs where E << V², this is much faster.
    
    Finds all reachable nodes from each node in the redirect graph.
    If URL A transitively redirects to malicious URL B,
    A inherits B's threat label.
    """
    from collections import deque
    
    closure = {}
    
    # For each node, run BFS to find all reachable nodes
    for start_node in graph.keys():
        reachable = set()
        visited = set([start_node])
        queue = deque([start_node])
        
        while queue:
            current = queue.popleft()
            
            # Explore neighbors
            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    reachable.add(neighbor)
                    queue.append(neighbor)
        
        closure[start_node] = reachable
    
    return closure


def warshall_transitive_closure(graph: Dict[str, List[str]]) -> Dict[str, set]:
    """
    Floyd-Warshall algorithm for transitive closure.
    
    ⚠️ WARNING: O(V³) complexity - SLOW for large graphs!
    Use bfs_transitive_closure() instead for better performance.
    
    Kept for educational purposes (DAA Unit IV requirement).
    """
    # Get all nodes
    nodes = list(graph.keys())
    n = len(nodes)
    node_to_idx = {node: i for i, node in enumerate(nodes)}
    
    # Initialize reachability matrix
    reach = [[False] * n for _ in range(n)]
    
    # Set direct edges
    for i, node in enumerate(nodes):
        reach[i][i] = True  # Self-reachable
        for neighbor in graph.get(node, []):
            if neighbor in node_to_idx:
                j = node_to_idx[neighbor]
                reach[i][j] = True
    
    # Floyd-Warshall: find transitive closure
    for k in range(n):
        for i in range(n):
            for j in range(n):
                reach[i][j] = reach[i][j] or (reach[i][k] and reach[k][j])
    
    # Convert back to dictionary format
    closure = {}
    for i, node in enumerate(nodes):
        reachable = set()
        for j in range(n):
            if reach[i][j] and i != j:
                reachable.add(nodes[j])
        closure[node] = reachable
    
    return closure


def dijkstra_shortest_path(graph: Dict[str, List[str]], start: str) -> Dict[str, int]:
    """
    Dijkstra's algorithm to find shortest redirect path lengths.
    Returns dictionary mapping each reachable URL to its distance from start.
    """
    # Initialize distances
    distances = {start: 0}
    visited = set()
    
    # Priority queue: (distance, node)
    pq = [(0, start)]
    
    while pq:
        current_dist, current = heapq.heappop(pq)
        
        if current in visited:
            continue
        
        visited.add(current)
        
        # Check neighbors
        for neighbor in graph.get(current, []):
            distance = current_dist + 1  # Each redirect has weight 1
            
            if neighbor not in distances or distance < distances[neighbor]:
                distances[neighbor] = distance
                heapq.heappush(pq, (distance, neighbor))
    
    return distances


class GreedyOptimizer:
    """Main class for Phase 4 greedy optimization."""
    
    def __init__(self):
        self.transitive_closure = {}
        self.malicious_urls = set()
    
    def build_transitive_closure(self, graph: Dict[str, List[str]]):
        """
        Build transitive closure of redirect graph.
        Uses BFS-based algorithm (O(V·E)) instead of Warshall (O(V³)) for speed.
        """
        self.transitive_closure = bfs_transitive_closure(graph)
    
    def register_malicious_url(self, url: str):
        """Register a URL as malicious."""
        self.malicious_urls.add(url)
    
    def propagate_threats(self, url: str) -> bool:
        """
        Check if URL transitively reaches any known malicious URL.
        Returns True if threat should be propagated.
        """
        if url in self.malicious_urls:
            return True
        
        # Check transitive closure
        reachable = self.transitive_closure.get(url, set())
        return bool(reachable & self.malicious_urls)
    
    def schedule_urls(self, urls: List[Dict], budget_ms: float = 100) -> List[Dict]:
        """
        Schedule URLs for processing using fractional knapsack.
        Returns prioritized list of URLs to process.
        """
        return fractional_knapsack(urls, budget_ms)
    
    def calculate_redirect_path(self, url: str, graph: Dict[str, List[str]]) -> Dict:
        """
        Calculate shortest redirect path from URL using Dijkstra.
        """
        distances = dijkstra_shortest_path(graph, url)
        
        # Find path to any malicious URL
        malicious_distances = {
            target: dist for target, dist in distances.items()
            if target in self.malicious_urls
        }
        
        if malicious_distances:
            closest_malicious = min(malicious_distances.items(), key=lambda x: x[1])
            return {
                'has_malicious_path': True,
                'closest_malicious_url': closest_malicious[0],
                'path_length': closest_malicious[1]
            }
        
        return {
            'has_malicious_path': False,
            'closest_malicious_url': None,
            'path_length': None
        }
    
    def analyze_url(self, url: str, url_data: Dict, graph: Dict[str, List[str]]) -> Dict:
        """
        Full greedy optimization analysis for a URL.
        """
        # Check threat propagation
        inherits_threat = self.propagate_threats(url)
        
        # Calculate redirect path
        path_info = self.calculate_redirect_path(url, graph)
        
        return {
            'url': url,
            'inherits_threat': inherits_threat,
            'transitive_malicious': inherits_threat,
            'redirect_path_info': path_info
        }
