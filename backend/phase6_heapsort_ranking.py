"""
Phase 6: Heapsort Threat Prioritization
Transform & Conquer · Max-heap ranking · Huffman entropy baseline
"""

from typing import List, Dict
import heapq
from collections import Counter
import math


def heapify(arr: List, n: int, i: int, key_func=None):
    """
    Heapify subtree rooted at index i.
    n is size of heap.
    """
    if key_func is None:
        key_func = lambda x: x
    
    largest = i
    left = 2 * i + 1
    right = 2 * i + 2
    
    # Check if left child exists and is greater
    if left < n and key_func(arr[left]) > key_func(arr[largest]):
        largest = left
    
    # Check if right child exists and is greater
    if right < n and key_func(arr[right]) > key_func(arr[largest]):
        largest = right
    
    # If largest is not root
    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]
        heapify(arr, n, largest, key_func)


def heapsort(arr: List, key_func=None, reverse=False):
    """
    Heapsort algorithm - O(n log n) time, O(1) extra space.
    
    Args:
        arr: List to sort
        key_func: Function to extract comparison key
        reverse: If True, sort descending (max-heap)
    """
    if key_func is None:
        key_func = lambda x: x
    
    n = len(arr)
    
    # Build max heap
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i, key_func)
    
    # Extract elements one by one
    for i in range(n - 1, 0, -1):
        arr[0], arr[i] = arr[i], arr[0]
        heapify(arr, i, 0, key_func)
    
    # Reverse if we want descending order
    if reverse:
        arr.reverse()


class HuffmanNode:
    """Node for Huffman tree."""
    
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None
    
    def __lt__(self, other):
        return self.freq < other.freq


def build_huffman_tree(text: str) -> HuffmanNode:
    """
    Build Huffman tree from character frequencies.
    """
    if not text:
        return None
    
    # Count character frequencies
    freq_map = Counter(text)
    
    # Create leaf nodes
    heap = [HuffmanNode(char, freq) for char, freq in freq_map.items()]
    heapq.heapify(heap)
    
    # Build tree
    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        
        merged = HuffmanNode(None, left.freq + right.freq)
        merged.left = left
        merged.right = right
        
        heapq.heappush(heap, merged)
    
    return heap[0] if heap else None


def get_huffman_codes(root: HuffmanNode, code: str = "", codes: Dict = None) -> Dict:
    """
    Generate Huffman codes from tree.
    Returns dictionary mapping characters to binary codes.
    """
    if codes is None:
        codes = {}
    
    if root is None:
        return codes
    
    # Leaf node
    if root.char is not None:
        codes[root.char] = code if code else "0"
        return codes
    
    # Traverse tree
    get_huffman_codes(root.left, code + "0", codes)
    get_huffman_codes(root.right, code + "1", codes)
    
    return codes


def calculate_huffman_baseline(benign_urls: List[str]) -> float:
    """
    Calculate expected code length (entropy baseline) using Huffman coding.
    This is used for anomaly detection.
    """
    # Combine all benign URLs
    combined_text = ''.join(benign_urls)
    
    if not combined_text:
        return 0.0
    
    # Build Huffman tree
    root = build_huffman_tree(combined_text)
    
    # Get codes
    codes = get_huffman_codes(root)
    
    # Calculate expected code length
    freq_map = Counter(combined_text)
    total_chars = len(combined_text)
    
    expected_length = sum(
        (freq / total_chars) * len(codes[char])
        for char, freq in freq_map.items()
    )
    
    return expected_length


class ThreatRanker:
    """
    Threat ranking system using composite score and heapsort.
    """
    
    def __init__(self, weights: Dict = None):
        """
        Initialize with feature weights.
        Default weights learned from training data.
        """
        if weights is None:
            self.weights = {
                'phishing_prob': 0.35,
                'entropy': 0.25,
                'redirect_depth': 0.20,
                'pattern_score': 0.20
            }
        else:
            self.weights = weights
        
        self.huffman_baseline = None
    
    def set_huffman_baseline(self, benign_urls: List[str]):
        """Calculate and set Huffman entropy baseline from benign URLs."""
        self.huffman_baseline = calculate_huffman_baseline(benign_urls)
    
    def calculate_threat_rank(self, url_data: Dict) -> float:
        """
        Composite threat rank driven by neural probability.
        threat_rank = 0.45×neural_prob + 0.25×entropy + 0.20×redirect + 0.10×keyword
        """
        neural_prob    = url_data.get('threat_probability', 0.5)
        entropy        = url_data.get('entropy', 3.0) / 5.0          # normalise to [0,1]
        redirect_depth = min(url_data.get('redirect_depth', 0) / 10.0, 1.0)
        # keyword_score is now a feature inside Phase 3; fall back to 0 gracefully
        keyword_score  = url_data.get('keyword_score', 0.0)

        return (0.45 * neural_prob +
                0.25 * entropy +
                0.20 * redirect_depth +
                0.10 * keyword_score)
    
    def check_entropy_anomaly(self, url: str) -> Dict:
        """
        Check if URL entropy deviates from Huffman baseline.
        Novel use of Huffman coding for anomaly detection.
        """
        if self.huffman_baseline is None:
            return {'is_anomaly': False, 'deviation': 0.0}
        
        # Calculate actual entropy
        from phase1_graph_traversal import entropy
        url_entropy = entropy(url)
        
        # Compare to baseline
        deviation = abs(url_entropy - self.huffman_baseline)
        
        # Flag as anomaly if deviation > 1.5
        is_anomaly = deviation > 1.5
        
        return {
            'is_anomaly': is_anomaly,
            'deviation': deviation,
            'url_entropy': url_entropy,
            'baseline_entropy': self.huffman_baseline
        }
    
    def rank_urls(self, urls_data: List[Dict], top_k: int = None) -> List[Dict]:
        """
        Rank URLs by threat score using heapsort.
        Returns sorted list with highest threats first.
        
        Args:
            urls_data: List of URL analysis dictionaries
            top_k: If specified, return only top K threats
        """
        # Calculate threat rank for each URL
        for url_data in urls_data:
            url_data['threat_rank'] = self.calculate_threat_rank(url_data)
        
        # Sort using heapsort (descending order)
        heapsort(urls_data, key_func=lambda x: x['threat_rank'], reverse=True)
        
        # Return top K if specified
        if top_k is not None:
            return urls_data[:top_k]
        
        return urls_data
    
    def extract_top_k_heap(self, urls_data: List[Dict], k: int) -> List[Dict]:
        """
        Extract top K threats using max-heap.
        More efficient than full sort when k << n.
        """
        # Use negative threat_rank for max-heap behavior
        heap = []
        
        for url_data in urls_data:
            threat_rank = self.calculate_threat_rank(url_data)
            url_data['threat_rank'] = threat_rank
            
            # Python heapq is min-heap, so negate for max-heap
            heapq.heappush(heap, (-threat_rank, url_data))
        
        # Extract top K
        top_k = []
        for _ in range(min(k, len(heap))):
            _, url_data = heapq.heappop(heap)
            top_k.append(url_data)
        
        return top_k


class HeapsortRanker:
    """Main class for Phase 6 heapsort ranking."""
    
    def __init__(self):
        self.ranker = ThreatRanker()
    
    def set_baseline(self, benign_urls: List[str]):
        """Set Huffman entropy baseline from benign URLs."""
        self.ranker.set_huffman_baseline(benign_urls)
    
    def analyze_url(self, url: str, url_data: Dict) -> Dict:
        """
        Analyze single URL for ranking.
        """
        # Calculate threat rank
        threat_rank = self.ranker.calculate_threat_rank(url_data)
        
        # Check entropy anomaly
        anomaly_info = self.ranker.check_entropy_anomaly(url)
        
        return {
            'url': url,
            'threat_rank': threat_rank,
            'entropy_anomaly': anomaly_info
        }
    
    def rank_batch(self, urls_data: List[Dict], top_k: int = None) -> List[Dict]:
        """Rank a batch of URLs."""
        return self.ranker.rank_urls(urls_data, top_k)
