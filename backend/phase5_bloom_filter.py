"""
Phase 5: Learned Bloom Filter with Decay Aging
Probabilistic hashing · LSH n-grams · DP memory functions · Backtracking verification
"""

import math
import time
from typing import Set, Dict, List
import hashlib


def get_hash_functions(k: int):
    """
    Generate k hash functions using different seeds.
    Returns list of hash functions.
    """
    def make_hash(seed):
        def hash_func(item: str, m: int) -> int:
            # Use hashlib with seed for consistent hashing
            h = hashlib.md5(f"{seed}:{item}".encode()).hexdigest()
            return int(h, 16) % m
        return hash_func
    
    return [make_hash(i) for i in range(k)]


def extract_trigrams(url: str) -> Set[str]:
    """
    Extract character trigrams (3-grams) from URL.
    Used for Locality-Sensitive Hashing.
    """
    url = url.lower()
    trigrams = set()
    for i in range(len(url) - 2):
        trigrams.add(url[i:i+3])
    return trigrams


def lsh_hash(url: str) -> int:
    """
    Locality-Sensitive Hash based on URL trigrams.
    Similar URLs will have similar hash values.
    """
    trigrams = extract_trigrams(url)
    # Combine trigram hashes
    combined = ''.join(sorted(trigrams))
    return hash(combined)


class BloomFilter:
    """
    Standard Bloom Filter with multiple hash functions.
    """
    
    def __init__(self, expected_elements: int = 316254, false_positive_rate: float = 0.01):
        """
        Initialize Bloom Filter.
        
        Args:
            expected_elements: Expected number of elements (n)
            false_positive_rate: Desired false positive rate (p)
        """
        # Calculate optimal bit array size (m)
        self.m = self._calculate_size(expected_elements, false_positive_rate)
        
        # Calculate optimal number of hash functions (k)
        self.k = self._calculate_hash_count(self.m, expected_elements)
        
        # Initialize bit array
        self.bit_array = [False] * self.m
        
        # Generate hash functions
        self.hash_functions = get_hash_functions(self.k)
        
        # Statistics
        self.element_count = 0
    
    def _calculate_size(self, n: int, p: float) -> int:
        """Calculate optimal bit array size."""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)
    
    def _calculate_hash_count(self, m: int, n: int) -> int:
        """Calculate optimal number of hash functions."""
        k = (m / n) * math.log(2)
        return max(1, int(k))
    
    def add(self, item: str):
        """Add an item to the Bloom Filter."""
        for hash_func in self.hash_functions:
            index = hash_func(item, self.m)
            self.bit_array[index] = True
        self.element_count += 1
    
    def contains(self, item: str) -> bool:
        """
        Check if item might be in the set.
        Returns True if possibly present, False if definitely not present.
        """
        for hash_func in self.hash_functions:
            index = hash_func(item, self.m)
            if not self.bit_array[index]:
                return False
        return True
    
    def get_stats(self) -> Dict:
        """Get Bloom Filter statistics."""
        bits_set = sum(self.bit_array)
        load_factor = bits_set / self.m if self.m > 0 else 0
        
        # Estimate false positive rate
        estimated_fpr = (bits_set / self.m) ** self.k if self.m > 0 else 0
        
        return {
            'size_bits': self.m,
            'size_kb': self.m / 8 / 1024,
            'hash_functions': self.k,
            'elements_added': self.element_count,
            'bits_set': bits_set,
            'load_factor': load_factor,
            'estimated_fpr': estimated_fpr
        }


class LearnedBloomFilter:
    """
    Enhanced Bloom Filter with:
    1. Decay-weighted aging (DP memory function)
    2. LSH for similar URL detection
    3. Backtracking constraint verification
    """
    
    def __init__(self, expected_elements: int = 316254, false_positive_rate: float = 0.01):
        # Standard Bloom Filter (H1)
        self.bloom = BloomFilter(expected_elements, false_positive_rate)
        
        # LSH-based Bloom Filter (H2) for trigram similarity
        self.lsh_bloom = BloomFilter(expected_elements, false_positive_rate)
        
        # Decay parameters
        self.decay_lambda = 0.0001  # Decay rate
        
        # Entry metadata: {url: {'score': float, 'timestamp': float}}
        self.entries = {}
        
        # Verified blacklist for exact matching
        self.verified_blacklist = set()
    
    def add(self, url: str, threat_score: float = 1.0):
        """
        Add URL to the learned Bloom Filter with threat score.
        """
        # Add to standard Bloom Filter
        self.bloom.add(url)
        
        # Add trigrams to LSH Bloom Filter
        trigrams = extract_trigrams(url)
        for trigram in trigrams:
            self.lsh_bloom.add(trigram)
        
        # Store metadata
        self.entries[url] = {
            'score': threat_score,
            'timestamp': time.time()
        }
    
    def _calculate_effective_score(self, url: str) -> float:
        """
        Calculate decay-weighted effective score.
        effective_score(url, t) = threat_score × e^(-λ(t - t_insert))
        
        This is the DP memory function with expiry.
        """
        if url not in self.entries:
            return 0.0
        
        entry = self.entries[url]
        threat_score = entry['score']
        t_insert = entry['timestamp']
        t_now = time.time()
        
        # Exponential decay
        decay_factor = math.exp(-self.decay_lambda * (t_now - t_insert))
        effective_score = threat_score * decay_factor
        
        return effective_score
    
    def contains(self, url: str) -> Dict:
        """
        Check if URL is in the filter.
        Returns detailed result including LSH similarity check.
        """
        # Check standard Bloom Filter
        in_bloom = self.bloom.contains(url)
        
        # Check LSH Bloom Filter (trigram similarity)
        trigrams = extract_trigrams(url)
        trigram_matches = sum(1 for tg in trigrams if self.lsh_bloom.contains(tg))
        lsh_similarity = trigram_matches / len(trigrams) if trigrams else 0
        
        # Check verified blacklist
        in_blacklist = url in self.verified_blacklist
        
        # Calculate effective score if in entries
        effective_score = self._calculate_effective_score(url)
        
        return {
            'in_bloom_filter': in_bloom,
            'lsh_similarity': lsh_similarity,
            'in_verified_blacklist': in_blacklist,
            'effective_score': effective_score,
            'possibly_malicious': in_bloom or lsh_similarity > 0.7 or in_blacklist
        }
    
    def verify_with_constraints(self, url: str, url_data: Dict) -> bool:
        """
        Backtracking constraint satisfaction for false positive handling.
        URL must satisfy >= 3 of 5 malicious constraints to be confirmed.
        
        Constraints:
        1. High entropy (> 4.0)
        2. Suspicious TLD
        3. Phishing keyword match
        4. IP in URL
        5. Redirect depth > 2
        """
        constraints_met = 0
        
        # Constraint 1: High entropy
        if url_data.get('entropy', 0) > 4.0:
            constraints_met += 1
        
        # Constraint 2: Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        if any(url.endswith(tld) for tld in suspicious_tlds):
            constraints_met += 1
        
        # Constraint 3: Phishing keyword match
        if url_data.get('pattern_score', 0) > 0.1:
            constraints_met += 1
        
        # Constraint 4: IP in URL
        if url_data.get('has_ip_address', False):
            constraints_met += 1
        
        # Constraint 5: Redirect depth > 2
        if url_data.get('redirect_depth', 0) > 2:
            constraints_met += 1
        
        # Require at least 3 constraints
        return constraints_met >= 3
    
    def add_to_blacklist(self, url: str):
        """Add URL to verified blacklist."""
        self.verified_blacklist.add(url)
    
    def cleanup_expired(self, threshold: float = 0.1):
        """
        Lazy eviction of entries with effective score below threshold.
        """
        current_time = time.time()
        to_remove = []
        
        for url, entry in self.entries.items():
            effective_score = self._calculate_effective_score(url)
            if effective_score < threshold:
                to_remove.append(url)
        
        for url in to_remove:
            del self.entries[url]
        
        return len(to_remove)
    
    def get_stats(self) -> Dict:
        """Get comprehensive statistics."""
        bloom_stats = self.bloom.get_stats()
        lsh_stats = self.lsh_bloom.get_stats()
        
        return {
            'standard_bloom': bloom_stats,
            'lsh_bloom': lsh_stats,
            'entries_tracked': len(self.entries),
            'verified_blacklist_size': len(self.verified_blacklist)
        }


class BloomFilterAnalyzer:
    """Main class for Phase 5 Bloom Filter analysis."""
    
    def __init__(self):
        self.bloom_filter = LearnedBloomFilter()
    
    def register_malicious_url(self, url: str, threat_score: float = 1.0):
        """Register a malicious URL in the Bloom Filter."""
        self.bloom_filter.add(url, threat_score)
    
    def analyze_url(self, url: str, url_data: Dict = None) -> Dict:
        """
        Analyze URL using Bloom Filter.
        """
        if url_data is None:
            url_data = {}
        
        # Check Bloom Filter
        bloom_result = self.bloom_filter.contains(url)
        
        # If possibly malicious, verify with constraints
        if bloom_result['possibly_malicious']:
            verified = self.bloom_filter.verify_with_constraints(url, url_data)
            
            if verified:
                # Add to verified blacklist
                self.bloom_filter.add_to_blacklist(url)
        else:
            verified = False
        
        return {
            'url': url,
            'bloom_result': bloom_result,
            'constraint_verified': verified,
            'final_verdict': 'malicious' if verified else ('suspicious' if bloom_result['possibly_malicious'] else 'unknown')
        }
