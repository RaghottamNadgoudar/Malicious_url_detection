"""
Phase 2: Pattern Matching — Boyer-Moore + Input Enhancement
Keyword detection · Adversarial normalization · Horspool fallback
"""

import re
from typing import List, Dict, Tuple
from urllib.parse import unquote


# Phishing keyword dictionary
PHISHING_KEYWORDS = [
    'login', 'verify', 'secure', 'update', 'bank', 'paypal',
    'apple', 'amazon', 'confirm', 'account', 'signin', 'ebay',
    'password', 'suspended', 'locked', 'urgent', 'click', 'verify'
]


def build_bad_char_table(pattern: str) -> Dict[str, int]:
    """Build bad character table for Boyer-Moore algorithm."""
    table = {}
    for i, ch in enumerate(pattern[:-1]):  # Exclude last character
        table[ch] = len(pattern) - 1 - i
    return table


def boyer_moore_search(text: str, pattern: str) -> int:
    """
    Boyer-Moore string search algorithm.
    Returns the index of first occurrence, or -1 if not found.
    """
    if not pattern or not text:
        return -1
    
    m, n = len(pattern), len(text)
    if m > n:
        return -1
    
    # Build bad character table
    bad_char = build_bad_char_table(pattern)
    
    s = 0  # Shift of the pattern
    while s <= n - m:
        j = m - 1
        
        # Keep reducing j while characters match
        while j >= 0 and pattern[j] == text[s + j]:
            j -= 1
        
        # Pattern found
        if j < 0:
            return s
        
        # Shift pattern based on bad character rule
        shift = bad_char.get(text[s + j], m)
        s += max(1, shift)
    
    return -1


def horspool_search(text: str, pattern: str) -> int:
    """
    Horspool algorithm (simplified Boyer-Moore).
    Faster alternative for pattern matching.
    """
    if not pattern or not text:
        return -1
    
    m, n = len(pattern), len(text)
    if m > n:
        return -1
    
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
        
        i += shift.get(text[i + m - 1], m)
    
    return -1


def percent_decode(url: str) -> str:
    """Decode percent-encoded characters (e.g., %6C%6F%67%69%6E → login)."""
    try:
        return unquote(url)
    except:
        return url


def leetspeak_expand(text: str) -> str:
    """Expand leetspeak characters to normal letters."""
    leet_map = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '@': 'a', '$': 's'
    }
    result = []
    for ch in text.lower():
        result.append(leet_map.get(ch, ch))
    return ''.join(result)


def strip_subdomain(url: str) -> str:
    """Extract root domain from URL."""
    # Remove protocol
    url = re.sub(r'^https?://', '', url)
    # Remove path
    url = url.split('/')[0]
    # Get last two parts (domain.tld)
    parts = url.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return url


def collapse_hyphens(text: str) -> str:
    """Remove hyphens to detect dash-based evasion."""
    return text.replace('-', '').replace('_', '')


def normalize_url(url: str) -> str:
    """
    Apply all input enhancement transformations.
    This is adversarial normalization to expose obfuscated patterns.
    """
    # Step 1: Percent decode
    url = percent_decode(url)
    
    # Step 2: Convert to lowercase
    url = url.lower()
    
    # Step 3: Leetspeak expansion
    url = leetspeak_expand(url)
    
    # Step 4: Collapse hyphens
    url = collapse_hyphens(url)
    
    return url


def count_pattern_matches(url: str, keywords: List[str] = None) -> Tuple[int, List[str]]:
    """
    Count how many phishing keywords are found in the URL.
    Uses Boyer-Moore for each keyword search.
    Returns (count, matched_keywords).
    """
    if keywords is None:
        keywords = PHISHING_KEYWORDS
    
    # Normalize URL first
    normalized = normalize_url(url)
    
    matched = []
    for keyword in keywords:
        # Try Boyer-Moore first
        if boyer_moore_search(normalized, keyword) != -1:
            matched.append(keyword)
        # Fallback to Horspool if needed
        elif horspool_search(normalized, keyword) != -1:
            if keyword not in matched:
                matched.append(keyword)
    
    return len(matched), matched


class PatternMatcher:
    """Main class for Phase 2 pattern matching."""
    
    def __init__(self, keywords: List[str] = None):
        self.keywords = keywords or PHISHING_KEYWORDS
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyze URL for phishing patterns.
        Returns pattern matching results.
        """
        # Original URL analysis
        match_count, matched_keywords = count_pattern_matches(url, self.keywords)
        
        # Calculate pattern score (normalized by total keywords)
        pattern_score = match_count / len(self.keywords)
        
        # Get normalized version
        normalized_url = normalize_url(url)
        
        # Additional features
        has_ip = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
        digit_ratio = sum(c.isdigit() for c in url) / len(url) if url else 0
        dot_count = url.count('.')
        hyphen_count = url.count('-')
        special_char_count = sum(1 for c in url if c in '@%=&?')
        special_char_ratio = special_char_count / len(url) if url else 0
        
        return {
            'url': url,
            'normalized_url': normalized_url,
            'pattern_score': pattern_score,
            'matched_keywords': matched_keywords,
            'match_count': match_count,
            'has_ip_address': has_ip,
            'digit_ratio': digit_ratio,
            'dot_count': dot_count,
            'hyphen_count': hyphen_count,
            'special_char_ratio': special_char_ratio
        }
