"""
URL Expander Module - Handles URL Shorteners
Expands shortened URLs to their final destination before analysis
"""

import requests
from typing import Dict, Optional, List
from urllib.parse import urlparse
import time


# Known URL shortener domains
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'lnkd.in',
    'db.tt', 'qr.ae', 'adf.ly', 'cur.lv', 'ity.im',
    'q.gs', 'po.st', 'bc.vc', 'u.to', 'j.mp',
    'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org',
    'prettylinkpro.com', 'scrnch.me', 'filoops.info',
    'vurl.com', 'vzturl.com', '2.gp', 'tweez.me',
    'v.gd', 'tr.im', 'link.zip', 'short.link'
}


def is_shortened_url(url: str) -> bool:
    """
    Check if a URL is from a known URL shortener service.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove 'www.' prefix
        domain = domain.replace('www.', '')
        
        return domain in URL_SHORTENERS
    except:
        return False


def expand_url(url: str, max_redirects: int = 10, timeout: int = 10) -> Dict:
    """
    Expand a shortened URL to its final destination.
    
    Args:
        url: The shortened URL to expand
        max_redirects: Maximum number of redirects to follow
        timeout: Request timeout in seconds
    
    Returns:
        Dict with expansion results including final URL and redirect chain
    """
    result = {
        'original_url': url,
        'final_url': url,
        'redirect_chain': [url],
        'redirect_count': 0,
        'is_shortened': is_shortened_url(url),
        'expansion_successful': False,
        'error': None,
        'status_codes': []
    }
    
    try:
        current_url = url
        
        for i in range(max_redirects):
            response = None
            last_err = None
            
            # If HTTPS request fails or times out, try HTTP fallback as plain HTTP
            # frequently bypasses proxy/SSL decryption filters or SSL handshaking limits.
            urls_to_try = [current_url]
            if current_url.startswith('https://'):
                urls_to_try.append(current_url.replace('https://', 'http://', 1))
                
            for test_url in urls_to_try:
                # Retry loop (up to 2 attempts per URL)
                for attempt in range(2):
                    try:
                        # Use requests.get directly with 'Connection': 'close' to disable connection keep-alive pooling,
                        # which avoids server connection-based rate limiting/throttling. Use stream=True to avoid body download.
                        response = requests.get(
                            test_url,
                            allow_redirects=False,
                            timeout=timeout,
                            stream=True,
                            headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                                'Connection': 'close'
                            }
                        )
                        if response.status_code < 500:
                            break
                    except requests.RequestException as e:
                        last_err = e
                        if attempt == 0:
                            time.sleep(0.5) # small delay before retry
                            
                # If we got a successful response (redirect or ok), we break the fallback loop
                if response is not None and response.status_code < 500:
                    current_url = test_url
                    break
            
            if response is None:
                result['error'] = f"Request failed at redirect {i}: {str(last_err)}"
                break
                
            result['status_codes'].append(response.status_code)
            
            # Check for redirect
            if response.status_code in [301, 302, 303, 307, 308]:
                next_url = response.headers.get('Location')
                
                if not next_url:
                    break
                
                # Handle relative URLs
                if not next_url.startswith('http'):
                    from urllib.parse import urljoin
                    next_url = urljoin(current_url, next_url)
                
                result['redirect_chain'].append(next_url)
                result['redirect_count'] += 1
                current_url = next_url
                
                # Small delay to be respectful
                time.sleep(0.1)
            else:
                # No more redirects
                break
        
        # Set final URL
        result['final_url'] = current_url
        result['expansion_successful'] = True
        
    except Exception as e:
        result['error'] = f"Expansion failed: {str(e)}"
    
    return result


def expand_url_safe(url: str) -> str:
    """
    Safely expand a URL, returning the original if expansion fails.
    This is a convenience wrapper for use in the main pipeline.
    """
    try:
        expansion_result = expand_url(url)
        if expansion_result['expansion_successful']:
            return expansion_result['final_url']
    except:
        pass
    
    return url


def batch_expand_urls(urls: List[str], max_workers: int = 5) -> Dict[str, Dict]:
    """
    Expand multiple URLs in parallel for efficiency.
    
    Args:
        urls: List of URLs to expand
        max_workers: Number of parallel workers
    
    Returns:
        Dict mapping original URL to expansion result
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_url = {
            executor.submit(expand_url, url): url 
            for url in urls
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                results[url] = future.result()
            except Exception as e:
                results[url] = {
                    'original_url': url,
                    'final_url': url,
                    'expansion_successful': False,
                    'error': str(e)
                }
    
    return results


class URLExpander:
    """Main class for URL expansion functionality."""
    
    def __init__(self, max_redirects: int = 10, timeout: int = 5):
        self.max_redirects = max_redirects
        self.timeout = timeout
        self.expansion_cache = {}  # Cache to avoid re-expanding same URLs
    
    def expand(self, url: str, use_cache: bool = True) -> Dict:
        """
        Expand a URL with optional caching.
        """
        # Check cache first
        if use_cache and url in self.expansion_cache:
            return self.expansion_cache[url]
        
        # Expand the URL
        result = expand_url(url, self.max_redirects, self.timeout)
        
        # Cache the result
        if use_cache:
            self.expansion_cache[url] = result
        
        return result
    
    def get_final_url(self, url: str) -> str:
        """
        Get the final destination URL, with fallback to original.
        """
        result = self.expand(url)
        return result['final_url']
    
    def clear_cache(self):
        """Clear the expansion cache."""
        self.expansion_cache.clear()
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics."""
        return {
            'cached_urls': len(self.expansion_cache),
            'cache_size_bytes': sum(
                len(str(v)) for v in self.expansion_cache.values()
            )
        }
