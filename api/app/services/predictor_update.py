import re
with open("/Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/api/app/services/predictor.py", "r") as f:
    content = f.read()

# Replace _is_whitelisted function
old_is_whitelisted = """def _is_whitelisted(url: str) -> bool:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower().lstrip("www.").split(":")[0]
        if host in WHITELISTED_DOMAINS:
            return True
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in WHITELISTED_DOMAINS:
                return True
    except Exception:
        pass
    return False"""

new_is_whitelisted = """import tldextract

# Optional: load a massive whitelist from disk if available
try:
    with open(str(ROOT / "data" / "majestic_top_10k.txt"), "r") as f:
        for line in f:
            WHITELISTED_DOMAINS.add(line.strip().lower())
except FileNotFoundError:
    pass
    
# Optional: load a massive blacklist from disk
BLACKLISTED_DOMAINS = set()
try:
    with open(str(ROOT / "data" / "openphish_domains.txt"), "r") as f:
        for line in f:
            BLACKLISTED_DOMAINS.add(line.strip().lower())
except FileNotFoundError:
    pass

def _is_whitelisted(url: str) -> bool:
    try:
        ext = tldextract.extract(url)
        # Check full registrable domain (e.g. google.com, rvce.edu.in)
        reg_domain = f"{ext.domain}.{ext.suffix}".lower()
        if reg_domain in WHITELISTED_DOMAINS:
            return True
        # Check full hostname (e.g. mail.google.com)
        full_host = f"{ext.subdomain}.{reg_domain}".strip(".").lower()
        if full_host in WHITELISTED_DOMAINS:
            return True
    except Exception:
        pass
    return False

def _is_blacklisted(url: str) -> bool:
    try:
        ext = tldextract.extract(url)
        reg_domain = f"{ext.domain}.{ext.suffix}".lower()
        if reg_domain in BLACKLISTED_DOMAINS:
            return True
    except Exception:
        pass
    return False"""

content = content.replace(old_is_whitelisted, new_is_whitelisted)

# Update predict method to use _is_blacklisted
old_fast_path = """        # Fast-path: whitelisted
        if _is_whitelisted(url):
            return {
                "label": ThreatLevel.SAFE,
                "confidence": 0.99,
                "threat_probability": 0.01,
                "expert_probabilities": {
                    "expert1_cnn": 0.01,
                    "expert2_distilbert": 0.01,
                    "expert3_lgb": 0.01,
                }
            }"""

new_fast_path = """        # Tier 1: Fast-path Whitelist
        if _is_whitelisted(url):
            return {
                "label": ThreatLevel.SAFE,
                "confidence": 0.99,
                "threat_probability": 0.01,
                "expert_probabilities": {
                    "expert1_cnn": 0.01,
                    "expert2_distilbert": 0.01,
                    "expert3_lgb": 0.01,
                }
            }
            
        # Tier 2: Fast-path Blacklist (Threat Intel)
        if _is_blacklisted(url):
            return {
                "label": ThreatLevel.MALICIOUS,
                "confidence": 0.99,
                "threat_probability": 0.99,
                "expert_probabilities": {
                    "expert1_cnn": 0.99,
                    "expert2_distilbert": 0.99,
                    "expert3_lgb": 0.99,
                }
            }"""

content = content.replace(old_fast_path, new_fast_path)

# Update THRESHOLD constants
old_threshold = """    THRESHOLD_SAFE       = 0.25
    THRESHOLD_MALICIOUS  = 0.60"""
new_threshold = """    # Recalibrated Thresholds based on OOD testing on real data
    THRESHOLD_SAFE       = 0.57
    THRESHOLD_MALICIOUS  = 0.60"""

content = content.replace(old_threshold, new_threshold)

with open("/Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection/api/app/services/predictor.py", "w") as f:
    f.write(content)
print("Updated predictor.py")
