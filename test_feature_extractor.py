import sys
from pathlib import Path
ROOT = Path("/Users/raghottamgirishnadgoudar/RVCE/4th_sem/DAA/Malicious_url_detection")
sys.path.insert(0, str(ROOT / "api"))
from app.services.feature_extractor import parse_domain

REGRESSION_CASES = [
    ("https://rvce.edu.in",        "", "rvce",  "edu.in"),
    ("https://mail.rvce.edu.in",   "mail", "rvce", "edu.in"),
    ("http://iitb.ac.in",         "", "iitb",  "ac.in"),
    ("https://ox.ac.uk",           "", "ox",    "ac.uk"),
    ("http://bbc.co.uk",          "", "bbc",   "co.uk"),
    ("https://nic.gov.in",         "", "nic",   "gov.in"),
    ("https://example.com.au",     "", "example", "com.au"),
]
for url, sub, dom, suf in REGRESSION_CASES:
    result = parse_domain(url)
    assert result["subdomain"] == sub, f"{url}: subdomain wrong. Got {result['subdomain']} Expected {sub}"
    assert result["registrable_domain"] == dom, f"{url}: domain wrong. Got {result['registrable_domain']} Expected {dom}"
    assert result["suffix"] == suf, f"{url}: suffix wrong. Got {result['suffix']} Expected {suf}"

print("All regression tests passed for tldextract!")
