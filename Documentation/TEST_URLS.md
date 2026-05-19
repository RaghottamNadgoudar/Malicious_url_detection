# Test URLs for URL Detection System

## 🔗 URL SHORTENER TEST CASES

### Safe Shortened URLs (will be expanded)
```
https://bit.ly/3abc123
https://tinyurl.com/news-article
https://t.co/example
https://goo.gl/maps
https://ow.ly/test
```

### Suspicious Shortened URLs (for testing)
```
https://bit.ly/paypal-verify
https://tinyurl.com/bank-login
https://is.gd/secure-update
https://bit.ly/apple-id-verify
https://t.co/phishing123
https://ow.ly/verify-account
```

### Real Shortened URLs (not in training data)
These are real shortened URLs you can test with:
```
https://bit.ly/3wX4kLm
https://tinyurl.com/2p8h3j4k
https://t.co/AbCdEfGhIj
https://is.gd/testurl
https://v.gd/example
https://goo.gl/maps/test
```

**Note:** These URLs may expire or redirect to different destinations over time.

**System Behavior:**
- ✓ Detects 35+ URL shortener services
- ✓ Expands to final destination automatically
- ✓ Applies +0.1 threat probability adjustment
- ✓ Shows full redirect chain in UI
- ✓ Extra scrutiny for multiple redirects

---

## ✅ SAFE URLs (Should show LOW threat probability)

### Popular Legitimate Sites
```
https://www.wikipedia.org
https://www.reddit.com
https://www.stackoverflow.com
https://www.linkedin.com
https://www.twitter.com
https://www.instagram.com
https://www.youtube.com
https://www.netflix.com
https://www.spotify.com
https://www.apple.com
```

### Educational & Government
```
https://www.mit.edu
https://www.stanford.edu
https://www.nasa.gov
https://www.nih.gov
https://www.whitehouse.gov
```

### Tech Companies
```
https://www.salesforce.com
https://www.oracle.com
https://www.ibm.com
https://www.adobe.com
https://www.zoom.us
```

### E-commerce
```
https://www.ebay.com
https://www.walmart.com
https://www.target.com
https://www.bestbuy.com
https://www.etsy.com
```

---

## ⚠️ SUSPICIOUS URLs (Should show MEDIUM threat probability)

### Shortened URLs
```
http://bit.ly/3xYz9Qw
http://tinyurl.com/abc123
http://goo.gl/maps/xyz
```

### Unusual TLDs
```
http://my-site.xyz
http://download-now.top
http://free-stuff.click
http://win-prize.online
http://get-app.site
```

### Suspicious Patterns
```
http://secure-login-verify.com
http://account-update-required.net
http://confirm-identity-now.org
```

### Long URLs with Parameters
```
http://example.com/redirect?url=http://another-site.com&token=abc123
http://tracking.com/click?id=12345&redirect=http://destination.com
```

---

## 🚨 MALICIOUS URLs (Should show HIGH threat probability)

### Phishing Patterns
```
http://paypal-secure-login.tk
http://amazon-account-verify.ml
http://microsoft-update-security.ga
http://apple-id-unlock.cf
http://facebook-security-check.gq
http://google-account-suspended.xyz
http://netflix-payment-update.top
http://bank-of-america-verify.click
```

### IP Address URLs
```
http://192.168.1.1/admin
http://10.0.0.1/login
http://172.16.0.1/config
http://203.0.113.0/admin/login
http://198.51.100.1/wp-admin
```

### Suspicious Subdomains
```
http://login.secure.paypal.phishing-site.com
http://verify.account.amazon.malicious.tk
http://update.microsoft.fake-domain.ml
```

### Malware/Download Patterns
```
http://free-download.tk/malware.exe
http://crack-software.ml/keygen.zip
http://pirated-games.ga/setup.exe
http://free-movies.cf/player.exe
```

### Homograph/Typosquatting
```
http://g00gle.com
http://faceb00k.com
http://micr0soft.com
http://yah00.com
http://netfIix.com
```

### Suspicious Query Parameters
```
http://legitimate-site.com/redirect?url=http://evil.tk
http://example.com/login?next=http://phishing.ml
http://site.com/download?file=../../etc/passwd
http://example.com/search?q=<script>alert('xss')</script>
```

### Multiple Redirects
```
http://redirect1.tk/go?url=http://redirect2.ml/go?url=http://final-malware.ga
```

---

## 🧪 EDGE CASES (Interesting test cases)

### Localhost/Private IPs
```
http://localhost:8080/admin
http://127.0.0.1/dashboard
http://0.0.0.0/config
```

### Very Long URLs
```
http://example.com/very/long/path/with/many/segments/that/goes/on/and/on/and/on/page.html
```

### Special Characters
```
http://example.com/search?q=test&filter=all&sort=date&page=1&limit=10
http://example.com/path%20with%20spaces/file.html
http://example.com/unicode/测试/page
```

### Subdomains
```
http://subdomain1.subdomain2.subdomain3.example.com
http://www.secure.login.banking.example.com
```

### No Protocol
```
example.com
www.google.com
github.com/user/repo
```

### FTP/Other Protocols
```
ftp://ftp.example.com/files
file:///etc/passwd
javascript:alert('xss')
```

---

## 📊 Testing Strategy

### 1. **Baseline Test** (Should all be SAFE)
- google.com
- facebook.com
- github.com
- wikipedia.org
- stackoverflow.com

### 2. **Phishing Test** (Should all be MALICIOUS)
- paypal-verify.tk
- amazon-security.ml
- bank-login.ga
- 192.168.1.1/admin
- microsoft-update.xyz

### 3. **Edge Cases** (Mixed results expected)
- bit.ly/abc123
- localhost:8080
- example.com/redirect?url=...
- subdomain.subdomain.example.com

### 4. **Real-World Phishing Examples** (Should be MALICIOUS)
```
http://secure-paypaI.com (note the capital i instead of l)
http://www.paypal.com.phishing-site.tk
http://paypal.com-secure-login.ml
http://account-verification-required.xyz/paypal
```

---

## 🎯 Expected Results Summary

| Category | Expected Verdict | Threat Probability |
|----------|-----------------|-------------------|
| Popular Sites | Safe | < 20% |
| Educational/Gov | Safe | < 20% |
| Shortened URLs | Suspicious/Uncertain | 20-60% |
| Unusual TLDs | Suspicious | 40-70% |
| Phishing Patterns | Malicious | > 80% |
| IP Addresses | Malicious | > 90% |
| Typosquatting | Malicious | > 85% |

---

## 💡 How to Test

1. **Copy URLs from each category**
2. **Paste into the URL Analyzer**
3. **Compare actual vs expected results**
4. **Note any false positives/negatives**

### Quick Test Script
You can also create a batch test by modifying `test_model.py` to include these URLs!

---

**Note**: These are synthetic/example malicious URLs for testing purposes. Real malicious URLs should never be visited directly!
