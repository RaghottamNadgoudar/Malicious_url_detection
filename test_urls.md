# Test URLs — URL Security Platform
# Use these with: POST http://localhost:8000/analyze
# Body: { "url": "<URL here>" }
# Or paste directly into the frontend at http://localhost:5173

---

## ✅ SAFE URLs
# Expected: verdict=Safe, risk_score ≤ 30

https://github.com
https://google.com
https://wikipedia.org
https://stackoverflow.com
https://microsoft.com
https://apple.com
https://youtube.com
https://linkedin.com
https://reddit.com
https://amazon.com
https://developer.mozilla.org/en-US/docs/Web/HTTP
https://docs.python.org/3/
https://en.wikipedia.org/wiki/Machine_learning
https://www.bbc.com/news
https://www.nasa.gov

---

## 🚨 MALICIOUS / PHISHING URLs
# Expected: verdict=Malicious, risk_score ≥ 60

# Typosquatting (digit-substitution)
http://paypa1-secure.xyz/login/verify
http://g00gle-secure-login.xyz/verify
http://micros0ft-account-verify.top/signin
http://app1e-id-confirm.click/update
http://arnazon-order.xyz/account/verify

# Brand spoofing in subdomain
http://paypal.secure-login.xyz/verify?account=suspended
http://apple.account-verify.top/signin
http://netflix.billing-update.click/payment
http://amazon.refund-portal.xyz/claim

# Direct IP address (no domain)
http://192.168.1.100/admin/login
http://45.33.22.11/paypal/verify/login
http://10.0.0.1/banking/signin
http://172.16.0.1/secure/update

# Suspicious keywords + bad TLD
http://secure-banking-update.xyz/account/login/verify
http://free-prize-winner-claim.top/redeem?id=99991
http://urgent-account-suspended.click/restore
http://credential-reset-portal.ml/validate
http://crypto-wallet-recovery.tk/restore

# High entropy / obfuscated
http://xK8mN2pQ7rT4vY1z.top/a/b/c/d/e/f?x=1&y=2&z=3
https://aHR0cHM6Ly9ldmlsLmNvbS9waGlzaA.xyz/redirect

---

## ⚠️ SUSPICIOUS URLs
# Expected: verdict=Suspicious, risk_score 31–60

# Long URL with some bad signals but not definitive
https://accounts.google.com.fake-secure-login.info/oauth2/v2/auth
http://login-verify-paypal.net/account/confirm?token=abc123
https://www.amazon.com.account-update.biz/order/return
http://secure.ebay.com.verify-account.info/login

# Suspicious keywords but on legitimate-looking domain
http://mybank.com/secure/update/verify/login?account=suspended
https://support.microsoft-helpdesk.com/reset-password

# Mixed signals
http://bit.ly/3free-gift-now        ← shortened + suspicious keyword
http://tiny.cc/verify-your-account  ← shortened + phishing keyword

---

## 🔗 REDIRECT / SHORTENED URLs
# Expected: is_shortened=true, redirect_chain shows hops

# Common shorteners
https://bit.ly/3OxKl9f
https://tinyurl.com/2p8b7kfm
https://t.co/example
https://goo.gl/maps/example
https://ow.ly/example
https://is.gd/example
https://buff.ly/example
https://rb.gy/example
https://shorturl.at/example

# t.co (Twitter links — always redirect)
https://t.co/abc123xyz

# Rebrand.ly
https://rebrand.ly/example-link

---

## 🔄 MULTI-HOP REDIRECT CHAINS
# These simulate chained redirects (URL → URL → URL → destination)
# Use these to test redirect depth > 2

http://bit.ly/chain-test-1        # shortener → intermediate → final
https://tinyurl.com/chain-test    # may have 2-3 hops
https://ow.ly/multi-hop           # longer chains

---

## 🌀 EDGE CASES

# URL without scheme (auto-fix expected: adds http://)
google.com
paypal.com
github.com

# Localhost / private IP (should flag has_ip=true)
http://localhost:8080/admin
http://127.0.0.1/login
http://0.0.0.0/secret

# Suspicious port
http://malicious-site.com:4444/payload
http://evil.xyz:8888/cmd/execute
http://phish.tk:9999/steal

# @ symbol in URL (classic phishing trick — hides real destination)
http://legitimate.com@evil-phishing.xyz/login
https://google.com@attacker.com/steal

# Double slash in path (open redirect attempt)
http://evil.com//login//verify//account
https://phish.xyz//redirect//paypal//signin

# Extremely long URL (> 200 chars)
http://this-is-a-very-long-phishing-url-designed-to-look-legitimate.secure-bank-login-verify-account-suspended.xyz/user/account/verify/update/confirm/login?token=abcdef123456&session=xyz789&redirect=http://evil.com

# High special char density
http://evil.xyz/%61%64%6D%69%6E/%6C%6F%67%69%6E?%72%65%64%69%72%65%63%74=%68%74%74%70%3A%2F%2F%70%68%69%73%68

# Subdomain depth (many dots)
http://secure.login.verify.account.update.paypal.com.evil.xyz/signin

# Known malware campaign patterns
http://malware-download.top/install.exe?source=email
http://ransomware-unlock.click/decrypt?id=victim123
http://exploit-kit.xyz/payload?browser=chrome&version=124

---

## 📋 QUICK CURL COMMANDS

### Test safe URL:
```bash
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com"}' | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(f'Verdict: {d[\"prediction\"][\"label\"]} | Risk: {d[\"risk_score\"][\"score\"]}/100')"
```

### Test malicious URL:
```bash
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure.xyz/login/verify?account=suspended"}' | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(f'Verdict: {d[\"prediction\"][\"label\"]} | Risk: {d[\"risk_score\"][\"score\"]}/100')"
```

### Test shortened URL (redirect tracing):
```bash
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://bit.ly/3OxKl9f"}' | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(f'Shortened: {d[\"is_shortened\"]} | Hops: {d[\"redirect_count\"]} | Expanded: {d[\"expanded_url\"]}')"
```

### Test IP URL:
```bash
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://45.33.22.11/paypal/verify"}' | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print(f'Has IP: {d[\"features\"][\"has_ip\"]} | Risk: {d[\"risk_score\"][\"score\"]}/100')"
```

### Batch test (run all at once):
```bash
for URL in \
  "https://github.com" \
  "http://paypa1-secure.xyz/login/verify" \
  "http://45.33.22.11/admin/login" \
  "http://g00gle-secure.xyz/signin" \
  "https://bit.ly/3OxKl9f" \
  "http://secure-banking-update.xyz/account"; do
  RESULT=$(curl -s -X POST http://localhost:8000/analyze \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"$URL\"}" | python3 -c \
    "import json,sys; d=json.load(sys.stdin); print(f'{d[\"prediction\"][\"label\"]:12} | Risk: {d[\"risk_score\"][\"score\"]:3}/100 | {d[\"original_url\"][:50]}')" 2>/dev/null)
  echo "$RESULT"
done
```
