"""
demo_batch.py — Full System Demo: 1000 URLs → Optimized → DistilBERT
=====================================================================
Run:
    cd daa_model
    /opt/homebrew/Caskroom/miniforge/base/envs/tf-metal/bin/python demo_batch.py
"""

import time
import random
from batch_optimizer import BatchOptimizer
from pipeline_bert import BertPipeline

# ── Synthetic 1000-URL batch ──────────────────────────────────────────────────
# Mirrors real-world enterprise traffic distribution:
#   ~40% clearly safe (whitelisted)
#   ~20% clearly malicious (keyword/TLD flags)
#   ~40% ambiguous (needs DistilBERT)
SAFE_POOL = [
    "https://google.com", "https://github.com", "https://stackoverflow.com",
    "https://rvce.edu.in", "https://iitb.ac.in", "https://nic.gov.in",
    "https://wikipedia.org/wiki/Machine_learning",
    "https://amazon.com/dp/B08N5WRWNW",
    "https://microsoft.com/en-us/windows",
    "https://cloudflare.com",
    "https://youtube.com/watch?v=dQw4w9WgXcQ",
    "https://reddit.com/r/python",
    "https://linkedin.com/in/johndoe",
    "https://iimb.ac.in/programmes/mba",
    "https://iisc.ac.in/research",
]
MALICIOUS_POOL = [
    "http://paypal-secure.tk/login?verify=account&redirect=http://evil.ml",
    "http://apple-id-suspended.ml/unlock?token=abc123",
    "http://amazon-prize-winner.xyz/claim?user=victim&code=FREE100",
    "http://192.168.100.1/admin/shell.php",
    "http://185.220.101.5/gate.php?botid=x7g&cmd=download",
    "http://signin.paypa1-verification.tk/login",
    "http://bank-of-america-secure.ml/verify-identity",
    "http://free-bitcoin-reward.top/wallet-verify?amount=0.5btc",
    "http://microsoft-support-alert.xyz/fix-virus?call=1800FAKE",
    "http://instagram-prize-offer.ml/claim-now",
]
AMBIGUOUS_POOL = [
    "http://shop.example.biz/checkout",
    "http://cdn.analytics-tracker.io/pixel.gif",
    "http://newsletter.marketing-platform.co/unsubscribe?id=12345",
    "https://api.weather-data.info/forecast?city=Bangalore",
    "http://forum.techcommunity.net/thread/12345",
    "https://download.softwarehub.org/setup.exe",
    "http://mail.business-services.co/login",
    "https://jobs.staffingportal.in/apply?role=developer",
    "http://app.cloudservice.io/dashboard",
    "https://tracker.shipping-info.net/track?id=IN123456",
]

random.seed(42)
batch = []
# 400 safe (with duplicates intentionally added)
for _ in range(400):
    batch.append(random.choice(SAFE_POOL))
# 200 malicious
for _ in range(200):
    url = random.choice(MALICIOUS_POOL)
    # add slight variation to some
    if random.random() > 0.5:
        url = url.replace("login", "signin").replace("verify", "confirm")
    batch.append(url)
# 400 ambiguous
for _ in range(400):
    url = random.choice(AMBIGUOUS_POOL)
    if random.random() > 0.5:
        url += f"&session={random.randint(1000,9999)}"
    batch.append(url)

random.shuffle(batch)
print(f"Generated batch of {len(batch)} URLs\n")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Run Batch Optimizer (DAA preprocessing)
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 65)
print("  STEP 1 — DAA Batch Optimizer (preprocessing)")
print("=" * 65)

optimizer = BatchOptimizer(verbose=True)
t_opt_start = time.monotonic()
result = optimizer.process(batch)
t_opt_end = time.monotonic()

print(f"\n{result.summary()}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Run DistilBERT only on uncertain URLs
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  STEP 2 — DistilBERT inference (uncertain URLs only)")
print("=" * 65)

pipe = BertPipeline(quiet=True)

bert_results = []
t_bert_start = time.monotonic()
for url in result.uncertain_urls:
    r = pipe.classify(url)
    bert_results.append(r)
t_bert_end = time.monotonic()

bert_ms = (t_bert_end - t_bert_start) * 1000
print(f"\n  DistilBERT classified {len(bert_results)} uncertain URLs in {bert_ms:.0f}ms "
      f"({bert_ms/max(len(bert_results),1):.1f}ms/url)")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Merge + Final Report
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  STEP 3 — Final Merged Report")
print("=" * 65)

all_verdicts = (
    [(r.url, r.verdict, r.confidence, r.stage) for r in result.decided]
    + [(r['url'], r['verdict'], r['confidence'], 'S5-DistilBERT') for r in bert_results]
)

counts = {"safe": 0, "suspicious": 0, "malicious": 0}
for _, v, _, _ in all_verdicts:
    counts[v] = counts.get(v, 0) + 1

total_ms = (t_opt_end - t_opt_start + t_bert_end - t_bert_start) * 1000
naive_ms  = len(batch) * 25   # naive: all URLs through DistilBERT @ ~25ms each

print(f"""
  URLs processed       : {len(batch)}
  ─────────────────────────────────────────
  🟢 Safe              : {counts['safe']}
  🟡 Suspicious        : {counts['suspicious']}
  🔴 Malicious         : {counts['malicious']}
  ─────────────────────────────────────────
  DAA preprocessing    : {(t_opt_end-t_opt_start)*1000:.1f} ms
  DistilBERT inference : {bert_ms:.0f} ms  (only {len(result.uncertain_urls)} URLs)
  Total time           : {total_ms:.0f} ms
  ─────────────────────────────────────────
  Naive time estimate  : {naive_ms:,} ms  (all {len(batch)} × 25ms)
  Speedup              : {naive_ms/max(total_ms,1):.1f}×  faster
  Reduction            : {result.reduction_pct:.0f}% fewer DistilBERT calls
""")

print(result.risk_report())

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: Huffman audit log compression demo (Unit IV)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  STEP 4 — Huffman Audit Log Compression (Unit IV)")
print("=" * 65)

from batch_optimizer import huffman_compress_log
import json

log_entry = json.dumps({
    "total": len(batch),
    "safe": counts["safe"],
    "malicious": counts["malicious"],
    "suspicious": counts["suspicious"],
    "top_threats": [r.url for r in result.decided if r.verdict == "malicious"][:3],
})
encoded_bits, ratio = huffman_compress_log(log_entry)
print(f"\n  Log entry     : {len(log_entry)} chars  ({len(log_entry)*8} bits)")
print(f"  Huffman coded : {len(encoded_bits)} bits")
print(f"  Ratio         : {ratio:.1%}  (saved {(1-ratio)*100:.0f}% storage)")
print(f"  Lossless      : True  (Huffman is lossless by construction)")
