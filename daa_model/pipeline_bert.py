"""
pipeline_bert.py — DistilBERT + Cisco Umbrella Malicious URL Pipeline
======================================================================
Architecture (4-tier, outermost wins):

  Tier 0 — URLhaus (abuse.ch) threat intelligence
            Real-time malware URL database — instantly blocks known-bad
            domains/URLs and lets DistilBERT focus on unknowns.
            Free API; gracefully skipped when Auth-Key is absent/timeout.

  Tier 1 — Local whitelist + trusted-suffix rules
            Hardcoded safe domains (rvce.edu.in, gov.in, github.com …)
            short-circuits before any ML inference (~0 ms).

  Tier 2 — DistilBERT [CLS] classifier
            Fine-tuned on URL text; catches phishing, brand-spoofing,
            and semantic tricks that purely structural rules miss.

  Tier 3 — Rule-based hard-signal supplement
            Structural heuristics (suspicious TLD, IP-as-host, brand
            in subdomain) boost confidence when DistilBERT is uncertain.

Usage:
    from pipeline_bert import BertPipeline
    pipe = BertPipeline()
    result = pipe.classify("http://paypal-secure.tk/login")

URLhaus setup:
    Add to daa_model/.env:
        URLHAUS_AUTH_KEY=<your-key>
    Get a free key at: https://auth.abuse.ch/
"""

import os, re, math, zipfile, io, logging
from collections import Counter
from urllib.parse import urlparse, unquote

# ── env flags — set BEFORE any C-extension import ────────────────────────────
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")   # use local HF cache only
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")  # OMP dylib coexistence

# Suppress PyTorch 2.x meta-parameter warnings that fire on every load_state_dict
# when a model is initialised with from_pretrained (which uses meta tensors).
# These are cosmetic — the model loads and runs correctly without assign=True.
import warnings
warnings.filterwarnings(
    "ignore",
    message=".*copying from a non-meta parameter.*",
    category=UserWarning,
)

import numpy as np
import torch
import torch.nn as nn
import tldextract
from transformers import DistilBertTokenizer, DistilBertModel
import cisco_umbrella as umbrella
from trusted_suffixes import is_trusted_suffix

logger = logging.getLogger(__name__)

# ── Model path ────────────────────────────────────────────────────────────────
_DIR        = os.path.dirname(os.path.abspath(__file__))
EXPERT2_DIR = os.path.join(_DIR, "expert2_distilbert.pt", "expert2_distilbert")

# ── Verdict thresholds ────────────────────────────────────────────────────────
SAFE_THRESHOLD       = 0.35   # below → safe
SUSPICIOUS_THRESHOLD = 0.60   # below → suspicious, above → malicious

# ── Logit de-saturation divisor ──────────────────────────────────────────────
# The model was trained without calibration and produces logits up to ±30.
# Dividing before sigmoid squashes them into a usable 0–1 range.
_SCALE = 15.0

# ── Domain lists ─────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    'tk','ml','ga','cf','gq','xyz','top','work','click','loan','win',
    'racing','date','download','stream','gdn','accountant','trade',
    'cc','pw','su','zip','icu','info',
}
PHISHING_KEYWORDS = [
    'login','verify','secure','update','bank','paypal','apple','amazon',
    'confirm','account','signin','ebay','password','suspended','locked',
    'urgent','support','billing','invoice','expire','validate','credential',
    'recovery','reset','authentication','wallet','crypto','security','alert',
    'click','free','prize','winner','download','install','offer','discount',
    'limited','claim','reward','gift',
]
SPOOFED_BRANDS = [
    'paypal','apple','google','microsoft','amazon','facebook',
    'netflix','instagram','twitter','ebay','wellsfargo',
    'bankofamerica','chase','citibank',
]
WHITELISTED_DOMAINS = {
    'google.com','youtube.com','facebook.com','twitter.com','x.com',
    'instagram.com','linkedin.com','reddit.com','wikipedia.org','amazon.com',
    'apple.com','microsoft.com','github.com','gitlab.com','stackoverflow.com',
    'openai.com','huggingface.co','kaggle.com','pypi.org','npmjs.com',
    'mozilla.org','cloudflare.com','netflix.com','spotify.com','dropbox.com',
    'zoom.us','slack.com','notion.so','medium.com','discord.com','twitch.tv',
    'digitalocean.com','bing.com','duckduckgo.com','yahoo.com',
    'nytimes.com','bbc.com','reuters.com','cnn.com',
    'mit.edu','stanford.edu','harvard.edu',
    'coursera.org','udemy.com','khanacademy.org','edx.org',
    'nasa.gov','nih.gov','cdc.gov','stripe.com','paypal.com',
    # Indian institutions
    'rvce.edu.in','iitb.ac.in','iitd.ac.in','iitm.ac.in','iisc.ac.in',
    'iimb.ac.in','bits-pilani.ac.in','vtu.ac.in','bbc.co.uk',
    'gov.in','nic.in','india.gov.in','irctc.co.in','sbi.co.in',
    'msrit.edu','bmsce.ac.in','pes.edu','nitte.edu.in','manipal.edu',
    'christuniversity.in','sjce.ac.in','nitk.ac.in','nitw.ac.in',
}


# ── Model architecture ────────────────────────────────────────────────────────
class URLDistilBert(nn.Module):
    """DistilBERT with a [CLS] → LayerNorm → Dropout → Linear(1) head."""
    def __init__(self):
        super().__init__()
        self.bert = DistilBertModel.from_pretrained(
            'distilbert-base-uncased', local_files_only=True)
        self.classifier = nn.Sequential(
            nn.LayerNorm(768),
            nn.Dropout(0.2),
            nn.Linear(768, 1),
        )

    def forward(self, input_ids, attention_mask):
        hidden = self.bert(input_ids=input_ids, attention_mask=attention_mask)[0]
        return self.classifier(hidden[:, 0, :])   # [CLS] token


# ── Loader (BytesIO — avoids macOS ARM segfault with temp files) ──────────────
def _zip_and_load(model_dir: str):
    """
    Pack a PyTorch save-directory into memory and torch.load it.
    Uses io.BytesIO instead of a temp file on disk to avoid the
    exit-139 segfault on PyTorch 2.12 + Python 3.12 / macOS ARM.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zf:
        for root, _, files in os.walk(model_dir):
            for f in files:
                fp = os.path.join(root, f)
                zf.write(fp, os.path.relpath(fp, os.path.dirname(model_dir)))
    buf.seek(0)
    return torch.load(buf, map_location='cpu', weights_only=False)


# ── Helper utilities ──────────────────────────────────────────────────────────
def _parse_domain(url: str) -> dict:
    ext = tldextract.extract(url)
    return {
        "subdomain":          ext.subdomain,
        "registrable_domain": ext.domain,
        "suffix":             ext.suffix,
        "full_registrable":   f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain,
        "subdomain_depth":    len(ext.subdomain.split(".")) if ext.subdomain else 0,
    }


def _entropy(text: str) -> float:
    if not text: return 0.0
    freq = Counter(text); total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _keyword_score(url: str) -> float:
    decoded = unquote(url).lower()
    return min(sum(1 for kw in PHISHING_KEYWORDS if kw in decoded) / len(PHISHING_KEYWORDS), 1.0)


def _brand_in_subdomain(url: str, ext: dict) -> bool:
    try:
        host = (urlparse(url).netloc or '').lower().split(':')[0]
        root = ext["full_registrable"]
        prefix = host[:host.rfind(root)].rstrip('.')
        path = (urlparse(url).path or '').lower()
        for brand in SPOOFED_BRANDS:
            if (brand in prefix or brand in path) and brand not in ext["registrable_domain"]:
                return True
    except Exception:
        pass
    return False


def is_whitelisted(url: str) -> bool:
    try:
        host = (urlparse(url).netloc or url.split('/')[0]).lower().split(':')[0]
        if host in WHITELISTED_DOMAINS: return True
        bare = host[4:] if host.startswith('www.') else host
        if bare in WHITELISTED_DOMAINS: return True
        for domain in WHITELISTED_DOMAINS:
            if host.endswith('.' + domain): return True
        # Trusted institutional suffixes — global education, government & academia
        # Sourced from Mozilla Public Suffix List (405 entries in trusted_suffixes.py)
        ext = tldextract.extract(url)
        if is_trusted_suffix(ext.suffix):
            return True
    except Exception:
        pass
    return False


def _hard_signal(url: str) -> float:
    """
    Rule-based suspicion score derived purely from URL structure.
    No ML — acts as a fast guard and a calibration boost when DistilBERT
    is uncertain (0.35–0.60 range).
    """
    score = 0.0
    ext = _parse_domain(url)
    if ext["suffix"] in SUSPICIOUS_TLDS:                               score += 0.40
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):        score += 0.30
    if '@' in url:                                                      score += 0.25
    if _brand_in_subdomain(url, ext):                                   score += 0.35
    ks = _keyword_score(url)
    if ks > 0.05:                                                       score += ks * 0.20
    if '//' in (urlparse(url).path or ''):                              score += 0.15
    if _entropy(url) > 5.0:                                             score += 0.10
    return min(score, 1.0)


def _feature_summary(url: str) -> dict:
    """Lightweight feature dict returned in every result for the UI."""
    ext = _parse_domain(url)
    return {
        'url_length':         len(url),
        'domain_length':      len(ext["full_registrable"]),
        'subdomain_depth':    ext["subdomain_depth"],
        'has_https':          url.startswith('https://'),
        'tld_suspicion':      ext["suffix"] in SUSPICIOUS_TLDS,
        'has_ip':             bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
        'has_at_symbol':      '@' in url,
        'keyword_score':      round(_keyword_score(url), 4),
        'brand_in_subdomain': _brand_in_subdomain(url, ext),
        'url_entropy':        round(_entropy(url), 4),
        'dot_count':          url.count('.'),
        'hyphen_count':       url.count('-'),
        'tld':                ext['suffix'],
        'registrable_domain': ext['full_registrable'],
    }


# ── Pipeline ──────────────────────────────────────────────────────────────────
class BertPipeline:
    """
    4-tier malicious URL detection pipeline.

    Tier 0 — URLhaus (abuse.ch) threat intelligence (free, pre-ML)
    Tier 1 — Local whitelist + trusted-suffix rules  (~0 ms)
    Tier 2 — DistilBERT [CLS] classifier             (~18–35 ms)
    Tier 3 — Rule-based hard-signal supplement       (~0 ms)

    Verdict thresholds:
        < 0.35   →  safe
        0.35–0.60 → suspicious
        > 0.60   →  malicious
    """

    def __init__(self, quiet: bool = False):
        self._quiet = quiet

        # Initialise URLhaus client once (reads URLHAUS_AUTH_KEY from .env)
        self._umbrella = umbrella.get_client()
        if self._umbrella.available:
            self._log("Tier-0: URLhaus (abuse.ch) threat intel enabled ✓")
        else:
            self._log("Tier-0: URLhaus not configured "
                      "(add URLHAUS_AUTH_KEY to daa_model/.env to enable).")

        self._log("Loading DistilBERT classifier...")
        ckpt = _zip_and_load(EXPERT2_DIR)
        self._bert_max_len = ckpt.get('max_length', 128)
        checkpoint_name    = ckpt.get('checkpoint', 'distilbert-base-uncased')

        model = URLDistilBert()
        # Warnings about meta-parameter copying are suppressed at module level
        # (see warnings.filterwarnings above). Do NOT pass assign=True here —
        # it causes device mismatch on Apple Silicon MPS when from_pretrained
        # places tensors on MPS while the checkpoint is loaded with map_location='cpu'.
        model.load_state_dict(ckpt['state_dict'])
        model.eval()
        self._model = model

        self.tokenizer = DistilBertTokenizer.from_pretrained(
            checkpoint_name, local_files_only=True)

        self._log("BertPipeline ready.")

    def _log(self, msg: str) -> None:
        if not self._quiet:
            print(f"[BertPipeline] {msg}")

    # ── Expert inference ─────────────────────────────────────────────────────
    def _bert_score(self, url: str) -> float:
        """Run DistilBERT on `url` and return calibrated P(malicious)."""
        tokens = self.tokenizer(
            url,
            max_length=self._bert_max_len,
            padding='max_length',
            truncation=True,
            return_tensors='pt',
        )
        with torch.no_grad():
            logit = self._model(tokens['input_ids'], tokens['attention_mask']).item()
        return float(torch.sigmoid(torch.tensor(logit / _SCALE)))

    # ── Main classify ────────────────────────────────────────────────────────
    def classify(self, url: str) -> dict:
        url = url.strip()
        umbrella_result = None

        # ── Tier 0: Cisco Umbrella threat intelligence ────────────────────────
        # Query the Investigate API for a real-time domain verdict.
        # If Umbrella is confident → short-circuit immediately (no DistilBERT).
        # If timeout / no token → transparent fallthrough to Tier 1.
        if self._umbrella.available:
            um = self._umbrella.lookup(url)
            umbrella_result = {
                'domain':     um.domain,
                'verdict':    um.verdict,
                'status':     um.status,
                'confidence': um.confidence,
                'categories': list(um.categories.keys())[:8],
                'security':   um.security,
                'source':     um.source,
                'latency_ms': um.latency_ms,
            }

            if um.verdict == 'malicious':
                # URLhaus has this domain in its threat DB → hard block
                return self._build_result(
                    url,
                    confidence   = max(um.confidence, 0.90),
                    bert_prob    = None,
                    verdict      = 'malicious',
                    reasoning    = (
                        f"URLhaus: MALICIOUS (status={um.status}, "
                        f"conf={um.confidence:.1%}, "
                        f"tags={list(um.categories.keys())[:3]}). "
                        f"DistilBERT skipped."
                    ),
                    umbrella_result = umbrella_result,
                )

            if um.verdict == 'safe' and um.source != 'unavailable':
                # URLhaus explicitly cleared this domain → safe fast-path
                return self._build_result(
                    url,
                    confidence   = 0.02,
                    bert_prob    = None,
                    verdict      = 'safe',
                    reasoning    = (
                        f"URLhaus: SAFE (not in malware DB). "
                        f"DistilBERT skipped."
                    ),
                    umbrella_result = umbrella_result,
                )
            # um.verdict == 'unknown' or source == 'unavailable'
            # → fall through to local tiers

        # ── Tier 1: Local whitelist + trusted-suffix rules ────────────────────
        if is_whitelisted(url):
            return self._build_result(
                url, 0.01, None, 'safe',
                'Whitelisted domain.',
                umbrella_result=umbrella_result,
            )

        # ── Tier 2: DistilBERT inference ──────────────────────────────────────
        bert_prob = self._bert_score(url)
        prob      = bert_prob

        # ── Tier 3: Rule-based hard-signal supplement ─────────────────────────
        hard = _hard_signal(url)
        reason_hard = ""
        if hard >= 0.40:
            prob = max(prob, 0.80 + hard * 0.15)
            reason_hard = f" Hard signals override (score={hard:.2f})."
        elif hard >= 0.20:
            prob = min(1.0, prob + 0.12)
            reason_hard = f" Moderate hard signals (score={hard:.2f})."

        prob = float(np.clip(prob, 0.0, 1.0))

        # ── Verdict ───────────────────────────────────────────────────────────
        if prob < SAFE_THRESHOLD:
            verdict = 'safe'
        elif prob < SUSPICIOUS_THRESHOLD:
            verdict = 'suspicious'
        else:
            verdict = 'malicious'

        reasoning = (
            f"DistilBERT {prob:.1%} (raw={bert_prob:.1%})."
            f"{reason_hard}"
        )
        return self._build_result(
            url, prob, bert_prob, verdict, reasoning,
            umbrella_result=umbrella_result,
        )

    # ── Result builder ────────────────────────────────────────────────────────
    def _build_result(
        self,
        url:             str,
        confidence:      float,
        bert_prob,                   # float or None (when skipped)
        verdict:         str,
        reasoning:       str,
        umbrella_result: dict = None,
    ) -> dict:
        result = {
            'url':        url,
            'verdict':    verdict,
            'confidence': round(confidence, 4),
            'expert_scores': {
                'distilbert': round(bert_prob, 4) if bert_prob is not None else None,
            },
            'features':       _feature_summary(url),
            'reasoning':      reasoning,
            'pipeline':       'distilbert_only',
            'umbrella':       umbrella_result,
        }
        return result


# ── CLI quick-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    pipe = BertPipeline()
    urls = sys.argv[1:] or [
        "https://www.google.com",
        "https://rvce.edu.in",
        "https://iitb.ac.in",
        "http://paypal-secure.tk/login",
        "http://phishing-login.ml",
        "http://verify-account.xyz/update",
        "http://192.168.1.1/admin",
        "https://en.wikipedia.org/wiki/Machine_learning#Applications",
        "https://github.com/openai/whisper/blob/main/whisper/tokenizer.py",
    ]

    ICONS = {"malicious": "🔴", "suspicious": "🟡", "safe": "🟢"}
    print(f"\n{'URL':<58} {'Verdict':<12} {'Conf':>6}  {'Tier'}")
    print("─" * 90)
    for url in urls:
        r = pipe.classify(url)
        icon = ICONS[r['verdict']]
        um   = r.get('umbrella')

        # Which tier decided the verdict?
        if um and um['verdict'] in ('malicious', 'safe') and um['source'] != 'unavailable':
            tier = f"T0-URLhaus ({um['source']})"
        elif 'Whitelisted' in r['reasoning']:
            tier = "T1-Whitelist"
        else:
            tier = "T2-DistilBERT"

        print(f"{icon} {url:<56} {r['verdict']:<12} {r['confidence']:>6.1%}  {tier}")
        print(f"   {r['reasoning']}")
        if um and um['categories']:
            print(f"   Umbrella cats: {um['categories']}")
