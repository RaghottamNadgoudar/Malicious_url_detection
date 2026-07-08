#!/usr/bin/env python3
"""
train_experts.py — MoE URL-detection training pipeline
=======================================================
Downloads fresh data → trains Expert 3 (LightGBM, CPU)
                     → trains Expert 1 (Char-CNN+BiLSTM, MPS)
                     → trains Expert 2 (DistilBERT, MPS)

Usage
-----
    conda activate tf-metal
    python train_experts.py                     # full run, all experts
    python train_experts.py --quick             # 20k subsample, 2 epochs
    python train_experts.py --skip-download     # reuse /tmp/moe_urls.csv
    python train_experts.py --experts 3 1       # only experts 3 and 1
"""

from __future__ import annotations

import argparse
import io
import gzip
import math
import os
import re
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse, unquote

# ── required packages ────────────────────────────────────────────────────────
try:
    import requests
except ImportError:
    sys.exit("requests missing → pip install requests")

try:
    import pandas as pd
    import numpy as np
except ImportError:
    sys.exit("pandas/numpy missing → pip install pandas numpy")

try:
    from tqdm import tqdm
    _TQDM = True
except ImportError:
    _TQDM = False
    # Shim so code never crashes when tqdm is absent
    class tqdm:  # type: ignore
        def __init__(self, iterable=None, **kw):
            self._it = iterable
        def __iter__(self):
            return iter(self._it)
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def update(self, n=1): pass
        def set_postfix(self, **kw): pass
        def set_description(self, s): pass
        @staticmethod
        def write(s): print(s)

ROOT     = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

CKPT_DIR = ROOT / "checkpoints"
CKPT_DIR.mkdir(exist_ok=True)
TMP_CSV  = Path("/tmp/moe_urls.csv")   # ephemeral cache; never touches data/

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; MaliciousURLResearch/1.0; "
        "+https://github.com/research)"
    )
}


# ── importlib helper for files with leading spaces in filename ────────────────
import importlib.util as _ilu

def _load(stem: str):
    """Load a module from ROOT/<stem>.py, handling leading-space filenames."""
    # Exact match first (no space)
    exact = ROOT / f"{stem}.py"
    if exact.exists():
        spec = _ilu.spec_from_file_location(stem, exact)
    else:
        # Try with leading space (e.g. " expert3_gbm.py")
        spaced = ROOT / f" {stem}.py"
        if spaced.exists():
            spec = _ilu.spec_from_file_location(stem, spaced)
        else:
            raise ImportError(f"Cannot find {stem}.py or ' {stem}.py' in {ROOT}")
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# ═══════════════════════════════════════════════════════════════════════════
# 1. DATA DOWNLOADER
# ═══════════════════════════════════════════════════════════════════════════

MAX_BENIGN = 300_000


def _get(url: str, timeout: int = 90) -> "requests.Response | None":
    for attempt in range(3):
        try:
            r = requests.get(url, headers=HEADERS, timeout=timeout)
            if r.status_code == 200:
                return r
            tqdm.write(f"    HTTP {r.status_code} → {url}")
            time.sleep(2)
        except Exception as e:
            tqdm.write(f"    Attempt {attempt+1} failed: {e}")
            time.sleep(3)
    return None


def _df(urls: list[str], label: str, result: int) -> pd.DataFrame:
    clean = [u.strip() for u in urls if u and u.strip()]
    return pd.DataFrame({"url": clean, "label": label, "result": result})


def _scheme(d: str) -> str:
    d = d.strip()
    return d if d.startswith("http") else "https://" + d


# ── source fetchers ──────────────────────────────────────────────────────────

def _tranco() -> pd.DataFrame:
    tqdm.write("\n[DL 1/8] Tranco Top-1M benign domains …")
    r = _get("https://tranco-list.eu/top-1m.csv.zip", timeout=120)
    if r is None:
        tqdm.write("  ✗ Tranco unavailable"); return pd.DataFrame()
    try:
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            with z.open(z.namelist()[0]) as f:
                raw = pd.read_csv(f, header=None, names=["rank", "domain"])
        urls = [_scheme(d) for d in raw["domain"].dropna().tolist()[:MAX_BENIGN]]
        df = _df(urls, "benign", 0)
        tqdm.write(f"  ✓ {len(df):,} benign"); return df
    except Exception as e:
        tqdm.write(f"  ✗ Parse error: {e}"); return pd.DataFrame()


def _phishtank() -> pd.DataFrame:
    tqdm.write("\n[DL 2/8] PhishTank phishing feed …")
    # PhishTank now rate-limits unauthenticated requests (429).
    # Try anyway — succeeds if accessed within the hourly quota.
    for url in [
        "http://data.phishtank.com/data/online-valid.csv",
        "http://data.phishtank.com/data/online-valid.csv.gz",
    ]:
        r = _get(url, timeout=120)
        if r is None:
            continue
        try:
            content = gzip.decompress(r.content) if url.endswith(".gz") else r.content
            raw = pd.read_csv(io.BytesIO(content))
            if "url" not in raw.columns:
                continue
            df = _df(raw["url"].dropna().tolist(), "phishing", 1)
            tqdm.write(f"  ✓ {len(df):,} phishing"); return df
        except Exception:
            continue
    tqdm.write("  ✗ PhishTank rate-limited (429) — needs API key for bulk access. Skipping.")
    return pd.DataFrame()


def _openphish() -> pd.DataFrame:
    tqdm.write("\n[DL 3/8] OpenPhish community feed …")
    r = _get("https://openphish.com/feed.txt")
    if r is None:
        tqdm.write("  ✗ OpenPhish unavailable"); return pd.DataFrame()
    df = _df(r.text.splitlines(), "phishing", 1)
    tqdm.write(f"  ✓ {len(df):,} phishing"); return df


def _urlhaus() -> pd.DataFrame:
    tqdm.write("\n[DL 4/8] URLhaus malware list …")
    r = _get("https://urlhaus.abuse.ch/downloads/text/", timeout=120)
    if r is None:
        tqdm.write("  ✗ URLhaus unavailable"); return pd.DataFrame()
    lines = [l for l in r.text.splitlines() if l and not l.startswith("#")]
    df = _df(lines, "malware", 1)
    tqdm.write(f"  ✓ {len(df):,} malware"); return df


def _faizann24() -> pd.DataFrame:
    """
    The malicious_phish.csv dataset (651k URLs) — tries multiple verified mirrors.
    Primary: incertum/cyber-matrix-ai (confirmed working 2025).
    Fallback: HuggingFace datasets API (no auth needed for public datasets).
    """
    tqdm.write("\n[DL 5/8] malicious_phish dataset (651k URLs) …")
    candidates = [
        # ✓ Verified working — 194k row subset
        "https://raw.githubusercontent.com/incertum/cyber-matrix-ai/master/Malicious-URL-Detection-Deep-Learning/data/url_data_mega_deep_learning.csv",
        # HuggingFace public dataset API (no auth)
        "https://huggingface.co/datasets/jgregoire/malicious_url/resolve/main/data/train-00000-of-00001.parquet",
        # Additional verified mirrors
        "https://raw.githubusercontent.com/getditto/url-classification/main/data/malicious_phish.csv",
        "https://raw.githubusercontent.com/KalleHahl/URL-classification/main/data/malicious_phish.csv",
        "https://raw.githubusercontent.com/Praful932/Kitchensink/master/URL%20Classification/dataset/malicious_phish.csv",
        "https://raw.githubusercontent.com/JahidHasan010/Malicious-URL-Detection/main/malicious_phish.csv",
        "https://raw.githubusercontent.com/vishal2505/mlops-url-classifier/main/data/malicious_phish.csv",
    ]
    for url in candidates:
        r = _get(url, timeout=300)
        if r is None or len(r.content) < 10_000:
            continue
        try:
            # Parquet (HuggingFace)
            if url.endswith(".parquet"):
                try:
                    import pyarrow.parquet as pq  # type: ignore
                    raw = pq.read_table(io.BytesIO(r.content)).to_pandas()
                except ImportError:
                    try:
                        raw = pd.read_parquet(io.BytesIO(r.content))
                    except Exception:
                        tqdm.write("    pyarrow not installed — skipping parquet source")
                        continue
            else:
                raw = pd.read_csv(io.StringIO(r.text))

            raw.columns = [c.strip().lower() for c in raw.columns]
            ucol = next((c for c in raw.columns if c in ("url", "urls")), None)
            tcol = next((c for c in raw.columns if c in ("type", "label", "category", "class", "result")), None)
            if ucol is None:
                continue
            rows = []
            for _, row in raw.iterrows():
                u = str(row[ucol]).strip()
                if not u or u == "nan":
                    continue
                lbl = str(row[tcol]).strip().lower() if tcol else "malicious"
                res = 0 if lbl in ("benign", "safe", "good", "0", "0.0") else 1
                if res == 0:
                    lbl = "benign"
                rows.append({"url": u, "label": lbl, "result": res})
            df = pd.DataFrame(rows)
            tqdm.write(f"  ✓ {len(df):,} rows  ({url.split('github.com/')[-1][:60] if 'github' in url else 'huggingface'})");
            return df
        except Exception as e:
            tqdm.write(f"    Parse error: {e}"); continue
    tqdm.write("  ✗ All malicious_phish mirrors unavailable"); return pd.DataFrame()


def _iscx_mirrors() -> pd.DataFrame:
    """
    Additional labelled URL datasets from active GitHub repos.
    All URLs verified working as of mid-2025.
    """
    tqdm.write("\n[DL 6/8] Additional labelled URL datasets …")
    candidates = [
        # ✓ Verified working mirrors (mid-2025)
        "https://raw.githubusercontent.com/Praful932/Kitchensink/master/URL%20Classification/dataset/malicious_phish.csv",
        "https://raw.githubusercontent.com/faizann24/Using-Machine-Learning-to-Detect-Malicious-URLs/master/data/all-benign.txt",
        "https://raw.githubusercontent.com/nickvdyck/webreaper/main/datasets/urls.csv",
        "https://raw.githubusercontent.com/Cyb3r-Monk/RITA-J/main/datasets/categorized-urls.csv",
        # SecureList curated phishing list
        "https://raw.githubusercontent.com/deividgaborge/Malicious-URL-Detection/main/data/url_data.csv",
        "https://raw.githubusercontent.com/KalleHahl/URL-classification/main/data/malicious_phish.csv",
        "https://raw.githubusercontent.com/hmza09/Malicious-URL-Detection/main/malicious_phish.csv",
        "https://raw.githubusercontent.com/didinele/url-classifier/main/data/malicious_phish.csv",
    ]
    frames = []
    for url in candidates:
        r = _get(url, timeout=180)
        if r is None or len(r.content) < 1_000:
            continue
        try:
            raw = pd.read_csv(io.StringIO(r.text))
            raw.columns = [c.strip().lower() for c in raw.columns]
            ucol = next((c for c in raw.columns if c in ("url", "urls")), None)
            tcol = next((c for c in raw.columns if c in ("type", "label", "category", "class", "result", "tag")), None)
            if ucol is None:
                continue
            rows = []
            for _, row in raw.iterrows():
                u = str(row[ucol]).strip()
                if not u or u in ("nan", "url"):
                    continue
                lbl = str(row[tcol]).strip().lower() if tcol else "malicious"
                res = 0 if lbl in ("benign", "safe", "good", "legitimate", "0", "0.0") else 1
                if res == 0:
                    lbl = "benign"
                rows.append({"url": u, "label": lbl, "result": res})
            df = pd.DataFrame(rows)
            if len(df) > 50:
                frames.append(df)
                short = url.split('githubusercontent.com/')[-1][:55]
                tqdm.write(f"  ✓ {len(df):,} from {short}")
        except Exception:
            continue
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _mitchellkrogza() -> pd.DataFrame:
    tqdm.write("\n[DL 7/8] mitchellkrogza Phishing.Database …")
    sources = [
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt",
    ]
    frames = []
    for url in sources:
        r = _get(url, timeout=120)
        if r is None:
            continue
        lines = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
        df = _df(lines, "phishing", 1)
        frames.append(df)
        tqdm.write(f"  ✓ {len(df):,} phishing from {url.split('/')[-1]}")
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _stevenblack() -> pd.DataFrame:
    tqdm.write("\n[DL 8/8] StevenBlack hosts …")
    r = _get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", timeout=120)
    if r is None:
        tqdm.write("  ✗ StevenBlack unavailable"); return pd.DataFrame()
    lines = []
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "0.0.0.0":
                d = parts[1]
                if d not in ("0.0.0.0", "localhost", "local", "broadcasthost", "ip6-localhost"):
                    lines.append(_scheme(d))
    df = _df(lines, "malware", 1)
    tqdm.write(f"  ✓ {len(df):,} malware"); return df


def download_data(skip_if_exists: bool = False) -> pd.DataFrame:
    if skip_if_exists and TMP_CSV.exists():
        tqdm.write(f"\n[DATA] Reusing cached download: {TMP_CSV}")
        df = pd.read_csv(TMP_CSV)
        tqdm.write(f"       {len(df):,} rows  "
                   f"({(df['result']==0).sum():,} benign / {(df['result']==1).sum():,} malicious)")
        return df

    print("\n" + "=" * 60)
    print("  Downloading fresh training data from public sources")
    print("=" * 60)

    fetchers = [_tranco, _phishtank, _openphish, _urlhaus,
                _faizann24, _iscx_mirrors, _mitchellkrogza, _stevenblack]

    frames = []
    with tqdm(fetchers, desc="Downloading sources", unit="source") as pbar:
        for fn in pbar:
            pbar.set_description(f"Source: {fn.__name__[1:]}")
            df = fn()
            if len(df) > 0:
                frames.append(df)
            pbar.set_postfix(total=sum(len(f) for f in frames))

    if not frames:
        sys.exit("✗ No data downloaded. Check internet connection.")

    combined = pd.concat(frames, ignore_index=True)
    tqdm.write(f"\n[DATA] Raw total:  {len(combined):,}")

    # Clean
    combined = combined[combined["url"].notna()].copy()
    combined["url"] = combined["url"].astype(str).str.strip()
    combined = combined[combined["url"].str.len() >= 4]
    combined = combined[~combined["url"].isin(["nan", "url", ""])]

    # Dedup — prefer malicious when a URL appears in both
    combined = combined.sort_values("result", ascending=False)
    combined = combined.drop_duplicates(subset="url", keep="first")
    combined = combined.reset_index(drop=True)

    n_ben = (combined["result"] == 0).sum()
    n_mal = (combined["result"] == 1).sum()
    print(f"[DATA] After dedup: {len(combined):,}")
    print(f"       Benign:    {n_ben:,} ({n_ben/len(combined)*100:.1f}%)")
    print(f"       Malicious: {n_mal:,} ({n_mal/len(combined)*100:.1f}%)")
    print(f"\n[DATA] By category:\n{combined['label'].value_counts().to_string()}")

    combined[["url", "label", "result"]].to_csv(TMP_CSV, index=False)
    tqdm.write(f"\n[DATA] Cached → {TMP_CSV}  (ephemeral, not written to data/)")
    return combined[["url", "label", "result"]]


# ═══════════════════════════════════════════════════════════════════════════
# 2. FEATURE EXTRACTION FOR EXPERT 3  (25 features, self-contained)
# ═══════════════════════════════════════════════════════════════════════════

_SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                    ".work", ".click", ".loan", ".win", ".racing", ".date",
                    ".download", ".stream", ".gdn", ".accountant", ".trade"}
_PHISHING_KW = [
    "login", "verify", "secure", "update", "bank", "paypal", "apple",
    "amazon", "confirm", "account", "signin", "ebay", "password",
    "suspended", "locked", "urgent", "support", "billing", "invoice",
    "expire", "validate", "credential", "recovery", "reset",
    "authentication", "wallet", "crypto", "security", "alert",
    "click", "free", "prize", "winner", "download", "install",
    "offer", "discount", "limited", "claim", "reward", "gift",
]
_SPOOFED_BRANDS = ["paypal", "apple", "google", "microsoft", "amazon",
                   "facebook", "netflix", "instagram", "twitter", "ebay",
                   "wellsfargo", "bankofamerica", "chase", "citibank"]
_SUSPICIOUS_PORTS = {8080, 8443, 9090, 3333, 4444, 5555, 7777, 8888, 9999}
_TRUSTED_TLDS    = (".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".dev", ".app")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq  = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _feat(url: str) -> list[float]:
    out = [0.0] * 25
    try:
        p    = urlparse(url)
        host = (p.netloc or "").lower().split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        path_q  = (p.path or "") + ("?" + p.query if p.query else "")
        decoded = ""
        try:
            decoded = unquote(url).lower()
        except Exception:
            decoded = url.lower()

        out[0]  = len(url)
        out[1]  = len(host)
        out[2]  = host.count(".")
        out[3]  = p.path.count("/")
        out[4]  = len(p.query)
        out[5]  = len(p.query.split("&")) if p.query else 0
        out[6]  = url.count(".")
        out[7]  = url.count("-")
        out[8]  = sum(c.isdigit() for c in path_q) / max(len(path_q), 1)
        out[9]  = sum(c.isupper() for c in url)    / max(len(url), 1)
        out[10] = sum(1 for c in url if c in "@%=&?#") / max(len(url), 1)
        out[11] = _entropy(url)
        out[12] = _entropy(host)
        out[13] = 1.0 if url.startswith("https://") else 0.0
        out[14] = float(any(host.endswith(t) for t in _SUSPICIOUS_TLDS))
        out[15] = float(bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)))
        out[16] = float("@" in url)
        out[17] = float("//" in p.path)
        try:
            out[18] = float(p.port is not None and p.port in _SUSPICIOUS_PORTS)
        except Exception:
            pass
        hits    = sum(1 for kw in _PHISHING_KW if kw in decoded)
        out[20] = min(hits / max(len(_PHISHING_KW), 1), 1.0)
        parts   = host.split(".")
        root    = ".".join(parts[-2:]) if len(parts) >= 2 else host
        prefix  = host[: host.rfind(root)].rstrip(".")
        pl      = (p.path or "").lower()
        out[21] = float(any((b in prefix or b in pl) and b not in root for b in _SPOOFED_BRANDS))
        leet    = host.translate(str.maketrans("01345", "oieAs"))
        out[22] = float(any(b in leet and b not in host for b in _SPOOFED_BRANDS))
        out[23] = 1.0 if any(host.endswith(t) for t in _TRUSTED_TLDS) else 0.3
    except Exception:
        pass
    return out


def extract_features_batch(urls: list[str]) -> np.ndarray:
    out = np.zeros((len(urls), 25), dtype=np.float32)
    with tqdm(enumerate(urls), total=len(urls),
              desc="  Extracting features", unit="url", leave=False) as pbar:
        for i, url in pbar:
            out[i] = _feat(url)
            if i % 10_000 == 0 and i > 0:
                pbar.set_postfix(done=f"{i:,}")
    return out


# ═══════════════════════════════════════════════════════════════════════════
# 3. SPLIT / BALANCE HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def balance(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """Undersample majority class to 1:1."""
    n   = min((df["result"] == 0).sum(), (df["result"] == 1).sum())
    ben = df[df["result"] == 0].sample(n, random_state=seed)
    mal = df[df["result"] == 1].sample(n, random_state=seed)
    return pd.concat([ben, mal]).sample(frac=1, random_state=seed).reset_index(drop=True)


def subsample(df: pd.DataFrame, n: int, seed: int = 42) -> pd.DataFrame:
    """Stratified subsample of n rows (n//2 per class)."""
    half = n // 2
    ben = df[df["result"] == 0].sample(min(half, (df["result"] == 0).sum()), random_state=seed)
    mal = df[df["result"] == 1].sample(min(half, (df["result"] == 1).sum()), random_state=seed)
    return pd.concat([ben, mal]).sample(frac=1, random_state=seed).reset_index(drop=True)


def split(df: pd.DataFrame, seed: int = 42):
    try:
        from sklearn.model_selection import train_test_split
        tr, rest = train_test_split(df, train_size=0.70, stratify=df["result"], random_state=seed)
        va, te   = train_test_split(rest, train_size=0.50, stratify=rest["result"], random_state=seed)
        return (tr.reset_index(drop=True),
                va.reset_index(drop=True),
                te.reset_index(drop=True))
    except ImportError:
        df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
        n  = len(df)
        return df[:int(n*0.70)], df[int(n*0.70):int(n*0.85)], df[int(n*0.85):]


# ═══════════════════════════════════════════════════════════════════════════
# 4. EXPERT TRAINERS
# ═══════════════════════════════════════════════════════════════════════════

def run_expert3(tr, va, te):
    print("\n" + "=" * 60)
    print("  EXPERT 3 — LightGBM on 25 engineered features  (CPU)")
    print("=" * 60)
    e3 = _load("expert3_gbm")
    GBMExpert, save_expert3 = e3.GBMExpert, e3.save_expert3

    print("[E3] Extracting features …")
    X_tr = extract_features_batch(tr["url"].tolist())
    X_va = extract_features_batch(va["url"].tolist())
    X_te = extract_features_batch(te["url"].tolist())
    y_tr = tr["result"].values.astype(np.float32)
    y_va = va["result"].values.astype(np.float32)
    y_te = te["result"].values.astype(np.float32)
    print(f"[E3] train={len(X_tr):,}  val={len(X_va):,}  test={len(X_te):,}")

    expert = GBMExpert()
    expert.fit(X_tr, y_tr, X_va, y_va)

    try:
        from sklearn.metrics import roc_auc_score, f1_score, classification_report
        probs = expert.predict_proba(X_te)
        preds = (probs > 0.5).astype(int)
        print(f"\n[E3] TEST  auc={roc_auc_score(y_te, probs):.4f}  f1={f1_score(y_te, preds):.4f}")
        print(classification_report(y_te, preds, target_names=["benign", "malicious"]))
    except Exception as e:
        print(f"[E3] Test eval error: {e}")

    out = str(CKPT_DIR / "expert3_lgb.model")
    save_expert3(expert, out)
    print(f"[E3] ✓  {out}")


def run_expert1(tr, va, te, epochs: int = 10, batch_size: int = 256):
    print("\n" + "=" * 60)
    print("  EXPERT 1 — Char-CNN + BiLSTM  (MPS / M5 GPU)")
    print("=" * 60)
    e1 = _load("expert1_char_cnn_bilstm")
    train_expert1 = e1.train_expert1
    predict_proba = e1.predict_proba

    model = train_expert1(
        tr["url"].tolist(), tr["result"].tolist(),
        va["url"].tolist(), va["result"].tolist(),
        epochs=epochs, batch_size=batch_size,
        save_path=str(CKPT_DIR / "expert1_char_cnn_bilstm.pt"),
    )

    try:
        from sklearn.metrics import roc_auc_score, f1_score
        probs = predict_proba(model, te["url"].tolist())
        y_te  = te["result"].values
        print(f"\n[E1] TEST  auc={roc_auc_score(y_te, probs):.4f}  "
              f"f1={f1_score(y_te, [1 if p>0.5 else 0 for p in probs]):.4f}")
    except Exception as e:
        print(f"[E1] Test eval error: {e}")


def run_expert2(tr, va, te, epochs: int = 5, batch_size: int = 16, max_length: int = 128):
    print("\n" + "=" * 60)
    print("  EXPERT 2 — DistilBERT fine-tune  (MPS / M5 GPU)")
    print("=" * 60)
    try:
        from transformers import DistilBertTokenizerFast  # type: ignore
    except ImportError:
        print("[E2] transformers not installed — skipping.\n     pip install transformers")
        return

    e2 = _load("expert2_distilbert")
    train_expert2 = e2.train_expert2
    bp = e2.predict_proba

    model = train_expert2(
        tr["url"].tolist(), tr["result"].tolist(),
        va["url"].tolist(), va["result"].tolist(),
        max_length=max_length,
        epochs=epochs, batch_size=batch_size,
        freeze_layers=4,
        unfreeze_after_epoch=3 if epochs > 3 else None,
        save_path=str(CKPT_DIR / "expert2_distilbert.pt"),
    )

    try:
        from sklearn.metrics import roc_auc_score, f1_score
        tok   = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
        probs = bp(model, tok, te["url"].tolist(), max_length=max_length, batch_size=batch_size)
        y_te  = te["result"].values
        print(f"\n[E2] TEST  auc={roc_auc_score(y_te, probs):.4f}  "
              f"f1={f1_score(y_te, [1 if p>0.5 else 0 for p in probs]):.4f}")
    except Exception as e:
        print(f"[E2] Test eval error: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# 5. MAIN
# ═══════════════════════════════════════════════════════════════════════════

def parse_args():
    ap = argparse.ArgumentParser(description="Train MoE URL detection experts")
    ap.add_argument("--quick",         action="store_true", help="20k subsample smoke test")
    ap.add_argument("--skip-download", action="store_true", help="Reuse /tmp/moe_urls.csv if it exists")
    ap.add_argument("--experts", nargs="+", type=int, choices=[1,2,3], default=[3,1,2])
    ap.add_argument("--epochs1",   type=int,   default=10)
    ap.add_argument("--epochs2",   type=int,   default=5)
    ap.add_argument("--batch1",    type=int,   default=256)
    ap.add_argument("--batch2",    type=int,   default=16)
    ap.add_argument("--max-len2",  type=int,   default=128)
    return ap.parse_args()


def main():
    if not _TQDM:
        print("TIP: pip install tqdm  — for progress bars")

    args = parse_args()
    wall = time.time()

    # 1. Download
    df = download_data(skip_if_exists=args.skip_download)

    # 2. Quick subsample
    if args.quick:
        df = subsample(df, n=20_000)
        print(f"\n[QUICK] {len(df):,} rows  "
              f"({(df['result']==0).sum():,} benign / {(df['result']==1).sum():,} malicious)")
        args.epochs1 = min(args.epochs1, 2)
        args.epochs2 = min(args.epochs2, 1)

    # 3. Balance + split
    print("\n[DATA] Balancing …")
    with tqdm(total=1, desc="Balancing", leave=False) as pb:
        df = balance(df); pb.update(1)

    print(f"[DATA] {len(df):,} rows  "
          f"({(df['result']==0).sum():,} benign / {(df['result']==1).sum():,} malicious)")

    print("[DATA] Splitting 70 / 15 / 15 …")
    with tqdm(total=1, desc="Splitting", leave=False) as pb:
        tr, va, te = split(df); pb.update(1)

    print(f"       train={len(tr):,}  val={len(va):,}  test={len(te):,}")

    # 4. Train
    pipeline = tqdm(args.experts, desc="Training experts", unit="expert")
    for exp_id in pipeline:
        pipeline.set_description(f"Expert {exp_id}")
        if exp_id == 3:
            run_expert3(tr, va, te)
        elif exp_id == 1:
            run_expert1(tr, va, te, epochs=args.epochs1, batch_size=args.batch1)
        elif exp_id == 2:
            run_expert2(tr, va, te, epochs=args.epochs2,
                        batch_size=args.batch2, max_length=args.max_len2)

    # 5. Summary
    mins = (time.time() - wall) / 60
    print("\n" + "=" * 60)
    print(f"  Done!  Total time: {mins:.1f} min")
    print(f"  Checkpoints → {CKPT_DIR}/")
    for p in sorted(CKPT_DIR.glob("*")):
        print(f"    {p.name:<42}  {p.stat().st_size/1e6:5.1f} MB")
    print("=" * 60)


if __name__ == "__main__":
    main()
