#!/usr/bin/env python3
"""
============================================================
  Real-Data URL Dataset Downloader & Merger
============================================================
Downloads from all publicly accessible sources:
  1.  Tranco Top-1M           → benign (1 000 000)
  2.  PhishTank live feed     → phishing  (~30-80 k)
  3.  OpenPhish community     → phishing  (~10 k)
  4.  URLhaus (text list)     → malware   (~100 k)
  5.  GitHub: Malicious URL dataset (sgmyo-ankara, 1.2M)
  6.  GitHub: Malicious URL dataset (faizann24 mirror)
  7.  GitHub: ISCX-URL mirrors / others
  8.  Phishing.Database (mitchellkrogza, GitHub)
  9.  StopForumSpam           → spam URLs
 10.  Emerging Threats / Abuse.ch plain lists
 11.  URLTeam / short-URL lists (bit.ly, t.co, etc.)

Schema output (merged_urls.csv):
  url, label, result
  url  – the raw URL string
  label – benign / phishing / malware / spam / defacement
  result – 0 (benign) or 1 (malicious)
============================================================
"""

import os
import io
import sys
import time
import gzip
import zipfile
import requests
import pandas as pd
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
DATA_DIR   = SCRIPT_DIR.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
OUT_CSV    = DATA_DIR / "merged_urls.csv"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; MaliciousURLResearch/1.0; "
        "+https://github.com/research)"
    )
}

MAX_BENIGN   = 500_000   # cap Tranco so dataset stays balanced
MAX_MALICIOUS = None     # no cap on malicious — take everything

# ── Helpers ──────────────────────────────────────────────────────────────────

def get(url: str, timeout: int = 60, stream: bool = False) -> requests.Response | None:
    """GET with retries, returns None on failure."""
    for attempt in range(3):
        try:
            r = requests.get(url, headers=HEADERS, timeout=timeout, stream=stream)
            if r.status_code == 200:
                return r
            print(f"    HTTP {r.status_code} for {url}")
            time.sleep(2)
        except Exception as e:
            print(f"    Error (attempt {attempt+1}): {e}")
            time.sleep(3)
    return None


def make_df(urls, label: str, result: int) -> pd.DataFrame:
    """Build a tidy DataFrame from a list of URL strings."""
    clean = [u.strip() for u in urls if u and u.strip()]
    return pd.DataFrame({"url": clean, "label": label, "result": result})


def add_scheme(domain: str) -> str:
    """Convert bare domain → https URL."""
    d = domain.strip()
    if d.startswith("http://") or d.startswith("https://"):
        return d
    return "https://" + d


def log(msg: str):
    print(msg, flush=True)


# ═══════════════════════════════════════════════════════════════════════════
#  SOURCE DOWNLOADERS
# ═══════════════════════════════════════════════════════════════════════════

def fetch_tranco() -> pd.DataFrame:
    """
    Tranco Top-1M benign domains (CSV zip).
    https://tranco-list.eu/top-1m.csv.zip
    """
    log("\n[1/11] Tranco Top-1M benign domains …")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    r = get(url, timeout=120)
    if r is None:
        log("  ✗ Failed to download Tranco list")
        return pd.DataFrame()

    try:
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            name = z.namelist()[0]
            with z.open(name) as f:
                df_raw = pd.read_csv(f, header=None, names=["rank", "domain"])

        domains = df_raw["domain"].dropna().tolist()[:MAX_BENIGN]
        urls    = [add_scheme(d) for d in domains]
        df      = make_df(urls, "benign", 0)
        log(f"  ✓ {len(df):,} benign URLs from Tranco")
        return df
    except Exception as e:
        log(f"  ✗ Parse error: {e}")
        return pd.DataFrame()


def fetch_phishtank() -> pd.DataFrame:
    """
    PhishTank online-valid.csv — live phishing feed (hourly).
    No API key required for occasional downloads.
    """
    log("\n[2/11] PhishTank phishing feed …")
    url = "http://data.phishtank.com/data/online-valid.csv"
    r   = get(url, timeout=120)
    if r is None:
        # Try gzip version
        log("  Trying gzip version …")
        r = get("http://data.phishtank.com/data/online-valid.csv.gz", timeout=120)
        if r is None:
            log("  ✗ PhishTank unavailable")
            return pd.DataFrame()
        content = gzip.decompress(r.content)
        df_raw  = pd.read_csv(io.BytesIO(content))
    else:
        try:
            df_raw = pd.read_csv(io.StringIO(r.text))
        except Exception:
            content = gzip.decompress(r.content)
            df_raw  = pd.read_csv(io.BytesIO(content))

    if "url" not in df_raw.columns:
        log(f"  ✗ Unexpected columns: {df_raw.columns.tolist()}")
        return pd.DataFrame()

    df = make_df(df_raw["url"].dropna().tolist(), "phishing", 1)
    log(f"  ✓ {len(df):,} phishing URLs from PhishTank")
    return df


def fetch_openphish() -> pd.DataFrame:
    """OpenPhish community feed — plain text, one URL per line."""
    log("\n[3/11] OpenPhish community feed …")
    url = "https://openphish.com/feed.txt"
    r   = get(url, timeout=60)
    if r is None:
        log("  ✗ OpenPhish unavailable")
        return pd.DataFrame()

    lines = r.text.splitlines()
    df    = make_df(lines, "phishing", 1)
    log(f"  ✓ {len(df):,} phishing URLs from OpenPhish")
    return df


def fetch_urlhaus_text() -> pd.DataFrame:
    """
    URLhaus plain-text list of active malware URLs (no auth needed).
    https://urlhaus.abuse.ch/downloads/text/
    """
    log("\n[4/11] URLhaus active malware list …")
    url = "https://urlhaus.abuse.ch/downloads/text/"
    r   = get(url, timeout=120)
    if r is None:
        log("  ✗ URLhaus text list unavailable")
        return pd.DataFrame()

    lines = [l for l in r.text.splitlines() if l and not l.startswith("#")]
    df    = make_df(lines, "malware", 1)
    log(f"  ✓ {len(df):,} malware URLs from URLhaus")
    return df


def fetch_urlhaus_csv() -> pd.DataFrame:
    """
    URLhaus full CSV export (no auth — 90-day dump).
    https://urlhaus.abuse.ch/downloads/csv/
    """
    log("\n[4b] URLhaus CSV dump …")
    url = "https://urlhaus.abuse.ch/downloads/csv/"
    r   = get(url, timeout=180)
    if r is None:
        log("  ✗ URLhaus CSV unavailable")
        return pd.DataFrame()

    try:
        # File is a zip containing a csv
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            name = z.namelist()[0]
            with z.open(name) as f:
                # Skip comment lines that start with #
                lines = [l.decode("utf-8", errors="replace")
                         for l in f.readlines()
                         if not l.startswith(b"#")]
                content = "".join(lines)
                df_raw  = pd.read_csv(io.StringIO(content))
    except Exception:
        try:
            # Maybe it's a plain CSV (not zipped)
            lines   = [l for l in r.text.splitlines() if not l.startswith("#")]
            df_raw  = pd.read_csv(io.StringIO("\n".join(lines)))
        except Exception as e2:
            log(f"  ✗ Parse error: {e2}")
            return pd.DataFrame()

    # Normalise column names (URLhaus uses 'url' column)
    df_raw.columns = [c.strip().lower() for c in df_raw.columns]
    if "url" not in df_raw.columns:
        log(f"  ✗ No 'url' column, found: {df_raw.columns.tolist()}")
        return pd.DataFrame()

    df = make_df(df_raw["url"].dropna().tolist(), "malware", 1)
    log(f"  ✓ {len(df):,} malware URLs from URLhaus CSV")
    return df


def fetch_sgmyo_dataset() -> pd.DataFrame:
    """
    Malicious URL Dataset by sgmyo-ankara (1.25M URLs, GitHub).
    Phishing / malware / spam / benign, labelled.
    """
    log("\n[5/11] sgmyo-ankara 1.25M URL dataset …")

    # The repo has the data split across releases or raw files
    # Try the raw file (they keep it in /data/ folder)
    candidates = [
        "https://raw.githubusercontent.com/sgmyo-ankara/malicious-url-dataset/main/malicious_url_dataset.csv",
        "https://raw.githubusercontent.com/sgmyo-ankara/malicious-url-dataset/master/malicious_url_dataset.csv",
        "https://raw.githubusercontent.com/sgmyo-ankara/malicious-url-dataset/main/dataset/malicious_url_dataset.csv",
        "https://raw.githubusercontent.com/sgmyo-ankara/malicious-url-dataset/main/data/malicious_url_dataset.csv",
        "https://raw.githubusercontent.com/sgmyo-ankara/malicious-url-dataset/main/urls.csv",
    ]

    for url in candidates:
        r = get(url, timeout=300)
        if r and len(r.content) > 1000:
            break
    else:
        log("  ✗ sgmyo dataset not accessible via raw URLs")
        return pd.DataFrame()

    try:
        df_raw = pd.read_csv(io.StringIO(r.text))
        df_raw.columns = [c.strip().lower() for c in df_raw.columns]

        # Expected columns: url, type/label/category
        url_col  = next((c for c in df_raw.columns if "url" in c), None)
        lab_col  = next((c for c in df_raw.columns
                         if c in ("type", "label", "category", "class")), None)

        if url_col is None:
            log(f"  ✗ No URL column, found: {df_raw.columns.tolist()}")
            return pd.DataFrame()

        rows = []
        for _, row in df_raw.iterrows():
            url_val = str(row[url_col]).strip()
            if not url_val or url_val == "nan":
                continue
            lbl = str(row[lab_col]).strip().lower() if lab_col else "malicious"
            res = 0 if lbl == "benign" else 1
            rows.append({"url": url_val, "label": lbl, "result": res})

        df = pd.DataFrame(rows)
        log(f"  ✓ {len(df):,} URLs from sgmyo-ankara dataset")
        return df
    except Exception as e:
        log(f"  ✗ Parse error: {e}")
        return pd.DataFrame()


def fetch_faizann24() -> pd.DataFrame:
    """
    faizann24 / sid321axn Malicious URLs dataset (~650K URLs).
    Columns: url, type  (benign / defacement / phishing / malware)
    Mirror on GitHub releases or raw.
    """
    log("\n[6/11] faizann24 / malicious_phish dataset …")

    candidates = [
        # Direct GitHub raw (if repo has it committed with LFS or splits)
        "https://raw.githubusercontent.com/incertum/cyber-matrix-ai/master/Malicious-URL-Detection-Deep-Learning/data/url_data_mega_deep_learning.csv",
        # Alternative mirrors
        "https://raw.githubusercontent.com/Antimalwaredb/Malicious-URLs-Dataset/main/malicious_phish.csv",
        "https://raw.githubusercontent.com/Antimalwaredb/Malicious-URLs-Dataset/master/malicious_phish.csv",
        # Another common mirror
        "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/5.urldata.csv",
    ]

    for url in candidates:
        r = get(url, timeout=300)
        if r and len(r.content) > 10_000:
            log(f"  Source: {url}")
            break
    else:
        log("  ✗ faizann24 mirror not accessible")
        return pd.DataFrame()

    try:
        df_raw = pd.read_csv(io.StringIO(r.text))
        df_raw.columns = [c.strip().lower() for c in df_raw.columns]

        url_col = next((c for c in df_raw.columns if c in ("url", "urls")), None)
        typ_col = next((c for c in df_raw.columns
                        if c in ("type", "label", "category", "class", "result")), None)

        if url_col is None:
            log(f"  ✗ No URL column. Columns: {df_raw.columns.tolist()}")
            return pd.DataFrame()

        rows = []
        for _, row in df_raw.iterrows():
            u   = str(row[url_col]).strip()
            if not u or u == "nan":
                continue
            lbl = str(row[typ_col]).strip().lower() if typ_col else "unknown"
            if lbl in ("benign", "safe", "good", "0", "0.0"):
                res, lbl = 0, "benign"
            else:
                res = 1
                if lbl in ("bad", "1", "1.0", "unknown"):
                    lbl = "malicious"
            rows.append({"url": u, "label": lbl, "result": res})

        df = pd.DataFrame(rows)
        log(f"  ✓ {len(df):,} URLs from faizann24 mirror")
        return df
    except Exception as e:
        log(f"  ✗ Parse error: {e}")
        return pd.DataFrame()


def fetch_mitchellkrogza_phishing() -> pd.DataFrame:
    """
    mitchellkrogza/Phishing.Database — thousands of phishing domains (GitHub).
    """
    log("\n[8/11] mitchellkrogza Phishing.Database …")

    sources = [
        ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
         "phishing", 1),
        ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt",
         "phishing", 1),
    ]

    frames = []
    for url, label, result in sources:
        r = get(url, timeout=120)
        if r is None:
            continue
        lines = [l.strip() for l in r.text.splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        df = make_df(lines, label, result)
        frames.append(df)
        log(f"  ✓ {len(df):,} URLs from {url.split('/')[-1]}")

    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def fetch_stopforumspam() -> pd.DataFrame:
    """
    StopForumSpam — top 500 spam domains (no auth).
    """
    log("\n[9/11] StopForumSpam spam URLs …")
    url = "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt"
    r   = get(url, timeout=60)
    if r is None:
        log("  ✗ StopForumSpam unavailable")
        return pd.DataFrame()

    lines = [l.strip() for l in r.text.splitlines()
             if l.strip() and not l.startswith("#")]
    urls  = [add_scheme(d) for d in lines]
    df    = make_df(urls, "spam", 1)
    log(f"  ✓ {len(df):,} spam URLs from StopForumSpam")
    return df


def fetch_emerging_threats() -> pd.DataFrame:
    """
    Emerging Threats compromised IP/URL list (Proofpoint, open feed).
    """
    log("\n[10/11] Emerging Threats compromised hosts …")

    sources = [
        ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
         "malware", 1),
        ("https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/malicious.txt",
         "malware", 1),
    ]

    frames = []
    for url, label, result in sources:
        r = get(url, timeout=90)
        if r is None:
            continue
        lines = [l.strip() for l in r.text.splitlines()
                 if l.strip() and not l.startswith("#")]
        # These are IPs/domains — add scheme
        urls  = [add_scheme(l) for l in lines]
        df    = make_df(urls, label, result)
        frames.append(df)
        log(f"  ✓ {len(df):,} entries from {url.split('/')[-1]}")

    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def fetch_shorturl_blacklists() -> pd.DataFrame:
    """
    Curated short-URL / redirect blacklists from GitHub community projects.
    Covers bit.ly, t.co, tinyurl, goo.gl, ow.ly abuse lists.
    """
    log("\n[11/11] Short-URL & redirect blacklists …")

    sources = [
        # StevenBlack hosts list (malware/phishing domains)
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        # URLTeam (short URL redirect blacklist fragments kept by community)
        "https://raw.githubusercontent.com/nickelc/url-shortener-blacklist/master/blacklist.txt",
        # Phishing short URLs
        "https://raw.githubusercontent.com/BarracudaNetworks/PhishingOpenDataset/master/data/phishing_urls.csv",
        # Abuse.ch SSLBL (SSL cert-based malware URLs)
        "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        # Another common blacklist
        "https://raw.githubusercontent.com/desbma/referer-spam-domains-blacklist/master/spammers.txt",
    ]

    frames = []
    for url in sources:
        r = get(url, timeout=120)
        if r is None:
            continue

        fname = url.split("/")[-1]
        text  = r.text

        if fname == "hosts":
            # StevenBlack hosts format: "0.0.0.0 domain.com" or "# comment"
            lines = []
            for l in text.splitlines():
                l = l.strip()
                if l and not l.startswith("#"):
                    parts = l.split()
                    if len(parts) >= 2 and parts[0] == "0.0.0.0":
                        domain = parts[1]
                        if domain not in ("0.0.0.0", "localhost", "local",
                                          "broadcasthost", "ip6-localhost"):
                            lines.append(add_scheme(domain))
            df = make_df(lines, "malware", 1)

        elif fname.endswith(".csv"):
            try:
                df_raw  = pd.read_csv(io.StringIO(text))
                df_raw.columns = [c.strip().lower() for c in df_raw.columns]
                url_col = next((c for c in df_raw.columns
                                if "url" in c or c in ("domain", "host")), None)
                if url_col is None:
                    continue
                vals = df_raw[url_col].dropna().tolist()
                df   = make_df([str(v) for v in vals], "malware", 1)
            except Exception:
                continue

        else:
            # Plain domain/URL list
            lines = [l.strip() for l in text.splitlines()
                     if l.strip() and not l.strip().startswith("#")]
            urls2  = [add_scheme(l) if not l.startswith("http") else l
                      for l in lines]
            df     = make_df(urls2, "malware", 1)

        if len(df) > 0:
            frames.append(df)
            log(f"  ✓ {len(df):,} entries from {fname}")

    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def fetch_github_iscx_mirror() -> pd.DataFrame:
    """
    Community mirrors of ISCX-URL2016 dataset on GitHub.
    These tend to have the 5-class CSV: URL, label
    (benign, spam, phishing, malware, defacement)
    """
    log("\n[7/11] ISCX-URL2016 community mirrors …")

    candidates = [
        "https://raw.githubusercontent.com/Jerrold028/URL-Classification/main/data/url_data.csv",
        "https://raw.githubusercontent.com/abubakarq3/URL-based-Phishing-Detection/main/dataset/urls.csv",
        "https://raw.githubusercontent.com/bhavika1304/Malicious-URL-Detection/main/datasets/malicious_phish.csv",
        "https://raw.githubusercontent.com/saaeedeh/phishing-url-detection/main/data/dataset.csv",
        "https://raw.githubusercontent.com/lmanesh/Malicious-URL-Detection/main/data/malicious_phish.csv",
        "https://raw.githubusercontent.com/SindhuBabu/malicious-url-detection/main/malicious_phish.csv",
    ]

    frames = []
    for url in candidates:
        r = get(url, timeout=180)
        if r is None or len(r.content) < 5000:
            continue

        try:
            df_raw = pd.read_csv(io.StringIO(r.text))
            df_raw.columns = [c.strip().lower() for c in df_raw.columns]

            url_col = next((c for c in df_raw.columns
                            if c in ("url", "urls")), None)
            typ_col = next((c for c in df_raw.columns
                            if c in ("type", "label", "category",
                                     "class", "result", "tag")), None)
            if url_col is None:
                continue

            rows = []
            for _, row in df_raw.iterrows():
                u   = str(row[url_col]).strip()
                if not u or u in ("nan", "url"):
                    continue
                lbl = str(row[typ_col]).strip().lower() if typ_col else "malicious"
                if lbl in ("benign", "safe", "good", "legitimate", "0", "0.0"):
                    res, lbl = 0, "benign"
                else:
                    res = 1
                rows.append({"url": u, "label": lbl, "result": res})

            df = pd.DataFrame(rows)
            if len(df) > 100:
                frames.append(df)
                log(f"  ✓ {len(df):,} URLs from {url.split('/')[-2]}/{url.split('/')[-1]}")
        except Exception as e:
            log(f"    Parse error for {url}: {e}")
            continue

    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 62)
    print("  Malicious URL Dataset Downloader")
    print("=" * 62)
    print(f"  Output: {OUT_CSV}")
    print("=" * 62)

    all_frames = []

    # ── 1. Benign: Tranco ─────────────────────────────────────────────────
    df = fetch_tranco()
    if len(df) > 0:
        all_frames.append(df)

    # ── 2. Malicious: PhishTank ───────────────────────────────────────────
    df = fetch_phishtank()
    if len(df) > 0:
        all_frames.append(df)

    # ── 3. Malicious: OpenPhish ───────────────────────────────────────────
    df = fetch_openphish()
    if len(df) > 0:
        all_frames.append(df)

    # ── 4. Malicious: URLhaus text list ───────────────────────────────────
    df = fetch_urlhaus_text()
    if len(df) > 0:
        all_frames.append(df)

    # ── 4b. Malicious: URLhaus CSV ────────────────────────────────────────
    df = fetch_urlhaus_csv()
    if len(df) > 0:
        all_frames.append(df)

    # ── 5. Mixed: sgmyo-ankara 1.25M ─────────────────────────────────────
    df = fetch_sgmyo_dataset()
    if len(df) > 0:
        all_frames.append(df)

    # ── 6. Mixed: faizann24 mirror ────────────────────────────────────────
    df = fetch_faizann24()
    if len(df) > 0:
        all_frames.append(df)

    # ── 7. Mixed: ISCX-URL mirrors ───────────────────────────────────────
    df = fetch_github_iscx_mirror()
    if len(df) > 0:
        all_frames.append(df)

    # ── 8. Malicious: mitchellkrogza phishing DB ──────────────────────────
    df = fetch_mitchellkrogza_phishing()
    if len(df) > 0:
        all_frames.append(df)

    # ── 9. Malicious: StopForumSpam ───────────────────────────────────────
    df = fetch_stopforumspam()
    if len(df) > 0:
        all_frames.append(df)

    # ── 10. Malicious: Emerging Threats ───────────────────────────────────
    df = fetch_emerging_threats()
    if len(df) > 0:
        all_frames.append(df)

    # ── 11. Malicious: Short-URL blacklists ───────────────────────────────
    df = fetch_shorturl_blacklists()
    if len(df) > 0:
        all_frames.append(df)

    # ── Merge & clean ─────────────────────────────────────────────────────
    if not all_frames:
        print("\n✗ No data downloaded from any source!")
        sys.exit(1)

    print("\n" + "=" * 62)
    print("  Merging & deduplicating …")

    combined = pd.concat(all_frames, ignore_index=True)
    print(f"  Raw total: {len(combined):,}")

    # Drop null / empty URLs
    combined = combined[combined["url"].notna()]
    combined = combined[combined["url"].str.strip() != ""]
    combined["url"] = combined["url"].str.strip()

    # Remove obviously invalid rows
    combined = combined[combined["url"].str.len() >= 4]

    # Deduplicate: keep first occurrence (priority order = benign, then malicious)
    # Sort so malicious comes last so duplicates keep the malicious label
    combined = combined.sort_values("result", ascending=False)
    combined = combined.drop_duplicates(subset="url", keep="first")

    print(f"  After dedup: {len(combined):,}")

    # Stats
    n_benign    = (combined["result"] == 0).sum()
    n_malicious = (combined["result"] == 1).sum()
    print(f"\n  Label breakdown:")
    print(f"    Benign:    {n_benign:,} ({n_benign/len(combined)*100:.1f}%)")
    print(f"    Malicious: {n_malicious:,} ({n_malicious/len(combined)*100:.1f}%)")
    print(f"\n  By category:")
    print(combined["label"].value_counts().to_string())

    # Save
    combined = combined[["url", "label", "result"]].reset_index(drop=True)
    combined.to_csv(OUT_CSV, index=False)
    size_mb = OUT_CSV.stat().st_size / (1024 * 1024)
    print(f"\n  ✓ Saved → {OUT_CSV}")
    print(f"    Size:  {size_mb:.1f} MB")
    print(f"    Rows:  {len(combined):,}")

    # Also write a balanced version
    bal_path = DATA_DIR / "balanced_urls.csv"
    min_class = min(n_benign, n_malicious)
    if min_class > 0:
        ben = combined[combined["result"] == 0].sample(
            min(min_class, n_benign), random_state=42
        )
        mal = combined[combined["result"] == 1].sample(
            min(min_class, n_malicious), random_state=42
        )
        balanced = pd.concat([ben, mal]).sample(frac=1, random_state=42)
        balanced.to_csv(bal_path, index=False)
        print(f"\n  ✓ Balanced version → {bal_path}")
        print(f"    Rows:  {len(balanced):,} (50/50 split)")

    print("\n" + "=" * 62)
    print("  Done! Run train_model.py to start training.")
    print("=" * 62)


if __name__ == "__main__":
    main()
