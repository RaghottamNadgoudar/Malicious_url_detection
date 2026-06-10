"""
Train the Neural Network Model
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Dataset  : balanced_urls.csv  (50/50 benign/malicious, ~995K URLs)
Features :
  • Live progress printed every 500 URLs (with ETA)
  • Checkpoint saved every 10 000 URLs → resumes after any stop
  • Training metrics streamed to terminal every epoch
  • Confusion matrix + training history plots saved to models/
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import sys
import time
import signal

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import matplotlib
matplotlib.use("Agg")          # headless – no display needed
import matplotlib.pyplot as plt
import seaborn as sns

from phase1_graph_traversal import RedirectGraphAnalyzer
from phase3_neural_classifier import extract_features, NeuralClassifier

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR      = os.path.dirname(os.path.abspath(__file__))
DATA_DIR        = os.path.join(SCRIPT_DIR, "..", "data")
MODEL_DIR       = os.path.join(SCRIPT_DIR, "models")
CKPT_FEATURES   = os.path.join(MODEL_DIR, "features_checkpoint.npz")
CKPT_META       = os.path.join(MODEL_DIR, "features_checkpoint_meta.txt")
FEATURES_CACHE  = os.path.join(MODEL_DIR, "features_cache.npz")   # full extracted features

os.makedirs(MODEL_DIR, exist_ok=True)

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def cprint(colour, msg):
    print(f"{colour}{msg}{RESET}", flush=True)

def bar(done, total, width=40):
    pct    = done / max(total, 1)
    filled = int(pct * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {pct*100:5.1f}%"


# ── Graceful shutdown ─────────────────────────────────────────────────────────
_interrupted = False

def _sigint(sig, frame):
    global _interrupted
    _interrupted = True
    print(f"\n{YELLOW}⚠  Ctrl+C received — finishing current batch then saving checkpoint …{RESET}",
          flush=True)

signal.signal(signal.SIGINT, _sigint)


# ═════════════════════════════════════════════════════════════════════════════
#  1.  LOAD DATA
# ═════════════════════════════════════════════════════════════════════════════

def load_data(data_path=None):
    """Load the balanced dataset (50/50 split)."""
    candidates = [data_path] if data_path else []
    candidates += [
        os.path.join(DATA_DIR, "balanced_urls.csv"),
        os.path.join(DATA_DIR, "merged_urls.csv"),
    ]

    df = None
    for path in candidates:
        if path and os.path.exists(path):
            cprint(CYAN, f"  Loading {path} …")
            df = pd.read_csv(path)
            break

    if df is None:
        raise FileNotFoundError(
            f"No dataset found. Tried: {candidates}\n"
            "Run download_datasets.py first."
        )

    n_ben = (df["result"] == 0).sum()
    n_mal = (df["result"] == 1).sum()
    cprint(GREEN, f"  ✓ Loaded {len(df):,} URLs")
    print(f"    Benign:    {n_ben:,}  ({n_ben/len(df)*100:.1f}%)")
    print(f"    Malicious: {n_mal:,}  ({n_mal/len(df)*100:.1f}%)")
    return df


# ═════════════════════════════════════════════════════════════════════════════
#  2.  FEATURE EXTRACTION  (with checkpoint + live progress)
# ═════════════════════════════════════════════════════════════════════════════

CHECKPOINT_EVERY = 10_000   # save partial results every N URLs
PRINT_EVERY      =    500   # print progress line every N URLs


def _load_checkpoint():
    """Return (features_list, labels, start_idx) from disk, or empty."""
    if os.path.exists(CKPT_FEATURES) and os.path.exists(CKPT_META):
        try:
            data   = np.load(CKPT_FEATURES)
            X_ckpt = data["X"].tolist()
            y_ckpt = data["y"].tolist()
            with open(CKPT_META) as f:
                start = int(f.read().strip())
            cprint(YELLOW,
                   f"  ↩  Resuming from checkpoint: {start:,} URLs already processed")
            return X_ckpt, y_ckpt, start
        except Exception as e:
            cprint(RED, f"  Checkpoint corrupt ({e}) — starting fresh")
    return [], [], 0


def _save_checkpoint(X_list, y_list, idx):
    np.savez_compressed(CKPT_FEATURES,
                        X=np.array(X_list, dtype=np.float32),
                        y=np.array(y_list, dtype=np.int8))
    with open(CKPT_META, "w") as f:
        f.write(str(idx))


def extract_all_features(df):
    global _interrupted

    cprint(BOLD, "\n  Initialising graph analyser …")
    graph_analyzer = RedirectGraphAnalyzer()
    sample_urls = df["url"].tolist()[:min(10_000, len(df))]
    graph_analyzer.build_graph(sample_urls)
    cprint(GREEN, f"  ✓ Redirect graph built ({len(graph_analyzer.graph)} nodes)")

    all_urls   = df["url"].tolist()
    all_labels = df["result"].tolist()
    total      = len(all_urls)

    # ── Resume from checkpoint if available ──────────────────────────────────
    features_list, labels, start_idx = _load_checkpoint()

    if start_idx >= total:
        cprint(GREEN, f"  ✓ All {total:,} URLs already in checkpoint — skipping extraction")
        return np.array(features_list, dtype=np.float32), np.array(labels, dtype=np.int8)

    cprint(CYAN, f"\n  Processing {total - start_idx:,} URLs "
                 f"(starting at {start_idx:,} / {total:,}) …\n")

    t_start = time.time()
    errors  = 0

    for idx in range(start_idx, total):
        if _interrupted:
            cprint(YELLOW, f"\n  Saving checkpoint at URL {idx:,} …")
            _save_checkpoint(features_list, labels, idx)
            cprint(GREEN, f"  ✓ Checkpoint saved. Re-run train_model.py to resume.")
            sys.exit(0)

        url   = all_urls[idx]
        label = all_labels[idx]

        try:
            phase1 = graph_analyzer.analyze_url(url)
            feat   = extract_features(url, phase1)
            features_list.append(feat)
            labels.append(label)
        except Exception:
            errors += 1
            continue

        done    = idx - start_idx + 1
        elapsed = time.time() - t_start

        # ── Live progress line ───────────────────────────────────────────────
        if done % PRINT_EVERY == 0 or idx == total - 1:
            speed   = done / max(elapsed, 1)
            remain  = (total - idx - 1) / max(speed, 1)
            eta_min = int(remain // 60)
            eta_sec = int(remain % 60)
            overall_done = idx + 1
            print(
                f"\r  {bar(overall_done, total)}  "
                f"{overall_done:>7,}/{total:,}  "
                f"{speed:>6.0f} URL/s  "
                f"ETA {eta_min:02d}:{eta_sec:02d}  "
                f"errors={errors}",
                end="", flush=True
            )

        # ── Periodic checkpoint ──────────────────────────────────────────────
        if done % CHECKPOINT_EVERY == 0:
            print()   # newline before status
            cprint(YELLOW, f"  💾 Checkpoint saved @ {idx+1:,} URLs …")
            _save_checkpoint(features_list, labels, idx + 1)

    print()   # final newline after progress bar

    # ── Clean up checkpoint files after full completion ──────────────────────
    for f in (CKPT_FEATURES, CKPT_META):
        if os.path.exists(f):
            os.remove(f)

    X = np.array(features_list, dtype=np.float32)
    y = np.array(labels,        dtype=np.int8)
    elapsed = time.time() - t_start
    cprint(GREEN, f"\n  ✓ Feature extraction complete!")
    print(f"    URLs processed : {len(X):,}")
    print(f"    Errors skipped : {errors:,}")
    print(f"    Time taken     : {int(elapsed//60)}m {int(elapsed%60)}s")
    print(f"    Feature shape  : {X.shape}")
    return X, y


# ═════════════════════════════════════════════════════════════════════════════
#  3.  TRAIN + EVALUATE
# ═════════════════════════════════════════════════════════════════════════════

def train_and_evaluate(X, y):
    cprint(BOLD, "\n" + "=" * 60)
    cprint(BOLD, "  Training Neural Network  (balanced 50/50 dataset)")
    cprint(BOLD, "=" * 60)

    # 70 / 15 / 15 split
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.176, random_state=42, stratify=y_temp
    )

    print(f"\n  Dataset split:")
    print(f"    Train : {len(X_train):,}  (benign={int((y_train==0).sum()):,} / malicious={int((y_train==1).sum()):,})")
    print(f"    Val   : {len(X_val):,}")
    print(f"    Test  : {len(X_test):,}")

    model_path = os.path.join(MODEL_DIR, "url_classifier.h5")
    classifier = NeuralClassifier(model_path=model_path)

    print(f"\n  Training … (epochs=50, batch=512, early-stop on val_auc)\n")
    t0 = time.time()
    history = classifier.train(
        X_train, y_train,
        X_val,   y_val,
        epochs=50,
        batch_size=512,
    )
    elapsed = time.time() - t0
    cprint(GREEN, f"\n  ✓ Training finished in {int(elapsed//60)}m {int(elapsed%60)}s")

    # ── Evaluation ──────────────────────────────────────────────────────────
    cprint(BOLD, "\n" + "=" * 60)
    cprint(BOLD, "  Evaluation on Test Set")
    cprint(BOLD, "=" * 60)

    print(f"\n  Running inference on {len(X_test):,} test URLs …", flush=True)
    y_pred_prob = []
    batch_size  = 2000
    t_inf = time.time()
    for i in range(0, len(X_test), batch_size):
        batch = X_test[i:i + batch_size]
        preds = [classifier.classifier.predict(x) for x in batch]
        y_pred_prob.extend(preds)
        done = min(i + batch_size, len(X_test))
        print(f"\r  {bar(done, len(X_test))}  {done:,}/{len(X_test):,}", end="", flush=True)
    print()

    y_pred_prob = np.array(y_pred_prob)
    y_pred      = (y_pred_prob > 0.5).astype(int)

    print(f"\n{BOLD}  Classification Report:{RESET}")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    auc = roc_auc_score(y_test, y_pred_prob)
    cprint(GREEN, f"  AUC-ROC Score : {auc:.4f}")

    # ── Confusion matrix plot ─────────────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Benign", "Malicious"],
                yticklabels=["Benign", "Malicious"])
    plt.title("Confusion Matrix")
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    cm_path = os.path.join(MODEL_DIR, "confusion_matrix.png")
    plt.savefig(cm_path)
    plt.close()
    cprint(GREEN, f"  ✓ Confusion matrix → {cm_path}")

    # ── Training history plot ─────────────────────────────────────────────────
    if hasattr(history, "history"):
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        ax1.plot(history.history["accuracy"],     label="Train")
        ax1.plot(history.history["val_accuracy"], label="Val")
        ax1.set_title("Model Accuracy");  ax1.set_xlabel("Epoch")
        ax1.set_ylabel("Accuracy");       ax1.legend();  ax1.grid(True)

        ax2.plot(history.history["loss"],     label="Train")
        ax2.plot(history.history["val_loss"], label="Val")
        ax2.set_title("Model Loss");  ax2.set_xlabel("Epoch")
        ax2.set_ylabel("Loss");       ax2.legend();  ax2.grid(True)

        plt.tight_layout()
        hist_path = os.path.join(MODEL_DIR, "training_history.png")
        plt.savefig(hist_path)
        plt.close()
        cprint(GREEN, f"  ✓ Training history → {hist_path}")

    return classifier, history, auc


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    cprint(BOLD, "\n" + "=" * 60)
    cprint(BOLD, "  URL Detection Model Training")
    cprint(BOLD, "=" * 60)

    # ── 1. Load data ──────────────────────────────────────────────────────────
    cprint(BOLD, "\n[1/4] Loading dataset …")
    balanced_path = os.path.join(DATA_DIR, "balanced_urls.csv")
    df = load_data(data_path=balanced_path)   # 50/50 split, ~995K URLs

    # ── 2. Feature extraction ─────────────────────────────────────────────────
    cprint(BOLD, "\n[2/4] Extracting features …")

    # Load cached features if they exist and match current dataset
    if os.path.exists(FEATURES_CACHE):
        try:
            cached   = np.load(FEATURES_CACHE)
            X_cached = cached["X"]
            y_cached = cached["y"]
            if len(X_cached) == len(df):
                cprint(GREEN, f"  ✓ Loaded cached features ({len(X_cached):,} URLs) — skipping extraction")
                cprint(YELLOW, f"    Delete {FEATURES_CACHE} to force re-extraction")
                X, y = X_cached, y_cached
            else:
                cprint(YELLOW, f"  Cache size mismatch ({len(X_cached):,} vs {len(df):,}) — re-extracting")
                raise ValueError("size mismatch")
        except Exception:
            print(f"  Checkpoint: {CKPT_FEATURES}")
            print(f"  (Saves every {CHECKPOINT_EVERY:,} URLs — safe to Ctrl+C and resume)\n")
            X, y = extract_all_features(df)
            np.savez_compressed(FEATURES_CACHE, X=X, y=y)
            cprint(GREEN, f"  ✓ Features cached → {FEATURES_CACHE}")
    else:
        print(f"  Checkpoint: {CKPT_FEATURES}")
        print(f"  (Saves every {CHECKPOINT_EVERY:,} URLs — safe to Ctrl+C and resume)\n")
        X, y = extract_all_features(df)
        np.savez_compressed(FEATURES_CACHE, X=X, y=y)
        cprint(GREEN, f"  ✓ Features cached → {FEATURES_CACHE}")

    # ── 3. Train ──────────────────────────────────────────────────────────────
    cprint(BOLD, "\n[3/4] Training neural network …")
    classifier, history, auc = train_and_evaluate(X, y)

    # ── 4. Done ───────────────────────────────────────────────────────────────
    cprint(BOLD, "\n[4/4] Complete!")
    cprint(BOLD, "\n" + "=" * 60)
    cprint(GREEN, "  ✓ Training Complete!")
    print(f"    Final AUC-ROC : {auc:.4f}")
    print(f"    Model saved   : models/url_classifier.h5")
    cprint(BOLD, "=" * 60)
    print("\n  Start the server:")
    cprint(CYAN, "    python3 app.py")
    cprint(BOLD, "=" * 60 + "\n")
