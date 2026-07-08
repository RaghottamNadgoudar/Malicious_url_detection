"""
Expert 3: Gradient Boosted Machine on 25 engineered URL features.
Uses LightGBM (preferred) with XGBoost as fallback.

Catches structural / statistical signals that deep models sometimes miss:
  entropy, TLD reputation, redirect depth, digit ratios, brand distance, etc.

Apple Silicon (M5 Air) notes
----------------------------
LightGBM does NOT expose an MPS/Metal backend — its "GPU" mode uses CUDA
(NVIDIA) or OpenCL (discontinued in recent builds).  On Apple Silicon the
correct strategy is:

  1. Use LightGBM on CPU  — it is already highly parallel via OpenMP and
     will saturate all efficiency + performance cores on the M5.
     For 650 k rows × 25 features training typically completes in < 5 min.

  2. Set n_jobs = -1  (use all logical CPUs) and
     device_type = "cpu"  explicitly so LightGBM does not try OpenCL.

  3. Optionally set num_threads to os.cpu_count() for deterministic threading.

XGBoost *does* have an experimental Metal backend via `device="mps"` in
recent builds (≥ 2.0), so the XGBoost fallback attempts it with a safe
CPU fallback.

PyTorch / MPS is NOT used in this expert (GBMs are not PyTorch models),
but the `get_device()` helper is kept for consistency with Experts 1 & 2
and is used in the smoke-test to show the full system's active backend.

Algorithm tie-ins (DAA syllabus)
---------------------------------
Expert 3 IS a decision-tree ensemble (Unit V — Decision Trees).
The GBM training loop is a greedy stage-wise additive model (Unit IV — Greedy).
Feature importance ranking uses a merge-sort-based argsort (Unit II — Sorting).
Boyer-Moore keyword scanning feeds feature[20] (keyword_score, Unit III).
"""

from __future__ import annotations

import os
import json
import math
from pathlib import Path

import numpy as np

try:
    import lightgbm as lgb
    _LGB = True
except ImportError:
    _LGB = False

try:
    import xgboost as xgb
    _XGB = True
except ImportError:
    _XGB = False

try:
    from sklearn.metrics import roc_auc_score, f1_score, classification_report
    from sklearn.model_selection import StratifiedKFold
    _SKLEARN = True
except ImportError:
    _SKLEARN = False


# ---------------------------------------------------------------------------
# Device helper (for reporting / consistency; GBM itself doesn't use MPS)
# ---------------------------------------------------------------------------

def get_device() -> str:
    """
    Returns 'mps', 'cuda', or 'cpu' as a string.
    GBM experts use CPU, but this is surfaced in logs for visibility.
    """
    try:
        import torch
        if torch.backends.mps.is_available():
            return "mps"
        if torch.cuda.is_available():
            return "cuda"
    except ImportError:
        pass
    return "cpu"


# ---------------------------------------------------------------------------
# Feature names (must match phase3_neural_classifier.py / expert1 pipeline)
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    # Structural
    "url_length",           # 0
    "domain_length",        # 1
    "subdomain_depth",      # 2
    "path_depth",           # 3
    "query_length",         # 4
    "num_query_params",     # 5
    # Character-level
    "dot_count",            # 6
    "hyphen_count",         # 7
    "digit_ratio",          # 8
    "uppercase_ratio",      # 9
    "special_char_ratio",   # 10
    # Entropy
    "url_entropy",          # 11
    "domain_entropy",       # 12
    # Protocol / TLD
    "has_https",            # 13
    "tld_suspicion",        # 14
    # IP / obfuscation
    "has_ip",               # 15
    "has_at_symbol",        # 16
    "double_slash_path",    # 17
    "has_suspicious_port",  # 18
    # Redirect / graph
    "redirect_depth",       # 19
    # Semantic / phishing
    "keyword_score",        # 20
    "brand_in_subdomain",   # 21
    "has_homograph",        # 22
    # Domain age proxy
    "domain_age_proxy",     # 23
    # Redirect chain
    "chain_length",         # 24
]

N_FEATURES = len(FEATURE_NAMES)  # 25


# ---------------------------------------------------------------------------
# LightGBM expert
# ---------------------------------------------------------------------------

def _lgb_params(n_jobs: int) -> dict:
    """
    LightGBM hyperparameters tuned for M5 Air (CPU, high-bandwidth memory).

    Key M5 choices:
      device_type = "cpu"      — no Metal/OpenCL on Apple Silicon
      num_threads = n_jobs     — saturate all P+E cores
      max_bin     = 255        — default; increase to 511 for tiny datasets
      num_leaves  = 63         — moderate complexity, fast
      min_child_samples = 20   — prevents tiny leaves on skewed datasets
    """
    return {
        "objective":         "binary",
        "metric":            ["binary_logloss", "auc"],
        "boosting_type":     "gbdt",
        "device_type":       "cpu",          # explicit — no MPS/OpenCL attempt
        "num_threads":       n_jobs,
        "num_leaves":        63,
        "max_depth":         -1,
        "learning_rate":     0.05,
        "n_estimators":      1000,           # early stopping limits this
        "min_child_samples": 20,
        "feature_fraction":  0.8,
        "bagging_fraction":  0.8,
        "bagging_freq":      5,
        "reg_alpha":         0.1,
        "reg_lambda":        0.1,
        "verbose":           -1,
        "seed":              42,
    }


class LGBExpert:
    """LightGBM wrapper with early-stopping and feature importance logging."""

    def __init__(self, n_jobs: int = -1):
        if not _LGB:
            raise ImportError("Install LightGBM: pip install lightgbm")
        self.n_jobs    = os.cpu_count() if n_jobs == -1 else n_jobs
        self.params    = _lgb_params(self.n_jobs)
        self.model: lgb.Booster | None = None
        self.threshold = 0.5

    # ------------------------------------------------------------------
    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val:   np.ndarray,
        y_val:   np.ndarray,
        early_stopping_rounds: int = 50,
        verbose_eval: int = 100,
    ) -> "LGBExpert":
        print(
            f"[Expert 3 LGB] training on CPU ({self.n_jobs} threads)  "
            f"[system device: {get_device()}]"
        )
        dtrain = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_NAMES)
        dval   = lgb.Dataset(X_val,   label=y_val,   reference=dtrain)

        callbacks = [
            lgb.early_stopping(early_stopping_rounds, verbose=True),
            lgb.log_evaluation(verbose_eval),
        ]

        self.model = lgb.train(
            self.params,
            dtrain,
            valid_sets=[dtrain, dval],
            valid_names=["train", "val"],
            callbacks=callbacks,
        )

        # ── Evaluation ──────────────────────────────────────────────────
        val_probs = self.model.predict(X_val)
        if _SKLEARN:
            auc = roc_auc_score(y_val, val_probs)
            f1  = f1_score(y_val, (val_probs > self.threshold).astype(int))
            print(f"[Expert 3 LGB] val_auc={auc:.4f}  val_f1={f1:.4f}")
            print(classification_report(
                y_val, (val_probs > self.threshold).astype(int),
                target_names=["benign", "malicious"],
            ))

        # ── Feature importance (DAA: merge-sort-based ranking) ──────────
        self._log_feature_importance()
        return self

    def _log_feature_importance(self) -> None:
        assert self.model is not None
        imp = self.model.feature_importance(importance_type="gain")
        # argsort is internally a merge-sort variant — Unit II tie-in
        ranked = sorted(zip(FEATURE_NAMES, imp), key=lambda x: -x[1])
        print("\n[Expert 3 LGB] Feature importance (gain, top-15):")
        for name, score in ranked[:15]:
            bar = "█" * int(score / max(imp) * 30) if max(imp) > 0 else ""
            print(f"  {name:<22}  {score:8.1f}  {bar}")

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        assert self.model is not None, "Model not trained yet. Call fit() first."
        return self.model.predict(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X) > self.threshold).astype(int)


# ---------------------------------------------------------------------------
# XGBoost expert (fallback / alternative)
# ---------------------------------------------------------------------------

def _xgb_device() -> str:
    """
    XGBoost ≥ 2.0 supports device='cuda' and experimentally device='mps'.
    We try MPS first on Apple Silicon, fall back to CPU on failure.
    """
    try:
        import xgboost as _xgb
        import torch
        if torch.backends.mps.is_available():
            # Quick probe — create a tiny DMatrix and train one round on MPS
            _probe = _xgb.DMatrix(np.zeros((4, 2)), label=np.array([0, 1, 0, 1]))
            _xgb.train({"device": "mps", "tree_method": "hist"}, _probe, num_boost_round=1)
            return "mps"
    except Exception:
        pass
    return "cpu"


class XGBExpert:
    """XGBoost wrapper — attempts Metal (MPS) on Apple Silicon, CPU fallback."""

    def __init__(self):
        if not _XGB:
            raise ImportError("Install XGBoost: pip install xgboost")
        self._device   = _xgb_device()
        self.model: xgb.Booster | None = None
        self.threshold = 0.5
        print(f"[Expert 3 XGB] will use device='{self._device}'")

    def _params(self) -> dict:
        return {
            "objective":        "binary:logistic",
            "eval_metric":      ["logloss", "auc"],
            "device":           self._device,
            "tree_method":      "hist",
            "max_depth":        6,
            "eta":              0.05,
            "subsample":        0.8,
            "colsample_bytree": 0.8,
            "min_child_weight": 20,
            "alpha":            0.1,
            "lambda":           0.1,
            "seed":             42,
        }

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val:   np.ndarray,
        y_val:   np.ndarray,
        num_boost_round: int = 1000,
        early_stopping_rounds: int = 50,
    ) -> "XGBExpert":
        print(
            f"[Expert 3 XGB] training on device='{self._device}'  "
            f"[system device: {get_device()}]"
        )
        dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=FEATURE_NAMES)
        dval   = xgb.DMatrix(X_val,   label=y_val,   feature_names=FEATURE_NAMES)

        self.model = xgb.train(
            self._params(),
            dtrain,
            num_boost_round=num_boost_round,
            evals=[(dtrain, "train"), (dval, "val")],
            early_stopping_rounds=early_stopping_rounds,
            verbose_eval=100,
        )

        val_probs = self.model.predict(dval)
        if _SKLEARN:
            auc = roc_auc_score(y_val, val_probs)
            f1  = f1_score(y_val, (val_probs > self.threshold).astype(int))
            print(f"[Expert 3 XGB] val_auc={auc:.4f}  val_f1={f1:.4f}")
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        assert self.model is not None
        dmat = xgb.DMatrix(X, feature_names=FEATURE_NAMES)
        return self.model.predict(dmat)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X) > self.threshold).astype(int)


# ---------------------------------------------------------------------------
# Unified Expert 3 class (picks LGB → XGB → heuristic fallback)
# ---------------------------------------------------------------------------

class GBMExpert:
    """
    Public API for Expert 3.

    Priority order: LightGBM → XGBoost → raises with clear message.
    LightGBM is preferred on M5 Air because:
      - Leaf-wise tree growth converges faster than XGBoost's level-wise
      - Lower memory footprint per tree (important for 16 GB unified memory)
      - More mature Apple Silicon CPU optimisations (OpenMP vs XGBoost's OMP)
    """

    def __init__(self, backend: str = "auto"):
        """
        Args:
            backend: 'lgb', 'xgb', or 'auto' (tries lgb first, then xgb).
        """
        if backend == "lgb" or (backend == "auto" and _LGB):
            self._impl = LGBExpert()
            self._backend = "lgb"
        elif backend == "xgb" or (backend == "auto" and _XGB):
            self._impl = XGBExpert()
            self._backend = "xgb"
        else:
            raise ImportError(
                "Neither LightGBM nor XGBoost is installed.\n"
                "Install one of:\n"
                "  pip install lightgbm\n"
                "  pip install xgboost"
            )
        print(f"[Expert 3] using backend: {self._backend}")

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val:   np.ndarray,
        y_val:   np.ndarray,
        **kwargs,
    ) -> "GBMExpert":
        self._impl.fit(X_train, y_train, X_val, y_val, **kwargs)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return P(malicious) array of shape (n,)."""
        return self._impl.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self._impl.predict(X)


# ---------------------------------------------------------------------------
# Cross-validated out-of-fold predictions (for meta-learner stacking)
# ---------------------------------------------------------------------------

def cross_val_oof_proba(
    X: np.ndarray,
    y: np.ndarray,
    n_splits: int = 5,
    backend: str = "auto",
) -> np.ndarray:
    """
    Generate out-of-fold P(malicious) predictions via stratified K-fold.

    These are used as inputs to the meta-learner (stacking layer) so the
    meta-learner never trains on in-fold predictions, preventing leakage.

    Returns:
        oof_probs: np.ndarray of shape (n_samples,)
    """
    if not _SKLEARN:
        raise ImportError("scikit-learn required: pip install scikit-learn")

    oof = np.zeros(len(y), dtype=np.float32)
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    for fold, (tr_idx, va_idx) in enumerate(skf.split(X, y)):
        print(f"\n[Expert 3 OOF] fold {fold+1}/{n_splits}")
        expert = GBMExpert(backend=backend)
        expert.fit(X[tr_idx], y[tr_idx], X[va_idx], y[va_idx])
        oof[va_idx] = expert.predict_proba(X[va_idx]).astype(np.float32)

    if _SKLEARN:
        oof_auc = roc_auc_score(y, oof)
        oof_f1  = f1_score(y, (oof > 0.5).astype(int))
        print(f"\n[Expert 3 OOF] overall  auc={oof_auc:.4f}  f1={oof_f1:.4f}")

    return oof


# ---------------------------------------------------------------------------
# Save / Load
# ---------------------------------------------------------------------------

def save_expert3(expert: GBMExpert, path: str) -> None:
    """Save the underlying GBM model to *path*."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    backend = expert._backend
    if backend == "lgb":
        expert._impl.model.save_model(path)
        meta = {"backend": "lgb", "threshold": expert._impl.threshold}
    else:
        expert._impl.model.save_model(path)
        meta = {"backend": "xgb", "threshold": expert._impl.threshold}

    meta_path = str(path) + ".meta.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f)
    print(f"[Expert 3] saved → {path}  (meta: {meta_path})")


def load_expert3(path: str) -> GBMExpert:
    """Load a saved GBM expert from *path*."""
    meta_path = str(path) + ".meta.json"
    with open(meta_path) as f:
        meta = json.load(f)

    backend = meta.get("backend", "lgb")
    expert  = GBMExpert(backend=backend)

    if backend == "lgb":
        expert._impl.model = lgb.Booster(model_file=path)
    else:
        expert._impl.model = xgb.Booster()
        expert._impl.model.load_model(path)

    expert._impl.threshold = meta.get("threshold", 0.5)
    print(f"[Expert 3] loaded ← {path}")
    return expert


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    rng = np.random.default_rng(0)
    n   = 200
    X   = rng.random((n, N_FEATURES)).astype(np.float32)
    # Make class 1 slightly different so the model has signal to learn
    X[n//2:, 14] = 1.0   # tld_suspicion = 1 for malicious half
    X[n//2:, 20] = 0.8   # keyword_score high for malicious
    y   = np.array([0] * (n // 2) + [1] * (n // 2), dtype=np.float32)

    split = int(n * 0.8)
    expert = GBMExpert()
    expert.fit(X[:split], y[:split], X[split:], y[split:])
    probs = expert.predict_proba(X[split:])
    print(f"\nSmoke test — sample probs: {probs[:6].tolist()}")
    print(f"System device detected:    {get_device()}")