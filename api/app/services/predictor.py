"""
Predictor Service
Loads the trained Keras model (if available) or falls back to the
heuristic weighted classifier. Returns a ThreatLevel + confidence score.
"""

import math
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

import numpy as np

from app.schemas.response import ThreatLevel
from app.utils.logger import get_logger

logger = get_logger("services.predictor")

# ── Whitelisted domains — always safe ────────────────────────────────────────
# These domains bypass ML models entirely (fast-path to SAFE).
# Add any domain you trust here. Subdomains of these are also matched.
WHITELISTED_DOMAINS = {
    # Search & portals
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
    # Social media
    "facebook.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "reddit.com", "youtube.com", "tiktok.com",
    "pinterest.com", "snapchat.com", "discord.com", "twitch.tv",
    # Tech & Dev
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com", "superuser.com",
    "serverfault.com", "askubuntu.com",
    "docs.python.org", "python.org", "pypi.org",
    "npmjs.com", "nodejs.org", "reactjs.org", "vuejs.org",
    "developer.mozilla.org", "mozilla.org",
    "docs.microsoft.com", "microsoft.com", "azure.microsoft.com",
    "apple.com", "developer.apple.com",
    "aws.amazon.com", "docs.aws.amazon.com", "cloud.google.com",
    "developers.google.com", "googleapis.com",
    "arxiv.org", "paperswithcode.com", "huggingface.co",
    "pytorch.org", "tensorflow.org", "keras.io",
    "oracle.com", "ibm.com", "salesforce.com", "adobe.com",
    # E-commerce & Finance (official)
    "amazon.com", "paypal.com", "ebay.com", "stripe.com", "shopify.com",
    # Cloud & Productivity
    "zoom.us", "slack.com", "notion.so", "dropbox.com",
    "drive.google.com", "docs.google.com", "sheets.google.com",
    "office.com", "onedrive.live.com", "outlook.com",
    # Media & News
    "wikipedia.org", "wikimedia.org", "bbc.com", "bbc.co.uk",
    "cnn.com", "reuters.com", "apnews.com", "theguardian.com",
    "nytimes.com", "washingtonpost.com",
    # Entertainment
    "netflix.com", "spotify.com", "twitch.tv", "imdb.com",
    # URL shorteners (trusted)
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
    # Education & Government
    "mit.edu", "stanford.edu", "harvard.edu", "berkeley.edu",
    "nasa.gov", "cdc.gov", "nih.gov", "whitehouse.gov",
}

# ── Feature normalisation max-values (same order as FEATURE_NAMES) ───────────
_MAX_VALUES = np.array([
    500, 100, 5, 20, 300, 15,
    20, 15, 1, 1, 1,
    5, 5,
    1, 1,
    1, 1, 1, 1,
    10,
    1, 1, 1, 1, 10,
], dtype=np.float32)

# ── Heuristic weights (same as FallbackClassifier in phase3) ─────────────────
_HEURISTIC_WEIGHTS = np.array([
    0.010, 0.008, 0.040, 0.010, 0.008, 0.005,
    0.012, 0.025, 0.050, 0.015, 0.040,
    0.030, 0.020,
    -0.080, 0.120,
    0.150, 0.080, 0.040, 0.060,
    0.030,
    0.160, 0.180, 0.200,
    -0.040,
    0.010,
], dtype=np.float32)


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


import tldextract

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
    return False


# ── Heuristic fallback ───────────────────────────────────────────────────────

def _heuristic_predict(feature_vector: List[float]) -> float:
    arr = np.array(feature_vector, dtype=np.float32)
    norm = np.minimum(arr / np.maximum(_MAX_VALUES, 1e-6), 1.0)
    score = float(np.dot(norm, _HEURISTIC_WEIGHTS))
    return _sigmoid(score * 5)


# ── Mixture of Experts model loader ──────────────────────────────────────────

import importlib.util as _ilu
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent.parent.resolve()

def _load(stem: str):
    """Load a module from ROOT/<stem>.py, handling leading-space filenames."""
    exact = ROOT / f"{stem}.py"
    if exact.exists():
        spec = _ilu.spec_from_file_location(stem, exact)
    else:
        spaced = ROOT / f" {stem}.py"
        if spaced.exists():
            spec = _ilu.spec_from_file_location(stem, spaced)
        else:
            raise ImportError(f"Cannot find {stem}.py or ' {stem}.py' in {ROOT}")
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Main service ─────────────────────────────────────────────────────────────

class PredictorService:
    """
    Wraps three Expert models in a Mixture of Experts (MoE) ensemble:
      - Expert 1: Char-CNN (PyTorch, runs on CPU or MPS)
      - Expert 2: DistilBERT (PyTorch/Transformers, runs on CPU or MPS)
      - Expert 3: LightGBM (runs on CPU)

    Computes prediction probabilities from all three and returns the averaged ensemble score.
    Temperature scaling (T=4.0) is applied to Expert 1 and Expert 2 logits to fix
    sigmoid saturation caused by the class-imbalanced training distribution.
    """

    # Recalibrated Thresholds based on OOD testing on real data
    THRESHOLD_SAFE       = 0.57
    THRESHOLD_MALICIOUS  = 0.60
    # Temperature for logit scaling on neural experts (E1, E2).
    # T=1.0  -> no scaling (raw sigmoid, everything saturates at ~1.0)
    # T=50.0 -> recommended: Expert 1 logits are 18-33, so:
    #   github.com  (logit~19) -> sigmoid(19/50) = sigmoid(0.38) = 0.59
    #   paypal-login.xyz (logit~27) -> sigmoid(27/50) = sigmoid(0.54) = 0.63
    # Combined with whitelist, this gives reliable safe/malicious separation.
    TEMPERATURE          = 50.0

    def __init__(self):
        self._expert1 = None
        self._expert2 = None
        self._expert2_tok = None
        self._expert2_max_length = 128
        self._expert3 = None
        self._predict_logit_e1 = None  # temperature-aware inference
        self._predict_logit_e2 = None  # temperature-aware inference
        
        self._model_loaded = False
        self._try_load_experts()

    def _try_load_experts(self) -> None:
        try:
            # Add ROOT to sys.path so modules can resolve local imports/configs
            if str(ROOT) not in sys.path:
                sys.path.insert(0, str(ROOT))

            e3 = _load("expert3_gbm")
            e1 = _load("expert1_char_cnn_bilstm")
            e2 = _load("expert2_distilbert")

            e1_path = ROOT / "checkpoints" / "expert1_char_cnn_bilstm.pt"
            e2_path = ROOT / "checkpoints" / "expert2_distilbert.pt"
            e3_path = ROOT / "checkpoints" / "expert3_lgb.model"

            missing = []
            for name, path in [("Expert 1", e1_path), ("Expert 2", e2_path), ("Expert 3", e3_path)]:
                if not path.exists():
                    missing.append(name)

            if missing:
                logger.warning(
                    f"Checkpoints missing: {missing}. "
                    "Make sure training has completed successfully. Using heuristic fallback."
                )
                return

            logger.info("Loading MoE expert weights...")
            
            # Load LightGBM first to prevent OpenMP/BLAS symbol collisions on macOS!
            # Expert 3 LightGBM
            self._expert3 = e3.load_expert3(str(e3_path))
            
            # Expert 1 CNN — store predict_logit for temperature scaling
            self._expert1 = e1.load_expert1(str(e1_path))
            self._predict_logit_e1 = e1.predict_logit

            # Expert 2 DistilBERT — store predict_logit for temperature scaling
            self._expert2, self._expert2_tok, self._expert2_max_length = e2.load_expert2(str(e2_path))
            self._predict_logit_e2 = e2.predict_logit

            self._model_loaded = True
            logger.info(f"MoE models loaded. Temperature scaling T={self.TEMPERATURE} active on neural experts.")

        except Exception as exc:
            logger.error(
                f"Failed to initialize Mixture of Experts: {exc}. "
                "Using heuristic fallback.",
                exc_info=True
            )

    @property
    def model_loaded(self) -> bool:
        return self._model_loaded

    def predict(self, url: str, feature_vector: List[float]) -> Dict:
        """
        Returns:
            label: ThreatLevel
            confidence: float [0, 1]
            threat_probability: float [0, 1]
            expert_probabilities: Dict[str, float]
        """
        # Tier 1: Fast-path Whitelist
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
            }

        expert_probs = {}

        # Run MoE ensemble or heuristic fallback
        if self._model_loaded:
            try:
                T = self.TEMPERATURE

                # ── Expert 1 prediction (Char-CNN, temperature-scaled) ────────
                p1 = self._predict_logit_e1(self._expert1, [url], temperature=T)[0]
                expert_probs["expert1_cnn"] = round(float(p1), 4)

                # ── Expert 2 prediction (DistilBERT, temperature-scaled) ──────
                p2 = self._predict_logit_e2(
                    self._expert2, self._expert2_tok, [url],
                    max_length=self._expert2_max_length,
                    temperature=T,
                )[0]
                expert_probs["expert2_distilbert"] = round(float(p2), 4)

                # ── Expert 3 prediction (LightGBM, no temperature needed) ─────
                X3 = np.array(feature_vector, dtype=np.float32).reshape(1, -1)
                p3 = self._expert3.predict_proba(X3)[0]
                expert_probs["expert3_lgb"] = round(float(p3), 4)

                # Soft voting: average probability
                prob = sum(expert_probs.values()) / 3.0

            except Exception as exc:
                logger.error(f"MoE prediction failed: {exc}. Falling back to heuristics.")
                prob = _heuristic_predict(feature_vector)
                expert_probs = {}
        else:
            prob = _heuristic_predict(feature_vector)

        # Classify
        if prob < self.THRESHOLD_SAFE:
            label = ThreatLevel.SAFE
            confidence = 1.0 - prob
        elif prob > self.THRESHOLD_MALICIOUS:
            label = ThreatLevel.MALICIOUS
            confidence = prob
        else:
            label = ThreatLevel.SUSPICIOUS
            confidence = abs(prob - 0.5) * 2  # distance from centre

        res = {
            "label": label,
            "confidence": round(confidence, 4),
            "threat_probability": round(prob, 4),
        }
        if expert_probs:
            res["expert_probabilities"] = expert_probs
            
        return res


# ── Module-level singleton ────────────────────────────────────────────────────
predictor_service = PredictorService()

