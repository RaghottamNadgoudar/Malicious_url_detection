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
WHITELISTED_DOMAINS = {
    "google.com", "www.google.com", "bing.com", "yahoo.com",
    "duckduckgo.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "reddit.com", "youtube.com",
    "github.com", "stackoverflow.com", "microsoft.com", "apple.com",
    "amazon.com", "paypal.com", "ebay.com", "wikipedia.org",
    "mozilla.org", "netflix.com", "spotify.com", "twitch.tv",
    "bbc.com", "cnn.com", "reuters.com", "mit.edu", "stanford.edu",
    "nasa.gov", "zoom.us", "slack.com", "notion.so", "dropbox.com",
    "adobe.com", "oracle.com", "ibm.com", "salesforce.com",
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


def _is_whitelisted(url: str) -> bool:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower().lstrip("www.").split(":")[0]
        if host in WHITELISTED_DOMAINS:
            return True
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in WHITELISTED_DOMAINS:
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


# ── Keras model (optional) ───────────────────────────────────────────────────

class _KerasPredictor:
    def __init__(self, model_path: str, stats_path: Optional[str] = None):
        import tensorflow as tf  # type: ignore
        self.model = tf.keras.models.load_model(model_path)
        self.feature_stats: Optional[Dict] = None
        if stats_path and os.path.exists(stats_path):
            with open(stats_path) as f:
                self.feature_stats = json.load(f)
        logger.info(f"Keras model loaded from {model_path}")

    def predict(self, vector: List[float]) -> float:
        arr = np.array(vector, dtype=np.float32).reshape(1, -1)
        if self.feature_stats:
            mean = np.array(self.feature_stats["mean"])
            std = np.where(
                np.array(self.feature_stats["std"]) == 0,
                1,
                np.array(self.feature_stats["std"]),
            )
            arr = (arr - mean) / std
        else:
            arr = np.minimum(arr / np.maximum(_MAX_VALUES, 1e-6), 1.0)
        prob = float(self.model.predict(arr, verbose=0)[0][0])
        return prob


# ── Main service ─────────────────────────────────────────────────────────────

class PredictorService:
    """
    Wraps neural-net or heuristic classifier.
    Initialised at app startup; safe as a module-level singleton.
    """

    THRESHOLD_SAFE = 0.25
    THRESHOLD_MALICIOUS = 0.60

    def __init__(self):
        self._keras: Optional[_KerasPredictor] = None
        self._model_loaded = False
        self._try_load_keras()

    def _try_load_keras(self) -> None:
        model_path = os.environ.get(
            "MODEL_PATH",
            os.path.join(
                os.path.dirname(__file__),
                "../../../../../backend/models/url_classifier.h5",
            ),
        )
        stats_path = os.environ.get(
            "MODEL_STATS_PATH",
            model_path.replace(".h5", "_stats.json"),
        )
        model_path = os.path.abspath(model_path)
        stats_path = os.path.abspath(stats_path)

        if not os.path.exists(model_path):
            logger.warning(
                f"Keras model not found at {model_path}. Using heuristic fallback."
            )
            return

        try:
            self._keras = _KerasPredictor(
                model_path,
                stats_path if os.path.exists(stats_path) else None,
            )
            self._model_loaded = True
        except Exception as exc:
            logger.warning(f"Could not load Keras model: {exc}. Using heuristic fallback.")

    @property
    def model_loaded(self) -> bool:
        return self._model_loaded

    def predict(self, url: str, feature_vector: List[float]) -> Dict:
        """
        Returns:
            label: ThreatLevel
            confidence: float [0, 1]
            threat_probability: float [0, 1]
        """
        # Fast-path: whitelisted
        if _is_whitelisted(url):
            return {
                "label": ThreatLevel.SAFE,
                "confidence": 0.99,
                "threat_probability": 0.01,
            }

        # ML or heuristic
        if self._keras:
            prob = self._keras.predict(feature_vector)
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

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "threat_probability": round(prob, 4),
        }


# ── Module-level singleton ────────────────────────────────────────────────────
predictor_service = PredictorService()
