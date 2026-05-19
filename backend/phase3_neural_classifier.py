"""
Phase 3: Neural Pre-classifier (25-Feature Feedforward Network)
Fully self-contained — zero dependency on Phase 2 pattern matching.
Features cover structural, lexical, entropy, and heuristic URL signals.
"""

import numpy as np
from typing import Dict, List
import re
import math
from collections import Counter
from urllib.parse import urlparse, unquote
import os
import json

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models
    from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("Warning: TensorFlow not available. Using fallback classifier.")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                   '.work', '.click', '.loan', '.win', '.racing', '.date',
                   '.download', '.stream', '.gdn', '.accountant', '.trade'}

# Phishing keywords — built-in, no external module needed
PHISHING_KEYWORDS = [
    # Victim-side lures
    'login', 'verify', 'secure', 'update', 'bank', 'paypal', 'apple',
    'amazon', 'confirm', 'account', 'signin', 'ebay', 'password',
    'suspended', 'locked', 'urgent', 'support', 'billing',
    'invoice', 'expire', 'validate', 'credential', 'recovery', 'reset',
    'authentication', 'wallet', 'crypto', 'security', 'alert',
    'click', 'free', 'prize', 'winner', 'download', 'install',
    'offer', 'discount', 'limited', 'claim', 'reward', 'gift',
    # Attacker-side / meta attack words
    'phishing', 'malware', 'ransomware', 'spyware', 'trojan', 'exploit',
    'hack', 'hacked', 'crack', 'bypass', 'payload', 'shell', 'cmd',
    'steal', 'stealer', 'keylog', 'logger', 'inject', 'xss', 'sqli',
]

# Legitimate brands frequently spoofed
SPOOFED_BRANDS = ['paypal', 'apple', 'google', 'microsoft', 'amazon',
                  'facebook', 'netflix', 'instagram', 'twitter', 'ebay',
                  'wellsfargo', 'bankofamerica', 'chase', 'citibank']

# Whitelisted domains — bypasses all ML scoring
WHITELISTED_DOMAINS = {
    'google.com', 'www.google.com', 'google.co.in',
    'bing.com', 'www.bing.com',
    'yahoo.com', 'www.yahoo.com',
    'duckduckgo.com', 'www.duckduckgo.com',
    'facebook.com', 'www.facebook.com',
    'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
    'instagram.com', 'www.instagram.com',
    'linkedin.com', 'www.linkedin.com',
    'reddit.com', 'www.reddit.com',
    'youtube.com', 'www.youtube.com',
    'whatsapp.com', 'www.whatsapp.com',
    'telegram.org', 'www.telegram.org',
    'github.com', 'www.github.com',
    'stackoverflow.com', 'www.stackoverflow.com',
    'microsoft.com', 'www.microsoft.com',
    'apple.com', 'www.apple.com',
    'amazon.com', 'www.amazon.com',
    'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
    'developer.apple.com', 'docs.microsoft.com', 'learn.microsoft.com',
    'developer.mozilla.org', 'mozilla.org', 'www.mozilla.org',
    'paypal.com', 'www.paypal.com',
    'ebay.com', 'www.ebay.com',
    'walmart.com', 'www.walmart.com',
    'target.com', 'www.target.com',
    'bestbuy.com', 'www.bestbuy.com',
    'etsy.com', 'www.etsy.com',
    'netflix.com', 'www.netflix.com',
    'spotify.com', 'www.spotify.com',
    'twitch.tv', 'www.twitch.tv',
    'imdb.com', 'www.imdb.com',
    'nytimes.com', 'www.nytimes.com',
    'bbc.com', 'www.bbc.com', 'bbc.co.uk', 'www.bbc.co.uk',
    'cnn.com', 'www.cnn.com',
    'reuters.com', 'www.reuters.com',
    'wikipedia.org', 'www.wikipedia.org', 'en.wikipedia.org',
    'mit.edu', 'www.mit.edu',
    'stanford.edu', 'www.stanford.edu',
    'harvard.edu', 'www.harvard.edu',
    'nasa.gov', 'www.nasa.gov',
    'nih.gov', 'www.nih.gov',
    'cdc.gov', 'www.cdc.gov',
    'whitehouse.gov', 'www.whitehouse.gov',
    'zoom.us', 'www.zoom.us',
    'slack.com', 'www.slack.com',
    'notion.so', 'www.notion.so',
    'dropbox.com', 'www.dropbox.com',
    'drive.google.com', 'docs.google.com', 'mail.google.com',
    'salesforce.com', 'www.salesforce.com',
    'oracle.com', 'www.oracle.com',
    'ibm.com', 'www.ibm.com',
    'adobe.com', 'www.adobe.com',
}

# Suspicious ports
SUSPICIOUS_PORTS = {8080, 8443, 9090, 3333, 4444, 5555, 7777, 8888, 9999}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def is_whitelisted(url: str) -> bool:
    """Return True if the URL's hostname is a known-safe domain."""
    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or parsed.path.split('/')[0]).lower()
        hostname = hostname.split(':')[0]  # strip port
        if hostname in WHITELISTED_DOMAINS:
            return True
        parts = hostname.split('.')
        for i in range(1, len(parts) - 1):
            if '.'.join(parts[i:]) in WHITELISTED_DOMAINS:
                return True
    except Exception:
        pass
    return False


def _keyword_score(url: str) -> float:
    """
    Count phishing keywords in URL (normalized).
    Decoded + lowercased; no external module required.
    """
    try:
        decoded = unquote(url).lower()
    except Exception:
        decoded = url.lower()
    hits = sum(1 for kw in PHISHING_KEYWORDS if kw in decoded)
    return min(hits / max(len(PHISHING_KEYWORDS), 1), 1.0)


def _brand_in_subdomain(url: str) -> int:
    """
    Returns 1 if a known brand name appears in subdomain/path but the root
    domain is NOT that brand (classic phishing pattern).
    e.g.  paypal.secure-login.tk  → 1
          www.paypal.com          → 0
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower() or url.split('/')[0].lower()
        parts = hostname.split('.')
        # root domain = last two parts
        root = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
        # check subdomains + path
        prefix = hostname[: hostname.rfind(root)].rstrip('.')
        path = (parsed.path or '').lower()
        for brand in SPOOFED_BRANDS:
            if brand in prefix or brand in path:
                # make sure root domain is NOT the real brand
                if brand not in root:
                    return 1
    except Exception:
        pass
    return 0


def _has_homograph(url: str) -> int:
    """Detect digit-substitution typosquatting (g00gle, faceb00k, micr0soft)."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        # Remove www
        if domain.startswith('www.'):
            domain = domain[4:]
        # Expand digits → letters
        leet = domain.translate(str.maketrans('01345', 'oieAs'))
        for brand in SPOOFED_BRANDS:
            if brand in leet and brand not in domain:
                return 1
    except Exception:
        pass
    return 0


def _has_suspicious_port(url: str) -> int:
    try:
        parsed = urlparse(url)
        port = parsed.port
        if port and port in SUSPICIOUS_PORTS:
            return 1
    except Exception:
        pass
    return 0


def _domain_length(url: str) -> int:
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower().split(':')[0]
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        return len(hostname)
    except Exception:
        return len(url)


def _query_length(url: str) -> int:
    try:
        return len(urlparse(url).query)
    except Exception:
        return 0


def _num_query_params(url: str) -> int:
    try:
        q = urlparse(url).query
        return len(q.split('&')) if q else 0
    except Exception:
        return 0


def _has_at_symbol(url: str) -> int:
    return 1 if '@' in url else 0


def _double_slash_in_path(url: str) -> int:
    try:
        path = urlparse(url).path
        return 1 if '//' in path else 0
    except Exception:
        return 0


def _domain_entropy(url: str) -> float:
    """Entropy of the domain part only (not full URL)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower().split(':')[0]
        return _entropy(hostname)
    except Exception:
        return _entropy(url)


def _uppercase_ratio(url: str) -> float:
    if not url:
        return 0.0
    return sum(1 for c in url if c.isupper()) / len(url)


# ---------------------------------------------------------------------------
# 25-Feature Extractor (fully self-contained)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    # Structural
    'url_length',           # 0
    'domain_length',        # 1
    'subdomain_depth',      # 2
    'path_depth',           # 3
    'query_length',         # 4
    'num_query_params',     # 5
    # Character-level
    'dot_count',            # 6
    'hyphen_count',         # 7
    'digit_ratio',          # 8
    'uppercase_ratio',      # 9
    'special_char_ratio',   # 10
    # Entropy
    'url_entropy',          # 11
    'domain_entropy',       # 12
    # Protocol / TLD
    'has_https',            # 13
    'tld_suspicion',        # 14
    # IP / obfuscation
    'has_ip',               # 15
    'has_at_symbol',        # 16
    'double_slash_path',    # 17
    'has_suspicious_port',  # 18
    # Redirect / graph (from Phase 1)
    'redirect_depth',       # 19
    # Semantic / phishing signals
    'keyword_score',        # 20
    'brand_in_subdomain',   # 21
    'has_homograph',        # 22
    # Domain age proxy
    'domain_age_proxy',     # 23
    # Redirect-chain entropy
    'chain_length',         # 24
]

N_FEATURES = len(FEATURE_NAMES)  # 25


def extract_features(url: str, phase1_data: Dict = None,
                     phase2_data: Dict = None) -> np.ndarray:
    """
    Extract 25-dimensional feature vector.
    phase2_data is accepted for backward-compat but NOT used.
    """
    features = np.zeros(N_FEATURES, dtype=np.float32)

    try:
        parsed = urlparse(url)
        hostname = (parsed.netloc or '').lower().split(':')[0]
        if hostname.startswith('www.'):
            hostname = hostname[4:]

        # 0 URL length
        features[0] = len(url)
        # 1 Domain length
        features[1] = _domain_length(url)
        # 2 Subdomain depth (number of dots in netloc)
        features[2] = hostname.count('.')
        # 3 Path depth (number of slashes)
        features[3] = url.count('/')
        # 4 Query string length
        features[4] = _query_length(url)
        # 5 Number of query parameters
        features[5] = _num_query_params(url)
        # 6 Dot count in full URL
        features[6] = url.count('.')
        # 7 Hyphen count
        features[7] = url.count('-')
        # 8 Digit ratio
        features[8] = sum(c.isdigit() for c in url) / len(url) if url else 0
        # 9 Uppercase ratio
        features[9] = _uppercase_ratio(url)
        # 10 Special char ratio (@%=&?#)
        features[10] = sum(1 for c in url if c in '@%=&?#') / len(url) if url else 0
        # 11 Full URL entropy
        features[11] = _entropy(url)
        # 12 Domain-only entropy
        features[12] = _domain_entropy(url)
        # 13 Has HTTPS
        features[13] = 1.0 if url.startswith('https://') else 0.0
        # 14 TLD suspicion (count of suspicious TLDs that match)
        features[14] = float(any(url.lower().split('?')[0].split('/')[0].endswith(t)
                                  or ('.' + hostname).endswith(t)
                                  for t in SUSPICIOUS_TLDS))
        # 15 Has IP address
        features[15] = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0.0
        # 16 Has @ symbol
        features[16] = float(_has_at_symbol(url))
        # 17 Double slash in path
        features[17] = float(_double_slash_in_path(url))
        # 18 Suspicious port
        features[18] = float(_has_suspicious_port(url))
        # 19 Redirect depth (from Phase 1)
        features[19] = float(phase1_data.get('redirect_depth', 0)) if phase1_data else 0.0
        # 20 Phishing keyword score (self-contained)
        features[20] = _keyword_score(url)
        # 21 Brand name in subdomain/path (spoofing signal)
        features[21] = float(_brand_in_subdomain(url))
        # 22 Homograph / typosquatting
        features[22] = float(_has_homograph(url))
        # 23 Domain age proxy (common TLDs are older / more trusted)
        features[23] = 1.0 if any(hostname.endswith(t) for t in
                                   ('.com', '.org', '.net', '.edu', '.gov')) else 0.3
        # 24 Redirect chain length (from Phase 1)
        features[24] = float(phase1_data.get('chain_length', 0)) if phase1_data else 0.0

    except Exception:
        pass  # Return zero-vector on any error

    return features


# ---------------------------------------------------------------------------
# Neural Network architecture  (25 → 128 → 64 → 32 → 1)
# ---------------------------------------------------------------------------

def build_neural_network(input_dim: int = N_FEATURES):
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(128, activation='relu', name='hidden1'),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(64, activation='relu', name='hidden2'),
        layers.BatchNormalization(),
        layers.Dropout(0.25),
        layers.Dense(32, activation='relu', name='hidden3'),
        layers.BatchNormalization(),
        layers.Dropout(0.2),
        layers.Dense(1, activation='sigmoid', name='output'),
    ])
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', keras.metrics.AUC(name='auc')],
    )
    return model


# ---------------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------------

class DeepNeuralClassifier:
    """TensorFlow/Keras deep classifier."""

    def __init__(self, model_path='models/url_classifier.h5'):
        self.model_path = model_path
        self.model = None
        self.threshold_safe = 0.25
        self.threshold_malicious = 0.55
        self.feature_stats = None

        # Try loading a saved model that matches the current feature count
        if os.path.exists(model_path):
            try:
                loaded = keras.models.load_model(model_path)
                # Accept model only if input shape matches N_FEATURES
                expected_in = loaded.input_shape[-1]
                if expected_in == N_FEATURES:
                    self.model = loaded
                    print(f"✓ Loaded trained model from {model_path} "
                          f"({N_FEATURES} features)")
                    stats_path = model_path.replace('.h5', '_stats.json')
                    if os.path.exists(stats_path):
                        with open(stats_path) as f:
                            self.feature_stats = json.load(f)
                else:
                    print(f"⚠ Saved model uses {expected_in} features but "
                          f"current extractor has {N_FEATURES}. "
                          f"Building fresh model — run train_model.py to retrain.")
            except Exception as e:
                print(f"Warning: Could not load model: {e}")

        if self.model is None:
            self.model = build_neural_network()
            print(f"✓ Built new neural network model ({N_FEATURES} features)")

    # ------------------------------------------------------------------
    def train(self, X_train, y_train, X_val, y_val,
              epochs=50, batch_size=256):
        self.feature_stats = {
            'mean': X_train.mean(axis=0).tolist(),
            'std':  X_train.std(axis=0).tolist(),
        }
        X_tr = self._normalize(X_train)
        X_v  = self._normalize(X_val)

        # Always recompile to get a fresh optimizer — avoids the
        # "Unknown variable" error when the saved model carried an
        # optimizer built for a different variable set.
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', keras.metrics.AUC(name='auc')],
        )

        callbacks = [
            EarlyStopping(monitor='val_auc', patience=7,
                          mode='max', restore_best_weights=True),
            ModelCheckpoint(self.model_path, monitor='val_auc',
                            mode='max', save_best_only=True),
        ]
        history = self.model.fit(
            X_tr, y_train,
            validation_data=(X_v, y_val),
            epochs=epochs, batch_size=batch_size,
            callbacks=callbacks, verbose=1,
        )
        stats_path = self.model_path.replace('.h5', '_stats.json')
        with open(stats_path, 'w') as f:
            json.dump(self.feature_stats, f)
        return history

    def predict(self, features: np.ndarray) -> float:
        if features.ndim == 1:
            features = features.reshape(1, -1)
        norm = self._normalize(features)
        return float(self.model.predict(norm, verbose=0)[0][0])

    def _normalize(self, X: np.ndarray) -> np.ndarray:
        if self.feature_stats is None:
            # Rough max-values for min-max fallback (one per feature)
            maxv = np.array([
                500, 100, 5, 20, 300, 15,
                20, 15, 1, 1, 1,
                5, 5,
                1, 1,
                1, 1, 1, 1,
                10,
                1, 1, 1, 1, 10,
            ], dtype=np.float32)
            return np.minimum(X / np.maximum(maxv, 1e-6), 1.0)
        mean = np.array(self.feature_stats['mean'])
        std  = np.array(self.feature_stats['std'])
        std  = np.where(std == 0, 1, std)
        return (X - mean) / std

    def classify(self, url: str, phase1_data: Dict = None,
                 phase2_data: Dict = None) -> Dict:
        if is_whitelisted(url):
            return _whitelist_result(url)
        features = extract_features(url, phase1_data)
        prob = self.predict(features)
        return _build_result(url, features, prob,
                             self.threshold_safe, self.threshold_malicious)


# ---------------------------------------------------------------------------

class FallbackClassifier:
    """
    Heuristic weighted classifier used when TensorFlow is unavailable
    or the saved model has a different input size.
    Weights tuned for 25-feature vector.
    """

    # One weight per feature (positive = suspicious, negative = safe signal)
    WEIGHTS = np.array([
        0.010,   # 0  url_length
        0.008,   # 1  domain_length
        0.040,   # 2  subdomain_depth
        0.010,   # 3  path_depth
        0.008,   # 4  query_length
        0.005,   # 5  num_query_params
        0.012,   # 6  dot_count
        0.025,   # 7  hyphen_count
        0.050,   # 8  digit_ratio
        0.015,   # 9  uppercase_ratio
        0.040,   # 10 special_char_ratio
        0.030,   # 11 url_entropy
        0.020,   # 12 domain_entropy
       -0.080,   # 13 has_https  (negative = safer)
        0.120,   # 14 tld_suspicion
        0.150,   # 15 has_ip
        0.080,   # 16 has_at_symbol
        0.040,   # 17 double_slash_path
        0.060,   # 18 suspicious_port
        0.030,   # 19 redirect_depth
        0.160,   # 20 keyword_score
        0.180,   # 21 brand_in_subdomain
        0.200,   # 22 has_homograph
       -0.040,   # 23 domain_age_proxy  (negative = safer)
        0.010,   # 24 chain_length
    ], dtype=np.float32)

    # Normalisation max-values (same order)
    MAX_VALUES = np.array([
        500, 100, 5, 20, 300, 15,
        20, 15, 1, 1, 1,
        5, 5,
        1, 1,
        1, 1, 1, 1,
        10,
        1, 1, 1, 1, 10,
    ], dtype=np.float32)

    def __init__(self):
        self.threshold_safe = 0.30
        self.threshold_malicious = 0.65

    def predict(self, features: np.ndarray) -> float:
        norm = np.minimum(features / np.maximum(self.MAX_VALUES, 1e-6), 1.0)
        score = float(np.dot(norm, self.WEIGHTS))
        return float(1.0 / (1.0 + math.exp(-score * 5)))  # scaled sigmoid

    def classify(self, url: str, phase1_data: Dict = None,
                 phase2_data: Dict = None) -> Dict:
        if is_whitelisted(url):
            return _whitelist_result(url)
        features = extract_features(url, phase1_data)
        prob = self.predict(features)
        return _build_result(url, features, prob,
                             self.threshold_safe, self.threshold_malicious)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _whitelist_result(url: str) -> Dict:
    # Still extract features so the frontend shows real values
    try:
        feats = extract_features(url)
        feat_list = feats.tolist()
    except Exception:
        feat_list = [0.0] * len(FEATURE_NAMES)
    return {
        'url': url,
        'features': feat_list,
        'feature_names': FEATURE_NAMES,
        'threat_probability': 0.01,
        'verdict': 'safe',
        'action': 'early_exit',
        'reason': 'Whitelisted domain',
    }


def _build_result(url: str, features: np.ndarray, prob: float,
                  thr_safe: float, thr_mal: float) -> Dict:
    if prob < thr_safe:
        verdict, action = 'safe', 'early_exit'
    elif prob <= thr_mal:
        verdict, action = 'uncertain', 'send_to_bloom_filter'
    else:
        verdict, action = 'malicious', 'flag_and_register'
    return {
        'url': url,
        'features': features.tolist(),
        'threat_probability': prob,
        'verdict': verdict,
        'action': action,
        'feature_names': FEATURE_NAMES,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class NeuralClassifier:
    """Main Phase 3 class — picks Deep or Fallback automatically."""

    def __init__(self, model_path='models/url_classifier.h5'):
        if TENSORFLOW_AVAILABLE:
            self.classifier = DeepNeuralClassifier(model_path)
        else:
            self.classifier = FallbackClassifier()
            print("Using fallback classifier (TensorFlow not available)")

    def analyze_url(self, url: str, phase1_data: Dict = None,
                    phase2_data: Dict = None) -> Dict:
        """Analyze URL — phase2_data ignored (pattern matching removed)."""
        return self.classifier.classify(url, phase1_data, None)

    def train(self, X_train, y_train, X_val, y_val, **kwargs):
        if hasattr(self.classifier, 'train'):
            return self.classifier.train(X_train, y_train, X_val, y_val, **kwargs)
        raise NotImplementedError("Training not available with fallback classifier")
