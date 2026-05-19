"""
Phase 3: Neural Pre-classifier (15-Feature Feedforward Network)
Space-time tradeoff · Pre-computed feature vector
REAL DEEP LEARNING MODEL using TensorFlow/Keras
"""

import numpy as np
from typing import Dict, List
import re
from urllib.parse import urlparse
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


# Suspicious TLDs (high-risk top-level domains)
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']


def extract_features(url: str, phase1_data: Dict = None, phase2_data: Dict = None) -> np.ndarray:
    """
    Extract 15-dimensional feature vector from URL.
    
    Features:
    1. URL length
    2. Shannon entropy
    3. Digit ratio
    4. Dot count
    5. Hyphen count
    6. Has IP address
    7. Subdomain depth
    8. Path depth
    9. Has HTTPS
    10. TLD suspicion score
    11. Pattern match score (from Phase 2)
    12. Redirect depth (from Phase 1)
    13. Special char ratio
    14. Keyword entropy delta
    15. Domain age proxy (simplified)
    """
    from phase1_graph_traversal import entropy
    
    features = []
    
    # Feature 1: URL length
    features.append(len(url))
    
    # Feature 2: Shannon entropy
    url_entropy = entropy(url) if phase1_data is None else phase1_data.get('entropy', entropy(url))
    features.append(url_entropy)
    
    # Feature 3: Digit ratio
    digit_ratio = sum(c.isdigit() for c in url) / len(url) if url else 0
    features.append(digit_ratio)
    
    # Feature 4: Dot count
    features.append(url.count('.'))
    
    # Feature 5: Hyphen count
    features.append(url.count('-'))
    
    # Feature 6: Has IP address (binary)
    has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    features.append(has_ip)
    
    # Feature 7: Subdomain depth
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path.split('/')[0]
        subdomain_depth = hostname.count('.')
    except:
        subdomain_depth = 0
    features.append(subdomain_depth)
    
    # Feature 8: Path depth
    path_depth = url.count('/')
    features.append(path_depth)
    
    # Feature 9: Has HTTPS (binary)
    has_https = 1 if url.startswith('https://') else 0
    features.append(has_https)
    
    # Feature 10: TLD suspicion score
    tld_suspicion = sum(1 for tld in SUSPICIOUS_TLDS if url.endswith(tld))
    features.append(tld_suspicion)
    
    # Feature 11: Pattern match score (from Phase 2)
    pattern_score = phase2_data.get('pattern_score', 0) if phase2_data else 0
    features.append(pattern_score)
    
    # Feature 12: Redirect depth (from Phase 1)
    redirect_depth = phase1_data.get('redirect_depth', 0) if phase1_data else 0
    features.append(redirect_depth)
    
    # Feature 13: Special char ratio
    special_chars = sum(1 for c in url if c in '@%=&?#')
    special_char_ratio = special_chars / len(url) if url else 0
    features.append(special_char_ratio)
    
    # Feature 14: Keyword entropy delta (simplified)
    # Entropy difference before/after normalization
    from phase2_pattern_matching import normalize_url
    normalized = normalize_url(url)
    entropy_delta = abs(entropy(url) - entropy(normalized))
    features.append(entropy_delta)
    
    # Feature 15: Domain age proxy (simplified heuristic)
    # Longer domains with common TLDs are likely older
    domain_age_proxy = 1.0 if any(url.endswith(tld) for tld in ['.com', '.org', '.net', '.edu', '.gov']) else 0.5
    features.append(domain_age_proxy)
    
    return np.array(features, dtype=np.float32)


def build_neural_network(input_dim=15):
    """
    Build a feedforward neural network: 15 → 64 → 32 → 1
    Architecture from implementation plan.
    """
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        
        # First hidden layer
        layers.Dense(64, activation='relu', name='hidden1'),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        
        # Second hidden layer
        layers.Dense(32, activation='relu', name='hidden2'),
        layers.BatchNormalization(),
        layers.Dropout(0.2),
        
        # Output layer
        layers.Dense(1, activation='sigmoid', name='output')
    ])
    
    # Compile with binary cross-entropy loss
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', keras.metrics.AUC(name='auc')]
    )
    
    return model


class DeepNeuralClassifier:
    """
    Real deep learning classifier using TensorFlow/Keras.
    Architecture: 15 → 64 → 32 → 1 (sigmoid)
    """
    
    def __init__(self, model_path='models/url_classifier.h5'):
        self.model_path = model_path
        self.model = None
        self.threshold_safe = 0.2
        self.threshold_malicious = 0.6
        self.feature_stats = None
        
        # Try to load existing model
        if os.path.exists(model_path):
            try:
                self.model = keras.models.load_model(model_path)
                print(f"✓ Loaded trained model from {model_path}")
                
                # Load feature statistics
                stats_path = model_path.replace('.h5', '_stats.json')
                if os.path.exists(stats_path):
                    with open(stats_path, 'r') as f:
                        self.feature_stats = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load model: {e}")
                self.model = None
        
        # Build new model if not loaded
        if self.model is None:
            self.model = build_neural_network()
            print("✓ Built new neural network model")
    
    def train(self, X_train, y_train, X_val, y_val, epochs=50, batch_size=256):
        """
        Train the neural network.
        
        Args:
            X_train: Training features (n_samples, 15)
            y_train: Training labels (n_samples,)
            X_val: Validation features
            y_val: Validation labels
            epochs: Number of training epochs
            batch_size: Batch size
        """
        # Calculate and save feature statistics for normalization
        self.feature_stats = {
            'mean': X_train.mean(axis=0).tolist(),
            'std': X_train.std(axis=0).tolist()
        }
        
        # Normalize features
        X_train_norm = self._normalize_features(X_train)
        X_val_norm = self._normalize_features(X_val)
        
        # Callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_auc',
                patience=5,
                mode='max',
                restore_best_weights=True
            ),
            ModelCheckpoint(
                self.model_path,
                monitor='val_auc',
                mode='max',
                save_best_only=True
            )
        ]
        
        # Train
        history = self.model.fit(
            X_train_norm, y_train,
            validation_data=(X_val_norm, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        # Save feature statistics
        stats_path = self.model_path.replace('.h5', '_stats.json')
        with open(stats_path, 'w') as f:
            json.dump(self.feature_stats, f)
        
        return history
    
    def predict(self, features: np.ndarray) -> float:
        """
        Predict threat probability for given features.
        Returns probability between 0 and 1.
        """
        # Ensure 2D array
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Normalize features
        normalized_features = self._normalize_features(features)
        
        # Predict
        probability = self.model.predict(normalized_features, verbose=0)[0][0]
        
        return float(probability)
    
    def _normalize_features(self, features: np.ndarray) -> np.ndarray:
        """Normalize features using z-score normalization."""
        if self.feature_stats is None:
            # Fallback to min-max normalization
            max_values = np.array([
                200, 5.0, 1.0, 10, 10, 1, 5, 10, 1, 3, 1.0, 10, 1.0, 2.0, 1.0
            ])
            return np.minimum(features / max_values, 1.0)
        
        # Z-score normalization
        mean = np.array(self.feature_stats['mean'])
        std = np.array(self.feature_stats['std'])
        std = np.where(std == 0, 1, std)  # Avoid division by zero
        
        return (features - mean) / std
    
    def classify(self, url: str, phase1_data: Dict = None, phase2_data: Dict = None) -> Dict:
        """
        Full classification pipeline for a URL.
        Returns threat probability and routing decision.
        """
        # Extract features
        features = extract_features(url, phase1_data, phase2_data)
        
        # Predict
        threat_prob = self.predict(features)
        
        # Routing logic
        if threat_prob < self.threshold_safe:
            verdict = 'safe'
            action = 'early_exit'
        elif threat_prob <= self.threshold_malicious:
            verdict = 'uncertain'
            action = 'send_to_bloom_filter'
        else:
            verdict = 'malicious'
            action = 'flag_and_register'
        
        return {
            'url': url,
            'features': features.tolist(),
            'threat_probability': threat_prob,
            'verdict': verdict,
            'action': action
        }


class FallbackClassifier:
    """Fallback classifier when TensorFlow is not available or model not trained."""
    
    def __init__(self):
        # Balanced weights for feature scoring
        self.feature_weights = np.array([
            0.03,   # URL length
            0.12,   # Entropy
            0.10,   # Digit ratio
            0.04,   # Dot count
            0.06,   # Hyphen count
            0.20,   # Has IP (suspicious)
            0.08,   # Subdomain depth
            0.04,   # Path depth
            -0.12,  # Has HTTPS (good)
            0.18,   # TLD suspicion
            0.22,   # Pattern score
            0.10,   # Redirect depth
            0.08,   # Special char ratio
            0.06,   # Entropy delta
            -0.08   # Domain age proxy (good)
        ])
        self.threshold_safe = 0.3
        self.threshold_malicious = 0.7
    
    def predict(self, features: np.ndarray) -> float:
        """Predict threat probability using weighted features."""
        # Normalize features
        normalized = np.minimum(features / np.array([
            200, 5.0, 1.0, 10, 10, 1, 5, 10, 1, 3, 1.0, 10, 1.0, 2.0, 1.0
        ]), 1.0)
        
        # Calculate weighted score
        score = np.dot(normalized, self.feature_weights)
        
        # Apply sigmoid
        probability = float(1 / (1 + np.exp(-score)))
        
        return probability
    
    def classify(self, url: str, phase1_data: Dict = None, phase2_data: Dict = None) -> Dict:
        """Classify URL using feature extraction and prediction."""
        # Extract features and predict
        features = extract_features(url, phase1_data, phase2_data)
        threat_prob = self.predict(features)
        
        # Routing logic based on thresholds
        if threat_prob < self.threshold_safe:
            verdict, action = 'safe', 'early_exit'
        elif threat_prob <= self.threshold_malicious:
            verdict, action = 'uncertain', 'send_to_bloom_filter'
        else:
            verdict, action = 'malicious', 'flag_and_register'
        
        return {
            'url': url,
            'features': features.tolist(),
            'threat_probability': threat_prob,
            'verdict': verdict,
            'action': action
        }


class NeuralClassifier:
    """Main class for Phase 3 neural classification."""
    
    def __init__(self, model_path='models/url_classifier.h5'):
        if TENSORFLOW_AVAILABLE:
            self.classifier = DeepNeuralClassifier(model_path)
        else:
            self.classifier = FallbackClassifier()
            print("Using fallback classifier (TensorFlow not available)")
    
    def analyze_url(self, url: str, phase1_data: Dict = None, phase2_data: Dict = None) -> Dict:
        """Analyze URL using neural classifier."""
        return self.classifier.classify(url, phase1_data, phase2_data)
    
    def train(self, X_train, y_train, X_val, y_val, **kwargs):
        """Train the model (only available with TensorFlow)."""
        if hasattr(self.classifier, 'train'):
            return self.classifier.train(X_train, y_train, X_val, y_val, **kwargs)
        else:
            raise NotImplementedError("Training not available with fallback classifier")
