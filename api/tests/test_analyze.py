"""
Unit tests for the analyze endpoint and core services.
Run with: pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


# ── Health ────────────────────────────────────────────────────────────────────

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "model_loaded" in data
    assert "uptime_seconds" in data


# ── Analyze ───────────────────────────────────────────────────────────────────

def test_analyze_safe_url():
    resp = client.post("/analyze", json={"url": "https://github.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["original_url"] == "https://github.com"
    assert "features" in data
    assert "prediction" in data
    assert "risk_score" in data
    assert data["risk_score"]["score"] <= 30  # whitelisted → safe


def test_analyze_suspicious_url():
    resp = client.post("/analyze", json={
        "url": "http://paypa1-secure.xyz/login/verify?account=reset"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"]["score"] > 30  # should be suspicious/malicious


def test_analyze_ip_url():
    resp = client.post("/analyze", json={"url": "http://192.168.1.1/admin"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["features"]["has_ip"] is True


def test_analyze_auto_prepend_scheme():
    """URL without scheme should be auto-prepended with http://"""
    resp = client.post("/analyze", json={"url": "google.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["original_url"].startswith("http://")


def test_analyze_empty_url():
    resp = client.post("/analyze", json={"url": ""})
    assert resp.status_code == 422  # Pydantic validation


def test_analyze_redirect_chain_structure():
    resp = client.post("/analyze", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    chain = data["redirect_chain"]
    assert isinstance(chain, list)
    assert len(chain) >= 1
    hop0 = chain[0]
    assert "url" in hop0
    assert "hop" in hop0
    assert "is_suspicious" in hop0


# ── Feature Extractor ─────────────────────────────────────────────────────────

def test_feature_extractor():
    from app.services.feature_extractor import feature_extractor_service

    features = feature_extractor_service.extract("http://paypal.secure-login.xyz/verify")
    assert features["tld_suspicious"] is True
    assert features["keyword_score"] > 0
    assert features["url_length"] > 0


def test_feature_vector_length():
    from app.services.feature_extractor import feature_extractor_service

    features = feature_extractor_service.extract("https://google.com")
    vector = feature_extractor_service.to_vector(features)
    assert len(vector) == 25


# ── Risk Scorer ───────────────────────────────────────────────────────────────

def test_risk_scorer_safe():
    from app.services.risk_scorer import risk_scorer_service
    from app.schemas.response import ThreatLevel

    prediction = {"label": ThreatLevel.SAFE, "confidence": 0.99, "threat_probability": 0.02}
    redirect_data = {"redirect_count": 0, "loop_detected": False,
                     "excessive_redirects": False, "suspicious_hops": 0, "max_hop_risk": 0.0}
    features = {k: 0 for k in [
        "has_ip", "has_at_symbol", "tld_suspicious", "brand_in_subdomain",
        "has_homograph", "keyword_score", "url_entropy", "url_length"
    ]}
    result = risk_scorer_service.score(prediction, redirect_data, features)
    assert result["score"] <= 30
    assert result["level"] == ThreatLevel.SAFE


def test_risk_scorer_malicious():
    from app.services.risk_scorer import risk_scorer_service
    from app.schemas.response import ThreatLevel

    prediction = {"label": ThreatLevel.MALICIOUS, "confidence": 0.97, "threat_probability": 0.95}
    redirect_data = {"redirect_count": 5, "loop_detected": True,
                     "excessive_redirects": True, "suspicious_hops": 3, "max_hop_risk": 0.9}
    features = {
        "has_ip": True, "has_at_symbol": True, "tld_suspicious": True,
        "brand_in_subdomain": True, "has_homograph": True,
        "keyword_score": 0.5, "url_entropy": 5.0, "url_length": 150
    }
    result = risk_scorer_service.score(prediction, redirect_data, features)
    assert result["score"] > 60
    assert result["level"] == ThreatLevel.MALICIOUS
