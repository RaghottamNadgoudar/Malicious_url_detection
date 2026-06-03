"""
Pydantic schemas — Response models.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class ThreatLevel(str, Enum):
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"
    UNKNOWN = "Unknown"


class RedirectHop(BaseModel):
    hop: int
    url: str
    status_code: Optional[int] = None
    is_suspicious: bool = False


class FeatureSet(BaseModel):
    url_length: int
    domain_length: int
    subdomain_depth: int
    path_depth: int
    query_length: int
    num_query_params: int
    dot_count: int
    hyphen_count: int
    digit_ratio: float
    uppercase_ratio: float
    special_char_ratio: float
    url_entropy: float
    domain_entropy: float
    has_https: bool
    tld_suspicious: bool
    has_ip: bool
    has_at_symbol: bool
    double_slash_path: bool
    has_suspicious_port: bool
    redirect_depth: int
    keyword_score: float
    brand_in_subdomain: bool
    has_homograph: bool
    domain_age_proxy: float
    chain_length: int


class MLPrediction(BaseModel):
    label: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0)
    threat_probability: float = Field(ge=0.0, le=1.0)


class RiskScore(BaseModel):
    score: int = Field(ge=0, le=100)
    level: ThreatLevel
    breakdown: Dict[str, Any] = Field(default_factory=dict)


class AnalyzeResponse(BaseModel):
    # Input
    original_url: str
    # Expansion
    expanded_url: str
    is_shortened: bool
    shortener_domain: Optional[str] = None
    # Redirect chain
    redirect_chain: List[RedirectHop] = Field(default_factory=list)
    redirect_count: int = 0
    loop_detected: bool = False
    excessive_redirects: bool = False
    # Features
    features: FeatureSet
    # ML
    prediction: MLPrediction
    # Risk
    risk_score: RiskScore
    # Meta
    analysis_time_ms: float
    errors: List[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    model_loaded: bool
    uptime_seconds: float
