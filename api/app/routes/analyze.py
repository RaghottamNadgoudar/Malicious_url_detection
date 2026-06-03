"""
POST /analyze — main URL analysis endpoint.
Runs the full pipeline:
  [Stage 1 Pre-Filter] Trie → Bloom Ensemble → Heuristics → Decision Gate
      ↓ BLOCK → return Malicious immediately (ML skipped)
      ↓ PASS  → return Safe immediately (ML skipped)
      ↓ FORWARD →
  [Stage 2 ML Core] URL Expansion → Redirect Analysis → Features → Prediction → Risk Score
"""

import sys
import os
import time
from fastapi import APIRouter, HTTPException, status

from app.schemas.request import AnalyzeRequest
from app.schemas.response import (
    AnalyzeResponse, FeatureSet, MLPrediction, RedirectHop, RiskScore, ThreatLevel,
)
from app.services.url_expander import url_expansion_service
from app.services.redirect_analyzer import redirect_analyzer_service
from app.services.feature_extractor import feature_extractor_service
from app.services.predictor import predictor_service
from app.services.risk_scorer import risk_scorer_service
from app.utils.logger import get_logger
from app.utils.validators import is_valid_url

logger = get_logger("routes.analyze")
router = APIRouter(tags=["Analysis"])

# ── Stage 1 filter pipeline (lazy import to avoid circular deps) ──────────────
_filter_pipeline = None

def _get_filter_pipeline():
    global _filter_pipeline
    if _filter_pipeline is None:
        try:
            # Add backend/ to path so we can import backend.filters
            backend_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../../../../backend")
            )
            if backend_path not in sys.path:
                sys.path.insert(0, backend_path)
            from filters.filter_pipeline import filter_pipeline
            _filter_pipeline = filter_pipeline
            logger.info("Stage 1 filter pipeline loaded successfully.")
        except Exception as exc:
            logger.warning(f"Stage 1 filter pipeline unavailable: {exc}. Skipping pre-filter.")
            _filter_pipeline = None
    return _filter_pipeline


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a URL for security threats",
    status_code=status.HTTP_200_OK,
)
async def analyze_url(body: AnalyzeRequest) -> AnalyzeResponse:
    """
    Full pipeline analysis of a URL.

    **Stage 1 — Classical Pre-Filter** (Trie + Bloom + Heuristics):
    - Clears known-safe URLs immediately (no ML cost)
    - Blocks known-malicious URLs immediately (no ML cost)
    - Routes uncertain URLs forward to ML

    **Stage 2 — ML Core**:
    - URL Expansion → Redirect Chain Analysis → Feature Extraction → ML Prediction → Risk Score
    """
    t_start = time.perf_counter()
    url = body.url
    errors: list[str] = []

    # ── Validate URL ──────────────────────────────────────────────────────────
    valid, reason = is_valid_url(url)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid URL: {reason}",
        )

    logger.info(f"Analyzing: {url}")

    # ══════════════════════════════════════════════════════════════════════════
    # STAGE 1 — Classical Algorithm Pre-Filter
    # ══════════════════════════════════════════════════════════════════════════
    pipeline = _get_filter_pipeline()
    stage1_result = None
    ml_skipped = False

    if pipeline is not None:
        try:
            stage1_result = pipeline.run(url)
            logger.info(
                f"Stage1 | decision={stage1_result.decision.value} | "
                f"trie={stage1_result.trie_result} | "
                f"bloom_score={stage1_result.bloom_score:.2f} | "
                f"heuristic={stage1_result.heuristic_score:.2f} | "
                f"{stage1_result.elapsed_ms}ms"
            )

            from filters.filter_pipeline import PipelineDecision

            if stage1_result.decision == PipelineDecision.BLOCK:
                # ── Fast-path BLOCK: confirmed malicious, skip ML ─────────────
                ml_skipped = True
                elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)
                logger.info(f"BLOCKED by pre-filter | {elapsed_ms}ms | {url}")

                _empty_features = {k: 0 for k in [
                    "url_length", "domain_length", "subdomain_depth", "path_depth",
                    "query_length", "num_query_params", "dot_count", "hyphen_count",
                    "digit_ratio", "uppercase_ratio", "special_char_ratio",
                    "url_entropy", "domain_entropy", "has_https", "tld_suspicious",
                    "has_ip", "has_at_symbol", "double_slash_path", "has_suspicious_port",
                    "redirect_depth", "keyword_score", "brand_in_subdomain",
                    "has_homograph", "domain_age_proxy", "chain_length",
                ]}
                _empty_features.update({
                    "keyword_score": round(stage1_result.heuristic_score, 4),
                    "url_length": len(url),
                })
                _malicious_pred = {
                    "label": ThreatLevel.MALICIOUS,
                    "confidence": min(0.60 + stage1_result.bloom_score * 0.35, 0.99),
                    "threat_probability": min(0.75 + stage1_result.heuristic_score * 0.20, 0.99),
                }
                _risk = {
                    "score": max(70, int(70 + stage1_result.heuristic_score * 25)),
                    "level": ThreatLevel.MALICIOUS,
                    "breakdown": {
                        "ml_contribution": 0,
                        "redirect_contribution": 0,
                        "heuristic_contribution": max(70, int(70 + stage1_result.heuristic_score * 25)),
                        "source": "stage1_pre_filter",
                    },
                }
                return AnalyzeResponse(
                    original_url=url,
                    expanded_url=url,
                    is_shortened=False,
                    shortener_domain=None,
                    redirect_chain=[RedirectHop(hop=0, url=url, status_code=None, is_suspicious=True)],
                    redirect_count=0,
                    loop_detected=False,
                    excessive_redirects=False,
                    features=FeatureSet(**_empty_features),
                    prediction=MLPrediction(**_malicious_pred),
                    risk_score=RiskScore(**_risk),
                    analysis_time_ms=elapsed_ms,
                    errors=[f"Blocked by Stage 1 pre-filter: {stage1_result.reason}"],
                )

            elif stage1_result.decision == PipelineDecision.PASS:
                # ── Fast-path PASS: confirmed safe, skip ML ───────────────────
                ml_skipped = True
                elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)
                logger.info(f"PASSED by pre-filter | {elapsed_ms}ms | {url}")

                _safe_features = {k: 0 for k in [
                    "url_length", "domain_length", "subdomain_depth", "path_depth",
                    "query_length", "num_query_params", "dot_count", "hyphen_count",
                    "digit_ratio", "uppercase_ratio", "special_char_ratio",
                    "url_entropy", "domain_entropy", "has_https", "tld_suspicious",
                    "has_ip", "has_at_symbol", "double_slash_path", "has_suspicious_port",
                    "redirect_depth", "keyword_score", "brand_in_subdomain",
                    "has_homograph", "domain_age_proxy", "chain_length",
                ]}
                _safe_features["url_length"] = len(url)
                _safe_features["has_https"] = url.startswith("https://")
                _safe_features["domain_age_proxy"] = 1.0

                _safe_pred = {
                    "label": ThreatLevel.SAFE,
                    "confidence": 0.99,
                    "threat_probability": 0.01,
                }
                _risk = {
                    "score": 1,
                    "level": ThreatLevel.SAFE,
                    "breakdown": {
                        "ml_contribution": 0,
                        "redirect_contribution": 0,
                        "heuristic_contribution": 1,
                        "source": "stage1_pre_filter",
                    },
                }
                return AnalyzeResponse(
                    original_url=url,
                    expanded_url=url,
                    is_shortened=False,
                    shortener_domain=None,
                    redirect_chain=[RedirectHop(hop=0, url=url, status_code=200, is_suspicious=False)],
                    redirect_count=0,
                    loop_detected=False,
                    excessive_redirects=False,
                    features=FeatureSet(**_safe_features),
                    prediction=MLPrediction(**_safe_pred),
                    risk_score=RiskScore(**_risk),
                    analysis_time_ms=elapsed_ms,
                    errors=[],
                )

            # FORWARD → fall through to ML pipeline below

        except Exception as exc:
            logger.warning(f"Stage 1 pre-filter error (bypassing): {exc}")
            errors.append(f"Stage1 warning: {exc}")

    # ══════════════════════════════════════════════════════════════════════════
    # STAGE 2 — ML Core Pipeline
    # ══════════════════════════════════════════════════════════════════════════

    # ── Step 1: URL Expansion ─────────────────────────────────────────────────
    try:
        expansion = await url_expansion_service.expand(url)
        errors.extend(expansion.get("errors", []))
    except Exception as exc:
        logger.error(f"URL expansion failed: {exc}")
        expansion = {
            "original_url": url, "expanded_url": url,
            "is_shortened": False, "shortener_domain": None,
            "redirect_chain": [{"hop": 0, "url": url, "status_code": None, "is_suspicious": False}],
            "redirect_count": 0, "loop_detected": False,
            "excessive_redirects": False, "errors": [str(exc)],
        }
        errors.append(str(exc))

    final_url: str = expansion["expanded_url"]

    # ── Step 2: Redirect Analysis ─────────────────────────────────────────────
    try:
        redirect_data = redirect_analyzer_service.analyze(expansion)
    except Exception as exc:
        logger.error(f"Redirect analysis failed: {exc}")
        redirect_data = {
            "redirect_chain": expansion.get("redirect_chain", []),
            "redirect_count": expansion.get("redirect_count", 0),
            "loop_detected": False, "excessive_redirects": False,
            "suspicious_hops": 0, "max_hop_risk": 0.0,
            "unique_domains_in_chain": 1, "cross_domain_redirect": False,
            "redirect_depth": 0, "chain_length": 1,
        }
        errors.append(str(exc))

    # ── Step 3: Feature Extraction ────────────────────────────────────────────
    try:
        features = feature_extractor_service.extract(final_url, redirect_data)
        # Enrich with heuristic signals from Stage 1 if available
        if stage1_result:
            features["keyword_score"] = max(
                features.get("keyword_score", 0),
                stage1_result.heuristic_score,
            )
        feature_vector = feature_extractor_service.to_vector(features)
    except Exception as exc:
        logger.error(f"Feature extraction failed: {exc}")
        features = {k: 0 for k in [
            "url_length", "domain_length", "subdomain_depth", "path_depth",
            "query_length", "num_query_params", "dot_count", "hyphen_count",
            "digit_ratio", "uppercase_ratio", "special_char_ratio",
            "url_entropy", "domain_entropy", "has_https", "tld_suspicious",
            "has_ip", "has_at_symbol", "double_slash_path", "has_suspicious_port",
            "redirect_depth", "keyword_score", "brand_in_subdomain",
            "has_homograph", "domain_age_proxy", "chain_length",
        ]}
        feature_vector = [0.0] * 25
        errors.append(str(exc))

    # ── Step 4: ML Prediction ─────────────────────────────────────────────────
    try:
        prediction = predictor_service.predict(final_url, feature_vector)
    except Exception as exc:
        logger.error(f"Prediction failed: {exc}")
        prediction = {
            "label": ThreatLevel.UNKNOWN,
            "confidence": 0.0,
            "threat_probability": 0.0,
        }
        errors.append(str(exc))

    # ── Step 5: Risk Scoring ──────────────────────────────────────────────────
    try:
        risk = risk_scorer_service.score(prediction, redirect_data, features)
    except Exception as exc:
        logger.error(f"Risk scoring failed: {exc}")
        risk = {"score": 0, "level": ThreatLevel.UNKNOWN, "breakdown": {}}
        errors.append(str(exc))

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)
    logger.info(
        f"Analysis complete | verdict={prediction['label']} | "
        f"risk={risk['score']} | ml_skipped={ml_skipped} | {elapsed_ms}ms"
    )

    # ── Assemble response ─────────────────────────────────────────────────────
    redirect_hops = [
        RedirectHop(
            hop=h.get("hop", i),
            url=h.get("url", ""),
            status_code=h.get("status_code"),
            is_suspicious=h.get("is_suspicious", False),
        )
        for i, h in enumerate(redirect_data.get("redirect_chain", []))
    ]

    return AnalyzeResponse(
        original_url=url,
        expanded_url=final_url,
        is_shortened=expansion.get("is_shortened", False),
        shortener_domain=expansion.get("shortener_domain"),
        redirect_chain=redirect_hops,
        redirect_count=redirect_data.get("redirect_count", 0),
        loop_detected=redirect_data.get("loop_detected", False),
        excessive_redirects=redirect_data.get("excessive_redirects", False),
        features=FeatureSet(**features),
        prediction=MLPrediction(**prediction),
        risk_score=RiskScore(**risk),
        analysis_time_ms=elapsed_ms,
        errors=errors,
    )
