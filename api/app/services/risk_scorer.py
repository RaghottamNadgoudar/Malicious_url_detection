"""
Risk Scorer Service
Combines ML probability, redirect signals, and heuristic features
into a unified 0–100 integer risk score.

  0 – 30   →  Safe
 31 – 60   →  Suspicious
 61 – 100  →  Malicious
"""

from typing import Dict

from app.schemas.response import ThreatLevel
from app.utils.logger import get_logger

logger = get_logger("services.risk_scorer")


class RiskScorerService:
    """
    Produces a unified risk score from all upstream signals.
    """

    # Contribution caps for each signal group (sum ≤ 100)
    _ML_WEIGHT = 55          # ML probability → up to 55 pts
    _REDIRECT_WEIGHT = 25    # Redirect chain signals → up to 25 pts
    _HEURISTIC_WEIGHT = 20   # Structural heuristic signals → up to 20 pts

    def score(
        self,
        prediction: Dict,        # output of PredictorService.predict()
        redirect_data: Dict,     # output of RedirectAnalyzerService.analyze()
        features: Dict,          # output of FeatureExtractorService.extract()
    ) -> Dict:
        """
        Returns:
            score: int [0, 100]
            level: ThreatLevel
            breakdown: dict of component contributions
        """
        # ── ML component ──────────────────────────────────────────────────────
        ml_prob = prediction.get("threat_probability", 0.0)
        ml_pts = round(ml_prob * self._ML_WEIGHT)

        # ── Redirect component ────────────────────────────────────────────────
        redirect_pts = 0
        redirect_count = redirect_data.get("redirect_count", 0)
        loop_detected = redirect_data.get("loop_detected", False)
        excessive = redirect_data.get("excessive_redirects", False)
        suspicious_hops = redirect_data.get("suspicious_hops", 0)
        max_hop_risk = redirect_data.get("max_hop_risk", 0.0)

        if loop_detected:
            redirect_pts += 10
        if excessive:
            redirect_pts += 8
        redirect_pts += min(redirect_count * 2, 5)       # each redirect ≤ 5 pts
        redirect_pts += min(suspicious_hops * 3, 9)     # suspicious hops ≤ 9 pts
        redirect_pts = min(redirect_pts, self._REDIRECT_WEIGHT)

        # ── Heuristic component ───────────────────────────────────────────────
        heuristic_pts = 0
        if features.get("has_ip"):
            heuristic_pts += 6
        if features.get("has_at_symbol"):
            heuristic_pts += 4
        if features.get("tld_suspicious"):
            heuristic_pts += 5
        if features.get("brand_in_subdomain"):
            heuristic_pts += 6
        if features.get("has_homograph"):
            heuristic_pts += 7
        if features.get("keyword_score", 0) > 0.15:
            heuristic_pts += 4
        if features.get("url_entropy", 0) > 4.5:
            heuristic_pts += 3
        if features.get("url_length", 0) > 100:
            heuristic_pts += 2
        heuristic_pts = min(heuristic_pts, self._HEURISTIC_WEIGHT)

        total = min(ml_pts + redirect_pts + heuristic_pts, 100)

        # ── Level assignment ──────────────────────────────────────────────────
        if total <= 30:
            level = ThreatLevel.SAFE
        elif total <= 60:
            level = ThreatLevel.SUSPICIOUS
        else:
            level = ThreatLevel.MALICIOUS

        breakdown = {
            "ml_contribution": ml_pts,
            "redirect_contribution": redirect_pts,
            "heuristic_contribution": heuristic_pts,
        }

        return {"score": total, "level": level, "breakdown": breakdown}


# ── Module-level singleton ────────────────────────────────────────────────────
risk_scorer_service = RiskScorerService()
