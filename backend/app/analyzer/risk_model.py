"""Stage 3 — Risk Prediction Engine.

Turns a field classification (Stage 2's output) into a 0-100 risk
score, severity bucket, and a list of plain-English reasons. This is
still NOT an SQLi verdict — it's a prioritization score ("which of the
200 fields this recon found deserve a security analyst's attention
first"), built from additive, individually-explainable factors so
every point on the score traces back to a stated reason.
"""
from __future__ import annotations

from app.analyzer.context_analyzer import page_importance_score
from app.analyzer.knowledge_base import FIELD_IMPORTANCE_SCORES, METHOD_SCORES

DATABASE_PROBABILITY_WEIGHT = 20  # max points contributed by database_probability (0-1 scaled)


def _severity(score: int) -> str:
    if score <= 30:
        return "LOW"
    if score <= 70:
        return "MEDIUM"
    return "HIGH"


def calculate_risk(
    category: str,
    page_url: str,
    http_method: str | None,
    database_probability: float,
) -> dict:
    method = (http_method or "GET").upper()

    field_points = FIELD_IMPORTANCE_SCORES.get(category, 0)
    page_points = page_importance_score(page_url)
    method_points = METHOD_SCORES.get(method, 0)
    db_points = round(database_probability * DATABASE_PROBABILITY_WEIGHT)

    raw_score = field_points + page_points + method_points + db_points
    score = max(0, min(100, raw_score))

    reasons = []
    if field_points >= 20:
        reasons.append(f"Field category '{category}' is high-value ({field_points} pts)")
    elif field_points > 0:
        reasons.append(f"Field category '{category}' carries some sensitivity ({field_points} pts)")
    if page_points > 0:
        reasons.append(f"Located on a security-relevant page ({page_points} pts)")
    if method_points >= 20:
        reasons.append(f"Submitted via {method}, which changes server-side state ({method_points} pts)")
    if database_probability >= 0.6:
        reasons.append(f"Likely used in a database lookup or query (probability {database_probability})")
    if not reasons:
        reasons.append("No strong risk signals found")

    return {
        "risk_score": score,
        "severity": _severity(score),
        "reasons": reasons,
    }
