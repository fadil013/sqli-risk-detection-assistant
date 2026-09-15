"""Stage 2, Part 3 — hybrid field classification: rules + ML + (later)
LLM explanation. This module owns the "combine" decision; rules.py and
the trained model each just offer an opinion.

Design: rules WIN when they have an exact keyword match (confidence
0.85+) — that's a human-curated fact ("a field literally named
'password' is authentication"), and no statistical model should
override it. The ML model's job is specifically the case rules are
unsure about: a field name that's NOT in any keyword list. There, its
structural features (contains_id, contains_password, ...) can still
recognize a near-miss like "user_id_2" that a plain dictionary lookup
would call "unknown".
"""
from __future__ import annotations

import pickle
from pathlib import Path

from app.analyzer.ml_features import build_feature_vector
from app.analyzer.rules import PURPOSE_TEMPLATES, database_probability, rule_classify

MODEL_PATH = Path(__file__).parent / "ml" / "model.pkl"

_model_cache: dict | None = None


def _load_model() -> dict | None:
    global _model_cache
    if _model_cache is None and MODEL_PATH.exists():
        with open(MODEL_PATH, "rb") as f:
            _model_cache = pickle.load(f)
    return _model_cache


def classify_field(
    name: str | None,
    field_type: str,
    page_url: str,
    page_type: str,
    http_method: str | None,
    api_relation: bool,
) -> dict:
    """Returns {category, purpose, confidence, database_probability,
    rule_category, ml_category} — the last two kept for transparency/
    debugging, not part of the "official" answer.
    """
    rule_category, rule_confidence = rule_classify(name, field_type)

    ml_category, ml_confidence = None, None
    bundle = _load_model()
    if bundle is not None:
        vector = build_feature_vector(name, page_type, http_method, api_relation)
        proba = bundle["model"].predict_proba([vector])[0]
        best_idx = proba.argmax()
        ml_category = bundle["encoder"].inverse_transform([best_idx])[0]
        ml_confidence = float(proba[best_idx])

    if rule_confidence >= 0.85:
        # Exact keyword or type match — trust the rule outright.
        category, confidence = rule_category, rule_confidence
    elif ml_category is not None and rule_category == "unknown" and ml_confidence >= 0.5:
        # Rules found nothing; let the ML layer's structural
        # generalization take a swing at it.
        category, confidence = ml_category, round(ml_confidence, 2)
    else:
        # Weak substring match (0.6) or ML disagrees without strong
        # confidence — keep the rule's weaker-but-explainable answer.
        category, confidence = rule_category, rule_confidence

    return {
        "category": category,
        "purpose": PURPOSE_TEMPLATES[category],
        "confidence": round(confidence, 2),
        "database_probability": database_probability(name, page_type),
        "rule_category": rule_category,
        "ml_category": ml_category,
    }
