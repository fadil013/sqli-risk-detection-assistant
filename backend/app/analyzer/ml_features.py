"""Structural feature extraction + fixed-order feature vectors shared
between model training (ml/train_classifier.py) and inference
(field_classifier.py). Keeping the vector-building logic in exactly
one place guarantees train and inference can never silently drift out
of sync with each other.
"""
from __future__ import annotations

from app.analyzer.rules import database_probability, sensitive_keyword_score

PAGE_TYPES = ["authentication", "admin", "checkout", "search", "api", "general"]
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]

FEATURE_NAMES = [
    "field_length",
    "contains_id",
    "contains_password",
    "contains_token",
    "contains_card",
    "contains_search",
    "page_type_encoded",
    "http_method_encoded",
    "is_api",
    "database_probability",
    "sensitive_keyword_score",
]


def _encode(value: str, options: list[str]) -> int:
    return options.index(value) if value in options else len(options)  # unseen -> one past the end


def structural_features(name: str | None) -> dict:
    lowered = (name or "").lower()
    return {
        "field_length": len(lowered),
        "contains_id": int("id" in lowered),
        "contains_password": int("pass" in lowered or "pwd" in lowered),
        "contains_token": int("token" in lowered or "secret" in lowered),
        "contains_card": int("card" in lowered or "cvv" in lowered or "cvc" in lowered),
        "contains_search": int(any(s in lowered for s in ("search", "query", "filter"))),
    }


def build_feature_vector(
    name: str | None,
    page_type: str,
    http_method: str | None,
    is_api: bool,
) -> list[float]:
    """Returns a feature vector in FEATURE_NAMES order — the exact
    input both the trained model and its training data are built from.
    """
    structural = structural_features(name)
    return [
        float(structural["field_length"]),
        float(structural["contains_id"]),
        float(structural["contains_password"]),
        float(structural["contains_token"]),
        float(structural["contains_card"]),
        float(structural["contains_search"]),
        float(_encode(page_type, PAGE_TYPES)),
        float(_encode((http_method or "GET").upper(), METHODS)),
        float(int(is_api)),
        database_probability(name, page_type),
        float(sensitive_keyword_score(name)),
    ]
