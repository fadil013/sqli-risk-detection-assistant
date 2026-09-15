"""Pure rule-based field classification — no ML, no I/O. This is the
security-knowledge pass: does the field's name or type match a
pattern a human analyst would recognize on sight?

Kept dependency-free of the ML layer (field_classifier.py) and of the
model-training script (ml/train_classifier.py) so both can import it
without any circular-import risk — this module is the one thing both
"sides" agree on.
"""
from __future__ import annotations

from app.analyzer.knowledge_base import (
    CATEGORY_PRIORITY,
    DATABASE_IDENTIFIERS,
    FILE_UPLOAD_TYPES,
    keyword_sets_by_category,
)

# Weaker, substring-based fallback signals — used only when a field's
# name isn't an exact match in knowledge_base's lists (e.g.
# "productIdentifier" isn't literally "productid", but obviously means
# the same thing to a human reader).
_SUBSTRING_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("authentication", ("pass", "pwd")),
    ("security_token", ("token", "secret")),
    ("payment", ("card", "cvv")),
    ("database_identifier", ("id",)),
    ("search_parameter", ("search", "query", "filter")),
]

PURPOSE_TEMPLATES = {
    "authentication": "Used for user authentication or credential verification",
    "security_token": "Carries a session or security token used to authorize requests",
    "payment": "Carries payment or financial information",
    "file_upload": "Accepts an uploaded file",
    "transaction_parameter": "Represents a transaction, order, or quantity value",
    "database_identifier": "Identifies a specific database record",
    "user_profile": "Represents user profile or personal information",
    "search_parameter": "Used to filter or search records",
    "unknown": "Purpose could not be confidently determined from its name or context",
}


def rule_classify(name: str | None, field_type: str) -> tuple[str, float]:
    """Returns (category, confidence). Confidence is 0.85 for an exact
    keyword match, 0.6 for a weaker substring match, 0.3 (i.e. "not
    sure, but let the ML layer have a say") otherwise.
    """
    lowered = (name or "").lower()
    field_type = (field_type or "text").lower()

    # Type is a stronger signal than name for these two — a field
    # named "secret_value" with type="password" is still a password.
    if field_type == "password":
        return "authentication", 0.95
    if field_type in FILE_UPLOAD_TYPES:
        return "file_upload", 0.95

    keyword_sets = keyword_sets_by_category()
    for category in CATEGORY_PRIORITY:
        if lowered in keyword_sets.get(category, set()):
            return category, 0.85

    for category, hints in _SUBSTRING_HINTS:
        if any(hint in lowered for hint in hints):
            return category, 0.6

    return "unknown", 0.3


def database_probability(name: str | None, page_type: str) -> float:
    """Heuristic score in [0, 1] — how likely this field's value ends
    up in a backend database lookup/query. Feeds both the ML feature
    vector and the final classification's transparency output.
    """
    lowered = (name or "").lower()
    if lowered in DATABASE_IDENTIFIERS:
        base = 0.85
    elif "id" in lowered:
        base = 0.6
    elif lowered in {"search", "query", "q", "filter"}:
        base = 0.55
    else:
        base = 0.2
    if page_type in ("authentication", "admin", "api"):
        base = min(0.99, base + 0.1)
    return round(base, 2)


def sensitive_keyword_score(name: str | None) -> int:
    """0-3: how many/how strong the keyword signals on this name are.
    Used as one input feature to the ML model, not a final score.
    """
    lowered = (name or "").lower()
    category, confidence = rule_classify(lowered, "text")
    if category == "unknown":
        return 0
    return 3 if confidence >= 0.85 else 1
