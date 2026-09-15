"""Turns page-level/request-level signals (URL, page_type from
recon.py's classify_page, HTTP method, whether the page fires API
calls) into the "context" half of a field's features. `field_classifier.py`
owns the field-name half (is this literally named "password"?); this
module owns "where does the field live, and does that location matter?".

Kept separate from field_classifier.py because the same context (e.g.
"/login, POST, authentication page") should push confidence up for a
"password" field and mean nothing for an unrelated "theme" field —
context is a multiplier on field identity, not a classification on
its own.
"""
from __future__ import annotations

from urllib.parse import urlparse

from app.analyzer.knowledge_base import PAGE_IMPORTANCE_SCORES

PAGE_TYPE_DESCRIPTIONS = {
    "authentication": "authentication page",
    "admin": "admin page",
    "checkout": "checkout page",
    "search": "search page",
    "api": "API page",
    "general": "general page",
}


def page_importance_score(page_url: str) -> int:
    """Stage 3's "page importance" score component — the highest-value
    keyword found in the path, or 0 if none match.
    """
    path = urlparse(page_url).path.lower()
    return max((score for keyword, score in PAGE_IMPORTANCE_SCORES.items() if keyword in path), default=0)


def analyze_context(
    page_url: str,
    page_type: str,
    http_method: str | None,
    api_relation: bool,
) -> dict:
    """Returns the context feature block merged into a field's full
    feature dict downstream by field_classifier.py.
    """
    method = (http_method or "GET").upper()
    return {
        "context": PAGE_TYPE_DESCRIPTIONS.get(page_type, "general page"),
        "page_type": page_type,
        "http_method": method,
        "is_authentication_context": page_type in ("authentication", "admin"),
        "is_api_context": api_relation,
        "page_importance_score": page_importance_score(page_url),
    }
