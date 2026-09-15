"""Stage 3 + Stage 4 — Security Feature Extraction / AI-ready pipeline.

Turns the raw discovery rows (Input, Parameter) sitting in the
database into flat, ML-friendly feature dicts. This is explicitly
NOT the AI model (Phase 2) — it's the data-cleaning step that has to
exist first, because a classifier fed a bag of raw HTML attributes is
strictly worse than one fed a handful of well-chosen features.

Kept as pure functions over already-persisted DB rows (not something
recon.py calls inline) so it can be re-run against historical crawl
data without re-crawling anything.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.crawler.recon import DB_LIKELY_PARAM_NAMES
from app.db.models import Website

CREDENTIAL_TYPES = {"password"}
SEARCH_NAMES = {"search", "q", "query", "filter", "sort"}


def _classify_field(name: str | None, field_type: str) -> tuple[str, str, float]:
    """Returns (parameter_type, sensitivity, database_likelihood).

    database_likelihood is a heuristic score in [0, 1], not a
    calibrated probability — it exists to rank candidates for Phase
    2's classifier, not to make a final risk call on its own.
    """
    lowered = (name or "").lower()

    if field_type in CREDENTIAL_TYPES:
        return "credential", "high", 0.9
    if lowered in DB_LIKELY_PARAM_NAMES:
        return "identifier", "high", 0.85
    if lowered in SEARCH_NAMES:
        return "search", "medium", 0.6
    return "text", "low", 0.2


def extract_features(session: Session, website_id: int) -> list[dict]:
    """Stage 4 output: one feature dict per discovered input/parameter,
    matching the shape in the spec (field, page, method, features{...}).
    """
    website = session.get(Website, website_id)
    if website is None:
        return []

    features: list[dict] = []

    for page in website.pages:
        api_relation = len(page.api_endpoints) > 0
        auth_relation = page.page_type in ("authentication", "admin")

        for inp in page.inputs:
            parameter_type, sensitivity, db_likelihood = _classify_field(inp.name, inp.type)
            if auth_relation:
                db_likelihood = min(0.99, db_likelihood + 0.1)
            features.append(
                {
                    "field": inp.name,
                    "page": page.url,
                    "method": inp.method,
                    "source": inp.source,  # "form" | "standalone"
                    "features": {
                        "parameter_type": parameter_type,
                        "context": page.page_type,
                        "sensitivity": sensitivity,
                        "authentication_relation": auth_relation,
                        "database_likelihood": round(db_likelihood, 2),
                        "api_relation": api_relation,
                    },
                }
            )

        for param in page.parameters:
            parameter_type, sensitivity, db_likelihood = _classify_field(param.name, "text")
            if param.risk_candidate:
                db_likelihood = max(db_likelihood, 0.85)
            if auth_relation:
                db_likelihood = min(0.99, db_likelihood + 0.1)
            features.append(
                {
                    "field": param.name,
                    "page": page.url,
                    "method": "GET",  # URL query parameters are always GET
                    "source": "url_parameter",
                    "features": {
                        "parameter_type": parameter_type,
                        "context": page.page_type,
                        "sensitivity": sensitivity,
                        "authentication_relation": auth_relation,
                        "database_likelihood": round(db_likelihood, 2),
                        "api_relation": api_relation,
                    },
                }
            )

    return features
