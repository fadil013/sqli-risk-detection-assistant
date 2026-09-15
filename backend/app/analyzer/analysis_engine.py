"""Stage 2 + 3 orchestrator: for every Input/Parameter already stored
for a website, runs classification -> risk scoring -> explanation and
persists one FieldAnalysis row each. This is the module
POST /api/v1/analyze/{website_id} calls; it reads only from the
existing recon tables and never re-crawls anything.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.analyzer.field_classifier import classify_field
from app.analyzer.risk_model import calculate_risk
from app.analyzer.llm_explainer import explain
from app.db.models import FieldAnalysis, Website


def run_analysis(session: Session, website_id: int) -> list[FieldAnalysis]:
    website = session.get(Website, website_id)
    if website is None:
        return []

    # Re-running analysis on a website replaces its prior findings
    # rather than piling up duplicates from repeated POST /analyze calls.
    # Deleting via session.delete() per-row (not a bulk query.delete())
    # keeps the identity map in sync — a bulk delete leaves stale
    # objects registered, which then collide when SQLite reuses their
    # rowid for a newly-inserted row later in this same function.
    prior = (
        session.query(FieldAnalysis)
        .filter(FieldAnalysis.page_id.in_([p.id for p in website.pages]))
        .all()
    )
    for row in prior:
        session.delete(row)
    session.flush()

    created: list[FieldAnalysis] = []

    for page in website.pages:
        api_relation = len(page.api_endpoints) > 0

        candidates = [(inp.id, "input", inp.name, inp.method, inp.type) for inp in page.inputs]
        candidates += [
            (param.id, "parameter", param.name, "GET", "text")  # URL params have no HTML input type
            for param in page.parameters
        ]

        for source_id, source_type, field_name, http_method, field_type in candidates:
            classification = classify_field(
                field_name,
                field_type,
                page.url,
                page.page_type,
                http_method,
                api_relation,
            )
            risk = calculate_risk(
                classification["category"], page.url, http_method, classification["database_probability"]
            )
            explanation = explain(
                field_name,
                page.url,
                classification["category"],
                classification["confidence"],
                risk["risk_score"],
                risk["severity"],
                risk["reasons"],
            )

            row = FieldAnalysis(
                page_id=page.id,
                source_type=source_type,
                source_id=source_id,
                field_name=field_name,
                category=classification["category"],
                confidence=classification["confidence"],
                database_probability=classification["database_probability"],
                risk_score=risk["risk_score"],
                severity=risk["severity"],
                reasons="; ".join(risk["reasons"]),
                explanation=explanation,
            )
            session.add(row)
            created.append(row)

    session.commit()
    for row in created:
        session.refresh(row)
    return created
