"""Reconnaissance report generator — the human-readable summary of a
completed crawl (Stage "REPORTING SYSTEM" in the spec). Distinct from
Phase 2's future risk report: this one describes what was FOUND, not
what's dangerous — no severity verdict here, since no AI has scored
anything yet.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import Website


def build_report(session: Session, website_id: int) -> dict | None:
    website = session.get(Website, website_id)
    if website is None:
        return None

    pages = website.pages
    inputs = [inp for page in pages for inp in page.inputs]
    parameters = [param for page in pages for param in page.parameters]
    api_endpoints = [ep for page in pages for ep in page.api_endpoints]
    auth_pages = [p for p in pages if p.page_type == "authentication"]
    high_value_params = sorted({p.name for p in parameters if p.risk_candidate})

    return {
        "target": website.url,
        "pages_discovered": len(pages),
        "inputs_discovered": len(inputs),
        "apis_discovered": len(api_endpoints),
        "authentication_pages": len(auth_pages),
        "authentication_page_urls": [p.url for p in auth_pages],
        "high_value_parameters": high_value_params,
        "technologies": [t.name for t in website.technologies],
    }


def build_application_map(session: Session, website_id: int) -> dict | None:
    """Stage 2 — application structure map, grouped by the one
    categorization axis we can actually compute today: `page_type`
    (auth/admin/checkout/search/api/general). A content-topic grouping
    ("Products", "Blog") would need page-content NLP, which is out of
    scope for a reconnaissance engine — that's a Phase 2+ concern.
    """
    website = session.get(Website, website_id)
    if website is None:
        return None

    groups: dict[str, list[dict]] = {}
    for page in website.pages:
        groups.setdefault(page.page_type, []).append(
            {
                "url": page.url,
                "importance": page.importance,
                "inputs": [{"name": i.name, "type": i.type} for i in page.inputs],
                "parameters": [{"name": p.name, "risk_candidate": p.risk_candidate} for p in page.parameters],
                "api_endpoints": [{"endpoint": e.endpoint, "method": e.method} for e in page.api_endpoints],
            }
        )

    return {"website": website.url, "categories": groups}
