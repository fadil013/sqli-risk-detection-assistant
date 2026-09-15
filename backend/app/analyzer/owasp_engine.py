"""Stage 5 orchestrator — runs passive OWASP checks over an already-
recon'd website, then generates a RAG-grounded remediation for each
finding, and persists both. Mirrors analysis_engine.py's pattern:
does not re-crawl, just reasons over data POST /recon already saved.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.analyzer.llm_explainer import explain_owasp_finding
from app.analyzer.owasp_checks import run_owasp_checks
from app.db.models import OwaspFindingRow, Page, Website


def run_owasp_analysis(session: Session, website_id: int) -> list[OwaspFindingRow]:
    """Runs every passive OWASP check for `website_id`, generates a
    remediation for each finding, persists the rows (replacing any
    prior run's rows so re-running doesn't duplicate), and returns them.
    """
    website = session.get(Website, website_id)
    if website is None:
        return []

    # Delete prior rows object-by-object (not a bulk query) — same fix
    # applied in analysis_engine.py for the identical SQLAlchemy
    # identity-map corruption bug.
    pages_by_url = {page.url: page for page in website.pages}
    prior_rows = (
        session.query(OwaspFindingRow)
        .join(Page)
        .filter(Page.website_id == website_id)
        .all()
    )
    for row in prior_rows:
        session.delete(row)
    session.flush()

    findings = run_owasp_checks(website)

    rows: list[OwaspFindingRow] = []
    for finding in findings:
        page = pages_by_url.get(finding.page)
        if page is None:
            continue  # defensive: every finding.page comes from a page we just iterated
        remediation = explain_owasp_finding(
            finding.category, finding.evidence, finding.description, finding.severity
        )
        row = OwaspFindingRow(
            page_id=page.id,
            category=finding.category,
            evidence=finding.evidence,
            severity=finding.severity,
            description=finding.description,
            remediation=remediation,
        )
        session.add(row)
        rows.append(row)

    session.commit()
    for row in rows:
        session.refresh(row)
    return rows
