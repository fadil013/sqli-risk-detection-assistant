from fastapi import APIRouter, HTTPException

from app.analyzer.analysis_engine import run_analysis
from app.analyzer.feature_extractor import extract_features
from app.analyzer.owasp_engine import run_owasp_analysis
from app.crawler.discovery import discover
from app.crawler.recon import recon
from app.db.models import CrawlSession, FieldAnalysis, OwaspFindingRow, Page, Website
from app.db.session import get_session, init_db
from app.models.schemas import CrawlRequest, CrawlResult, ReconRequest, ReconResult
from app.reports.generator import build_application_map, build_report
from app.storage.repository import save_recon_result

router = APIRouter()


@router.post("/crawl", response_model=CrawlResult)
async def crawl(request: CrawlRequest) -> CrawlResult:
    """Discover forms, inputs, and URL parameters on a single page.

    Kept for single-page use (e.g. quick checks); for a full-site
    sweep use POST /recon instead.
    """
    result = await discover(str(request.url), request.timeout_seconds)
    if result.errors and not result.forms and not result.url_parameters:
        # Page never loaded at all — surface it as a 502, not a 200
        # with an empty report that looks like "no vulnerabilities found".
        raise HTTPException(status_code=502, detail=result.errors)
    return result


@router.post("/recon", response_model=ReconResult)
async def recon_endpoint(request: ReconRequest) -> ReconResult:
    """Stage 1 — priority-ordered, sitemap-seeded, same-domain multi-page
    reconnaissance. Crawls up to `max_pages` pages, `max_depth`
    link-hops deep from `request.url`, fingerprints the site's stack,
    classifies each page (auth/admin/api/...), and persists everything
    (Feature 6 + Stage "DATABASE IMPROVEMENT") before returning the
    aggregated report.

    Runs synchronously — see GET /recon/{website_id} for why that's a
    deliberate scope decision, not an oversight.
    """
    result = await recon(
        str(request.url), request.max_depth, request.max_pages, request.timeout_seconds
    )
    if result.pages_scanned == 0:
        raise HTTPException(status_code=502, detail=result.errors)

    init_db()
    session = get_session()
    try:
        website = save_recon_result(session, result, request.max_depth, request.max_pages)
        result.website_id = website.id
    finally:
        session.close()

    return result


@router.get("/recon/{website_id}")
async def recon_status(website_id: int) -> dict:
    """Scan status lookup.

    `recon()` is synchronous today (the POST above only returns once
    the whole crawl is done), so this will always report "completed"
    for a website_id that exists — there's no in-progress state to
    observe yet. It exists now so callers can already code against the
    eventual async contract; wiring up a real background job queue is
    future work, not part of this reconnaissance-engine phase.
    """
    init_db()
    session = get_session()
    try:
        crawl_session = (
            session.query(CrawlSession)
            .filter(CrawlSession.website_id == website_id)
            .order_by(CrawlSession.id.desc())
            .first()
        )
        if crawl_session is None:
            raise HTTPException(status_code=404, detail="Unknown website_id")
        return {
            "website_id": website_id,
            "status": crawl_session.status,
            "pages_scanned": crawl_session.pages_scanned,
            "max_depth": crawl_session.max_depth,
            "max_pages": crawl_session.max_pages,
            "started_at": crawl_session.started_at,
            "completed_at": crawl_session.completed_at,
        }
    finally:
        session.close()


@router.get("/map/{website_id}")
async def application_map(website_id: int) -> dict:
    """Stage 2 — application structure map, grouped by page type."""
    init_db()
    session = get_session()
    try:
        result = build_application_map(session, website_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Unknown website_id")
        return result
    finally:
        session.close()


@router.get("/report/{website_id}")
async def report(website_id: int) -> dict:
    """Human-readable reconnaissance summary — what was found, not a
    risk verdict (no AI has scored anything yet)."""
    init_db()
    session = get_session()
    try:
        result = build_report(session, website_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Unknown website_id")
        return result
    finally:
        session.close()


@router.get("/features/{website_id}")
async def features(website_id: int) -> list[dict]:
    """Stage 3/4 — flat, ML-ready feature list for Phase 2's classifier."""
    init_db()
    session = get_session()
    try:
        return extract_features(session, website_id)
    finally:
        session.close()


@router.post("/analyze/{website_id}")
async def analyze(website_id: int) -> dict:
    """Stage 2/3 — runs field classification + risk scoring over every
    input/parameter already discovered for this website and persists
    the results. Does not re-crawl; requires POST /recon to have run
    for this website_id first.
    """
    init_db()
    session = get_session()
    try:
        website = session.get(Website, website_id)
        if website is None:
            raise HTTPException(status_code=404, detail="Unknown website_id")
        results = run_analysis(session, website_id)
        return {
            "website_id": website_id,
            "fields_analyzed": len(results),
            "high_severity_count": sum(1 for r in results if r.severity == "HIGH"),
        }
    finally:
        session.close()


@router.get("/analysis/{website_id}")
async def analysis(website_id: int) -> list[dict]:
    """Returns every stored FieldAnalysis for this website — the
    classifications, risk scores, and explanations from a prior
    POST /analyze/{website_id} call.
    """
    init_db()
    session = get_session()
    try:
        rows = (
            session.query(FieldAnalysis)
            .join(Page)
            .filter(Page.website_id == website_id)
            .all()
        )
        return [
            {
                "field_name": r.field_name,
                "page": r.page.url,
                "source_type": r.source_type,
                "category": r.category,
                "confidence": r.confidence,
                "database_probability": r.database_probability,
                "risk_score": r.risk_score,
                "severity": r.severity,
                "reasons": r.reasons.split("; "),
                "explanation": r.explanation,
            }
            for r in rows
        ]
    finally:
        session.close()


@router.post("/owasp/{website_id}")
async def owasp_analyze(website_id: int) -> dict:
    """Stage 5 — runs passive OWASP Top 10 detection over an
    already-crawled website and generates a RAG-grounded remediation
    (local knowledge-base retrieval + WhiteRabbitNeo, or the KB text
    itself if LLM_EXPLAINER_BACKEND isn't set to lmstudio) for each
    finding. Does not re-crawl; requires POST /recon to have run first.
    """
    init_db()
    session = get_session()
    try:
        website = session.get(Website, website_id)
        if website is None:
            raise HTTPException(status_code=404, detail="Unknown website_id")
        rows = run_owasp_analysis(session, website_id)
        return {
            "website_id": website_id,
            "findings_count": len(rows),
            "high_severity_count": sum(1 for r in rows if r.severity == "HIGH"),
        }
    finally:
        session.close()


@router.get("/owasp/{website_id}")
async def owasp_findings(website_id: int) -> list[dict]:
    """Returns every stored OwaspFindingRow for this website — the
    category, evidence, severity, and remediation from a prior
    POST /owasp/{website_id} call.
    """
    init_db()
    session = get_session()
    try:
        rows = (
            session.query(OwaspFindingRow)
            .join(Page)
            .filter(Page.website_id == website_id)
            .all()
        )
        return [
            {
                "category": r.category,
                "page": r.page.url,
                "evidence": r.evidence,
                "severity": r.severity,
                "description": r.description,
                "remediation": r.remediation,
            }
            for r in rows
        ]
    finally:
        session.close()
