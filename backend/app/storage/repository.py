"""Persists a ReconResult into Website/Page/Input/Parameter/ApiEndpoint/
Technology/CrawlSession tables (Feature 6, extended in Stage 1). Kept
separate from recon.py so the crawler itself has no database
dependency and stays easy to unit-test in isolation.
"""
from __future__ import annotations

import datetime
import json

from sqlalchemy.orm import Session

from app.db.models import ApiEndpointRow, CrawlSession, Input, Page, Parameter, Technology, Website
from app.models.schemas import ReconResult


def save_recon_result(
    session: Session, result: ReconResult, max_depth: int, max_pages: int
) -> Website:
    website = Website(url=result.target)
    session.add(website)
    session.flush()  # assigns website.id without committing yet

    pages_by_url: dict[str, Page] = {}

    # Pre-create a row for every page that was actually visited — not
    # just the ones that happen to have an input/parameter/API call on
    # them — so a plain content page still shows up in pages_discovered.
    for meta in result.pages:
        page = Page(
            website_id=website.id,
            url=meta.url,
            title=meta.title,
            page_type=meta.page_type,
            importance=meta.importance,
            response_headers=json.dumps(meta.response_headers) if meta.response_headers else None,
        )
        session.add(page)
        session.flush()
        pages_by_url[meta.url] = page

    def get_or_create_page(page_url: str) -> Page:
        if page_url not in pages_by_url:
            # Shouldn't normally happen (every finding comes from a
            # page we just crawled), but stay defensive rather than
            # crash the whole persistence step over one orphan row.
            page = Page(website_id=website.id, url=page_url)
            session.add(page)
            session.flush()
            pages_by_url[page_url] = page
        return pages_by_url[page_url]

    for finding in result.inputs_found:
        page = get_or_create_page(finding.page)
        session.add(
            Input(
                page_id=page.id,
                name=finding.field,
                type=finding.field_type,
                source=finding.type,
                method=finding.method,
            )
        )

    for param in result.parameters_found:
        page = get_or_create_page(param.page)
        session.add(
            Parameter(
                page_id=page.id,
                name=param.name,
                example_value=param.example_value,
                risk_candidate=param.risk_candidate,
            )
        )

    for endpoint in result.api_endpoints:
        page = get_or_create_page(endpoint.page)
        session.add(
            ApiEndpointRow(
                page_id=page.id,
                endpoint=endpoint.endpoint,
                method=endpoint.method,
                parameters=",".join(endpoint.parameters) if endpoint.parameters else None,
                source=endpoint.source,
            )
        )

    for tech in result.technologies:
        session.add(
            Technology(
                website_id=website.id,
                name=tech.name,
                category=tech.category,
                confidence=tech.confidence,
            )
        )

    session.add(
        CrawlSession(
            website_id=website.id,
            status="completed",
            max_depth=max_depth,
            max_pages=max_pages,
            pages_scanned=result.pages_scanned,
            completed_at=datetime.datetime.now(datetime.UTC),
        )
    )

    session.commit()
    session.refresh(website)
    return website
