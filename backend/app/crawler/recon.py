"""Phase 1.5 / Stage 1 — Advanced Website Reconnaissance Engine.

Turns single-page discovery into a same-domain, depth-limited,
priority-ordered crawl: a breadth-first-ish walk starting at one URL
(plus any pages robots.txt/sitemap.xml advertise), following only
links that stay on the same host, up to `max_depth` hops and
`max_pages` total pages, visiting security-relevant pages (login,
admin, api, checkout, ...) before decorative ones.

Security boundary (same one discovery.py documents, restated here
because this is the module that actually decides what to fetch next):
this crawler only ever visits pages by following <a href> links it
found on a page it already loaded, or URLs a site's own robots.txt /
sitemap.xml publicly advertise — it never guesses URLs, never
brute-forces paths, and never leaves the starting domain. That keeps
it squarely in "map what's already reachable/advertised" territory
rather than "probe for hidden things."
"""
from __future__ import annotations

import itertools
from urllib.parse import urlparse

from playwright.async_api import async_playwright
from bs4 import BeautifulSoup

from app.crawler.discovery import (
    _extract_forms,
    _extract_same_domain_links,
    _extract_standalone_inputs,
    _extract_url_parameters,
    _load_page,
)
from app.crawler.sitemap import discover_seed_urls
from app.crawler.ssrf_guard import UnsafeUrlError, assert_safe_url
from app.crawler.technology import fingerprint
from app.crawler.url_utils import classify_page, crawl_priority, normalize_url
from app.models.schemas import (
    InputFinding,
    ParameterFinding,
    PageInfo,
    ReconResult,
    TechFinding,
)

# Parameter names that, in practice, almost always end up in a WHERE
# clause or lookup query somewhere on the backend. Used only to flag
# a candidate for Phase 2's AI scoring to look at first — it is not
# itself a vulnerability finding.
DB_LIKELY_PARAM_NAMES = {
    "id", "productid", "userid", "postid", "orderid", "categoryid",
    "search", "query", "q", "filter", "sort", "name", "email", "username",
}


async def recon(
    start_url: str,
    max_depth: int = 2,
    max_pages: int = 25,
    timeout_seconds: int = 15,
) -> ReconResult:
    result = ReconResult(target=start_url, pages_scanned=0)

    try:
        assert_safe_url(start_url)
    except UnsafeUrlError as exc:
        result.errors = [str(exc)]
        return result

    start_host = urlparse(start_url).netloc
    visited: set[str] = set()  # normalized URLs (Stage 1.1 dedup key)

    # Priority queue: (priority, insertion_order, url, depth). The
    # insertion counter breaks ties deterministically since raw URLs
    # aren't orderable against each other.
    counter = itertools.count()
    queue: list[tuple[int, int, str, int]] = [(crawl_priority(start_url), next(counter), start_url, 0)]

    for seed_url in await discover_seed_urls(start_url, timeout_seconds):
        # Sitemap/robots.txt entries are "real" pages the site already
        # advertises, so we treat them like depth-1 links rather than
        # depth-0 — they still count against max_depth normally.
        queue.append((crawl_priority(seed_url), next(counter), seed_url, 1))

    seen_params: set[tuple[str, str, str | None]] = set()  # dedupe (Feature 7)
    fingerprinted = False

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            while queue and len(visited) < max_pages:
                queue.sort(key=lambda item: (item[0], item[1]))  # small queues; simplicity over heapq perf
                _priority, _order, url, depth = queue.pop(0)

                normalized = normalize_url(url)
                if normalized in visited:
                    continue
                if urlparse(url).netloc != start_host:
                    continue  # defense in depth: link extraction already filters this
                if depth > max_depth:
                    # Sitemap/robots.txt seeds are queued at depth 1 up
                    # front, independent of max_depth — without this
                    # check a max_depth=0 crawl would still visit them.
                    continue
                visited.add(normalized)

                title, html, api_endpoints, errors, headers = await _load_page(browser, url, timeout_seconds)
                result.errors.extend(errors)
                if html is None:
                    continue  # page failed to load; recorded above, don't crash the whole crawl (Feature 8)

                result.pages_scanned += 1
                result.api_endpoints.extend(api_endpoints)

                page_type, importance = classify_page(url)
                result.pages.append(
                    PageInfo(
                        url=url,
                        title=title,
                        page_type=page_type,
                        importance=importance,
                        response_headers=headers,
                    )
                )

                if not fingerprinted:
                    # Once per site is enough — a stack doesn't usually
                    # vary page to page, and skipping repeat fingerprint
                    # work keeps the crawl fast.
                    for name, category, confidence in fingerprint(html, headers):
                        result.technologies.append(TechFinding(name=name, category=category, confidence=confidence))
                    fingerprinted = True

                soup = BeautifulSoup(html, "html.parser")

                for form in _extract_forms(soup, url):
                    for field in form.inputs:
                        result.inputs_found.append(
                            InputFinding(
                                type="form",
                                page=form.page,
                                field=field.name,
                                field_type=field.type,
                                method=form.method,
                            )
                        )

                for standalone in _extract_standalone_inputs(soup, url):
                    result.inputs_found.append(
                        InputFinding(
                            type="standalone",
                            page=standalone.page,
                            field=standalone.name or standalone.id,
                            field_type=standalone.type,
                        )
                    )

                for param in _extract_url_parameters(soup, url):
                    key = (param.name, param.page, param.example_value)
                    if key in seen_params:
                        continue
                    seen_params.add(key)
                    result.parameters_found.append(
                        ParameterFinding(
                            name=param.name,
                            page=param.page,
                            example_value=param.example_value,
                            risk_candidate=param.name.lower() in DB_LIKELY_PARAM_NAMES,
                        )
                    )

                if depth < max_depth:
                    for link in _extract_same_domain_links(soup, url):
                        if normalize_url(link) not in visited:
                            queue.append((crawl_priority(link), next(counter), link, depth + 1))
        finally:
            await browser.close()

    return result
