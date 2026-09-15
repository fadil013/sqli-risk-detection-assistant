"""Phase 1 / 1.5 — single-page discovery.

Loads ONE page with a real browser (Playwright) so JavaScript-rendered
forms are visible, then parses the rendered DOM with BeautifulSoup to
pull out forms, standalone inputs, buttons, query-string parameters,
same-domain links (for recon.py to queue), and real network calls the
page fired while loading.

Security note (read this before wiring this up to anything):
This module is READ-ONLY. It never fills in or submits a form, never
sends crafted payloads, and never follows links off the target's own
domain itself (link *discovery* happens here; link *following* is
recon.py's job, and it enforces the same-domain rule again there).
That's a deliberate boundary: fetching a page an authorized tester
points us at is normal recon; auto-filling login forms starts to look
like an attack. Keep it that way in later phases.

SSRF: `discover()` checks the target against `ssrf_guard.assert_safe_url`
before fetching anything — loopback/private/link-local/reserved IPs
(including the 169.254.169.254 cloud metadata endpoint) are rejected
with an error in `result.errors` rather than fetched.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Browser, Request

from app.crawler.ssrf_guard import UnsafeUrlError, assert_safe_url
from app.models.schemas import (
    ApiEndpoint,
    CrawlResult,
    FormInfo,
    InputField,
    StandaloneInput,
    UrlParameter,
)

# Tags whose values are actually submitted as form data.
FIELD_TAGS = ["input", "textarea", "select"]

# Requests to these Playwright resource types are page-initiated data
# calls (what Feature 5 wants) — not the images/fonts/stylesheets the
# page also loads, which aren't "API endpoints" in any useful sense.
API_RESOURCE_TYPES = {"fetch", "xhr"}


def _page_path(url: str) -> str:
    """Returns the full page URL (not just the path).

    Kept as a named helper (rather than inlining `url` at each call
    site) so the "which page did we find this on" concept has one
    definition. It used to return path-only (e.g. "/login"), but that
    made it impossible to distinguish query-string page variants
    (product.html?id=1 vs ?id=2) from each other or to key a DB Page
    row consistently with PageInfo.url in recon.py — both now use the
    full URL as the identifier.
    """
    return url


def _extract_forms(soup: BeautifulSoup, page_url: str) -> list[FormInfo]:
    forms: list[FormInfo] = []

    for form_tag in soup.find_all("form"):
        raw_action = form_tag.get("action") or page_url
        action = urljoin(page_url, raw_action)
        method = (form_tag.get("method") or "GET").upper()

        inputs: list[InputField] = []
        for field in form_tag.find_all(FIELD_TAGS):
            field_type = field.get("type", "text") if field.name == "input" else field.name
            inputs.append(
                InputField(
                    name=field.get("name"),
                    id=field.get("id"),
                    type=field_type or "text",
                    placeholder=field.get("placeholder"),
                    required=field.has_attr("required"),
                    autocomplete=field.get("autocomplete"),
                )
            )

        button_labels = [
            btn.get_text(strip=True) or btn.get("value", "")
            for btn in form_tag.find_all(["button", "input"])
            if btn.name == "button" or btn.get("type") in ("submit", "button")
        ]
        button_labels = [b for b in button_labels if b]

        forms.append(
            FormInfo(
                action=action,
                method=method,
                page=_page_path(page_url),
                inputs=inputs,
                button_labels=button_labels,
            )
        )

    return forms


def _extract_standalone_inputs(soup: BeautifulSoup, page_url: str) -> list[StandaloneInput]:
    """Fields NOT inside a <form> — the React-search-box case (Feature 4).

    We already parse the DOM *after* Playwright ran the page's
    JavaScript, so a JS-injected <input> is physically present in
    `soup` here just like a static one — no special "wait for React"
    logic needed, we just have to remember to look outside <form> too.
    """
    standalone: list[StandaloneInput] = []
    for field in soup.find_all(FIELD_TAGS):
        if field.find_parent("form") is not None:
            continue  # already captured by _extract_forms
        field_type = field.get("type", "text") if field.name == "input" else field.name
        standalone.append(
            StandaloneInput(
                name=field.get("name"),
                id=field.get("id"),
                type=field_type or "text",
                placeholder=field.get("placeholder"),
                page=_page_path(page_url),
            )
        )
    return standalone


def _extract_url_parameters(soup: BeautifulSoup, page_url: str) -> list[UrlParameter]:
    """Pull query-string parameters off <a href> links on the page.

    These are GET-based inputs (?id=5, ?search=foo) that a
    forms-only scan would completely miss, and they're some of the
    most classic SQLi entry points (?id=... on a details page).
    """
    params: list[UrlParameter] = []
    seen: set[tuple[str, str]] = set()

    for a_tag in soup.find_all("a", href=True):
        absolute = urljoin(page_url, a_tag["href"])
        query = urlparse(absolute).query
        if not query:
            continue

        for name, values in parse_qs(query).items():
            key = (name, absolute)
            if key in seen:
                continue
            seen.add(key)
            params.append(
                UrlParameter(
                    name=name,
                    example_value=values[0] if values else None,
                    source_url=absolute,
                    page=_page_path(page_url),
                )
            )

    return params


def _extract_same_domain_links(soup: BeautifulSoup, page_url: str) -> list[str]:
    """Absolute, same-host links — the queue feedstock for recon.py.

    Deliberately excludes mailto:/tel:/javascript: pseudo-links and
    common static-asset extensions, which aren't "pages" and would
    just waste crawl budget without ever containing a form.
    """
    start_host = urlparse(page_url).netloc
    skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico", ".pdf", ".woff", ".woff2")

    links: list[str] = []
    seen: set[str] = set()
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue

        absolute = urljoin(page_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https") or parsed.netloc != start_host:
            continue
        if parsed.path.lower().endswith(skip_ext):
            continue

        normalized = absolute.split("#")[0]  # fragments aren't distinct pages
        if normalized in seen:
            continue
        seen.add(normalized)
        links.append(normalized)

    return links


async def _load_page(
    browser: Browser, url: str, timeout_seconds: int
) -> tuple[str | None, str | None, list[ApiEndpoint], list[str], dict[str, str]]:
    """Navigate to `url` using an already-open browser and return
    (title, html, api_endpoints, errors, response_headers).

    Takes an existing Browser so recon.py can reuse one browser
    process across a whole multi-page crawl instead of paying
    Chromium's ~1s startup cost per page.
    """
    api_endpoints: list[ApiEndpoint] = []
    errors: list[str] = []
    response_headers: dict[str, str] = {}

    page = await browser.new_page()

    def _on_request(req: Request) -> None:
        # Passive listener only — we observe what the page's own JS
        # requests while loading, we never issue requests ourselves.
        if req.resource_type in API_RESOURCE_TYPES:
            parameters: list[str] = []
            if req.method in ("POST", "PUT", "PATCH"):
                try:
                    body = req.post_data_json
                    if isinstance(body, dict):
                        parameters = list(body.keys())
                except Exception:
                    pass  # body isn't JSON (form-encoded, binary, etc.) — endpoint is still recorded
            api_endpoints.append(
                ApiEndpoint(
                    endpoint=urlparse(req.url).path or "/",
                    method=req.method,
                    full_url=req.url,
                    page=_page_path(url),
                    parameters=parameters,
                    source="javascript",
                )
            )

    def _on_response(resp) -> None:
        # Only the top-level document's headers matter for tech
        # fingerprinting (Server, X-Powered-By, ...) — sub-resource
        # responses would just add noise.
        if resp.url == url:
            response_headers.update(resp.headers)

    page.on("request", _on_request)
    page.on("response", _on_response)

    try:
        try:
            # "networkidle" waits for zero in-flight network activity,
            # which real sites (analytics beacons, chat widgets,
            # polling) often never reach — that hangs the crawl until
            # timeout. "domcontentloaded" + a short settle buffer gets
            # us the fully-JS-rendered DOM without that failure mode.
            await page.goto(url, timeout=timeout_seconds * 1000, wait_until="domcontentloaded")
            await page.wait_for_timeout(1000)
        except Exception as exc:  # navigation timeout, DNS failure, refused conn, etc.
            errors.append(f"Failed to load {url}: {exc}")
            return None, None, api_endpoints, errors, response_headers

        title = await page.title()
        html = await page.content()
        return title, html, api_endpoints, errors, response_headers
    finally:
        await page.close()


async def discover(url: str, timeout_seconds: int = 15) -> CrawlResult:
    """Render `url` in a headless browser and extract its input surface.

    Single-page entry point: launches its own browser. For a
    multi-page crawl, use recon.py instead — it reuses one browser
    across all pages for speed.
    """
    result = CrawlResult(target_url=url)

    try:
        assert_safe_url(url)
    except UnsafeUrlError as exc:
        result.errors = [str(exc)]
        return result

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            title, html, api_endpoints, errors, _headers = await _load_page(browser, url, timeout_seconds)
        finally:
            await browser.close()

    result.errors = errors
    if html is None:
        return result

    result.page_title = title
    result.api_endpoints = api_endpoints
    soup = BeautifulSoup(html, "html.parser")
    result.forms = _extract_forms(soup, url)
    result.standalone_inputs = _extract_standalone_inputs(soup, url)
    result.url_parameters = _extract_url_parameters(soup, url)
    result.links = _extract_same_domain_links(soup, url)
    return result
