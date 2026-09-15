"""Stage 1 feature tests: URL utils, sitemap/robots discovery,
authentication detection, technology fingerprinting, API parameter
extraction, and large(r) multi-page crawling.
"""
import pytest

from app.crawler.recon import recon
from app.crawler.sitemap import discover_seed_urls
from app.crawler.url_utils import classify_page, crawl_priority, normalize_url


# ---- pure unit tests: no browser, no network ----

def test_url_normalization_collapses_equivalent_urls():
    a = normalize_url("https://Example.com/path/?b=2&a=1#section")
    b = normalize_url("https://example.com/path?a=1&b=2")
    assert a == b


def test_crawl_priority_ranks_high_value_paths_first():
    assert crawl_priority("https://x.com/login") < crawl_priority("https://x.com/about")
    assert crawl_priority("https://x.com/about") < crawl_priority("https://x.com/static/logo.png")


def test_classify_page_login_is_critical_authentication():
    page_type, importance = classify_page("https://x.com/login")
    assert page_type == "authentication"
    assert importance == "critical"


def test_classify_page_unknown_path_is_general_low():
    page_type, importance = classify_page("https://x.com/about-us")
    assert page_type == "general"
    assert importance == "low"


# ---- integration tests against the fixture site (browser + HTTP) ----

@pytest.mark.asyncio
async def test_sitemap_and_robots_discovery(fixture_site_url):
    # robots.txt Disallow's /login-legacy.html, which is otherwise
    # unlinked from every crawlable page — this proves it's reachable
    # ONLY through the sitemap/robots discovery step (Stage 1.2).
    seeds = await discover_seed_urls(f"{fixture_site_url}/index.html")
    assert f"{fixture_site_url}/login-legacy.html" in seeds


@pytest.mark.asyncio
async def test_authentication_page_detected_end_to_end(fixture_site_url):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)
    login_page = next(p for p in result.pages if p.url.endswith("login.html"))
    assert login_page.page_type == "authentication"
    assert login_page.importance == "critical"


@pytest.mark.asyncio
async def test_technology_fingerprint_detects_react(fixture_site_url):
    # search.html carries a data-reactroot marker (see fixtures/site/search.html)
    result = await recon(f"{fixture_site_url}/search.html", max_depth=0)
    tech_names = {t.name for t in result.technologies}
    assert "React" in tech_names


@pytest.mark.asyncio
async def test_api_endpoint_post_body_parameters_extracted(fixture_site_url):
    result = await recon(f"{fixture_site_url}/api.html", max_depth=0)
    login_call = next(e for e in result.api_endpoints if e.endpoint == "/api/login")
    assert login_call.method == "POST"
    assert set(login_call.parameters) == {"email", "password"}


@pytest.mark.asyncio
async def test_large_multi_page_crawl_covers_whole_site(fixture_site_url):
    # "Large website crawling": every reachable + advertised page across
    # the fixture site, in one crawl, none missed and none duplicated.
    result = await recon(f"{fixture_site_url}/index.html", max_depth=2, max_pages=50)
    scanned_pages = {p.url.rsplit("/", 1)[-1].split("?")[0] for p in result.pages}
    assert scanned_pages == {"index.html", "login.html", "search.html", "product.html", "login-legacy.html"}
