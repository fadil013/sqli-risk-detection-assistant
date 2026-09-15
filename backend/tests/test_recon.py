import pytest

from app.crawler.recon import recon


@pytest.mark.asyncio
async def test_multi_page_crawl_visits_linked_pages(fixture_site_url):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=2, max_pages=25)

    assert result.errors == []
    # index, login, search, product?id=1, product?id=2, login-legacy (via
    # robots.txt Disallow) — external.example.com and mailto: must NOT count.
    assert result.pages_scanned == 6


@pytest.mark.asyncio
async def test_login_form_detected(fixture_site_url):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)

    login_fields = {
        f.field for f in result.inputs_found if f.page.endswith("login.html") and f.type == "form"
    }
    assert login_fields == {"email", "password"}

    password_field = next(
        f for f in result.inputs_found if f.page.endswith("login.html") and f.field == "password"
    )
    assert password_field.method == "POST"


@pytest.mark.asyncio
async def test_search_form_detected(fixture_site_url):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)

    search_fields = [
        f for f in result.inputs_found if f.page.endswith("search.html") and f.type == "form"
    ]
    assert len(search_fields) == 1
    assert search_fields[0].field == "q"
    assert search_fields[0].method == "GET"


@pytest.mark.asyncio
async def test_url_parameter_extraction(fixture_site_url):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=2)

    id_params = {p.example_value for p in result.parameters_found if p.name == "id"}
    assert id_params == {"1", "2"}

    # "id" is in the DB-likely name list, so it should be flagged.
    assert all(p.risk_candidate for p in result.parameters_found if p.name == "id")


@pytest.mark.asyncio
async def test_javascript_generated_input_detected(fixture_site_url):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)

    standalone = [
        f for f in result.inputs_found if f.page.endswith("search.html") and f.type == "standalone"
    ]
    assert any(f.field == "searchBox" for f in standalone)


@pytest.mark.asyncio
async def test_duplicate_pages_not_recrawled(fixture_site_url):
    # login.html, search.html, and both product.html variants all link
    # back to index.html — it must only ever be counted/crawled once.
    result = await recon(f"{fixture_site_url}/index.html", max_depth=2, max_pages=25)
    index_hits = sum(1 for f in result.inputs_found if f.page.endswith("index.html"))
    assert index_hits == 0  # index.html has no forms/inputs at all
    assert result.pages_scanned == 6  # not 10+, which is what re-visiting would produce


@pytest.mark.asyncio
async def test_depth_limit_stops_recursion(fixture_site_url):
    # max_depth=0 must crawl ONLY the start page.
    result = await recon(f"{fixture_site_url}/index.html", max_depth=0)
    assert result.pages_scanned == 1
