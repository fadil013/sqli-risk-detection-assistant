"""Stage 2 (application map), Stage 3/4 (feature extraction), database
relationship integrity, and report generation.

Uses its own in-memory SQLite engine per test rather than the app's
default crawler.db file, so these tests never touch (or depend on the
state of) a real developer's local database.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.analyzer.feature_extractor import extract_features
from app.crawler.recon import recon
from app.db.models import Base
from app.reports.generator import build_application_map, build_report
from app.storage.repository import save_recon_result


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.mark.asyncio
async def test_database_relationships_resolve(fixture_site_url, db_session):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)
    website = save_recon_result(db_session, result, max_depth=1, max_pages=25)

    assert website.id is not None
    assert len(website.pages) == result.pages_scanned

    login_page = next(p for p in website.pages if p.url.endswith("login.html"))
    assert login_page.website_id == website.id
    assert {i.name for i in login_page.inputs} == {"email", "password"}
    assert login_page.page_type == "authentication"

    assert len(website.crawl_sessions) == 1
    assert website.crawl_sessions[0].status == "completed"


@pytest.mark.asyncio
async def test_application_map_groups_by_page_type(fixture_site_url, db_session):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)
    website = save_recon_result(db_session, result, max_depth=1, max_pages=25)

    app_map = build_application_map(db_session, website.id)
    assert "authentication" in app_map["categories"]
    login_entry = next(
        p for p in app_map["categories"]["authentication"] if p["url"].endswith("login.html")
    )
    assert {i["name"] for i in login_entry["inputs"]} == {"email", "password"}


@pytest.mark.asyncio
async def test_report_generation(fixture_site_url, db_session):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=2, max_pages=50)
    website = save_recon_result(db_session, result, max_depth=2, max_pages=50)

    report = build_report(db_session, website.id)
    assert report["target"] == f"{fixture_site_url}/index.html"
    assert report["pages_discovered"] == result.pages_scanned
    assert report["authentication_pages"] >= 1
    assert "id" in report["high_value_parameters"]


@pytest.mark.asyncio
async def test_feature_extraction_produces_ai_ready_json(fixture_site_url, db_session):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)
    website = save_recon_result(db_session, result, max_depth=1, max_pages=25)

    features = extract_features(db_session, website.id)
    password_feature = next(f for f in features if f["field"] == "password")

    assert password_feature["method"] == "POST"
    assert password_feature["features"]["parameter_type"] == "credential"
    assert password_feature["features"]["sensitivity"] == "high"
    assert password_feature["features"]["authentication_relation"] is True
    assert password_feature["features"]["database_likelihood"] > 0.5


def test_report_and_features_return_none_for_unknown_website(db_session):
    assert build_report(db_session, 999) is None
    assert build_application_map(db_session, 999) is None
    assert extract_features(db_session, 999) == []
