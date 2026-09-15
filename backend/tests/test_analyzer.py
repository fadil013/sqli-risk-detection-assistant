"""Stage 2 (classification) + Stage 3 (risk scoring) tests, including
the three exact scenarios given in the spec.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.analyzer.analysis_engine import run_analysis
from app.analyzer.field_classifier import classify_field
from app.analyzer.risk_model import calculate_risk
from app.crawler.recon import recon
from app.db.models import Base, FieldAnalysis
from app.storage.repository import save_recon_result


def _classify_and_score(name, field_type, page_url, page_type, method, api_relation=False):
    classification = classify_field(name, field_type, page_url, page_type, method, api_relation)
    risk = calculate_risk(
        classification["category"], page_url, method, classification["database_probability"]
    )
    return classification, risk


# ---- the three scenarios from the spec, verbatim ----

def test_password_login_post_is_authentication_high_risk():
    classification, risk = _classify_and_score(
        "password", "password", "https://x.com/login", "authentication", "POST"
    )
    assert classification["category"] == "authentication"
    assert risk["severity"] == "HIGH"


def test_productid_product_get_is_database_identifier_medium_or_high():
    classification, risk = _classify_and_score(
        "productId", "text", "https://x.com/product", "general", "GET"
    )
    assert classification["category"] == "database_identifier"
    assert risk["severity"] in ("MEDIUM", "HIGH")


def test_color_settings_post_is_low_risk():
    classification, risk = _classify_and_score(
        "color", "text", "https://x.com/settings", "general", "POST"
    )
    assert risk["severity"] == "LOW"


# ---- classifier behavior ----

def test_classifier_trusts_exact_rule_match_over_ml():
    result = classify_field("username", "text", "https://x.com/login", "authentication", "POST", False)
    assert result["category"] == "authentication"
    assert result["confidence"] >= 0.85


def test_classifier_generalizes_to_unlisted_id_like_name():
    # "orderRefId" isn't a literal keyword — this only works if either
    # the substring fallback or the ML layer catches it.
    result = classify_field("orderRefId", "text", "https://x.com/orders", "general", "GET", False)
    assert result["category"] in ("database_identifier", "transaction_parameter")


def test_every_category_has_an_explanation_template():
    from app.analyzer.rules import PURPOSE_TEMPLATES
    from app.analyzer.knowledge_base import CATEGORY_PRIORITY

    for category in CATEGORY_PRIORITY + ["file_upload", "unknown"]:
        assert category in PURPOSE_TEMPLATES


# ---- full pipeline integration: recon -> persist -> analyze -> persist ----

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.mark.asyncio
async def test_analysis_engine_end_to_end(fixture_site_url, db_session):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)
    website = save_recon_result(db_session, result, max_depth=1, max_pages=25)

    analyzed = run_analysis(db_session, website.id)
    assert len(analyzed) > 0

    password_row = next(r for r in analyzed if r.field_name == "password")
    assert password_row.category == "authentication"
    assert password_row.severity == "HIGH"
    assert password_row.explanation  # non-empty, human-readable

    # Persisted correctly and queryable independent of the in-memory objects.
    stored = db_session.query(FieldAnalysis).filter_by(page_id=password_row.page_id).all()
    assert any(r.field_name == "password" for r in stored)


@pytest.mark.asyncio
async def test_analysis_engine_replaces_prior_run_not_duplicates(fixture_site_url, db_session):
    result = await recon(f"{fixture_site_url}/index.html", max_depth=1)
    website = save_recon_result(db_session, result, max_depth=1, max_pages=25)

    first_run = run_analysis(db_session, website.id)
    second_run = run_analysis(db_session, website.id)

    total_stored = (
        db_session.query(FieldAnalysis)
        .join(FieldAnalysis.page)
        .filter_by(website_id=website.id)
        .count()
    )
    assert len(first_run) == len(second_run)
    assert total_stored == len(second_run)  # not doubled
