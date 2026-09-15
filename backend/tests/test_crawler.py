from pathlib import Path

import pytest

from app.crawler.discovery import discover

FIXTURE = Path(__file__).parent / "fixtures" / "login_page.html"
FIXTURE_URL = FIXTURE.resolve().as_uri()


@pytest.mark.asyncio
async def test_discovers_forms_and_fields():
    result = await discover(FIXTURE_URL)

    assert result.errors == []
    assert result.page_title == "Test Login Page"
    assert len(result.forms) == 2

    login_form = next(f for f in result.forms if f.method == "POST")
    assert login_form.action.endswith("/login")
    field_names = {i.name for i in login_form.inputs}
    assert field_names == {"username", "password"}

    password_field = next(i for i in login_form.inputs if i.name == "password")
    assert password_field.type == "password"
    assert password_field.required is True
    assert "Login" in login_form.button_labels


@pytest.mark.asyncio
async def test_discovers_get_form():
    result = await discover(FIXTURE_URL)
    search_form = next(f for f in result.forms if f.method == "GET")
    assert search_form.inputs[0].name == "query"
    assert search_form.inputs[0].type == "search"


@pytest.mark.asyncio
async def test_discovers_url_parameters():
    result = await discover(FIXTURE_URL)
    param_names = {p.name for p in result.url_parameters}
    assert param_names == {"id", "ref"}

    id_param = next(p for p in result.url_parameters if p.name == "id")
    assert id_param.example_value == "42"


@pytest.mark.asyncio
async def test_handles_unreachable_url_gracefully():
    result = await discover("http://127.0.0.1:1/does-not-exist", timeout_seconds=3)
    assert result.errors  # should not raise, should report the failure
    assert result.forms == []
