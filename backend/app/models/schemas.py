"""Pydantic data contracts for the discovery engine.

Kept separate from crawler logic so Phase 2+ (classification, scoring)
can import these shapes without importing Playwright.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl


class InputField(BaseModel):
    """One <input>/<textarea>/<select> found inside a form.

    `name` is what actually gets sent as the POST/GET parameter key —
    it's what a backend query would interpolate, so it's the field
    later phases score for SQLi risk (not `id`, which is only a DOM hook).
    """

    name: str | None = None
    id: str | None = None
    type: str = "text"  # text, password, email, hidden, search, number, ...
    placeholder: str | None = None
    required: bool = False
    autocomplete: str | None = None


class FormInfo(BaseModel):
    """One <form> element and everything submitted with it."""

    action: str  # absolute URL the form submits to
    method: str = "GET"  # GET or POST, uppercased
    page: str  # path the form was found on, e.g. /login
    inputs: list[InputField] = Field(default_factory=list)
    button_labels: list[str] = Field(default_factory=list)


class UrlParameter(BaseModel):
    """A query-string parameter observed on a link found on the page.

    These matter because they're server-controlled read paths
    (?id=..., ?search=...) that never go through a <form> and are
    easy to miss when only looking at forms.
    """

    name: str
    example_value: str | None = None
    source_url: str
    page: str


class StandaloneInput(BaseModel):
    """An <input>/<textarea>/<select> that is NOT inside a <form>.

    Common on JS-driven sites (React/Vue) where a "form" is really a
    div with an onClick handler wired up in JS — e.g. a search box
    that calls fetch() on Enter instead of submitting. Phase 1 only
    looked inside <form> tags and would silently miss these.
    """

    name: str | None = None
    id: str | None = None
    type: str = "text"
    placeholder: str | None = None
    page: str = ""


class ApiEndpoint(BaseModel):
    """A fetch/XHR/axios request the page actually fired while loading.

    Captured by listening to Playwright's network events — i.e. this
    is a request the site's own JavaScript really made, not a guess
    parsed out of (often minified) script source.
    """

    endpoint: str  # path, e.g. /api/login
    method: str
    full_url: str
    page: str = ""  # page that fired this request
    parameters: list[str] = Field(default_factory=list)  # top-level JSON body keys, e.g. ["email", "password"]
    source: str = "javascript"


class CrawlRequest(BaseModel):
    url: HttpUrl
    timeout_seconds: int = 15


class CrawlResult(BaseModel):
    target_url: str
    page_title: str | None = None
    forms: list[FormInfo] = Field(default_factory=list)
    standalone_inputs: list[StandaloneInput] = Field(default_factory=list)
    url_parameters: list[UrlParameter] = Field(default_factory=list)
    api_endpoints: list[ApiEndpoint] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)  # same-domain links found, for recon.py to queue
    errors: list[str] = Field(default_factory=list)


# ---- Phase 1.5: multi-page reconnaissance ----

class ReconRequest(BaseModel):
    url: HttpUrl
    max_depth: int = 2
    max_pages: int = 25  # safety valve: query-string variations can otherwise explode the queue
    timeout_seconds: int = 15


class InputFinding(BaseModel):
    """One row of the flattened `inputs_found` list in the final report."""

    type: str  # "form" | "standalone"
    page: str
    field: str | None
    field_type: str = "text"
    method: str | None = None  # only set for form fields


class ParameterFinding(BaseModel):
    name: str
    page: str
    example_value: str | None = None
    risk_candidate: bool = False  # true for names that commonly hit a DB lookup (id, search, query, ...)


class PageInfo(BaseModel):
    """Stage 1.3 — one visited page and its AI-facing classification."""

    url: str
    title: str | None = None
    page_type: str = "general"  # authentication | admin | checkout | search | api | general
    importance: str = "low"  # critical | high | medium | low
    response_headers: dict[str, str] = Field(default_factory=dict)  # top-level doc response only


class OwaspFinding(BaseModel):
    """Stage 5 — one passively-detected OWASP Top 10 candidate."""

    category: str  # e.g. "broken_access_control", "security_misconfiguration"
    page: str
    evidence: str
    severity: str = "MEDIUM"  # LOW | MEDIUM | HIGH
    description: str = ""


class TechFinding(BaseModel):
    """Stage 1.7 — one fingerprinted technology."""

    name: str
    category: str  # frontend | backend | server
    confidence: float


class ReconResult(BaseModel):
    website_id: int | None = None  # set after persistence; used by /map, /report, /features
    target: str
    pages_scanned: int
    pages: list[PageInfo] = Field(default_factory=list)
    inputs_found: list[InputFinding] = Field(default_factory=list)
    parameters_found: list[ParameterFinding] = Field(default_factory=list)
    api_endpoints: list[ApiEndpoint] = Field(default_factory=list)
    technologies: list[TechFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
