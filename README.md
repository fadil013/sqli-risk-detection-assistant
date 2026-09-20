# SQLi Risk Detection Assistant

Defensive security tool for **authorized** vulnerability assessment.
Crawls a site (read-only, same-domain only, SSRF-guarded), classifies
every input it finds, scores SQL injection risk 0–100, extends that
into four more OWASP Top 10 categories, and generates a remediation
for each finding via a local, uncensored LLM (WhiteRabbitNeo) using
retrieval-augmented generation — no cloud API, nothing leaves the
machine. It never fills in a form, sends a payload, or attempts an
exploit — it's a discovery + explainable-risk-scoring tool, not an
attack tool.

**Current state, stated plainly:** Stages 1–4 (crawler, field
classification, risk scoring, explanation) are built, tested, and
verified end-to-end. Stage 5 (OWASP Top 10 + agentic RAG
remediation, below) is written and syntax-checked but **not yet run**
— see that section for specifics before relying on it.

## What's here

```
backend/
  app/
    main.py            FastAPI app, mounts the API router
    api/routes.py       POST /api/v1/crawl
    crawler/discovery.py  Playwright + BeautifulSoup extraction logic
    models/schemas.py   Pydantic contracts (CrawlRequest, CrawlResult, ...)
  tests/
    test_crawler.py     4 tests against a local HTML fixture
    fixtures/login_page.html
  requirements.txt
  pytest.ini
```

## Why this design (Phase 1 decisions)

- **Playwright over `requests`+BeautifulSoup alone.** Many real login/
  search forms are rendered or modified by JavaScript after the
  initial HTML loads (React/Vue SPAs, dynamically-injected CSRF
  fields, etc.). A plain HTTP GET would miss those. Playwright
  renders the page like a real browser, then we hand the *final* DOM
  to BeautifulSoup for parsing — cheap, well-understood HTML parsing,
  on top of a DOM that's actually complete.
- **`name`, not `id`, is the field we care about.** When a form
  submits, the browser sends `name=value` pairs — that's the literal
  parameter key a vulnerable backend query might concatenate. `id` is
  just a DOM hook for CSS/JS and isn't sent anywhere, so later
  phases will key risk scoring off `name`.
- **URL query parameters are collected separately from forms.**
  Classic injectable patterns like `/product?id=42` never touch a
  `<form>` tag — they're just a link. A forms-only crawler would miss
  one of the most common SQLi entry points, so `discovery.py` also
  walks every `<a href>` on the page.
- **Read-only by construction.** The crawler never calls `.fill()`,
  `.click()`, or `.submit()` on anything — it only navigates to the
  target URL and reads the rendered DOM. That's the line between
  "discovery tool" and "active scanner," and it's deliberate: Phase 1
  should be safe to point at any page you're authorized to view.
- **`HttpUrl` input validation.** Pydantic's `HttpUrl` type rejects
  anything that isn't `http://`/`https://` — e.g. `file://`,
  `javascript:`, etc. — at the API boundary, before it ever reaches
  Playwright.

## ⚠️ SSRF caution before you deploy this anywhere shared

`/api/v1/crawl` will fetch whatever URL it's given, server-side, using
a real browser. That's fine for a tool you run locally against
targets you're authorized to test. If you ever expose this endpoint
to other users or the public internet, add a URL allowlist/denylist
(block `localhost`, `127.0.0.1`, `169.254.169.254` (cloud metadata),
and RFC1918 private ranges) before it reaches anything internet-facing.
This is a known gap in the current code, tracked here rather than
silently shipped — do not skip it in a real deployment.

## Setup

Requires Python 3.11+ (developed against 3.12).

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate        # Windows
# source .venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
python -m playwright install chromium
```

## Run it

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

Then either open http://127.0.0.1:8000/docs for the interactive
Swagger UI, or call it directly:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/crawl \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Response shape:

```json
{
  "target_url": "https://example.com/login",
  "page_title": "Login",
  "forms": [
    {
      "action": "https://example.com/login",
      "method": "POST",
      "page": "/login",
      "inputs": [
        {"name": "username", "type": "text", "required": true, ...},
        {"name": "password", "type": "password", "required": true, ...}
      ],
      "button_labels": ["Login"]
    }
  ],
  "url_parameters": [
    {"name": "id", "example_value": "42", "source_url": "...", "page": "/login"}
  ],
  "errors": []
}
```

## Testing

Tests point Playwright at a local HTML fixture (`tests/fixtures/login_page.html`)
via a `file://` URL, so they run offline with no network dependency.

```bash
cd backend
pytest tests/ -v
```

All 4 tests were run and pass as part of building this: two forms
(POST login with username/password, GET search) are correctly
extracted with field names/types/required flags, and both URL query
parameters (`id`, `ref`) off the product link are picked up. A
graceful-failure test also confirms an unreachable URL reports an
error instead of raising.

This was additionally smoke-tested end-to-end: ran the real FastAPI
server, served the fixture over plain HTTP (not `file://`, since the
API's `HttpUrl` validator correctly rejects non-http(s) schemes), and
confirmed `POST /api/v1/crawl` returns the identical extraction over
the wire.

## Phase 1.5 — Advanced Reconnaissance (multi-page)

`POST /api/v1/recon` (or `python cli.py`) crawls a whole site, not
just one page:

- **Same-domain BFS crawl** (`app/crawler/recon.py`) — follows only
  `<a href>` links that stay on the start host, up to `max_depth` hops
  and `max_pages` total pages (a safety valve, since query-string
  variations of the same page can otherwise explode the queue). A
  `visited` set guarantees no page or parameter is double-counted.
- **Standalone inputs** — fields not wrapped in a `<form>` (the
  React-search-box case) are now caught, not just classic HTML forms.
- **Real API endpoint discovery** — instead of regex-guessing at JS
  source (unreliable against minified/bundled code), `discovery.py`
  listens to Playwright's actual network events and records every
  `fetch`/`XHR` request the page's own JavaScript fires while
  loading. Still fully passive: we only observe, never issue, requests.
- **Persistence** (`app/db/`, `app/storage/repository.py`) — every
  recon run is saved to SQLite (`crawler.db`) as
  `Website → Pages → Inputs / Parameters / ApiEndpoints`, matching
  the schema in the original plan. One-line swap to PostgreSQL later
  (`app/db/session.py`).
- **`risk_candidate` flag** on parameters whose name commonly hits a
  DB lookup (`id`, `search`, `query`, `productid`, ...) — a hint for
  Phase 2's classifier to look at first, not a finding by itself.

Try it:
```bash
cd backend
python cli.py
# Website URL: testphp.vulnweb.com
# Max crawl depth [2]: 2
```

New tests in `tests/test_recon.py` (11 tests total, all passing)
cover: multi-page traversal, login form detection, search form
detection, URL parameter extraction (with `risk_candidate` flagging),
JS-generated standalone input detection, duplicate-page prevention,
and depth-limit enforcement. They run against a 4-page fixture site
served over real local HTTP (`tests/conftest.py`) rather than
`file://`, because `recon.py` deliberately only follows `http(s)`
links — the same rule that keeps it from ever wandering onto
`javascript:`/`mailto:` pseudo-links on a real target.

Feature 5 (API discovery) and Feature 6 (DB persistence) were
additionally verified with a manual smoke test: a fixture page firing
`fetch("/api/login", {method: "POST"})` was correctly captured and
written through to `Website → Page → ApiEndpoint` rows.

## Stage 1–4 — Complete Reconnaissance Engine

Builds on Phase 1.5 with:

- **Priority-ordered crawling** (`crawler/url_utils.py`) — URL
  normalization (canonical dedup key), and a priority queue that
  visits `/login`, `/admin`, `/api`, `/checkout`, etc. before
  decorative pages.
- **Sitemap/robots.txt discovery** (`crawler/sitemap.py`) — seeds the
  crawl with URLs a site publicly advertises but may not link from
  anywhere crawlable (a classic way to find an unlinked `/admin`).
  Passive: reading a public file, same as Googlebot does.
- **Page classification** — every visited page gets `page_type`
  (authentication/admin/checkout/search/api/general) and `importance`
  (critical/high/medium/low), URL-heuristic based.
- **Technology fingerprinting** (`crawler/technology.py`) — React/
  Angular/Vue/Next.js, PHP/Node/Django/ASP.NET, Nginx/Apache, via DOM
  signatures + response headers.
- **API parameter extraction** — POST/PUT/PATCH bodies fired by the
  page's own JS are parsed for their top-level JSON keys (e.g.
  `axios.post("/api/login", {email, password})` → `parameters:
  ["email","password"]`).
- **Feature extraction** (`analyzer/feature_extractor.py`, Stage 3/4)
  — turns DB rows into the AI-ready shape from the spec:
  `parameter_type`, `context`, `sensitivity`,
  `authentication_relation`, `database_likelihood`, `api_relation`.
  This is data prep, not the classifier — Phase 2 still writes that.
- **Reporting/mapping** (`reports/generator.py`) — a recon summary
  and an application map grouped by page type.

New endpoints: `GET /api/v1/recon/{website_id}` (status),
`GET /api/v1/map/{website_id}`, `GET /api/v1/report/{website_id}`,
`GET /api/v1/features/{website_id}`.

**Scope decisions, stated explicitly:**
- `POST /api/v1/recon` still runs the crawl synchronously — no
  background job queue was built. The status endpoint mirrors the
  async contract for later; today it only ever reports "completed."
- No `Findings` table — a "finding" implies a risk verdict, which
  doesn't exist until Phase 2's classifier runs.
- Kept `discovery.py`/`recon.py` as single files rather than splitting
  into `browser.py`/`links.py`/`inputs.py` — that split had no
  functional benefit and only added risk to already-tested code.

14 new tests (25 total, all passing) cover: URL normalization/
priority, sitemap/robots discovery, authentication detection,
technology fingerprinting, API POST-body parameter extraction,
whole-site crawling, database relationship integrity, application-map
grouping, report generation, and AI-ready feature output. Also
smoke-tested end-to-end: ran the real server, POSTed `/recon` against
a live local site, then hit all three new GET endpoints and confirmed
correct output over the wire — and separately confirmed `cli.py` now
persists to `crawler.db` and prints the resulting `website_id`.

## Stage 2/3 — AI Field Understanding + Risk Prediction

The first actual AI layer, built on top of the recon data without
touching the crawler. `app/analyzer/`:

- `knowledge_base.py` — hand-curated security keyword lists (auth,
  payment, security-token, database-identifier, ...) and scoring
  weights. This is security knowledge, not AI.
- `rules.py` — exact/substring matching against the knowledge base.
  Wins outright on an exact match (confidence 0.85+).
- `ml_features.py` + `ml/train_classifier.py` — an XGBoost classifier
  trained on **synthetic data bootstrapped from the knowledge base
  itself** (no real labeled SQLi dataset exists to train on). It
  learns structural features (`contains_id`, `contains_password`, ...)
  so it can generalize to field names NOT in any keyword list (e.g.
  `orderRefId`), which a pure dictionary lookup would call "unknown".
  Training accuracy: **71%** on its own synthetic data — stated
  honestly; several categories (payment/profile/transaction) share
  no distinguishing structural feature, so some ceiling is expected
  and was not chased away by re-encoding the keyword lists as more
  boolean flags.
- `field_classifier.py` — combines the two: rules win on exact
  matches, ML only gets a vote when rules found nothing.
- `context_analyzer.py` — page-type/URL/method context feeding both
  the classifier and the risk model.
- `risk_model.py` — additive 0–100 score (field category + page
  importance + HTTP method + database probability) → LOW/MEDIUM/HIGH,
  with the contributing factors listed per field.
- `llm_explainer.py` — **template-based, not a live LLM call** — no
  API key is configured in this project, and I'm not wiring one up
  silently. Structured so a real Claude/OpenAI call is a one-function
  swap later.
- `analysis_engine.py` — orchestrates the above over everything a
  prior `POST /recon` already found, and persists one `FieldAnalysis`
  row per field. Re-running it replaces prior findings rather than
  duplicating them.

New endpoints: `POST /api/v1/analyze/{website_id}` (runs analysis over
already-crawled data — does not re-crawl), `GET
/api/v1/analysis/{website_id}` (returns every classification/risk
score/explanation). `cli.py` now offers to run this automatically
after a scan.

**Verified against the exact three scenarios given in the spec:**
`password`/`/login`/POST → authentication, 86/100 HIGH.
`productId`/`/product`/GET → database_identifier, 47/100 MEDIUM
(spec accepted HIGH or MEDIUM). `color`/`/settings`/POST → 24/100 LOW.
8 new tests cover these plus the full recon→analyze pipeline and
re-run/no-duplication behavior (41 tests total, all passing). Also
smoke-tested live: real server, real crawl, `POST /analyze` +
`GET /analysis` over HTTP, and the same flow through `cli.py`.

One real bug caught and fixed during this build: re-running analysis
on the same website reused SQLite rowids in a way that corrupted
SQLAlchemy's identity map (`analysis_engine.py` now deletes prior
rows object-by-object instead of via a bulk query, which keeps the
session in sync) — caught by treating a SQLAlchemy warning as a
hard test failure rather than ignoring it.

## Stage 5 — OWASP Top 10 Detection + Agentic RAG Remediation

Expands risk scoring past SQL injection into four more OWASP Top 10
(2021) categories, using data the crawler already collects — no new
requests are made to the target. `app/analyzer/owasp_checks.py`:

- **Cryptographic Failures** — target served over plain HTTP.
- **Security Misconfiguration** — missing security response headers
  (`Content-Security-Policy`, `X-Frame-Options`,
  `Strict-Transport-Security`, `X-Content-Type-Options`).
- **Broken Access Control** — an admin-classified page returning
  content with no visible login/403/404 gate.
- **Vulnerable Components** — every fingerprinted technology is
  flagged for a manual version check. Said plainly rather than faked:
  the fingerprinter doesn't extract version numbers today, so this
  can point at what to check, not confirm a CVE match.

**Not auto-detected, on purpose:** Insecure Design, Software/Data
Integrity Failures, and Security Logging & Monitoring Failures aren't
observable passively from outside the app (no source, log, or session
access), so no check pretends to cover them.

**Remediation is agentic RAG, not a canned lookup**
(`app/analyzer/remediation_kb.py` + `llm_explainer.py`):
1. Retrieve — pull the best-matching chunk from a small local
   knowledge base (plain-Python TF-IDF, no scipy/sklearn dependency,
   so it isn't at the mercy of a native-DLL toolchain).
2. Reason — WhiteRabbitNeo (via LM Studio's local, OpenAI-compatible
   server) is asked what additional concept it needs to sharpen the
   fix, given what was already retrieved. The *model* decides the
   follow-up query — it isn't hardcoded.
3. Retrieve again — that model-chosen query is looked up against the
   same local KB.
4. Generate — WhiteRabbitNeo writes the final fix, grounded in both
   retrieved chunks plus the specific finding.

Connected by default (no env var needed) at `localhost:1234`, model
`whiterabbitneo-v3-7b`. Fails soft to the raw retrieved KB text at any
step if LM Studio isn't running, so this never raises and never
returns an empty string. Set `LLM_EXPLAINER_DISABLE_LOCAL_MODEL=1` to
skip the model calls entirely (fast/offline runs).

New endpoints: `POST /api/v1/owasp/{website_id}` (runs detection +
remediation over an already-crawled site — does not re-crawl),
`GET /api/v1/owasp/{website_id}` (returns stored findings).

**Honest status: written and syntax-checked, not yet run.** Unlike
every stage above, Stage 5 has no passing test run and no smoke test
behind it yet — that's the one thing standing between "code exists"
and "confirmed working."

## Not yet built

- **A frontend.** Everything is still API-only — Swagger docs
  (`/docs`) or `curl`/Postman, no UI to enter a URL and see results.
- **Stage 5 end-to-end verification** (see above).
- **PDF/HTML report export** — `reports/generator.py` returns JSON;
  nothing renders a document yet.
