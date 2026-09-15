"""Stage 1.1 — URL normalization, dedup keys, and crawl priority.

Kept separate from recon.py because "what counts as the same URL" and
"what order should we visit URLs in" are pure functions with no
Playwright dependency — easy to unit test in isolation.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

HIGH_VALUE_KEYWORDS = (
    "login", "signin", "sign-in", "admin", "account", "profile",
    "search", "api", "checkout", "register", "signup", "sign-up",
    "password", "reset",
)
LOW_VALUE_KEYWORDS = ("images", "img", "css", "javascript", "static", "assets", "fonts")


def normalize_url(url: str) -> str:
    """Canonical form used for the visited-set / dedup key (Feature 7,
    Stage 1.1 "canonical URL handling").

    Two URLs that are "the same page" to a server — differing only in
    fragment, trailing slash, or query-parameter order — must collapse
    to one entry, or the crawler wastes budget re-visiting duplicates
    and the report double-counts pages.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"
    # Sort query params so ?a=1&b=2 and ?b=2&a=1 normalize identically.
    query = urlencode(sorted(parse_qsl(parsed.query)))
    return urlunparse((scheme, netloc, path, "", query, ""))  # fragment always dropped


def crawl_priority(url: str) -> int:
    """Lower number = crawled sooner. Used as the heapq sort key.

    Security-relevant surfaces (login, admin, api, checkout, ...) are
    exactly where SQLi risk concentrates, so a depth/page-limited crawl
    should reach them before it burns its budget on decorative pages.
    """
    path = urlparse(url).path.lower()
    if any(kw in path for kw in HIGH_VALUE_KEYWORDS):
        return 0
    if any(kw in path for kw in LOW_VALUE_KEYWORDS):
        return 2
    return 1


PAGE_TYPE_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("authentication", ("login", "signin", "sign-in", "signup", "sign-up", "register", "password", "reset")),
    ("admin", ("admin", "dashboard", "manage")),
    ("checkout", ("checkout", "cart", "payment", "billing")),
    ("search", ("search", "find", "query")),
    ("api", ("/api/",)),
]
IMPORTANCE_BY_TYPE = {
    "authentication": "critical",
    "admin": "critical",
    "checkout": "high",
    "api": "high",
    "search": "medium",
    "general": "low",
}


def classify_page(url: str) -> tuple[str, str]:
    """Stage 1.3 — Authentication/admin/etc. page detection.

    Heuristic on the URL path only (no page-content NLP) — cheap,
    deterministic, and matches the exact examples in the spec
    (`/login` -> authentication/critical). Good enough for Phase 1.5's
    job of *flagging candidates* for the AI layer, not for making a
    final call.
    """
    path = urlparse(url).path.lower()
    for page_type, keywords in PAGE_TYPE_RULES:
        if any(kw in path for kw in keywords):
            return page_type, IMPORTANCE_BY_TYPE[page_type]
    return "general", IMPORTANCE_BY_TYPE["general"]
