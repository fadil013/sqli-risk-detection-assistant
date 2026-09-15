"""Stage 1.7 — Technology fingerprinting.

Signature-based detection against the rendered DOM and response
headers of one page (the homepage, in practice — a site's stack
doesn't usually vary page to page, so fingerprinting once per site is
enough and keeps the crawl fast).

Confidence is a plain heuristic, not a calibrated probability: a
strong, hard-to-fake signature (a framework's own data attribute or
global object) scores high; a weak signal (just a script filename
substring) scores lower because it's easier to coincidentally match.
"""
from __future__ import annotations

from bs4 import BeautifulSoup

# (technology, category, confidence, matcher) — matcher receives the
# lowercased HTML text and the response headers dict.
Signature = tuple[str, str, float]

_SCRIPT_SRC_HINTS: list[tuple[str, str, str, float]] = [
    ("react", "frontend", "React", 0.6),
    ("angular", "frontend", "Angular", 0.6),
    ("vue", "frontend", "Vue.js", 0.6),
    ("next", "frontend", "Next.js", 0.6),
    ("jquery", "frontend", "jQuery", 0.5),
]

_HEADER_HINTS: list[tuple[str, str, str, str, float]] = [
    # (header_name, value_substring, technology, category, confidence)
    ("server", "nginx", "Nginx", "server", 0.9),
    ("server", "apache", "Apache", "server", 0.9),
    ("x-powered-by", "php", "PHP", "backend", 0.9),
    ("x-powered-by", "express", "Node.js / Express", "backend", 0.9),
    ("x-powered-by", "asp.net", "ASP.NET", "backend", 0.9),
    ("x-drupal-cache", "", "Drupal", "backend", 0.8),
    ("x-generator", "django", "Django", "backend", 0.8),
]


def fingerprint(html: str, headers: dict[str, str]) -> list[tuple[str, str, float]]:
    """Returns [(technology, category, confidence), ...], deduped by
    technology name (keeping the highest confidence seen).
    """
    findings: dict[str, tuple[str, float]] = {}

    def record(name: str, category: str, confidence: float) -> None:
        existing = findings.get(name)
        if existing is None or confidence > existing[1]:
            findings[name] = (category, confidence)

    soup = BeautifulSoup(html, "html.parser")

    # Strong DOM signatures beat weak filename substrings.
    if soup.find(attrs={"data-reactroot": True}) or "data-reactroot" in html:
        record("React", "frontend", 0.9)
    if "__NEXT_DATA__" in html:
        record("Next.js", "frontend", 0.95)
    if soup.find(attrs={"ng-app": True}) or soup.find(attrs={"ng-version": True}):
        record("Angular", "frontend", 0.9)
    if soup.find(attrs={"data-v-app": True}) or 'id="app"' in html and "vue" in html.lower():
        record("Vue.js", "frontend", 0.5)  # weak — "id=app" alone is common and generic

    for script in soup.find_all("script", src=True):
        src = script["src"].lower()
        for hint, category, name, confidence in _SCRIPT_SRC_HINTS:
            if hint in src:
                record(name, category, confidence)

    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        content = generator["content"]
        record(content, "backend", 0.85)

    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    for header_name, value_substr, name, category, confidence in _HEADER_HINTS:
        value = lower_headers.get(header_name, "")
        if value and (value_substr == "" or value_substr in value):
            record(name, category, confidence)

    return [(name, category, confidence) for name, (category, confidence) in findings.items()]
