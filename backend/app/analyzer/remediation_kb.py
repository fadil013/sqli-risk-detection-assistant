"""Stage 5 — local remediation knowledge base + TF-IDF retrieval.

This is the "R" in the RAG pipeline: a small, hand-curated corpus of
OWASP-standard remediation guidance, chunked by topic, retrieved by
cosine similarity against a finding's own text (category + evidence)
rather than a flat category->text lookup — so a finding's specific
wording pulls in the most relevant chunk(s), not just "whatever's
filed under this category".

No external vector DB / embedding model needed for a corpus this
size. Retrieval is plain-Python TF-IDF + cosine similarity over a
bag-of-words — no scipy/sklearn dependency, so it isn't at the mercy
of a native-DLL toolchain (this codebase's own scikit-learn import
is blocked by a Windows Application Control policy in at least one
deployment environment; this module deliberately doesn't share that
failure mode).
"""
from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has",
    "in", "is", "it", "its", "of", "on", "or", "that", "the", "to", "was",
    "were", "will", "with", "not", "no",
}


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


def _tf(tokens: list[str]) -> Counter:
    return Counter(tokens)


def _cosine(a: Counter, b: Counter) -> float:
    shared = set(a) & set(b)
    dot = sum(a[t] * b[t] for t in shared)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)

_CHUNKS: list[tuple[str, str]] = [
    (
        "cryptographic_failures",
        "Serve the entire site over HTTPS only. Redirect all HTTP requests to HTTPS with a 301. "
        "Add a Strict-Transport-Security header (HSTS) with a long max-age (e.g. 31536000) and "
        "includeSubDomains so browsers refuse to downgrade on repeat visits. Use a valid certificate "
        "from a trusted CA and disable legacy TLS versions (TLS 1.0/1.1) and weak cipher suites.",
    ),
    (
        "security_misconfiguration",
        "Set Content-Security-Policy to restrict script/style/frame sources to trusted origins only — "
        "start with default-src 'self' and widen deliberately. Set X-Frame-Options: DENY or SAMEORIGIN "
        "to prevent clickjacking. Set X-Content-Type-Options: nosniff to stop MIME-sniffing. Remove or "
        "mask server/framework version headers (Server, X-Powered-By) so they don't hand an attacker a "
        "version to look up known CVEs for.",
    ),
    (
        "broken_access_control",
        "Enforce authentication and authorization server-side on every admin/privileged route — never "
        "rely on hiding a URL (security through obscurity) or client-side route guards alone, since "
        "those can be bypassed by hitting the URL/API directly. Return 401/403 with no page content for "
        "unauthenticated/unauthorized requests, not a redirect that still leaks the page shell.",
    ),
    (
        "vulnerable_components",
        "Pin dependencies to specific versions and run an automated vulnerability scanner (npm audit, "
        "pip-audit, Dependabot, Snyk) as part of CI so new CVEs in existing dependencies are caught on "
        "every build, not just when someone remembers to check manually. Track the actual deployed "
        "version of frontend libraries (React, jQuery, etc.) and backend frameworks, and subscribe to "
        "their security advisories.",
    ),
    (
        "injection",
        "Use parameterized queries / prepared statements for every database call — never concatenate "
        "user input into a SQL string. Validate and allow-list input where possible. For output going "
        "into HTML, use context-aware output encoding (the templating engine's default auto-escaping, "
        "not string concatenation) to prevent stored/reflected XSS.",
    ),
    (
        "ssrf",
        "If a parameter or endpoint accepts a URL from the user, validate it against a strict allow-list "
        "of permitted hosts/schemes before the server fetches it. Block requests to private IP ranges, "
        "localhost, and cloud metadata endpoints (169.254.169.254) at the network layer, not just in "
        "application code, since app-level checks alone are bypassable via redirects/DNS rebinding.",
    ),
    (
        "authentication_failures",
        "Enforce rate limiting and account lockout/backoff on login endpoints to blunt credential "
        "stuffing and brute force. Require CAPTCHA after repeated failures. Never disclose whether the "
        "username or password was the wrong part of a failed login. Enforce a minimum password policy "
        "and offer MFA.",
    ),
]

# Document frequency across the corpus, computed once at import time —
# standard TF-IDF: a term that appears in every chunk (e.g. "the") is
# worth less than one that appears in only one.
_DOC_TOKENS = [_tf(_tokenize(text)) for _, text in _CHUNKS]
_DOC_FREQ: Counter = Counter()
for _doc in _DOC_TOKENS:
    _DOC_FREQ.update(_doc.keys())
_N_DOCS = len(_CHUNKS)


def _tfidf(tf: Counter) -> Counter:
    return Counter(
        {term: count * math.log((1 + _N_DOCS) / (1 + _DOC_FREQ.get(term, 0)) + 1) for term, count in tf.items()}
    )


_DOC_VECTORS = [_tfidf(tf) for tf in _DOC_TOKENS]


def retrieve(query: str, k: int = 2) -> list[str]:
    """Returns the top-k most relevant remediation chunks for `query`
    (a finding's category + evidence text), ranked by TF-IDF cosine
    similarity — plain Python, no scipy/sklearn dependency.
    """
    query_vec = _tfidf(_tf(_tokenize(query)))
    scores = [_cosine(query_vec, doc_vec) for doc_vec in _DOC_VECTORS]
    ranked = sorted(range(len(_CHUNKS)), key=lambda i: scores[i], reverse=True)
    return [_CHUNKS[i][1] for i in ranked[:k] if scores[i] > 0]
