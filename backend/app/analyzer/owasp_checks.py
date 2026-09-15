"""Stage 5 — passive OWASP Top 10 (2021) detection.

Everything here is read-only pattern matching over data the crawler
already collected (response headers, page classification, tech
fingerprint, target scheme) — no requests are sent beyond what
recon.py already made, nothing is guessed or brute-forced.

Deliberately NOT auto-detected (flagged honestly, not faked):
A04 Insecure Design, A08 Software/Data Integrity Failures, A09
Security Logging & Monitoring Failures — none of these are observable
from outside the app without source access, log access, or an actual
authenticated session, so no check pretends to cover them.
"""
from __future__ import annotations

import json

from app.db.models import Website
from app.models.schemas import OwaspFinding

# Headers whose *absence* is itself the misconfiguration signal.
_EXPECTED_SECURITY_HEADERS = {
    "content-security-policy": "No Content-Security-Policy header — the browser has no restriction on which scripts/styles/frames can execute, making XSS payloads (if any injection point exists) fully effective.",
    "x-frame-options": "No X-Frame-Options header — the page can be embedded in an <iframe> on an attacker's site, enabling clickjacking.",
    "strict-transport-security": "No Strict-Transport-Security (HSTS) header — browsers won't force HTTPS on repeat visits, leaving a downgrade-to-HTTP window for a man-in-the-middle.",
    "x-content-type-options": "No X-Content-Type-Options: nosniff header — browsers may MIME-sniff responses, which can turn an uploaded/reflected file into executable script in some browsers.",
}

# Admin-ish page titles that indicate an actual auth gate is present —
# used to avoid flagging a *properly protected* admin page.
_AUTH_GATE_HINTS = ("login", "sign in", "denied", "403", "forbidden", "unauthorized", "not found", "404")


def _check_crypto_failures(website: Website) -> list[OwaspFinding]:
    if website.url.startswith("http://"):
        return [
            OwaspFinding(
                category="cryptographic_failures",
                page=website.url,
                evidence=f"Target served over plain HTTP: {website.url}",
                severity="HIGH",
                description="Traffic (including any submitted credentials/session cookies) travels unencrypted and is readable/modifiable in transit.",
            )
        ]
    return []


def _check_security_misconfiguration(website: Website) -> list[OwaspFinding]:
    findings: list[OwaspFinding] = []
    for page in website.pages:
        if not page.response_headers:
            continue
        headers = {k.lower(): v for k, v in json.loads(page.response_headers).items()}
        for header, evidence in _EXPECTED_SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    OwaspFinding(
                        category="security_misconfiguration",
                        page=page.url,
                        evidence=evidence,
                        severity="MEDIUM",
                        description=f"Missing security header: {header}",
                    )
                )
    return findings


def _check_broken_access_control(website: Website) -> list[OwaspFinding]:
    findings: list[OwaspFinding] = []
    for page in website.pages:
        if page.page_type != "admin":
            continue
        title = (page.title or "").lower()
        if any(hint in title for hint in _AUTH_GATE_HINTS):
            continue  # looks gated (login wall / 403 / 404) — not a finding
        findings.append(
            OwaspFinding(
                category="broken_access_control",
                page=page.url,
                evidence=f"Admin-classified page returned content with title '{page.title}' and no visible auth gate.",
                severity="HIGH",
                description="An admin-area URL is reachable and rendering content without an apparent login redirect or access-denied response.",
            )
        )
    return findings


def _check_vulnerable_components(website: Website) -> list[OwaspFinding]:
    # No version numbers are extracted by the fingerprinter today, so
    # this can only flag "here's your stack, go check it" — not a
    # confirmed CVE match. Said plainly rather than faking precision.
    findings: list[OwaspFinding] = []
    for tech in website.technologies:
        findings.append(
            OwaspFinding(
                category="vulnerable_components",
                page=website.url,
                evidence=f"Detected: {tech.name} ({tech.category}, confidence {tech.confidence})",
                severity="LOW",
                description="Version number not extracted by passive fingerprinting — manually confirm this isn't running a version with known CVEs.",
            )
        )
    return findings


def run_owasp_checks(website: Website) -> list[OwaspFinding]:
    """Runs every passive check and returns the combined finding list."""
    findings: list[OwaspFinding] = []
    findings.extend(_check_crypto_failures(website))
    findings.extend(_check_security_misconfiguration(website))
    findings.extend(_check_broken_access_control(website))
    findings.extend(_check_vulnerable_components(website))
    return findings
