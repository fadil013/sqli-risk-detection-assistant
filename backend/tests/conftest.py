"""Serves tests/fixtures/site/ over real HTTP for recon.py tests.

recon.py deliberately only follows http(s) links (it must never treat
file:// or javascript: as a same-domain page to crawl on a real site),
so exercising multi-page crawling needs an actual HTTP server, not
file:// URLs like the single-page discovery tests use.
"""
import functools
import http.server
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

SITE_DIR = Path(__file__).parent / "fixtures" / "site"


@pytest.fixture(scope="session", autouse=True)
def _allow_loopback_for_tests():
    """ssrf_guard.assert_safe_url blocks 127.0.0.1 in normal operation
    (it's a classic SSRF target), but every fixture server in this
    suite legitimately runs on 127.0.0.1 — it's our own test HTTP
    server, not an attacker-controlled internal target. Patched only
    for the test session, not the guard's actual behavior.
    """
    with (
        patch("app.crawler.discovery.assert_safe_url", lambda url: None),
        patch("app.crawler.recon.assert_safe_url", lambda url: None),
    ):
        yield


@pytest.fixture(scope="session")
def fixture_site_url():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE_DIR))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()
