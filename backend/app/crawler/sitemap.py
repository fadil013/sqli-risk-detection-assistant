"""Stage 1.2 — Sitemap / robots.txt discovery.

robots.txt and sitemap.xml are public-by-design files a server
publishes specifically so crawlers can find pages — reading them is
standard, passive reconnaissance (this is what Googlebot does), not
an attack. We use them purely to seed the crawl queue with real page
URLs the site is already advertising, so a depth-limited crawl doesn't
miss pages that aren't linked from the homepage.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

import httpx


async def discover_seed_urls(start_url: str, timeout_seconds: int = 10) -> list[str]:
    """Best-effort: returns same-domain URLs found in robots.txt's
    Sitemap: entries (and the sitemaps they point to) plus Disallow
    paths. Never raises — a missing/malformed robots.txt or sitemap
    just means an empty result, not a crawl failure (Feature 8).
    """
    parsed = urlparse(start_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    found: set[str] = set()

    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
        sitemap_urls = [urljoin(origin, "/sitemap.xml")]

        try:
            resp = await client.get(urljoin(origin, "/robots.txt"))
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("sitemap:"):
                        sitemap_urls.append(line.split(":", 1)[1].strip())
                    elif line.lower().startswith("disallow:"):
                        raw_path = line.split(":", 1)[1].strip()
                        if raw_path and raw_path != "/":
                            candidate = urljoin(origin, raw_path)
                            if urlparse(candidate).netloc == parsed.netloc:
                                found.add(candidate)
        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        for sitemap_url in sitemap_urls:
            try:
                resp = await client.get(sitemap_url)
                if resp.status_code != 200:
                    continue
                root = ElementTree.fromstring(resp.content)
                for loc in root.iter():
                    if loc.tag.endswith("loc") and loc.text:
                        candidate = loc.text.strip()
                        if urlparse(candidate).netloc == parsed.netloc:
                            found.add(candidate)
            except (httpx.HTTPError, httpx.TimeoutException, ElementTree.ParseError):
                continue

    return sorted(found)
