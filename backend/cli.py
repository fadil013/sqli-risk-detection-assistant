"""Standalone CLI for the recon engine — no server needed.

Run: python cli.py
Then paste a URL when prompted. Crawls up to max_depth link-hops from
that URL (same domain only), extracting forms, standalone inputs, URL
parameters, and real API calls the site's JS fires.
"""
import asyncio
import json
import re
from datetime import datetime, UTC
from pathlib import Path
from urllib.parse import urlparse

from app.analyzer.analysis_engine import run_analysis
from app.crawler.recon import recon
from app.db.session import get_session, init_db
from app.storage.repository import save_recon_result

SCANS_DIR = Path(__file__).parent / "scans"


def _save_json(url: str, result) -> Path:
    """One JSON file per scan, named after the site — separate from
    crawler.db so a result can be grepped/diffed/shared without
    needing SQLite tooling.
    """
    SCANS_DIR.mkdir(exist_ok=True)
    hostname = urlparse(url).netloc or "unknown-host"
    safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", hostname)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = SCANS_DIR / f"{safe_name}_{timestamp}.json"
    path.write_text(json.dumps(result.model_dump(), indent=2), encoding="utf-8")
    return path


async def main() -> None:
    url = input("Website URL: ").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    depth_raw = input("Max crawl depth [2]: ").strip()
    max_depth = int(depth_raw) if depth_raw else 2
    max_pages = 25

    print(f"\nCrawling {url} (max_depth={max_depth}) ...\n")
    result = await recon(url, max_depth=max_depth, max_pages=max_pages)

    if result.pages_scanned > 0:
        init_db()
        session = get_session()
        try:
            website = save_recon_result(session, result, max_depth, max_pages)
            result.website_id = website.id
        finally:
            session.close()

    print(f"Pages scanned: {result.pages_scanned}\n")

    print("Pages:")
    for p in result.pages:
        print(f"  - [{p.importance:>8}] ({p.page_type}) {p.url}")

    if result.technologies:
        print(f"\nTechnologies detected:")
        for t in result.technologies:
            print(f"  - {t.name} ({t.category}, confidence={t.confidence})")

    print(f"\nInputs found: {len(result.inputs_found)}")
    for inp in result.inputs_found:
        method = f" [{inp.method}]" if inp.method else ""
        print(f"  - ({inp.type}){method} {inp.page}  field={inp.field!r} type={inp.field_type}")

    print(f"\nParameters found: {len(result.parameters_found)}")
    for p in result.parameters_found:
        flag = " <-- risk candidate" if p.risk_candidate else ""
        print(f"  - {p.name}={p.example_value!r}  (on {p.page}){flag}")

    print(f"\nAPI endpoints observed: {len(result.api_endpoints)}")
    for ep in result.api_endpoints:
        print(f"  - [{ep.method}] {ep.endpoint}  (fired from {ep.page})")

    if result.errors:
        print(f"\nErrors ({len(result.errors)}):")
        for e in result.errors:
            print(f"  - {e}")

    if result.website_id:
        print(f"\nSaved to backend/crawler.db as website_id={result.website_id}")
        print(f"  Report:   GET /api/v1/report/{result.website_id}")
        print(f"  App map:  GET /api/v1/map/{result.website_id}")
        print(f"  Features: GET /api/v1/features/{result.website_id}")

        run_ai = input("\nRun AI risk analysis on these findings? [Y/n]: ").strip().lower()
        if run_ai in ("", "y", "yes"):
            session = get_session()
            try:
                findings = run_analysis(session, result.website_id)
                # Extract while the session is still open — `.page` is a
                # lazy-loaded relationship and would raise
                # DetachedInstanceError if touched after session.close().
                rows = [(f.severity, f.risk_score, f.category, f.field_name, f.page.url) for f in findings]
            finally:
                session.close()

            rows.sort(key=lambda r: r[1], reverse=True)
            print(f"\nAI analysis: {len(rows)} fields scored\n")
            for severity, risk_score, category, field_name, page_url in rows[:15]:
                print(f"  [{severity:>6} {risk_score:>3}] {category:<22} {field_name!r} on {page_url}")
            if len(rows) > 15:
                print(f"  ... and {len(rows) - 15} more — see GET /api/v1/analysis/{result.website_id}")

    json_path = _save_json(url, result)
    print(f"\nFull results saved to: {json_path}")


if __name__ == "__main__":
    asyncio.run(main())
