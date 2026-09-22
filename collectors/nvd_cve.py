"""Collector for the NVD CVE API 2.0 (JSON).

https://services.nvd.nist.gov/rest/json/cves/2.0 — unauthenticated requests
are capped at 5 per rolling 30s. The session is throttled client-side to
stay under that limit proactively; the shared retry policy in `base.py`
still absorbs any 429 that gets through regardless.
"""

from typing import Any

from collectors.base import DEFAULT_TIMEOUT, RateLimiterConfig, build_session


API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "collector-parser-demo/0.1 (portfolio project)"
RATE_LIMIT = RateLimiterConfig(max_rate=5, time_period=30)


def fetch_cves(results_per_page: int = 20, start_index: int = 0) -> dict[str, Any]:
    session = build_session(USER_AGENT, rate_limit=RATE_LIMIT)
    response = session.get(
        API_URL,
        params={"resultsPerPage": results_per_page, "startIndex": start_index},
        timeout=DEFAULT_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def iter_vulnerabilities(payload: dict[str, Any]):
    for entry in payload.get("vulnerabilities", []):
        yield entry["cve"]
