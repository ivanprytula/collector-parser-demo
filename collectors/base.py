"""Shared HTTP session: retry/backoff on 429 and 5xx, optional client-side
rate limiting, bounded timeouts.

One session factory reused by every collector so retry and rate-limit
policy live in one place, not copy-pasted per source.
"""

import http

import requests
from pydantic import BaseModel
from requests.adapters import HTTPAdapter
from requests_ratelimiter import LimiterSession
from urllib3.util.retry import Retry


CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 15
DEFAULT_TIMEOUT = (CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS)


class RateLimiterConfig(BaseModel):
    """Client-side rate limit: at most `max_rate` requests per `time_period`
    seconds. Proactive throttling, distinct from the retry policy below —
    it avoids tripping a source's rate limit (e.g. NVD's 5 req/30s) instead
    of just recovering from the 429 after the fact.
    """

    max_rate: float
    time_period: float


def build_session(
    user_agent: str, rate_limit: RateLimiterConfig | None = None
) -> requests.Session:
    if rate_limit:
        rate = rate_limit.max_rate / rate_limit.time_period
        session = LimiterSession(per_second=rate)
    else:
        session = requests.Session()
    session.headers["User-Agent"] = user_agent

    retry = Retry(
        total=5,
        backoff_factor=1.5,
        backoff_jitter=0.1,
        status_forcelist=[
            http.HTTPStatus.TOO_MANY_REQUESTS,
            http.HTTPStatus.INTERNAL_SERVER_ERROR,
            http.HTTPStatus.BAD_GATEWAY,
            http.HTTPStatus.SERVICE_UNAVAILABLE,
            http.HTTPStatus.GATEWAY_TIMEOUT,
        ],
        respect_retry_after_header=True,
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
