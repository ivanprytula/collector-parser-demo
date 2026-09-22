"""Tests for the shared HTTP session and retry configuration."""

import http

import requests
import responses
from requests.adapters import HTTPAdapter
from requests_ratelimiter import LimiterSession
from urllib3.util.retry import Retry

from collectors.base import DEFAULT_TIMEOUT, RateLimiterConfig, build_session


def _retry_policy(session: requests.Session, url: str = "https://example.com") -> Retry:
    """Fetch the Retry policy mounted on `session`'s adapter for `url`.

    `session.get_adapter()` is typed to return the abstract `BaseAdapter`;
    narrowing to `HTTPAdapter` here keeps that assertion in one place
    instead of repeating an isinstance check in every test.
    """
    adapter = session.get_adapter(url)
    assert isinstance(adapter, HTTPAdapter)
    assert adapter.max_retries is not None
    return adapter.max_retries


class TestBuildSession:
    """Session factory tests."""

    def test_build_session_sets_user_agent(self):
        """Session should have the provided User-Agent header."""
        user_agent = "test-collector/1.0"
        session = build_session(user_agent)

        assert session.headers["User-Agent"] == user_agent

    def test_build_session_mounts_adapters(self):
        """Session should mount HTTPAdapter for both http and https."""
        session = build_session("test")

        assert "https://" in session.adapters
        assert "http://" in session.adapters

    def test_session_has_retry_configuration(self):
        """Session adapters should have Retry configured."""
        session = build_session("test")
        retry = _retry_policy(session)

        assert retry.total == 5

    def test_retry_includes_jitter(self):
        """Retry should be configured with jitter for backoff."""
        session = build_session("test")
        retry = _retry_policy(session)

        assert retry.backoff_jitter == 0.1

    def test_retry_respects_retry_after_header(self):
        """Retry should respect Retry-After header from server."""
        session = build_session("test")
        retry = _retry_policy(session)

        assert retry.respect_retry_after_header is True

    def test_retry_status_forcelist_includes_429(self):
        """Retry should include 429 (Too Many Requests) in retry list."""
        session = build_session("test")
        retry = _retry_policy(session)

        assert http.HTTPStatus.TOO_MANY_REQUESTS in retry.status_forcelist

    def test_retry_status_forcelist_includes_5xx(self):
        """Retry should include 5xx server errors in retry list."""
        session = build_session("test")
        status_list = _retry_policy(session).status_forcelist

        assert http.HTTPStatus.INTERNAL_SERVER_ERROR in status_list
        assert http.HTTPStatus.BAD_GATEWAY in status_list
        assert http.HTTPStatus.SERVICE_UNAVAILABLE in status_list
        assert http.HTTPStatus.GATEWAY_TIMEOUT in status_list

    def test_retry_allowed_methods_is_get_only(self):
        """Retry should only apply to GET requests."""
        session = build_session("test")
        allowed_methods = _retry_policy(session).allowed_methods

        assert allowed_methods is not None
        assert "GET" in allowed_methods

    def test_default_timeout_is_tuple(self):
        """DEFAULT_TIMEOUT should be a tuple (connect, read)."""
        assert isinstance(DEFAULT_TIMEOUT, tuple)
        assert len(DEFAULT_TIMEOUT) == 2

    def test_default_timeout_values(self):
        """DEFAULT_TIMEOUT should have reasonable values."""
        connect_timeout, read_timeout = DEFAULT_TIMEOUT

        assert connect_timeout == 5
        assert read_timeout == 15
        assert connect_timeout < read_timeout

    def test_no_rate_limit_by_default(self):
        """Without a rate_limit, session is a plain requests.Session."""
        session = build_session("test")

        assert not isinstance(session, LimiterSession)

    def test_rate_limit_wraps_session_in_limiter(self):
        """Passing rate_limit produces a LimiterSession."""
        rate_limit = RateLimiterConfig(max_rate=5, time_period=30)
        session = build_session("test", rate_limit=rate_limit)

        assert isinstance(session, LimiterSession)

    def test_rate_limited_session_still_has_retry_and_user_agent(self):
        """Rate limiting doesn't drop the retry adapter or User-Agent header."""
        rate_limit = RateLimiterConfig(max_rate=5, time_period=30)
        session = build_session("test-agent", rate_limit=rate_limit)

        assert session.headers["User-Agent"] == "test-agent"
        assert _retry_policy(session).total == 5


class TestSessionRetryBehavior:
    """Integration tests for retry behavior."""

    @responses.activate
    def test_retry_on_429_with_backoff(self):
        """Session should retry on 429 Too Many Requests."""
        session = build_session("test-agent")

        # First two calls return 429, third succeeds
        responses.add(
            responses.GET,
            "https://api.example.com/data",
            status=429,
        )
        responses.add(
            responses.GET,
            "https://api.example.com/data",
            status=429,
        )
        responses.add(
            responses.GET,
            "https://api.example.com/data",
            json={"result": "ok"},
            status=200,
        )

        response = session.get("https://api.example.com/data", timeout=DEFAULT_TIMEOUT)

        assert response.status_code == 200
        assert response.json() == {"result": "ok"}
        # Should have retried: 3 calls total
        assert len(responses.calls) == 3

    @responses.activate
    def test_retry_on_503_with_backoff(self):
        """Session should retry on 503 Service Unavailable."""
        session = build_session("test-agent")

        # First call returns 503, second succeeds
        responses.add(
            responses.GET,
            "https://api.example.com/data",
            status=503,
        )
        responses.add(
            responses.GET,
            "https://api.example.com/data",
            json={"result": "recovered"},
            status=200,
        )

        response = session.get("https://api.example.com/data", timeout=DEFAULT_TIMEOUT)

        assert response.status_code == 200
        assert len(responses.calls) == 2

    @responses.activate
    def test_no_retry_on_4xx_non_429(self):
        """Session should not retry on 4xx errors (except 429)."""
        session = build_session("test-agent")

        responses.add(
            responses.GET,
            "https://api.example.com/data",
            status=404,
        )

        response = session.get("https://api.example.com/data", timeout=DEFAULT_TIMEOUT)

        # Should not retry on 404
        assert response.status_code == 404
        assert len(responses.calls) == 1

    @responses.activate
    def test_no_retry_on_2xx(self):
        """Session should not retry on successful responses."""
        session = build_session("test-agent")

        responses.add(
            responses.GET,
            "https://api.example.com/data",
            json={"result": "ok"},
            status=200,
        )

        response = session.get("https://api.example.com/data", timeout=DEFAULT_TIMEOUT)

        assert response.status_code == 200
        assert len(responses.calls) == 1

    @responses.activate
    def test_timeout_configuration(self):
        """Session should respect configured timeouts."""
        session = build_session("test-agent")

        # Create a successful response
        responses.add(
            responses.GET,
            "https://api.example.com/data",
            json={"result": "ok"},
        )

        # Call with timeout
        response = session.get(
            "https://api.example.com/data",
            timeout=DEFAULT_TIMEOUT,
        )

        assert response.status_code == 200
