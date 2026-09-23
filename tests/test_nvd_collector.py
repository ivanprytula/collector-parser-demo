import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import requests
import responses

from collectors.nvd_cve import API_URL, fetch_cves, iter_vulnerabilities
from parsers.mapper import MappingError
from parsers.normalize import cve_to_advisory


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def nvd_payload():
    return json.loads((FIXTURES / "nvd_cve_response.json").read_text())


@pytest.fixture
def nvd_malformed_payload():
    return json.loads((FIXTURES / "nvd_cve_malformed.json").read_text())


def test_iter_vulnerabilities_yields_cve_dicts(nvd_payload):
    cves = list(iter_vulnerabilities(nvd_payload))

    assert len(cves) == 2
    assert cves[0]["id"] == "CVE-1999-0095"


def test_cve_to_advisory_normalizes_full_record(nvd_payload):
    cve = next(iter_vulnerabilities(nvd_payload))

    advisory = cve_to_advisory(cve)

    assert advisory.external_id == "CVE-1999-0095"
    assert advisory.severity == "HIGH"
    assert advisory.cvss_score == 10.0
    assert advisory.source == "nvd_cve"
    assert len(advisory.references) == 2


def test_cve_to_advisory_raises_on_missing_description(nvd_malformed_payload):
    cve = next(iter_vulnerabilities(nvd_malformed_payload))

    with pytest.raises(MappingError, match="description"):
        cve_to_advisory(cve)


class TestFetchCves:
    """Integration tests for the NVD API boundary, mocked at the HTTP layer
    against a golden (recorded-shape) response fixture — never calls the
    real vendor API.
    """

    @responses.activate
    def test_fetch_cves_returns_parsed_payload(self, nvd_payload):
        responses.add(
            responses.GET,
            API_URL,
            json=nvd_payload,
            status=200,
        )

        result = fetch_cves(results_per_page=2, start_index=0)

        assert result == nvd_payload

    @responses.activate
    def test_fetch_cves_sends_expected_query_params(self, nvd_payload):
        responses.add(
            responses.GET,
            API_URL,
            json=nvd_payload,
            status=200,
        )

        fetch_cves(results_per_page=50, start_index=100)

        request = responses.calls[0].request
        assert request.url is not None
        query = parse_qs(urlparse(request.url).query)
        assert query == {"resultsPerPage": ["50"], "startIndex": ["100"]}

    @responses.activate
    def test_fetch_cves_raises_on_http_error(self):
        responses.add(
            responses.GET,
            API_URL,
            json={"message": "forbidden"},
            status=403,
        )

        with pytest.raises(requests.HTTPError):
            fetch_cves()

    @responses.activate
    def test_fetch_cves_response_feeds_into_iter_vulnerabilities(self, nvd_payload):
        responses.add(
            responses.GET,
            API_URL,
            json=nvd_payload,
            status=200,
        )

        payload = fetch_cves()
        cves = list(iter_vulnerabilities(payload))

        assert len(cves) == 2
        assert cves[0]["id"] == "CVE-1999-0095"
