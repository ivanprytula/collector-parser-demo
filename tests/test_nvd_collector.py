import json
from pathlib import Path

import pytest

from collectors.nvd_cve import iter_vulnerabilities
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
