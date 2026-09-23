"""End-to-end pipeline tests: mocked vendor HTTP boundary through parsing
and normalization to a real file-backed SQLite database. No unit/component
test in this suite calls a real vendor API — the HTTP layer is always
mocked with `responses` against golden (recorded-shape) fixtures, matching
how these collectors will run against live sources in production.
"""

from pathlib import Path

import pytest
import responses

from collectors.nvd_cve import API_URL, fetch_cves, iter_vulnerabilities
from collectors.sans_isc_xml import FEED_URL, fetch_feed, parse_items
from db import count_advisories, init_db, list_advisories, save_advisories
from parsers.normalize import cve_to_advisory, rss_item_to_advisory


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "advisories.db"


class TestNvdPipelineEndToEnd:
    @responses.activate
    def test_fetch_parse_normalize_persist(self, db_path):
        responses.add(
            responses.GET,
            API_URL,
            body=(FIXTURES / "nvd_cve_response.json").read_text(),
            status=200,
            content_type="application/json",
        )
        init_db(db_path)

        payload = fetch_cves(results_per_page=2, start_index=0)
        cves = list(iter_vulnerabilities(payload))
        advisories = [cve_to_advisory(cve) for cve in cves]
        save_advisories(advisories, db_path)

        rows = list_advisories(db_path, source="nvd_cve")
        assert len(rows) == 2
        assert count_advisories(db_path) == 2
        assert rows[0]["external_id"] in {cve["id"] for cve in cves}

    @responses.activate
    def test_pipeline_is_idempotent_on_rerun(self, db_path):
        responses.add(
            responses.GET,
            API_URL,
            body=(FIXTURES / "nvd_cve_response.json").read_text(),
            status=200,
            content_type="application/json",
        )
        init_db(db_path)

        for _ in range(2):
            payload = fetch_cves()
            advisories = [cve_to_advisory(cve) for cve in iter_vulnerabilities(payload)]
            save_advisories(advisories, db_path)

        assert count_advisories(db_path) == 2


class TestSansIscPipelineEndToEnd:
    @responses.activate
    def test_fetch_parse_normalize_persist(self, db_path):
        responses.add(
            responses.GET,
            FEED_URL,
            body=(FIXTURES / "sans_isc_response.xml").read_text(),
            status=200,
            content_type="application/xml",
        )
        init_db(db_path)

        xml_text = fetch_feed()
        items = parse_items(xml_text)
        advisories = [rss_item_to_advisory(item) for item in items]
        save_advisories(advisories, db_path)

        rows = list_advisories(db_path, source="sans_isc")
        assert len(rows) == 2
        assert count_advisories(db_path) == 2


class TestCombinedSourcesEndToEnd:
    @responses.activate
    def test_both_sources_persist_independently_to_same_db(self, db_path):
        responses.add(
            responses.GET,
            API_URL,
            body=(FIXTURES / "nvd_cve_response.json").read_text(),
            status=200,
            content_type="application/json",
        )
        responses.add(
            responses.GET,
            FEED_URL,
            body=(FIXTURES / "sans_isc_response.xml").read_text(),
            status=200,
            content_type="application/xml",
        )
        init_db(db_path)

        nvd_payload = fetch_cves()
        nvd_advisories = [
            cve_to_advisory(cve) for cve in iter_vulnerabilities(nvd_payload)
        ]
        save_advisories(nvd_advisories, db_path)

        xml_text = fetch_feed()
        sans_advisories = [rss_item_to_advisory(item) for item in parse_items(xml_text)]
        save_advisories(sans_advisories, db_path)

        assert count_advisories(db_path) == 4
        assert count_advisories(db_path, source="nvd_cve") == 2
        assert count_advisories(db_path, source="sans_isc") == 2

    @responses.activate
    def test_malformed_records_are_skipped_without_failing_the_batch(self, db_path):
        responses.add(
            responses.GET,
            API_URL,
            body=(FIXTURES / "nvd_cve_malformed.json").read_text(),
            status=200,
            content_type="application/json",
        )
        init_db(db_path)

        payload = fetch_cves()
        advisories = []
        errors = []
        for cve in iter_vulnerabilities(payload):
            try:
                advisories.append(cve_to_advisory(cve))
            except Exception as exc:  # MappingError, kept broad like cli.py
                errors.append((cve.get("id", "unknown"), str(exc)))
        save_advisories(advisories, db_path)

        assert errors, "malformed fixture is expected to raise on at least one record"
        assert count_advisories(db_path) == len(advisories)
