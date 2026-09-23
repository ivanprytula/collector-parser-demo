"""Tests for SQLite persistence — real file-backed database, no mocking."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from db import (
    count_advisories,
    init_db,
    list_advisories,
    save_advisories,
    save_advisory,
)
from parsers.models import SecurityAdvisory


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "advisories.db"


@pytest.fixture
def advisory() -> SecurityAdvisory:
    return SecurityAdvisory(
        external_id="CVE-1999-0095",
        title="Sendmail debug command",
        description="The debug command in Sendmail is enabled.",
        published_at=datetime(1999, 1, 1, tzinfo=UTC),
        severity="HIGH",
        cvss_score=10.0,
        references=["https://example.com/1", "https://example.com/2"],
        source="nvd_cve",
    )


def test_init_db_creates_table(db_path):
    init_db(db_path)

    assert count_advisories(db_path) == 0


def test_init_db_is_idempotent(db_path):
    init_db(db_path)
    init_db(db_path)

    assert count_advisories(db_path) == 0


def test_init_db_creates_parent_directories(tmp_path):
    nested_path = tmp_path / "nested" / "dir" / "advisories.db"

    init_db(nested_path)

    assert nested_path.exists()


def test_save_advisory_persists_record(db_path, advisory):
    init_db(db_path)

    save_advisory(advisory, db_path)

    rows = list_advisories(db_path)
    assert len(rows) == 1
    assert rows[0]["external_id"] == "CVE-1999-0095"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["cvss_score"] == 10.0


def test_save_advisory_stores_references_joined(db_path, advisory):
    init_db(db_path)

    save_advisory(advisory, db_path)

    rows = list_advisories(db_path)
    assert rows[0]["refs"] == "https://example.com/1;https://example.com/2"


def test_save_advisory_upserts_on_duplicate_external_id_and_source(db_path, advisory):
    init_db(db_path)
    save_advisory(advisory, db_path)

    updated = advisory.model_copy(update={"severity": "CRITICAL", "cvss_score": 9.8})
    save_advisory(updated, db_path)

    rows = list_advisories(db_path)
    assert len(rows) == 1
    assert rows[0]["severity"] == "CRITICAL"
    assert rows[0]["cvss_score"] == 9.8


def test_save_advisory_same_external_id_different_source_is_distinct(db_path, advisory):
    init_db(db_path)
    save_advisory(advisory, db_path)

    other_source = advisory.model_copy(update={"source": "sans_isc"})
    save_advisory(other_source, db_path)

    assert count_advisories(db_path) == 2


def test_save_advisories_batch_inserts_all(db_path, advisory):
    init_db(db_path)
    second = advisory.model_copy(update={"external_id": "CVE-2000-0001"})

    save_advisories([advisory, second], db_path)

    assert count_advisories(db_path) == 2


def test_list_advisories_returns_empty_list_when_db_missing(tmp_path):
    missing_path = tmp_path / "does-not-exist.db"

    assert list_advisories(missing_path) == []


def test_list_advisories_filters_by_source(db_path, advisory):
    init_db(db_path)
    sans_advisory = advisory.model_copy(
        update={"external_id": "diary/1", "source": "sans_isc"}
    )
    save_advisories([advisory, sans_advisory], db_path)

    nvd_rows = list_advisories(db_path, source="nvd_cve")

    assert len(nvd_rows) == 1
    assert nvd_rows[0]["source"] == "nvd_cve"


def test_list_advisories_orders_by_published_at_descending(db_path, advisory):
    init_db(db_path)
    older = advisory.model_copy(
        update={
            "external_id": "CVE-older",
            "published_at": datetime(1990, 1, 1, tzinfo=UTC),
        }
    )
    newer = advisory.model_copy(
        update={
            "external_id": "CVE-newer",
            "published_at": datetime(2020, 1, 1, tzinfo=UTC),
        }
    )
    save_advisories([older, newer], db_path)

    rows = list_advisories(db_path)

    assert [row["external_id"] for row in rows] == ["CVE-newer", "CVE-older"]


def test_count_advisories_returns_zero_when_db_missing(tmp_path):
    missing_path = tmp_path / "does-not-exist.db"

    assert count_advisories(missing_path) == 0


def test_count_advisories_filters_by_source(db_path, advisory):
    init_db(db_path)
    sans_advisory = advisory.model_copy(
        update={"external_id": "diary/1", "source": "sans_isc"}
    )
    save_advisories([advisory, sans_advisory], db_path)

    assert count_advisories(db_path, source="nvd_cve") == 1
    assert count_advisories(db_path, source="sans_isc") == 1
    assert count_advisories(db_path) == 2
