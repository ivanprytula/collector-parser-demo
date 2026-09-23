"""SQLite persistence for normalized advisories."""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from parsers.models import SecurityAdvisory


def init_db(db_path: str | Path) -> None:
    """Create advisories table if it doesn't exist."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS advisories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                external_id TEXT NOT NULL,
                source TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                published_at TEXT NOT NULL,
                severity TEXT,
                cvss_score REAL,
                refs TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(external_id, source)
            )
            """
        )
        conn.commit()


def save_advisory(advisory: SecurityAdvisory, db_path: str | Path) -> None:
    """Insert or replace an advisory in the database."""
    db_path = Path(db_path)
    references_json = ";".join(advisory.references) if advisory.references else ""

    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO advisories (
                external_id, source, title, description,
                published_at, severity, cvss_score, refs, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                advisory.external_id,
                advisory.source,
                advisory.title,
                advisory.description,
                advisory.published_at.isoformat(),
                advisory.severity,
                advisory.cvss_score,
                references_json,
                datetime.now(UTC).isoformat(),
            ),
        )
        conn.commit()


def save_advisories(advisories: list[SecurityAdvisory], db_path: str | Path) -> None:
    """Batch insert advisories."""
    for advisory in advisories:
        save_advisory(advisory, db_path)


def list_advisories(db_path: str | Path, source: str | None = None) -> list[dict]:
    """Fetch advisories from database, optionally filtered by source."""
    db_path = Path(db_path)
    if not db_path.exists():
        return []

    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if source:
            rows = conn.execute(
                "SELECT * FROM advisories WHERE source = ? ORDER BY published_at DESC",
                (source,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM advisories ORDER BY published_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]


def count_advisories(db_path: str | Path, source: str | None = None) -> int:
    """Count advisories, optionally filtered by source."""
    db_path = Path(db_path)
    if not db_path.exists():
        return 0

    with closing(sqlite3.connect(db_path)) as conn:
        if source:
            count = conn.execute(
                "SELECT COUNT(*) FROM advisories WHERE source = ?", (source,)
            ).fetchone()[0]
        else:
            count = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        return count
