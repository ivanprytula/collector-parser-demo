from datetime import datetime

from pydantic import BaseModel, Field


class SecurityAdvisory(BaseModel, frozen=True):
    """Normalized shape both the NVD (JSON) and SANS ISC (XML) sources map onto."""

    external_id: str
    title: str
    description: str
    published_at: datetime
    severity: str | None = None
    cvss_score: float | None = None
    references: list[str] = Field(default_factory=list)
    source: str
