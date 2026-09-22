"""Combines the YAML-driven mapper with source-specific list handling
(references) that doesn't fit the mapper's scalar-path contract, and
assembles the result into a `SecurityAdvisory`.
"""

from pathlib import Path
from typing import Any

import yaml

from parsers.mapper import apply_mapping
from parsers.models import SecurityAdvisory


MAPPINGS_DIR = Path(__file__).parent.parent / "mappings"


def _load_mapping(name: str) -> dict[str, Any]:
    path = MAPPINGS_DIR / f"{name}.yaml"
    return yaml.safe_load(path.read_text())


def cve_to_advisory(cve: dict[str, Any]) -> SecurityAdvisory:
    """Map NVD CVE response to advisory, extracting URLs from references."""
    mapping = _load_mapping("nvd_cve")
    fields = apply_mapping(cve, mapping)
    fields["references"] = [ref["url"] for ref in cve.get("references", [])]
    fields["source"] = "nvd_cve"
    return SecurityAdvisory(**fields)


def rss_item_to_advisory(item: dict[str, Any]) -> SecurityAdvisory:
    """Map SANS ISC RSS item to advisory, extracting link if present."""
    mapping = _load_mapping("sans_isc")
    fields = apply_mapping(item, mapping)
    fields["references"] = [item["link"]] if item.get("link") else []
    fields["source"] = "sans_isc"
    return SecurityAdvisory(**fields)
