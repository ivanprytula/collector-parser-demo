"""YAML-driven field mapper: walks a dotted source path through a parsed
record and coerces it to a target type, per a declarative mapping file.

A mapping file looks like:

    external_id:
      source: cve.id
      type: str
      required: true
    severity:
      source: cve.metrics.cvssMetricV2.0.baseSeverity
      type: str
      required: false

Numeric path segments (e.g. "0") index into a list.
"""

from collections.abc import Mapping
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any


_COERCERS = {
    "str": str,
    "float": float,
    "int": int,
    "datetime": datetime.fromisoformat,
    "datetime_rfc822": parsedate_to_datetime,
}


class MappingError(Exception):
    """A required field was missing or a value could not be coerced."""


def _walk(record: Any, path: str) -> Any:
    node = record
    for segment in path.split("."):
        if node is None:
            return None
        if isinstance(node, list):
            index = int(segment)
            node = node[index] if index < len(node) else None
        elif isinstance(node, Mapping):
            node = node.get(segment)
        else:
            return None
    return node


def apply_mapping(
    record: Mapping[str, Any], mapping: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Produce a target-shaped dict from `record` per `mapping`."""
    result: dict[str, Any] = {}
    for target_field, spec in mapping.items():
        raw = _walk(record, spec["source"])
        required = spec.get("required", False)

        if raw is None:
            if required:
                raise MappingError(
                    f"required field '{target_field}' missing at path "
                    f"'{spec['source']}'"
                )
            result[target_field] = None
            continue

        coerce = _COERCERS[spec.get("type", "str")]
        try:
            result[target_field] = coerce(raw)
        except (TypeError, ValueError) as exc:
            raise MappingError(
                f"field '{target_field}' failed '{spec.get('type', 'str')}' "
                f"coercion on value {raw!r}: {exc}"
            ) from exc

    return result
