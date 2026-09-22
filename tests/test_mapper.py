import pytest

from parsers.mapper import MappingError, apply_mapping


def test_apply_mapping_walks_nested_and_indexed_paths():
    record = {"id": "X-1", "descriptions": [{"lang": "en", "value": "hello"}]}
    mapping = {
        "external_id": {"source": "id", "type": "str", "required": True},
        "description": {
            "source": "descriptions.0.value",
            "type": "str",
            "required": True,
        },
    }

    result = apply_mapping(record, mapping)

    assert result == {"external_id": "X-1", "description": "hello"}


def test_apply_mapping_raises_on_missing_required_field():
    mapping = {"external_id": {"source": "id", "type": "str", "required": True}}

    with pytest.raises(MappingError, match="required field 'external_id'"):
        apply_mapping({}, mapping)


def test_apply_mapping_leaves_optional_field_none_when_missing():
    mapping = {"severity": {"source": "severity", "type": "str", "required": False}}

    result = apply_mapping({}, mapping)

    assert result == {"severity": None}


def test_apply_mapping_raises_on_bad_coercion():
    mapping = {"score": {"source": "score", "type": "float", "required": True}}

    with pytest.raises(MappingError, match="failed 'float' coercion"):
        apply_mapping({"score": "not-a-number"}, mapping)
