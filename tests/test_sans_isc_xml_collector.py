from pathlib import Path

import pytest

from collectors.sans_isc_xml import parse_items
from parsers.mapper import MappingError
from parsers.normalize import rss_item_to_advisory


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def feed_xml():
    return (FIXTURES / "sans_isc_response.xml").read_text()


@pytest.fixture
def malformed_feed_xml():
    return (FIXTURES / "sans_isc_malformed.xml").read_text()


def test_parse_items_returns_flat_dicts_per_item(feed_xml):
    items = parse_items(feed_xml)

    assert len(items) == 2
    assert items[0]["title"].startswith("The Truth about GET and HTTP Standards")
    assert items[0]["guid"] == "https://isc.sans.edu/diary/rss/33358"


def test_rss_item_to_advisory_normalizes_full_item(feed_xml):
    item = parse_items(feed_xml)[0]

    advisory = rss_item_to_advisory(item)

    assert advisory.external_id == "https://isc.sans.edu/diary/rss/33358"
    assert advisory.source == "sans_isc"
    assert advisory.severity is None
    assert advisory.references == ["https://isc.sans.edu/diary/rss/33358"]


def test_rss_item_to_advisory_raises_on_missing_required_field(malformed_feed_xml):
    item = parse_items(malformed_feed_xml)[0]

    with pytest.raises(MappingError):
        rss_item_to_advisory(item)
