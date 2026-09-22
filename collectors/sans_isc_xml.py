"""Collector for the SANS Internet Storm Center RSS feed (XML).

https://isc.sans.edu/rssfeed_full.xml — public, unauthenticated, no key.
Parsed with defusedxml to reject external entity resolution (XXE); an RSS
feed is exactly the kind of untrusted-but-structured input where that
matters.
"""

from typing import Any

from defusedxml import ElementTree

from collectors.base import DEFAULT_TIMEOUT, build_session


FEED_URL = "https://isc.sans.edu/rssfeed_full.xml"
USER_AGENT = "collector-parser-demo/0.1 (portfolio project)"


def fetch_feed() -> str:
    session = build_session(USER_AGENT)
    response = session.get(FEED_URL, timeout=DEFAULT_TIMEOUT)
    response.raise_for_status()
    return response.text


def _item_to_dict(item) -> dict[str, Any]:
    return {child.tag: (child.text or "").strip() for child in item}


def parse_items(xml_text: str) -> list[dict[str, Any]]:
    root = ElementTree.fromstring(xml_text)
    channel = root.find("channel")
    if channel is None:
        return []
    return [_item_to_dict(item) for item in channel.findall("item")]
