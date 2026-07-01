"""Tests for ``aegistrace.collectors`` with mocked HTTP."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

import requests
import responses

from aegistrace import collectors

# ---------------------------------------------------------------------------
# fetch_urlhaus
# ---------------------------------------------------------------------------

URLHAUS_CSV_BODY = """################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3878702","2026-07-01 00:12:22","https://x089w0f5.btyek.boats/?ublib=70c1a1c4-b1af-4d09-9b8f-13323c0520ea","offline","","malware_download","ClearFake","https://urlhaus.abuse.ch/url/3878702/","anonymous"
"3878701","2026-07-01 00:11:09","http://123.129.131.196:36697/i","online","2026-07-01 00:11:09","malware_download","Mozi","https://urlhaus.abuse.ch/url/3878701/","reporter"
"""


@responses.activate
def test_fetch_urlhaus_parses_valid_csv() -> None:
    responses.add(
        responses.GET,
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        body=URLHAUS_CSV_BODY,
        status=200,
    )
    threats = collectors.fetch_urlhaus()
    assert len(threats) == 2
    assert threats[0]["source"] == "URLhaus"
    assert threats[0]["url"].startswith("http")
    assert isinstance(threats[0]["timestamp"], datetime)
    assert "malware_download" in threats[0]["title"]


@responses.activate
def test_fetch_urlhaus_returns_empty_on_http_error() -> None:
    responses.add(
        responses.GET,
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        status=500,
    )
    assert collectors.fetch_urlhaus() == []


@responses.activate
def test_fetch_urlhaus_skips_comment_and_header_lines() -> None:
    body = "# header comment\n# another\n# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\"1\",\"2026-01-01 00:00:00\",\"http://x.example.com\",\"online\",\"\",\"malware_download\",\"tag\",\"link\",\"rep\"\n"
    responses.add(
        responses.GET,
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        body=body,
        status=200,
    )
    threats = collectors.fetch_urlhaus()
    assert len(threats) == 1
    assert threats[0]["url"] == "http://x.example.com"


# ---------------------------------------------------------------------------
# fetch_feodotracker
# ---------------------------------------------------------------------------

FEODO_CSV_BODY = """################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #
################################################################
#
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"
"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"
"""


@responses.activate
def test_fetch_feodotracker_parses_valid_csv() -> None:
    responses.add(
        responses.GET,
        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        body=FEODO_CSV_BODY,
        status=200,
    )
    threats = collectors.fetch_feodotracker()
    assert len(threats) == 2
    assert threats[0]["source"] == "FeodoTracker"
    assert "162.243.103.246" in threats[0]["summary"]
    assert "Emotet" in threats[0]["title"]


@responses.activate
def test_fetch_feodotracker_handles_http_error() -> None:
    responses.add(
        responses.GET,
        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        status=503,
    )
    assert collectors.fetch_feodotracker() == []


# ---------------------------------------------------------------------------
# fetch_malwarebazaar
# ---------------------------------------------------------------------------

@responses.activate
def test_fetch_malwarebazaar_parses_samples() -> None:
    payload = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_type": "exe",
                "first_seen": "2026-06-15 10:00:00",
            },
            {
                "sha256_hash": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                "file_type": "dll",
                "first_seen": "2026-06-16 11:00:00",
            },
        ],
    }
    responses.add(
        responses.POST,
        "https://mb-api.abuse.ch/api/v1/",
        json=payload,
        status=200,
    )
    threats = collectors.fetch_malwarebazaar()
    assert len(threats) == 2
    assert threats[0]["source"] == "MalwareBazaar"
    assert "exe" in threats[0]["title"]


@responses.activate
def test_fetch_malwarebazaar_handles_http_error() -> None:
    responses.add(
        responses.POST,
        "https://mb-api.abuse.ch/api/v1/",
        status=500,
    )
    assert collectors.fetch_malwarebazaar() == []


# ---------------------------------------------------------------------------
# fetch_rss
# ---------------------------------------------------------------------------

RSS_BODY = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>First threat</title>
      <link>https://example.com/1</link>
      <description>Description of first threat</description>
    </item>
    <item>
      <title>Second threat</title>
      <link>https://example.com/2</link>
      <description>Description of second threat</description>
    </item>
  </channel>
</rss>
"""


@responses.activate
def test_fetch_rss_parses_items() -> None:
    responses.add(
        responses.GET,
        "https://krebsonsecurity.com/feed/",
        body=RSS_BODY,
        status=200,
    )
    with patch("aegistrace.collectors.config.RSS_FEEDS", ["https://krebsonsecurity.com/feed/"]):
        threats = collectors.fetch_rss()
    assert len(threats) == 2
    assert threats[0]["title"] in {"First threat", "Second threat"}


@responses.activate
def test_fetch_rss_continues_on_feed_error() -> None:
    responses.add(
        responses.GET,
        "https://krebsonsecurity.com/feed/",
        status=500,
    )
    responses.add(
        responses.GET,
        "https://feeds.feedburner.com/TheHackersNews",
        body=RSS_BODY,
        status=200,
    )
    feeds = [
        "https://krebsonsecurity.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
    ]
    with patch("aegistrace.collectors.config.RSS_FEEDS", feeds):
        threats = collectors.fetch_rss()
    assert len(threats) == 2  # only the second feed contributed


# ---------------------------------------------------------------------------
# fetch_otx
# ---------------------------------------------------------------------------

def test_fetch_otx_returns_empty_when_no_api_key() -> None:
    with patch("aegistrace.collectors.config.otx_api_key", return_value=""):
        assert collectors.fetch_otx() == []


@responses.activate
def test_fetch_otx_parses_pulses_when_key_present() -> None:
    responses.add(
        responses.GET,
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        json={
            "results": [
                {
                    "name": "Test Pulse",
                    "description": "A test pulse",
                    "references": ["https://example.com/pulse"],
                    "industries": ["Finance"],
                    "created": "2026-06-15T10:00:00",
                }
            ]
        },
        status=200,
    )
    with patch("aegistrace.collectors.config.otx_api_key", return_value="fake-key"):
        threats = collectors.fetch_otx()
    assert len(threats) == 1
    assert threats[0]["title"] == "Test Pulse"
    assert threats[0]["source"] == "OTX"


# ---------------------------------------------------------------------------
# fetch_all_sources
# ---------------------------------------------------------------------------

def test_fetch_all_sources_uses_mock_fallback_when_all_sources_fail() -> None:
    """When every source raises, the pipeline returns a mock threat."""
    with patch.dict(collectors.SOURCE_FETCHERS, dict.fromkeys(collectors.SOURCE_FETCHERS, _raise)):
        threats = collectors.fetch_all_sources()
    assert len(threats) == 1
    assert threats[0]["source"] == "MockData"


def _raise(*_args, **_kwargs):
    raise requests.RequestException("simulated failure")


def test_fetch_all_sources_respects_subset() -> None:
    """Passing ``sources`` should limit which fetchers run."""
    calls: list[str] = []

    def make_fetcher(name: str):
        def _fetcher():
            calls.append(name)
            return []

        return _fetcher

    fake_fetchers = {name: make_fetcher(name) for name in collectors.SOURCE_FETCHERS}
    with patch.dict(collectors.SOURCE_FETCHERS, fake_fetchers):
        collectors.fetch_all_sources(sources=["urlhaus", "rss"])
    assert set(calls) == {"urlhaus", "rss"}


def test_fetch_all_sources_warns_on_unknown_source() -> None:
    """Unknown source names are skipped, not raised."""
    with patch.dict(collectors.SOURCE_FETCHERS, {"urlhaus": lambda: []}):
        threats = collectors.fetch_all_sources(sources=["urlhaus", "nonexistent"])
    # Mock fallback should not trigger because urlhaus returned [].
    assert threats[0]["source"] == "MockData"
