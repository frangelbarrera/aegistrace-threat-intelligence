"""Threat data collectors.

Pulls threat intelligence from multiple open sources and normalises every
record into a common dict shape so the rest of the pipeline can treat them
uniformly::

    {
        "title":     str,
        "summary":   str,
        "url":       str,
        "sector":    str,
        "timestamp": datetime,
        "source":    str,
    }
"""

from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Any

import requests

from . import config
from .logging_config import get_logger

logger = get_logger(__name__)

HEADERS_GENERIC: dict[str, str] = {"User-Agent": config.USER_AGENT}


def _parse_datetime(value: str, fmt: str = "%Y-%m-%d %H:%M:%S") -> datetime:
    """Parse a datetime string, falling back to ``datetime.now()`` on errors."""
    try:
        return datetime.strptime(value, fmt)
    except (ValueError, TypeError):
        logger.warning("Could not parse datetime %r with fmt %r; using now()", value, fmt)
        return datetime.now()


def fetch_otx() -> list[dict[str, Any]]:
    """Fetch subscribed pulses from AlienVault OTX.

    Returns an empty list when no API key is configured or the request
    fails; the rest of the pipeline continues regardless.
    """
    threats: list[dict[str, Any]] = []
    api_key = config.otx_api_key()
    if not api_key:
        logger.info("OTX API key missing, skipping OTX source")
        return threats

    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10"
    headers = {"X-OTX-API-KEY": api_key, **HEADERS_GENERIC}
    try:
        resp = requests.get(url, headers=headers, timeout=config.HTTP_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("OTX returned status %d", resp.status_code)
            return threats
        for pulse in resp.json().get("results", []):
            references = pulse.get("references") or ["#"]
            industries = pulse.get("industries") or ["General"]
            threats.append(
                {
                    "title": pulse.get("name", "Unknown Threat"),
                    "summary": (pulse.get("description", "") or "")[:200] + "...",
                    "url": references[0] if isinstance(references, list) else references,
                    "sector": industries[0] if isinstance(industries, list) else industries,
                    "timestamp": _parse_iso(pulse.get("created")),
                    "source": "OTX",
                }
            )
    except Exception as exc:  # noqa: BLE001 - external call, never crash pipeline
        logger.warning("OTX fetch error: %s", exc)
    return threats


def _parse_iso(value: Any) -> datetime:
    """Best-effort ISO-8601 parser used by the OTX collector."""
    if not value:
        return datetime.now()
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return datetime.now()


def fetch_rss() -> list[dict[str, Any]]:
    """Fetch the configured RSS feeds and parse the latest items."""
    threats: list[dict[str, Any]] = []
    for feed_url in config.RSS_FEEDS:
        try:
            resp = requests.get(feed_url, headers=HEADERS_GENERIC, timeout=config.HTTP_TIMEOUT)
            if resp.status_code != 200:
                logger.warning("RSS %s returned status %d", feed_url, resp.status_code)
                continue
            root = ET.fromstring(resp.content)
            for entry in root.findall(".//item")[:5]:
                threats.append(
                    {
                        "title": entry.findtext("title", "Unknown") or "Unknown",
                        "summary": (entry.findtext("description") or "")[:200] + "...",
                        "url": entry.findtext("link", "#") or "#",
                        "sector": "General",
                        "timestamp": datetime.now() - timedelta(hours=1),
                        "source": feed_url,
                    }
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("RSS fetch error (%s): %s", feed_url, exc)
    return threats


def fetch_urlhaus() -> list[dict[str, Any]]:
    """Fetch recent malicious URLs from URLhaus.

    The CSV header is ``id,dateadded,url,url_status,last_online,threat,
    tags,urlhaus_link,reporter``. Comment lines start with ``#``.
    """
    threats: list[dict[str, Any]] = []
    try:
        resp = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            headers=HEADERS_GENERIC,
            timeout=config.HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("URLhaus returned status %d", resp.status_code)
            return threats
        reader = csv.reader(io.StringIO(resp.text))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # Skip the in-band header row ("id,dateadded,...")
            if row[0].strip().lower() == "id":
                continue
            if len(row) < 9:
                continue
            _id, date_added, url, _url_status, _last_online, threat_type, tags, _link, _reporter = row[:9]
            threats.append(
                {
                    "title": f"URLhaus: {threat_type}",
                    "summary": f"Malicious URL reported to URLhaus. Tags: {tags}",
                    "url": url,
                    "sector": "Unknown",
                    "timestamp": _parse_datetime(date_added),
                    "source": "URLhaus",
                }
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("URLhaus fetch error: %s", exc)
    return threats


def fetch_malwarebazaar() -> list[dict[str, Any]]:
    """Fetch recent malware samples from MalwareBazaar."""
    threats: list[dict[str, Any]] = []
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent"},
            headers=HEADERS_GENERIC,
            timeout=config.HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("MalwareBazaar returned status %d", resp.status_code)
            return threats
        data = resp.json()
        for sample in data.get("data", [])[:10]:
            threats.append(
                {
                    "title": f"MalwareBazaar: {sample.get('file_type')}",
                    "summary": f"Malware sample {sample.get('sha256_hash')} ({sample.get('file_type')})",
                    "url": "#",
                    "sector": "Unknown",
                    "timestamp": _parse_datetime(sample.get("first_seen", "")),
                    "source": "MalwareBazaar",
                }
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("MalwareBazaar fetch error: %s", exc)
    return threats


def fetch_feodotracker() -> list[dict[str, Any]]:
    """Fetch the Feodo Tracker C2 IP blocklist.

    The CSV header is ``first_seen_utc,dst_ip,dst_port,c2_status,
    last_online,malware``. Comment lines start with ``#``.
    """
    threats: list[dict[str, Any]] = []
    try:
        resp = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            headers=HEADERS_GENERIC,
            timeout=config.HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("FeodoTracker returned status %d", resp.status_code)
            return threats
        reader = csv.reader(io.StringIO(resp.text))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # Skip the in-band header row ("first_seen_utc,dst_ip,...")
            if row[0].strip().lower().startswith("first_seen"):
                continue
            if len(row) < 6:
                continue
            first_seen, ip, _port, _status, _last_online, malware = row[:6]
            threats.append(
                {
                    "title": f"FeodoTracker: {malware}",
                    "summary": f"IP {ip} associated with {malware} C2 server.",
                    "url": "#",
                    "sector": "Unknown",
                    "timestamp": _parse_datetime(first_seen),
                    "source": "FeodoTracker",
                }
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("FeodoTracker fetch error: %s", exc)
    return threats


# Map of source name -> fetcher, used by the CLI ``--sources`` flag.
SOURCE_FETCHERS: dict[str, Any] = {
    "otx": fetch_otx,
    "rss": fetch_rss,
    "urlhaus": fetch_urlhaus,
    "malwarebazaar": fetch_malwarebazaar,
    "feodotracker": fetch_feodotracker,
}


def fetch_all_sources(sources: list[str] | None = None) -> list[dict[str, Any]]:
    """Collect threats from every configured source.

    Args:
        sources: Optional subset of source names (keys of
            :data:`SOURCE_FETCHERS`). ``None`` means "all sources".

    Returns:
        List of normalised threat dicts, sorted newest-first, capped at
        :data:`config.MAX_THREATS`. If no real data is fetched a single
        mock threat is returned so the rest of the pipeline can still run.
    """
    selected = list(sources) if sources else list(SOURCE_FETCHERS.keys())
    all_threats: list[dict[str, Any]] = []
    for name in selected:
        fetcher = SOURCE_FETCHERS.get(name.lower())
        if fetcher is None:
            logger.warning("Unknown source %r, skipping", name)
            continue
        try:
            all_threats.extend(fetcher())
        except Exception as exc:  # noqa: BLE001 - never let one source kill the rest
            logger.warning("Source %s failed: %s", name, exc)

    if not all_threats:
        logger.warning("No real data fetched. Using mock data.")
        all_threats.append(
            {
                "title": "Mock Threat",
                "summary": "Simulated threat for testing.",
                "url": "#",
                "sector": "General",
                "timestamp": datetime.now(),
                "source": "MockData",
            }
        )

    return sorted(all_threats, key=lambda x: x["timestamp"], reverse=True)[: config.MAX_THREATS]
