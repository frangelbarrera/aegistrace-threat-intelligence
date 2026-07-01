"""IoC extraction from threat text.

Pure-regex extraction of IPv4 addresses, domains and file hashes from the
``title``, ``summary`` and ``url`` of each threat record. The extractor
deduplicates and aggregates indicators across threats so a single IoC
that appears in multiple sources keeps references to every source.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

# === Regular expressions for IoC detection ==============================
# Practical, conservative patterns. They deliberately avoid edge cases
# like IPv6 (too many false positives against the domain regex) and
# Punycode domains.
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,24}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _norm_domain(d: str) -> str:
    """Strip surrounding punctuation and lowercase a domain."""
    return d.strip().strip(".,;:\"'()[]{}").lower()


def _norm_ip(ip: str) -> str:
    """Strip surrounding punctuation from an IP address."""
    return ip.strip().strip(".,;:\"'()[]{}")


def _norm_hash(h: str) -> str:
    """Lowercase a hash."""
    return h.strip().lower()


def _extract_from_text(text: str) -> dict[str, set[str]]:
    """Extract IoCs from a single text blob.

    Args:
        text: Free text to scan.

    Returns:
        Dict with three sets: ``{"ip": {...}, "domain": {...}, "hash": {...}}``.
    """
    iocs: dict[str, set[str]] = {"ip": set(), "domain": set(), "hash": set()}
    if not text:
        return iocs

    for m in IPV4_RE.findall(text):
        iocs["ip"].add(_norm_ip(m))

    for m in DOMAIN_RE.findall(text):
        if IPV4_RE.match(m):
            continue
        iocs["domain"].add(_norm_domain(m))

    for m in MD5_RE.findall(text):
        iocs["hash"].add(_norm_hash(m))
    for m in SHA1_RE.findall(text):
        iocs["hash"].add(_norm_hash(m))
    for m in SHA256_RE.findall(text):
        iocs["hash"].add(_norm_hash(m))

    return iocs


def extract_iocs(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract and aggregate IoCs across threat records.

    Args:
        threats: List of threat dicts containing at least ``title``,
            ``summary`` (or ``summary_nlp``) and ``url``.

    Returns:
        List of dicts, one per unique IoC, with keys:
          - ``indicator``: the IoC value.
          - ``type``: ``"ip"`` | ``"domain"`` | ``"hash"``.
          - ``sources``: sorted list of URLs where the IoC was seen.
          - ``titles``: sorted list of threat titles where it appeared.
          - ``first_seen``: ``None``, reserved for the enricher.
    """
    ioc_map: dict[tuple[str, str], dict[str, Any]] = {}

    for t in threats:
        title = t.get("title", "") or ""
        summary = t.get("summary", "") or t.get("summary_nlp", "") or ""
        url = t.get("url", "") or ""
        text_blob = " ".join([title, summary, url])

        found = _extract_from_text(text_blob)

        # Pull the host out of an HTTP(S) URL as an extra domain IoC.
        if url.startswith("http"):
            try:
                parsed = urlparse(url)
                host = parsed.hostname
                if host and DOMAIN_RE.match(host):
                    found["domain"].add(_norm_domain(host))
            except Exception:  # noqa: BLE001
                pass

        for ioc_type, source_set in found.items():
            for value in source_set:
                key = (value, ioc_type)
                ioc = ioc_map.get(
                    key, {"indicator": value, "type": ioc_type, "sources": set(), "titles": set()}
                )
                if url:
                    ioc["sources"].add(url)
                if title:
                    ioc["titles"].add(title)
                ioc_map[key] = ioc

    return [
        {
            "indicator": data["indicator"],
            "type": data["type"],
            "sources": sorted(data["sources"]),
            "titles": sorted(data["titles"]),
            "first_seen": None,
        }
        for (_, _type), data in ioc_map.items()
    ]
