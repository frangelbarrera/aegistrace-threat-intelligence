"""IoC enrichment via external intelligence APIs.

Enrichment is best-effort: every external call is wrapped so that
network errors, missing API keys or unexpected payloads never break the
pipeline. When enrichment is disabled in :mod:`config` the function
simply tags each IoC with ``"enrichment disabled"``.
"""

from __future__ import annotations

from typing import Any

import requests

from . import config
from .logging_config import get_logger

logger = get_logger(__name__)

HEADERS_GENERIC: dict[str, str] = {"User-Agent": config.USER_AGENT}


def _disabled_ioc(ioc: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``ioc`` tagged as enrichment-disabled."""
    return {
        **ioc,
        "reputation": "disabled",
        "country": None,
        "active": "unknown",
        "campaigns": [],
        "details_url": None,
        "note": "enrichment disabled",
    }


def _enrich_ip(ind: str, base: dict[str, Any]) -> None:
    """Populate ``base`` with AbuseIPDB + Pulsedive data for an IP."""
    if config.ABUSEIPDB_API_KEY:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json", **HEADERS_GENERIC},
                params={"ipAddress": ind, "maxAgeInDays": 90},
                timeout=config.HTTP_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                base["country"] = data.get("countryCode")
                base["reputation_parts"].append(f"AbuseIPDB:{score}/100")
                base["details_url"] = f"https://www.abuseipdb.com/check/{ind}"
            else:
                base["reputation_parts"].append("AbuseIPDB:unavailable")
        except Exception as exc:  # noqa: BLE001
            logger.debug("AbuseIPDB error for %s: %s", ind, exc)
            base["reputation_parts"].append("AbuseIPDB:error")
    else:
        base["reputation_parts"].append("AbuseIPDB:missing_key")

    # Pulsedive (works without a key for some queries)
    try:
        pd_params: dict[str, Any] = {"indicator": ind, "pretty": "1"}
        if config.PULSEDIVE_API_KEY:
            pd_params["key"] = config.PULSEDIVE_API_KEY
        resp = requests.get(
            "https://pulsedive.com/api/info.php",
            params=pd_params,
            headers=HEADERS_GENERIC,
            timeout=config.HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            pdata = resp.json()
            tags = pdata.get("tags") or []
            if isinstance(tags, str):
                tags = [tags]
            if tags:
                base["campaigns"] = tags
            state = pdata.get("state") or pdata.get("status")
            if state:
                base["active"] = state
            if not base["details_url"]:
                base["details_url"] = f"https://pulsedive.com/indicator/?ioc={ind}"
            base["reputation_parts"].append("Pulsedive:ok")
        else:
            base["reputation_parts"].append("Pulsedive:unavailable")
    except Exception as exc:  # noqa: BLE001
        logger.debug("Pulsedive error for %s: %s", ind, exc)
        base["reputation_parts"].append("Pulsedive:error")


def _enrich_domain(ind: str, base: dict[str, Any]) -> None:
    """Populate ``base`` with Pulsedive data for a domain."""
    try:
        pd_params: dict[str, Any] = {"indicator": ind, "pretty": "1"}
        if config.PULSEDIVE_API_KEY:
            pd_params["key"] = config.PULSEDIVE_API_KEY
        resp = requests.get(
            "https://pulsedive.com/api/info.php",
            params=pd_params,
            headers=HEADERS_GENERIC,
            timeout=config.HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            pdata = resp.json()
            tags = pdata.get("tags") or []
            if isinstance(tags, str):
                tags = [tags]
            if tags:
                base["campaigns"] = tags
            state = pdata.get("state") or pdata.get("status")
            if state:
                base["active"] = state
            base["details_url"] = f"https://pulsedive.com/indicator/?ioc={ind}"
            base["reputation_parts"].append("Pulsedive:ok")
        else:
            base["reputation_parts"].append("Pulsedive:unavailable")
    except Exception as exc:  # noqa: BLE001
        logger.debug("Pulsedive error for %s: %s", ind, exc)
        base["reputation_parts"].append("Pulsedive:error")


def _enrich_hash(ind: str, base: dict[str, Any]) -> None:
    """Populate ``base`` with VirusTotal data for a file hash."""
    if config.VIRUSTOTAL_API_KEY:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{ind}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY, **HEADERS_GENERIC},
                timeout=config.HTTP_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                base["reputation_parts"].append(f"VT:m={malicious},s={suspicious}")
                base["details_url"] = f"https://www.virustotal.com/gui/file/{ind}"
                base["active"] = "unknown"
            elif resp.status_code == 404:
                base["reputation_parts"].append("VT:not_found")
            else:
                base["reputation_parts"].append("VT:unavailable")
        except Exception as exc:  # noqa: BLE001
            logger.debug("VirusTotal error for %s: %s", ind, exc)
            base["reputation_parts"].append("VT:error")
    else:
        base["reputation_parts"].append("VT:missing_key")


def enrich_iocs(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich a list of IoCs using available external sources.

    Each IoC dict is updated in place and returned. New fields:

      - ``reputation``: ``";"``-joined reputation strings.
      - ``country``: ISO country code (IP only, when AbuseIPDB responds).
      - ``active``: ``"unknown"`` | ``"active"`` | ``"inactive"`` | other.
      - ``campaigns``: list of tags/campaign names.
      - ``details_url``: link to a public reference page.
      - ``note``: short status message.

    Args:
        iocs: List of IoC dicts as produced by
            :func:`aegistrace.ioc_extractor.extract_iocs`.

    Returns:
        The same list (mutated) with the enrichment fields populated.
    """
    if not config.ENABLE_ENRICHMENT:
        return [_disabled_ioc(ioc) for ioc in iocs]

    out: list[dict[str, Any]] = []
    for ioc in iocs:
        base: dict[str, Any] = {
            "reputation": "",
            "country": None,
            "active": "unknown",
            "campaigns": [],
            "details_url": None,
            "note": "",
            "reputation_parts": [],
        }
        ind = ioc["indicator"]
        typ = ioc["type"]
        try:
            if typ == "ip":
                _enrich_ip(ind, base)
            elif typ == "domain":
                _enrich_domain(ind, base)
            elif typ == "hash":
                _enrich_hash(ind, base)
            else:
                base["note"] = f"unknown_type:{typ}"

            reputation = "; ".join(p for p in base["reputation_parts"] if p)
            base["reputation"] = reputation or "no_data"
            base.pop("reputation_parts", None)

            if not ioc.get("first_seen"):
                ioc["first_seen"] = None

            out.append({**ioc, **base})
        except Exception as exc:  # noqa: BLE001 - never break on enrichment
            logger.warning("Enrichment failed for %s: %s", ind, exc)
            out.append(
                {
                    **ioc,
                    "reputation": "error",
                    "country": None,
                    "active": "unknown",
                    "campaigns": [],
                    "details_url": None,
                    "note": f"error:{type(exc).__name__}",
                }
            )
    return out
