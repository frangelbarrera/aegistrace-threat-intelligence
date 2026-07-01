"""Tests for ``aegistrace.enricher`` with mocked HTTP APIs."""

from __future__ import annotations

from unittest.mock import patch

import requests

from aegistrace import enricher


def test_enrich_iocs_disabled_marks_all_as_disabled(sample_iocs: list[dict]) -> None:
    with patch("aegistrace.config.ENABLE_ENRICHMENT", False):
        result = enricher.enrich_iocs(sample_iocs)
    assert len(result) == len(sample_iocs)
    for ioc in result:
        assert ioc["reputation"] == "disabled"
        assert ioc["note"] == "enrichment disabled"
        assert ioc["campaigns"] == []


def test_enrich_iocs_missing_keys_does_not_crash(sample_iocs: list[dict]) -> None:
    # Make sure all API keys are empty so we exercise the missing-key paths.
    with (
        patch("aegistrace.config.ABUSEIPDB_API_KEY", ""),
        patch("aegistrace.config.VIRUSTOTAL_API_KEY", ""),
        patch("aegistrace.config.PULSEDIVE_API_KEY", ""),
        patch("aegistrace.config.ENABLE_ENRICHMENT", True),
        patch("aegistrace.enricher.requests.get") as mock_get,
    ):
        # Stub out requests.get so no real network call is attempted.
        mock_get.side_effect = requests.RequestException("network down")
        result = enricher.enrich_iocs(sample_iocs)

    assert len(result) == len(sample_iocs)
    for ioc in result:
        assert "reputation" in ioc
        assert isinstance(ioc["campaigns"], list)


def test_enrich_iocs_abuseipdb_success(sample_iocs: list[dict]) -> None:
    """A successful AbuseIPDB response should populate reputation + country."""

    class FakeResponse:
        status_code = 200

        def json(self) -> dict:
            return {
                "data": {
                    "abuseConfidenceScore": 87,
                    "countryCode": "RU",
                }
            }

    with (
        patch("aegistrace.config.ABUSEIPDB_API_KEY", "fake-key"),
        patch("aegistrace.config.PULSEDIVE_API_KEY", ""),
        patch("aegistrace.config.ENABLE_ENRICHMENT", True),
        patch("aegistrace.enricher.requests.get", return_value=FakeResponse()),
    ):
        result = enricher.enrich_iocs(sample_iocs)

    ip_ioc = next(i for i in result if i["type"] == "ip")
    assert "AbuseIPDB:87/100" in ip_ioc["reputation"]
    assert ip_ioc["country"] == "RU"
    assert ip_ioc["details_url"] == "https://www.abuseipdb.com/check/185.220.101.34"


def test_enrich_iocs_virustotal_success_for_hash(sample_iocs: list[dict]) -> None:
    """A successful VirusTotal response populates the hash IoC."""

    class FakeResponse:
        status_code = 200

        def json(self) -> dict:
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 12, "suspicious": 2, "harmless": 60}
                    }
                }
            }

    with (
        patch("aegistrace.config.VIRUSTOTAL_API_KEY", "fake-vt-key"),
        patch("aegistrace.config.ENABLE_ENRICHMENT", True),
        patch("aegistrace.enricher.requests.get", return_value=FakeResponse()),
    ):
        result = enricher.enrich_iocs(sample_iocs)

    hash_ioc = next(i for i in result if i["type"] == "hash")
    assert "VT:m=12,s=2" in hash_ioc["reputation"]
    assert hash_ioc["details_url"].startswith("https://www.virustotal.com/gui/file/")


def test_enrich_iocs_handles_api_error_gracefully(sample_iocs: list[dict]) -> None:
    """A raising requests.get must not crash the pipeline."""

    with (
        patch("aegistrace.config.ABUSEIPDB_API_KEY", "fake-key"),
        patch("aegistrace.config.PULSEDIVE_API_KEY", "fake-pd-key"),
        patch("aegistrace.config.VIRUSTOTAL_API_KEY", "fake-vt-key"),
        patch("aegistrace.config.ENABLE_ENRICHMENT", True),
        patch("aegistrace.enricher.requests.get", side_effect=requests.RequestException("boom")),
    ):
        result = enricher.enrich_iocs(sample_iocs)

    assert len(result) == len(sample_iocs)
    for ioc in result:
        # Reputation is always populated (either with error parts or "no_data").
        assert isinstance(ioc["reputation"], str) and ioc["reputation"]
        assert ioc["active"] in {"unknown", "active", "inactive"}


def test_enrich_iocs_preserves_indicator_and_type(sample_iocs: list[dict]) -> None:
    with patch("aegistrace.config.ENABLE_ENRICHMENT", False):
        result = enricher.enrich_iocs(sample_iocs)
    original = {(i["indicator"], i["type"]) for i in sample_iocs}
    enriched = {(i["indicator"], i["type"]) for i in result}
    assert original == enriched


def test_enrich_iocs_empty_input_returns_empty() -> None:
    assert enricher.enrich_iocs([]) == []


def test_enrich_iocs_unknown_type_uses_note(sample_iocs: list[dict]) -> None:
    weird = [{"indicator": "weird", "type": "url", "sources": [], "titles": [], "first_seen": None}]
    with patch("aegistrace.config.ENABLE_ENRICHMENT", True):
        # No HTTP calls expected for unknown type.
        result = enricher.enrich_iocs(weird)
    assert len(result) == 1
    assert "unknown_type:url" in (result[0].get("note") or "")
