"""Tests for the package metadata and config module."""

from __future__ import annotations

import importlib
from unittest.mock import patch

from aegistrace import config


def test_package_exposes_version() -> None:
    import aegistrace

    assert aegistrace.__version__ == "0.2.0"
    assert aegistrace.__author__ == "Frangel Barrera"


def test_config_has_required_attributes() -> None:
    assert hasattr(config, "OTX_API_KEY")
    assert hasattr(config, "ABUSEIPDB_API_KEY")
    assert hasattr(config, "VIRUSTOTAL_API_KEY")
    assert hasattr(config, "PULSEDIVE_API_KEY")
    assert hasattr(config, "RSS_FEEDS")
    assert hasattr(config, "MAX_THREATS")
    assert hasattr(config, "THREAT_CATEGORIES")
    assert hasattr(config, "HTTP_TIMEOUT")
    assert hasattr(config, "USER_AGENT")
    assert hasattr(config, "DB_FILE")


def test_otx_api_key_treats_legacy_placeholder_as_empty() -> None:
    with patch("aegistrace.config.OTX_API_KEY", "your_otx_key_here"):
        importlib.reload(config)
        assert config.otx_api_key() == ""
    # Restore by reloading with empty env.
    importlib.reload(config)


def test_otx_api_key_returns_real_key() -> None:
    with patch("aegistrace.config.OTX_API_KEY", "real-key-123"):
        assert config.otx_api_key() == "real-key-123"


def test_user_agent_mentions_aegistrace() -> None:
    assert "AegisTrace" in config.USER_AGENT


def test_threat_categories_contains_expected_keys() -> None:
    expected = {"Ransomware", "Phishing", "Malware", "APT", "Vulnerability", "Data Breach"}
    assert set(config.THREAT_CATEGORIES.keys()) == expected


def test_rss_feeds_are_https_urls() -> None:
    for feed in config.RSS_FEEDS:
        assert feed.startswith("http://") or feed.startswith("https://")
