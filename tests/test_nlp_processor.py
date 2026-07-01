"""Tests for ``aegistrace.nlp_processor``."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from aegistrace.nlp_processor import classify_threat, process_nlp


def test_classify_threat_recognises_ransomware() -> None:
    assert classify_threat("LockBit ransomware encrypts files") == "Ransomware"


def test_classify_threat_recognises_phishing() -> None:
    assert classify_threat("Phishing campaign steals credentials") == "Phishing"


def test_classify_threat_recognises_malware() -> None:
    assert classify_threat("New trojan malware sample analyzed") == "Malware"


def test_classify_threat_recognises_apt() -> None:
    assert classify_threat("APT29 state-sponsored attack") == "APT"


def test_classify_threat_recognises_vulnerability() -> None:
    assert classify_threat("CVE-2026-1234 zero-day exploit") == "Vulnerability"


def test_classify_threat_recognises_data_breach() -> None:
    assert classify_threat("Massive data breach leaks records") == "Data Breach"


def test_classify_threat_returns_uncategorized_when_no_match() -> None:
    assert classify_threat("just some random text") == "Uncategorized"


def test_classify_threat_is_case_insensitive() -> None:
    assert classify_threat("RANSOMWARE detected") == "Ransomware"


def test_classify_threat_handles_empty_string() -> None:
    assert classify_threat("") == "Uncategorized"


def test_classify_threat_handles_none() -> None:
    assert classify_threat(None) == "Uncategorized"  # type: ignore[arg-type]


def test_process_nlp_adds_required_fields(sample_threats: list[dict]) -> None:
    """process_nlp must always populate entities, summary_nlp, threat_type."""
    with patch("aegistrace.nlp_processor._get_nlp", return_value=None):
        result = process_nlp(sample_threats)
    for threat in result:
        assert "entities" in threat
        assert "summary_nlp" in threat
        assert "threat_type" in threat
        assert isinstance(threat["entities"], list)
        assert isinstance(threat["summary_nlp"], str)


def test_process_nlp_falls_back_to_summary_when_no_spacy(sample_threats: list[dict]) -> None:
    with patch("aegistrace.nlp_processor._get_nlp", return_value=None):
        result = process_nlp(sample_threats)
    for threat in result:
        assert threat["summary_nlp"] == (threat.get("summary") or "")
        assert threat["entities"] == []


def test_process_nlp_classifies_each_threat(sample_threats: list[dict]) -> None:
    with patch("aegistrace.nlp_processor._get_nlp", return_value=None):
        result = process_nlp(sample_threats)
    types = {t["threat_type"] for t in result}
    assert "Ransomware" in types  # the LockBit threat
    assert "Phishing" in types    # the phishing threat
    assert "Vulnerability" in types  # the CVE threat


def test_process_nlp_with_real_spacy_model(sample_threats: list[dict]) -> None:
    """If the spaCy model is installed, exercise the full code path."""
    try:
        import spacy

        spacy.load("en_core_web_sm")
    except OSError:
        pytest.skip("spaCy model en_core_web_sm not installed")
    result = process_nlp([dict(t) for t in sample_threats])
    for threat in result:
        assert "entities" in threat
        assert isinstance(threat["entities"], list)
        assert "summary_nlp" in threat
        assert isinstance(threat["summary_nlp"], str)


def test_process_nlp_empty_input_returns_empty() -> None:
    assert process_nlp([]) == []


def test_process_nlp_handles_missing_summary() -> None:
    threats = [{"title": "Just a title with ransomware"}]
    with patch("aegistrace.nlp_processor._get_nlp", return_value=None):
        result = process_nlp(threats)
    assert result[0]["threat_type"] == "Ransomware"
    assert result[0]["summary_nlp"] == ""
    assert result[0]["entities"] == []
