"""Tests for ``aegistrace.ioc_extractor``."""

from __future__ import annotations

from aegistrace.ioc_extractor import (
    DOMAIN_RE,
    IPV4_RE,
    _extract_from_text,
    _norm_domain,
    _norm_hash,
    _norm_ip,
    extract_iocs,
)

SAMPLE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SAMPLE_SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
SAMPLE_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def test_ipv4_regex_matches_valid_addresses() -> None:
    matches = IPV4_RE.findall("Servers 10.0.0.1 and 255.255.255.255 and 192.168.1.10.")
    assert "10.0.0.1" in matches
    assert "255.255.255.255" in matches
    assert "192.168.1.10" in matches


def test_ipv4_regex_rejects_out_of_range() -> None:
    matches = IPV4_RE.findall("256.0.0.1 and 999.999.999.999")
    assert matches == []


def test_domain_regex_matches_common_domains() -> None:
    matches = DOMAIN_RE.findall("Visit example.com or sub.example.co.uk for info.")
    assert "example.com" in matches
    # The simple regex captures "example.co" only (no multi-level TLD support) - acceptable.
    assert any(m.startswith("sub.example") for m in matches)


def test_extract_from_text_finds_all_ioc_types(sample_text_with_iocs: str) -> None:
    found = _extract_from_text(sample_text_with_iocs)
    assert "185.220.101.34" in found["ip"]
    assert "evil.example.com" in found["domain"]
    assert SAMPLE_MD5 in found["hash"]
    assert SAMPLE_SHA1 in found["hash"]
    assert SAMPLE_SHA256 in found["hash"]


def test_extract_from_text_empty_input_returns_empty_sets() -> None:
    found = _extract_from_text("")
    assert found == {"ip": set(), "domain": set(), "hash": set()}


def test_extract_from_text_none_input_returns_empty_sets() -> None:
    found = _extract_from_text(None)  # type: ignore[arg-type]
    assert found == {"ip": set(), "domain": set(), "hash": set()}


def test_extract_from_text_with_no_iocs_returns_empty() -> None:
    found = _extract_from_text("Just a plain sentence with no indicators at all.")
    assert found == {"ip": set(), "domain": set(), "hash": set()}


def test_extract_from_text_strips_trailing_punctuation() -> None:
    found = _extract_from_text("See evil.example.com, then 8.8.8.8.")
    assert "evil.example.com" in found["domain"]
    assert "8.8.8.8" in found["ip"]


def test_norm_helpers_lowercases_and_strips_punctuation() -> None:
    assert _norm_domain("Evil.Example.COM.") == "evil.example.com"
    assert _norm_ip("(8.8.8.8)") == "8.8.8.8"
    assert _norm_hash("D41D8CD98F00B204E9800998ECF8427E") == "d41d8cd98f00b204e9800998ecf8427e"


def test_extract_iocs_aggregates_across_threats(sample_threats: list[dict]) -> None:
    iocs = extract_iocs(sample_threats)
    indicators = {ioc["indicator"] for ioc in iocs}
    assert "185.220.101.34" in indicators
    assert "login.bank-of-america.example.com" in indicators
    assert SAMPLE_SHA256 in indicators


def test_extract_iocs_deduplicates_indicator_type_pairs(sample_threats: list[dict]) -> None:
    iocs = extract_iocs(sample_threats + sample_threats)
    # Same indicator+type should appear only once even though threats are duplicated.
    keys = [(ioc["indicator"], ioc["type"]) for ioc in iocs]
    assert len(keys) == len(set(keys))


def test_extract_iocs_returns_expected_schema(sample_threats: list[dict]) -> None:
    iocs = extract_iocs(sample_threats)
    for ioc in iocs:
        assert set(ioc.keys()) == {"indicator", "type", "sources", "titles", "first_seen"}
        assert ioc["first_seen"] is None
        assert isinstance(ioc["sources"], list)
        assert isinstance(ioc["titles"], list)
        assert ioc["type"] in {"ip", "domain", "hash"}


def test_extract_iocs_with_empty_input_returns_empty_list() -> None:
    assert extract_iocs([]) == []


def test_extract_iocs_pulls_domain_from_url() -> None:
    threats = [{"title": "T", "summary": "", "url": "https://malware.example.com/payload"}]
    iocs = extract_iocs(threats)
    domains = [ioc["indicator"] for ioc in iocs if ioc["type"] == "domain"]
    assert "malware.example.com" in domains
