"""Shared pytest fixtures for AegisTrace tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


@pytest.fixture
def sample_threats() -> list[dict[str, Any]]:
    """A small set of realistic threat records for tests."""
    return [
        {
            "title": "LockBit 3.0 ransomware hits ACME Corp",
            "summary": (
                "ACME Corp disclosed a ransomware incident. The LockBit 3.0 "
                "affiliate encrypted 1.2 TB of data and demanded a ransom. "
                "Indicator 185.220.101.34 was used as C2."
            ),
            "url": "https://example.com/article/lockbit-acme",
            "sector": "Finance",
            "source": "MockData",
            "timestamp": "2026-06-15T10:00:00",
        },
        {
            "title": "Phishing campaign spoofs Bank of America",
            "summary": (
                "A phishing kit was found at https://login.bank-of-america.example.com/login "
                "targeting US customers. SHA256 hash "
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
                "matches the dropped payload."
            ),
            "url": "https://example.com/phishing-boa",
            "sector": "Finance",
            "source": "MockData",
            "timestamp": "2026-06-16T11:00:00",
        },
        {
            "title": "CVE-2026-1234 zero-day in Apache Struts",
            "summary": "Patch now: a remote code execution vulnerability affects Apache Struts.",
            "url": "https://example.com/cve-2026-1234",
            "sector": "Technology",
            "source": "MockData",
            "timestamp": "2026-06-17T09:00:00",
        },
    ]


@pytest.fixture
def sample_text_with_iocs() -> str:
    """Text containing a representative mix of IoCs."""
    return (
        "C2 server at 185.220.101.34 was observed communicating with "
        "evil.example.com. Sample MD5: d41d8cd98f00b204e9800998ecf8427e. "
        "SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d. "
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
    )


@pytest.fixture
def sample_iocs() -> list[dict[str, Any]]:
    """Pre-extracted IoCs for enricher tests."""
    return [
        {"indicator": "185.220.101.34", "type": "ip", "sources": ["https://a.example"], "titles": ["T1"], "first_seen": None},
        {"indicator": "evil.example.com", "type": "domain", "sources": ["https://b.example"], "titles": ["T2"], "first_seen": None},
        {
            "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": "hash",
            "sources": ["https://c.example"],
            "titles": ["T3"],
            "first_seen": None,
        },
    ]


@pytest.fixture
def tmp_db(tmp_path: Path) -> str:
    """Return a path to a fresh SQLite database file inside a tmp dir."""
    return str(tmp_path / "test.db")


@pytest.fixture
def initialized_db(tmp_db: str) -> str:
    """Return a path to an initialised (empty) SQLite database."""
    from aegistrace.storage import init_db

    init_db(tmp_db)
    return tmp_db


@pytest.fixture(autouse=True)
def _isolate_runtime(monkeypatch, tmp_path):
    """Run each test in an isolated working directory with a fresh DB.

    Prevents tests from clobbering the developer's local ``threatintel.db``
    or writing ``dashboard.html`` / ``iocs_enriched.csv`` into the repo.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AEGISTRACE_DB_FILE", str(tmp_path / "test.db"))
    # Patch DB_FILE at module level so storage picks it up.
    with patch("aegistrace.config.DB_FILE", str(tmp_path / "test.db")):
        yield
