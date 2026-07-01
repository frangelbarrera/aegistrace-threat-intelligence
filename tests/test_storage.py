"""Tests for ``aegistrace.storage`` (SQLite layer)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from aegistrace.storage import (
    init_db,
    load_threat_counts,
    save_iocs,
    save_threats,
)


def test_init_db_creates_tables(tmp_db: str) -> None:
    init_db(tmp_db)
    conn = sqlite3.connect(tmp_db)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        names = {row[0] for row in cur.fetchall()}
    finally:
        conn.close()
    assert "threats" in names
    assert "iocs" in names


def test_init_db_is_idempotent(tmp_db: str) -> None:
    init_db(tmp_db)
    init_db(tmp_db)  # must not raise
    assert Path(tmp_db).exists()


def test_save_threats_persists_records(tmp_db: str) -> None:
    init_db(tmp_db)
    threats = [
        {
            "title": "Test threat 1",
            "summary_nlp": "Summary one",
            "sector": "Finance",
            "threat_type": "Ransomware",
            "source": "MockData",
        },
        {
            "title": "Test threat 2",
            "summary": "Summary two",
            "sector": "Healthcare",
            "threat_type": "Phishing",
            "source": "MockData",
        },
    ]
    inserted = save_threats(threats, tmp_db)
    assert inserted == 2

    conn = sqlite3.connect(tmp_db)
    try:
        cur = conn.cursor()
        cur.execute("SELECT title, sector, threat_type FROM threats ORDER BY title")
        rows = cur.fetchall()
    finally:
        conn.close()
    assert rows == [
        ("Test threat 1", "Finance", "Ransomware"),
        ("Test threat 2", "Healthcare", "Phishing"),
    ]


def test_save_threats_falls_back_to_summary_when_no_nlp(tmp_db: str) -> None:
    init_db(tmp_db)
    save_threats([{"title": "T", "summary": "raw summary"}], tmp_db)
    conn = sqlite3.connect(tmp_db)
    try:
        cur = conn.cursor()
        cur.execute("SELECT summary FROM threats")
        row = cur.fetchone()
    finally:
        conn.close()
    assert row == ("raw summary",)


def test_save_iocs_persists_enriched_records(tmp_db: str) -> None:
    init_db(tmp_db)
    iocs = [
        {
            "indicator": "1.2.3.4",
            "type": "ip",
            "reputation": "AbuseIPDB:50/100",
            "country": "US",
            "active": "active",
            "campaigns": ["botnet", "c2"],
            "details_url": "https://abuseipdb.com/check/1.2.3.4",
            "first_seen": None,
        }
    ]
    inserted = save_iocs(iocs, tmp_db)
    assert inserted == 1

    conn = sqlite3.connect(tmp_db)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT indicator, type, reputation, country, campaigns FROM iocs"
        )
        row = cur.fetchone()
    finally:
        conn.close()
    assert row == ("1.2.3.4", "ip", "AbuseIPDB:50/100", "US", "botnet, c2")


def test_save_iocs_handles_string_campaigns(tmp_db: str) -> None:
    init_db(tmp_db)
    save_iocs(
        [{"indicator": "x.com", "type": "domain", "campaigns": "single-tag"}],
        tmp_db,
    )
    conn = sqlite3.connect(tmp_db)
    try:
        cur = conn.cursor()
        cur.execute("SELECT campaigns FROM iocs")
        row = cur.fetchone()
    finally:
        conn.close()
    assert row == ("single-tag",)


def test_load_threat_counts_returns_empty_when_no_data(tmp_db: str) -> None:
    init_db(tmp_db)
    assert load_threat_counts(days=30, db_file=tmp_db) == []


def test_load_threat_counts_returns_rows_after_insert(tmp_db: str) -> None:
    init_db(tmp_db)
    save_threats(
        [
            {"title": "T1", "summary": "s", "sector": "x", "threat_type": "y", "source": "z"},
            {"title": "T2", "summary": "s", "sector": "x", "threat_type": "y", "source": "z"},
        ],
        tmp_db,
    )
    counts = load_threat_counts(days=30, db_file=tmp_db)
    assert len(counts) == 1
    date_str, count = counts[0]
    assert isinstance(date_str, str)
    assert count == 2


def test_save_threats_handles_empty_iterable(tmp_db: str) -> None:
    init_db(tmp_db)
    assert save_threats([], tmp_db) == 0
