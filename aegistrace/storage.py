"""SQLite persistence for threats and IoCs.

The schema is intentionally simple and append-only. Each run adds new
rows; the predictor reads aggregated daily counts from the ``threats``
table to feed the ARIMA model.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from . import config
from .logging_config import get_logger

logger = get_logger(__name__)


def _resolve_db(db_file: str | None = None) -> str:
    """Return the active DB path, falling back to ``config.DB_FILE``.

    Reading the value lazily lets tests (and users) override ``DB_FILE``
    at runtime via ``monkeypatch`` without re-importing the module.
    """
    return db_file or config.DB_FILE


def _connect(db_file: str | None = None) -> sqlite3.Connection:
    """Open a SQLite connection. Kept tiny so tests can override the path."""
    return sqlite3.connect(_resolve_db(db_file))


def init_db(db_file: str | None = None) -> None:
    """Create the ``threats`` and ``iocs`` tables if they do not exist.

    Args:
        db_file: Path to the SQLite database file. Defaults to ``DB_FILE``
            from :mod:`aegistrace.config`.
    """
    conn = _connect(db_file)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                summary TEXT,
                sector TEXT,
                threat_type TEXT,
                source TEXT,
                timestamp TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT,
                type TEXT,
                reputation TEXT,
                country TEXT,
                active TEXT,
                campaigns TEXT,
                details_url TEXT,
                first_seen TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def save_threats(threats: Iterable[dict[str, Any]], db_file: str | None = None) -> int:
    """Persist threat records into the ``threats`` table.

    Args:
        threats: Iterable of threat dicts. Each dict should contain the
            keys produced by :func:`aegistrace.nlp_processor.process_nlp`
            (``title``, ``summary``/``summary_nlp``, ``sector``,
            ``threat_type``, ``source``).
        db_file: SQLite database path.

    Returns:
        Number of rows inserted.
    """
    conn = _connect(db_file)
    inserted = 0
    try:
        cur = conn.cursor()
        for t in threats:
            cur.execute(
                """
                INSERT INTO threats (title, summary, sector, threat_type, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    t.get("title"),
                    t.get("summary_nlp") or t.get("summary"),
                    t.get("sector"),
                    t.get("threat_type"),
                    t.get("source"),
                    datetime.now().isoformat(),
                ),
            )
            inserted += 1
        conn.commit()
    finally:
        conn.close()
    logger.info("Saved %d threats to %s", inserted, _resolve_db(db_file))
    return inserted


def save_iocs(iocs: Iterable[dict[str, Any]], db_file: str | None = None) -> int:
    """Persist enriched IoC records into the ``iocs`` table.

    Args:
        iocs: Iterable of IoC dicts as produced by
            :func:`aegistrace.enricher.enrich_iocs`.
        db_file: SQLite database path.

    Returns:
        Number of rows inserted.
    """
    conn = _connect(db_file)
    inserted = 0
    try:
        cur = conn.cursor()
        for i in iocs:
            campaigns = i.get("campaigns")
            if isinstance(campaigns, list):
                campaigns = ", ".join(campaigns)
            cur.execute(
                """
                INSERT INTO iocs (indicator, type, reputation, country, active, campaigns, details_url, first_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    i.get("indicator"),
                    i.get("type"),
                    i.get("reputation"),
                    i.get("country"),
                    i.get("active"),
                    campaigns,
                    i.get("details_url"),
                    i.get("first_seen"),
                ),
            )
            inserted += 1
        conn.commit()
    finally:
        conn.close()
    logger.info("Saved %d iocs to %s", inserted, _resolve_db(db_file))
    return inserted


def load_threat_counts(days: int = 30, db_file: str | None = None) -> list[tuple[str, int]]:
    """Return daily threat counts for the last ``days`` days.

    Args:
        days: Lookback window in days.
        db_file: SQLite database path.

    Returns:
        List of ``(date_string, count)`` tuples ordered by date ascending.
        Returns an empty list if the database or ``threats`` table does
        not exist yet.
    """
    try:
        conn = _connect(db_file)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT date(timestamp), COUNT(*) FROM threats
                WHERE date(timestamp) >= date('now', ?)
                GROUP BY date(timestamp)
                ORDER BY date(timestamp)
                """,
                (f"-{days} day",),
            )
            rows = cur.fetchall()
        finally:
            conn.close()
    except sqlite3.OperationalError as exc:
        logger.debug("load_threat_counts: DB not ready (%s); returning []", exc)
        return []
    return rows
