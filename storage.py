# storage.py
import sqlite3
from datetime import datetime

DB_FILE = "threatintel.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        summary TEXT,
        sector TEXT,
        threat_type TEXT,
        source TEXT,
        timestamp TEXT
    )
    """)
    cur.execute("""
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
    """)
    conn.commit()
    conn.close()

def save_threats(threats):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    for t in threats:
        cur.execute("""
        INSERT INTO threats (title, summary, sector, threat_type, source, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            t.get("title"),
            t.get("summary_nlp") or t.get("summary"),
            t.get("sector"),
            t.get("threat_type"),
            t.get("source"),
            datetime.now().isoformat()
        ))
    conn.commit()
    conn.close()

def save_iocs(iocs):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    for i in iocs:
        cur.execute("""
        INSERT INTO iocs (indicator, type, reputation, country, active, campaigns, details_url, first_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            i.get("indicator"),
            i.get("type"),
            i.get("reputation"),
            i.get("country"),
            i.get("active"),
            ", ".join(i.get("campaigns", [])) if isinstance(i.get("campaigns"), list) else i.get("campaigns"),
            i.get("details_url"),
            i.get("first_seen")
        ))
    conn.commit()
    conn.close()

def load_threat_counts(days=30):
    """Devuelve conteo diario de amenazas para los últimos N días"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    SELECT date(timestamp), COUNT(*) FROM threats
    WHERE date(timestamp) >= date('now', ?)
    GROUP BY date(timestamp)
    ORDER BY date(timestamp)
    """, (f"-{days} day",))
    rows = cur.fetchall()
    conn.close()
    return rows
