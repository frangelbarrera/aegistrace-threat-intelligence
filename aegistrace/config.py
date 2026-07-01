"""Configuration for AegisTrace.

All sensitive values are read from environment variables so that no real
API keys are ever committed to the repository. The module also exposes
tunable runtime settings (HTTP timeout, User-Agent, threat categories,
etc.) used across the pipeline.
"""

from __future__ import annotations

import os
from typing import Final

# === Optional API keys (read from environment) ===========================
# The platform runs without any of these; setting them enables richer
# enrichment. Empty string / sentinel values are treated as "missing".
OTX_API_KEY: Final[str] = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_API_KEY: Final[str] = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY: Final[str] = os.getenv("VIRUSTOTAL_API_KEY", "")
PULSEDIVE_API_KEY: Final[str] = os.getenv("PULSEDIVE_API_KEY", "")

# Sentinel used historically by the OTX collector; kept for backward
# compatibility with users that may still set this string in their env.
_OTX_LEGACY_PLACEHOLDER = "your_otx_key_here"


def otx_api_key() -> str:
    """Return the OTX API key, treating the legacy placeholder as empty."""
    if OTX_API_KEY and OTX_API_KEY != _OTX_LEGACY_PLACEHOLDER:
        return OTX_API_KEY
    return ""


# === Public RSS feeds ====================================================
# Public cybersecurity news feeds. If any feed is unreachable the pipeline
# keeps going with the rest.
RSS_FEEDS: Final[list[str]] = [
    "https://krebsonsecurity.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.securityweek.com/feed/",
]

# === Runtime tunables ====================================================
MAX_THREATS: Final[int] = 25
ENABLE_ENRICHMENT: Final[bool] = True
HTTP_TIMEOUT: Final[int] = 10
USER_AGENT: Final[str] = "AegisTrace/0.2.0 (+https://github.com/frangelbarrera/aegistrace-threat-intelligence)"

# === Threat classification keywords =====================================
# Used by nlp_processor.classify_threat for rule-based categorisation.
THREAT_CATEGORIES: Final[dict[str, list[str]]] = {
    "Ransomware": ["ransomware", "lockbit", "blackcat", "encrypt"],
    "Phishing": ["phishing", "credential", "fake login", "spoof"],
    "Malware": ["malware", "trojan", "worm", "virus", "spyware", "stealc"],
    "APT": ["apt", "advanced persistent threat", "state-sponsored"],
    "Vulnerability": ["cve-", "zero-day", "exploit", "patch"],
    "Data Breach": ["data breach", "leak", "compromised records"],
}

# === Storage =============================================================
DB_FILE: Final[str] = os.getenv("AEGISTRACE_DB_FILE", "threatintel.db")
