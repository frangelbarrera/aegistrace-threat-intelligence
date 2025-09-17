# config.py
import os

# Claves API (opcionales, el sistema funciona sin ellas)
OTX_API_KEY = os.getenv("OTX_API_KEY", "your_otx_key_here")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
PULSEDIVE_API_KEY = os.getenv("PULSEDIVE_API_KEY", "")

# Fuentes RSS (públicas). Si fallan, el sistema sigue con mocks.
RSS_FEEDS = [
    "https://krebsonsecurity.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.securityweek.com/feed/"
]

# Límite de amenazas a mostrar en dashboard
MAX_THREATS = 25

# Palabras clave para clasificación automática
THREAT_CATEGORIES = {
    "Ransomware": ["ransomware", "lockbit", "blackcat", "encrypt"],
    "Phishing": ["phishing", "credential", "fake login", "spoof"],
    "Malware": ["malware", "trojan", "worm", "virus", "spyware", "stealc"],
    "APT": ["apt", "advanced persistent threat", "state-sponsored"],
    "Vulnerability": ["cve-", "zero-day", "exploit", "patch"],
    "Data Breach": ["data breach", "leak", "compromised records"]
}

# Enriquecimiento: habilitar/deshabilitar (útil si hay restricciones de red)
ENABLE_ENRICHMENT = True

# Timeouts y configuración HTTP
HTTP_TIMEOUT = 10
USER_AGENT = "ThreatIntelPro/1.0 (+https://example.local)"
