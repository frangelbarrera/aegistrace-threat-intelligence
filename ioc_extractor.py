# ioc_extractor.py
import re
from urllib.parse import urlparse

# === Regular expressions for IoC detection ===
# These are practical and robust patterns (not exhaustive).
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,24}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# === Normalization helpers ===
def _norm_domain(d: str) -> str:
    """Normalize domain by stripping punctuation and converting to lowercase."""
    return d.strip().strip(".,;:\"'()[]{}").lower()

def _norm_ip(ip: str) -> str:
    """Normalize IP address by stripping punctuation."""
    return ip.strip().strip(".,;:\"'()[]{}")

def _norm_hash(h: str) -> str:
    """Normalize hash by stripping punctuation and converting to lowercase."""
    return h.strip().lower()

def _extract_from_text(text: str):
    """
    Extract IoCs from a given text string.
    Returns a dict with sets for 'ip', 'domain', and 'hash'.
    """
    iocs = {
        "ip": set(),
        "domain": set(),
        "hash": set()
    }
    if not text:
        return iocs

    # Extract IPv4 addresses
    for m in IPV4_RE.findall(text):
        iocs["ip"].add(_norm_ip(m))

    # Extract domains (skip if it matches an IP)
    for m in DOMAIN_RE.findall(text):
        if IPV4_RE.match(m):
            continue
        iocs["domain"].add(_norm_domain(m))

    # Extract hashes (MD5, SHA1, SHA256)
    for m in MD5_RE.findall(text):
        iocs["hash"].add(_norm_hash(m))
    for m in SHA1_RE.findall(text):
        iocs["hash"].add(_norm_hash(m))
    for m in SHA256_RE.findall(text):
        iocs["hash"].add(_norm_hash(m))

    return iocs

def extract_iocs(threats):
    """
    Extract IoCs from the title, summary, and URL of each threat record.

    Args:
        threats (list of dict): Threat records containing at least 'title', 'summary'/'summary_nlp', and 'url'.

    Returns:
        list of dict: Each dict contains:
            - indicator: the IoC value (IP, domain, or hash)
            - type: 'ip', 'domain', or 'hash'
            - sources: list of URLs where the IoC was found
            - titles: list of threat titles where the IoC was mentioned
            - first_seen: placeholder for enrichment (None by default)
    """
    # Map to aggregate IoCs: key = (indicator, type)
    ioc_map = {}

    for t in threats:
        title = t.get("title", "")
        summary = t.get("summary", "") or t.get("summary_nlp", "")
        url = t.get("url", "")
        text_blob = " ".join([title, summary, url])

        found = _extract_from_text(text_blob)

        # If the URL is HTTP(S), try to extract the domain from it
        if url and url.startswith("http"):
            try:
                parsed = urlparse(url)
                host = parsed.hostname
                if host and DOMAIN_RE.match(host):
                    found["domain"].add(_norm_domain(host))
            except Exception:
                pass

        # Aggregate IPs
        for ip in found["ip"]:
            key = (ip, "ip")
            ioc = ioc_map.get(key, {"indicator": ip, "type": "ip", "sources": set(), "titles": set()})
            if url:
                ioc["sources"].add(url)
            if title:
                ioc["titles"].add(title)
            ioc_map[key] = ioc

        # Aggregate domains
        for dom in found["domain"]:
            key = (dom, "domain")
            ioc = ioc_map.get(key, {"indicator": dom, "type": "domain", "sources": set(), "titles": set()})
            if url:
                ioc["sources"].add(url)
            if title:
                ioc["titles"].add(title)
            ioc_map[key] = ioc

        # Aggregate hashes
        for h in found["hash"]:
            key = (h, "hash")
            ioc = ioc_map.get(key, {"indicator": h, "type": "hash", "sources": set(), "titles": set()})
            if url:
                ioc["sources"].add(url)
            if title:
                ioc["titles"].add(title)
            ioc_map[key] = ioc

    # Convert sets to sorted lists for output
    iocs = []
    for (_ind, _type), data in ioc_map.items():
        iocs.append({
            "indicator": data["indicator"],
            "type": data["type"],
            "sources": sorted(list(data["sources"])),
            "titles": sorted(list(data["titles"])),
            "first_seen": None  # Reserved for enrichment if available
        })

    return iocs

