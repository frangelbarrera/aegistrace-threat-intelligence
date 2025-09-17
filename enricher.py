# enricher.py
import requests
from datetime import datetime
from config import (
    ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, PULSEDIVE_API_KEY,
    ENABLE_ENRICHMENT, HTTP_TIMEOUT, USER_AGENT
)

# Generic HTTP headers for all enrichment requests
HEADERS_GENERIC = {"User-Agent": USER_AGENT}

def enrich_iocs(iocs):
    """
    Enrich Indicators of Compromise (IoCs) using available external sources.

    Fields added per IoC:
      - reputation: str summary (e.g., "AbuseIPDB: 85/100; VT: malicious=3")
      - country: str (for IP addresses)
      - active: bool/str ("unknown" if not available)
      - campaigns: list of tags/campaigns (if Pulsedive responds)
      - details_url: link to a public reference page (AbuseIPDB/VirusTotal/Pulsedive)
      - note: short status message (e.g., missing keys, no internet, success)
    """
    if not ENABLE_ENRICHMENT:
        # Mark all IoCs as unknown but continue processing
        for i in iocs:
            i.update({
                "reputation": "disabled",
                "country": None,
                "active": "unknown",
                "campaigns": [],
                "details_url": None,
                "note": "enrichment disabled"
            })
        return iocs

    out = []
    for ioc in iocs:
        # Base enrichment fields
        base = {
            "reputation": "",
            "country": None,
            "active": "unknown",
            "campaigns": [],
            "details_url": None,
            "note": ""
        }
        ind = ioc["indicator"]
        typ = ioc["type"]
        rep_parts = []

        try:
            if typ == "ip":
                # === AbuseIPDB enrichment (if API key available) ===
                if ABUSEIPDB_API_KEY:
                    try:
                        url = "https://api.abuseipdb.com/api/v2/check"
                        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json", **HEADERS_GENERIC}
                        params = {"ipAddress": ind, "maxAgeInDays": 90}
                        r = requests.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
                        if r.status_code == 200:
                            data = r.json().get("data", {})
                            score = data.get("abuseConfidenceScore", 0)
                            country = data.get("countryCode")
                            base["country"] = country
                            rep_parts.append(f"AbuseIPDB:{score}/100")
                            base["details_url"] = f"https://www.abuseipdb.com/check/{ind}"
                        else:
                            rep_parts.append("AbuseIPDB:unavailable")
                    except Exception:
                        rep_parts.append("AbuseIPDB:error")
                else:
                    rep_parts.append("AbuseIPDB:missing_key")

                # === Pulsedive enrichment for IPs (optional, works without key for some queries) ===
                try:
                    pd_params = {"indicator": ind, "pretty": "1"}
                    if PULSEDIVE_API_KEY:
                        pd_params["key"] = PULSEDIVE_API_KEY
                    pd_resp = requests.get("https://pulsedive.com/api/info.php", params=pd_params, headers=HEADERS_GENERIC, timeout=HTTP_TIMEOUT)
                    if pd_resp.status_code == 200:
                        pdata = pd_resp.json()
                        # Some responses may contain "risk", "category", "tags", "stampAdded"
                        tags = pdata.get("tags") or []
                        if isinstance(tags, str):
                            tags = [tags]
                        if tags:
                            base["campaigns"] = tags
                        state = pdata.get("state") or pdata.get("status")  # may return "active"/"inactive"
                        if state:
                            base["active"] = state
                        if not base["details_url"]:
                            base["details_url"] = f"https://pulsedive.com/indicator/?ioc={ind}"
                        rep_parts.append("Pulsedive:ok")
                    else:
                        rep_parts.append("Pulsedive:unavailable")
                except Exception:
                    rep_parts.append("Pulsedive:error")

            elif typ == "domain":
                # === Pulsedive enrichment for domains ===
                try:
                    pd_params = {"indicator": ind, "pretty": "1"}
                    if PULSEDIVE_API_KEY:
                        pd_params["key"] = PULSEDIVE_API_KEY
                    pd_resp = requests.get("https://pulsedive.com/api/info.php", params=pd_params, headers=HEADERS_GENERIC, timeout=HTTP_TIMEOUT)
                    if pd_resp.status_code == 200:
                        pdata = pd_resp.json()
                        tags = pdata.get("tags") or []
                        if isinstance(tags, str):
                            tags = [tags]
                        if tags:
                            base["campaigns"] = tags
                        state = pdata.get("state") or pdata.get("status")
                        if state:
                            base["active"] = state
                        base["details_url"] = f"https://pulsedive.com/indicator/?ioc={ind}"
                        rep_parts.append("Pulsedive:ok")
                    else:
                        rep_parts.append("Pulsedive:unavailable")
                except Exception:
                    rep_parts.append("Pulsedive:error")

            elif typ == "hash":
                # === VirusTotal enrichment for file hashes (requires API key) ===
                if VIRUSTOTAL_API_KEY:
                    try:
                        vt_url = f"https://www.virustotal.com/api/v3/files/{ind}"
                        headers = {"x-apikey": VIRUSTOTAL_API_KEY, **HEADERS_GENERIC}
                        r = requests.get(vt_url, headers=headers, timeout=HTTP_TIMEOUT)
                        if r.status_code == 200:
                            data = r.json().get("data", {}).get("attributes", {})
                            stats = data.get("last_analysis_stats", {})
                            malicious = stats.get("malicious", 0)
                            suspicious = stats.get("suspicious", 0)
                            rep_parts.append(f"VT:m={malicious},s={suspicious}")
                            base["details_url"] = f"https://www.virustotal.com/gui/file/{ind}"
                            base["active"] = "unknown"
                        elif r.status_code == 404:
                            rep_parts.append("VT:not_found")
                        else:
                            rep_parts.append("VT:unavailable")
                    except Exception:
                        rep_parts.append("VT:error")
                else:
                    rep_parts.append("VT:missing_key")

            # === Finalize reputation string ===
            base["reputation"] = "; ".join([p for p in rep_parts if p])
            if not base["reputation"]:
                base["reputation"] = "no_data"

            # Placeholder for first_seen if provided by a source in the future
            if not ioc.get("first_seen"):
                ioc["first_seen"] = None

            # Merge enrichment data into the IoC record
            enriched = {**ioc, **base}
            out.append(enriched)

        except Exception as e:
            # Never break the pipeline on enrichment errors
            enriched = {**ioc, **{
                "reputation": "error",
                "country": None,
                "active": "unknown",
                "campaigns": [],
                "details_url": None,
                "note": f"error:{type(e).__name__}"
            }}
            out.append(enriched)

    return out
