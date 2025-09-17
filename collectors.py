# collectors.py
import requests
import csv
import io
from datetime import datetime, timedelta
from config import OTX_API_KEY, RSS_FEEDS, MAX_THREATS, HTTP_TIMEOUT, USER_AGENT

HEADERS_GENERIC = {"User-Agent": USER_AGENT}

def fetch_otx():
    threats = []
    if OTX_API_KEY != "your_otx_key_here":
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10"
        headers = {"X-OTX-API-KEY": OTX_API_KEY, **HEADERS_GENERIC}
        try:
            resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                for pulse in resp.json().get("results", []):
                    threats.append({
                        "title": pulse.get("name", "Unknown Threat"),
                        "summary": pulse.get("description", "")[:200] + "...",
                        "url": pulse.get("references", ["#"])[0],
                        "sector": pulse.get("industries", ["General"])[0],
                        "timestamp": datetime.fromisoformat(pulse.get("created", datetime.now().isoformat())),
                        "source": "OTX"
                    })
        except Exception as e:
            print(f"[!] OTX fetch error: {e}")
    else:
        print("[!] OTX API key missing, skipping...")
    return threats

def fetch_rss():
    import xml.etree.ElementTree as ET
    threats = []
    for feed_url in RSS_FEEDS:
        try:
            resp = requests.get(feed_url, headers=HEADERS_GENERIC, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                root = ET.fromstring(resp.content)
                for entry in root.findall(".//item")[:5]:
                    threats.append({
                        "title": entry.findtext("title", "Unknown"),
                        "summary": (entry.findtext("description") or "")[:200] + "...",
                        "url": entry.findtext("link", "#"),
                        "sector": "General",
                        "timestamp": datetime.now() - timedelta(hours=1),
                        "source": feed_url
                    })
        except Exception as e:
            print(f"[!] RSS fetch error ({feed_url}): {e}")
    return threats

def fetch_urlhaus():
    threats = []
    try:
        resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=HEADERS_GENERIC, timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            f = io.StringIO(resp.text)
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                date_added, url, url_status, threat_type, tags, _, _ = row[:7]
                threats.append({
                    "title": f"URLhaus: {threat_type}",
                    "summary": f"Malicious URL reported to URLhaus. Tags: {tags}",
                    "url": url,
                    "sector": "Unknown",
                    "timestamp": datetime.strptime(date_added, "%Y-%m-%d %H:%M:%S"),
                    "source": "URLhaus"
                })
    except Exception as e:
        print(f"[!] URLhaus fetch error: {e}")
    return threats

def fetch_malwarebazaar():
    threats = []
    try:
        resp = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_recent"}, headers=HEADERS_GENERIC, timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for sample in data.get("data", [])[:10]:
                threats.append({
                    "title": f"MalwareBazaar: {sample.get('file_type')}",
                    "summary": f"Malware sample {sample.get('sha256_hash')} ({sample.get('file_type')})",
                    "url": "#",
                    "sector": "Unknown",
                    "timestamp": datetime.strptime(sample.get("first_seen"), "%Y-%m-%d %H:%M:%S"),
                    "source": "MalwareBazaar"
                })
    except Exception as e:
        print(f"[!] MalwareBazaar fetch error: {e}")
    return threats

def fetch_feodotracker():
    threats = []
    try:
        resp = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv", headers=HEADERS_GENERIC, timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            f = io.StringIO(resp.text)
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                ip, first_seen, _, malware, _ = row[:5]
                threats.append({
                    "title": f"FeodoTracker: {malware}",
                    "summary": f"IP {ip} associated with {malware} C2 server.",
                    "url": "#",
                    "sector": "Unknown",
                    "timestamp": datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S"),
                    "source": "FeodoTracker"
                })
    except Exception as e:
        print(f"[!] FeodoTracker fetch error: {e}")
    return threats

def fetch_all_sources():
    all_threats = []
    all_threats.extend(fetch_otx())
    all_threats.extend(fetch_rss())
    all_threats.extend(fetch_urlhaus())
    all_threats.extend(fetch_malwarebazaar())
    all_threats.extend(fetch_feodotracker())

    if not all_threats:
        print("[!] No real data fetched. Using mock data.")
        now = datetime.now()
        all_threats.append({
            "title": "Mock Threat",
            "summary": "Simulated threat for testing.",
            "url": "#",
            "sector": "General",
            "timestamp": now,
            "source": "MockData"
        })

    return sorted(all_threats, key=lambda x: x["timestamp"], reverse=True)[:MAX_THREATS]
