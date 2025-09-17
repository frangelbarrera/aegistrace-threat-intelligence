# 🛡️ AegisTrace

**AegisTrace** is an advanced **Cyber Threat Intelligence (CTI)** platform designed to collect, process, enrich, and visualize threat data from multiple open sources.  
It extracts **Indicators of Compromise (IoCs)** such as IP addresses, domains, and file hashes, enriches them with external intelligence feeds, and presents actionable insights through an interactive dashboard.

---

## 🚀 Key Features

- **Multi-Source Threat Collection**
  - Public RSS feeds from leading cybersecurity news outlets.
  - URLhaus (malicious URLs).
  - MalwareBazaar (malware file hashes).
  - FeodoTracker (active C2 IP addresses).
  - Optional OTX integration (AlienVault).

- **Natural Language Processing (NLP)**
  - Entity extraction (organizations, countries, groups, etc.).
  - Automatic threat classification based on keywords.
  - Summarization of threat descriptions.

- **IoC Extraction & Enrichment**
  - Regex-based detection of IPs, domains, and hashes.
  - Enrichment via:
    - **AbuseIPDB** (IP reputation, geolocation).
    - **VirusTotal** (file hash analysis).
    - **Pulsedive** (threat intelligence tags, activity status).
  - Works with or without API keys (graceful fallback).

- **Data Persistence & Forecasting**
  - SQLite database for historical storage of threats and IoCs.
  - ARIMA-based 7-day threat trend forecasting using real historical data when available.

- **Interactive Dashboard**
  - KPIs: total threats, top sector, top entity, top threat type.
  - Charts: threats by sector, threats by type, 7-day forecast.
  - Tables: recent threats, enriched IoCs.
  - Export enriched IoCs to CSV for external analysis.

---

## 📂 Project Structure

```
AegisTrace/
│
├── collectors.py          # Data collection from multiple sources
├── config.py              # Configuration and API keys
├── dashboard_generator.py # Dashboard creation with Plotly
├── enricher.py            # IoC enrichment logic
├── ioc_extractor.py       # IoC extraction from text
├── main.py                # Main execution pipeline
├── nlp_processor.py       # NLP entity extraction and classification
├── predictor.py           # Threat trend forecasting
├── storage.py             # SQLite database operations
├── requirements.txt       # Python dependencies
└── setup_aegistrace.bat   # One-click setup and run script (Windows)
```

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/frangelbarrera/aegistrace-threat-intelligence.git
cd AegisTrace
```

### 2. (Windows) One-click setup
Run:
```bash
setup_aegistrace.bat
```
This will:
- Create and activate a virtual environment.
- Install dependencies.
- Download the spaCy English model.
- Run AegisTrace and open the dashboard.

### 3. (Manual setup)
```bash
python -m venv venv
venv\Scripts\activate  # On Windows
pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python main.py
```

---

## 🔑 Optional API Keys

To enable full IoC enrichment, set the following environment variables before running:

```bash
set OTX_API_KEY=your_otx_key
set ABUSEIPDB_API_KEY=your_abuseipdb_key
set VIRUSTOTAL_API_KEY=your_virustotal_key
set PULSEDIVE_API_KEY=your_pulsedive_key
```

Without keys, AegisTrace will still run but with limited enrichment data.

---

## 📊 Output

- **dashboard.html** → Interactive dashboard with KPIs, charts, and tables.
- **iocs_enriched.csv** → Export of enriched IoCs.
- **threatintel.db** → SQLite database storing historical threats and IoCs.

---

## 🛠️ Technology Stack

- **Python 3.9+**
- **spaCy** – NLP entity extraction and text processing.
- **Plotly** – Interactive data visualization.
- **pandas** – Data manipulation and analysis.
- **statsmodels** – ARIMA forecasting.
- **SQLite** – Lightweight database for persistence.
- **requests** – HTTP requests to external APIs.

---

## 📌 Roadmap

- [ ] Add MITRE ATT&CK mapping for detected threats.
- [ ] Integrate additional CTI feeds (CIRCL, MISP).
- [ ] Implement sector mapping for non-RSS feeds.
- [ ] Add Docker support for easy deployment.
- [ ] Build API endpoints for programmatic access.

---


## 🤝 Contributing

Contributions are welcome!  
Please fork the repository, create a feature branch, and submit a pull request.

---
