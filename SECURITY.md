# Security Policy — AegisTrace Threat Intelligence

AegisTrace is a modular Cyber Threat Intelligence (CTI) pipeline that collects
threat data from open sources (RSS, URLhaus, MalwareBazaar, FeodoTracker,
AlienVault OTX), extracts Indicators of Compromise (IoCs) via regex, enriches
them with external intelligence feeds (AbuseIPDB, VirusTotal, Pulsedive),
forecasts 7-day threat trends with an ARIMA(1, 1, 1) model, persists results
to a local SQLite database and CSV file, and renders an interactive Plotly
HTML dashboard. This repository is **actively maintained** (last commit
2026-06-30, release `0.2.0` dated 2026-07-01, CI runs on Python 3.10, 3.11
and 3.12).

## Supported Versions

| Version | Supported          | Notes                                                        |
|---------|--------------------|--------------------------------------------------------------|
| 0.2.x   | ✅ Yes             | Current line on `main`. Security fixes land here first.      |
| < 0.2   | ❌ No              | EOL. Upgrade to the latest `0.2.x` before reporting.         |
| `main`  | ⚠️ Best-effort     | Unreleased commits are not a stable target; pin to a tag.    |

The project has **no git tags or GitHub Releases yet**. Until the first tag
is cut, the only supported ref is the tip of `main`.

## Reporting a Vulnerability

If you believe you have found a security vulnerability **in AegisTrace
itself** (not in the threat data it collects, nor in the upstream APIs it
queries), please report it privately — **do not open a public GitHub issue**.

1. Email the maintainer at **frangelrcbarrera@gmail.com** with the subject
   `[AegisTrace Security] <short summary>`.
2. Preferably also open a private GitHub Security Advisory at
   https://github.com/frangelbarrera/aegistrace-threat-intelligence/security/advisories/new
   (this lets us use the coordinated-disclosure workflow and optionally
   request a CVE).
3. Include in the report:
   - Affected version (output of `aegistrace --version` or git commit SHA).
   - Module and line numbers (e.g. `aegistrace/dashboard_generator.py:103`).
   - A minimal proof of concept (PoC) — fake IoC strings, malicious RSS
     payload, crafted threat summary, etc.
   - Observed impact and any prerequisites (e.g.OTX API key present,
     specific Python version).
4. You will receive an acknowledgement within **72 hours**.

Please **do not** include real API keys, real customer data, or active
malware payloads in the report. Redact or substitute them.

## Response Timeline

| Stage                     | Target SLA          |
|---------------------------|---------------------|
| Acknowledgement of report | 72 hours            |
| Initial triage & severity | 7 days              |
| Critical fix or mitigation| 14 days from triage |
| High-severity fix         | 30 days             |
| Medium / Low fix          | 90 days (best-effort) |
| Coordinated public disclosure | 90 days from acknowledgement, or sooner if a fix is shipped |

Severities follow the CVSS v3.1 base-score bands (Critical ≥ 9.0, High
7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9). The maintainer may extend the
timeline for complex fixes; extensions will be communicated to the reporter
before the original deadline lapses.

## Scope

**In scope:**
- Source code under `aegistrace/` (collectors, NLP processor, IoC extractor,
  enricher, predictor, storage, dashboard generator, CLI, config, logging).
- The CI workflow at `.github/workflows/ci.yml`.
- Generated artefacts whose content is influenced by the pipeline:
  `dashboard.html`, `iocs_enriched.csv`, `threatintel.db`.
- The package metadata in `pyproject.toml`, `requirements.txt`,
  `requirements-dev.txt` and `setup_aegistrace.bat`.

**Out of scope** (please report to the upstream projects directly):
- Vulnerabilities in third-party dependencies (`requests`, `pandas`,
  `spacy`, `statsmodels`, `plotly`, `pytest`, `responses`, `ruff`, `mypy`).
- Vulnerabilities in the external intelligence APIs that AegisTrace queries
  (AlienVault OTX, AbuseIPDB, VirusTotal, Pulsedive, URLhaus, MalwareBazaar,
  FeodoTracker) — including their data quality, false positives or outages.
- Issues arising from a user feeding maliciously crafted RSS feeds that are
  not in the hardcoded `config.RSS_FEEDS` list (the list is fixed and
  trusted; users who patch it accept the risk).
- Findings that require prior compromise of the host (e.g. an attacker who
  already has write access to `threatintel.db`).

## Safe Harbor

AegisTrace is a threat-intelligence tool whose entire purpose is to ingest
untrusted external data (malware hashes, malicious URLs, C2 IPs, attack
descriptions). Researchers testing the pipeline with crafted IoC strings,
malicious RSS payloads, or adversarial NLP inputs are doing exactly what
the tool is designed to process — **this is good-faith security research,
not abuse**.

The maintainer will not pursue civil or criminal action against researchers
who:
- Make a good-faith effort to respect the 90-day coordinated-disclosure
  window.
- Avoid degrading the availability of upstream CTI sources (do not DoS
  URLhaus, AbuseIPDB, VirusTotal, Pulsedive, FeodoTracker, MalwareBazaar,
  OTX or the hardcoded RSS feeds).
- Do not exfiltrate, modify or destroy data that is not their own.
- Do not access systems or accounts that they do not own or have explicit
  permission to test.

## Legal Framework

This policy operates within the following international legal instruments.
Reporters are expected to act consistently with them:

- **Council of Europe Convention on Cybercrime (Budapest Convention, 2001)**,
  in particular Article 2 (illegal access), Article 3 (illegal
  interception), Article 4 (data interference), Article 5 (system
  interference) and Article 6 (misuse of devices).
- **United States Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030**.
- **Directive 2013/40/EU of the European Parliament and of the Council**
  on attacks against information systems (OJ L 218, 14.8.2013, p. 8).
- **United Kingdom Computer Misuse Act 1990** (as amended).

Researchers located in jurisdictions not covered by the above should comply
with their local cybercrime legislation. This Safe Harbor is a good-faith
commitment by the maintainer, not a waiver of any legal right.

## Known Security Considerations

The following are **known and acknowledged** limitations of the current
codebase. They are documented here so reporters can focus on novel
findings, and so operators can make informed deployment decisions:

1. **XSS in the IoC table** — `aegistrace/dashboard_generator.py:103` calls
   `df_ioc[cols].head(20).to_html(index=False, escape=False)`. Because
   `escape=False`, any HTML/JavaScript present in an IoC `indicator`,
   `campaigns`, or `details_url` field is rendered unescaped in
   `dashboard.html`. A malicious RSS `<description>` or OTX pulse that
   contains an IoC-looking string with embedded `<script>` can therefore
   execute JavaScript when the dashboard is opened. Severity: Medium (the
   dashboard is a local HTML file, but is often opened in a browser that
   has access to corporate SSO cookies).

2. **XSS in KPI cards** — lines 190-193 of the same file interpolate
   `top_sector`, `top_entity`, `top_threat_type` directly into the HTML
   template via Python f-string. `top_entity` is derived from spaCy named
   entities extracted from threat summaries, so a crafted summary can
   inject arbitrary HTML into the KPI `<div>`. Severity: Medium.

3. **ReDoS in `DOMAIN_RE`** — `aegistrace/ioc_extractor.py:20` defines
   `\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,24}\b`. The regex is
   bounded per label by `{1,63}` but exhibits superlinear (~n^1.8) runtime
   on adversarial inputs of >100 KB. A 128 KB crafted string takes ~2.9 s.
   For typical threat summaries (<5 KB) the impact is negligible. Severity:
   Low.

4. **Mock-data fallback is persisted** — when every source fails,
   `aegistrace/collectors.py:263-274` injects a single `"Mock Threat"`
   record with `source="MockData"`. This record is then passed to
   `storage.save_threats()` and written to `threatintel.db`. Subsequent
   runs of `predictor.predict_trends()` will treat that mock row as real
   history and produce a 7-day ARIMA forecast (typically 1.0 threats/day,
   "Low" risk) that the dashboard renders without any "this is mock data"
   marker. Operators should purge `threatintel.db` after a no-network run.
   Severity: Low (correctness/trust, not direct RCE).

5. **Unpinned Plotly CDN** — `dashboard.html` (line 161) loads
   `https://cdn.plot.ly/plotly-latest.min.js`. The `latest` tag means
   future dashboard renders will execute whatever JavaScript Plotly
   currently serves. If `cdn.plot.ly` is ever compromised, every generated
   dashboard becomes a code-execution vector. Mitigation: pin to a
   specific version and add a Subresource Integrity (SRI) hash. Severity:
   Medium (supply-chain).

6. **XML parsing of RSS feeds** — `aegistrace/collectors.py:100` parses
   RSS content with `xml.etree.ElementTree.fromstring(resp.content)`.
   Modern CPython (3.10+) does **not** resolve external entities, so
   classic XXE (file disclosure via `file://`) is blocked. However,
   entity-expansion attacks (the "billion laughs" pattern) are still
   expanded by ElementTree and can cause memory exhaustion. Because
   `config.RSS_FEEDS` is a hardcoded list of trusted sources, the
   realistic exposure is limited to a compromise of one of those feeds.
   Severity: Low.

7. **No security scanning in CI** — `.github/workflows/ci.yml` runs only
   `ruff check` and `pytest`. There is no `bandit`, `pip-audit`, `safety`,
   CodeQL or dependency-vulnerability gate. Severity: Process (not a code
   bug). Contributors are welcome to add a `pip-audit` step.

8. **No signed releases** — there are no git tags, no GitHub Releases and
   no SLSA provenance. Users installing from `main` accept a mutable-ref
   supply-chain risk. Severity: Process.

Items 1, 2, 5 and 7 are the highest-priority areas for security
contributions. PRs that switch `escape=False` → `escape=True` (or that
HTML-escape the KPI values), pin the Plotly CDN version with SRI, or add
a `pip-audit` step to CI are explicitly welcomed.

## Contact

- **Security reports:** `frangelrcbarrera@gmail.com` (private, preferred).
- **GitHub Security Advisories:**
  https://github.com/frangelbarrera/aegistrace-threat-intelligence/security/advisories/new
- **General issues and PRs:** use the public GitHub Issues tracker at
  https://github.com/frangelbarrera/aegistrace-threat-intelligence/issues —
  but **do not** post vulnerability details there.

## Recognition

With the reporter's consent, fixed vulnerabilities will be credited in the
`CHANGELOG.md` entry for the release that ships the fix (e.g.
_"Reported by @username via coordinated disclosure"_). Reporters who prefer
to remain anonymous will be respected.

Responsible disclosure is a contribution to the AegisTrace user community
and is treated with the same gratitude as code contributions.
