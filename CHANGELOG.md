# Changelog

All notable changes to AegisTrace are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-01

### Added
- Packaging: new `aegistrace/` package, `pyproject.toml` (PEP 621), `pip install -e .` support, `aegistrace` console script.
- CLI: new `aegistrace/cli.py` with argparse (`--sources`, `--no-enrich`, `--no-forecast`, `--output`, `--csv`, `--verbose`). Exit codes 0/1/2.
- Backward-compat: `python main.py` still works as a thin shim to the CLI.
- Logging: shared `aegistrace.logging_config.get_logger()` with `AEGISTRACE_LOG_LEVEL` and `AEGISTRACE_LOG_FILE` env vars. All `print()` calls in library code replaced with structured logging.
- Tests: full `tests/` suite with 91% coverage (pytest + pytest-cov + responses). Coverage gate enforced at 80% in `pyproject.toml`.
- CI: `.github/workflows/ci.yml` runs ruff + pytest on Python 3.10/3.11/3.12.
- Pre-commit: `.pre-commit-config.yaml` with ruff (lint + format) and sanity hooks.
- `.gitignore` for Python, DBs, CSVs, dashboards, env files, editor caches.
- `.env.example` documenting all environment variables.
- `CONTRIBUTING.md` with development workflow, code style and areas that need help.
- `CHANGELOG.md` (this file).
- Type hints on every public function across all modules.
- Google-style docstrings on every public function.
- `USER_AGENT` updated to `AegisTrace/0.2.0` with the GitHub repo URL.
- Storage: `load_threat_counts` is now resilient to a missing `threats` table (returns `[]` instead of crashing).
- Dashboard: restyled with KPI cards, responsive grid and a cleaner table layout.

### Fixed
- **URLhaus parser**: CSV column mapping was wrong. The current URLhaus schema is `id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter`; the parser was reading `id` as `date_added`. Now correctly parses all 9 columns and skips both the `#` comment lines and the in-band header row.
- **FeodoTracker parser**: same class of bug. The current Feodo schema is `first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware`; the parser was reading `first_seen` as `ip` and `dst_ip` as `first_seen`. Now correctly maps all 6 columns and skips the in-band header.
- **spaCy 3.8 compatibility**: `doc.sents` is a generator, not subscriptable. Replaced `doc.sents[:2]` with `list(doc.sents)[:2]`.
- **ARIMA warnings**: the predictor now calls `series.asfreq("D")` so statsmodels stops emitting `ValueWarning: A date index has been provided, but it has no associated frequency information`. Forecast dates are also generated with `freq="D"` to silence the `FutureWarning: No supported index is available`.
- **Storage path resolution**: `DB_FILE` is now read lazily from `config` (via `_resolve_db`) so tests can override it with `monkeypatch` without re-importing the module.
- **NLP graceful degradation**: when the spaCy model is missing, `process_nlp` no longer calls `exit(1)`; it falls back to keyword classification and the original summary, so the pipeline keeps running.
- **Predictor risk bins**: `pd.cut` bins now start at `-inf` instead of `0` so negative ARIMA residuals (rare but possible) are classified as `Low` instead of `NaN`.

### Changed
- `config.py` no longer hardcodes the `your_otx_key_here` placeholder. Empty env var now means "no key" consistently across all sources. `OTX_API_KEY` is read through `config.otx_api_key()` which still treats the legacy placeholder as empty for backward compatibility.
- `nlp_processor` no longer crashes on import when spaCy is missing; the model is loaded lazily on first call to `process_nlp`.
- `predictor.predict_trends(threats, days_ahead=7)` keeps the same signature but `threats` is now ignored (it was never used). The historical series is always read from the SQLite database via `storage.load_threat_counts`.
- `requirements.txt` now pins versions with `>=` lower bounds. `requirements-dev.txt` adds pytest, pytest-cov, responses, ruff, mypy, types-requests.
- `dashboard_generator.generate_dashboard` returns the output path (previously returned `None`).
- `enricher` refactored into per-type helpers (`_enrich_ip`, `_enrich_domain`, `_enrich_hash`) for readability and testability. Public `enrich_iocs` signature is unchanged.
- README rewritten: removed the unsupported "70%+ workload reduction" claim, added badges, a Mermaid architecture diagram, a Quick Start section, a CLI reference and a library usage example.

### Removed
- `# threat_aggregator.py` (leftover hackathon MVP, superseded by the modular package).
- Hardcoded `your_otx_key_here` string in `config.py` (replaced by env-var lookup).
- Direct `print()` calls in library modules (replaced by structured logging).

## [0.1.0] - 2026-01-20

Initial public release: modular CTI pipeline with collectors, NLP, IoC extraction, enrichment, ARIMA forecasting, SQLite storage and Plotly dashboard.
