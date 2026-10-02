**Maintainer:** Frangel Raúl Crespo Barrera
**Last verified:** 2026-10-02
**Scope:** IoC collection, provenance, freshness, deduplication, schemas, feeds, and report output.

| Field | Current record |
|---|---|
| Status | Tests and CI exist; feed compatibility must be stated per implemented operation. |
| Evidence | `aegistrace/`, `tests/test_collectors.py`, `tests/test_storage.py`, `tests/test_config_and_package.py`, `pyproject.toml`, `.github/workflows/ci.yml`. |
| Standard | STIX/TAXII is not claimed beyond formats and operations implemented by the current code. |
| Verification | `pytest -q`; inspect collector fixtures and schema validation before changing feeds. |
| Owner | Repository owner. |
| Limitations | External feed data is untrusted and may be stale, malformed, duplicated, or withdrawn. |

Record source, collection time, freshness, deduplication key, confidence, and schema for each indicator. API keys come from environment configuration and must not appear in logs or fixtures.
