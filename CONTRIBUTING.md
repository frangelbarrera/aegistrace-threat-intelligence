# Contributing to AegisTrace

Thanks for your interest in improving AegisTrace! This document explains the development workflow, code style and review expectations.

## Quick Start for Contributors

```bash
# 1. Fork and clone
git clone https://github.com/<your-username>/aegistrace-threat-intelligence.git
cd aegistrace-threat-intelligence

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate    # Linux/macOS
# venv\Scripts\activate     # Windows

# 3. Install dev dependencies + the package itself (editable)
pip install -r requirements-dev.txt
pip install -e .

# 4. Download the spaCy model required by the NLP module
python -m spacy download en_core_web_sm

# 5. Install pre-commit hooks (recommended)
pip install pre-commit
pre-commit install

# 6. Run the test suite to confirm everything works
pytest -v
```

## Development Workflow

1. **Open an issue first** for any non-trivial change (new feature, behaviour change, large refactor). Small bug fixes can go straight to a PR.
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feat/short-description
   ```
3. **Make your changes** following the code style below.
4. **Run all checks locally**:
   ```bash
   ruff check aegistrace tests
   pytest --cov=aegistrace --cov-fail-under=80
   ```
5. **Commit with conventional commit messages**:
   - `feat: add support for CIRCL feed`
   - `fix: handle empty summary in NLP processor`
   - `docs: clarify API key setup in README`
   - `test: cover ARIMA fallback path`
   - `refactor: split enricher into per-type helpers`
6. **Push and open a Pull Request** against `main`. Reference the issue number in the PR description (`Closes #123`).

## Code Style

- **Python version**: target 3.10+. Use modern syntax (`from __future__ import annotations`, `X | None` instead of `Optional[X]`, etc.).
- **Line length**: 100 characters (enforced by ruff).
- **Imports**: sorted by ruff/isort. Use `from __future__ import annotations` at the top of every module.
- **Type hints**: required on every public function. Internal helpers may omit them when obvious.
- **Docstrings**: Google-style for every public function. Include `Args`, `Returns`, and `Raises` sections when applicable.
- **Logging**: use `from aegistrace.logging_config import get_logger` and `logger = get_logger(__name__)`. Never `print()` from library code (the CLI may print user-facing summaries).
- **Error handling**: external HTTP calls must be wrapped so the pipeline never crashes. Log a warning and continue.
- **No API keys in source code**: read all secrets from environment variables via `aegistrace.config`.

## Tests

- Tests live in `tests/` and follow the `test_*.py` naming convention.
- Use `pytest` fixtures defined in `tests/conftest.py`. The `_isolate_runtime` autouse fixture already chdirs each test into a temp dir and overrides `DB_FILE`, so you should never write into the real repository.
- Mock external HTTP calls with the `responses` library (see `tests/test_collectors.py` for examples). Never hit real APIs in tests.
- Coverage threshold is **80%** (`--cov-fail-under=80` in `pyproject.toml`). Try to keep it above 85%.
- When adding a new feature, add tests in the same PR.

## CI

GitHub Actions runs on every push and PR to `main`:

- **Lint**: `ruff check aegistrace tests` must pass.
- **Tests**: `pytest --cov=aegistrace --cov-fail-under=80` on Python 3.10, 3.11, 3.12.

PRs that fail CI will not be merged.

## Areas That Need Help

- **STIX 2.1 output** for SIEM/SOAR integration.
- **MITRE ATT&CK mapping** for extracted IoCs.
- **Docker** deployment (Dockerfile + docker-compose).
- **MISP feed** as an alternative to OTX.
- **Sector inference** for URLhaus / MalwareBazaar records (currently `"Unknown"`).
- **i18n** of the dashboard (English-only today).

## Reporting Security Issues

If you find a security vulnerability in AegisTrace itself (not in the data it collects), please **do not** open a public issue. Email the maintainer privately via the GitHub security advisory feature instead.

## Code of Conduct

Be respectful. Be constructive. Assume good intent. Disagreements about technical decisions are normal and welcome; personal attacks are not.
