# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-30

### Phase 0: Foundation and Test Corpus
#### Added
- Full modular project directory layout according to architecture specification.
- Python virtual environment configuration and pinned `requirements.txt`.
- Code quality configuration: `pytest.ini` and `pyproject.toml` (Ruff linter).
- Clean importable stub modules with type annotations and stable contracts for `app/`, `tests/`, `benchmark/`, and `docs/`.
- Hand-crafted test fixture corpus (`tests/fixtures/vulnerable/`, `tests/fixtures/safe/`) covering all 10 security rules, safe counterparts, 5 attack-chain combinations, and edge cases.
- Real-world test fixture corpus (`tests/fixtures/real_world/`) with verified public GitHub Actions workflows, license provenance, and `SOURCES.md`.
- Hand-reasoned benchmark ground truth dataset (`benchmark/ground_truth.json`).
- Fixture corpus validation and smoke test suite (`tests/test_fixtures.py`).
- Architecture, rules, attack chains, scoring, testing, and limitations documentation in `docs/`.

