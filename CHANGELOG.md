# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-01

### Phase 1: Ingestion and YAML Parser
#### Added
- Safe filesystem ingestion in `app/ingest/local_loader.py`:
  - Discovers `.github/workflows/*.yml` and `*.yaml` files across local repository structures.
  - Symlink escape prevention via canonical path validation.
  - Strict file-size limit enforcement (default 1 MB) to guard against Denial-of-Service via massive inputs.
- Read-only GitHub REST API client in `app/ingest/github_client.py`:
  - SSRF protection: strictly validates `github.com` HTTPS URLs, rejects non-standard ports, credentials in URLs, and path traversal.
  - Fetches workflow configurations via GitHub Contents API with ref/branch support.
  - Secure credential handling: optional `GITHUB_TOKEN` is never logged or exposed in string representations.
  - Handles rate limits (HTTP 403/429 with reset tracking), 404 resource errors, timeouts, and oversized responses.
  - Fully mockable network interface with zero live network calls during testing.
- Structured AST object model in `app/parser/model.py`:
  - Typed dataclasses: `Workflow`, `Job`, `Step`, `ParsedUses` (`ActionRef`), `ParseError`, `ParseResult`.
  - Line-level source tracking across every workflow element.
- Line-preserving safe YAML parser in `app/parser/loader.py`:
  - Parses workflow content using `yaml.compose()` AST node traversal.
  - Resolves YAML 1.1 `on` -> `True` boolean tag quirk without data loss.
  - Normalizes trigger formats (single string, list, mapping) and captures trigger source lines.
  - Parses workflow- and job-level permissions (string, mapping, empty, or omitted).
  - Normalizes `runs-on`, `needs`, and `environment`.
  - Comprehensive `uses` classifier distinguishing SHA-pinned commits, version tags, branches, local actions, and container images.
  - Non-crashing structured error handling for malformed YAML, empty files, non-mapping roots, and missing jobs.
- Public `load_workflows()` unified entry point supporting files, directories, and raw YAML strings.
- Test suites in `tests/test_parser.py` and `tests/test_ingest.py` (49 passing tests).

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

