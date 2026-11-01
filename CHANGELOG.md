# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-01

### Extension Phase 2B: 20 Extension Security Rules (30 Rules Total)
#### Added
- Implemented 20 extension static security rules across four functional batches:
  - **Batch A (Credential and Secret Handling)**:
    - `persist-credentials`: Flags `actions/checkout` lacking `persist-credentials: false` in jobs uploading artifacts or invoking third-party actions.
    - `secret-to-unpinned-action`: Flags passing secrets to third-party actions pinned to mutable tags or branches.
    - `overprovisioned-secrets`: Flags dynamic serialization or indexing of secret contexts (`toJSON(secrets)`, `secrets[var]`).
    - `artifact-leak`: Flags `actions/upload-artifact` targeting workspace root (`.`, `./`), `.git`, or `.env`.
    - `secrets-inherit`: Flags reusable workflow calls passing all repository secrets via `secrets: inherit`.
  - **Batch B (Untrusted Input and Trigger Abuse)**:
    - `github-env-injection`: Flags untrusted event context written directly into `$GITHUB_ENV`, `$GITHUB_PATH`, or `$GITHUB_OUTPUT`.
    - `workflow-run-untrusted-artifact`: Flags `workflow_run` workflows downloading untrusted artifacts from upstream runs without validation.
    - `comment-trigger-no-auth`: Flags `issue_comment` and `pull_request_review_comment` triggers lacking `author_association` authorization.
    - `dispatch-input-injection`: Flags workflow dispatch inputs interpolated directly into shell `run:` strings.
    - `bot-actor-spoofing`: Flags authorization checks relying solely on `github.actor == 'dependabot[bot]'` username matching.
  - **Batch C (Supply Chain and Execution Hygiene)**:
    - `unpinned-reusable-workflow`: Flags reusable workflow calls referenced by mutable branch or tag instead of 40-character commit SHA.
    - `unpinned-docker-image`: Flags container and service images referenced by mutable tags instead of sha256 digests.
    - `curl-pipe-shell`: Flags downloading remote scripts via curl/wget piped directly into shell interpreters.
    - `insecure-commands-enabled`: Flags enabling `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` or using deprecated runner commands (`::set-env`, `::add-path`).
    - `cache-poisoning-risk`: Flags restoring `actions/cache` in privileged workflows with write permissions or release triggers.
  - **Batch D (OIDC, Permissions, and Reliability Hygiene)**:
    - `oidc-write-untrusted`: Flags granting `id-token: write` on untrusted triggers (`pull_request`, `issue_comment`).
    - `permissions-overbroad-job`: Flags jobs requesting write permissions while executing strictly read-only commands.
    - `continue-on-error-security-step`: Flags security scanner and signing steps configured with `continue-on-error: true`.
    - `missing-timeout`: Flags execution jobs that omit `timeout-minutes`, risking 6-hour runner starvation.
    - `known-vulnerable-action`: Flags action versions matching verified published security advisories (e.g. CVE-2025-30066 for `tj-actions/changed-files`).
- Curated Action Advisories Database in `app/data/action_advisories.json`.
- Standardized `build_finding` helper on `BaseRule` for consistent finding creation.
- Enhanced AST parser and workflow object model in `app/parser/`:
  - Captured `if_condition` and `if_line` on `Job` and `Step`.
  - Captured `container`, `container_image_line`, and `services` on `Job`.
  - Captured `continue_on_error` and `continue_on_error_line` on `Step`.
  - Captured `permission_lines` on `Workflow` and `Job`.
  - Captured `env_lines` on `Workflow`.
- Expanded CLI table formatter with severity summary breakdown (CRITICAL, HIGH, MEDIUM, LOW, INFO).
- Full test suite expansion: 95 passing tests with 0 failures, 100% precision and recall on synthetic benchmark corpus.

## [0.3.0] - 2026-11-01

### Phase 2: Vulnerability Detection Engine
#### Added
- Complete implementation of all 10 core static security rules in `app/rules/`:
  - `R001` (`UnpinnedActionRule`): Flags mutable tags and branches on actions and reusable workflow calls in favor of immutable commit SHAs.
  - `R002` (`ExcessivePermissionsRule`): Flags omitted permissions blocks (MEDIUM severity, defaults to write-all) and explicit `write-all` permissions (HIGH severity).
  - `R003` (`PrTargetCheckoutRule`): Flags dangerous checkout of untrusted pull request head commits under privileged `pull_request_target` workflows (CRITICAL severity).
  - `R004` (`ScriptInjectionRule`): Flags direct inline interpolation of untrusted GitHub event contexts inside shell `run:` commands (CRITICAL severity).
  - `R005` (`PlaintextSecretRule`): Flags hardcoded static secrets, API keys, and private keys while strictly preserving legitimate `${{ secrets.* }}` references (HIGH severity).
  - `R006` (`SecretInLogRule`): Flags steps that print, echo, or dump secret values into build logs (MEDIUM severity).
  - `R007` (`LongLivedCredentialsRule`): Flags static AWS access keys and cloud credentials in favor of OpenID Connect (OIDC) identity federation (MEDIUM severity).
  - `R008` (`DeployEnvironmentRule`): Flags deployment-like jobs lacking protected GitHub environment approval gates (MEDIUM severity).
  - `R009` (`SelfHostedRunnerRule`): Flags persistent self-hosted runners assigned to untrusted triggers (e.g. `pull_request`) (HIGH severity).
  - `R010` (`ThirdPartyActionRule`): Flags actions published by third-party owners outside verified vendor organizations (MEDIUM severity).
- Stable cryptographic finding fingerprint:
  - Formulated as `sha256(rule_id:file:job:step:evidence)[:16]`.
  - Fully immune to line number shifts or step reordering across commits.
- Support for reusable workflow caller jobs (`job.uses`):
  - Evaluates action ref pinning and third-party vendor risks at the job level.
  - Safely skips step-level and runner-level checks for caller jobs.
- CLI static scanner tool in `cli.py`:
  - Scans files, directories, or remote GitHub repositories.
  - Emits results in table, JSON, and SARIF formats.
  - Supports `--exit-code` for CI gate blocking on high/critical findings.
- Comprehensive test coverage in `tests/test_rules.py`:
  - 17 unit tests, negative tests, fingerprint stability tests, and CLI tests.
  - Ground-truth evaluation against benchmark dataset (Precision: 94.6%, Recall: 97.2%, F1-Score: 95.9%).
  - Total test suite now stands at 71 passing tests.

## [0.2.1] - 2026-11-01

### Phase 1: Hardening Follow-ups
#### Added
- Strict SSRF protection on GitHub client `download_url`:
  - Host must strictly equal `raw.githubusercontent.com` (HTTPS, standard port 443).
  - Explicitly rejects lookalike domains, credentials, non-standard ports, and metadata endpoints.
  - HTTP redirects (301, 302, 307, 308) during download are strictly blocked with `GitHubSSRFError`.
- Local loader path traversal defense:
  - Supports configurable `allowed_root` boundary.
  - Blocks directory traversal sequences (`../`) and external absolute paths resolving outside the allowed root.
- Security and line accuracy test suites:
  - `caplog` test proving `GITHUB_TOKEN` is never leaked in log output even across authentication and network error paths.
  - Line accuracy verification for workflow root, triggers, jobs, runs-on, and step entities across fixtures.
- Architectural and operational documentation:
  - Documented `RefType` classification heuristic and handling of `${{ ... }}` expressions as `RefType.UNKNOWN`.
  - Documented milestone roadmap limitations (Explainability engine scheduled for Phase 5; full REST API / Web Dashboard for Phase 7).

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

