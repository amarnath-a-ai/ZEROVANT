# CI/CD Pipeline Security Auditor

**Explainable Supply-Chain Risk Remediation & Misconfiguration Detection for GitHub Actions**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

## Overview

Modern software engineering relies heavily on Continuous Integration and Continuous Deployment (CI/CD) pipelines to automate builds, tests, and deployments. GitHub Actions has become one of the most widely adopted CI/CD automation platforms. However, workflows execute with sensitive credentials (`GITHUB_TOKEN`, cloud deploy keys, npm/PyPI publishing tokens) and can interact directly with untrusted code submissions (Pull Requests). 

Misconfigurations in CI/CD workflows expose organizations to severe supply chain attacks, such as **Pwn-Requests**, **arbitrary code execution via script injection**, **credential exfiltration**, **runner persistence**, and **unvetted dependency tampering**.

**CI/CD Pipeline Security Auditor** is a static security analysis tool specifically engineered to:
1. Parse and model GitHub Actions workflows with source-line fidelity.
2. Statically audit workflows across 10 security rules without code execution.
3. Correlate isolated findings into high-risk multi-stage **Attack Chains**.
4. Compute deterministic, explainable risk scores.
5. Provide actionable remediation (What / Why / How + YAML unified diffs).
6. Present findings in a web dashboard with interactive Cytoscape.js attack-path graphs.

---

## Architecture and Data Flow

The auditor follows a strict modular pipeline:

```text
+---------------------------------------------------------------------------------+
|                                 USER INPUT                                      |
|            (Public GitHub Repository | Pasted YAML | Local Directory)           |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                       INGESTION (app.ingest)                                    |
|   GitHub Client (REST API with rate-limiting & backoff) / Local Directory Loader|
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                    PARSER & OBJECT MODEL (app.parser)                           |
|       YAML Safe Loader with Line Mapping -> Workflow, Job, and Step Models     |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                     RULE ENGINE (app.rules: 10 Rules)                           |
|   Detects unpinned actions, excessive permissions, script injection, etc.       |
|   Emits normalized Finding objects with source lines & stable fingerprints      |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                   ATTACK CHAIN CORRELATION (app.correlation)                    |
|   Correlates discrete findings into directed attack graphs & composite chains  |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                      RISK SCORING (app.scoring)                                 |
|   Deterministic multi-factor formula: Severity + Context + Chain Amplification  |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                    EXPLAINABILITY ENGINE (app.explain)                          |
|   Template-driven explanations + YAML Unified Diffs (Optional LLM enrichment)   |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                   PERSISTENCE & API (app.storage, app.api)                      |
|         SQLite Database Storage -> REST API Endpoints -> Web Dashboard          |
+---------------------------------------------------------------------------------+
```

---

## 10 Security Rules

| Rule ID | Rule Name | Description | Default Severity |
| :--- | :--- | :--- | :--- |
| `R001` | `r_unpinned_action` | Action pinned to a mutable tag/branch rather than an immutable 40-character commit SHA | HIGH / MEDIUM |
| `R002` | `r_excessive_permissions` | Omitted `permissions` block (defaults to write-all) or excessive explicit scopes | HIGH |
| `R003` | `r_pr_target_checkout` | `pull_request_target` trigger combined with checking out untrusted PR head commit | CRITICAL |
| `R004` | `r_script_injection` | Inline `${{ ... }}` interpolation of untrusted user context inside shell `run:` commands | CRITICAL |
| `R005` | `r_plaintext_secret` | Hardcoded secrets, static tokens, or private keys detected in plaintext | HIGH |
| `R006` | `r_secret_in_log` | Potential unmasked echo, printing, or logging of sensitive secret values | MEDIUM |
| `R007` | `r_long_lived_credentials` | Use of long-lived static credentials (e.g. AWS access keys) instead of OpenID Connect (OIDC) | MEDIUM |
| `R008` | `r_deploy_environment` | Production or deployment jobs lacking environment protection rules or gates | MEDIUM |
| `R009` | `r_self_hosted_runner` | Untrusted workflows executing on persistent self-hosted runners | HIGH |
| `R010` | `r_third_party_action` | Actions sourced from untrusted third-party publishers without provenance | MEDIUM |

---

## 5 Correlated Attack Chains

1. **Pwn-Request (`pwn-request`)**: Privileged `pull_request_target` event + checking out untrusted PR ref + build script execution -> arbitrary code execution in repository context with write tokens.
2. **Injection to Exfiltration (`injection-to-exfil`)**: Untrusted input interpolated into shell commands (`r_script_injection`) + excessive workflow permissions or repository secrets -> exfiltration of environment credentials.
3. **Supply-Chain Takeover (`supply-chain-takeover`)**: Unpinned 3rd-party action (`r_unpinned_action` / `r_third_party_action`) running with broad write permissions -> malicious dependency tampering or repo hijack.
4. **Deploy Blast Radius (`deploy-blast-radius`)**: Unprotected deployment jobs (`r_deploy_environment`) utilizing static long-lived credentials (`r_long_lived_credentials`) -> unauthorized infrastructure compromise.
5. **Runner Persistence (`runner-persistence`)**: Untrusted pull request trigger running on a non-ephemeral self-hosted runner (`r_self_hosted_runner`) -> host takeover and lateral movement in private network.

---

## Project Structure

```text
cicd-auditor/
├── app/
│   ├── __init__.py           # Flask application factory
│   ├── config.py             # Application settings & environment configuration
│   ├── ingest/               # Ingestion adapters (GitHub API & local filesystem)
│   ├── parser/               # Safe YAML parser with source line mapping & AST model
│   ├── rules/                # Rule engine interface, registry, and 10 rule modules
│   ├── correlation/          # Attack graph builder and multi-stage chain correlation
│   ├── scoring/              # Deterministic risk scoring algorithms
│   ├── explain/              # Remediation guidance, YAML diffs, and template engine
│   ├── storage/              # SQLite database schema, repository, and migrations
│   ├── api/                  # REST API routes and request validation
│   └── web/                  # Web dashboard (templates, CSS, JS, visualizations)
├── tests/
│   ├── fixtures/
│   │   ├── vulnerable/       # Hand-crafted fixtures triggering each rule & chain
│   │   ├── safe/             # Safe counterpart workflows adhering to best practices
│   │   └── real_world/       # Real public GitHub Actions workflows with provenance
│   ├── test_fixtures.py      # Fixture corpus validation & smoke tests
│   └── ...                   # Unit, correlation, scoring, and integration tests
├── benchmark/
│   ├── ground_truth.json     # Hand-curated security benchmark dataset
│   ├── run_benchmark.py      # Precision/recall benchmark execution harness
│   └── results/              # Evaluation benchmark output reports
├── docs/                     # Academic documentation & viva defense guides
├── instance/                 # SQLite database & runtime instance files
├── .env.example              # Environment variables template
├── .gitignore                # Git ignore configuration
├── pyproject.toml            # Linter & tool configuration
├── pytest.ini                # Pytest configuration
├── requirements.txt          # Python dependency specifications
└── README.md                 # Project documentation
```

---

## Quickstart

### Prerequisites
- Python 3.11+
- Git

### Setup
```bash
# 1. Clone repository
git clone <repo-url>
cd cicd-auditor

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run tests & fixture verification
pytest
```

---

## License

This project is licensed under the MIT License.

