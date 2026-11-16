# CI/CD Pipeline Security Auditor
## Phase 6 Complete Engineering Report: Database and Historical Tracking

**Project**: CI/CD Pipeline Security Auditor for Misconfiguration Detection and Explainable Supply-Chain Risk Remediation  
**Academic Level**: Final-Year Computer Science and Engineering (CSE) Capstone Project  
**Date**: November 16, 2026  
**Status**: Completed, Verified (199/199 Pytest Suite Passing), Committed (`a6e0551`), and Pushed to `main`  
**Repository**: `https://github.com/amarnath-a-ai/ZEROVANT.git`  

---

### Table of Contents
1. [Executive Summary & Scope](#1-executive-summary--scope)
2. [Database Schema & Relational Integrity](#2-database-schema--relational-integrity)
3. [Connection Management & Transaction Architecture](#3-connection-management--transaction-architecture)
4. [Scan Persistence & Multi-Entity Storage](#4-scan-persistence--multi-entity-storage)
5. [Historical Metric Tracking](#5-historical-metric-tracking)
6. [Differential Scan Comparison Engine](#6-differential-scan-comparison-engine)
7. [Dashboard Analytics Aggregation Engine](#7-dashboard-analytics-aggregation-engine)
8. [End-to-End Pipeline & CLI Integration](#8-end-to-end-pipeline--cli-integration)
9. [Verification Suite & Quality Assurance](#9-verification-suite--quality-assurance)
10. [Viva Defensibility Guide](#10-viva-defensibility-guide)

---

### 1. Executive Summary & Scope

Phase 6 implements the persistent storage and historical analytics backbone for the CI/CD Pipeline Security Auditor. Previously (Phases 0–5), the system operated in an ephemeral analytical capacity: taking workflow definitions, parsing AST structures, running 30 security rules, correlating findings into multi-stage attack chains, calculating deterministic risk scores, and generating actionable remediation patches.

Phase 6 bridges the analysis engine to persistent SQLite storage (`instance/auditor.db` or in-memory `:memory:` for high-speed test harnesses). It provides:
1. **Relational Data Integrity**: Strict foreign key constraints with cascade deletions across repositories, scans, findings, attack chains, and explanations.
2. **Atomic All-or-Nothing Transactions**: Context-managed atomic database writes that guarantee no partial or corrupted scan states are ever committed.
3. **Line-Shift Invariant Differential Comparison**: Using cryptographic fingerprints ($\text{SHA256}$ signatures devoid of raw line numbers), the comparison engine distinguishes truly persisting vulnerabilities from newly introduced or remediated findings, while tracking chain dissolution and creation.
4. **Holistic Dashboard Aggregations**: Dynamic grouping by severity, rule category, and rule tier (`core` vs `extension`) calculated at read-time without denormalized schema bloat.
5. **Unified Pipeline Orchestrator**: The `run_scan()` pipeline wiring Ingestion $\to$ AST Parser $\to$ Rule Engine $\to$ Attack Chains $\to$ Scoring $\to$ Explainability $\to$ Storage.

---

### 2. Database Schema & Relational Integrity

The schema is defined in declarative SQL (`app/storage/schema.sql`). It models the domain entities into 6 relational tables with targeted B-tree indexes:

```
+---------------------------------------------------------------------------------+
|                                     REPOS                                       |
|  id (PK) | name (UNIQUE) | url | created_at                                     |
+---------------------------------------------------------------------------------+
                                       | 1
                                       |
                                       | N (ON DELETE CASCADE)
+---------------------------------------------------------------------------------+
|                                     SCANS                                       |
|  id (PK) | repo_id (FK) | commit_sha | ref | scanned_at | repo_score            |
|  risk_level | finding_count | chain_count | source_type | severity_dist_json    |
+---------------------------------------------------------------------------------+
          |                               |                              |
          | 1                             | 1                            | 1
          | N (CASCADE)                   | N (CASCADE)                  | N (CASCADE)
+-------------------+           +-------------------+          +------------------+
|     WORKFLOWS     |           |     FINDINGS      |          |      CHAINS      |
|  id (PK)          |           |  id (PK)          |          |  id (PK)         |
|  scan_id (FK)     |           |  scan_id (FK)     |          |  scan_id (FK)    |
|  file_path        |           |  rule_id          |          |  chain_type      |
|  name             |           |  title, severity  |          |  finding_ids_json|
|  triggers_json    |           |  file_path, line  |          |  job_id          |
|  line_count       |           |  job_id, step_id  |          |  nodes_json      |
+-------------------+           |  evidence, tags   |          |  edges_json      |
                                |  base_score       |          |  graph_json      |
                                |  fingerprint (IDX)|          |  narrative       |
                                |  explanation_json |          |  chain_score     |
                                +-------------------+          +------------------+
                                          | 1
                                          |
                                          | N (CASCADE)
                                +-------------------+
                                |   EXPLANATIONS    |
                                |  id (PK)          |
                                |  scan_id (FK)     |
                                |  finding_id (FK)  |
                                |  what, why, how   |
                                |  fix_diff, source |
                                +-------------------+
```

#### Key Schema Specifications
- **`repos`**: Tracks target identities. GitHub repositories store their canonical name (e.g., `owner/repo`) and URL. Pasted YAML scans receive a deterministic synthetic identity (`pasted-yaml:<sha256[:12]>`), and local directory scans receive (`local:<dir_name>`).
- **`scans`**: Encapsulates holistic scan execution metadata. Holds the deterministic repo score ($0.0 \dots 100.0$), risk band (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), finding and chain counts, and source classification (`github_repo`, `pasted_yaml`, `local_directory`).
- **`findings`**: Contains detailed vulnerability instances. The `fingerprint` column is indexed via `idx_findings_fingerprint` to accelerate historical diffing.
- **`chains`**: Stores correlated attack graphs, linking multi-stage exploit steps into unified attack paths with serialized Cytoscape-compatible node/edge JSON structures.
- **`explanations`**: Stores actionable remediation advice, distinguishing between deterministic template patches and optional LLM-enriched narratives.

---

### 3. Connection Management & Transaction Architecture

SQLite connection handling and transaction safety are governed by `app/storage/db.py`:

```python
def get_db_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path_str)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn
```

#### Transaction Safety via `@contextmanager transaction(conn)`
- **Foreign Key Enforcement**: SQLite disables foreign keys by default. `PRAGMA foreign_keys = ON;` is explicitly executed on **every** connection before queries run.
- **Atomic Rollback on Error**: The context manager encapsulates the connection lifecycle. If any statement or sub-operation raises an error, `conn.rollback()` triggers automatically.
- **SQL Detail Redaction**: Driver errors are captured and re-raised as typed domain exceptions (`StorageError`, `DatabaseIntegrityError`, `RecordNotFoundError`), guaranteeing that raw internal SQL strings and table internals are never leaked to API clients or CLI users.

---

### 4. Scan Persistence & Multi-Entity Storage

The `ScanRepository.save_scan()` method saves an entire audit run in a single atomic transaction:

```python
with transaction(conn):
    # 1. Validate repository existence
    # 2. Insert scan row
    # 3. Insert all findings (with scan-scoped unique IDs and fingerprints)
    # 4. Insert structured explanations
    # 5. Insert correlated attack chains and graph JSON
    # 6. Insert workflow catalog records
```

#### Scan-Scoped Entity Disambiguation
In real-world repositories, multiple workflow files (or repeated steps within a job) often produce findings with identical local IDs (e.g., `f-r001-0001`). To guarantee global uniqueness in the database while maintaining clean IDs for callers:
- Findings are stored under the compound key: `db_finding_id = f"{scan_id}:{f_id}"`.
- When retrieved via `get_scan()`, the repository transparently strips the prefix, returning original IDs like `f-r001-0001` to downstream API and dashboard layers.
- Multiple instances of the same fingerprint can coexist within the same scan without constraint violations, allowing separate jobs to have their own distinct finding records.

---

### 5. Historical Metric Tracking

The `get_history(repo_id: str, limit: int = 50)` method extracts chronological risk trends over time:
- Scans are sorted strictly by `scanned_at ASC, rowid ASC`.
- Each record exposes the timestamp, commit SHA, git ref, repo risk score, risk level, finding count, chain count, and the complete severity distribution breakdown (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- This serves as the direct data provider for Chart.js trend lines in the upcoming Phase 7 dashboard.

---

### 6. Differential Scan Comparison Engine

The `compare_scans(scan_a_id: str, scan_b_id: str)` engine compares a baseline scan ($A$) against a newer scan ($B$):

#### Mathematical Classification via Fingerprints
Each finding possesses a deterministic fingerprint:
$$\text{Fingerprint} = \text{SHA256}(\text{rule\_id} : \text{file} : \text{job} : \text{step} : \text{evidence})[:16]$$
Because raw line numbers and step indices are excluded, line shifts (such as prepending comments or unrelated steps above) preserve the exact same fingerprint.

For a fingerprint occurring $N_A$ times in scan $A$ and $N_B$ times in scan $B$:
- **Persisting Findings**: $\min(N_A, N_B)$ findings persist across scans.
- **Fixed Findings**: $\max(0, N_A - N_B)$ findings were successfully remediated.
- **New Findings**: $\max(0, N_B - N_A)$ findings were newly introduced.

#### Attack Chain Lifecycle
Chains are compared across scans:
- **`fixed_chains`**: Chains that were active in Scan $A$ but broken in Scan $B$ because one or more prerequisite misconfigurations were resolved.
- **`new_chains`**: Chains formed in Scan $B$ due to new misconfigurations.
- **`persisting_chains`**: Chains that remain active in both scans.
- **`score_delta`**: $\Delta = \text{Score}_B - \text{Score}_A$. A negative delta indicates risk reduction.

---

### 7. Dashboard Analytics Aggregation Engine

The `get_dashboard_stats()` method compiles real-time system metrics directly from stored database rows:
- **Totals**: `total_repos`, `total_scans`, `total_findings`.
- **Severity Distribution**: Total occurrences of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.
- **Read-Time Category & Tier Mapping**: Grouped counts by rule category (`Supply Chain`, `Permissions`, `Code Injection`, etc.) and tier (`core` vs `extension`) are resolved by joining stored `rule_id` values against `default_registry.get_rule(rule_id)` in memory. This eliminates database schema migration requirements when rule taxonomies expand.
- **Mean Risk**: System-wide average repository risk score.
- **Recent Activity**: The 5 most recent scans with associated repository names and timestamps.

---

### 8. End-to-End Pipeline & CLI Integration

The orchestrator in `app/pipeline.py` wires all six phases into a single call:

```python
scan_id = run_scan(
    source="tests/fixtures/vulnerable",
    source_type="local_directory",
    db_path="instance/auditor.db"
)
```

#### Pipeline Flow
1. **Source Ingestion**: Ingests files from GitHub (`GitHubClient`), local directories (`load_workflows`), or raw YAML strings.
2. **AST Parsing**: Generates line-accurate workflow AST models.
3. **Static Rule Evaluation**: Evaluates all 30 core and extension rules.
4. **Attack Chain Correlation**: Identifies multi-step exploit paths.
5. **Deterministic Scoring**: Calculates individual finding scores, chain scores, and the repository score using rank-decay aggregation.
6. **Remediation Explainability**: Generates What/Why/How explanations and unified diff patches.
7. **Relational Persistence**: Saves the complete hierarchy into SQLite.

#### CLI `--save` Flag
Users can execute scans and optionally persist them via the command line:
```bash
python cli.py scan .github/workflows/ci.yml --save --db instance/auditor.db --format table
```

---

### 9. Verification Suite & Quality Assurance

The test suite in `tests/test_storage.py` includes 20 comprehensive automated tests:

| Test Name | Verification Focus | Status |
| :--- | :--- | :---: |
| `test_db_initialization_in_memory` | Schema generation & foreign keys active | PASSED |
| `test_schema_creates_all_tables_and_indexes` | Presence of 6 tables & 8 custom indexes | PASSED |
| `test_foreign_key_enforcement` | Orphan insertion rejected & cascade delete | PASSED |
| `test_save_scan_rollback_on_failure` | Mid-transaction failure leaves zero trace | PASSED |
| `test_save_scan_non_existent_repo_raises` | `RecordNotFoundError` on invalid repo foreign key | PASSED |
| `test_round_trip_save_and_get_scan` | Bit-for-bit reload of findings, chains, diffs | PASSED |
| `test_list_scans_and_repo_filtering` | Scan pagination, ordering, and repo filtering | PASSED |
| `test_sql_injection_resistance` | SQL injection in names, URLs, evidence strings safely stored | PASSED |
| `test_empty_database_returns_clean_defaults`| Clean zero state without exceptions | PASSED |
| `test_synthetic_repo_identity_deterministic`| Pasted YAML and local path hash stability | PASSED |
| `test_duplicate_fingerprints_in_single_scan_allowed` | Non-unique fingerprints permitted within single scan | PASSED |
| `test_get_history_ordering_and_data` | Chronological sort and metric accuracy | PASSED |
| `test_compare_scans_new_fixed_persisting` | Exact count verification of diff sets | PASSED |
| `test_compare_scans_extension_rule_and_chains`| Broken chain and resolved extension rule (`persist-credentials`) | PASSED |
| `test_line_shift_regression_fingerprints_stable` | Shifted lines classified as persisting | PASSED |
| `test_fingerprint_stability_all_30_rules` | Line-shift invariance verified across all 30 rules | PASSED |
| `test_get_dashboard_stats_matches_inserted_data` | Aggregated counts match inserted DB rows exactly | PASSED |
| `test_dashboard_stats_empty_database` | Zero defaults on unpopulated database | PASSED |
| `test_run_scan_pipeline_pasted_and_local` | End-to-end pipeline execution from raw sources | PASSED |
| `test_cli_save_option` | CLI persistence via `--save --db` flags | PASSED |

**Full Suite Status**: **199 passed in 3.98s**. Zero failures. Zero regressions.  
**Linter Status**: `ruff check .` clean with 0 warnings or errors.

---

### 10. Viva Defensibility Guide

#### Q1: Why did you choose SQLite over PostgreSQL or MongoDB for this system?
**Answer**: SQLite was chosen for architectural efficiency, zero external operational overhead, and deterministic local reproducibility. In static analysis tools (like SonarQube CLI, Trivy, or Semgrep), scans often run locally or inside air-gapped CI runners. SQLite provides full ACID compliance, zero-latency in-process querying, and support for in-memory execution (`:memory:`) during unit testing, while maintaining standard SQL parameterization that can be migrated to PostgreSQL via SQLAlchemy if multi-user horizontal scaling is required.

#### Q2: How does the differential scanner handle line-number shifts when code is inserted above a vulnerability?
**Answer**: Many naive SAST tools identify findings by `file:line`, causing a line shift to register as a false "remediation" followed by a false "new finding". Our auditor generates an immutable cryptographic fingerprint:
$$\text{SHA256}(\text{rule\_id} : \text{file} : \text{job} : \text{step} : \text{evidence})[:16]$$
Because raw line numbers are excluded from this hash, line shifts produce identical fingerprints, allowing the comparison engine to correctly classify the finding as `persisting`.

#### Q3: What prevents SQL injection attacks when malicious workflow content is scanned?
**Answer**: Every database interaction in `ScanRepository` utilizes parameter substitution exclusively (`conn.execute(sql, params)` with `?` placeholders). We explicitly tested payloads containing malicious SQL fragments (e.g., `'; DROP TABLE findings; --` in evidence and repo names), verifying that inputs are stored as inert text data without escaping into the SQLite execution engine.

#### Q4: How is atomicity preserved if a scan failure occurs during the insertion of attack chains?
**Answer**: Scan persistence is wrapped in a Python context manager `with transaction(conn):`. SQLite executes inside a transaction block (`BEGIN` / `COMMIT`). If an exception is raised anywhere during the insertion of findings, chains, or explanations, the context manager catches the exception, issues a `ROLLBACK`, and re-raises a wrapped domain error. As proven in `test_save_scan_rollback_on_failure`, zero partial records remain in the database.
