"""Tests for Database and Repository Layer (Phase 6a)."""

import pytest

from app.correlation.chains import Chain, ChainType
from app.explain.explainer import Explanation
from app.rules.base import Finding, Severity
from app.storage.db import get_db_connection, init_db, transaction
from app.storage.errors import DatabaseIntegrityError, RecordNotFoundError, StorageError
from app.storage.repository import ScanRepository, synthetic_repo_identity


@pytest.fixture
def repo_storage(tmp_path):
    """Provide a fresh ScanRepository backed by a temporary SQLite file."""
    db_file = tmp_path / "test_auditor.db"
    init_db(str(db_file))
    return ScanRepository(str(db_file))


def test_db_initialization_in_memory():
    """Verify SQLite database schema initializes cleanly and foreign keys are active."""
    conn = get_db_connection(":memory:")
    init_db(":memory:")
    pragma = conn.execute("PRAGMA foreign_keys;").fetchone()
    assert pragma[0] == 1
    conn.close()


def test_schema_creates_all_tables_and_indexes(repo_storage):
    """Verify all 6 tables and expected indexes exist in the initialized schema."""
    conn = get_db_connection(repo_storage.db_path)
    tables = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        ).fetchall()
    }
    expected_tables = {"repos", "scans", "workflows", "findings", "chains", "explanations"}
    assert expected_tables.issubset(tables)

    indexes = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%';"
        ).fetchall()
    }
    expected_indexes = {
        "idx_repos_name",
        "idx_scans_repo",
        "idx_scans_scanned_at",
        "idx_findings_scan",
        "idx_findings_fingerprint",
        "idx_findings_rule",
        "idx_chains_scan",
        "idx_explanations_scan",
        "idx_explanations_finding",
    }
    assert expected_indexes.issubset(indexes)
    conn.close()


def test_foreign_key_enforcement(repo_storage):
    """Verify that foreign key constraints prevent orphan records and support cascade delete."""
    conn = get_db_connection(repo_storage.db_path)

    # 1. Inserting a scan with an invalid repo_id must violate foreign key
    with pytest.raises(DatabaseIntegrityError):
        with transaction(conn):
            conn.execute(
                """
                INSERT INTO scans (
                    id, repo_id, repo_score, risk_level, finding_count, chain_count, source_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                ("scan-orphan", "repo-does-not-exist", 10.0, "LOW", 0, 0, "local"),
            )

    # 2. Insert valid repo and scan
    repo_id = repo_storage.get_or_create_repo("test-org/fk-repo")
    scan_id = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-fk-1",
            "repo_score": 35.0,
            "findings": [
                {
                    "id": "find-fk-1",
                    "rule_id": "R001",
                    "severity": "HIGH",
                    "file_path": ".github/workflows/ci.yml",
                    "line_number": 12,
                    "evidence": "actions/checkout@master",
                }
            ],
        },
    )

    # Assert scan and finding exist
    scan_row = conn.execute("SELECT id FROM scans WHERE id = ?;", (scan_id,)).fetchone()
    assert scan_row is not None
    find_row = conn.execute("SELECT id FROM findings WHERE scan_id = ?;", (scan_id,)).fetchone()
    assert find_row is not None

    # 3. Deleting the repo must cascade delete the scan and its findings
    with transaction(conn):
        conn.execute("DELETE FROM repos WHERE id = ?;", (repo_id,))

    assert conn.execute("SELECT id FROM scans WHERE id = ?;", (scan_id,)).fetchone() is None
    assert conn.execute("SELECT id FROM findings WHERE scan_id = ?;", (scan_id,)).fetchone() is None
    conn.close()


def test_save_scan_rollback_on_failure(repo_storage):
    """Verify that if an error occurs mid-save, the entire transaction is rolled back."""
    repo_id = repo_storage.get_or_create_repo("test-org/rollback-repo")

    # Pass malformed finding data that will raise an error during insertion
    class BadFinding:
        def __init__(self):
            self.id = "find-bad"
            self.rule_id = "R001"
            self.severity = "HIGH"

        @property
        def line(self):
            # Simulate an unhandled exception during finding persistence
            raise RuntimeError("Simulated failure mid-transaction!")

    scan_data = {
        "id": "scan-rollback-test",
        "repo_score": 85.0,
        "findings": [BadFinding()],
    }

    with pytest.raises(Exception) as exc_info:
        repo_storage.save_scan(repo_id, scan_data)

    assert "Simulated failure" in str(exc_info.value) or isinstance(exc_info.value, StorageError)

    # Verify that the scan was NOT persisted in the database
    conn = get_db_connection(repo_storage.db_path)
    scan_row = conn.execute("SELECT id FROM scans WHERE id = 'scan-rollback-test';").fetchone()
    assert scan_row is None

    findings = conn.execute("SELECT id FROM findings WHERE scan_id = 'scan-rollback-test';").fetchall()
    assert len(findings) == 0
    conn.close()


def test_save_scan_non_existent_repo_raises(repo_storage):
    """Verify that attempting to save a scan for a non-existent repo raises RecordNotFoundError."""
    with pytest.raises(RecordNotFoundError):
        repo_storage.save_scan("repo-does-not-exist", {"repo_score": 10.0})


def test_round_trip_save_and_get_scan(repo_storage):
    """Verify that a complete scan with findings, explanations, and chains persists and reloads identically."""
    repo_id = repo_storage.get_or_create_repo(
        name="octocat/secure-pipeline",
        url="https://github.com/octocat/secure-pipeline",
    )

    finding_1 = Finding(
        id="find-rt-1",
        rule_id="R001",
        title="Unpinned GitHub Action",
        severity=Severity.HIGH,
        file=".github/workflows/deploy.yml",
        job="build",
        step="checkout",
        line=15,
        evidence="actions/checkout@v2",
        tags=["supply-chain", "pinning"],
        base_score=7.0,
    )
    finding_2 = Finding(
        id="find-rt-2",
        rule_id="R004",
        title="Script Injection via Untrusted Context",
        severity=Severity.CRITICAL,
        file=".github/workflows/deploy.yml",
        job="build",
        step="run-script",
        line=22,
        evidence="run: echo ${{ github.event.issue.title }}",
        tags=["injection", "cwe-78"],
        base_score=9.5,
    )

    explanation_1 = Explanation(
        finding_id="find-rt-1",
        what="The workflow references an unpinned third-party action using a mutable tag.",
        why="An attacker compromising the tag can achieve arbitrary code execution.",
        how="Pin the action to a full 40-character SHA hash.",
        fix_diff="--- a\n+++ b\n- uses: actions/checkout@v2\n+ uses: actions/checkout@<FULL_40_CHAR_COMMIT_SHA>",
        source="template",
    )
    explanation_2 = Explanation(
        finding_id="find-rt-2",
        what="Untrusted input is interpolated directly into an inline shell script.",
        why="External users can inject shell metacharacters and escape execution.",
        how="Pass untrusted context values through intermediate environment variables.",
        fix_diff="--- a\n+++ b\n- run: echo ${{ github.event.issue.title }}\n+ env:\n+   TITLE: ${{ github.event.issue.title }}\n+ run: echo \"$TITLE\"",
        source="llm",
    )

    chain = Chain(
        id="chain-rt-1",
        chain_type=ChainType.SUPPLY_CHAIN_TAKEOVER,
        finding_ids=["find-rt-1", "find-rt-2"],
        job_id="build",
        jobs=["build"],
        nodes=[
            {"id": "node-1", "label": "Unpinned Action"},
            {"id": "node-2", "label": "Script Injection"},
        ],
        edges=[{"source": "node-1", "target": "node-2"}],
        narrative="Attacker compromises checkout action and executes arbitrary script via injection.",
        chain_score=9.2,
    )

    scan_id = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-rt-100",
            "commit_sha": "a1b2c3d4e5f678901234567890abcdef12345678",
            "ref": "refs/heads/main",
            "repo_score": 88.5,
            "risk_level": "CRITICAL",
            "source_type": "github_repo",
            "severity_distribution": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "findings": [finding_1, finding_2],
            "explanations": {
                "find-rt-1": explanation_1,
                "find-rt-2": explanation_2,
            },
            "chains": [chain],
        },
    )

    assert scan_id == "scan-rt-100"

    # Reload scan
    scan = repo_storage.get_scan(scan_id)
    assert scan is not None
    assert scan["id"] == "scan-rt-100"
    assert scan["repo_id"] == repo_id
    assert scan["repo_name"] == "octocat/secure-pipeline"
    assert scan["repo_url"] == "https://github.com/octocat/secure-pipeline"
    assert scan["commit_sha"] == "a1b2c3d4e5f678901234567890abcdef12345678"
    assert scan["ref"] == "refs/heads/main"
    assert scan["repo_score"] == 88.5
    assert scan["risk_level"] == "CRITICAL"
    assert scan["finding_count"] == 2
    assert scan["chain_count"] == 1
    assert scan["source_type"] == "github_repo"
    assert scan["severity_distribution"]["CRITICAL"] == 1
    assert scan["severity_distribution"]["HIGH"] == 1

    # Findings verification
    assert len(scan["findings"]) == 2
    f1 = scan["findings"][0]
    assert f1["id"] == "find-rt-1"
    assert f1["rule_id"] == "R001"
    assert f1["severity"] == "HIGH"
    assert f1["file_path"] == ".github/workflows/deploy.yml"
    assert f1["job_id"] == "build"
    assert f1["step_id"] == "checkout"
    assert f1["line_number"] == 15
    assert f1["evidence"] == "actions/checkout@v2"
    assert f1["base_score"] == 7.0
    assert f1["tags"] == ["supply-chain", "pinning"]
    assert f1["fingerprint"] == finding_1.fingerprint
    assert f1["explanation"]["what"] == explanation_1.what
    assert f1["explanation"]["source"] == "template"

    f2 = scan["findings"][1]
    assert f2["id"] == "find-rt-2"
    assert f2["rule_id"] == "R004"
    assert f2["severity"] == "CRITICAL"
    assert f2["base_score"] == 9.5
    assert f2["fingerprint"] == finding_2.fingerprint
    assert f2["explanation"]["source"] == "llm"

    # Chains verification
    assert len(scan["chains"]) == 1
    c = scan["chains"][0]
    assert c["id"] == "chain-rt-1"
    assert c["chain_type"] == "supply-chain-takeover"
    assert c["finding_ids"] == ["find-rt-1", "find-rt-2"]
    assert c["chain_score"] == 9.2
    assert len(c["nodes"]) == 2
    assert len(c["edges"]) == 1
    assert c["narrative"] == chain.narrative


def test_list_scans_and_repo_filtering(repo_storage):
    """Verify list_scans ordering, limit, offset, and per-repo filtering."""
    repo_a = repo_storage.get_or_create_repo("org/repo-a")
    repo_b = repo_storage.get_or_create_repo("org/repo-b")

    # Insert 3 scans for repo A and 2 scans for repo B
    for i in range(3):
        repo_storage.save_scan(
            repo_a,
            {"id": f"scan-a-{i}", "repo_score": 20.0 + i * 10, "source_type": "local"},
        )
    for j in range(2):
        repo_storage.save_scan(
            repo_b,
            {"id": f"scan-b-{j}", "repo_score": 50.0 + j * 5, "source_type": "local"},
        )

    all_scans = repo_storage.list_scans()
    assert len(all_scans) == 5

    # Filter by repo A
    repo_a_scans = repo_storage.list_scans(repo_id=repo_a)
    assert len(repo_a_scans) == 3
    assert all(s["repo_id"] == repo_a for s in repo_a_scans)

    # Filter by repo B
    repo_b_scans = repo_storage.list_scans(repo_id=repo_b)
    assert len(repo_b_scans) == 2
    assert all(s["repo_id"] == repo_b for s in repo_b_scans)

    # Test pagination (limit and offset)
    limited = repo_storage.list_scans(limit=2)
    assert len(limited) == 2

    offset_scans = repo_storage.list_scans(limit=2, offset=2)
    assert len(offset_scans) == 2
    assert limited[0]["id"] != offset_scans[0]["id"]


def test_sql_injection_resistance(repo_storage):
    """Verify that malicious SQL injection inputs in repository name, evidence, and paths are safely stored."""
    evil_repo_name = "evil-repo'; DROP TABLE repos; --"
    evil_url = "https://example.com/repo' OR '1'='1"
    repo_id = repo_storage.get_or_create_repo(name=evil_repo_name, url=evil_url)

    evil_finding = {
        "id": "find-evil-1",
        "rule_id": "R005'; DROP TABLE findings; --",
        "title": "Secret in code'; DROP TABLE scans; --",
        "severity": "CRITICAL",
        "file_path": "../../etc/passwd'; DELETE FROM repos; --",
        "line_number": 666,
        "evidence": "eval('malicious'); DROP TABLE chains; --",
        "base_score": 10.0,
    }

    scan_id = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-evil-1",
            "repo_score": 99.9,
            "findings": [evil_finding],
        },
    )

    # Verify that repos, scans, findings tables are still intact and rows match
    retrieved_scan = repo_storage.get_scan(scan_id)
    assert retrieved_scan is not None
    assert retrieved_scan["repo_name"] == evil_repo_name
    assert retrieved_scan["repo_url"] == evil_url

    retrieved_finding = retrieved_scan["findings"][0]
    assert retrieved_finding["evidence"] == "eval('malicious'); DROP TABLE chains; --"
    assert retrieved_finding["rule_id"] == "R005'; DROP TABLE findings; --"
    assert retrieved_finding["file_path"] == "../../etc/passwd'; DELETE FROM repos; --"

    # Check table counts directly
    conn = get_db_connection(repo_storage.db_path)
    count = conn.execute("SELECT COUNT(*) FROM repos;").fetchone()[0]
    assert count >= 1
    conn.close()


def test_empty_database_returns_clean_defaults(repo_storage):
    """Verify that querying an empty database returns empty results without exceptions."""
    assert repo_storage.get_scan("non-existent-scan-id") is None
    assert repo_storage.get_repo("non-existent-repo-id") is None
    assert repo_storage.get_repo_by_name("non-existent-name") is None
    assert repo_storage.list_scans() == []
    assert repo_storage.list_scans(repo_id="non-existent") == []


def test_synthetic_repo_identity_deterministic():
    """Verify synthetic repository identity generation for pasted YAML and local directories."""
    yaml_content = "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
    name1, url1 = synthetic_repo_identity("pasted_yaml", yaml_content)
    name2, url2 = synthetic_repo_identity("pasted_yaml", yaml_content)
    assert name1.startswith("pasted-yaml:")
    assert name1 == name2
    assert url1 == "pasted://inline"

    loc_name, loc_url = synthetic_repo_identity("local_directory", "/var/projects/my-app")
    assert loc_name == "local:my-app"
    assert loc_url == "file:///var/projects/my-app"

    gh_name, gh_url = synthetic_repo_identity("github_repo", "owner/repo")
    assert gh_name == "owner/repo"
    assert gh_url is None


def test_duplicate_fingerprints_in_single_scan_allowed(repo_storage):
    """Verify that multiple findings with identical fingerprints (e.g. repeated issue in different jobs) are allowed."""
    repo_id = repo_storage.get_or_create_repo("org/duplicate-fp")

    f1 = {
        "id": "find-fp-1",
        "rule_id": "R001",
        "severity": "HIGH",
        "file_path": ".github/workflows/ci.yml",
        "job_id": "job-a",
        "step_id": "checkout",
        "line_number": 10,
        "evidence": "actions/checkout@v2",
        "fingerprint": "same-fingerprint-123",
    }
    f2 = {
        "id": "find-fp-2",
        "rule_id": "R001",
        "severity": "HIGH",
        "file_path": ".github/workflows/ci.yml",
        "job_id": "job-b",
        "step_id": "checkout",
        "line_number": 20,
        "evidence": "actions/checkout@v2",
        "fingerprint": "same-fingerprint-123",
    }

    scan_id = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-dup-fp",
            "repo_score": 40.0,
            "findings": [f1, f2],
        },
    )

    scan = repo_storage.get_scan(scan_id)
    assert scan is not None
    assert len(scan["findings"]) == 2
    assert scan["findings"][0]["fingerprint"] == "same-fingerprint-123"
    assert scan["findings"][1]["fingerprint"] == "same-fingerprint-123"
    assert scan["findings"][0]["id"] != scan["findings"][1]["id"]


def test_get_history_ordering_and_data(repo_storage):
    """Verify that get_history returns chronological scans with scores and metrics."""
    repo_id = repo_storage.get_or_create_repo("org/history-repo")

    # Insert 3 scans with distinct scores and timestamps
    s1 = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-hist-1",
            "repo_score": 30.0,
            "source_type": "local",
            "severity_distribution": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        },
    )
    s2 = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-hist-2",
            "repo_score": 65.0,
            "source_type": "local",
            "severity_distribution": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        },
    )
    s3 = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-hist-3",
            "repo_score": 15.0,
            "source_type": "local",
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0},
        },
    )

    history = repo_storage.get_history(repo_id)
    assert len(history) == 3
    assert history[0]["scan_id"] == s1
    assert history[0]["repo_score"] == 30.0
    assert history[1]["scan_id"] == s2
    assert history[1]["repo_score"] == 65.0
    assert history[2]["scan_id"] == s3
    assert history[2]["repo_score"] == 15.0
    assert history[1]["severity_distribution"]["CRITICAL"] == 1


def test_compare_scans_new_fixed_persisting(repo_storage):
    """Verify that compare_scans correctly categorizes findings into new, fixed, and persisting."""
    repo_id = repo_storage.get_or_create_repo("org/diff-repo")

    # Scan 1: findings A, B, C
    f_a = {"id": "f-a", "rule_id": "R001", "file": "ci.yml", "line": 10, "fingerprint": "fp-alpha"}
    f_b = {"id": "f-b", "rule_id": "R002", "file": "ci.yml", "line": 20, "fingerprint": "fp-beta"}
    f_c = {"id": "f-c", "rule_id": "R003", "file": "ci.yml", "line": 30, "fingerprint": "fp-gamma"}

    s1_id = repo_storage.save_scan(
        repo_id,
        {"id": "scan-diff-1", "repo_score": 75.0, "findings": [f_a, f_b, f_c]},
    )

    # Scan 2: findings B, C, D (A fixed, D added, B and C persisting)
    f_b2 = {"id": "f-b2", "rule_id": "R002", "file": "ci.yml", "line": 22, "fingerprint": "fp-beta"}
    f_c2 = {"id": "f-c2", "rule_id": "R003", "file": "ci.yml", "line": 35, "fingerprint": "fp-gamma"}
    f_d = {"id": "f-d", "rule_id": "R004", "file": "ci.yml", "line": 40, "fingerprint": "fp-delta"}

    s2_id = repo_storage.save_scan(
        repo_id,
        {"id": "scan-diff-2", "repo_score": 55.0, "findings": [f_b2, f_c2, f_d]},
    )

    comparison = repo_storage.compare_scans(s1_id, s2_id)
    assert comparison["previous_score"] == 75.0
    assert comparison["current_score"] == 55.0
    assert comparison["score_delta"] == -20.0

    assert comparison["fixed_count"] == 1
    assert comparison["fixed_findings"][0]["fingerprint"] == "fp-alpha"

    assert comparison["new_count"] == 1
    assert comparison["new_findings"][0]["fingerprint"] == "fp-delta"

    assert comparison["persisting_count"] == 2
    persisting_fps = {f["fingerprint"] for f in comparison["persisting_findings"]}
    assert persisting_fps == {"fp-beta", "fp-gamma"}


def test_compare_scans_extension_rule_and_chains(repo_storage):
    """Verify comparison identifies fixed extension rules (e.g. persist-credentials) and broken attack chains."""
    repo_id = repo_storage.get_or_create_repo("org/ext-chain-repo")

    # Extension finding persist-credentials and R004 (script injection)
    f_ext = {
        "id": "f-ext-1",
        "rule_id": "persist-credentials",
        "title": "Persistent Credentials in Git Configuration",
        "severity": "HIGH",
        "file": ".github/workflows/deploy.yml",
        "line": 14,
        "evidence": "persist-credentials: true",
        "fingerprint": "fp-ext-persist-credentials",
    }
    f_inj = {
        "id": "f-inj-1",
        "rule_id": "R004",
        "title": "Script Injection",
        "severity": "CRITICAL",
        "file": ".github/workflows/deploy.yml",
        "line": 24,
        "evidence": "echo ${{ github.event.issue.title }}",
        "fingerprint": "fp-inj-r004",
    }
    chain_cred = {
        "id": "chain-cred-1",
        "chain_type": "credential-persistence",
        "finding_ids": ["f-ext-1", "f-inj-1"],
        "narrative": "Persistent credentials allow injected scripts to exfiltrate tokens.",
        "chain_score": 8.5,
    }

    # Baseline scan with extension finding and chain
    s1_id = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-ext-chain-1",
            "repo_score": 82.0,
            "findings": [f_ext, f_inj],
            "chains": [chain_cred],
        },
    )

    # Remediation scan: R011 is resolved, so chain is broken and only R004 persists
    s2_id = repo_storage.save_scan(
        repo_id,
        {
            "id": "scan-ext-chain-2",
            "repo_score": 45.0,
            "findings": [f_inj],
            "chains": [],  # chain broken
        },
    )

    diff = repo_storage.compare_scans(s1_id, s2_id)
    assert diff["score_delta"] == -37.0
    assert diff["fixed_count"] == 1
    assert diff["fixed_findings"][0]["rule_id"] == "persist-credentials"
    assert diff["persisting_count"] == 1
    assert diff["persisting_findings"][0]["rule_id"] == "R004"

    # Chain comparison
    assert diff["fixed_chains_count"] == 1
    assert diff["fixed_chains"][0]["chain_type"] == "credential-persistence"
    assert diff["new_chains_count"] == 0
    assert diff["persisting_chains_count"] == 0


def test_line_shift_regression_fingerprints_stable(repo_storage):
    """Verify that shifting a finding's line number marks it as persisting rather than new + fixed."""
    repo_id = repo_storage.get_or_create_repo("org/line-shift-repo")

    # Baseline scan: finding on line 12
    finding_line_12 = Finding(
        id="find-line-12",
        rule_id="R001",
        title="Unpinned Action",
        severity=Severity.HIGH,
        file=".github/workflows/ci.yml",
        job="build",
        step="checkout",
        line=12,
        evidence="actions/checkout@v2",
    )
    s1_id = repo_storage.save_scan(
        repo_id,
        {"id": "scan-shift-1", "repo_score": 50.0, "findings": [finding_line_12]},
    )

    # Follow-up scan: same finding shifted to line 88 (e.g. 76 lines of comments/steps prepended)
    finding_line_88 = Finding(
        id="find-line-88",
        rule_id="R001",
        title="Unpinned Action",
        severity=Severity.HIGH,
        file=".github/workflows/ci.yml",
        job="build",
        step="checkout",
        line=88,
        evidence="actions/checkout@v2",
    )
    s2_id = repo_storage.save_scan(
        repo_id,
        {"id": "scan-shift-2", "repo_score": 50.0, "findings": [finding_line_88]},
    )

    # Fingerprints must be strictly identical
    assert finding_line_12.fingerprint == finding_line_88.fingerprint

    diff = repo_storage.compare_scans(s1_id, s2_id)
    assert diff["persisting_count"] == 1
    assert diff["new_count"] == 0
    assert diff["fixed_count"] == 0


def test_fingerprint_stability_all_30_rules():
    """Verify fingerprint determinism across all 30 registered rules under arbitrary line shifts."""
    from app.rules import default_registry

    rules = default_registry.list_rules()
    assert len(rules) == 30

    for rule in rules:
        f_early = Finding(
            id=f"f-{rule.id}-early",
            rule_id=rule.id,
            title=rule.name,
            severity=Severity.HIGH,
            file=".github/workflows/main.yml",
            job="test-job",
            step="target-step",
            line=10,
            evidence="simulated-test-evidence",
        )
        f_late = Finding(
            id=f"f-{rule.id}-late",
            rule_id=rule.id,
            title=rule.name,
            severity=Severity.HIGH,
            file=".github/workflows/main.yml",
            job="test-job",
            step="target-step",
            line=999,  # massive line shift
            evidence="simulated-test-evidence",
        )
        assert f_early.fingerprint == f_late.fingerprint, f"Rule {rule.id} fingerprint unstable across line shifts!"


def test_get_dashboard_stats_matches_inserted_data(repo_storage):
    """Verify that get_dashboard_stats computes exact metrics from stored database rows."""
    repo_1 = repo_storage.get_or_create_repo("org/dashboard-repo-1")
    repo_2 = repo_storage.get_or_create_repo("org/dashboard-repo-2")

    # Scan 1: Core rules (CRITICAL + HIGH)
    f1 = {"id": "d-f1", "rule_id": "R004", "severity": "CRITICAL", "file": "ci.yml", "line": 1}
    f2 = {"id": "d-f2", "rule_id": "R001", "severity": "HIGH", "file": "ci.yml", "line": 2}
    repo_storage.save_scan(
        repo_1,
        {"id": "d-s1", "repo_score": 80.0, "findings": [f1, f2], "source_type": "local"},
    )

    # Scan 2: Extension rule (MEDIUM)
    f3 = {"id": "d-f3", "rule_id": "persist-credentials", "severity": "MEDIUM", "file": "ci.yml", "line": 3}
    repo_storage.save_scan(
        repo_2,
        {"id": "d-s2", "repo_score": 40.0, "findings": [f3], "source_type": "github_repo"},
    )

    stats = repo_storage.get_dashboard_stats()
    assert stats["total_repos"] == 2
    assert stats["total_scans"] == 2
    assert stats["total_findings"] == 3
    assert stats["critical_count"] == 1
    assert stats["high_count"] == 1
    assert stats["severity_counts"]["CRITICAL"] == 1
    assert stats["severity_counts"]["HIGH"] == 1
    assert stats["severity_counts"]["MEDIUM"] == 1
    assert stats["average_repo_score"] == 60.0  # (80.0 + 40.0) / 2

    # Derived category and tier breakdown
    assert stats["tier_counts"]["core"] == 2  # R004 and R001
    assert stats["tier_counts"]["extension"] == 1  # persist-credentials
    assert len(stats["category_counts"]) > 0
    assert len(stats["recent_scans"]) == 2


def test_dashboard_stats_empty_database(repo_storage):
    """Verify get_dashboard_stats on an empty database yields clean zero metrics."""
    stats = repo_storage.get_dashboard_stats()
    assert stats["total_repos"] == 0
    assert stats["total_scans"] == 0
    assert stats["total_findings"] == 0
    assert stats["critical_count"] == 0
    assert stats["high_count"] == 0
    assert stats["severity_counts"]["CRITICAL"] == 0
    assert stats["average_repo_score"] == 0.0
    assert stats["recent_scans"] == []


def test_run_scan_pipeline_pasted_and_local(repo_storage):
    """Verify run_scan pipeline end-to-end execution for pasted YAML and local directories."""
    from app.pipeline import run_scan

    # 1. Pasted YAML scan
    pasted_yaml = """
name: Insecure CI
on:
  pull_request_target:
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: echo ${{ github.event.issue.title }}
"""
    scan_id_pasted = run_scan(
        source=pasted_yaml,
        source_type="pasted_yaml",
        repository=repo_storage,
    )
    assert scan_id_pasted.startswith("scan-")
    scan_pasted = repo_storage.get_scan(scan_id_pasted)
    assert scan_pasted is not None
    assert scan_pasted["source_type"] == "pasted_yaml"
    assert scan_pasted["finding_count"] >= 2
    assert scan_pasted["repo_score"] > 50.0

    # 2. Local directory scan
    scan_id_local = run_scan(
        source="tests/fixtures/vulnerable",
        source_type="local_directory",
        repository=repo_storage,
    )
    assert scan_id_local.startswith("scan-")
    scan_local = repo_storage.get_scan(scan_id_local)
    assert scan_local is not None
    assert scan_local["source_type"] == "local_directory"
    assert scan_local["finding_count"] > 0
    assert scan_local["chain_count"] > 0
    assert len(scan_local["explanations"]) > 0


def test_cli_save_option(tmp_path):
    """Verify that CLI scan with --save stores scan directly into target SQLite database."""
    import cli

    db_file = tmp_path / "cli_test.db"
    ret = cli.main(
        [
            "scan",
            "tests/fixtures/vulnerable/vuln_r001_unpinned.yml",
            "--save",
            "--db",
            str(db_file),
        ]
    )
    assert ret == 0

    repo_storage = ScanRepository(str(db_file))
    scans = repo_storage.list_scans()
    assert len(scans) == 1
    assert scans[0]["finding_count"] >= 1
