-- CI/CD Pipeline Security Auditor Database Schema (Phase 6)
-- Relational schema for repositories, scans, findings, attack chains, and explanations.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS repos (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL,
    commit_sha TEXT,
    ref TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    repo_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    chain_count INTEGER NOT NULL,
    source_type TEXT NOT NULL,         -- 'github_repo', 'pasted_yaml', 'local_directory'
    severity_dist_json TEXT,            -- JSON object e.g. {"CRITICAL": 0, "HIGH": 1, ...}
    FOREIGN KEY(repo_id) REFERENCES repos(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS workflows (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    name TEXT,
    triggers_json TEXT,
    line_count INTEGER,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    file_path TEXT NOT NULL,
    job_id TEXT,
    step_id TEXT,
    line_number INTEGER NOT NULL,
    evidence TEXT,
    tags_json TEXT,
    base_score REAL NOT NULL,
    fingerprint TEXT NOT NULL,
    explanation_json TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chains (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    chain_type TEXT NOT NULL,
    finding_ids_json TEXT NOT NULL,
    job_id TEXT,
    nodes_json TEXT,
    edges_json TEXT,
    graph_json TEXT,
    narrative TEXT NOT NULL,
    chain_score REAL NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS explanations (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    what TEXT NOT NULL,
    why TEXT NOT NULL,
    how TEXT NOT NULL,
    fix_diff TEXT NOT NULL,
    source TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_repos_name ON repos(name);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_chains_scan ON chains(scan_id);
CREATE INDEX IF NOT EXISTS idx_explanations_scan ON explanations(scan_id);
CREATE INDEX IF NOT EXISTS idx_explanations_finding ON explanations(finding_id);
