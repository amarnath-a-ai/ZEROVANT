-- CI/CD Pipeline Security Auditor Database Schema

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,         -- 'github_repo', 'pasted_yaml', 'local_directory'
    target_name TEXT NOT NULL,         -- e.g. 'owner/repo' or file name
    commit_sha TEXT,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    total_findings INTEGER NOT NULL,
    total_chains INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workflows (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    name TEXT,
    triggers_json TEXT,
    raw_content TEXT,
    line_count INTEGER,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    workflow_id TEXT NOT NULL,
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
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY(workflow_id) REFERENCES workflows(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chains (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    chain_type TEXT NOT NULL,
    finding_ids_json TEXT NOT NULL,
    nodes_json TEXT NOT NULL,
    edges_json TEXT NOT NULL,
    narrative TEXT NOT NULL,
    chain_score REAL NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS explanations (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    what TEXT NOT NULL,
    why TEXT NOT NULL,
    how TEXT NOT NULL,
    fix_diff TEXT NOT NULL,
    source TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_name);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_chains_scan ON chains(scan_id);

