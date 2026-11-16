"""Deterministic scoring weights and multiplier constants.

All values are fixed by the Phase-4 specification and must NOT be changed
without updating docs/scoring.md and the corresponding test assertions.
"""

# ---------------------------------------------------------------------------
# Severity weights  (sᵢ ∈ {0.5, 2, 4, 7, 9})
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 2.0,
    "INFO": 0.5,
}

# ---------------------------------------------------------------------------
# Trigger exploitability multipliers
# Unlisted triggers → DEFAULT_TRIGGER_MULTIPLIER (1.0)
# Multi-trigger workflows: take the maximum multiplier present.
# ---------------------------------------------------------------------------
TRIGGER_MULTIPLIERS: dict[str, float] = {
    # High-risk attacker-influenced triggers → 1.3
    "pull_request_target": 1.3,
    "issue_comment": 1.3,
    "workflow_run": 1.3,
    "issues": 1.3,
    "pull_request_review_comment": 1.3,
    "discussion": 1.3,
    "discussion_comment": 1.3,
    # Neutral triggers → 1.0
    "push": 1.0,
    "pull_request": 1.0,
    "schedule": 1.0,
    "release": 1.0,
    "create": 1.0,
    "delete": 1.0,
    "fork": 1.0,
    "gollum": 1.0,
    "label": 1.0,
    "milestone": 1.0,
    "page_build": 1.0,
    "project": 1.0,
    "project_card": 1.0,
    "project_column": 1.0,
    "public": 1.0,
    "pull_request_review": 1.0,
    "registry_package": 1.0,
    "repository_dispatch": 1.0,
    "status": 1.0,
    "watch": 1.0,
    # Low-risk gated triggers → 0.8
    "workflow_dispatch": 0.8,
    "workflow_call": 0.8,
}

DEFAULT_TRIGGER_MULTIPLIER: float = 1.0

# ---------------------------------------------------------------------------
# Chain amplification multipliers (based on number of member findings)
# ---------------------------------------------------------------------------
CHAIN_MULTIPLIER_2: float = 1.3   # exactly 2 member findings
CHAIN_MULTIPLIER_3PLUS: float = 1.5  # 3 or more member findings

# ---------------------------------------------------------------------------
# Repository decay factor  k ∈ (0, 1]
# repo_score = 100 × (1 − ∏ᵢ (1 − sᵢ/10 × k))
# ---------------------------------------------------------------------------
REPO_DECAY_K: float = 0.9

# ---------------------------------------------------------------------------
# Rule-to-default-severity mapping (reference — authoritative source is each
# rule class; this dict is kept for documentation and cross-checks).
# ---------------------------------------------------------------------------
RULE_SEVERITIES: dict[str, str] = {
    # Core 10 Rules
    "R001": "HIGH",
    "R002": "HIGH",
    "R003": "CRITICAL",
    "R004": "CRITICAL",
    "R005": "HIGH",
    "R006": "MEDIUM",
    "R007": "MEDIUM",
    "R008": "MEDIUM",
    "R009": "HIGH",
    "R010": "MEDIUM",
    # Extension Rules — Batch A
    "persist-credentials": "HIGH",
    "secret-to-unpinned-action": "HIGH",
    "overprovisioned-secrets": "MEDIUM",
    "artifact-leak": "HIGH",
    "secrets-inherit": "MEDIUM",
    # Extension Rules — Batch B
    "github-env-injection": "HIGH",
    "workflow-run-untrusted-artifact": "HIGH",
    "comment-trigger-no-auth": "HIGH",
    "dispatch-input-injection": "LOW",
    "bot-actor-spoofing": "MEDIUM",
    # Extension Rules — Batch C
    "unpinned-reusable-workflow": "HIGH",
    "unpinned-docker-image": "MEDIUM",
    "curl-pipe-shell": "HIGH",
    "insecure-commands-enabled": "HIGH",
    "cache-poisoning-risk": "HIGH",
    # Extension Rules — Batch D
    "oidc-write-untrusted": "HIGH",
    "permissions-overbroad-job": "MEDIUM",
    "continue-on-error-security-step": "MEDIUM",
    "missing-timeout": "LOW",
    "known-vulnerable-action": "CRITICAL",
}
