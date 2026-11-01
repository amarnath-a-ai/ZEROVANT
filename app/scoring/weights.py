"""Deterministic scoring weights and multiplier constants."""

SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.5,
}

TRIGGER_RISK_MULTIPLIERS = {
    "pull_request_target": 1.5,
    "workflow_run": 1.3,
    "issues": 1.2,
    "issue_comment": 1.2,
    "pull_request": 1.0,
    "push": 1.0,
    "workflow_dispatch": 1.0,
    "schedule": 0.9,
}

CHAIN_AMPLIFICATION_FACTORS = {
    # 5 Core Chains
    "pwn-request": 1.6,
    "injection-to-exfil": 1.5,
    "supply-chain-takeover": 1.4,
    "deploy-blast-radius": 1.3,
    "runner-persistence": 1.4,
    # 5 Extension Chains
    "artifact-poisoning": 1.5,
    "comment-trigger-takeover": 1.4,
    "credential-persistence": 1.3,
    "cache-poisoning-escalation": 1.4,
    "oidc-abuse": 1.5,
}

# Rule ID to default base severity mapping
RULE_SEVERITIES = {
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
    # Extension Rules (Batch A)
    "persist-credentials": "HIGH",
    "secret-to-unpinned-action": "HIGH",
    "overprovisioned-secrets": "MEDIUM",
    "artifact-leak": "HIGH",
    "secrets-inherit": "MEDIUM",
    # Extension Rules (Batch B)
    "github-env-injection": "HIGH",
    "workflow-run-untrusted-artifact": "HIGH",
    "comment-trigger-no-auth": "HIGH",
    "dispatch-input-injection": "LOW",
    "bot-actor-spoofing": "MEDIUM",
    # Extension Rules (Batch C)
    "unpinned-reusable-workflow": "HIGH",
    "unpinned-docker-image": "MEDIUM",
    "curl-pipe-shell": "HIGH",
    "insecure-commands-enabled": "HIGH",
    "cache-poisoning-risk": "HIGH",
    # Extension Rules (Batch D)
    "oidc-write-untrusted": "HIGH",
    "permissions-overbroad-job": "MEDIUM",
    "continue-on-error-security-step": "MEDIUM",
    "missing-timeout": "LOW",
    "known-vulnerable-action": "CRITICAL",
}

