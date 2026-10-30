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
    "pwn-request": 1.6,
    "injection-to-exfil": 1.5,
    "supply-chain-takeover": 1.4,
    "deploy-blast-radius": 1.3,
    "runner-persistence": 1.4,
}

