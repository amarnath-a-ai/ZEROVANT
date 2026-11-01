"""Rule R006: Detection of direct echoing, printing, or logging of sensitive secret values."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

# Patterns matching commands that emit secrets into runner stdout/stderr logs
SECRET_LOG_PATTERNS = [
    (
        re.compile(r"(?i)\b(?:echo|printf)\s+.*?\$\{\{\s*secrets\.[a-zA-Z0-9_]+\s*\}\}"),
        "Echoing secret directly via expression interpolation",
    ),
    (
        re.compile(r"(?i)^\s*(?:printenv|env)\b(?:\s*\|.*)?$"),
        "Dumping full environment with printenv/env",
    ),
]


class SecretInLogRule(BaseRule):
    """Flags workflow steps that print or echo sensitive secrets directly to logs."""

    id = "R006"
    name = "secret_in_log"
    description = (
        "Step prints or echoes secret values directly into workflow execution logs. "
        "While GitHub Actions masks exact secret strings, variations, substrings, or transformed "
        "secrets may bypass masking and expose credentials in build logs."
    )
    default_severity = Severity.MEDIUM
    category = "Information Disclosure"
    tags = ["secrets", "logging", "cwe-532"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#preventing-accidental-leakage-of-secrets-into-logs"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                if not step.run:
                    continue

                for pattern, desc in SECRET_LOG_PATTERNS:
                    if pattern.search(step.run):
                        step_display = step.name or "Script"
                        finding_line = step.run_line or step.line
                        findings.append(
                            Finding(
                                id=f"f-r006-{len(findings)+1:04d}",
                                rule_id=self.id,
                                title="Potential Secret Leakage in Workflow Logs",
                                severity=Severity.MEDIUM,
                                file=workflow.file_path,
                                job=job_id,
                                step=step_display,
                                line=finding_line,
                                evidence=(
                                    f"Step '{step_display}' executes command that may log secret values: {desc}. "
                                    "Refrain from echoing secrets or printing entire environment tables to build logs."
                                ),
                                tags=list(self.tags),
                                base_score=6.5,
                            )
                        )
                        break

        return findings
