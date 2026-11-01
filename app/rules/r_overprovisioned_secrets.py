"""Rule 13: overprovisioned-secrets: toJSON(secrets) or dynamic secret exposure."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

OVERPROVISIONED_PATTERNS = [
    (re.compile(r"tojson\s*\(\s*secrets\s*\)", re.IGNORECASE), "toJSON(secrets) serializes and exposes all repository secrets"),
    (re.compile(r"tojson\s*\(\s*env\s*\)", re.IGNORECASE), "toJSON(env) serializes environment table containing secrets"),
    (re.compile(r"secrets\s*\[\s*[^\]]+\s*\]", re.IGNORECASE), "Dynamic secrets[...] indexing exposes unpredictable secret values"),
]


class OverprovisionedSecretsRule(BaseRule):
    """Flags bulk or dynamic secret serialization (e.g. toJSON(secrets))."""

    id = "overprovisioned-secrets"
    name = "overprovisioned_secrets"
    description = (
        "Workflow utilizes '${{ toJSON(secrets) }}' or dynamic secret access. Passing all secrets "
        "en masse violates the principle of least privilege, dramatically expands blast radius, "
        "and risks accidental leakage in child processes or logs."
    )
    default_severity = Severity.MEDIUM
    category = "credentials"
    tier = "extension"
    tags = ["credentials", "least-privilege", "information-disclosure"]
    references = [
        "https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []
        raw_lines = workflow.raw_content.splitlines() if workflow.raw_content else []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                step_display = step.name or step.uses or "Step"
                found_match = False
                matched_reason = ""
                matched_snippet = ""

                # Check env
                for k, v in step.env.items():
                    v_str = str(v)
                    for pat, desc in OVERPROVISIONED_PATTERNS:
                        if pat.search(v_str):
                            found_match = True
                            matched_reason = desc
                            matched_snippet = f"{k}: {v_str}"
                            break
                    if found_match:
                        break

                # Check with_params
                if not found_match:
                    for k, v in step.with_params.items():
                        v_str = str(v)
                        for pat, desc in OVERPROVISIONED_PATTERNS:
                            if pat.search(v_str):
                                found_match = True
                                matched_reason = desc
                                matched_snippet = f"{k}: {v_str}"
                                break
                        if found_match:
                            break

                # Check run
                if not found_match and step.run:
                    for pat, desc in OVERPROVISIONED_PATTERNS:
                        if pat.search(step.run):
                            found_match = True
                            matched_reason = desc
                            matched_snippet = step.run[:100]
                            break

                if found_match:
                    # Determine exact line number from raw content if available
                    finding_line = step.line
                    for line_no, raw_line in enumerate(raw_lines, start=1):
                        for pat, _ in OVERPROVISIONED_PATTERNS:
                            if pat.search(raw_line):
                                finding_line = line_no
                                break

                    findings.append(
                        Finding(
                            id=f"f-overprov-sec-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Overprovisioned Bulk Secret Access via toJSON",
                            severity=self.default_severity,
                            file=workflow.file_path,
                            job=job_id,
                            step=step_display,
                            line=finding_line,
                            evidence=(
                                f"Step '{step_display}' uses overprovisioned secret access ({matched_reason}). "
                                f"Found: '{matched_snippet}'. Pass only specific named secrets (${{ secrets.NAME }})."
                            ),
                            tags=list(self.tags),
                            base_score=6.8,
                        )
                    )

        return findings
