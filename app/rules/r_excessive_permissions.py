"""Rule R002: Detection of missing permissions block or excessive permissions (write-all / broad write)."""

from typing import Any

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

# Scopes that grant write/mutate permissions to sensitive repository assets
SENSITIVE_WRITE_SCOPES = {
    "contents",
    "id-token",
    "packages",
    "deployments",
    "security-events",
    "actions",
}


class ExcessivePermissionsRule(BaseRule):
    """Flags omitted permissions blocks or explicit overbroad permissions."""

    id = "R002"
    name = "excessive_permissions"
    description = (
        "Workflow or job omits explicit permissions block (defaulting to write-all) "
        "or specifies excessive explicit write scopes"
    )
    default_severity = Severity.HIGH
    category = "Permissions"
    tags = ["permissions", "least-privilege", "access-control"]
    references = [
        "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        # 1. Top-level workflow permissions check
        wf_perms = workflow.permissions

        if wf_perms == "write-all":
            findings.append(
                Finding(
                    id=f"f-r002-{len(findings)+1:04d}",
                    rule_id=self.id,
                    title="Explicit Workflow-Level write-all Permissions",
                    severity=Severity.HIGH,
                    file=workflow.file_path,
                    job=None,
                    step=None,
                    line=workflow.permissions_line or workflow.line,
                    evidence="Workflow explicitly configures 'permissions: write-all', granting full write access across all scopes.",
                    tags=list(self.tags),
                    base_score=8.5,
                )
            )

        # 2. Check each job
        for job_id, job in workflow.jobs.items():
            # Skip reusable workflow calls at job level if they don't declare local step permissions
            if job.uses and not job.permissions:
                continue

            job_perms = job.permissions

            # Case A: Job explicitly specifies write-all
            if job_perms == "write-all":
                findings.append(
                    Finding(
                        id=f"f-r002-{len(findings)+1:04d}",
                        rule_id=self.id,
                        title="Explicit Job-Level write-all Permissions",
                        severity=Severity.HIGH,
                        file=workflow.file_path,
                        job=job_id,
                        step=None,
                        line=job.permissions_line or job.line,
                        evidence=f"Job '{job_id}' explicitly specifies 'permissions: write-all'.",
                        tags=list(self.tags),
                        base_score=8.0,
                    )
                )
                continue

            # Case B: Both workflow and job omit permissions block entirely
            if wf_perms is None and job_perms is None:
                findings.append(
                    Finding(
                        id=f"f-r002-{len(findings)+1:04d}",
                        rule_id=self.id,
                        title="Omitted Permissions Block (Defaulting to Permissive Token)",
                        severity=Severity.MEDIUM,
                        file=workflow.file_path,
                        job=job_id,
                        step=None,
                        line=job.line,
                        evidence=(
                            f"Job '{job_id}' and top-level workflow omit explicit 'permissions:' configuration. "
                            "GITHUB_TOKEN permissions will default to repository settings (often write-all by default)."
                        ),
                        tags=list(self.tags),
                        base_score=6.0,
                    )
                )
                continue

            # Case C: Job specifies a mapping with excessive write scopes
            effective_perms: Any = job_perms if job_perms is not None else wf_perms
            if isinstance(effective_perms, dict):
                # Check for write scopes on untrusted triggers or broad write permissions
                write_scopes = [
                    k for k, v in effective_perms.items()
                    if str(v).lower() in ("write", "true")
                ]
                has_untrusted_trigger = any(
                    trig in ("issues", "issue_comment", "pull_request", "pull_request_target")
                    for trig in workflow.triggers
                )
                if len(write_scopes) >= 2 or (has_untrusted_trigger and "contents" in write_scopes):
                    finding_line = job.permissions_line or workflow.permissions_line or job.line
                    findings.append(
                        Finding(
                            id=f"f-r002-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Overbroad Write Permissions Configuration",
                            severity=Severity.HIGH,
                            file=workflow.file_path,
                            job=job_id,
                            step=None,
                            line=finding_line,
                            evidence=(
                                f"Job '{job_id}' grants excessive write permissions ({', '.join(write_scopes)}). "
                                "Adhere to the principle of least privilege by scoping GITHUB_TOKEN permissions "
                                "only to the minimum required scopes."
                            ),
                            tags=list(self.tags),
                            base_score=7.8,
                        )
                    )

        return findings
