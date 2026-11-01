"""Rule: Detection of overbroad job write permissions for read-only workloads."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

WRITE_OPERATIONS_PATTERN = re.compile(
    r"\b(?:git\s+push|npm\s+publish|twine\s+upload|docker\s+push|gh\s+release|gh\s+pr\s+(?:create|merge|comment)|kubectl\s+apply)\b",
    re.IGNORECASE,
)

PUBLISHING_ACTIONS = {
    "release",
    "publish",
    "upload-release-asset",
    "create-release",
    "gh-release",
}


class PermissionsOverbroadJobRule(BaseRule):
    """Flags jobs requesting write permissions when their execution steps only perform read-only tasks."""

    id = "permissions-overbroad-job"
    name = "permissions_overbroad_job"
    description = (
        "Job requests write permissions (such as contents: write or packages: write) but only performs read-only "
        "operations like testing or linting. Apply the Principle of Least Privilege by scoping permissions to read."
    )
    default_severity = Severity.MEDIUM
    category = "Access Control"
    tags = ["permissions", "least-privilege", "access-control"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#assigning-permissions-to-jobs",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if not job.permissions:
                continue

            write_scopes: list[str] = []
            if job.permissions == "write-all":
                write_scopes = ["write-all"]
            elif isinstance(job.permissions, dict):
                write_scopes = [k for k, v in job.permissions.items() if v == "write"]

            if not write_scopes:
                continue

            # Check if steps perform any genuine write/publish operations
            has_write_action = False
            for step in job.steps:
                if step.run and WRITE_OPERATIONS_PATTERN.search(step.run):
                    has_write_action = True
                    break
                if step.action_ref:
                    repo_lower = step.action_ref.repository.lower()
                    if any(act in repo_lower for act in PUBLISHING_ACTIONS):
                        has_write_action = True
                        break

            if not has_write_action:
                first_scope = write_scopes[0]
                target_line = job.permission_lines.get(first_scope, job.permissions_line or job.line)
                findings.append(
                    self.build_finding(
                        workflow=workflow,
                        job=job,
                        line=target_line,
                        message=(
                            f"Job '{job_id}' requests write permissions ({', '.join(write_scopes)}) but steps only "
                            "perform test, lint, or read-only execution. Restrict permissions to 'contents: read'."
                        ),
                        context={
                            "write_scopes": write_scopes,
                            "job_id": job_id,
                        },
                    )
                )

        return findings
