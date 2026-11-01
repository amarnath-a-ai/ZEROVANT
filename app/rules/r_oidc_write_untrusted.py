"""Rule: Detection of id-token: write on untrusted triggers."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

UNTRUSTED_OIDC_TRIGGERS = {
    "pull_request",
    "pull_request_target",
    "issue_comment",
    "pull_request_review_comment",
    "discussion_comment",
}


class OidcWriteUntrustedRule(BaseRule):
    """Flags granting id-token: write permissions on untrusted trigger workflows."""

    id = "oidc-write-untrusted"
    name = "oidc_write_untrusted"
    description = (
        "Workflow grants 'id-token: write' on untrusted triggers (e.g. pull_request). "
        "Any public user opening a pull request from a fork can mint OIDC identity tokens "
        "and potentially assume federated cloud roles (AWS, GCP, Azure)."
    )
    default_severity = Severity.HIGH
    category = "Access Control"
    tags = ["oidc", "id-token", "permissions", "access-control", "privilege-escalation"]
    references = [
        "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow:
            return []

        active_untrusted = [t for t in UNTRUSTED_OIDC_TRIGGERS if t in workflow.triggers]
        if not active_untrusted:
            return []

        findings: list[Finding] = []

        # Check workflow-level permissions
        if workflow.permissions:
            has_oidc_write = False
            if workflow.permissions == "write-all":
                has_oidc_write = True
            elif isinstance(workflow.permissions, dict) and workflow.permissions.get("id-token") == "write":
                has_oidc_write = True

            if has_oidc_write:
                target_line = workflow.permission_lines.get("id-token", workflow.permissions_line or workflow.line)
                findings.append(
                    self.build_finding(
                        workflow=workflow,
                        job=None,
                        line=target_line,
                        message=(
                            f"Workflow grants 'id-token: write' while triggered by untrusted event '{active_untrusted[0]}'. "
                            "Restrict OIDC minting to protected branch push events or verify PR head repository."
                        ),
                        context={
                            "trigger": active_untrusted[0],
                            "scope": "workflow",
                        },
                    )
                )

        # Check job-level permissions
        if workflow.jobs:
            for job_id, job in workflow.jobs.items():
                if job.permissions:
                    has_job_oidc_write = False
                    if job.permissions == "write-all":
                        has_job_oidc_write = True
                    elif isinstance(job.permissions, dict) and job.permissions.get("id-token") == "write":
                        has_job_oidc_write = True

                    if has_job_oidc_write:
                        target_line = job.permission_lines.get("id-token", job.permissions_line or job.line)
                        findings.append(
                            self.build_finding(
                                workflow=workflow,
                                job=job,
                                line=target_line,
                                message=(
                                    f"Job '{job_id}' requests 'id-token: write' on untrusted trigger '{active_untrusted[0]}'. "
                                    "OIDC tokens should not be issued to untrusted pull requests."
                                ),
                                context={
                                    "trigger": active_untrusted[0],
                                    "job_id": job_id,
                                },
                            )
                        )

        return findings
