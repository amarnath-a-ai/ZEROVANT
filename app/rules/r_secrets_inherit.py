"""Rule 15: secrets-inherit: reusable workflow call using secrets: inherit."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class SecretsInheritRule(BaseRule):
    """Flags reusable workflow calls that pass all repository secrets via secrets: inherit."""

    id = "secrets-inherit"
    name = "secrets_inherit"
    description = (
        "Job calls a reusable workflow using 'secrets: inherit'. This implicitly exposes all organization "
        "and repository secrets to the called workflow. If the called workflow is compromised or modified, "
        "all secrets are exposed instead of only those strictly necessary."
    )
    default_severity = Severity.MEDIUM
    category = "credentials"
    tier = "extension"
    tags = ["credentials", "reusable-workflows", "least-privilege"]
    references = [
        "https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-secrets-to-nested-workflows"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if not job.uses:
                continue

            if str(job.secrets).strip().lower() == "inherit":
                finding_line = job.secrets_line or job.line
                findings.append(
                    Finding(
                        id=f"f-sec-inherit-{len(findings)+1:04d}",
                        rule_id=self.id,
                        title="Reusable Workflow Call with 'secrets: inherit'",
                        severity=self.default_severity,
                        file=workflow.file_path,
                        job=job_id,
                        step=None,
                        line=finding_line,
                        evidence=(
                            f"Job '{job_id}' invokes reusable workflow '{job.uses}' with 'secrets: inherit'. "
                            "Pass only explicitly required secrets under the 'secrets:' block."
                        ),
                        tags=list(self.tags),
                        base_score=6.2,
                    )
                )

        return findings
