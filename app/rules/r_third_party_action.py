"""Rule R010: Detection of unvetted third-party actions outside trusted owner organizations."""

from app.config import TRUSTED_ACTION_OWNERS
from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class ThirdPartyActionRule(BaseRule):
    """Flags actions sourced from third-party publishers outside verified organizations."""

    id = "R010"
    name = "third_party_action"
    description = (
        "Action is sourced from a third-party publisher outside official organizations (actions/*, github/*). "
        "Third-party actions represent external software dependencies that can introduce supply chain vulnerabilities, "
        "backdoors, or silent malicious updates if untracked."
    )
    default_severity = Severity.MEDIUM
    category = "Supply Chain"
    tags = ["supply-chain", "third-party", "vendor-risk"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            # Check reusable workflow call at job level
            if job.uses and job.action_ref:
                owner = (job.action_ref.owner or "").lower()
                if owner and owner not in TRUSTED_ACTION_OWNERS:
                    findings.append(
                        Finding(
                            id=f"f-r010-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Third-Party Reusable Workflow from External Publisher",
                            severity=Severity.MEDIUM,
                            file=workflow.file_path,
                            job=job_id,
                            step=None,
                            line=job.line,
                            evidence=(
                                f"Reusable workflow '{job.uses}' is published by third-party owner "
                                f"'{job.action_ref.owner}'. Verify publisher reputation and pin to commit SHA."
                            ),
                            tags=list(self.tags),
                            base_score=6.0,
                        )
                    )
                continue

            for step in job.steps:
                if not step.uses or not step.action_ref:
                    continue

                owner = (step.action_ref.owner or "").lower()
                if not owner or owner in TRUSTED_ACTION_OWNERS:
                    continue

                step_display = step.name or step.uses
                finding_line = step.uses_line or step.line
                findings.append(
                    Finding(
                        id=f"f-r010-{len(findings)+1:04d}",
                        rule_id=self.id,
                        title="Third-Party Action from External Publisher",
                        severity=Severity.MEDIUM,
                        file=workflow.file_path,
                        job=job_id,
                        step=step_display,
                        line=finding_line,
                        evidence=(
                            f"Step '{step_display}' references third-party action '{step.uses}' "
                            f"published by '{step.action_ref.owner}'. Audit third-party action source code, "
                            "verify organization provenance, and strictly pin to an immutable commit SHA."
                        ),
                        tags=list(self.tags),
                        base_score=6.0,
                    )
                )

        return findings
