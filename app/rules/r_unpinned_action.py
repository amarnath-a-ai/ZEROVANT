"""Rule R001: Detection of actions pinned to mutable tags or branches instead of immutable SHAs."""

from app.parser.model import RefType, Workflow
from app.rules.base import BaseRule, Finding, Severity


class UnpinnedActionRule(BaseRule):
    """Flags actions and reusable workflows not pinned to a full 40-character commit SHA."""

    id = "R001"
    name = "unpinned_action"
    description = "Action or reusable workflow referenced by mutable tag/branch instead of immutable SHA"
    default_severity = Severity.HIGH
    category = "Supply Chain"
    tags = ["supply-chain", "actions", "integrity"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            # Check reusable workflow caller job (job-level uses)
            if job.uses and job.action_ref:
                if job.action_ref.ref_type in (RefType.BRANCH, RefType.TAG):
                    findings.append(
                        Finding(
                            id=f"f-r001-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Unpinned Reusable Workflow Reference",
                            severity=self.default_severity,
                            file=workflow.file_path,
                            job=job_id,
                            step=None,
                            line=job.line,
                            evidence=(
                                f"Reusable workflow '{job.uses}' is referenced by mutable "
                                f"{job.action_ref.ref_type.value} '{job.action_ref.ref}' "
                                f"instead of an immutable 40-character commit SHA."
                            ),
                            tags=list(self.tags),
                            base_score=7.5,
                        )
                    )
                # Reusable workflow caller jobs have no steps to evaluate
                continue

            # Check individual job steps
            for step in job.steps:
                if not step.uses or not step.action_ref:
                    continue

                if step.action_ref.ref_type in (RefType.BRANCH, RefType.TAG):
                    step_display = step.name or step.uses
                    finding_line = step.uses_line or step.line
                    findings.append(
                        Finding(
                            id=f"f-r001-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Unpinned Action Reference",
                            severity=self.default_severity,
                            file=workflow.file_path,
                            job=job_id,
                            step=step_display,
                            line=finding_line,
                            evidence=(
                                f"Action '{step.uses}' is referenced by mutable "
                                f"{step.action_ref.ref_type.value} '{step.action_ref.ref}' "
                                f"instead of an immutable 40-character commit SHA."
                            ),
                            tags=list(self.tags),
                            base_score=7.5,
                        )
                    )

        return findings
