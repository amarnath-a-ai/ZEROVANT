"""Rule 12: secret-to-unpinned-action: passing secrets to an unpinned third-party action."""

from app.config import TRUSTED_ACTION_OWNERS
from app.parser.model import RefType, Workflow
from app.rules.base import BaseRule, Finding, Severity


class SecretToUnpinnedActionRule(BaseRule):
    """Flags secrets passed to third-party actions that are not pinned to an immutable commit SHA."""

    id = "secret-to-unpinned-action"
    name = "secret_to_unpinned_action"
    description = (
        "A repository secret is passed via 'with:' or 'env:' to a third-party action that is referenced "
        "by a mutable tag or branch. If the action repository or tag is compromised, the attacker can "
        "silently exfiltrate the provided secret."
    )
    default_severity = Severity.HIGH
    category = "credentials"
    tier = "extension"
    tags = ["credentials", "supply-chain", "secrets-exfiltration"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                if not step.uses or not step.action_ref:
                    continue

                # Check if action is unpinned
                if step.action_ref.ref_type not in (RefType.BRANCH, RefType.TAG):
                    continue

                owner = (step.action_ref.owner or "").lower()
                # Check if third-party
                if not owner or owner in TRUSTED_ACTION_OWNERS:
                    continue

                # Check for secrets passed in with: or env:
                passed_secrets = []
                for k, v in step.with_params.items():
                    v_str = str(v)
                    if "${{ secrets." in v_str or "${{secrets." in v_str:
                        passed_secrets.append(f"with.{k}")

                for k, v in step.env.items():
                    v_str = str(v)
                    if "${{ secrets." in v_str or "${{secrets." in v_str:
                        passed_secrets.append(f"env.{k}")

                if passed_secrets:
                    step_display = step.name or step.uses
                    finding_line = step.line
                    findings.append(
                        Finding(
                            id=f"f-sec-unpinned-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Secret Passed to Unpinned Third-Party Action",
                            severity=self.default_severity,
                            file=workflow.file_path,
                            job=job_id,
                            step=step_display,
                            line=finding_line,
                            evidence=(
                                f"Step '{step_display}' passes repository secret(s) ({', '.join(passed_secrets)}) "
                                f"to third-party action '{step.uses}' pinned to mutable ref "
                                f"'{step.action_ref.ref}'. Pin the action to an immutable 40-character commit SHA "
                                "to guard against credential exfiltration via supply-chain tampering."
                            ),
                            tags=list(self.tags),
                            base_score=8.5,
                        )
                    )

        return findings
