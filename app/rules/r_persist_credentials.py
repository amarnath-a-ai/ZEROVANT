"""Rule 11: persist-credentials: actions/checkout without persist-credentials: false."""

from app.config import TRUSTED_ACTION_OWNERS
from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class PersistCredentialsRule(BaseRule):
    """Flags actions/checkout when persist-credentials is not set to false in risky jobs."""

    id = "persist-credentials"
    name = "persist_credentials"
    description = (
        "actions/checkout executed without 'persist-credentials: false' in a job that later uses "
        "third-party actions, uploads artifacts, or pushes. By default, checkout stores "
        "the privileged repository token in .git/config, where third-party actions or artifacts can leak it."
    )
    default_severity = Severity.HIGH
    category = "credentials"
    tier = "extension"
    tags = ["credentials", "git", "token-leak"]
    references = [
        "https://github.com/actions/checkout#usage"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for idx, step in enumerate(job.steps):
                if not step.uses or "checkout" not in step.uses.lower():
                    continue

                persist_val = str(step.with_params.get("persist-credentials", "true")).strip().lower()
                if persist_val == "false":
                    continue

                # Check if subsequent steps use third-party actions, upload artifacts, or push
                has_risky_subsequent_step = False
                risk_reason = ""

                for sub_step in job.steps[idx + 1:]:
                    # 1. Uploads artifacts
                    if sub_step.uses and "upload-artifact" in sub_step.uses.lower():
                        has_risky_subsequent_step = True
                        risk_reason = f"subsequent artifact upload '{sub_step.uses}'"
                        break

                    # 2. Uses third-party action
                    if sub_step.uses and sub_step.action_ref:
                        owner = (sub_step.action_ref.owner or "").lower()
                        if owner and owner not in TRUSTED_ACTION_OWNERS:
                            has_risky_subsequent_step = True
                            risk_reason = f"subsequent third-party action '{sub_step.uses}'"
                            break

                    # 3. Executes git push
                    if sub_step.run and "git push" in sub_step.run.lower():
                        has_risky_subsequent_step = True
                        risk_reason = "subsequent 'git push' command"
                        break

                if has_risky_subsequent_step:
                    step_display = step.name or step.uses
                    finding_line = step.line
                    findings.append(
                        Finding(
                            id=f"f-persist-cred-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="actions/checkout Leaves Credential in .git/config",
                            severity=self.default_severity,
                            file=workflow.file_path,
                            job=job_id,
                            step=step_display,
                            line=finding_line,
                            evidence=(
                                f"Step '{step_display}' runs actions/checkout without 'persist-credentials: false' "
                                f"in a job with {risk_reason}. The GITHUB_TOKEN remains stored in plain text inside "
                                ".git/config on the runner filesystem, exposing it to potential exfiltration."
                            ),
                            tags=list(self.tags),
                            base_score=7.8,
                        )
                    )

        return findings
