"""Rule R003: Detection of dangerous checkout of untrusted PR head commit in pull_request_target workflows."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

# Patterns referencing untrusted pull request head references
PR_HEAD_REF_PATTERNS = [
    re.compile(r"github\.event\.pull_request\.head\.sha"),
    re.compile(r"github\.event\.pull_request\.head\.ref"),
    re.compile(r"github\.head_ref"),
    re.compile(r"github\.event\.pull_request\.head"),
]


class PrTargetCheckoutRule(BaseRule):
    """Flags pull_request_target workflows that checkout the untrusted PR head ref."""

    id = "R003"
    name = "pr_target_checkout"
    description = (
        "Workflow triggered by pull_request_target checks out the untrusted PR head commit "
        "rather than the base repository ref, exposing repository secrets and write tokens."
    )
    default_severity = Severity.CRITICAL
    category = "Privilege Escalation"
    tags = ["pwn-request", "pr-target", "privilege-escalation"]
    references = [
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        # Only applicable to workflows triggered by pull_request_target
        if "pull_request_target" not in workflow.triggers:
            return []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                # Check for actions/checkout step
                is_checkout = False
                if step.uses and "checkout" in step.uses.lower():
                    is_checkout = True
                elif step.name and "checkout" in step.name.lower():
                    is_checkout = True

                if not is_checkout:
                    continue

                # Inspect ref parameter in with_params
                ref_param = str(step.with_params.get("ref", ""))
                is_untrusted_head = any(p.search(ref_param) for p in PR_HEAD_REF_PATTERNS)

                if is_untrusted_head:
                    step_display = step.name or step.uses or "Checkout"
                    finding_line = step.uses_line or step.line
                    findings.append(
                        Finding(
                            id=f"f-r003-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Dangerous PR Head Checkout in pull_request_target",
                            severity=Severity.CRITICAL,
                            file=workflow.file_path,
                            job=job_id,
                            step=step_display,
                            line=finding_line,
                            evidence=(
                                f"Step '{step_display}' checks out untrusted PR head commit "
                                f"via 'ref: {ref_param}' within a privileged 'pull_request_target' workflow. "
                                "This enables untrusted pull requests to execute arbitrary code with repository write permissions."
                            ),
                            tags=list(self.tags),
                            base_score=9.8,
                        )
                    )

        return findings
