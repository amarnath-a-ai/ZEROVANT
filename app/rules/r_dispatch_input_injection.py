"""Rule: Detection of workflow/repository dispatch input interpolation in shell commands."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

DISPATCH_INPUT_PATTERN = re.compile(
    r"\$\{\{\s*(?:inputs|github\.event\.inputs)\.[a-zA-Z0-9_-]+\s*\}\}",
    re.IGNORECASE,
)


class DispatchInputInjectionRule(BaseRule):
    """Flags direct inline interpolation of workflow_dispatch or repository_dispatch inputs in run steps."""

    id = "dispatch-input-injection"
    name = "dispatch_input_injection"
    description = (
        "Workflow inputs (${{ inputs.* }} or ${{ github.event.inputs.* }}) are directly interpolated "
        "into a shell 'run:' command. While dispatch requires repository write access, passing inputs "
        "via environment variables prevents unintended argument splitting and subshell expansion vulnerabilities."
    )
    default_severity = Severity.LOW
    category = "Injection"
    tags = ["dispatch", "input-injection", "workflow_dispatch", "defense-in-depth"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for _job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                if not step.run:
                    continue

                matches = DISPATCH_INPUT_PATTERN.findall(step.run)
                if matches:
                    target_line = step.run_line or step.line
                    findings.append(
                        self.build_finding(
                            workflow=workflow,
                            job=job,
                            step=step,
                            line=target_line,
                            message=(
                                f"Step interpolates dispatch inputs ({', '.join(set(matches))}) directly into shell script. "
                                "Pass inputs through the step's 'env:' block to avoid command expansion hazards."
                            ),
                            context={
                                "matched_inputs": list(set(matches)),
                            },
                        )
                    )

        return findings
