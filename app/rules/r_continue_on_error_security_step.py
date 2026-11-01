"""Rule: Detection of continue-on-error on security scanning steps."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

SECURITY_STEP_PATTERN = re.compile(
    r"\b(?:audit|snyk|trivy|semgrep|bandit|gitleaks|trufflehog|checkov|cosign|codeql|grype|clamav|pip-audit|cargo-audit|security-scan|vulnerability)\b",
    re.IGNORECASE,
)


class ContinueOnErrorSecurityStepRule(BaseRule):
    """Flags security scanning or signing steps that set continue-on-error: true."""

    id = "continue-on-error-security-step"
    name = "continue_on_error_security_step"
    description = (
        "Step sets 'continue-on-error: true' on a security scanner, SAST tool, or verification step. "
        "This silences detected vulnerabilities and critical findings, allowing vulnerable code or compromised "
        "dependencies to be deployed to production."
    )
    default_severity = Severity.HIGH
    category = "Reliability Hygiene"
    tags = ["continue-on-error", "security-gate", "sast", "compliance"]
    references = [
        "https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepscontinue-on-error",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for _job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                is_continue_on_error = False
                if step.continue_on_error is True:
                    is_continue_on_error = True
                elif isinstance(step.continue_on_error, str) and step.continue_on_error.strip().lower() in ("true", "1", "yes"):
                    is_continue_on_error = True

                if not is_continue_on_error:
                    continue

                # Check if this is a security scanning / verification step
                step_text = f"{step.name} {step.uses} {step.run}"
                if SECURITY_STEP_PATTERN.search(step_text):
                    target_line = step.continue_on_error_line or step.line
                    findings.append(
                        self.build_finding(
                            workflow=workflow,
                            job=job,
                            step=step,
                            line=target_line,
                            message=(
                                f"Security step '{step.name or step.run[:30]}' sets 'continue-on-error: true'. "
                                "Failing security scans must block the pipeline rather than silently succeeding."
                            ),
                            context={
                                "step_name": step.name,
                            },
                        )
                    )

        return findings
