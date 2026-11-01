"""Rule R004: Detection of script injection vulnerabilities via inline GitHub context interpolation."""

import re

from app.config import UNTRUSTED_CONTEXT_PATTERNS
from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

# Additional regex matching any ${{ github.event.* }} context containing user-controllable input
GENERIC_UNTRUSTED_INJECTION = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|commits|head_commit|client_payload)[^\}]*|head_ref)\s*\}\}",
    re.IGNORECASE,
)


class ScriptInjectionRule(BaseRule):
    """Flags direct interpolation of untrusted GitHub event context inside shell script run steps."""

    id = "R004"
    name = "script_injection"
    description = (
        "Shell 'run:' command contains direct inline interpolation of untrusted user context "
        "(e.g. issue titles, PR bodies, commit messages), enabling arbitrary command execution."
    )
    default_severity = Severity.CRITICAL
    category = "Code Injection"
    tags = ["injection", "script-injection", "cwe-78"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                if not step.run:
                    continue

                matched_expressions: list[str] = []

                # Check specific untrusted context patterns
                for pattern in UNTRUSTED_CONTEXT_PATTERNS:
                    matches = pattern.findall(step.run)
                    if matches:
                        matched_expressions.extend(matches)

                # Check generic untrusted context pattern
                generic_matches = GENERIC_UNTRUSTED_INJECTION.findall(step.run)
                if generic_matches:
                    for gm in generic_matches:
                        if gm not in matched_expressions:
                            matched_expressions.append(gm)

                if matched_expressions:
                    step_display = step.name or "Script Execution"
                    finding_line = step.run_line or step.line
                    findings.append(
                        Finding(
                            id=f"f-r004-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Script Injection via Untrusted Context Interpolation",
                            severity=Severity.CRITICAL,
                            file=workflow.file_path,
                            job=job_id,
                            step=step_display,
                            line=finding_line,
                            evidence=(
                                f"Step '{step_display}' interpolates untrusted GitHub context "
                                f"directly inside shell script: {', '.join(set(matched_expressions))}. "
                                "An attacker can manipulate the issue/PR title to inject arbitrary bash commands. "
                                "Remediate by assigning the value to an intermediate environment variable (env:) "
                                "and referencing it as a shell variable ($VAR)."
                            ),
                            tags=list(self.tags),
                            base_score=9.5,
                        )
                    )

        return findings
