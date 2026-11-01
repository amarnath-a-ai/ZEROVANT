"""Rule: Detection of untrusted event input written directly into environment / output files."""

import re

from app.config import UNTRUSTED_CONTEXT_PATTERNS
from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

GITHUB_ENV_REDIRECT_PATTERN = re.compile(
    r"(?:>>|>)\s*[\"']?(?:\$(?:GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT)|%(?:GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT)%)[\"']?",
    re.IGNORECASE,
)

GENERIC_EVENT_CONTEXT = re.compile(
    r"\$\{\{\s*github\.event\.[a-zA-Z0-9_.]+\s*\}\}",
    re.IGNORECASE,
)


class GitHubEnvInjectionRule(BaseRule):
    """Flags direct interpolation of untrusted GitHub event data into GITHUB_ENV, GITHUB_PATH, or GITHUB_OUTPUT."""

    id = "github-env-injection"
    name = "github_env_injection"
    description = (
        "Untrusted event data is written directly to $GITHUB_ENV, $GITHUB_PATH, or $GITHUB_OUTPUT "
        "via inline expression interpolation, allowing attackers to inject arbitrary environment variables or paths."
    )
    default_severity = Severity.HIGH
    category = "Injection"
    tags = ["injection", "environment-injection", "github-env", "cwe-78"]
    references = [
        "https://securitylab.github.com/research/github-actions-untrusted-input-analysis-runners-environment-injection/",
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

                # Check line by line or overall step run
                run_lines = step.run.splitlines()
                has_env_redirect = bool(GITHUB_ENV_REDIRECT_PATTERN.search(step.run))
                if not has_env_redirect:
                    continue

                for line_offset, line in enumerate(run_lines):
                    if not GITHUB_ENV_REDIRECT_PATTERN.search(line):
                        continue

                    # Check if line contains untrusted event context interpolation
                    matched_exprs = []
                    for pattern in UNTRUSTED_CONTEXT_PATTERNS:
                        matched_exprs.extend(pattern.findall(line))

                    if not matched_exprs:
                        matched_exprs.extend(GENERIC_EVENT_CONTEXT.findall(line))

                    if matched_exprs:
                        target_line = (step.run_line or step.line) + line_offset
                        findings.append(
                            self.build_finding(
                                workflow=workflow,
                                job=job,
                                step=step,
                                line=target_line,
                                message=(
                                    f"Step interpolates untrusted event context ({', '.join(set(matched_exprs))}) "
                                    "directly into a command writing to $GITHUB_ENV, $GITHUB_PATH, or $GITHUB_OUTPUT. "
                                    "Attackers can inject newlines and malicious environment variables (e.g. LD_PRELOAD)."
                                ),
                                context={
                                    "matched_expressions": list(set(matched_exprs)),
                                    "line_snippet": line.strip(),
                                },
                            )
                        )

        return findings
