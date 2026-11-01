"""Rule: Detection of ACTIONS_ALLOW_UNSECURE_COMMANDS and deprecated runner commands."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

DEPRECATED_RUNNER_COMMANDS = re.compile(
    r"::(?:set-env|add-path)\s+",
    re.IGNORECASE,
)


class InsecureCommandsEnabledRule(BaseRule):
    """Flags enablement of ACTIONS_ALLOW_UNSECURE_COMMANDS or deprecated runner workflow commands."""

    id = "insecure-commands-enabled"
    name = "insecure_commands_enabled"
    description = (
        "ACTIONS_ALLOW_UNSECURE_COMMANDS is enabled or deprecated runner workflow commands (::set-env, ::add-path) "
        "are used. GitHub disabled these commands because untrusted output can inject arbitrary environment variables "
        "and modify system paths, leading to arbitrary code execution."
    )
    default_severity = Severity.CRITICAL
    category = "Injection"
    tags = ["insecure-commands", "runner", "environment-injection", "cwe-78"]
    references = [
        "https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/",
        "https://securitylab.github.com/research/github-actions-untrusted-input-analysis-runners-environment-injection/",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow:
            return []

        findings: list[Finding] = []

        # Check workflow-level env
        if workflow.env:
            for k, v in workflow.env.items():
                if k.upper() == "ACTIONS_ALLOW_UNSECURE_COMMANDS":
                    val_str = str(v).strip().lower()
                    if val_str in ("true", "1", "yes", "on"):
                        target_line = workflow.env_lines.get(k, workflow.line)
                        findings.append(
                            self.build_finding(
                                workflow=workflow,
                                job=None,
                                line=target_line,
                                message=(
                                    "Workflow explicitly enables 'ACTIONS_ALLOW_UNSECURE_COMMANDS: true'. "
                                    "This re-enables vulnerable ::set-env and ::add-path commands that allow "
                                    "untrusted log output to execute arbitrary code."
                                ),
                                context={
                                    "env_var": k,
                                    "value": str(v),
                                },
                            )
                        )

        # Check jobs and steps
        if workflow.jobs:
            for job_id, job in workflow.jobs.items():
                if job.env:
                    for k, v in job.env.items():
                        if k.upper() == "ACTIONS_ALLOW_UNSECURE_COMMANDS":
                            val_str = str(v).strip().lower()
                            if val_str in ("true", "1", "yes", "on"):
                                findings.append(
                                    self.build_finding(
                                        workflow=workflow,
                                        job=job,
                                        line=job.line,
                                        message=(
                                            f"Job '{job_id}' enables 'ACTIONS_ALLOW_UNSECURE_COMMANDS: true'."
                                        ),
                                    )
                                )

                for step in job.steps:
                    if step.run and DEPRECATED_RUNNER_COMMANDS.search(step.run):
                        findings.append(
                            self.build_finding(
                                workflow=workflow,
                                job=job,
                                step=step,
                                line=step.run_line or step.line,
                                message=(
                                    "Step uses deprecated workflow command (::set-env or ::add-path). "
                                    "Use environment files ($GITHUB_ENV, $GITHUB_PATH) instead."
                                ),
                            )
                        )

        return findings
