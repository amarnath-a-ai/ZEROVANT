"""Rule: Detection of curl or wget piped directly into shell interpreter."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|(?:curl|wget)\b[^|;&\n]*\|\s*(?:python[23]?|perl|ruby)\b",
    re.IGNORECASE,
)


class CurlPipeShellRule(BaseRule):
    """Flags remote scripts downloaded via curl or wget piped directly into a shell interpreter."""

    id = "curl-pipe-shell"
    name = "curl_pipe_shell"
    description = (
        "Script downloads remote executable content via curl or wget and pipes it directly into a shell interpreter "
        "(e.g. 'curl ... | bash') without checksum verification. Compromise of the CDN, DNS spoofing, or MITM enables "
        "arbitrary remote code execution."
    )
    default_severity = Severity.HIGH
    category = "Supply Chain"
    tags = ["curl", "shell", "pipe-to-shell", "supply-chain", "remote-execution"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
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

                run_lines = step.run.splitlines()
                for line_offset, line in enumerate(run_lines):
                    if CURL_PIPE_SHELL_PATTERN.search(line):
                        target_line = (step.run_line or step.line) + line_offset
                        findings.append(
                            self.build_finding(
                                workflow=workflow,
                                job=job,
                                step=step,
                                line=target_line,
                                message=(
                                    "Step downloads remote script with curl/wget and pipes directly into a shell interpreter. "
                                    "Download script to disk, verify its SHA256 checksum against a known hash, and execute explicitly."
                                ),
                                context={
                                    "line_snippet": line.strip(),
                                },
                            )
                        )

        return findings
