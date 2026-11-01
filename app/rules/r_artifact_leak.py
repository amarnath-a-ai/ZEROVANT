"""Rule 14: artifact-leak: upload-artifact archiving entire workspace, .git, or .env."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

LEAK_PATHS = {".", "./", ".git", ".env"}


class ArtifactLeakRule(BaseRule):
    """Flags actions/upload-artifact configurations that archive whole repository roots or secrets."""

    id = "artifact-leak"
    name = "artifact_leak"
    description = (
        "actions/upload-artifact archives the entire workspace root ('.'), the '.git' directory, "
        "or '.env' files. Uploading the whole repository packages git history, configuration files, "
        "and potentially sensitive tokens (.git/config) into downloadable public artifacts."
    )
    default_severity = Severity.HIGH
    category = "credentials"
    tier = "extension"
    tags = ["credentials", "artifacts", "token-leak"]
    references = [
        "https://github.com/actions/upload-artifact"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []
        raw_lines = workflow.raw_content.splitlines() if workflow.raw_content else []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                if not step.uses or "upload-artifact" not in step.uses.lower():
                    continue

                raw_path = str(step.with_params.get("path", "")).strip()
                is_leaky = False
                leak_reason = ""

                if raw_path in LEAK_PATHS:
                    is_leaky = True
                    leak_reason = f"Path '{raw_path}' archives repository root or dotfile directory"
                elif raw_path.startswith((".git", ".env")):
                    is_leaky = True
                    leak_reason = f"Path '{raw_path}' archives sensitive git metadata or env file"

                if is_leaky:
                    step_display = step.name or step.uses
                    finding_line = step.line
                    # Locate exact line for path parameter if raw content available
                    for line_no, raw_line in enumerate(raw_lines, start=1):
                        stripped = raw_line.strip()
                        if stripped.startswith("path:") and raw_path in stripped:
                            finding_line = line_no
                            break

                    findings.append(
                        Finding(
                            id=f"f-artifact-leak-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Dangerous Overbroad Artifact Upload Path",
                            severity=self.default_severity,
                            file=workflow.file_path,
                            job=job_id,
                            step=step_display,
                            line=finding_line,
                            evidence=(
                                f"Step '{step_display}' uploads artifact with overbroad path '{raw_path}' ({leak_reason}). "
                                "Restrict uploaded artifact paths to dedicated build directories (e.g. dist/ or build/)."
                            ),
                            tags=list(self.tags),
                            base_score=7.8,
                        )
                    )

        return findings
