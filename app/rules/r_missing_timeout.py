"""Rule: Detection of missing timeout-minutes on execution jobs."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class MissingTimeoutRule(BaseRule):
    """Flags jobs that omit timeout-minutes, risking runaway execution and resource exhaustion."""

    id = "missing-timeout"
    name = "missing_timeout"
    description = (
        "Job does not define 'timeout-minutes'. By default, GitHub Actions workflows can run for up to 6 hours (360 minutes) "
        "before being terminated, consuming build minutes and locking self-hosted or shared runners during hung processes."
    )
    default_severity = Severity.LOW
    category = "Reliability Hygiene"
    tags = ["timeout", "reliability", "resource-exhaustion", "denial-of-service"]
    references = [
        "https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            # Skip reusable workflow caller jobs (they do not take timeout-minutes)
            if job.uses:
                continue

            if job.timeout_minutes is None:
                findings.append(
                    self.build_finding(
                        workflow=workflow,
                        job=job,
                        line=job.line,
                        message=(
                            f"Job '{job_id}' does not specify 'timeout-minutes'. "
                            "Set an explicit timeout (e.g. 'timeout-minutes: 15') to prevent hung builds from exhausting runner resources."
                        ),
                        context={
                            "job_id": job_id,
                        },
                    )
                )

        return findings
