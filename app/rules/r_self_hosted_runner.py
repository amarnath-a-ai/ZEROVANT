"""Rule R009: Detection of untrusted workflows executing on self-hosted runners."""

from app.config import UNTRUSTED_TRIGGERS
from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class SelfHostedRunnerRule(BaseRule):
    """Flags persistent self-hosted runners assigned to workflows responding to untrusted events."""

    id = "R009"
    name = "self_hosted_runner"
    description = (
        "Workflow triggered by untrusted external events (e.g. pull_request) executes on a self-hosted runner. "
        "Self-hosted runners lack sandbox isolation between runs, allowing pull requests from forks to achieve "
        "lateral movement, access host network services, or install persistent rootkits."
    )
    default_severity = Severity.HIGH
    category = "Infrastructure Security"
    tags = ["self-hosted", "runners", "persistence", "infrastructure"]
    references = [
        "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        # Find untrusted triggers present on this workflow
        triggered_untrusted = [t for t in workflow.triggers if t in UNTRUSTED_TRIGGERS]
        if not triggered_untrusted:
            return []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            runs_on_val = job.runs_on
            is_self_hosted = False

            if isinstance(runs_on_val, str):
                if "self-hosted" in runs_on_val.lower():
                    is_self_hosted = True
            elif isinstance(runs_on_val, list):
                if any("self-hosted" in str(item).lower() for item in runs_on_val):
                    is_self_hosted = True

            if is_self_hosted:
                finding_line = job.runs_on_line or job.line
                findings.append(
                    Finding(
                        id=f"f-r009-{len(findings)+1:04d}",
                        rule_id=self.id,
                        title="Self-Hosted Runner on Untrusted Workflow Trigger",
                        severity=Severity.HIGH,
                        file=workflow.file_path,
                        job=job_id,
                        step=None,
                        line=finding_line,
                        evidence=(
                            f"Job '{job_id}' executes on a self-hosted runner ({runs_on_val}) while "
                            f"triggered by untrusted external event(s): {', '.join(triggered_untrusted)}. "
                            "Untrusted fork pull requests can compromise the host machine. "
                            "Switch to GitHub-hosted runners or ephemeral, single-use autoscaled VMs."
                        ),
                        tags=list(self.tags),
                        base_score=8.5,
                    )
                )

        return findings
