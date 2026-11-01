"""Rule: Detection of untrusted artifact ingestion in workflow_run workflows."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

DOWNLOAD_ARTIFACT_ACTIONS = {
    "actions/download-artifact",
    "dawidd6/action-download-artifact",
}


class WorkflowRunUntrustedArtifactRule(BaseRule):
    """Flags workflow_run workflows that download and process untrusted artifacts."""

    id = "workflow-run-untrusted-artifact"
    name = "workflow_run_untrusted_artifact"
    description = (
        "A workflow triggered by workflow_run downloads artifacts from the triggering workflow run. "
        "Because workflow_run executes in the base repository context with access to secrets and write tokens, "
        "executing code or parsing untrusted artifacts from an unauthenticated PR run can lead to repository compromise."
    )
    default_severity = Severity.HIGH
    category = "Privilege Escalation"
    tags = ["workflow_run", "artifact", "privilege-escalation", "supply-chain"]
    references = [
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        "https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_run",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        if "workflow_run" not in workflow.triggers:
            return []

        findings: list[Finding] = []

        for _job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                is_artifact_download = False
                action_name = ""

                if step.action_ref:
                    action_key = f"{step.action_ref.owner}/{step.action_ref.repository}".lower()
                    if action_key in DOWNLOAD_ARTIFACT_ACTIONS:
                        is_artifact_download = True
                        action_name = step.action_ref.raw
                elif step.uses:
                    lower_uses = step.uses.lower()
                    if any(act in lower_uses for act in DOWNLOAD_ARTIFACT_ACTIONS):
                        is_artifact_download = True
                        action_name = step.uses

                if is_artifact_download:
                    target_line = step.uses_line or step.line
                    findings.append(
                        self.build_finding(
                            workflow=workflow,
                            job=job,
                            step=step,
                            line=target_line,
                            message=(
                                f"Step uses '{action_name}' within a 'workflow_run' triggered workflow. "
                                "Artifacts produced by untrusted forks can contain malicious executables or inputs, "
                                "which execute with this workflow's privileged credentials."
                            ),
                            context={
                                "action": action_name,
                                "trigger": "workflow_run",
                            },
                        )
                    )

        return findings
