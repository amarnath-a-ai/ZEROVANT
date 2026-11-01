"""Rule: Detection of unpinned reusable workflow calls."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

HEX_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class UnpinnedReusableWorkflowRule(BaseRule):
    """Flags reusable workflows referenced by mutable git branch or tag instead of immutable commit SHA."""

    id = "unpinned-reusable-workflow"
    name = "unpinned_reusable_workflow"
    description = (
        "Job calls a reusable workflow using a mutable reference (branch or tag) rather than an immutable 40-character commit SHA. "
        "Upstream branch modifications or compromised tags can alter pipeline execution logic without notice."
    )
    default_severity = Severity.HIGH
    category = "Supply Chain"
    tags = ["reusable-workflow", "unpinned", "supply-chain", "pinning"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        "https://docs.github.com/en/actions/using-workflows/reusing-workflows",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if not job.uses:
                continue

            raw_uses = job.uses.strip()
            # Check if this is a reusable workflow reference (typically .github/workflows/*.yml@ref)
            if ".github/workflows/" in raw_uses and "@" in raw_uses:
                _target, ref = raw_uses.split("@", 1)
                ref = ref.strip()
                if not HEX_SHA_PATTERN.match(ref):
                    target_line = job.uses_line or job.line
                    findings.append(
                        self.build_finding(
                            workflow=workflow,
                            job=job,
                            line=target_line,
                            message=(
                                f"Reusable workflow call '{raw_uses}' is pinned to mutable reference '@{ref}' "
                                "instead of an immutable 40-character commit SHA. Pin to a full SHA hash to prevent "
                                "supply chain tampering."
                            ),
                            context={
                                "uses": raw_uses,
                                "ref": ref,
                                "job_id": job_id,
                            },
                        )
                    )

        return findings
