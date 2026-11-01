"""Rule: Detection of cache poisoning risks in privileged release or write workflows."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class CachePoisoningRiskRule(BaseRule):
    """Flags actions/cache usage in workflows with write permissions or release/tag triggers."""

    id = "cache-poisoning-risk"
    name = "cache_poisoning_risk"
    description = (
        "Workflow uses 'actions/cache' in a privileged context (with write permissions or release/tag triggers). "
        "Because GitHub Actions caches can be populated from non-protected branches or pull requests within the same scope, "
        "a compromised cache entry can inject malicious dependencies or binaries into release artifacts."
    )
    default_severity = Severity.HIGH
    category = "Supply Chain"
    tags = ["cache", "cache-poisoning", "supply-chain", "release-security"]
    references = [
        "https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#restrictions-for-accessing-a-cache",
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        # Check if workflow is privileged (write permissions or release/tag trigger)
        is_privileged_trigger = False
        if "release" in workflow.triggers:
            is_privileged_trigger = True
        elif "push" in workflow.triggers:
            push_cfg = workflow.triggers.get("push")
            if isinstance(push_cfg, dict) and "tags" in push_cfg:
                is_privileged_trigger = True

        findings: list[Finding] = []

        for _job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            # Check permissions
            effective_perms = job.permissions if job.permissions is not None else workflow.permissions
            has_write_perms = False
            if effective_perms == "write-all":
                has_write_perms = True
            elif isinstance(effective_perms, dict):
                has_write_perms = any(v == "write" for v in effective_perms.values())

            if not (is_privileged_trigger or has_write_perms):
                continue

            for step in job.steps:
                is_cache_action = False
                if step.action_ref and step.action_ref.repository == "cache" and step.action_ref.owner == "actions":
                    is_cache_action = True
                elif step.uses and "actions/cache" in step.uses.lower():
                    is_cache_action = True

                if is_cache_action:
                    target_line = step.uses_line or step.line
                    findings.append(
                        self.build_finding(
                            workflow=workflow,
                            job=job,
                            step=step,
                            line=target_line,
                            message=(
                                f"Job uses '{step.uses}' in a privileged workflow with write permissions or release triggers. "
                                "Avoid restoring shared caches during artifact packaging or releases to eliminate cache poisoning."
                            ),
                            context={
                                "action": step.uses,
                            },
                        )
                    )

        return findings
