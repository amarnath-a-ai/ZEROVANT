"""Rule: Detection of insecure bot actor verification patterns."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

BOT_ACTOR_PATTERN = re.compile(
    r"github\.actor\s*==\s*['\"][a-zA-Z0-9_\-]+\[bot\]['\"]|github\.actor\s*==\s*['\"]dependabot(?:\[bot\])?['\"]",
    re.IGNORECASE,
)


class BotActorSpoofingRule(BaseRule):
    """Flags authorization checks relying solely on github.actor username matching for bot accounts."""

    id = "bot-actor-spoofing"
    name = "bot_actor_spoofing"
    description = (
        "Workflow condition relies on github.actor matching a bot username string (such as 'dependabot[bot]'). "
        "Actor names can be spoofed in certain trigger contexts or by creating accounts/branches with matching prefixes. "
        "Verify immutable numeric account IDs (e.g. github.event.pull_request.user.id == 49699333 for Dependabot) "
        "or enforce GitHub branch protection rules."
    )
    default_severity = Severity.MEDIUM
    category = "Authentication Bypass"
    tags = ["authentication", "bot-spoofing", "dependabot", "authorization"]
    references = [
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if job.if_condition and BOT_ACTOR_PATTERN.search(job.if_condition):
                target_line = job.if_line or job.line
                findings.append(
                    self.build_finding(
                        workflow=workflow,
                        job=job,
                        line=target_line,
                        message=(
                            f"Job '{job_id}' condition '{job.if_condition.strip()}' relies on 'github.actor' "
                            "matching a bot username. Use the immutable numeric user id "
                            "(e.g. 'github.event.pull_request.user.id == 49699333') instead."
                        ),
                        context={
                            "condition": job.if_condition.strip(),
                            "job_id": job_id,
                        },
                    )
                )

            for step in job.steps:
                if step.if_condition and BOT_ACTOR_PATTERN.search(step.if_condition):
                    target_line = step.if_line or step.line
                    findings.append(
                        self.build_finding(
                            workflow=workflow,
                            job=job,
                            step=step,
                            line=target_line,
                            message=(
                                f"Step condition '{step.if_condition.strip()}' relies on 'github.actor' "
                                "matching a bot username. Use the immutable numeric user id instead."
                            ),
                            context={
                                "condition": step.if_condition.strip(),
                            },
                        )
                    )

        return findings
