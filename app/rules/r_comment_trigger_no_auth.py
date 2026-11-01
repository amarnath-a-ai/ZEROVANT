"""Rule: Detection of comment-triggered workflows lacking author_association verification."""

import re

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

COMMENT_TRIGGERS = {"issue_comment", "pull_request_review_comment"}

AUTHOR_ASSOC_PATTERN = re.compile(
    r"author_association\s*(?:==|in|\!=)",
    re.IGNORECASE,
)


class CommentTriggerNoAuthRule(BaseRule):
    """Flags issue_comment or pull_request_review_comment workflows without author_association checks."""

    id = "comment-trigger-no-auth"
    name = "comment_trigger_no_auth"
    description = (
        "Workflow triggers on issue_comment or pull_request_review_comment without verifying "
        "github.event.comment.author_association (e.g. OWNER, MEMBER, COLLABORATOR), "
        "allowing external unauthenticated users to trigger automation and abuse repository permissions."
    )
    default_severity = Severity.HIGH
    category = "Access Control"
    tags = ["comment", "issue_comment", "access-control", "authorization"]
    references = [
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#potential-impact-of-a-compromised-runner",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        active_comment_triggers = [trig for trig in COMMENT_TRIGGERS if trig in workflow.triggers]
        if not active_comment_triggers:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            # Check if job-level or step-level conditions check author_association
            has_auth_check = False

            if job.if_condition and AUTHOR_ASSOC_PATTERN.search(job.if_condition):
                has_auth_check = True

            if not has_auth_check:
                for step in job.steps:
                    if step.if_condition and AUTHOR_ASSOC_PATTERN.search(step.if_condition):
                        has_auth_check = True
                        break
                    # Also check run command for author association inspection
                    if step.run and AUTHOR_ASSOC_PATTERN.search(step.run):
                        has_auth_check = True
                        break

            if not has_auth_check:
                trigger_name = active_comment_triggers[0]
                target_line = workflow.trigger_lines.get(trigger_name, job.line)
                findings.append(
                    self.build_finding(
                        workflow=workflow,
                        job=job,
                        line=target_line,
                        message=(
                            f"Workflow triggers on '{trigger_name}' but job '{job_id}' does not verify "
                            "the commenter's identity using 'github.event.comment.author_association'. "
                            "Any public GitHub user can trigger this workflow by commenting."
                        ),
                        context={
                            "trigger": trigger_name,
                            "job_id": job_id,
                        },
                    )
                )

        return findings
