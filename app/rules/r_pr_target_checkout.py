"""Rule R003: Detection of pull_request_target checking out untrusted head commits."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class PrTargetCheckoutRule(BaseRule):
    """Flags pull_request_target checking out PR head ref."""

    id = "R003"
    name = "pr_target_checkout"
    description = "Workflow triggered by pull_request_target checks out untrusted PR head commit"
    default_severity = Severity.CRITICAL
    tags = ["pwn-request", "code-execution", "pull-request"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

