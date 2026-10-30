"""Rule R001: Detection of actions pinned to mutable tags or branches instead of immutable SHAs."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class UnpinnedActionRule(BaseRule):
    """Flags actions not pinned to a full 40-character commit SHA."""

    id = "R001"
    name = "unpinned_action"
    description = "GitHub Action referenced by mutable ref (tag or branch) instead of immutable SHA"
    default_severity = Severity.HIGH
    tags = ["supply-chain", "actions", "integrity"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

