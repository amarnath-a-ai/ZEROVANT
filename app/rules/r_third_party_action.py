"""Rule R010: Detection of unvetted third-party actions outside verified organizations."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class ThirdPartyActionRule(BaseRule):
    """Flags actions from untrusted third-party organizations."""

    id = "R010"
    name = "third_party_action"
    description = "Step uses an unvetted third-party action from outside trusted organizations"
    default_severity = Severity.MEDIUM
    tags = ["supply-chain", "third-party", "provenance"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

