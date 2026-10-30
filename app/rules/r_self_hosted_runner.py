"""Rule R009: Detection of untrusted workflows executing on self-hosted runners."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class SelfHostedRunnerRule(BaseRule):
    """Flags untrusted triggers executing on self-hosted runners without isolation."""

    id = "R009"
    name = "self_hosted_runner"
    description = "Untrusted workflow trigger runs on persistent self-hosted runner infrastructure"
    default_severity = Severity.HIGH
    tags = ["runners", "persistence", "infrastructure-security"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

