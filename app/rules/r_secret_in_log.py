"""Rule R006: Detection of secret exposure or printing in build/workflow logs."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class SecretInLogRule(BaseRule):
    """Flags direct echo or print commands that may expose secrets in build logs."""

    id = "R006"
    name = "secret_in_log"
    description = "Step echoes, prints, or exposes sensitive secrets into execution logs"
    default_severity = Severity.MEDIUM
    tags = ["secrets", "information-disclosure", "logging"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

