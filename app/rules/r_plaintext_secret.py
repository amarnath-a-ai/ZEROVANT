"""Rule R005: Detection of hardcoded plaintext secrets, tokens, or credentials."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class PlaintextSecretRule(BaseRule):
    """Flags hardcoded credentials or API keys directly committed in workflow YAML."""

    id = "R005"
    name = "plaintext_secret"
    description = "Hardcoded static secret, credential, or API key found in plaintext"
    default_severity = Severity.HIGH
    tags = ["secrets", "credentials", "cwe-798"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

