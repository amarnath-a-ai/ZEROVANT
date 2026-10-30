"""Rule R007: Detection of static long-lived cloud credentials instead of OIDC."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class LongLivedCredentialsRule(BaseRule):
    """Flags use of static credentials (AWS_ACCESS_KEY_ID, static tokens) instead of OIDC."""

    id = "R007"
    name = "long_lived_credentials"
    description = "Static long-lived cloud credentials used instead of OpenID Connect (OIDC) federation"
    default_severity = Severity.MEDIUM
    tags = ["credentials", "oidc", "cloud-security"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

