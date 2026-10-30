"""Rule R004: Detection of script injection vulnerabilities in shell run: commands."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class ScriptInjectionRule(BaseRule):
    """Flags direct interpolation of untrusted user context in run: commands."""

    id = "R004"
    name = "script_injection"
    description = "Shell command directly interpolates untrusted user expressions via ${{ ... }}"
    default_severity = Severity.CRITICAL
    tags = ["injection", "command-injection", "cwe-78"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

