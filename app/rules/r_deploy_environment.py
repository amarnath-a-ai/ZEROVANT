"""Rule R008: Detection of production/deployment jobs lacking environment protection rules."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class DeployEnvironmentRule(BaseRule):
    """Flags deployment workflows missing environment protection or manual approval gates."""

    id = "R008"
    name = "deploy_environment"
    description = "Deployment job executed without protected environment configuration or approvals"
    default_severity = Severity.MEDIUM
    tags = ["deployment", "environment-protection", "governance"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

