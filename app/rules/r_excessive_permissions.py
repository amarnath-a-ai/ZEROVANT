"""Rule R002: Detection of missing permissions block or excessive write permissions."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class ExcessivePermissionsRule(BaseRule):
    """Flags omitted permissions blocks or overly broad write permissions."""

    id = "R002"
    name = "excessive_permissions"
    description = "Workflow or job has omitted permissions (defaulting to write-all) or excessive explicit scopes"
    default_severity = Severity.HIGH
    tags = ["permissions", "least-privilege", "access-control"]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        """(Detailed rule evaluation implemented in Phase 2)"""
        return []

