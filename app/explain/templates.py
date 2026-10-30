"""Remediation templates and YAML patch diff generators."""

from dataclasses import dataclass
from typing import Any


@dataclass
class Explanation:
    """Explainable finding remediation guidance."""

    finding_id: str
    what: str
    why: str
    how: str
    fix_diff: str
    source: str = "template"  # 'template' or 'llm'


class TemplateExplainer:
    """Generates deterministic explanations and unified diffs based on static rule templates."""

    def explain(self, finding: Any) -> Explanation:
        """Generate structured explanation and remediation guidance.

        (Detailed implementation in Phase 4)
        """
        return Explanation(
            finding_id=getattr(finding, "id", "f-0000"),
            what=f"Security issue detected by rule {getattr(finding, 'rule_id', 'R000')}.",
            why="Unsafe configuration in CI/CD pipeline violates least-privilege principles.",
            how="Update the workflow YAML according to the remediation guidelines.",
            fix_diff="",
            source="template",
        )

