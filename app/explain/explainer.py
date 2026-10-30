"""Explainability coordinator dispatching to template engine or optional LLM."""

from app.explain.llm import LLMExplainer
from app.explain.templates import Explanation, TemplateExplainer
from app.rules.base import Finding


class RemediationExplainer:
    """Coordinates generating actionable explanations and YAML diff patches."""

    def __init__(self, anthropic_api_key: str | None = None):
        self.template_engine = TemplateExplainer()
        self.llm_engine = LLMExplainer(api_key=anthropic_api_key)

    def explain(self, finding: Finding, raw_workflow: str = "") -> Explanation:
        """Produce What, Why, How, and unified diff for a finding."""
        base_exp = self.template_engine.explain(finding)
        return self.llm_engine.enrich(finding, base_exp)

