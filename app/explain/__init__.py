"""Explainability and remediation module."""

from app.explain.explainer import RemediationExplainer, ScanExplanation
from app.explain.fixes import apply_mechanical_fix, generate_fix_diff
from app.explain.llm import LLMExplainer
from app.explain.templates import ChainExplanation, Explanation, TemplateExplainer

__all__ = [
    "ChainExplanation",
    "Explanation",
    "LLMExplainer",
    "RemediationExplainer",
    "ScanExplanation",
    "TemplateExplainer",
    "apply_mechanical_fix",
    "generate_fix_diff",
]

