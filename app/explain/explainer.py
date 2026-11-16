"""Explainability coordinator dispatching to template engine or optional LLM."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.correlation.chains import Chain
from app.explain.llm import LLMExplainer
from app.explain.templates import ChainExplanation, Explanation, TemplateExplainer
from app.parser.model import Workflow
from app.rules.base import Finding


@dataclass
class ScanExplanation:
    """Consolidated explanations for findings and attack chains across a scan."""

    findings: dict[str, Explanation] = field(default_factory=dict)
    """finding_id -> Explanation"""

    chains: dict[str, ChainExplanation] = field(default_factory=dict)
    """chain_id -> ChainExplanation"""

    def to_dict(self) -> dict[str, Any]:
        """Convert scan explanation to JSON-serializable dictionary."""
        return {
            "findings": {k: v.to_dict() for k, v in self.findings.items()},
            "chains": {k: v.to_dict() for k, v in self.chains.items()},
        }


class RemediationExplainer:
    """Coordinates generating actionable explanations, attack paths, and YAML diff patches."""

    def __init__(
        self,
        anthropic_api_key: str | None = None,
        model: str | None = None,
        llm_client: Any = None,
    ):
        self.template_engine = TemplateExplainer()
        kwargs: dict[str, Any] = {}
        if model:
            kwargs["model"] = model
        if llm_client is not None:
            kwargs["client"] = llm_client
        self.llm_engine = LLMExplainer(api_key=anthropic_api_key, **kwargs)

    def explain_finding(self, finding: Finding, raw_workflow: str = "") -> Explanation:
        """Produce What, Why, How, and unified diff for a single finding."""
        base_exp = self.template_engine.explain_finding(finding, raw_workflow=raw_workflow)
        return self.llm_engine.enrich(finding, base_exp)

    def explain(self, finding: Finding, raw_workflow: str = "") -> Explanation:
        """Alias for explain_finding() for backward compatibility."""
        return self.explain_finding(finding, raw_workflow=raw_workflow)

    def explain_chain(
        self,
        chain: Chain,
        findings_by_id: dict[str, Finding] | None = None,
    ) -> ChainExplanation:
        """Generate structured narrative, attack path, and break-the-chain remediation for a chain."""
        return self.template_engine.explain_chain(chain, findings_by_id=findings_by_id)

    def explain_all(
        self,
        findings: list[Finding],
        chains: list[Chain] | None = None,
        workflows: list[Workflow] | None = None,
    ) -> ScanExplanation:
        """Generate explanations for all findings and attack chains in a scan."""
        raw_by_file: dict[str, str] = {}
        if workflows:
            for wf in workflows:
                raw_by_file[wf.file_path] = getattr(wf, "raw_content", "")

        finding_exps: dict[str, Explanation] = {}
        findings_by_id: dict[str, Finding] = {}
        for f in findings:
            findings_by_id[f.id] = f
            raw = raw_by_file.get(f.file, "")
            finding_exps[f.id] = self.explain_finding(f, raw_workflow=raw)

        chain_exps: dict[str, ChainExplanation] = {}
        if chains:
            for c in chains:
                chain_exps[c.id] = self.explain_chain(c, findings_by_id=findings_by_id)

        return ScanExplanation(findings=finding_exps, chains=chain_exps)
