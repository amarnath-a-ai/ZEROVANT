"""Tests for Remediation Guidance and Explainer (Phase 4)."""

from app.explain.explainer import RemediationExplainer
from app.rules.base import Finding, Severity


def test_explainer_stub():
    """Verify explainer generates structured guidance."""
    explainer = RemediationExplainer()
    dummy_finding = Finding(
        id="f-0001",
        rule_id="R001",
        title="Unpinned Action",
        severity=Severity.HIGH,
        file="workflow.yml",
        line=10,
        evidence="uses: actions/checkout@v4",
    )
    exp = explainer.explain(dummy_finding)
    assert exp.finding_id == "f-0001"
    assert exp.what != ""
    assert exp.why != ""
    assert exp.how != ""

