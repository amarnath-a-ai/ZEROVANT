"""Tests for Risk Scoring Engine (Phase 3)."""

from app.rules.base import Finding, Severity
from app.scoring.scorer import RiskScorer


def test_scorer_calculation_stub():
    """Verify scorer computes normalized score on findings."""
    scorer = RiskScorer()
    dummy_finding = Finding(
        id="f-0001",
        rule_id="R001",
        title="Unpinned Action",
        severity=Severity.HIGH,
        file="workflow.yml",
        line=10,
        evidence="uses: actions/checkout@v4",
    )
    report = scorer.score([dummy_finding], [])
    assert report.finding_count == 1
    assert report.total_score > 0

