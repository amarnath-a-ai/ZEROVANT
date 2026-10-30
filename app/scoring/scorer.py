"""Deterministic risk scoring engine."""

from dataclasses import dataclass

from app.correlation.chains import Chain
from app.rules.base import Finding
from app.scoring.weights import SEVERITY_WEIGHTS


@dataclass
class RiskReport:
    """Consolidated deterministic risk scoring evaluation."""

    total_score: float  # Normalized 0.0 - 100.0
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    finding_count: int
    chain_count: int


class RiskScorer:
    """Calculates deterministic risk scores based on findings, context triggers, and attack chains."""

    def score(self, findings: list[Finding], chains: list[Chain]) -> RiskReport:
        """Compute holistic risk score.

        (Detailed implementation in Phase 3)
        """
        raw_sum = sum(SEVERITY_WEIGHTS.get(f.severity.value, 1.0) for f in findings)
        normalized = min(100.0, raw_sum * 2.0)
        risk_level = "LOW"
        if normalized >= 75.0:
            risk_level = "CRITICAL"
        elif normalized >= 50.0:
            risk_level = "HIGH"
        elif normalized >= 25.0:
            risk_level = "MEDIUM"
        return RiskReport(
            total_score=normalized,
            risk_level=risk_level,
            finding_count=len(findings),
            chain_count=len(chains),
        )

