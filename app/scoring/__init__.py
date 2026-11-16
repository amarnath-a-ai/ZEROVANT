"""Risk scoring package — Phase 4: Deterministic Risk Scoring Engine."""

from app.scoring.scorer import RiskReport, RiskScorer, ScoringResult, compute_scores
from app.scoring.weights import (
    CHAIN_MULTIPLIER_2,
    CHAIN_MULTIPLIER_3PLUS,
    REPO_DECAY_K,
    RULE_SEVERITIES,
    SEVERITY_WEIGHTS,
    TRIGGER_MULTIPLIERS,
)

__all__ = [
    # Dataclasses / result types
    "RiskReport",
    "RiskScorer",
    "ScoringResult",
    # Public API
    "compute_scores",
    # Weight constants
    "CHAIN_MULTIPLIER_2",
    "CHAIN_MULTIPLIER_3PLUS",
    "REPO_DECAY_K",
    "RULE_SEVERITIES",
    "SEVERITY_WEIGHTS",
    "TRIGGER_MULTIPLIERS",
]
