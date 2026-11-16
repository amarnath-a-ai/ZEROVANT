"""Deterministic risk scoring engine — Phase 4.

Public API
----------
score_finding(finding, triggers)   → float  [0–10]
score_chain(chain, finding_scores) → float  [0–10]
score_repository(chains, standalone_findings, chain_scores, finding_scores)
                                   → float  [0–100]
compute_scores(findings, chains, workflows) → ScoringResult

All functions are pure and deterministic: identical inputs always produce
identical outputs.  No AI, no randomness, no external state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.correlation.chains import Chain
from app.parser.model import Workflow
from app.rules.base import Finding, Severity
from app.scoring.weights import (
    CHAIN_MULTIPLIER_2,
    CHAIN_MULTIPLIER_3PLUS,
    DEFAULT_TRIGGER_MULTIPLIER,
    REPO_DECAY_K,
    SEVERITY_WEIGHTS,
    TRIGGER_MULTIPLIERS,
)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ScoringResult:
    """Complete deterministic scoring output for a scan."""

    finding_scores: dict[str, float] = field(default_factory=dict)
    """finding_id → score in [0, 10]"""

    chain_scores: dict[str, float] = field(default_factory=dict)
    """chain_id → score in [0, 10]"""

    repo_score: float = 0.0
    """Repository-level risk score in [0, 100]"""

    severity_distribution: dict[str, int] = field(default_factory=dict)
    """Count of findings per severity level"""

    breakdown: list[dict[str, Any]] = field(default_factory=list)
    """Transparent per-item scoring detail for CLI/dashboard output"""


# Legacy dataclass kept for backwards-compatibility with the stub test.
@dataclass
class RiskReport:
    """Consolidated deterministic risk scoring evaluation (legacy interface)."""

    total_score: float  # Normalised 0.0–100.0
    risk_level: str  # CRITICAL / HIGH / MEDIUM / LOW
    finding_count: int
    chain_count: int


# ---------------------------------------------------------------------------
# Core scoring functions
# ---------------------------------------------------------------------------


def _get_trigger_multiplier(triggers: dict[str, Any]) -> float:
    """Return the maximum exploitability multiplier for a set of workflow triggers.

    Args:
        triggers: The ``Workflow.triggers`` dict (keys are trigger event names).

    Returns:
        Highest multiplier found; falls back to ``DEFAULT_TRIGGER_MULTIPLIER``
        when ``triggers`` is empty or contains only unknown trigger names.
    """
    if not triggers:
        return DEFAULT_TRIGGER_MULTIPLIER
    multipliers = [TRIGGER_MULTIPLIERS.get(t, DEFAULT_TRIGGER_MULTIPLIER) for t in triggers]
    return max(multipliers)


def score_finding(finding: Finding, triggers: dict[str, Any]) -> float:
    """Compute a deterministic risk score for a single finding.

    Formula::

        finding_score = min(10.0, severity_weight × exploitability_multiplier)

    The exploitability multiplier is the *maximum* multiplier across all
    workflow triggers.

    Args:
        finding: The security finding to score.
        triggers: The containing workflow's trigger dict (``Workflow.triggers``).

    Returns:
        A float in [0.0, 10.0].
    """
    weight = SEVERITY_WEIGHTS.get(finding.severity.value, 4.0)
    multiplier = _get_trigger_multiplier(triggers)
    return min(10.0, weight * multiplier)


def score_chain(chain: Chain, finding_scores: dict[str, float]) -> float:
    """Compute a deterministic risk score for an attack chain.

    Formula::

        multiplier  = 1.3 if N==2 else 1.5     (N = number of members)
        max_score   = max(member scores)
        rest        = sum(all other member scores)
        chain_score = min(10.0, max_score × multiplier + 0.25 × rest)

    Args:
        chain: The correlated attack chain.
        finding_scores: Mapping of finding_id → pre-computed finding score.
            Members missing from the mapping are assigned score 0.

    Returns:
        A float in [0.0, 10.0].
    """
    member_scores = [finding_scores.get(fid, 0.0) for fid in chain.finding_ids]
    if not member_scores:
        return 0.0

    n = len(member_scores)
    multiplier = CHAIN_MULTIPLIER_2 if n == 2 else CHAIN_MULTIPLIER_3PLUS
    sorted_scores = sorted(member_scores, reverse=True)
    max_score = sorted_scores[0]
    rest = sum(sorted_scores[1:])
    return min(10.0, max_score * multiplier + 0.25 * rest)


def score_repository(
    chains: list[Chain],
    standalone_findings: list[Finding],
    chain_scores: dict[str, float],
    finding_scores: dict[str, float],
) -> float:
    """Compute a repository-level risk score using the decay-product formula.

    Formula::

        repo_score = 100 × (1 − ∏ᵢ (1 − sᵢ/10 × k))

    Score items are:
    - One score per chain (the chain's overall score).
    - One score per standalone finding (findings NOT in any chain).
    Items are sorted descending before the product so that high-risk items
    dominate.  Findings already counted inside a chain are excluded to prevent
    double-counting.

    Args:
        chains: All detected attack chains.
        standalone_findings: Findings that do not belong to any chain.
        chain_scores: Mapping of chain_id → chain score.
        finding_scores: Mapping of finding_id → finding score.

    Returns:
        A float in [0.0, 100.0].
    """
    score_items: list[float] = []

    # Chain scores
    for c in chains:
        score_items.append(chain_scores.get(c.id, 0.0))

    # Standalone finding scores (never in a chain)
    for f in standalone_findings:
        score_items.append(finding_scores.get(f.id, 0.0))

    if not score_items:
        return 0.0

    # Sort descending so high-risk items dominate the product
    score_items.sort(reverse=True)

    k = REPO_DECAY_K
    product = 1.0
    for s in score_items:
        product *= 1.0 - (s / 10.0) * k

    return round(100.0 * (1.0 - product), 6)


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------


def compute_scores(
    findings: list[Finding],
    chains: list[Chain],
    workflows: list[Workflow],
) -> ScoringResult:
    """Master scoring function: score findings, chains, and the whole repository.

    Side effects
    ------------
    Mutates ``finding.base_score`` and ``chain.chain_score`` in-place so that
    downstream code (Flask API, CLI) can read scores directly from the objects
    without calling this function a second time.

    Args:
        findings: All security findings from the rule engine.
        chains: All correlated attack chains.
        workflows: Parsed workflow objects (used to look up trigger dicts).

    Returns:
        A :class:`ScoringResult` with per-finding scores, per-chain scores,
        repo score, severity distribution, and a transparent breakdown list.
    """
    # Build a file_path → triggers mapping for fast lookup
    triggers_by_file: dict[str, dict[str, Any]] = {
        wf.file_path: wf.triggers for wf in workflows
    }

    # --- Finding scores ---
    finding_scores: dict[str, float] = {}
    severity_distribution: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    }

    for f in findings:
        triggers = triggers_by_file.get(f.file, {})
        fs = score_finding(f, triggers)
        finding_scores[f.id] = fs
        f.base_score = fs  # mutate in-place

        sev_key = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
        severity_distribution[sev_key] = severity_distribution.get(sev_key, 0) + 1

    # --- Chain scores ---
    chain_scores: dict[str, float] = {}
    chained_finding_ids: set[str] = set()

    for c in chains:
        cs = score_chain(c, finding_scores)
        chain_scores[c.id] = cs
        c.chain_score = cs  # mutate in-place
        chained_finding_ids.update(c.finding_ids)

    # --- Standalone findings (not in any chain) ---
    standalone_findings = [f for f in findings if f.id not in chained_finding_ids]

    # --- Repository score ---
    repo_score = score_repository(chains, standalone_findings, chain_scores, finding_scores)

    # --- Transparent breakdown ---
    breakdown: list[dict[str, Any]] = []
    for f in findings:
        breakdown.append({
            "type": "finding",
            "id": f.id,
            "rule_id": f.rule_id,
            "severity": f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
            "score": finding_scores[f.id],
            "in_chain": f.id in chained_finding_ids,
        })
    for c in chains:
        breakdown.append({
            "type": "chain",
            "id": c.id,
            "chain_type": c.chain_type.value if hasattr(c.chain_type, "value") else str(c.chain_type),
            "members": len(c.finding_ids),
            "score": chain_scores[c.id],
        })

    return ScoringResult(
        finding_scores=finding_scores,
        chain_scores=chain_scores,
        repo_score=repo_score,
        severity_distribution=severity_distribution,
        breakdown=breakdown,
    )


# ---------------------------------------------------------------------------
# Legacy interface (keep old RiskScorer so test_scorer_calculation_stub passes)
# ---------------------------------------------------------------------------


class RiskScorer:
    """Legacy scoring facade.  New code should call :func:`compute_scores`."""

    def score(self, findings: list[Finding], chains: list[Chain]) -> RiskReport:
        """Compute a holistic risk report using the Phase-4 deterministic engine.

        Triggers default to an empty dict (multiplier = 1.0) when no workflow
        objects are available, which is the case for the stub test.
        """
        result = compute_scores(findings, chains, workflows=[])
        score = result.repo_score
        if score >= 75.0:
            risk_level = "CRITICAL"
        elif score >= 50.0:
            risk_level = "HIGH"
        elif score >= 25.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        return RiskReport(
            total_score=score,
            risk_level=risk_level,
            finding_count=len(findings),
            chain_count=len(chains),
        )
