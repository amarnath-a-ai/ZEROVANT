"""Comprehensive tests for Phase-4 Deterministic Risk Scoring Engine.

Every numerical assertion has its hand-calculation shown in a comment so
that an examiner can verify correctness without running the code.

Notation used in comments
--------------------------
  SW  = severity_weight
  M   = trigger multiplier (max across triggers)
  CM  = chain multiplier (1.3 for N=2, 1.5 for N>=3)
  k   = repo decay factor (0.9)
  fs  = finding_score = min(10, SW * M)
  cs  = chain_score   = min(10, max(member_scores)*CM + 0.25*sum(rest))
  rs  = repo_score    = 100 * (1 - product_i(1 - s_i/10 * k))
"""

from app.correlation.chains import Chain, ChainType
from app.parser.model import Workflow
from app.rules.base import Finding, Severity
from app.scoring.scorer import (
    RiskReport,
    RiskScorer,
    ScoringResult,
    compute_scores,
    score_chain,
    score_finding,
    score_repository,
)
from app.scoring.weights import (
    CHAIN_MULTIPLIER_2,
    CHAIN_MULTIPLIER_3PLUS,
    SEVERITY_WEIGHTS,
    TRIGGER_MULTIPLIERS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    fid: str = "f-0001",
    rule_id: str = "R001",
    severity: Severity = Severity.HIGH,
    file: str = "workflow.yml",
) -> Finding:
    return Finding(
        id=fid,
        rule_id=rule_id,
        title="Test Finding",
        severity=severity,
        file=file,
        line=1,
        evidence="test",
    )


def _make_workflow(triggers: dict | None = None, file_path: str = "workflow.yml") -> Workflow:
    return Workflow(name="test", file_path=file_path, triggers=triggers or {})


def _make_chain(
    cid: str,
    finding_ids: list[str],
    chain_type: ChainType = ChainType.PWN_REQUEST,
) -> Chain:
    return Chain(id=cid, chain_type=chain_type, finding_ids=finding_ids)


# ===========================================================================
# 1. Weight table sanity
# ===========================================================================


def test_severity_weight_table():
    """All five severity weights exactly match the spec.

    Hand-calc: direct table read.
    """
    assert SEVERITY_WEIGHTS["CRITICAL"] == 9.0
    assert SEVERITY_WEIGHTS["HIGH"] == 7.0
    assert SEVERITY_WEIGHTS["MEDIUM"] == 4.0
    assert SEVERITY_WEIGHTS["LOW"] == 2.0
    assert SEVERITY_WEIGHTS["INFO"] == 0.5


def test_trigger_multiplier_table_high_risk():
    """High-risk triggers map to 1.3."""
    high_risk = [
        "pull_request_target",
        "issue_comment",
        "workflow_run",
        "issues",
        "pull_request_review_comment",
        "discussion",
        "discussion_comment",
    ]
    for t in high_risk:
        assert TRIGGER_MULTIPLIERS[t] == 1.3, f"Expected 1.3 for {t}"


def test_trigger_multiplier_table_low_risk():
    """Low-risk gated triggers map to 0.8."""
    assert TRIGGER_MULTIPLIERS["workflow_dispatch"] == 0.8
    assert TRIGGER_MULTIPLIERS["workflow_call"] == 0.8


def test_trigger_multiplier_table_neutral():
    """Neutral triggers map to 1.0."""
    for t in ("push", "pull_request", "schedule"):
        assert TRIGGER_MULTIPLIERS[t] == 1.0, f"Expected 1.0 for {t}"


def test_chain_multipliers_values():
    """Chain multipliers are 1.3 (N=2) and 1.5 (N≥3) per spec."""
    assert CHAIN_MULTIPLIER_2 == 1.3
    assert CHAIN_MULTIPLIER_3PLUS == 1.5


# ===========================================================================
# 2. score_finding — individual finding scores
# ===========================================================================


def test_finding_score_critical_no_trigger():
    """CRITICAL with empty triggers → multiplier 1.0 (default).

    Hand-calc:  SW=9.0, M=1.0  →  fs = min(10, 9.0*1.0) = 9.0
    """
    f = _make_finding(severity=Severity.CRITICAL)
    assert score_finding(f, {}) == 9.0


def test_finding_score_high_no_trigger():
    """HIGH, no triggers → fs = 7.0.

    Hand-calc:  SW=7.0, M=1.0  →  min(10, 7.0) = 7.0
    """
    f = _make_finding(severity=Severity.HIGH)
    assert score_finding(f, {}) == 7.0


def test_finding_score_medium_no_trigger():
    """MEDIUM, no triggers → fs = 4.0.

    Hand-calc:  SW=4.0, M=1.0  →  min(10, 4.0) = 4.0
    """
    f = _make_finding(severity=Severity.MEDIUM)
    assert score_finding(f, {}) == 4.0


def test_finding_score_low_no_trigger():
    """LOW, no triggers → fs = 2.0.

    Hand-calc:  SW=2.0, M=1.0  →  min(10, 2.0) = 2.0
    """
    f = _make_finding(severity=Severity.LOW)
    assert score_finding(f, {}) == 2.0


def test_finding_score_info_no_trigger():
    """INFO, no triggers → fs = 0.5.

    Hand-calc:  SW=0.5, M=1.0  →  min(10, 0.5) = 0.5
    """
    f = _make_finding(severity=Severity.INFO)
    assert score_finding(f, {}) == 0.5


def test_finding_score_cap_at_10():
    """CRITICAL × pull_request_target must cap at 10.0.

    Hand-calc:  SW=9.0, M=1.3  →  9.0*1.3 = 11.7  →  min(10, 11.7) = 10.0
    """
    f = _make_finding(severity=Severity.CRITICAL)
    fs = score_finding(f, {"pull_request_target": None})
    assert fs == 10.0


def test_finding_score_high_prt():
    """HIGH × pull_request_target.

    Hand-calc:  SW=7.0, M=1.3  →  7.0*1.3 = 9.1  →  min(10, 9.1) = 9.1
    """
    f = _make_finding(severity=Severity.HIGH)
    fs = score_finding(f, {"pull_request_target": None})
    assert abs(fs - 9.1) < 1e-9


def test_finding_score_medium_issue_comment():
    """MEDIUM × issue_comment.

    Hand-calc:  SW=4.0, M=1.3  →  4.0*1.3 = 5.2
    """
    f = _make_finding(severity=Severity.MEDIUM)
    fs = score_finding(f, {"issue_comment": None})
    assert abs(fs - 5.2) < 1e-9


def test_finding_score_high_workflow_dispatch():
    """HIGH × workflow_dispatch uses the 0.8 multiplier.

    Hand-calc:  SW=7.0, M=0.8  →  7.0*0.8 = 5.6
    """
    f = _make_finding(severity=Severity.HIGH)
    fs = score_finding(f, {"workflow_dispatch": None})
    assert abs(fs - 5.6) < 1e-9


def test_multi_trigger_takes_max():
    """When triggers include push (1.0) AND pull_request_target (1.3), take max=1.3.

    Hand-calc:  SW=7.0, M=max(1.0,1.3)=1.3  →  7.0*1.3 = 9.1
    """
    f = _make_finding(severity=Severity.HIGH)
    triggers = {"push": None, "pull_request_target": None}
    fs = score_finding(f, triggers)
    assert abs(fs - 9.1) < 1e-9


def test_unknown_trigger_defaults_1_0():
    """An unrecognised trigger name falls back to multiplier 1.0.

    Hand-calc:  SW=4.0, M=1.0  →  4.0
    """
    f = _make_finding(severity=Severity.MEDIUM)
    fs = score_finding(f, {"my_custom_event": None})
    assert fs == 4.0


def test_low_rule_cap_dispatch_input_injection():
    """LOW (dispatch-input-injection) × workflow_dispatch stays well below severity cap.

    Hand-calc:  SW=2.0, M=0.8  →  2.0*0.8 = 1.6
    """
    f = _make_finding(severity=Severity.LOW, rule_id="dispatch-input-injection")
    fs = score_finding(f, {"workflow_dispatch": None})
    assert abs(fs - 1.6) < 1e-9
    assert fs < 2.5  # well under any high-severity threshold


def test_low_rule_missing_timeout():
    """LOW (missing-timeout) × push stays low.

    Hand-calc:  SW=2.0, M=1.0  →  2.0
    """
    f = _make_finding(severity=Severity.LOW, rule_id="missing-timeout")
    fs = score_finding(f, {"push": None})
    assert fs == 2.0


# ===========================================================================
# 3. score_chain — attack chain scores
# ===========================================================================


def test_chain_score_2_members_caps():
    """2-member chain with CRITICAL+HIGH both on pull_request_target → capped.

    Finding scores:
      f1 (CRITICAL, prt): min(10, 9*1.3)=10.0
      f2 (HIGH, prt):     min(10, 7*1.3)=9.1
    Chain (N=2, CM=1.3):
      max=10.0, rest=9.1
      raw = 10.0*1.3 + 0.25*9.1 = 13.0 + 2.275 = 15.275
      cs  = min(10, 15.275) = 10.0
    """
    _make_finding("f1", severity=Severity.CRITICAL)
    _make_finding("f2", severity=Severity.HIGH)
    scores = {"f1": 10.0, "f2": 9.1}
    c = _make_chain("c1", ["f1", "f2"])
    cs = score_chain(c, scores)
    assert cs == 10.0


def test_chain_score_2_members_no_cap():
    """2-member chain with small scores: no cap.

    Finding scores: f1=3.2, f2=2.0
    Hand-calc (N=2, CM=1.3):
      max=3.2, rest=2.0
      raw = 3.2*1.3 + 0.25*2.0 = 4.16 + 0.5 = 4.66
      cs  = min(10, 4.66) = 4.66
    """
    scores = {"f1": 3.2, "f2": 2.0}
    c = _make_chain("c1", ["f1", "f2"])
    cs = score_chain(c, scores)
    assert abs(cs - 4.66) < 1e-9


def test_chain_score_3plus_members():
    """3-member chain: multiplier = 1.5.

    Finding scores: f1=7.0, f2=5.6, f3=4.0
    Hand-calc (N=3, CM=1.5):
      max=7.0, rest=5.6+4.0=9.6
      raw = 7.0*1.5 + 0.25*9.6 = 10.5 + 2.4 = 12.9
      cs  = min(10, 12.9) = 10.0
    """
    scores = {"f1": 7.0, "f2": 5.6, "f3": 4.0}
    c = _make_chain("c1", ["f1", "f2", "f3"])
    cs = score_chain(c, scores)
    assert cs == 10.0


def test_chain_score_3plus_members_no_cap():
    """3-member chain with small scores, no cap.

    Finding scores: f1=2.0, f2=1.6, f3=0.5
    Hand-calc (N=3, CM=1.5):
      max=2.0, rest=1.6+0.5=2.1
      raw = 2.0*1.5 + 0.25*2.1 = 3.0 + 0.525 = 3.525
      cs  = min(10, 3.525) = 3.525
    """
    scores = {"f1": 2.0, "f2": 1.6, "f3": 0.5}
    c = _make_chain("c1", ["f1", "f2", "f3"])
    cs = score_chain(c, scores)
    assert abs(cs - 3.525) < 1e-9


def test_chain_score_empty_chain():
    """An empty chain has score 0.0."""
    c = _make_chain("c1", [])
    cs = score_chain(c, {})
    assert cs == 0.0


def test_chain_score_missing_finding_treated_as_zero():
    """Finding IDs absent from the scores dict contribute 0.

    Finding scores: only f1=5.0 provided; f2 missing.
    Hand-calc (N=2, CM=1.3):
      member_scores=[5.0, 0.0]  →  max=5.0, rest=0.0
      raw = 5.0*1.3 + 0.25*0.0 = 6.5
      cs  = min(10, 6.5) = 6.5
    """
    c = _make_chain("c1", ["f1", "f2"])
    cs = score_chain(c, {"f1": 5.0})
    assert abs(cs - 6.5) < 1e-9


def test_chain_score_single_member():
    """Single-member chain uses 1.5 multiplier (N>=3 path falls through; N==1 → still 1.5).

    Wait — spec says multiplier based on count: 2→1.3, 3+→1.5.
    N=1 is a degenerate chain; use 1.5 (the 3+ branch) as the safe default.
    Hand-calc: max=5.0, rest=0, raw=5.0*1.5=7.5  →  cs=7.5
    """
    c = _make_chain("c1", ["f1"])
    cs = score_chain(c, {"f1": 5.0})
    # N=1 → neither 2 nor 3+; implementation uses CHAIN_MULTIPLIER_3PLUS as default
    assert abs(cs - 7.5) < 1e-9


# ===========================================================================
# 4. score_repository
# ===========================================================================


def test_repo_score_empty():
    """Example A: empty repository → 0.0.

    Hand-calc: empty product=1 → 100*(1-1) = 0.0
    """
    rs = score_repository([], [], {}, {})
    assert rs == 0.0


def test_repo_score_single_low_finding():
    """Single LOW finding, push trigger.

    fs = 2.0 (from LOW, push)
    Hand-calc:
      product = (1 - 2.0/10 * 0.9) = (1 - 0.18) = 0.82
      rs = 100 * (1 - 0.82) = 18.0
    """
    f = _make_finding("f1", severity=Severity.LOW)
    rs = score_repository([], [f], {}, {"f1": 2.0})
    assert abs(rs - 18.0) < 1e-6


def test_repo_score_single_critical():
    """Example B: single CRITICAL finding, push trigger.

    fs = 9.0 (CRITICAL, push: 9*1.0=9.0)
    Hand-calc:
      product = (1 - 9.0/10 * 0.9) = (1 - 0.81) = 0.19
      rs = 100 * (1 - 0.19) = 81.0
    """
    f = _make_finding("f1", severity=Severity.CRITICAL)
    rs = score_repository([], [f], {}, {"f1": 9.0})
    assert abs(rs - 81.0) < 1e-6


def test_repo_score_many_lows_vs_one_critical():
    """Example C: five LOW findings should be less than one CRITICAL.

    Five LOW findings, each fs=2.0:
      product_per = (1 - 0.18) = 0.82
      product     = 0.82^5 ≈ 0.370726
      rs          = 100*(1-0.370726) ≈ 62.927...
    One CRITICAL (fs=9.0) → 81.0  (from test above)
    Assert many-lows < one-critical (diminishing returns confirmed).
    """
    findings_5low = [_make_finding(f"f{i}", severity=Severity.LOW) for i in range(5)]
    scores = {f"f{i}": 2.0 for i in range(5)}
    rs_many_low = score_repository([], findings_5low, {}, scores)
    rs_one_crit = score_repository([], [_make_finding("fx", severity=Severity.CRITICAL)], {}, {"fx": 9.0})
    # 62.9x < 81.0
    assert rs_many_low < rs_one_crit
    # Exact value check
    expected = 100.0 * (1.0 - 0.82**5)
    assert abs(rs_many_low - expected) < 1e-4


def test_chain_vs_standalone_no_double_count():
    """Example D: findings in a chain are NOT added again as standalone.

    Chain C1: f1 (CRITICAL, push→fs=9.0), f2 (HIGH, push→fs=7.0)
    Chain score (N=2, CM=1.3):
      raw = 9.0*1.3 + 0.25*7.0 = 11.7 + 1.75 = 13.45  →  cs=10.0
    repo_score with chain only:
      product = (1 - 10.0/10 * 0.9) = (1-0.9) = 0.1
      rs = 100*(1-0.1) = 90.0

    If we incorrectly double-counted f1 and f2 too:
      items=[10.0, 9.0, 7.0]
      product=(0.1)(1-0.81)(1-0.63)=0.1*0.19*0.37=0.00703
      rs≈99.3  (inflated — wrong)
    """
    _make_finding("f1", severity=Severity.CRITICAL)
    _make_finding("f2", severity=Severity.HIGH)
    c = _make_chain("c1", ["f1", "f2"])
    finding_scores = {"f1": 9.0, "f2": 7.0}
    chain_scores = {"c1": 10.0}
    # standalone_findings must be empty: f1, f2 are chained
    rs = score_repository([c], [], chain_scores, finding_scores)
    assert abs(rs - 90.0) < 1e-6


def test_repo_score_chain_plus_standalone():
    """Chain (score=10.0) + one standalone LOW (fs=2.0).

    Hand-calc (sorted desc: [10.0, 2.0]):
      p1 = (1 - 10.0/10 * 0.9) = 0.1
      p2 = (1 - 2.0/10 * 0.9)  = 0.82
      product = 0.1 * 0.82 = 0.082
      rs = 100*(1-0.082) = 91.8
    """
    f_standalone = _make_finding("f_s", severity=Severity.LOW)
    c = _make_chain("c1", ["f1", "f2"])
    rs = score_repository([c], [f_standalone], {"c1": 10.0}, {"f_s": 2.0})
    assert abs(rs - 91.8) < 1e-6


# ===========================================================================
# 5. compute_scores (integration)
# ===========================================================================


def test_compute_scores_empty():
    """compute_scores on empty input → ScoringResult with all zeros."""
    result = compute_scores([], [], [])
    assert isinstance(result, ScoringResult)
    assert result.repo_score == 0.0
    assert result.finding_scores == {}
    assert result.chain_scores == {}


def test_compute_scores_single_finding_no_workflow():
    """Single HIGH finding with no workflow (triggers={}) → multiplier=1.0.

    Hand-calc:  fs=7.0, rs=100*(1-(1-0.63))=63.0
    """
    f = _make_finding("f1", severity=Severity.HIGH)
    result = compute_scores([f], [], [])
    assert abs(result.finding_scores["f1"] - 7.0) < 1e-9
    # product = (1 - 7.0/10*0.9) = (1-0.63) = 0.37
    expected_rs = 100.0 * (1.0 - 0.37)
    assert abs(result.repo_score - expected_rs) < 1e-6


def test_compute_scores_mutates_base_score():
    """compute_scores sets finding.base_score in-place."""
    f = _make_finding("f1", severity=Severity.MEDIUM)
    compute_scores([f], [], [])
    # MEDIUM no trigger → 4.0
    assert abs(f.base_score - 4.0) < 1e-9


def test_compute_scores_mutates_chain_score():
    """compute_scores sets chain.chain_score in-place."""
    f1 = _make_finding("f1", severity=Severity.HIGH)
    f2 = _make_finding("f2", severity=Severity.MEDIUM)
    c = _make_chain("c1", ["f1", "f2"])
    compute_scores([f1, f2], [c], [])
    # fs(f1)=7.0, fs(f2)=4.0, N=2 CM=1.3
    # raw=7.0*1.3+0.25*4.0=9.1+1.0=10.1  →  cs=10.0
    assert c.chain_score == 10.0


def test_compute_scores_severity_distribution():
    """Severity distribution is counted correctly."""
    findings = [
        _make_finding("f1", severity=Severity.CRITICAL),
        _make_finding("f2", severity=Severity.HIGH),
        _make_finding("f3", severity=Severity.HIGH),
        _make_finding("f4", severity=Severity.LOW),
    ]
    result = compute_scores(findings, [], [])
    assert result.severity_distribution["CRITICAL"] == 1
    assert result.severity_distribution["HIGH"] == 2
    assert result.severity_distribution["LOW"] == 1
    assert result.severity_distribution["MEDIUM"] == 0


def test_compute_scores_uses_workflow_triggers():
    """Trigger from matching Workflow object is applied to findings.

    Workflow triggers = {pull_request_target: ...}
    HIGH finding → SW=7.0, M=1.3 → fs=9.1
    """
    f = _make_finding("f1", severity=Severity.HIGH, file="wf.yml")
    wf = _make_workflow(triggers={"pull_request_target": None}, file_path="wf.yml")
    result = compute_scores([f], [], [wf])
    assert abs(result.finding_scores["f1"] - 9.1) < 1e-9


def test_compute_scores_no_double_count_in_repo_score():
    """Findings inside a chain must NOT also appear as standalones."""
    f1 = _make_finding("f1", severity=Severity.CRITICAL)
    f2 = _make_finding("f2", severity=Severity.HIGH)
    c = _make_chain("c1", ["f1", "f2"])
    result = compute_scores([f1, f2], [c], [])
    # Standalone list should be empty → only chain contributes
    # chain_score: fs(f1)=9.0, fs(f2)=7.0, N=2 CM=1.3
    #   raw=9.0*1.3+0.25*7.0=11.7+1.75=13.45  →  cs=10.0
    # repo: product=(1-0.9)=0.1  →  rs=90.0
    assert abs(result.repo_score - 90.0) < 1e-6


def test_monotonicity():
    """Adding a finding never lowers the repository score."""
    f1 = _make_finding("f1", severity=Severity.HIGH)
    result1 = compute_scores([f1], [], [])
    f2 = _make_finding("f2", severity=Severity.LOW)
    result2 = compute_scores([f1, f2], [], [])
    assert result2.repo_score >= result1.repo_score


def test_determinism():
    """Same input twice → identical output."""
    findings = [
        _make_finding("f1", severity=Severity.CRITICAL),
        _make_finding("f2", severity=Severity.MEDIUM),
    ]
    r1 = compute_scores(list(findings), [], [])
    r2 = compute_scores(list(findings), [], [])
    assert r1.repo_score == r2.repo_score
    assert r1.finding_scores == r2.finding_scores


def test_breakdown_contains_all_items():
    """breakdown list includes one entry per finding and one per chain."""
    f1 = _make_finding("f1")
    f2 = _make_finding("f2")
    c = _make_chain("c1", ["f1", "f2"])
    result = compute_scores([f1, f2], [c], [])
    types = [item["type"] for item in result.breakdown]
    assert types.count("finding") == 2
    assert types.count("chain") == 1


def test_breakdown_in_chain_flag():
    """Findings in a chain are marked in_chain=True in breakdown."""
    f1 = _make_finding("f1")
    f2 = _make_finding("f2")
    c = _make_chain("c1", ["f1"])
    result = compute_scores([f1, f2], [c], [])
    items = {i["id"]: i for i in result.breakdown if i["type"] == "finding"}
    assert items["f1"]["in_chain"] is True
    assert items["f2"]["in_chain"] is False


# ===========================================================================
# 6. docs/scoring.md examples (regression anchors)
# ===========================================================================


def test_docs_example_A_empty_repo():
    """docs/scoring.md Example A: empty → 0.0."""
    rs = score_repository([], [], {}, {})
    assert rs == 0.0


def test_docs_example_B_single_critical():
    """docs/scoring.md Example B: single CRITICAL (push) → 81.0.

    fs=9.0, product=(1-0.81)=0.19, rs=100*(1-0.19)=81.0
    """
    f = _make_finding("f1", severity=Severity.CRITICAL)
    rs = score_repository([], [f], {}, {"f1": 9.0})
    assert abs(rs - 81.0) < 1e-6


def test_docs_example_C_diminishing_returns():
    """docs/scoring.md Example C: 5 LOWs < 1 CRITICAL (diminishing returns)."""
    # Five LOWs
    low_findings = [_make_finding(f"l{i}", severity=Severity.LOW) for i in range(5)]
    low_scores = {f"l{i}": 2.0 for i in range(5)}
    rs_low = score_repository([], low_findings, {}, low_scores)
    # One CRITICAL
    crit_f = _make_finding("c0", severity=Severity.CRITICAL)
    rs_crit = score_repository([], [crit_f], {}, {"c0": 9.0})
    assert rs_low < rs_crit


def test_docs_example_D_no_double_count():
    """docs/scoring.md Example D: chain replaces member findings in repo score."""
    _make_finding("f1", severity=Severity.CRITICAL)
    _make_finding("f2", severity=Severity.HIGH)
    c = _make_chain("c1", ["f1", "f2"])
    # Only chain contributes (rs=90.0 per docs)
    rs = score_repository([c], [], {"c1": 10.0}, {"f1": 9.0, "f2": 7.0})
    assert abs(rs - 90.0) < 1e-6


# ===========================================================================
# 7. Mixed scenario — 2 chains + extra standalone findings
# ===========================================================================


def test_mixed_2_chains_plus_standalone():
    """Two chains + two standalone findings, hand-calculated.

    Chains:
      C1 (N=2): members f1=10.0, f2=9.1  →  cs1=10.0
      C2 (N=3): members f3=7.0, f4=5.6, f5=4.0  →  raw=10.5+2.4=12.9  →  cs2=10.0

    Standalone: f6=4.0, f7=2.0

    score_items (sorted desc): [10.0, 10.0, 4.0, 2.0]
    p1 = 1 - (10/10)*0.9 = 0.1
    p2 = 1 - (10/10)*0.9 = 0.1
    p3 = 1 - (4/10)*0.9  = 0.64
    p4 = 1 - (2/10)*0.9  = 0.82
    product = 0.1 * 0.1 * 0.64 * 0.82 = 0.005248
    rs = 100*(1-0.005248) = 99.4752
    """
    finding_scores = {
        "f1": 10.0, "f2": 9.1, "f3": 7.0, "f4": 5.6, "f5": 4.0,
        "f6": 4.0, "f7": 2.0,
    }
    c1 = _make_chain("c1", ["f1", "f2"])
    c2 = _make_chain("c2", ["f3", "f4", "f5"])
    chain_scores = {"c1": 10.0, "c2": 10.0}
    f6 = _make_finding("f6", severity=Severity.MEDIUM)
    f7 = _make_finding("f7", severity=Severity.LOW)

    rs = score_repository([c1, c2], [f6, f7], chain_scores, finding_scores)
    expected = 100.0 * (1.0 - 0.1 * 0.1 * 0.64 * 0.82)
    assert abs(rs - expected) < 1e-4


# ===========================================================================
# 8. Extension rule finding scores
# ===========================================================================


def test_extension_rule_known_vulnerable_action():
    """known-vulnerable-action is CRITICAL → score 9.0 (push trigger).

    Hand-calc: SW=9.0, M=1.0  →  9.0
    """
    f = _make_finding("f1", rule_id="known-vulnerable-action", severity=Severity.CRITICAL)
    fs = score_finding(f, {"push": None})
    assert fs == 9.0


def test_extension_rule_cache_poisoning_risk():
    """cache-poisoning-risk is HIGH → 7.0 (push).

    Hand-calc: SW=7.0, M=1.0  →  7.0
    """
    f = _make_finding("f1", rule_id="cache-poisoning-risk", severity=Severity.HIGH)
    fs = score_finding(f, {"push": None})
    assert fs == 7.0


def test_extension_rule_missing_timeout():
    """missing-timeout is LOW → 2.0 (push).

    Hand-calc: SW=2.0, M=1.0  →  2.0
    """
    f = _make_finding("f1", rule_id="missing-timeout", severity=Severity.LOW)
    fs = score_finding(f, {"push": None})
    assert fs == 2.0


# ===========================================================================
# 9. Legacy RiskScorer interface (backward compatibility)
# ===========================================================================


def test_scorer_calculation_stub():
    """Verify legacy RiskScorer computes a positive normalized score.

    This is the original Phase-3 stub test; it must continue to pass.
    """
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


def test_legacy_scorer_risk_level_critical():
    """Legacy scorer assigns CRITICAL when repo_score >= 75."""
    scorer = RiskScorer()
    # Need several high findings to push repo_score >= 75
    findings = [_make_finding(f"f{i}", severity=Severity.CRITICAL) for i in range(5)]
    report = scorer.score(findings, [])
    assert report.risk_level == "CRITICAL"
    assert report.total_score >= 75.0


def test_legacy_scorer_risk_level_low():
    """Legacy scorer assigns LOW when repo_score < 25."""
    scorer = RiskScorer()
    # Single INFO finding → very low score
    f = _make_finding("f1", severity=Severity.INFO)
    report = scorer.score([f], [])
    assert report.risk_level == "LOW"
    assert report.total_score < 25.0


def test_legacy_scorer_returns_risk_report():
    """Legacy scorer returns a RiskReport dataclass."""
    scorer = RiskScorer()
    report = scorer.score([], [])
    assert isinstance(report, RiskReport)
    assert report.total_score == 0.0
    assert report.finding_count == 0
    assert report.chain_count == 0
