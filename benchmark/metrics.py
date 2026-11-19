"""Evaluation metric calculations and finding matching for ZEROVANT benchmark."""

from typing import Any

from benchmark.mapping import RULE_MAPPINGS

# Rule name to Canonical Rule ID alias mapping
_RULE_NAME_TO_ID: dict[str, str] = {
    m.name.lower(): m.rule_id for m in RULE_MAPPINGS
}
# Extra aliases found in test fixtures or documentation
_RULE_NAME_TO_ID.update({
    "unpinned-action-tag": "R001",
    "unpinned-action": "R001",
    "unpinned_action": "R001",
    "excessive-permissions": "R002",
    "excessive_permissions": "R002",
    "pr-target-checkout": "R003",
    "script-injection": "R004",
    "plaintext-secret": "R005",
    "secret-in-log": "R006",
    "long-lived-credentials": "R007",
    "deploy-environment": "R008",
    "self-hosted-runner": "R009",
    "third-party-action": "R010",
})


def canonicalize_rule_id(rule_str: str) -> str:
    """Normalize a rule ID or rule name to the canonical ZEROVANT rule ID."""
    cleaned = rule_str.strip().lower()
    if cleaned.upper() in [m.rule_id.upper() for m in RULE_MAPPINGS]:
        return cleaned.upper() if cleaned.upper().startswith("R0") else cleaned
    return _RULE_NAME_TO_ID.get(cleaned, rule_str.strip())


def calculate_precision(tp: int, fp: int) -> float:
    """Calculate Precision: TP / (TP + FP). Returns 0.0 if denominator is 0."""
    total = tp + fp
    if total <= 0:
        return 0.0
    return tp / total


def calculate_recall(tp: int, fn: int) -> float:
    """Calculate Recall: TP / (TP + FN). Returns 0.0 if denominator is 0."""
    total = tp + fn
    if total <= 0:
        return 0.0
    return tp / total


def calculate_f1(precision: float, recall: float) -> float:
    """Calculate F1-Score: 2 * (P * R) / (P + R). Returns 0.0 if denominator is 0."""
    total = precision + recall
    if total <= 0:
        return 0.0
    return 2 * (precision * recall) / total


def calculate_metrics(tp: int, fp: int, fn: int) -> dict[str, float | int]:
    """Compute complete metric dictionary for given counts."""
    prec = calculate_precision(tp, fp)
    rec = calculate_recall(tp, fn)
    f1 = calculate_f1(prec, rec)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
    }


def match_findings(
    expected_findings: list[dict[str, Any]],
    actual_findings: list[dict[str, Any]],
    default_tolerance: int = 3,
    strict_tolerance: int = 1,
) -> tuple[int, int, int]:
    """Perform bipartite matching between expected and actual findings for a single fixture.

    Args:
        expected_findings: Ground truth expected findings list.
        actual_findings: Detected findings list from tool. Each item must have 'rule_id',
            and optional 'job' and 'line'.
        default_tolerance: Line tolerance when line_strict is False.
        strict_tolerance: Line tolerance when line_strict is True.

    Returns:
        tuple of (tp, fp, fn)
    """
    matched_expected: set[int] = set()
    matched_actual: set[int] = set()

    for a_idx, act in enumerate(actual_findings):
        act_rule = canonicalize_rule_id(str(act.get("rule_id", "")))
        act_job = act.get("job")
        act_line = act.get("line")

        best_match_idx: int | None = None
        best_line_diff = float("inf")

        for e_idx, exp in enumerate(expected_findings):
            if e_idx in matched_expected:
                continue

            exp_rule = canonicalize_rule_id(str(exp.get("rule_id", "")))
            if exp_rule != act_rule:
                continue

            # Check job match if both specify a job
            exp_job = exp.get("job")
            if exp_job and act_job and exp_job != act_job:
                continue

            # Check line tolerance if line is specified
            exp_line = exp.get("line")
            is_strict = exp.get("line_strict", False)
            tol = strict_tolerance if is_strict else default_tolerance

            if exp_line is not None and act_line is not None:
                diff = abs(exp_line - act_line)
                if diff > tol:
                    if is_strict:
                        continue
                if diff < best_line_diff:
                    best_line_diff = diff
                    best_match_idx = e_idx
            else:
                # No line specified in either, match unconditionally on rule (+ job)
                if best_match_idx is None:
                    best_match_idx = e_idx

        if best_match_idx is not None:
            matched_expected.add(best_match_idx)
            matched_actual.add(a_idx)

    tp = len(matched_expected)
    fn = len(expected_findings) - tp
    fp = len(actual_findings) - len(matched_actual)

    return tp, fp, fn
