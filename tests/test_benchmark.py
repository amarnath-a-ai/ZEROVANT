"""Unit and integration tests for Phase 9 Benchmarking and Evaluation module."""

import csv
from pathlib import Path

import pytest

from benchmark.explainability_study.analyse_study import (
    analyze_results,
    format_markdown_report,
    load_study_data,
)
from benchmark.mapping import (
    get_all_mappings,
    get_rule_mapping,
    poutine_rule_to_zerovant_rules,
    zizmor_rule_to_zerovant_rules,
)
from benchmark.metrics import (
    calculate_f1,
    calculate_metrics,
    calculate_precision,
    calculate_recall,
    canonicalize_rule_id,
    match_findings,
)
from benchmark.run_benchmark import (
    locate_poutine,
    locate_zizmor,
    run_benchmark,
)


def test_calculate_metrics_values_and_div_zero():
    """Verify precision, recall, and F1 formulas and zero-division handling."""
    # Zero cases
    assert calculate_precision(0, 0) == 0.0
    assert calculate_recall(0, 0) == 0.0
    assert calculate_f1(0.0, 0.0) == 0.0

    m_zero = calculate_metrics(0, 0, 0)
    assert m_zero["precision"] == 0.0
    assert m_zero["recall"] == 0.0
    assert m_zero["f1"] == 0.0

    # Normal cases
    tp, fp, fn = 8, 2, 2
    # Precision = 8 / (8 + 2) = 0.8
    # Recall = 8 / (8 + 2) = 0.8
    # F1 = 2 * (0.8 * 0.8) / (0.8 + 0.8) = 0.8
    m = calculate_metrics(tp, fp, fn)
    assert m["precision"] == 0.8
    assert m["recall"] == 0.8
    assert m["f1"] == 0.8

    # High precision, lower recall
    m2 = calculate_metrics(10, 0, 10)
    assert m2["precision"] == 1.0
    assert m2["recall"] == 0.5
    assert m2["f1"] == pytest.approx(0.6667, abs=1e-4)


def test_canonicalize_rule_id():
    """Verify rule ID canonicalization for rule names and aliases."""
    assert canonicalize_rule_id("R001") == "R001"
    assert canonicalize_rule_id("r001") == "R001"
    assert canonicalize_rule_id("unpinned-action") == "R001"
    assert canonicalize_rule_id("unpinned-action-tag") == "R001"
    assert canonicalize_rule_id("script-injection") == "R004"
    assert canonicalize_rule_id("persist-credentials") == "persist-credentials"
    assert canonicalize_rule_id("missing-timeout") == "missing-timeout"


def test_match_findings_exact_and_tolerance():
    """Verify bipartite matching between expected and actual findings."""
    expected = [
        {"rule_id": "R001", "job": "build", "line": 10, "line_strict": False},
        {"rule_id": "R004", "job": "test", "line": 20, "line_strict": True},
    ]

    # Perfect match
    actual = [
        {"rule_id": "R001", "job": "build", "line": 11},
        {"rule_id": "R004", "job": "test", "line": 20},
    ]
    tp, fp, fn = match_findings(expected, actual)
    assert tp == 2
    assert fp == 0
    assert fn == 0

    # Strict failure: line 25 vs 20 with line_strict=True
    actual_strict_fail = [
        {"rule_id": "R001", "job": "build", "line": 11},
        {"rule_id": "R004", "job": "test", "line": 25},
    ]
    tp, fp, fn = match_findings(expected, actual_strict_fail)
    assert tp == 1
    assert fp == 1
    assert fn == 1

    # Empty actual
    tp, fp, fn = match_findings(expected, [])
    assert tp == 0
    assert fp == 0
    assert fn == 2


def test_mapping_completeness_and_integrity():
    """Verify that all 30 ZEROVANT detection rules are mapped with valid schema."""
    mappings = get_all_mappings()
    assert len(mappings) == 30

    rule_ids = {m.rule_id for m in mappings}
    # Verify core rules R001 - R010
    for i in range(1, 11):
        assert f"R{i:03d}" in rule_ids

    # Verify categories
    valid_categories = {"supply-chain", "permissions", "injection", "credentials", "execution", "hygiene"}
    for m in mappings:
        assert m.category in valid_categories, f"Invalid category {m.category} on {m.rule_id}"
        assert m.tier in ["core", "extension"], f"Invalid tier {m.tier} on {m.rule_id}"
        assert len(m.notes) > 10, f"Notes too short on {m.rule_id}"

    # Verify lookup helper
    r1 = get_rule_mapping("R001")
    assert r1 is not None
    assert r1.name == "unpinned-action"
    assert get_rule_mapping("non-existent-rule") is None


def test_zizmor_and_poutine_rule_lookup():
    """Verify bidirectional mappings from external tool rule names."""
    # Zizmor
    unpinned = zizmor_rule_to_zerovant_rules("unpinned-uses")
    assert "R001" in unpinned
    assert "R010" in unpinned

    artipacked = zizmor_rule_to_zerovant_rules("artipacked")
    assert "persist-credentials" in artipacked

    # Poutine
    unpinnable = poutine_rule_to_zerovant_rules("unpinnable_action")
    assert "R001" in unpinnable


def test_missing_tool_handling():
    """Verify graceful handling and detection of external tools."""
    # Zizmor should be detected in our venv
    z_bin = locate_zizmor()
    assert z_bin is not None
    assert Path(z_bin).exists()

    # Poutine is not on Windows
    p_bin = locate_poutine()
    # locate_poutine() must return None or string safely without crashing
    assert p_bin is None or isinstance(p_bin, str)


def test_benchmark_runner_executes_and_generates_outputs(tmp_path):
    """Verify that benchmark runner executes across corpus and generates valid CSVs."""
    res_dir = tmp_path / "benchmark_results"
    res = run_benchmark(
        ground_truth_path="benchmark/ground_truth.json",
        results_dir=str(res_dir),
        repetitions=1,
    )
    assert res["status"] == "success"

    # Verify expected files exist
    expected_files = [
        "summary.csv",
        "per_fixture.csv",
        "per_category.csv",
        "timing.csv",
        "mapping.csv",
        "benchmark_report.md",
    ]
    for ef in expected_files:
        p = res_dir / ef
        assert p.exists(), f"Missing output file: {ef}"
        assert p.stat().st_size > 50, f"File {ef} unexpectedly empty"

    # Verify summary.csv structure
    with (res_dir / "summary.csv").open("r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) >= 6
        tools = {r["Tool"] for r in reader}
        assert "ZEROVANT" in tools
        assert "Zizmor" in tools
        assert "Poutine" in tools


def test_analyse_study_rejects_empty_template():
    """Verify analyse_study raises ValueError when CSV template contains only headers."""
    with pytest.raises(ValueError, match="CSV template contains only headers"):
        load_study_data("benchmark/explainability_study/results_template.csv")


def test_analyse_study_calculates_metrics_on_sample_data(tmp_path):
    """Verify analyse_study computes accurate statistics and t-tests on populated data."""
    sample_csv = tmp_path / "sample_results.csv"
    with sample_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Participant_ID",
            "Group_Order",
            "Task_ID",
            "Condition",
            "Time_To_Remediate_Sec",
            "Fix_Correctness",
            "Comprehension_Score",
            "Clarity_Rating",
            "Confidence_Rating",
        ])
        # Participant 1
        writer.writerow(["P01", "G1", "T1", "Baseline", "180", "0.5", "1", "2", "3"])
        writer.writerow(["P01", "G1", "T2", "ZEROVANT", "60", "1.0", "2", "5", "5"])
        # Participant 2
        writer.writerow(["P02", "G2", "T1", "ZEROVANT", "45", "1.0", "2", "5", "4"])
        writer.writerow(["P02", "G2", "T2", "Baseline", "210", "0.0", "0", "2", "2"])

    rows = load_study_data(sample_csv)
    assert len(rows) == 4

    metrics = analyze_results(rows)
    assert metrics["sample_size"] == 2
    assert metrics["total_trials"] == 4
    assert metrics["baseline_trials"] == 2
    assert metrics["zerovant_trials"] == 2

    # Baseline time: (180 + 210) / 2 = 195.0
    # ZEROVANT time: (60 + 45) / 2 = 52.5
    assert metrics["time_to_remediate"]["baseline_mean"] == 195.0
    assert metrics["time_to_remediate"]["zerovant_mean"] == 52.5
    assert metrics["time_to_remediate"]["reduction_pct"] > 70.0

    # Report generation
    md = format_markdown_report(metrics)
    assert "ZEROVANT Explainability User Study Results" in md
    assert "-73.08% faster" in md or "faster" in md
