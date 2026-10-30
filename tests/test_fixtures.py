"""Smoke tests validating the fixture corpus and ground truth dataset."""

import json
from pathlib import Path

import pytest
import yaml

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
GROUND_TRUTH_PATH = Path(__file__).resolve().parent.parent / "benchmark" / "ground_truth.json"


def test_ground_truth_json_validity():
    """Verify ground_truth.json exists and is valid JSON."""
    assert GROUND_TRUTH_PATH.is_file(), f"Missing ground truth file at {GROUND_TRUTH_PATH}"
    data = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    assert "fixtures" in data, "ground_truth.json must contain a 'fixtures' root key"
    assert len(data["fixtures"]) > 0, "ground_truth.json fixtures list must not be empty"


def test_all_ground_truth_files_exist():
    """Verify every path registered in ground_truth.json points to an actual existing file."""
    data = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    base_dir = GROUND_TRUTH_PATH.parent.parent

    for rel_path, meta in data["fixtures"].items():
        full_path = base_dir / rel_path
        assert full_path.is_file(), f"Ground truth fixture does not exist on disk: {rel_path}"


def test_fixture_corpus_coverage():
    """Verify fixture corpus meets specified size thresholds."""
    vuln_files = list((FIXTURES_DIR / "vulnerable").glob("*.yml")) + list(
        (FIXTURES_DIR / "vulnerable").glob("*.yaml")
    )
    safe_files = list((FIXTURES_DIR / "safe").glob("*.yml")) + list(
        (FIXTURES_DIR / "safe").glob("*.yaml")
    )
    real_files = list((FIXTURES_DIR / "real_world").glob("*.yml")) + list(
        (FIXTURES_DIR / "real_world").glob("*.yaml")
    )

    # Hand-crafted corpus requirement: 15-20 fixtures
    hand_crafted_count = len(vuln_files) + len(safe_files)
    assert hand_crafted_count >= 15, f"Expected >= 15 hand-crafted fixtures, got {hand_crafted_count}"

    # Real-world corpus requirement: >= 10 public workflows
    assert len(real_files) >= 10, f"Expected >= 10 real-world fixtures, got {len(real_files)}"


def test_malformed_fixture_fails_yaml_parser():
    """Verify edge_malformed.yml genuinely raises a YAML parsing exception."""
    malformed_path = FIXTURES_DIR / "vulnerable" / "edge_malformed.yml"
    assert malformed_path.is_file()
    content = malformed_path.read_text(encoding="utf-8")

    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(content)


def test_valid_fixtures_parse_cleanly():
    """Verify that all non-malformed fixtures parse cleanly with standard safe_load."""
    for fixture_path in FIXTURES_DIR.rglob("*"):
        if not fixture_path.is_file() or fixture_path.suffix not in [".yml", ".yaml"]:
            continue
        if "edge_malformed.yml" in fixture_path.name:
            continue

        content = fixture_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        # Empty file returns None in yaml.safe_load, which is expected
        if fixture_path.name == "edge_empty.yml":
            assert parsed is None
        else:
            assert isinstance(
                parsed, dict
            ), f"Fixture {fixture_path.name} did not parse into a mapping dictionary"


def test_real_world_sources_documented():
    """Verify SOURCES.md exists and documents the real-world fixtures."""
    sources_file = FIXTURES_DIR / "real_world" / "SOURCES.md"
    assert sources_file.is_file()
    content = sources_file.read_text(encoding="utf-8")
    assert "actions_checkout_check_dist.yml" in content
    assert "pallets_flask_tests.yaml" in content
    assert "License" in content
