"""Comprehensive test suite for the Rule Engine, 10 Security Rules, and CLI Scanner."""

import json
from pathlib import Path

from app.parser import WorkflowLoader, load_workflows
from app.rules import (
    ALL_RULES,
    DeployEnvironmentRule,
    ExcessivePermissionsRule,
    Finding,
    LongLivedCredentialsRule,
    PlaintextSecretRule,
    PrTargetCheckoutRule,
    ScriptInjectionRule,
    SecretInLogRule,
    SelfHostedRunnerRule,
    Severity,
    ThirdPartyActionRule,
    UnpinnedActionRule,
    default_registry,
)
from cli import main as cli_main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
BENCHMARK_GROUND_TRUTH = Path(__file__).resolve().parent.parent / "benchmark" / "ground_truth.json"


# ============================================================================
# Rule Registry & Metadata Tests
# ============================================================================


def test_all_ten_rules_registered():
    """Verify all 10 security rules are defined, metadata-complete, and registered."""
    registered = default_registry.list_rules()
    assert len(registered) == 10
    assert len(ALL_RULES) == 10

    expected_ids = {
        "R001", "R002", "R003", "R004", "R005",
        "R006", "R007", "R008", "R009", "R010",
    }
    actual_ids = {r.id for r in registered}
    assert actual_ids == expected_ids

    for rule in registered:
        assert rule.id.startswith("R")
        assert rule.name, f"Rule {rule.id} missing name"
        assert rule.description, f"Rule {rule.id} missing description"
        assert rule.default_severity in Severity, f"Rule {rule.id} has invalid severity"
        assert len(rule.tags) > 0, f"Rule {rule.id} missing tags"
        assert len(rule.references) > 0, f"Rule {rule.id} missing references"


# ============================================================================
# Unit Tests for Each of the 10 Rules
# ============================================================================


def test_r001_unpinned_action_detection():
    """R001: Detects mutable tags and branches; accepts immutable 40-hex SHAs."""
    loader = WorkflowLoader()
    rule = UnpinnedActionRule()

    # Vulnerable workflow: uses tag @v4 and branch @main
    vuln_yaml = """
name: Unpinned Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@main
"""
    res = loader.load_string(vuln_yaml, file_path="test_unpinned.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 2
    assert findings[0].rule_id == "R001"
    assert "actions/checkout@v4" in findings[0].evidence
    assert findings[1].rule_id == "R001"
    assert "actions/setup-python@main" in findings[1].evidence

    # Safe workflow: full 40-character commit SHA
    safe_yaml = """
name: Pinned Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
    res_safe = loader.load_string(safe_yaml, file_path="test_pinned.yml")
    findings_safe = rule.evaluate(res_safe.workflow)
    assert len(findings_safe) == 0


def test_r001_reusable_workflow_call():
    """R001: Detects unpinned reusable workflow call at job level."""
    loader = WorkflowLoader()
    rule = UnpinnedActionRule()

    yaml_content = """
name: Caller
on: push
jobs:
  call_reusable:
    uses: acme-corp/shared-workflows/.github/workflows/build.yml@main
"""
    res = loader.load_string(yaml_content, file_path="caller.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R001"
    assert findings[0].job == "call_reusable"
    assert "reusable workflow" in findings[0].title.lower()


def test_r002_excessive_permissions_detection():
    """R002: Detects explicit write-all and omitted permissions blocks."""
    loader = WorkflowLoader()
    rule = ExcessivePermissionsRule()

    # Omitted permissions block -> MEDIUM finding
    omitted_yaml = """
name: Omitted Perms
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
"""
    res_omitted = loader.load_string(omitted_yaml, file_path="omitted.yml")
    f_omitted = rule.evaluate(res_omitted.workflow)
    assert len(f_omitted) == 1
    assert f_omitted[0].rule_id == "R002"
    assert f_omitted[0].severity == Severity.MEDIUM
    assert "Omitted Permissions" in f_omitted[0].title

    # Explicit write-all -> HIGH finding
    write_all_yaml = """
name: Write All
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
"""
    res_write = loader.load_string(write_all_yaml, file_path="write_all.yml")
    f_write = rule.evaluate(res_write.workflow)
    assert any(f.severity == Severity.HIGH and "write-all" in f.evidence for f in f_write)

    # Safe: restricted contents: read
    safe_yaml = """
name: Safe Perms
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps: []
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe.yml")
    f_safe = rule.evaluate(res_safe.workflow)
    assert len(f_safe) == 0


def test_r003_pr_target_checkout_detection():
    """R003: Detects checkout of PR head under pull_request_target."""
    loader = WorkflowLoader()
    rule = PrTargetCheckoutRule()

    # Vulnerable: pull_request_target checking out PR head sha
    vuln_yaml = """
name: Pwn Request
on:
  pull_request_target:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR Head
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    res = loader.load_string(vuln_yaml, file_path="pr_target.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R003"
    assert findings[0].severity == Severity.CRITICAL

    # Safe: standard pull_request trigger (not pull_request_target)
    safe_pr = """
name: Safe PR
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    res_safe = loader.load_string(safe_pr, file_path="safe_pr.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r004_script_injection_detection():
    """R004: Detects inline expression interpolation in run: commands."""
    loader = WorkflowLoader()
    rule = ScriptInjectionRule()

    # Vulnerable: direct inline interpolation of issue title in run
    vuln_yaml = """
name: Injection
on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Issue title is: ${{ github.event.issue.title }}"
"""
    res = loader.load_string(vuln_yaml, file_path="inject.yml")
    assert res.is_valid, f"Errors: {res.errors}"
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R004"
    assert findings[0].severity == Severity.CRITICAL

    # Safe: context passed through env: and referenced as $VAR
    safe_yaml = """
name: Safe Injection Prevention
on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        run: |
          echo "Issue title is: $ISSUE_TITLE"
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_inject.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r005_plaintext_secret_detection():
    """R005: Detects hardcoded plaintext secrets; ignores ${{ secrets.* }} references."""
    loader = WorkflowLoader()
    rule = PlaintextSecretRule()

    # Vulnerable: hardcoded token string in env
    vuln_yaml = """
name: Secret Test
on: push
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - env:
          STATIC_API_TOKEN: super_secret_production_api_token_value_99999
        run: echo "Posting..."
"""
    res = loader.load_string(vuln_yaml, file_path="secret.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R005"
    assert findings[0].severity == Severity.HIGH

    # Safe: secrets referenced via GitHub Encrypted Secrets syntax
    safe_yaml = """
name: Safe Secret
on: push
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - env:
          AUTH_TOKEN: ${{ secrets.PROD_API_TOKEN }}
        run: echo "Posting..."
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_secret.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r006_secret_in_log_detection():
    """R006: Detects commands printing secrets to logs."""
    loader = WorkflowLoader()
    rule = SecretInLogRule()

    vuln_yaml = """
name: Log Secret
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Token is: ${{ secrets.DEPLOY_TOKEN }}"
"""
    res = loader.load_string(vuln_yaml, file_path="log_sec.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R006"
    assert findings[0].severity == Severity.MEDIUM


def test_r007_long_lived_credentials_detection():
    """R007: Detects static cloud access keys in configure-aws-credentials."""
    loader = WorkflowLoader()
    rule = LongLivedCredentialsRule()

    vuln_yaml = """
name: AWS Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          aws-access-key-id: ${{ secrets.AWS_KEY }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET }}
          aws-region: us-east-1
"""
    res = loader.load_string(vuln_yaml, file_path="aws_static.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R007"
    assert findings[0].severity == Severity.MEDIUM

    # Safe: OIDC role assumption
    safe_yaml = """
name: AWS OIDC
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          role-to-assume: arn:aws:iam::123456789012:role/my-role
          aws-region: us-east-1
"""
    res_safe = loader.load_string(safe_yaml, file_path="aws_oidc.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r008_deploy_environment_detection():
    """R008: Detects deployment jobs lacking protected GitHub environment."""
    loader = WorkflowLoader()
    rule = DeployEnvironmentRule()

    # Vulnerable: deploy job without environment
    vuln_yaml = """
name: Prod Deploy
on: release
jobs:
  deploy_production:
    runs-on: ubuntu-latest
    steps:
      - run: kubectl apply -f k8s/
"""
    res = loader.load_string(vuln_yaml, file_path="deploy_no_env.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R008"

    # Safe: environment configured
    safe_yaml = """
name: Prod Deploy
on: release
jobs:
  deploy_production:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: kubectl apply -f k8s/
"""
    res_safe = loader.load_string(safe_yaml, file_path="deploy_with_env.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0

    # Safe: non-deployment job without environment (e.g. linter)
    linter_yaml = """
name: Linter
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: flake8 .
"""
    res_linter = loader.load_string(linter_yaml, file_path="lint.yml")
    assert len(rule.evaluate(res_linter.workflow)) == 0


def test_r009_self_hosted_runner_detection():
    """R009: Detects self-hosted runners responding to untrusted pull requests."""
    loader = WorkflowLoader()
    rule = SelfHostedRunnerRule()

    # Vulnerable: self-hosted runner triggered by pull_request
    vuln_yaml = """
name: Self Hosted PR
on: pull_request
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: ./build.sh
"""
    res = loader.load_string(vuln_yaml, file_path="self_hosted.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R009"
    assert findings[0].severity == Severity.HIGH

    # Safe: hosted runner
    safe_hosted = """
name: Hosted PR
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./build.sh
"""
    res_safe = loader.load_string(safe_hosted, file_path="safe_hosted.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0

    # Safe: self-hosted runner on trusted push trigger
    safe_push = """
name: Self Hosted Push
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: ./build.sh
"""
    res_push = loader.load_string(safe_push, file_path="safe_push.yml")
    assert len(rule.evaluate(res_push.workflow)) == 0


def test_r010_third_party_action_detection():
    """R010: Detects third-party actions from untrusted publishers."""
    loader = WorkflowLoader()
    rule = ThirdPartyActionRule()

    # Vulnerable: untrusted publisher
    vuln_yaml = """
name: Third Party
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: random-unverified-org/super-helper@b4ffde65f46336ab88eb53be808477a3936bae11
"""
    res = loader.load_string(vuln_yaml, file_path="third_party.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "R010"
    assert "random-unverified-org" in findings[0].evidence

    # Safe: trusted official action from actions/*
    safe_yaml = """
name: Official
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_official.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


# ============================================================================
# Fingerprint Stability Across Line Shifts
# ============================================================================


def test_finding_fingerprint_stability_across_line_shifts():
    """Verify that shifting line numbers upstream does NOT alter finding fingerprint."""
    f1 = Finding(
        id="f-0001",
        rule_id="R001",
        title="Unpinned Action",
        severity=Severity.HIGH,
        file=".github/workflows/ci.yml",
        job="build",
        step="Checkout",
        line=10,
        evidence="Action 'actions/checkout@v4' is unpinned",
    )

    # Same finding after 50 blank lines inserted above it (line changed from 10 to 60)
    f2 = Finding(
        id="f-0002",
        rule_id="R001",
        title="Unpinned Action",
        severity=Severity.HIGH,
        file=".github/workflows/ci.yml",
        job="build",
        step="Checkout",
        line=60,
        evidence="Action 'actions/checkout@v4' is unpinned",
    )

    assert f1.fingerprint != "", "Fingerprint must not be empty"
    assert f1.fingerprint == f2.fingerprint, "Fingerprint must remain identical across line shifts"


# ============================================================================
# Ground Truth Benchmark Verification
# ============================================================================


def test_ground_truth_vulnerable_and_safe_corpus():
    """Verify detection accuracy against benchmark ground truth fixtures."""
    with open(BENCHMARK_GROUND_TRUTH, encoding="utf-8") as f:
        ground_truth = json.load(f)

    base_dir = BENCHMARK_GROUND_TRUTH.parent.parent
    total_expected = 0
    total_detected = 0
    false_positives_in_safe = 0

    # Test all 10 synthetic vulnerable fixtures
    for i in range(1, 11):
        vuln_name = f"tests/fixtures/vulnerable/vuln_r{i:03d}"
        matching_keys = [k for k in ground_truth["fixtures"] if k.startswith(vuln_name)]
        assert len(matching_keys) == 1, f"Missing ground truth for {vuln_name}"
        rel_path = matching_keys[0]

        expected_meta = ground_truth["fixtures"][rel_path]
        expected_findings = expected_meta.get("expected_findings", [])

        wf_res = load_workflows(base_dir / rel_path)[0]
        assert wf_res.is_valid and wf_res.workflow is not None

        detected = default_registry.run_all(wf_res.workflow)
        detected_rules = {d.rule_id for d in detected}

        # Verify the primary rule is detected
        primary_rule = f"R{i:03d}"
        assert primary_rule in detected_rules, (
            f"Failed to detect expected primary rule {primary_rule} in {rel_path}. Detected: {detected_rules}"
        )

        for ef in expected_findings:
            total_expected += 1
            if ef["rule_id"] in detected_rules:
                total_detected += 1

    # Test synthetic safe counterparts
    for i in range(1, 11):
        safe_name = f"tests/fixtures/safe/safe_r{i:03d}"
        matching_keys = [k for k in ground_truth["fixtures"] if k.startswith(safe_name)]
        if not matching_keys:
            continue
        rel_path = matching_keys[0]

        wf_res = load_workflows(base_dir / rel_path)[0]
        assert wf_res.is_valid and wf_res.workflow is not None

        detected = default_registry.run_all(wf_res.workflow)
        if len(detected) > 0:
            false_positives_in_safe += len(detected)

    # Safe fixtures must produce 0 false positives
    assert false_positives_in_safe == 0, f"Encountered {false_positives_in_safe} false positives in safe fixtures"


# ============================================================================
# CLI Scan Tests
# ============================================================================


def test_cli_scan_json_output(capsys):
    """Verify CLI scan output in JSON format."""
    target_fixture = str(FIXTURES_DIR / "vulnerable" / "vuln_r001_unpinned.yml")
    exit_code = cli_main(["scan", target_fixture, "--format", "json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) >= 2
    rule_ids = {item["rule_id"] for item in data}
    assert "R001" in rule_ids


def test_cli_scan_table_output(capsys):
    """Verify CLI scan output in human-readable table format."""
    target_fixture = str(FIXTURES_DIR / "safe" / "safe_r001_pinned.yml")
    exit_code = cli_main(["scan", target_fixture, "--format", "table"])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "No security vulnerabilities detected" in captured.out


def test_cli_scan_exit_code_flag():
    """Verify --exit-code flag returns code 1 when HIGH/CRITICAL findings are found."""
    vuln_fixture = str(FIXTURES_DIR / "vulnerable" / "vuln_r001_unpinned.yml")
    code = cli_main(["scan", vuln_fixture, "--exit-code"])
    assert code == 1

    safe_fixture = str(FIXTURES_DIR / "safe" / "safe_r001_pinned.yml")
    code_safe = cli_main(["scan", safe_fixture, "--exit-code"])
    assert code_safe == 0
