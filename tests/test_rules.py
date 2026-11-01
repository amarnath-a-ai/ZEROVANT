"""Comprehensive test suite for the Rule Engine, 10 Security Rules, and CLI Scanner."""

import json
from pathlib import Path

from app.parser import WorkflowLoader, load_workflows
from app.rules import (
    BATCH_A_RULES,
    BATCH_B_RULES,
    CORE_RULES,
    ArtifactLeakRule,
    BotActorSpoofingRule,
    CommentTriggerNoAuthRule,
    DeployEnvironmentRule,
    DispatchInputInjectionRule,
    ExcessivePermissionsRule,
    Finding,
    GitHubEnvInjectionRule,
    LongLivedCredentialsRule,
    OverprovisionedSecretsRule,
    PersistCredentialsRule,
    PlaintextSecretRule,
    PrTargetCheckoutRule,
    ScriptInjectionRule,
    SecretInLogRule,
    SecretsInheritRule,
    SecretToUnpinnedActionRule,
    SelfHostedRunnerRule,
    Severity,
    ThirdPartyActionRule,
    UnpinnedActionRule,
    WorkflowRunUntrustedArtifactRule,
    default_registry,
)
from cli import main as cli_main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
BENCHMARK_GROUND_TRUTH = Path(__file__).resolve().parent.parent / "benchmark" / "ground_truth.json"


# ============================================================================
# Rule Registry & Metadata Tests
# ============================================================================


def test_all_ten_rules_registered():
    """Verify all 10 core security rules and extension rules are registered."""
    registered = default_registry.list_rules()
    assert len(registered) >= 20
    assert len(CORE_RULES) == 10
    assert len(BATCH_A_RULES) == 5
    assert len(BATCH_B_RULES) == 5

    core_expected_ids = {
        "R001", "R002", "R003", "R004", "R005",
        "R006", "R007", "R008", "R009", "R010",
    }
    actual_ids = {r.id for r in registered}
    assert core_expected_ids.issubset(actual_ids)

    batch_a_expected_ids = {
        "persist-credentials",
        "secret-to-unpinned-action",
        "overprovisioned-secrets",
        "artifact-leak",
        "secrets-inherit",
    }
    assert batch_a_expected_ids.issubset(actual_ids)

    for rule in registered:
        assert rule.name, f"Rule {rule.id} missing name"
        assert rule.description, f"Rule {rule.id} missing description"
        assert rule.default_severity in Severity, f"Rule {rule.id} has invalid severity"
        assert len(rule.tags) > 0, f"Rule {rule.id} missing tags"
        assert len(rule.references) > 0, f"Rule {rule.id} missing references"
        assert rule.tier in ("core", "extension"), f"Rule {rule.id} has invalid tier"


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


def test_r11_persist_credentials_detection():
    """Rule 11 (persist-credentials): Detects actions/checkout without persist-credentials: false."""
    loader = WorkflowLoader()
    rule = PersistCredentialsRule()

    vuln_yaml = """
name: Persist Cred
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: actions/upload-artifact@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          name: dist
          path: dist/
"""
    res = loader.load_string(vuln_yaml, file_path="persist.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "persist-credentials"

    safe_yaml = """
name: No Persist Cred
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          persist-credentials: false
      - run: make dist
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_persist.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r12_secret_to_unpinned_action_detection():
    """Rule 12 (secret-to-unpinned-action): Detects secrets passed to unpinned third-party actions."""
    loader = WorkflowLoader()
    rule = SecretToUnpinnedActionRule()

    vuln_yaml = """
name: Secret Unpinned
on: push
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - uses: acme-corp/notify-action@v1
        with:
          token: ${{ secrets.NOTIFY_TOKEN }}
"""
    res = loader.load_string(vuln_yaml, file_path="sec_unpinned.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "secret-to-unpinned-action"

    safe_yaml = """
name: Secret Pinned
on: push
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - uses: acme-corp/notify-action@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          token: ${{ secrets.NOTIFY_TOKEN }}
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_sec_pinned.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r13_overprovisioned_secrets_detection():
    """Rule 13 (overprovisioned-secrets): Detects toJSON(secrets) or dynamic indexing."""
    loader = WorkflowLoader()
    rule = OverprovisionedSecretsRule()

    vuln_yaml = """
name: Overprov
on: push
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - run: ./collect.sh
        env:
          ALL_SECRETS: ${{ toJSON(secrets) }}
"""
    res = loader.load_string(vuln_yaml, file_path="overprov.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "overprovisioned-secrets"

    safe_yaml = """
name: Safe Secrets
on: push
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - run: ./collect.sh
        env:
          TOKEN: ${{ secrets.REPORT_TOKEN }}
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_secrets.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r14_artifact_leak_detection():
    """Rule 14 (artifact-leak): Detects archiving entire workspace root or .git/config."""
    loader = WorkflowLoader()
    rule = ArtifactLeakRule()

    vuln_yaml = """
name: Leak
on: push
jobs:
  pkg:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          name: everything
          path: .
"""
    res = loader.load_string(vuln_yaml, file_path="leak.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "artifact-leak"

    safe_yaml = """
name: Safe Upload
on: push
jobs:
  pkg:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          name: dist
          path: dist/
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_upload.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r15_secrets_inherit_detection():
    """Rule 15 (secrets-inherit): Detects reusable workflow calls using secrets: inherit."""
    loader = WorkflowLoader()
    rule = SecretsInheritRule()

    vuln_yaml = """
name: Inherit
on: push
jobs:
  build:
    uses: ./.github/workflows/build.yml
    secrets: inherit
"""
    res = loader.load_string(vuln_yaml, file_path="inherit.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "secrets-inherit"

    safe_yaml = """
name: Safe Inherit
on: push
jobs:
  build:
    uses: ./.github/workflows/build.yml
    secrets:
      token: ${{ secrets.MY_TOKEN }}
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_inherit.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_extension_batch_a_fixtures_ground_truth():
    """Verify Batch A extension fixtures (ext_r11..ext_r15) match ground truth."""
    with open(BENCHMARK_GROUND_TRUTH, encoding="utf-8") as f:
        ground_truth = json.load(f)

    base_dir = BENCHMARK_GROUND_TRUTH.parent.parent
    for i in range(11, 16):
        vuln_key = f"tests/fixtures/extension/vulnerable/ext_r{i}_"
        matching_v = [k for k in ground_truth["fixtures"] if k.startswith(vuln_key)]
        assert len(matching_v) == 1
        v_path = matching_v[0]

        wf_res = load_workflows(base_dir / v_path)[0]
        detected = default_registry.run_all(wf_res.workflow)
        detected_rule_ids = {d.rule_id for d in detected}

        must_include = ground_truth["fixtures"][v_path].get("must_include", [])
        for expected in must_include:
            assert expected["rule_id"] in detected_rule_ids, (
                f"Missing expected rule {expected['rule_id']} in {v_path}. Found: {detected_rule_ids}"
            )

        # Safe counterpart
        safe_key = f"tests/fixtures/extension/safe/ext_r{i}_safe.yml"
        if safe_key in ground_truth["fixtures"]:
            safe_res = load_workflows(base_dir / safe_key)[0]
            detected_safe = default_registry.run_all(safe_res.workflow)
            must_not_include = ground_truth["fixtures"][safe_key].get("must_not_include", [])
            for not_rule in must_not_include:
                assert not_rule not in {d.rule_id for d in detected_safe}, (
                    f"Unexpected rule {not_rule} fired on safe fixture {safe_key}"
                )


def test_r16_github_env_injection_detection():
    """Rule 16 (github-env-injection): Detects untrusted event context written to GITHUB_ENV."""
    loader = WorkflowLoader()
    rule = GitHubEnvInjectionRule()

    vuln_yaml = """
name: Env Injection
on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TITLE=${{ github.event.issue.title }}" >> "$GITHUB_ENV"
"""
    res = loader.load_string(vuln_yaml, file_path="env_inj.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "github-env-injection"
    assert findings[0].severity == Severity.HIGH

    safe_yaml = """
name: Safe Env
on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TITLE_LEN=${#TITLE}" >> "$GITHUB_ENV"
        env:
          TITLE: ${{ github.event.issue.title }}
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_env.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r17_workflow_run_untrusted_artifact_detection():
    """Rule 17 (workflow-run-untrusted-artifact): Detects download-artifact in workflow_run."""
    loader = WorkflowLoader()
    rule = WorkflowRunUntrustedArtifactRule()

    vuln_yaml = """
name: Workflow Run Artifact
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          name: untrusted-bin
"""
    res = loader.load_string(vuln_yaml, file_path="wf_run.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "workflow-run-untrusted-artifact"
    assert findings[0].severity == Severity.HIGH

    safe_yaml = """
name: Safe Workflow Run
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  status:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Done"
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_wf_run.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r18_comment_trigger_no_auth_detection():
    """Rule 18 (comment-trigger-no-auth): Detects comment triggers without author verification."""
    loader = WorkflowLoader()
    rule = CommentTriggerNoAuthRule()

    vuln_yaml = """
name: Comment Trigger
on:
  issue_comment:
    types: [created]
jobs:
  handle:
    runs-on: ubuntu-latest
    steps:
      - run: ./handle.sh
"""
    res = loader.load_string(vuln_yaml, file_path="comment.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "comment-trigger-no-auth"
    assert findings[0].severity == Severity.HIGH

    safe_yaml = """
name: Safe Comment Trigger
on:
  issue_comment:
    types: [created]
jobs:
  handle:
    if: github.event.comment.author_association == 'OWNER'
    runs-on: ubuntu-latest
    steps:
      - run: ./handle.sh
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_comment.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r19_dispatch_input_injection_detection():
    """Rule 19 (dispatch-input-injection): Detects dispatch inputs interpolated in run steps."""
    loader = WorkflowLoader()
    rule = DispatchInputInjectionRule()

    vuln_yaml = """
name: Dispatch
on:
  workflow_dispatch:
    inputs:
      target:
        required: true
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying ${{ inputs.target }}"
"""
    res = loader.load_string(vuln_yaml, file_path="dispatch.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "dispatch-input-injection"
    assert findings[0].severity == Severity.LOW

    safe_yaml = """
name: Safe Dispatch
on:
  workflow_dispatch:
    inputs:
      target:
        required: true
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying $TARGET"
        env:
          TARGET: ${{ inputs.target }}
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_dispatch.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_r20_bot_actor_spoofing_detection():
    """Rule 20 (bot-actor-spoofing): Detects github.actor == 'bot' authorization."""
    loader = WorkflowLoader()
    rule = BotActorSpoofingRule()

    vuln_yaml = """
name: Bot Spoofing
on: pull_request_target
jobs:
  merge:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge
"""
    res = loader.load_string(vuln_yaml, file_path="bot_spoof.yml")
    findings = rule.evaluate(res.workflow)
    assert len(findings) == 1
    assert findings[0].rule_id == "bot-actor-spoofing"
    assert findings[0].severity == Severity.MEDIUM

    safe_yaml = """
name: Safe Bot
on: pull_request_target
jobs:
  merge:
    if: github.event.pull_request.user.id == 49699333
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge
"""
    res_safe = loader.load_string(safe_yaml, file_path="safe_bot.yml")
    assert len(rule.evaluate(res_safe.workflow)) == 0


def test_extension_batch_b_fixtures_ground_truth():
    """Verify Batch B extension fixtures (ext_r16..ext_r20) match ground truth."""
    with open(BENCHMARK_GROUND_TRUTH, encoding="utf-8") as f:
        ground_truth = json.load(f)

    base_dir = BENCHMARK_GROUND_TRUTH.parent.parent
    for i in range(16, 21):
        vuln_key = f"tests/fixtures/extension/vulnerable/ext_r{i}_"
        matching_v = [k for k in ground_truth["fixtures"] if k.startswith(vuln_key)]
        assert len(matching_v) == 1
        v_path = matching_v[0]

        wf_res = load_workflows(base_dir / v_path)[0]
        detected = default_registry.run_all(wf_res.workflow)
        detected_rule_ids = {d.rule_id for d in detected}

        must_include = ground_truth["fixtures"][v_path].get("must_include", [])
        for expected in must_include:
            assert expected["rule_id"] in detected_rule_ids, (
                f"Missing expected rule {expected['rule_id']} in {v_path}. Found: {detected_rule_ids}"
            )

        # Safe counterpart
        safe_key = f"tests/fixtures/extension/safe/ext_r{i}_safe.yml"
        if safe_key in ground_truth["fixtures"]:
            safe_res = load_workflows(base_dir / safe_key)[0]
            detected_safe = default_registry.run_all(safe_res.workflow)
            must_not_include = ground_truth["fixtures"][safe_key].get("must_not_include", [])
            for not_rule in must_not_include:
                assert not_rule not in {d.rule_id for d in detected_safe}, (
                    f"Unexpected rule {not_rule} fired on safe fixture {safe_key}"
                )



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
