"""Tests for Attack Chain Correlation and Graph Generation (Phase 3)."""

import json
import textwrap
from pathlib import Path

from app.correlation import (
    AttackGraph,
    Chain,
    ChainCorrelator,
    ChainType,
    CorrelationResult,
)
from app.parser import load_workflows
from app.rules import default_registry

BASE_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = BASE_DIR / "tests" / "fixtures"
GROUND_TRUTH_FILE = BASE_DIR / "benchmark" / "ground_truth.json"
GROUND_TRUTH_EXT_FILE = BASE_DIR / "benchmark" / "ground_truth_extension.json"


def test_correlation_classes_importable():
    """Verify correlation models and correlator import cleanly with 10 chain types."""
    correlator = ChainCorrelator()
    assert correlator is not None
    assert len(correlator.definitions) == 10
    assert len(ChainType) == 10

    expected_types = {
        "pwn-request",
        "injection-to-exfil",
        "supply-chain-takeover",
        "deploy-blast-radius",
        "runner-persistence",
        "artifact-poisoning",
        "comment-trigger-takeover",
        "credential-persistence",
        "cache-poisoning-escalation",
        "oidc-abuse",
    }
    actual_types = {ct.value for ct in ChainType}
    assert actual_types == expected_types

    graph = AttackGraph()
    assert graph.to_cytoscape_elements() == []
    valid, errors = graph.validate()
    assert valid and len(errors) == 0


def test_ten_positive_attack_chain_fixtures():
    """Verify that all 10 positive chain fixtures produce their respective expected attack chain."""
    correlator = ChainCorrelator()

    positive_cases = [
        ("tests/fixtures/vulnerable/chain_pwn_request.yml", ChainType.PWN_REQUEST),
        ("tests/fixtures/vulnerable/chain_injection_to_exfil.yml", ChainType.INJECTION_TO_EXFIL),
        ("tests/fixtures/vulnerable/chain_supply_chain_takeover.yml", ChainType.SUPPLY_CHAIN_TAKEOVER),
        ("tests/fixtures/vulnerable/chain_deploy_blast_radius.yml", ChainType.DEPLOY_BLAST_RADIUS),
        ("tests/fixtures/vulnerable/chain_runner_persistence.yml", ChainType.RUNNER_PERSISTENCE),
        ("tests/fixtures/extension/chains/chain_artifact_poisoning.yml", ChainType.ARTIFACT_POISONING),
        ("tests/fixtures/extension/chains/chain_comment_trigger_takeover.yml", ChainType.COMMENT_TRIGGER_TAKEOVER),
        ("tests/fixtures/extension/chains/chain_credential_persistence.yml", ChainType.CREDENTIAL_PERSISTENCE),
        ("tests/fixtures/extension/chains/chain_cache_poisoning_escalation.yml", ChainType.CACHE_POISONING_ESCALATION),
        ("tests/fixtures/extension/chains/chain_oidc_abuse.yml", ChainType.OIDC_ABUSE),
    ]

    for rel_path, expected_chain_type in positive_cases:
        full_path = BASE_DIR / rel_path
        assert full_path.is_file(), f"Missing fixture file: {rel_path}"

        wf = load_workflows(full_path)[0].workflow
        assert wf is not None, f"Failed to parse workflow: {rel_path}"

        findings = default_registry.run_all(wf)
        chains = correlator.correlate(findings, workflow=wf)

        detected_chain_types = [c.chain_type for c in chains]
        assert expected_chain_type in detected_chain_types, (
            f"Fixture {rel_path} failed to produce expected chain {expected_chain_type.value}. "
            f"Detected: {[c.chain_type.value for c in chains]}"
        )

        # Verify each chain has nodes, edges, narrative, and valid schema
        for chain in chains:
            assert chain.id.startswith("c-")
            assert len(chain.nodes) >= 3, f"Chain {chain.id} has insufficient nodes: {chain.nodes}"
            assert len(chain.edges) >= 2, f"Chain {chain.id} has insufficient edges: {chain.edges}"
            assert len(chain.narrative) > 20, f"Chain {chain.id} missing descriptive narrative"
            assert chain.chain_score is None  # Phase 4 placeholder

            graph = AttackGraph.from_chain(chain)
            is_valid, validation_errors = graph.validate()
            assert is_valid, f"Chain {chain.id} graph validation failed: {validation_errors}"


def test_ten_negative_near_miss_fixtures():
    """Verify that all 10 near-miss fixtures do NOT trigger their prohibited attack chains."""
    correlator = ChainCorrelator()

    negative_cases = [
        ("tests/fixtures/extension/chains/neg_core_pwn_request_no_privilege.yml", ChainType.PWN_REQUEST),
        ("tests/fixtures/extension/chains/neg_core_injection_no_secrets_in_job.yml", ChainType.INJECTION_TO_EXFIL),
        ("tests/fixtures/extension/chains/neg_core_supply_chain_readonly.yml", ChainType.SUPPLY_CHAIN_TAKEOVER),
        ("tests/fixtures/extension/chains/neg_core_deploy_protected.yml", ChainType.DEPLOY_BLAST_RADIUS),
        ("tests/fixtures/extension/chains/neg_core_runner_trusted_trigger.yml", ChainType.RUNNER_PERSISTENCE),
        ("tests/fixtures/extension/chains/neg_artifact_poisoning_split.yml", ChainType.ARTIFACT_POISONING),
        ("tests/fixtures/extension/chains/neg_comment_with_auth.yml", ChainType.COMMENT_TRIGGER_TAKEOVER),
        ("tests/fixtures/extension/chains/neg_credential_persistence_split.yml", ChainType.CREDENTIAL_PERSISTENCE),
        ("tests/fixtures/extension/chains/neg_cache_unprivileged.yml", ChainType.CACHE_POISONING_ESCALATION),
        ("tests/fixtures/extension/chains/neg_oidc_trusted.yml", ChainType.OIDC_ABUSE),
    ]

    for rel_path, prohibited_chain_type in negative_cases:
        full_path = BASE_DIR / rel_path
        assert full_path.is_file(), f"Missing fixture file: {rel_path}"

        wf = load_workflows(full_path)[0].workflow
        assert wf is not None, f"Failed to parse workflow: {rel_path}"

        findings = default_registry.run_all(wf)
        chains = correlator.correlate(findings, workflow=wf)

        detected_chain_types = [c.chain_type for c in chains]
        assert prohibited_chain_type not in detected_chain_types, (
            f"Near-miss fixture {rel_path} incorrectly fired prohibited chain "
            f"{prohibited_chain_type.value}. Detected chains: {[c.chain_type.value for c in chains]}"
        )


def test_clean_fixtures_produce_no_chains():
    """Verify that safe/clean fixtures produce zero attack chains."""
    correlator = ChainCorrelator()

    safe_fixtures = [
        "tests/fixtures/safe/safe_r001_pinned.yml",
        "tests/fixtures/safe/safe_r002_minimal_perms.yml",
        "tests/fixtures/safe/safe_r003_pr_target_safe.yml",
        "tests/fixtures/safe/safe_r004_safe_script.yml",
        "tests/fixtures/safe/safe_r005_env_secret.yml",
        "tests/fixtures/safe/safe_r006_masked_secret.yml",
        "tests/fixtures/safe/safe_r007_oidc.yml",
        "tests/fixtures/safe/safe_r008_deploy_environment.yml",
        "tests/fixtures/safe/safe_r009_github_runner.yml",
        "tests/fixtures/safe/safe_r010_first_party_action.yml",
        "tests/fixtures/extension/safe/ext_r11_safe.yml",
        "tests/fixtures/extension/safe/ext_r12_safe.yml",
        "tests/fixtures/extension/safe/ext_r13_safe.yml",
        "tests/fixtures/extension/safe/ext_r14_safe.yml",
        "tests/fixtures/extension/safe/ext_r18_safe.yml",
        "tests/fixtures/extension/safe/ext_r25_safe.yml",
        "tests/fixtures/extension/safe/ext_r26_safe.yml",
    ]

    for rel_path in safe_fixtures:
        full_path = BASE_DIR / rel_path
        if not full_path.is_file():
            continue
        wf = load_workflows(full_path)[0].workflow
        assert wf is not None
        findings = default_registry.run_all(wf)
        chains = correlator.correlate(findings, workflow=wf)
        assert len(chains) == 0, (
            f"Safe fixture {rel_path} unexpectedly produced attack chains: "
            f"{[c.chain_type.value for c in chains]}"
        )


def test_multi_chain_membership():
    """Verify that a single shared finding can participate in multiple attack chains."""
    correlator = ChainCorrelator()

    # Synthetic workflow with both Pwn-Request and Script Injection into Exfiltration
    yaml_content = textwrap.dedent("""
        name: Multi Chain Test
        on:
          pull_request_target:
            types: [opened]

        jobs:
          exploit_job:
            runs-on: ubuntu-latest
            steps:
              - name: Untrusted Checkout
                uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - name: Script Injection
                env:
                  MY_SECRET: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "PR title: ${{ github.event.pull_request.title }}"
    """).strip()
    results = load_workflows(yaml_content, file_path="multi_chain.yml")
    if results[0].workflow is None:
        raise AssertionError(f"Parse failed: {[e.message for e in results[0].errors]}")
    wf = results[0].workflow

    findings = default_registry.run_all(wf)
    res = correlator.correlate_workflow(wf, findings)

    chain_types = {c.chain_type for c in res.chains}
    assert ChainType.PWN_REQUEST in chain_types
    assert ChainType.INJECTION_TO_EXFIL in chain_types

    # Find the shared excessive permissions (R002) finding
    r002_findings = [f for f in findings if f.rule_id == "R002"]
    assert len(r002_findings) > 0
    r002_id = r002_findings[0].id

    # Verify R002 is present in finding_ids of both chains
    pwn_chain = next(c for c in res.chains if c.chain_type == ChainType.PWN_REQUEST)
    injection_chain = next(c for c in res.chains if c.chain_type == ChainType.INJECTION_TO_EXFIL)

    assert r002_id in pwn_chain.finding_ids
    assert r002_id in injection_chain.finding_ids


def test_standalone_findings_retained():
    """Verify that findings not participating in any attack chain remain in standalone_findings."""
    correlator = ChainCorrelator()

    yaml_content = textwrap.dedent("""
        name: Standalone Test
        on:
          push:
            branches: [main]
        permissions:
          contents: read

        jobs:
          job_with_chain:
            runs-on: ubuntu-latest
            timeout-minutes: 10
            steps:
              - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
              - uses: acme-corp/build-helper@v3

          unrelated_job:
            runs-on: ubuntu-latest
            timeout-minutes: 10
            steps:
              - name: Step with plaintext secret
                env:
                  STATIC_API_TOKEN: super_secret_production_api_token_value_99999
                run: echo "done"
    """).strip()
    results = load_workflows(yaml_content, file_path="standalone_test.yml")
    wf = results[0].workflow
    assert wf is not None

    findings = default_registry.run_all(wf)
    result: CorrelationResult = correlator.correlate_workflow(wf, findings)

    # R005 (plaintext secret in unrelated_job) is not chained
    r005_findings = [f for f in findings if f.rule_id == "R005"]
    assert len(r005_findings) > 0
    r005_id = r005_findings[0].id

    standalone_ids = {f.id for f in result.standalone_findings}
    assert r005_id in standalone_ids, "Uncorrelated R005 finding was dropped from standalone_findings"


def test_cytoscape_schema_and_validation():
    """Verify that Cytoscape export adheres strictly to data element schema and graph validation rules."""
    chain = Chain(
        id="c-001",
        chain_type=ChainType.PWN_REQUEST,
        finding_ids=["f-r003-0001", "f-r002-0001"],
        job_id="test_job",
        nodes=[
            {"id": "c-001-trigger", "label": "Trigger: PR Target", "category": "trigger"},
            {"id": "c-001-vuln-R003", "label": "R003 Checkout", "category": "misconfiguration", "rule_id": "R003"},
            {"id": "c-001-priv", "label": "Write Token", "category": "privilege"},
            {"id": "c-001-impact", "label": "Repo Compromise", "category": "impact"},
        ],
        edges=[
            {"id": "c-001-e1", "source": "c-001-trigger", "target": "c-001-vuln-R003", "label": "triggers"},
            {"id": "c-001-e2", "source": "c-001-vuln-R003", "target": "c-001-priv", "label": "enables"},
            {"id": "c-001-e3", "source": "c-001-priv", "target": "c-001-impact", "label": "results_in"},
        ],
        narrative="Test narrative",
    )

    graph = AttackGraph.from_chain(chain)
    valid, errors = graph.validate()
    assert valid, f"Expected graph to be valid, got errors: {errors}"

    elements = graph.to_cytoscape_elements()
    assert len(elements) == 7  # 4 nodes + 3 edges

    # Validate elements have data wrapper
    node_data_ids = set()
    for el in elements:
        assert "data" in el
        data = el["data"]
        assert "id" in data
        if "source" in data:
            # Edge
            assert "target" in data
            assert data["source"] in node_data_ids
        else:
            # Node
            assert "category" in data
            assert data["category"] in {"trigger", "misconfiguration", "privilege", "impact"}
            node_data_ids.add(data["id"])

    # Test broken graph validation
    broken_graph = AttackGraph(
        nodes=[{"id": "n1", "label": "Start"}],
        edges=[{"id": "e1", "source": "n1", "target": "missing_node"}],
    )
    is_valid, validation_errors = broken_graph.validate()
    assert not is_valid
    assert any("missing_node" in err for err in validation_errors)


def test_ground_truth_all_corpus_chains():
    """Verify all benchmark ground-truth fixtures pass expected_chains and must_not_have_chains assertions."""
    correlator = ChainCorrelator()

    with open(GROUND_TRUTH_FILE, encoding="utf-8") as f:
        gt = json.load(f)

    for rel_path, meta in gt.get("fixtures", {}).items():
        full_path = BASE_DIR / rel_path
        if not full_path.is_file():
            continue

        wf = load_workflows(full_path)[0].workflow
        if not wf:
            continue

        findings = default_registry.run_all(wf)
        chains = correlator.correlate(findings, workflow=wf)
        detected_types = {c.chain_type.value for c in chains}

        # Check expected chains
        expected_chains = meta.get("expected_chains", [])
        for exp in expected_chains:
            exp_type = exp if isinstance(exp, str) else exp.get("chain_type")
            assert exp_type in detected_types, (
                f"Fixture {rel_path} expected chain '{exp_type}', but detected: {detected_types}"
            )

        # Check must_not_have_chains
        must_not_have = meta.get("must_not_have_chains", [])
        for forbidden in must_not_have:
            assert forbidden not in detected_types, (
                f"Fixture {rel_path} triggered forbidden chain '{forbidden}'! Detected: {detected_types}"
            )
