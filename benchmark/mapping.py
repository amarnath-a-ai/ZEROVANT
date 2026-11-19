"""Rule mapping table between ZEROVANT, Zizmor, and Poutine.

Maps all 30 ZEROVANT static detection rules to their closest equivalents in:
- Zizmor (woodruffw/zizmor)
- Poutine (boostsecurityio/poutine)

Rules with no counterpart in external tools are explicitly marked as "no equivalent"
and reported as coverage differences, rather than false negatives for the other tools.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleMapping:
    """Mapping record connecting ZEROVANT rule to external SAST equivalents."""

    rule_id: str
    name: str
    category: str
    tier: str  # "core" | "extension"
    zizmor_rule: str | None
    poutine_rule: str | None
    notes: str


RULE_MAPPINGS: list[RuleMapping] = [
    # -------------------------------------------------------------------------
    # Core Rules (R001 - R010)
    # -------------------------------------------------------------------------
    RuleMapping(
        rule_id="R001",
        name="unpinned-action",
        category="supply-chain",
        tier="core",
        zizmor_rule="unpinned-uses",
        poutine_rule="unpinnable_action",
        notes="Detects third-party actions referenced by mutable tags or branch names instead of full 40-char commit SHAs.",
    ),
    RuleMapping(
        rule_id="R002",
        name="excessive-permissions",
        category="permissions",
        tier="core",
        zizmor_rule="excessive-permissions",
        poutine_rule="default_permissions_on_risky_events",
        notes="Detects explicit write-all permissions or missing permissions block defaulting to broad read/write scopes.",
    ),
    RuleMapping(
        rule_id="R003",
        name="pr-target-checkout",
        category="injection",
        tier="core",
        zizmor_rule="dangerous-triggers",
        poutine_rule="arbitrary_code_exec",
        notes="Detects pull_request_target trigger combined with explicit checkout of untrusted PR head reference.",
    ),
    RuleMapping(
        rule_id="R004",
        name="script-injection",
        category="injection",
        tier="core",
        zizmor_rule="template-injection",
        poutine_rule="injection_with_external_input",
        notes="Detects direct interpolation of untrusted GitHub event expressions into run: shell scripts.",
    ),
    RuleMapping(
        rule_id="R005",
        name="plaintext-secret",
        category="credentials",
        tier="core",
        zizmor_rule="secrets",
        poutine_rule="job_uses_all_secrets",
        notes="Detects hardcoded high-entropy API tokens, private keys, or credentials embedded directly in YAML.",
    ),
    RuleMapping(
        rule_id="R006",
        name="secret-in-log",
        category="credentials",
        tier="core",
        zizmor_rule="secrets",
        poutine_rule="unverified_script_exec",
        notes="Detects commands that echo or dump secrets and environment variables to standard output/logs.",
    ),
    RuleMapping(
        rule_id="R007",
        name="long-lived-credentials",
        category="credentials",
        tier="core",
        zizmor_rule=None,
        poutine_rule=None,
        notes="Detects static cloud access keys (AWS_ACCESS_KEY_ID, GCP_SA_KEY) instead of OIDC federation.",
    ),
    RuleMapping(
        rule_id="R008",
        name="deploy-environment",
        category="hygiene",
        tier="core",
        zizmor_rule=None,
        poutine_rule=None,
        notes="Detects production deployment commands executing without an explicit GitHub Environment protection rule.",
    ),
    RuleMapping(
        rule_id="R009",
        name="self-hosted-runner",
        category="execution",
        tier="core",
        zizmor_rule="self-hosted-runner",
        poutine_rule="pr_runs_on_self_hosted",
        notes="Detects self-hosted runners executing on public/untrusted pull request events.",
    ),
    RuleMapping(
        rule_id="R010",
        name="third-party-action",
        category="supply-chain",
        tier="core",
        zizmor_rule="unpinned-uses",
        poutine_rule="github_action_from_unverified_creator",
        notes="Detects third-party actions from unverified publishers outside GitHub/Docker official namespaces.",
    ),
    # -------------------------------------------------------------------------
    # Extension Rules (persist-credentials through known-vulnerable-action)
    # -------------------------------------------------------------------------
    RuleMapping(
        rule_id="persist-credentials",
        name="persist-credentials",
        category="credentials",
        tier="extension",
        zizmor_rule="artipacked",
        poutine_rule=None,
        notes="Detects actions/checkout without persist-credentials: false leaving GitHub tokens on disk.",
    ),
    RuleMapping(
        rule_id="secret-to-unpinned-action",
        name="secret-to-unpinned-action",
        category="supply-chain",
        tier="extension",
        zizmor_rule="unpinned-uses",
        poutine_rule=None,
        notes="Detects sensitive repository secrets passed directly into an unpinned third-party action step.",
    ),
    RuleMapping(
        rule_id="overprovisioned-secrets",
        name="overprovisioned-secrets",
        category="credentials",
        tier="extension",
        zizmor_rule="overprovisioned-secrets",
        poutine_rule="job_uses_all_secrets",
        notes="Detects jobs referencing more than three distinct repository secrets.",
    ),
    RuleMapping(
        rule_id="artifact-leak",
        name="artifact-leak",
        category="credentials",
        tier="extension",
        zizmor_rule="artipacked",
        poutine_rule=None,
        notes="Detects upload-artifact storing sensitive files (.env, id_rsa, credentials, keys).",
    ),
    RuleMapping(
        rule_id="secrets-inherit",
        name="secrets-inherit",
        category="credentials",
        tier="extension",
        zizmor_rule="secrets-inherit",
        poutine_rule="job_uses_all_secrets",
        notes="Detects reusable workflow call passing secrets: inherit without fine-grained scoping.",
    ),
    RuleMapping(
        rule_id="github-env-injection",
        name="github-env-injection",
        category="injection",
        tier="extension",
        zizmor_rule="env-injection",
        poutine_rule="injection_with_external_input",
        notes="Detects writing untrusted attacker input into GITHUB_ENV or GITHUB_PATH files.",
    ),
    RuleMapping(
        rule_id="workflow-run-untrusted-artifact",
        name="workflow-run-untrusted-artifact",
        category="supply-chain",
        tier="extension",
        zizmor_rule="dangerous-triggers",
        poutine_rule="arbitrary_code_exec",
        notes="Detects privileged workflow_run trigger downloading artifacts from untrusted workflow execution.",
    ),
    RuleMapping(
        rule_id="comment-trigger-no-auth",
        name="comment-trigger-no-auth",
        category="execution",
        tier="extension",
        zizmor_rule="dangerous-triggers",
        poutine_rule="default_permissions_on_risky_events",
        notes="Detects issue_comment workflows executing commands without verifying commenter membership/privilege.",
    ),
    RuleMapping(
        rule_id="dispatch-input-injection",
        name="dispatch-input-injection",
        category="injection",
        tier="extension",
        zizmor_rule="template-injection",
        poutine_rule="injection_with_external_input",
        notes="Detects workflow_dispatch inputs evaluated directly inside run: shell scripts.",
    ),
    RuleMapping(
        rule_id="bot-actor-spoofing",
        name="bot-actor-spoofing",
        category="injection",
        tier="extension",
        zizmor_rule="bot-conditions",
        poutine_rule="confused_deputy_automerge",
        notes="Detects spoofable bot actor checks (e.g. github.actor == 'dependabot[bot]') without trigger checks.",
    ),
    RuleMapping(
        rule_id="unpinned-reusable-workflow",
        name="unpinned-reusable-workflow",
        category="supply-chain",
        tier="extension",
        zizmor_rule="unpinned-uses",
        poutine_rule="unpinnable_action",
        notes="Detects external reusable workflow called with mutable branch or tag instead of immutable commit SHA.",
    ),
    RuleMapping(
        rule_id="unpinned-docker-image",
        name="unpinned-docker-image",
        category="supply-chain",
        tier="extension",
        zizmor_rule="unpinned-uses",
        poutine_rule=None,
        notes="Detects container action or job container using mutable Docker tag (e.g. :latest) without SHA256 digest.",
    ),
    RuleMapping(
        rule_id="curl-pipe-shell",
        name="curl-pipe-shell",
        category="execution",
        tier="extension",
        zizmor_rule=None,
        poutine_rule="unverified_script_exec",
        notes="Detects downloading and executing remote scripts in a single command (curl | bash).",
    ),
    RuleMapping(
        rule_id="insecure-commands-enabled",
        name="insecure-commands-enabled",
        category="execution",
        tier="extension",
        zizmor_rule="insecure-commands",
        poutine_rule=None,
        notes="Detects ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable enabling legacy set-env commands.",
    ),
    RuleMapping(
        rule_id="cache-poisoning-risk",
        name="cache-poisoning-risk",
        category="supply-chain",
        tier="extension",
        zizmor_rule="cache-poisoning",
        poutine_rule=None,
        notes="Detects actions/cache saving cache keys with untrusted user expressions or PR refs.",
    ),
    RuleMapping(
        rule_id="oidc-write-untrusted",
        name="oidc-write-untrusted",
        category="permissions",
        tier="extension",
        zizmor_rule="excessive-permissions",
        poutine_rule="default_permissions_on_risky_events",
        notes="Detects id-token: write permission granted on untrusted fork triggers (pull_request_target).",
    ),
    RuleMapping(
        rule_id="permissions-overbroad-job",
        name="permissions-overbroad-job",
        category="permissions",
        tier="extension",
        zizmor_rule="excessive-permissions",
        poutine_rule="default_permissions_on_risky_events",
        notes="Detects job requesting more than four distinct write permission scopes.",
    ),
    RuleMapping(
        rule_id="continue-on-error-security-step",
        name="continue-on-error-security-step",
        category="hygiene",
        tier="extension",
        zizmor_rule=None,
        poutine_rule=None,
        notes="Detects continue-on-error: true set on security scanning, linting, or verification steps.",
    ),
    RuleMapping(
        rule_id="missing-timeout",
        name="missing-timeout",
        category="hygiene",
        tier="extension",
        zizmor_rule=None,
        poutine_rule=None,
        notes="Detects jobs without timeout-minutes configured, exposing runners to 6-hour execution hang attacks.",
    ),
    RuleMapping(
        rule_id="known-vulnerable-action",
        name="known-vulnerable-action",
        category="supply-chain",
        tier="extension",
        zizmor_rule="known-vulnerable-actions",
        poutine_rule="build_component_with_known_vulnerability",
        notes="Detects usage of action versions with known published GitHub Security Advisories.",
    ),
]


def get_rule_mapping(rule_id: str) -> RuleMapping | None:
    """Retrieve mapping record by ZEROVANT rule ID."""
    for m in RULE_MAPPINGS:
        if m.rule_id == rule_id:
            return m
    return None


def get_all_mappings() -> list[RuleMapping]:
    """Retrieve all 30 rule mappings."""
    return list(RULE_MAPPINGS)


def zizmor_rule_to_zerovant_rules(zizmor_ident: str) -> list[str]:
    """Map a Zizmor audit identifier to one or more corresponding ZEROVANT rule IDs."""
    ident = zizmor_ident.strip().lower()
    matches = []
    for m in RULE_MAPPINGS:
        if m.zizmor_rule and m.zizmor_rule.lower() == ident:
            matches.append(m.rule_id)
    if ident == "secrets" and "overprovisioned-secrets" not in matches:
        matches.append("overprovisioned-secrets")
    return matches


def poutine_rule_to_zerovant_rules(poutine_rule: str) -> list[str]:
    """Map a Poutine rule name to one or more corresponding ZEROVANT rule IDs."""
    p_rule = poutine_rule.strip().lower()
    matches = []
    for m in RULE_MAPPINGS:
        if m.poutine_rule and m.poutine_rule.lower() == p_rule:
            matches.append(m.rule_id)
    return matches


def export_mapping_csv(output_path: str = "benchmark/results/mapping.csv") -> None:
    """Export the 30-rule mapping table to a CSV file."""
    import csv
    from pathlib import Path

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ZEROVANT_Rule_ID",
            "Rule_Name",
            "Category",
            "Tier",
            "Zizmor_Equivalent",
            "Poutine_Equivalent",
            "Notes",
        ])
        for m in RULE_MAPPINGS:
            writer.writerow([
                m.rule_id,
                m.name,
                m.category,
                m.tier,
                m.zizmor_rule or "no equivalent",
                m.poutine_rule or "no equivalent",
                m.notes,
            ])

