"""Attack chain models and declarative multi-stage correlation engine."""

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.parser.model import Job, Workflow
from app.rules.base import Finding


class ChainType(str, Enum):
    """Catalog of known attack-chain templates (5 core + 5 extension)."""

    PWN_REQUEST = "pwn-request"
    INJECTION_TO_EXFIL = "injection-to-exfil"
    SUPPLY_CHAIN_TAKEOVER = "supply-chain-takeover"
    DEPLOY_BLAST_RADIUS = "deploy-blast-radius"
    RUNNER_PERSISTENCE = "runner-persistence"
    ARTIFACT_POISONING = "artifact-poisoning"
    COMMENT_TRIGGER_TAKEOVER = "comment-trigger-takeover"
    CREDENTIAL_PERSISTENCE = "credential-persistence"
    CACHE_POISONING_ESCALATION = "cache-poisoning-escalation"
    OIDC_ABUSE = "oidc-abuse"


@dataclass
class Chain:
    """A correlated multi-stage attack chain combining multiple discrete findings."""

    id: str  # e.g. 'c-001'
    chain_type: ChainType
    finding_ids: list[str] = field(default_factory=list)
    job_id: str | None = None
    jobs: list[str] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    narrative: str = ""
    chain_score: float | None = None  # None until Phase 4 scoring

    def to_dict(self) -> dict[str, Any]:
        """Serialize attack chain to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "chain_type": self.chain_type.value if isinstance(self.chain_type, Enum) else str(self.chain_type),
            "finding_ids": list(self.finding_ids),
            "job_id": self.job_id,
            "jobs": list(self.jobs),
            "nodes": self.nodes,
            "edges": self.edges,
            "narrative": self.narrative,
            "chain_score": self.chain_score,
        }


@dataclass
class CorrelationResult:
    """Full outcome of attack chain correlation including chains and standalone findings."""

    chains: list[Chain] = field(default_factory=list)
    standalone_findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize correlation result to JSON-serializable dictionary."""
        return {
            "chains": [c.to_dict() for c in self.chains],
            "standalone_findings": [f.to_dict() for f in self.standalone_findings],
        }


UNTRUSTED_TRIGGERS = {
    "pull_request",
    "pull_request_target",
    "issues",
    "issue_comment",
    "pull_request_review_comment",
    "pull_request_review",
    "fork",
    "discussion",
    "discussion_comment",
}


@dataclass
class JobContext:
    """Security context extracted from a Job and its parent Workflow."""

    job_id: str
    job: Job | None
    workflow: Workflow | None
    findings: list[Finding] = field(default_factory=list)
    triggers: dict[str, Any] = field(default_factory=dict)
    has_untrusted_trigger: bool = False
    has_pr_target: bool = False
    has_workflow_run: bool = False
    has_comment_trigger: bool = False
    has_write_permissions: bool = False
    has_contents_write: bool = False
    has_oidc_write: bool = False
    has_secrets_reachable: bool = False
    is_deploy_like: bool = False
    is_self_hosted: bool = False

    def has_finding(self, rule_id: str) -> bool:
        """Check if any finding in this context matches the specified rule_id."""
        return any(f.rule_id == rule_id for f in self.findings)

    def get_findings(self, rule_id: str) -> list[Finding]:
        """Retrieve all findings matching the given rule_id."""
        return [f for f in self.findings if f.rule_id == rule_id]

    @classmethod
    def from_job_and_workflow(
        cls,
        job_id: str,
        job: Job | None,
        workflow: Workflow | None,
        all_findings: list[Finding],
    ) -> "JobContext":
        """Build JobContext by analyzing the workflow AST and findings."""
        # Findings scoped to this job or workflow-level findings (job is None)
        job_findings = [
            f for f in all_findings
            if f.job == job_id or f.job is None or f.job == ""
        ]

        triggers = workflow.triggers if workflow and workflow.triggers else {}
        trigger_keys = set(triggers.keys())

        has_untrusted = bool(trigger_keys.intersection(UNTRUSTED_TRIGGERS))
        has_pr_target = "pull_request_target" in trigger_keys
        has_wf_run = "workflow_run" in trigger_keys
        has_comment = bool(trigger_keys.intersection({"issue_comment", "pull_request_review_comment"}))

        # Check write permissions
        has_write = False
        has_contents_write = False
        has_oidc_write = False

        # Permissions check helper
        def inspect_perms(perms_val: Any) -> tuple[bool, bool, bool]:
            w, cw, ow = False, False, False
            if perms_val == "write-all":
                w, cw, ow = True, True, True
            elif isinstance(perms_val, dict):
                for k, v in perms_val.items():
                    if str(v).lower() == "write":
                        w = True
                        if k == "contents":
                            cw = True
                        elif k == "id-token":
                            ow = True
            return w, cw, ow

        if job and job.permissions is not None:
            has_write, has_contents_write, has_oidc_write = inspect_perms(job.permissions)
        elif workflow and workflow.permissions is not None:
            has_write, has_contents_write, has_oidc_write = inspect_perms(workflow.permissions)
        else:
            # Default GitHub Actions behavior when permissions block is omitted: write-all
            has_write = True
            has_contents_write = True

        # Finding R002 / permissions-overbroad-job also implies write permissions
        if any(f.rule_id in ("R002", "permissions-overbroad-job") for f in job_findings):
            has_write = True

        # Reachable secrets check
        has_secrets = False
        secret_rules = {
            "R005", "R006", "R007", "secret-to-unpinned-action",
            "overprovisioned-secrets", "secrets-inherit"
        }
        if any(f.rule_id in secret_rules for f in job_findings):
            has_secrets = True

        # Inspect AST for secrets expressions if not already found (excluding standard GITHUB_TOKEN)
        if not has_secrets:
            secret_pat = re.compile(r"\$\{\{\s*secrets\.(?!github_token\b)[\w-]+\s*\}\}", re.IGNORECASE)

            def check_val(val: Any) -> bool:
                if isinstance(val, str) and secret_pat.search(val):
                    return True
                if isinstance(val, dict):
                    return any(check_val(v) for v in val.values())
                if isinstance(val, list):
                    return any(check_val(item) for item in val)
                return False

            if workflow and workflow.env and check_val(workflow.env):
                has_secrets = True
            if not has_secrets and job:
                if job.env and check_val(job.env):
                    has_secrets = True
                if not has_secrets and job.secrets is not None:
                    has_secrets = True
                if not has_secrets:
                    for st in job.steps:
                        if (
                            check_val(st.env)
                            or check_val(st.with_params)
                            or (st.run and secret_pat.search(st.run))
                        ):
                            has_secrets = True
                            break

        # Deploy-like check
        is_deploy = False
        if any(f.rule_id == "R008" for f in job_findings):
            is_deploy = True
        elif job:
            if job.environment is not None:
                is_deploy = True
            elif re.search(r"(deploy|release|publish|production|prod|staging)", f"{job_id} {job.name}", re.I):
                is_deploy = True

        # Self-hosted check
        is_self_hosted = False
        if any(f.rule_id == "R009" for f in job_findings):
            is_self_hosted = True
        elif job and job.runs_on:
            runs_str = str(job.runs_on).lower()
            if "self-hosted" in runs_str:
                is_self_hosted = True

        return cls(
            job_id=job_id,
            job=job,
            workflow=workflow,
            findings=job_findings,
            triggers=triggers,
            has_untrusted_trigger=has_untrusted,
            has_pr_target=has_pr_target,
            has_workflow_run=has_wf_run,
            has_comment_trigger=has_comment,
            has_write_permissions=has_write,
            has_contents_write=has_contents_write,
            has_oidc_write=has_oidc_write,
            has_secrets_reachable=has_secrets,
            is_deploy_like=is_deploy,
            is_self_hosted=is_self_hosted,
        )


@dataclass
class ChainDefinition:
    """Declarative definition of an attack chain pattern."""

    chain_type: ChainType
    name: str
    scope: str  # "job"
    required_rules: list[str]
    secondary_rules: list[str]
    predicate: Callable[[JobContext], bool]
    narrative_template: str
    trigger_label: str
    privilege_label: str
    impact_label: str


def _build_pwn_request_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "The workflow executes on 'pull_request_target' and checks out untrusted code from "
        "the pull request head commit (R003) while running with elevated write permissions "
        "or repository secrets (R002). An external adversary can submit a pull request modifying "
        "build scripts or tests to execute arbitrary code within the base repository context, "
        "leading to repository compromise or secret exfiltration."
    )


def _build_injection_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "Untrusted external event input (e.g. issue or PR title/body) is interpolated directly "
        "into a shell script via inline expression (R004) in a job with reachable repository secrets. "
        "An attacker can craft a malicious issue or PR payload containing shell command substitutions "
        "to exfiltrate secrets to an external server."
    )


def _build_supply_chain_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "The job invokes an unpinned third-party action (R001, R010) while executing with write "
        "permissions or access to sensitive credentials. If the upstream action author's account "
        "is hijacked or the mutable tag/branch is altered, malicious payloads will run with "
        "the job's elevated permissions to tamper with releases, artifacts, or code."
    )


def _build_deploy_blast_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "A deployment job lacks environment protection rules or manual approval gates (R008) "
        "and utilizes long-lived static cloud credentials (R007). Unreviewed pull requests "
        "or unauthorized branch pushes can directly trigger production deployments and risk "
        "leaking persistent cloud credentials."
    )


def _build_runner_persistence_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "A persistent self-hosted runner executes workflows triggered by untrusted external events (R009). "
        "An external contributor can execute malicious code that establishes host backdoors, "
        "persists malicious binaries across builds, or pivots laterally into the internal corporate network."
    )


def _build_artifact_poisoning_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "A privileged workflow triggered by 'workflow_run' downloads and unpacks an untrusted "
        "build artifact generated by a fork pull request (workflow-run-untrusted-artifact) in a context "
        "with write permissions or secrets. The untrusted artifact can contain malicious executable "
        "binaries or scripts that execute with base repository privileges."
    )


def _build_comment_trigger_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "A workflow triggered by comments (issue_comment or pull_request_review_comment) executes "
        "privileged actions without verifying that the commenter is an authorized repository owner "
        "or member (comment-trigger-no-auth). Any external user can comment on a public issue "
        "to trigger commands, deploy jobs, or execute arbitrary code via script injection."
    )


def _build_credential_persistence_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "The job executes actions/checkout without setting 'persist-credentials: false' (persist-credentials), "
        "leaving a live GITHUB_TOKEN inside .git/config on disk. Subsequent execution of third-party actions "
        "(R010/R001) or artifact uploads (artifact-leak) can harvest or leak the persistent git credentials."
    )


def _build_cache_poisoning_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "The job restores dependency caches using actions/cache or package manager cache keys that can "
        "be poisoned from unprivileged branches or pull requests (cache-poisoning-risk). In a privileged "
        "or deployment context, the poisoned cache injects malicious build dependencies into release binaries "
        "or production deployments."
    )


def _build_oidc_abuse_narrative(ctx: JobContext, findings: list[Finding]) -> str:
    return (
        "The workflow requests OpenID Connect cloud tokens (id-token: write) in an untrusted trigger "
        "context or paired with unpinned actions (oidc-write-untrusted, R001). A compromised action "
        "or untrusted execution context can intercept the temporary OIDC token to authenticate directly "
        "against AWS, GCP, or Azure cloud infrastructure."
    )


CHAIN_DEFINITIONS: list[ChainDefinition] = [
    ChainDefinition(
        chain_type=ChainType.PWN_REQUEST,
        name="Pwn-Request via Pull Request Target",
        scope="job",
        required_rules=["R003"],
        secondary_rules=["R002", "R004", "missing-timeout"],
        predicate=lambda ctx: ctx.has_pr_target and (
            ctx.has_write_permissions or ctx.has_secrets_reachable or ctx.has_finding("R002")
        ),
        narrative_template="",
        trigger_label="pull_request_target (External Contributor)",
        privilege_label="Elevated Repository Permissions (write-all token)",
        impact_label="Full Repository Compromise & Arbitrary Code Execution",
    ),
    ChainDefinition(
        chain_type=ChainType.INJECTION_TO_EXFIL,
        name="Untrusted Input Script Injection to Secret Exfiltration",
        scope="job",
        required_rules=["R004"],
        secondary_rules=["R002", "R005", "R006", "R007", "permissions-overbroad-job", "missing-timeout"],
        predicate=lambda ctx: ctx.has_secrets_reachable,
        narrative_template="",
        trigger_label="Untrusted Event Payload (issues/pull_request)",
        privilege_label="Reachable Repository Secrets in Job Scope",
        impact_label="Secret Exfiltration & Credential Compromise",
    ),
    ChainDefinition(
        chain_type=ChainType.SUPPLY_CHAIN_TAKEOVER,
        name="Supply-Chain Takeover via Unpinned Third-Party Action",
        scope="job",
        required_rules=["R001", "R010"],
        secondary_rules=["R002", "permissions-overbroad-job", "persist-credentials", "secret-to-unpinned-action", "missing-timeout"],
        predicate=lambda ctx: ctx.has_write_permissions or ctx.has_finding("R002") or ctx.has_secrets_reachable,
        narrative_template="",
        trigger_label="Workflow Execution (push/schedule)",
        privilege_label="Elevated Repository Write Permissions",
        impact_label="Supply Chain Compromise & Backdoored Artifacts",
    ),
    ChainDefinition(
        chain_type=ChainType.DEPLOY_BLAST_RADIUS,
        name="Deploy Blast Radius via Unprotected Environment",
        scope="job",
        required_rules=["R008"],
        secondary_rules=["R007", "R001", "R002", "missing-timeout"],
        predicate=lambda ctx: ctx.has_finding("R007") or ctx.has_secrets_reachable,
        narrative_template="",
        trigger_label="Automated Commit / Branch Push",
        privilege_label="Long-Lived Static Cloud Credentials (R007)",
        impact_label="Unauthorized Production Deployment & Blast Radius",
    ),
    ChainDefinition(
        chain_type=ChainType.RUNNER_PERSISTENCE,
        name="Host Runner Persistence on Untrusted Workload",
        scope="job",
        required_rules=["R009"],
        secondary_rules=["R002", "R004", "missing-timeout"],
        predicate=lambda ctx: ctx.has_untrusted_trigger,
        narrative_template="",
        trigger_label="Untrusted Trigger (pull_request/issues)",
        privilege_label="Persistent Host Runner Daemon Infrastructure",
        impact_label="Host Persistence, Lateral Movement & Node Takeover",
    ),
    ChainDefinition(
        chain_type=ChainType.ARTIFACT_POISONING,
        name="Artifact Poisoning via Untrusted Workflow Run",
        scope="job",
        required_rules=["workflow-run-untrusted-artifact"],
        secondary_rules=["R002", "permissions-overbroad-job", "missing-timeout"],
        predicate=lambda ctx: ctx.has_write_permissions or ctx.has_secrets_reachable or ctx.has_finding("R002"),
        narrative_template="",
        trigger_label="workflow_run Event (Completed Untrusted Build)",
        privilege_label="Privileged Base Repo Permissions & Secrets",
        impact_label="Privilege Escalation & Malicious Artifact Execution",
    ),
    ChainDefinition(
        chain_type=ChainType.COMMENT_TRIGGER_TAKEOVER,
        name="Comment Trigger Takeover without Authorization",
        scope="job",
        required_rules=["comment-trigger-no-auth"],
        secondary_rules=["R004", "R002", "permissions-overbroad-job", "missing-timeout"],
        predicate=lambda ctx: ctx.has_finding("R004") or ctx.has_write_permissions or ctx.has_secrets_reachable or ctx.has_finding("R002"),
        narrative_template="",
        trigger_label="issue_comment / review_comment Event",
        privilege_label="Write Token & Bot Execution Context",
        impact_label="Unauthorized Bot Hijack & Script Execution",
    ),
    ChainDefinition(
        chain_type=ChainType.CREDENTIAL_PERSISTENCE,
        name="Git Credential Persistence to Action/Artifact Leak",
        scope="job",
        required_rules=["persist-credentials"],
        secondary_rules=["R010", "R001", "artifact-leak", "missing-timeout"],
        predicate=lambda ctx: ctx.has_finding("R010") or ctx.has_finding("R001") or ctx.has_finding("artifact-leak"),
        narrative_template="",
        trigger_label="Workflow Checkout Execution",
        privilege_label="Stored GITHUB_TOKEN in local .git/config",
        impact_label="Repository Token Exfiltration by Third Party",
    ),
    ChainDefinition(
        chain_type=ChainType.CACHE_POISONING_ESCALATION,
        name="Cache Poisoning Escalation to Privileged Build",
        scope="job",
        required_rules=["cache-poisoning-risk"],
        secondary_rules=["R008", "R002", "permissions-overbroad-job", "missing-timeout"],
        predicate=lambda ctx: ctx.is_deploy_like or ctx.has_secrets_reachable or ctx.has_write_permissions or ctx.has_finding("R002") or ctx.has_finding("R008"),
        narrative_template="",
        trigger_label="Privileged Release / Deploy Workflow",
        privilege_label="Shared Cache Key Namespace Access",
        impact_label="Build Dependency Poisoning & Backdoored Releases",
    ),
    ChainDefinition(
        chain_type=ChainType.OIDC_ABUSE,
        name="OpenID Connect Cloud Token Abuse",
        scope="job",
        required_rules=["oidc-write-untrusted"],
        secondary_rules=["R001", "R010", "R004", "R008", "permissions-overbroad-job", "missing-timeout"],
        predicate=lambda ctx: ctx.has_finding("R001") or ctx.has_finding("R010") or ctx.has_finding("R004") or ctx.has_finding("R008") or ctx.has_untrusted_trigger,
        narrative_template="",
        trigger_label="Untrusted Trigger / Untrusted Action Context",
        privilege_label="Cloud Identity Federation (id-token: write)",
        impact_label="Cloud Account Compromise (AWS/GCP/Azure Assume-Role)",
    ),
]


NARRATIVE_BUILDERS = {
    ChainType.PWN_REQUEST: _build_pwn_request_narrative,
    ChainType.INJECTION_TO_EXFIL: _build_injection_narrative,
    ChainType.SUPPLY_CHAIN_TAKEOVER: _build_supply_chain_narrative,
    ChainType.DEPLOY_BLAST_RADIUS: _build_deploy_blast_narrative,
    ChainType.RUNNER_PERSISTENCE: _build_runner_persistence_narrative,
    ChainType.ARTIFACT_POISONING: _build_artifact_poisoning_narrative,
    ChainType.COMMENT_TRIGGER_TAKEOVER: _build_comment_trigger_narrative,
    ChainType.CREDENTIAL_PERSISTENCE: _build_credential_persistence_narrative,
    ChainType.CACHE_POISONING_ESCALATION: _build_cache_poisoning_narrative,
    ChainType.OIDC_ABUSE: _build_oidc_abuse_narrative,
}


def build_chain_graph(
    chain_id: str,
    definition: ChainDefinition,
    ctx: JobContext,
    chain_findings: list[Finding],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Construct schema-compliant Cytoscape nodes and edges for an attack chain."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    # Node 1: Trigger
    trigger_node_id = f"{chain_id}-trigger"
    trigger_label = definition.trigger_label
    if ctx.triggers:
        trig_names = ", ".join(ctx.triggers.keys())
        trigger_label = f"Trigger: {trig_names}"
    nodes.append({
        "id": trigger_node_id,
        "label": trigger_label,
        "category": "trigger",
        "job": ctx.job_id,
    })

    # Nodes for Component Misconfigurations
    prev_node_id = trigger_node_id
    edge_idx = 1

    for f in chain_findings:
        misconfig_node_id = f"{chain_id}-vuln-{f.rule_id}-{f.line}"
        nodes.append({
            "id": misconfig_node_id,
            "label": f"{f.rule_id}: {f.title}",
            "category": "misconfiguration",
            "finding_id": f.id,
            "rule_id": f.rule_id,
            "job": ctx.job_id,
            "line": f.line,
            "severity": f.severity.value if isinstance(f.severity, Enum) else str(f.severity),
        })
        edges.append({
            "id": f"{chain_id}-e{edge_idx}",
            "source": prev_node_id,
            "target": misconfig_node_id,
            "label": "triggers" if prev_node_id == trigger_node_id else "escalates_with",
        })
        edge_idx += 1
        prev_node_id = misconfig_node_id

    # Node: Privilege
    priv_node_id = f"{chain_id}-privilege"
    nodes.append({
        "id": priv_node_id,
        "label": definition.privilege_label,
        "category": "privilege",
        "job": ctx.job_id,
    })
    edges.append({
        "id": f"{chain_id}-e{edge_idx}",
        "source": prev_node_id,
        "target": priv_node_id,
        "label": "enables_access",
    })
    edge_idx += 1

    # Node: Impact
    impact_node_id = f"{chain_id}-impact"
    nodes.append({
        "id": impact_node_id,
        "label": definition.impact_label,
        "category": "impact",
        "job": ctx.job_id,
    })
    edges.append({
        "id": f"{chain_id}-e{edge_idx}",
        "source": priv_node_id,
        "target": impact_node_id,
        "label": "results_in",
    })

    return nodes, edges


class ChainCorrelator:
    """Correlates individual findings across a workflow or repo into multi-stage attack chains."""

    def __init__(self, definitions: list[ChainDefinition] | None = None):
        self.definitions = definitions or CHAIN_DEFINITIONS

    def correlate(
        self,
        findings: list[Finding],
        workflow: Workflow | None = None,
    ) -> list[Chain]:
        """Analyze findings and discover correlated attack chains.

        Parameters:
            findings: List of static analysis findings to correlate.
            workflow: Optional Workflow AST object providing rich trigger and job context.
        """
        result = self.correlate_workflow(workflow, findings)
        return result.chains

    def correlate_workflow(
        self,
        workflow: Workflow | None,
        findings: list[Finding],
    ) -> CorrelationResult:
        """Correlate findings against workflow jobs, returning chains and standalone findings."""
        if not findings:
            return CorrelationResult(chains=[], standalone_findings=[])

        # Group jobs to inspect
        job_ids: set[str] = set()
        if workflow and workflow.jobs:
            job_ids.update(workflow.jobs.keys())
        else:
            for f in findings:
                if f.job:
                    job_ids.add(f.job)
        if not job_ids:
            job_ids.add("default_job")

        discovered_chains: list[Chain] = []
        chain_counter = 1
        all_correlated_finding_ids: set[str] = set()

        for j_id in sorted(job_ids):
            job_obj = workflow.jobs.get(j_id) if workflow and workflow.jobs else None
            ctx = JobContext.from_job_and_workflow(j_id, job_obj, workflow, findings)

            for definition in self.definitions:
                # Check required rules
                has_all_required = all(ctx.has_finding(r_id) for r_id in definition.required_rules)
                if not has_all_required:
                    continue

                # Evaluate contextual predicate
                if not definition.predicate(ctx):
                    continue

                # Gather findings participating in this chain
                chain_findings: list[Finding] = []
                for r_id in definition.required_rules:
                    chain_findings.extend(ctx.get_findings(r_id))
                for r_id in definition.secondary_rules:
                    chain_findings.extend(ctx.get_findings(r_id))

                # Deduplicate findings preserving order
                unique_findings: list[Finding] = []
                seen_ids: set[str] = set()
                for f in chain_findings:
                    if f.id not in seen_ids:
                        seen_ids.add(f.id)
                        unique_findings.append(f)

                chain_id = f"c-{chain_counter:03d}"
                chain_counter += 1

                nodes, edges = build_chain_graph(chain_id, definition, ctx, unique_findings)
                narrative_fn = NARRATIVE_BUILDERS.get(definition.chain_type)
                narrative = narrative_fn(ctx, unique_findings) if narrative_fn else ""

                finding_id_list = [f.id for f in unique_findings]
                all_correlated_finding_ids.update(finding_id_list)

                chain = Chain(
                    id=chain_id,
                    chain_type=definition.chain_type,
                    finding_ids=finding_id_list,
                    job_id=j_id if j_id != "default_job" else None,
                    jobs=[j_id] if j_id != "default_job" else [],
                    nodes=nodes,
                    edges=edges,
                    narrative=narrative,
                    chain_score=None,
                )
                discovered_chains.append(chain)

        # Standalone findings are findings not part of any discovered attack chain
        standalone = [f for f in findings if f.id not in all_correlated_finding_ids]

        return CorrelationResult(chains=discovered_chains, standalone_findings=standalone)
