"""Pipeline orchestrator: wires ingestion -> parsing -> rules -> correlation -> scoring -> explainability -> storage."""

from pathlib import Path

from app.correlation import ChainCorrelator
from app.explain import RemediationExplainer
from app.ingest import GitHubClient
from app.parser import load_workflows
from app.parser.model import Workflow
from app.rules import default_registry
from app.rules.base import Finding
from app.scoring.scorer import compute_scores
from app.storage.repository import ScanRepository, synthetic_repo_identity


def run_scan(
    source: str | Path,
    source_type: str = "auto",
    repo_name: str | None = None,
    repo_url: str | None = None,
    commit_sha: str | None = None,
    ref: str | None = None,
    db_path: str | Path | None = None,
    repository: ScanRepository | None = None,
    use_llm: bool = False,
    anthropic_api_key: str | None = None,
) -> str:
    """Execute complete end-to-end audit scan and persist results to the database.

    Data flow:
    User input -> Ingestion -> Parser -> Rule engine -> Attack-chain correlation
    -> Deterministic risk scoring -> Remediation explainability -> SQLite Storage.

    Args:
        source: File path, directory path, GitHub repo (owner/repo), or raw YAML string.
        source_type: 'auto', 'local_directory', 'pasted_yaml', or 'github_repo'.
        repo_name: Optional explicit name for the repository.
        repo_url: Optional explicit URL for the repository.
        commit_sha: Optional commit hash.
        ref: Optional git reference (branch or tag).
        db_path: Optional path to SQLite database.
        repository: Optional initialized ScanRepository instance.
        use_llm: Whether to enrich explanations with LLM if key is configured.
        anthropic_api_key: Optional Anthropic API key.

    Returns:
        The stored scan_id.
    """
    workflows: list[Workflow] = []
    resolved_source_type = source_type

    # 1. Ingestion & Source Resolution
    if source_type == "auto":
        if isinstance(source, Path):
            resolved_source_type = "local_directory"
        elif isinstance(source, str):
            p = Path(source)
            if p.exists():
                resolved_source_type = "local_directory"
            elif "\n" in source or source.strip().startswith("name:") or "jobs:" in source or "on:" in source:
                resolved_source_type = "pasted_yaml"
            elif "/" in source and not source.startswith("/"):
                resolved_source_type = "github_repo"
            else:
                resolved_source_type = "local_directory"

    if resolved_source_type == "github_repo":
        target_name = repo_name or str(source)
        target_url = repo_url or (
            target_name if target_name.startswith("http") else f"https://github.com/{target_name}"
        )
        client = GitHubClient()
        workflow_tuples = client.fetch_workflows(target_name)
        for fp, content in workflow_tuples:
            results = load_workflows(content, file_path=fp)
            for res in results:
                if res.is_valid and res.workflow:
                    workflows.append(res.workflow)
    elif resolved_source_type == "pasted_yaml":
        synth_name, synth_url = synthetic_repo_identity("pasted_yaml", str(source))
        target_name = repo_name or synth_name
        target_url = repo_url or synth_url
        results = load_workflows(str(source), file_path="pasted.yml")
        for res in results:
            if res.is_valid and res.workflow:
                workflows.append(res.workflow)
    else:  # local_directory or local file
        synth_name, synth_url = synthetic_repo_identity("local_directory", str(source))
        target_name = repo_name or synth_name
        target_url = repo_url or synth_url
        p = Path(source)
        if p.exists():
            results = load_workflows(p)
            for res in results:
                if res.is_valid and res.workflow:
                    workflows.append(res.workflow)

    # 2. Rule evaluation (all 30 rules)
    findings: list[Finding] = []
    seen_ids: set[str] = set()
    for wf in workflows:
        wf_findings = default_registry.run_all(wf)
        for f in wf_findings:
            if f.id in seen_ids:
                wf_stem = Path(wf.file_path).stem if wf.file_path else "wf"
                f.id = f"{f.id}-{wf_stem}"
            seen_ids.add(f.id)
        findings.extend(wf_findings)

    # 3. Attack chain correlation
    correlator = ChainCorrelator()
    chains = []
    for wf in workflows:
        wf_findings = [f for f in findings if f.file == wf.file_path]
        correlated_chains = correlator.correlate(wf_findings, workflow=wf)
        chains.extend(correlated_chains)

    # 4. Deterministic risk scoring
    scoring_result = compute_scores(findings, chains, workflows)
    repo_score = scoring_result.repo_score
    if repo_score >= 75.0:
        risk_level = "CRITICAL"
    elif repo_score >= 50.0:
        risk_level = "HIGH"
    elif repo_score >= 25.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # 5. Explainability & Remediation
    explainer = RemediationExplainer(anthropic_api_key=anthropic_api_key if use_llm else None)
    scan_explanation = explainer.explain_all(findings, chains, workflows)

    # 6. Database Storage
    repo_mgr = repository or ScanRepository(db_path=db_path)
    repo_id = repo_mgr.get_or_create_repo(name=target_name, url=target_url)

    scan_id = repo_mgr.save_scan(
        repo_id=repo_id,
        scan_data={
            "commit_sha": commit_sha,
            "ref": ref,
            "repo_score": repo_score,
            "risk_level": risk_level,
            "finding_count": len(findings),
            "chain_count": len(chains),
            "source_type": resolved_source_type,
            "severity_distribution": scoring_result.severity_distribution,
            "findings": findings,
            "chains": chains,
            "explanations": scan_explanation.findings,
            "workflows": workflows,
        },
    )

    return scan_id
