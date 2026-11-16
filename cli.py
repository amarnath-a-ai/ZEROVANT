"""Command Line Interface (CLI) for CI/CD Pipeline Security Auditor."""

import argparse
import json
import sys
from pathlib import Path

from app.correlation import Chain, ChainCorrelator
from app.ingest import GitHubClient
from app.parser import load_workflows
from app.parser.model import Workflow
from app.rules import default_registry
from app.rules.base import Finding, Severity


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="CI/CD Pipeline Security Auditor - Statically scan GitHub Actions workflows."
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    scan_parser = subparsers.add_parser("scan", help="Scan workflows")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target path to local workflow file or directory (positional)",
    )
    scan_parser.add_argument(
        "--path", type=str, default=None, help="Path to local workflow file or directory"
    )
    scan_parser.add_argument(
        "--repo", type=str, default=None, help="GitHub repository (owner/repo or https://github.com/owner/repo)"
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--chains",
        action="store_true",
        default=False,
        help="Include correlated attack chain analysis in output",
    )
    scan_parser.add_argument(
        "--exit-code",
        action="store_true",
        default=False,
        help="Exit with code 1 if CRITICAL or HIGH findings are discovered",
    )

    return parser.parse_args(args)


def format_table(findings: list[Finding], chains: list[Chain] | None = None) -> str:
    """Format findings and correlated attack chains as a human-readable ASCII table."""
    if not findings and not chains:
        return "\n[+] No security vulnerabilities detected. All checks passed!\n"

    lines = []
    if findings:
        lines.append("\n" + "=" * 110)
        lines.append(f"{'RULE':<32} {'SEV':<10} {'LOCATION':<32} {'TITLE'}")
        lines.append("-" * 110)

        from collections import Counter
        sev_counts = Counter()
        rule_counts = Counter()

        for f in findings:
            loc = f"{Path(f.file).name}:{f.line}"
            if f.job:
                loc += f" [{f.job}]"
            sev_str = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            sev_counts[sev_str] += 1
            rule_counts[f.rule_id] += 1
            lines.append(f"{f.rule_id:<32} {sev_str:<10} {loc:<32} {f.title}")

        lines.append("=" * 110)
        lines.append(f"Total findings: {len(findings)}")

        # Severity summary breakdown
        ordered_sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev_parts = [f"{s}: {sev_counts[s]}" for s in ordered_sevs if sev_counts[s] > 0]
        if sev_parts:
            lines.append("Severity breakdown: " + ", ".join(sev_parts))

        lines.append("")

    if chains:
        lines.append("=" * 110)
        lines.append("DISCOVERED ATTACK CHAINS (Phase 3 Correlation Engine)")
        lines.append("=" * 110)
        lines.append(f"{'CHAIN ID':<12} {'CHAIN TYPE':<32} {'JOB':<22} {'FINDINGS'}")
        lines.append("-" * 110)
        for c in chains:
            c_type = c.chain_type.value if hasattr(c.chain_type, "value") else str(c.chain_type)
            job_name = c.job_id or (c.jobs[0] if c.jobs else "-")
            f_str = ", ".join(c.finding_ids[:4])
            if len(c.finding_ids) > 4:
                f_str += f" (+{len(c.finding_ids)-4} more)"
            lines.append(f"{c.id:<12} {c_type:<32} {job_name:<22} {f_str}")
        lines.append("=" * 110)
        lines.append(f"Total attack chains: {len(chains)}")
        lines.append("")

    return "\n".join(lines)


def run_scan(args) -> int:
    """Execute static security scan according to parsed CLI arguments."""
    target_path = args.path or args.target
    findings: list[Finding] = []
    workflows: list[Workflow] = []

    if args.repo:
        client = GitHubClient()
        try:
            workflow_tuples = client.fetch_workflows(args.repo)
            for file_path, content in workflow_tuples:
                results = load_workflows(content, file_path=file_path)
                for res in results:
                    if res.is_valid and res.workflow:
                        findings.extend(default_registry.run_all(res.workflow))
                        workflows.append(res.workflow)
        except Exception as exc:
            print(f"[-] Error fetching workflows from GitHub repo '{args.repo}': {exc}", file=sys.stderr)
            return 2

    elif target_path:
        p = Path(target_path)
        if not p.exists():
            print(f"[-] Target path does not exist: {target_path}", file=sys.stderr)
            return 2

        results = load_workflows(p)
        for res in results:
            if res.is_valid and res.workflow:
                findings.extend(default_registry.run_all(res.workflow))
                workflows.append(res.workflow)
    else:
        print("[-] Must provide either a local path or --repo to scan.", file=sys.stderr)
        return 2

    # Run attack chain correlation
    correlator = ChainCorrelator()
    all_chains: list[Chain] = []
    for wf in workflows:
        wf_findings = [f for f in findings if f.file == wf.file_path]
        chains = correlator.correlate(wf_findings, workflow=wf)
        all_chains.extend(chains)

    # Render results
    if args.format == "json":
        if getattr(args, "chains", False):
            print(json.dumps({
                "findings": [f.to_dict() for f in findings],
                "chains": [c.to_dict() for c in all_chains],
            }, indent=2))
        else:
            output_data = [f.to_dict() for f in findings]
            print(json.dumps(output_data, indent=2))
    elif args.format == "table":
        print(format_table(findings, chains=all_chains))
    elif args.format == "sarif":
        # SARIF baseline format
        sarif_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cicd-auditor",
                            "rules": [
                                {"id": r.id, "name": r.name, "shortDescription": {"text": r.description}}
                                for r in default_registry.list_rules()
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule_id,
                            "level": "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                            "message": {"text": f.title},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file},
                                        "region": {"startLine": f.line},
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        }
        print(json.dumps(sarif_data, indent=2))

    if args.exit_code:
        has_high_or_crit = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
        )
        return 1 if has_high_or_crit else 0

    return 0


def main(argv=None):
    args = parse_args(argv)
    if not args.command:
        print("CI/CD Pipeline Security Auditor CLI. Run with --help for options.")
        return 0

    if args.command == "scan":
        return run_scan(args)

    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
