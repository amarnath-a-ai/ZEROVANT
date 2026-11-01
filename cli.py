"""Command Line Interface (CLI) for CI/CD Pipeline Security Auditor."""

import argparse
import json
import sys
from pathlib import Path

from app.ingest import GitHubClient
from app.parser import load_workflows
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
        "--exit-code",
        action="store_true",
        default=False,
        help="Exit with code 1 if CRITICAL or HIGH findings are discovered",
    )

    return parser.parse_args(args)


def format_table(findings: list[Finding]) -> str:
    """Format findings as a human-readable ASCII table."""
    if not findings:
        return "\n[+] No security vulnerabilities detected. All checks passed!\n"

    lines = []
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
    return "\n".join(lines)


def run_scan(args) -> int:
    """Execute static security scan according to parsed CLI arguments."""
    target_path = args.path or args.target
    findings: list[Finding] = []

    if args.repo:
        client = GitHubClient()
        try:
            workflow_tuples = client.fetch_workflows(args.repo)
            for file_path, content in workflow_tuples:
                results = load_workflows(content, file_path=file_path)
                for res in results:
                    if res.is_valid and res.workflow:
                        findings.extend(default_registry.run_all(res.workflow))
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
    else:
        print("[-] Must provide either a local path or --repo to scan.", file=sys.stderr)
        return 2

    # Render results
    if args.format == "json":
        output_data = [f.to_dict() for f in findings]
        print(json.dumps(output_data, indent=2))
    elif args.format == "table":
        print(format_table(findings))
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
