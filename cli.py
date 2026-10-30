"""Command Line Interface (CLI) for CI/CD Pipeline Security Auditor."""

import argparse
import sys


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="CI/CD Pipeline Security Auditor - Statically scan GitHub Actions workflows."
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    scan_parser = subparsers.add_parser("scan", help="Scan workflows")
    scan_parser.add_argument(
        "--path", type=str, help="Path to local workflow file or directory"
    )
    scan_parser.add_argument(
        "--repo", type=str, help="GitHub repository (owner/repo)"
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format",
    )

    return parser.parse_args(args)


def main():
    args = parse_args()
    if not args.command:
        print("CI/CD Pipeline Security Auditor CLI. Run with --help for options.")
        return 0
    print(f"Command '{args.command}' invoked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

