"""Rule: Detection of actions with published security advisories (CVE / GHSA)."""

import json
from pathlib import Path

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

ADVISORIES_FILE = Path(__file__).resolve().parent.parent / "data" / "action_advisories.json"


def _load_advisories() -> dict:
    if ADVISORIES_FILE.is_file():
        try:
            with open(ADVISORIES_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


class KnownVulnerableActionRule(BaseRule):
    """Flags actions pinned to versions with verified, published security advisories."""

    id = "known-vulnerable-action"
    name = "known_vulnerable_action"
    description = (
        "Action is pinned to a version affected by a known published security vulnerability (CVE or GitHub Advisory). "
        "Upgrade to a patched version or pin to an audited immutable commit SHA."
    )
    default_severity = Severity.CRITICAL
    category = "Supply Chain"
    tags = ["vulnerable-action", "cve", "ghsa", "supply-chain", "advisory"]
    references = [
        "https://github.com/advisories",
        "https://nvd.nist.gov/",
    ]

    def __init__(self):
        super().__init__()
        self._advisories = _load_advisories()

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for _job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                if not step.action_ref:
                    continue

                repo_key = f"{step.action_ref.owner}/{step.action_ref.repository}".lower()
                if repo_key not in self._advisories:
                    continue

                ref = step.action_ref.ref.lower()
                for adv in self._advisories[repo_key]:
                    vuln_versions = [v.lower() for v in adv.get("vulnerable_versions", [])]
                    # Check exact match or version prefix match (e.g. v35 matching v35.0.1)
                    is_match = ref in vuln_versions or any(ref.startswith(v) for v in vuln_versions)
                    if is_match:
                        target_line = step.uses_line or step.line
                        findings.append(
                            self.build_finding(
                                workflow=workflow,
                                job=job,
                                step=step,
                                line=target_line,
                                message=(
                                    f"Action '{step.action_ref.raw}' is affected by known advisory "
                                    f"{adv.get('advisory_id')}: {adv.get('title')}. "
                                    f"See {adv.get('url')} for remediation guidance."
                                ),
                                context={
                                    "advisory_id": adv.get("advisory_id"),
                                    "advisory_url": adv.get("url"),
                                    "action": step.action_ref.raw,
                                },
                            )
                        )

        return findings
