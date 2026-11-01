"""Rule R007: Detection of static long-lived cloud credentials in favor of OIDC."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

STATIC_AWS_KEYS = {"aws-access-key-id", "aws-secret-access-key"}
STATIC_AWS_ENV = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}


class LongLivedCredentialsRule(BaseRule):
    """Flags usage of static long-lived cloud credentials instead of OpenID Connect (OIDC)."""

    id = "R007"
    name = "long_lived_credentials"
    description = (
        "Workflow utilizes static long-lived cloud credentials (e.g. AWS access keys or GCP service account keys). "
        "Modern cloud security best practices mandate temporary short-lived credentials via OpenID Connect (OIDC)."
    )
    default_severity = Severity.MEDIUM
    category = "Credential Management"
    tags = ["credentials", "cloud", "oidc", "iam"]
    references = [
        "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            for step in job.steps:
                step_display = step.name or step.uses or "Step"
                finding_line = step.uses_line or step.line

                # 1. Check cloud auth action with static credentials in with_params
                if step.uses and "configure-aws-credentials" in step.uses.lower():
                    # If using static access keys rather than role-to-assume
                    has_static_keys = any(k.lower() in STATIC_AWS_KEYS for k in step.with_params)
                    has_oidc_role = "role-to-assume" in step.with_params

                    if has_static_keys and not has_oidc_role:
                        findings.append(
                            Finding(
                                id=f"f-r007-{len(findings)+1:04d}",
                                rule_id=self.id,
                                title="Static AWS Access Keys in Configure Credentials Action",
                                severity=Severity.MEDIUM,
                                file=workflow.file_path,
                                job=job_id,
                                step=step_display,
                                line=finding_line,
                                evidence=(
                                    f"Step '{step_display}' uses static AWS access keys (aws-access-key-id) "
                                    "instead of OpenID Connect (OIDC) role assumption. Static credentials are "
                                    "perpetual, increase blast radius upon compromise, and require manual rotation."
                                ),
                                tags=list(self.tags),
                                base_score=6.8,
                            )
                        )
                        continue

                # 2. Check static AWS credentials passed via environment variables (e.g. for aws cli or terraform)
                static_env_present = any(k in STATIC_AWS_ENV for k in step.env)
                if static_env_present:
                    findings.append(
                        Finding(
                            id=f"f-r007-{len(findings)+1:04d}",
                            rule_id=self.id,
                            title="Static Cloud Credentials in Environment Variables",
                            severity=Severity.MEDIUM,
                            file=workflow.file_path,
                            job=job_id,
                            step=step_display,
                            line=step.line,
                            evidence=(
                                f"Step '{step_display}' passes static AWS credential environment variables "
                                f"({', '.join(set(step.env.keys()) & STATIC_AWS_ENV)}). Migrate to GitHub OIDC federation."
                            ),
                            tags=list(self.tags),
                            base_score=6.8,
                        )
                    )

        return findings
