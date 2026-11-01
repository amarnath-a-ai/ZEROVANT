"""Rule R005: Detection of hardcoded plaintext secrets, API keys, and static credentials."""

from app.config import SECRET_PATTERNS
from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class PlaintextSecretRule(BaseRule):
    """Flags hardcoded credentials, static bearer tokens, or private keys in workflow definitions."""

    id = "R005"
    name = "plaintext_secret"
    description = (
        "Hardcoded API token, webhook URL, or private key discovered in plaintext. "
        "Workflow secrets should be stored in GitHub Encrypted Secrets and referenced via ${{ secrets.KEY }}."
    )
    default_severity = Severity.HIGH
    category = "Secrets Management"
    tags = ["secrets", "credentials", "cwe-798"]
    references = [
        "https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions"
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
                finding_line = step.line

                # Check step-level environment variables
                for env_key, env_val in step.env.items():
                    val_str = str(env_val).strip()
                    # Never flag legitimate GitHub Encrypted Secret references
                    if "${{ secrets." in val_str or "${{secrets." in val_str:
                        continue

                    # Also check key name for high-confidence static secret assignment
                    matched_desc = None
                    for pattern, desc in SECRET_PATTERNS:
                        full_entry = f"{env_key}: {val_str}"
                        if pattern.search(val_str) or pattern.search(full_entry):
                            matched_desc = desc
                            break

                    if matched_desc:
                        # Mask secret value in evidence for security
                        masked = val_str[:4] + "..." + val_str[-4:] if len(val_str) > 8 else "***"
                        findings.append(
                            Finding(
                                id=f"f-r005-{len(findings)+1:04d}",
                                rule_id=self.id,
                                title=f"Plaintext {matched_desc} in Environment Variable",
                                severity=Severity.HIGH,
                                file=workflow.file_path,
                                job=job_id,
                                step=step_display,
                                line=finding_line,
                                evidence=(
                                    f"Environment variable '{env_key}' in step '{step_display}' "
                                    f"contains hardcoded plaintext secret ({masked}). "
                                    "Move sensitive values to GitHub Secrets (${{ secrets." + env_key + " }})."
                                ),
                                tags=list(self.tags),
                                base_score=8.2,
                            )
                        )

                # Check step parameters (with_params)
                for param_key, param_val in step.with_params.items():
                    val_str = str(param_val).strip()
                    if "${{ secrets." in val_str or "${{secrets." in val_str:
                        continue

                    for pattern, desc in SECRET_PATTERNS:
                        if pattern.search(val_str):
                            masked = val_str[:4] + "..." + val_str[-4:] if len(val_str) > 8 else "***"
                            findings.append(
                                Finding(
                                    id=f"f-r005-{len(findings)+1:04d}",
                                    rule_id=self.id,
                                    title=f"Plaintext {desc} in Action Parameter",
                                    severity=Severity.HIGH,
                                    file=workflow.file_path,
                                    job=job_id,
                                    step=step_display,
                                    line=finding_line,
                                    evidence=(
                                        f"Parameter '{param_key}' in step '{step_display}' "
                                        f"contains hardcoded plaintext secret ({masked})."
                                    ),
                                    tags=list(self.tags),
                                    base_score=8.2,
                                )
                            )
                            break

        return findings
