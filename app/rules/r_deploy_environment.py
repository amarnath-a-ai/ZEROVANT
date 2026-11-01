"""Rule R008: Detection of production/deploy jobs lacking protected GitHub environment gates."""

from app.config import PRODUCTION_KEYWORDS
from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity

DEPLOYMENT_COMMAND_SNIPPETS = [
    "kubectl apply",
    "kubectl create",
    "kubectl rollout",
    "helm upgrade",
    "helm install",
    "docker push",
    "aws s3 sync",
    "terraform apply",
    "npm publish",
    "twine upload",
]


class DeployEnvironmentRule(BaseRule):
    """Flags deployment jobs that lack an explicit GitHub environment protection configuration."""

    id = "R008"
    name = "deploy_environment"
    description = (
        "Deployment or production release job executes without specifying a protected GitHub environment. "
        "Binding jobs to environments enforces required manual approvers, deployment wait timers, "
        "and deployment branch protection rules."
    )
    default_severity = Severity.MEDIUM
    category = "Environment Protection"
    tags = ["environment", "deployment", "approval-gates"]
    references = [
        "https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment"
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            # If the job already defines an environment, it is properly configured
            if job.environment:
                continue

            is_deploy_job = False
            deploy_reason = ""

            # Check for production/release target in job ID or name
            job_name_lower = f"{job_id} {job.name}".lower()
            for kw in PRODUCTION_KEYWORDS:
                if kw in job_name_lower:
                    is_deploy_job = True
                    deploy_reason = f"Job identifier or name matches production target keyword '{kw}'"
                    break

            # If not detected by name, check step commands for active deployment commands
            if not is_deploy_job:
                for step in job.steps:
                    if not step.run:
                        continue
                    run_lower = step.run.lower()
                    for cmd in DEPLOYMENT_COMMAND_SNIPPETS:
                        if cmd in run_lower:
                            is_deploy_job = True
                            deploy_reason = f"Step script executes deployment command '{cmd}'"
                            break
                    if is_deploy_job:
                        break

            if is_deploy_job:
                findings.append(
                    Finding(
                        id=f"f-r008-{len(findings)+1:04d}",
                        rule_id=self.id,
                        title="Deployment Job Lacks Protected Environment",
                        severity=Severity.MEDIUM,
                        file=workflow.file_path,
                        job=job_id,
                        step=None,
                        line=job.line,
                        evidence=(
                            f"Job '{job_id}' is a deployment-like workload ({deploy_reason}) but does not specify "
                            "a target 'environment:'. Without environment protection rules, untrusted branches "
                            "or unauthorized pull requests can trigger direct deployments without manual approval."
                        ),
                        tags=list(self.tags),
                        base_score=6.5,
                    )
                )

        return findings

