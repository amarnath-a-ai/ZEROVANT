"""Rule: Detection of Docker container images unpinned by sha256 digest."""

from app.parser.model import Workflow
from app.rules.base import BaseRule, Finding, Severity


class UnpinnedDockerImageRule(BaseRule):
    """Flags container and service images referenced by mutable tags instead of immutable sha256 digests."""

    id = "unpinned-docker-image"
    name = "unpinned_docker_image"
    description = (
        "Container image is referenced by a mutable tag (or ':latest') rather than an immutable sha256 digest. "
        "Container tags can be modified, re-pushed, or compromised in upstream registries."
    )
    default_severity = Severity.HIGH
    category = "Supply Chain"
    tags = ["docker", "container", "unpinned", "supply-chain", "pinning"]
    references = [
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
    ]

    def evaluate(self, workflow: Workflow) -> list[Finding]:
        if not workflow or not workflow.jobs:
            return []

        findings: list[Finding] = []

        for job_id, job in workflow.jobs.items():
            if job.uses:
                continue

            # Check job.container
            if job.container is not None:
                image_str = ""
                if isinstance(job.container, str):
                    image_str = job.container.strip()
                elif isinstance(job.container, dict):
                    image_str = str(job.container.get("image", "")).strip()

                if image_str and "@sha256:" not in image_str:
                    target_line = job.container_image_line or job.container_line or job.line
                    findings.append(
                        self.build_finding(
                            workflow=workflow,
                            job=job,
                            line=target_line,
                            message=(
                                f"Container image '{image_str}' in job '{job_id}' is pinned by mutable tag. "
                                "Pin image to an immutable digest (e.g. image@sha256:...) to prevent supply chain tampering."
                            ),
                            context={
                                "image": image_str,
                                "job_id": job_id,
                            },
                        )
                    )

            # Check job.services
            if isinstance(job.services, dict):
                for svc_name, svc_cfg in job.services.items():
                    svc_img = ""
                    if isinstance(svc_cfg, str):
                        svc_img = svc_cfg.strip()
                    elif isinstance(svc_cfg, dict):
                        svc_img = str(svc_cfg.get("image", "")).strip()

                    if svc_img and "@sha256:" not in svc_img:
                        target_line = job.services_line or job.line
                        findings.append(
                            self.build_finding(
                                workflow=workflow,
                                job=job,
                                line=target_line,
                                message=(
                                    f"Service '{svc_name}' uses container image '{svc_img}' unpinned by digest. "
                                    "Pin service image to an immutable sha256 digest."
                                ),
                                context={
                                    "service": svc_name,
                                    "image": svc_img,
                                },
                            )
                        )

            # Check docker:// steps
            for step in job.steps:
                if step.uses and step.uses.startswith("docker://"):
                    raw_docker = step.uses[len("docker://") :].strip()
                    if "@sha256:" not in raw_docker:
                        target_line = step.uses_line or step.line
                        findings.append(
                            self.build_finding(
                                workflow=workflow,
                                job=job,
                                step=step,
                                line=target_line,
                                message=(
                                    f"Docker action '{step.uses}' is not pinned by sha256 digest. "
                                    "Pin docker action using docker://image@sha256:digest."
                                ),
                                context={
                                    "uses": step.uses,
                                },
                            )
                        )

        return findings
