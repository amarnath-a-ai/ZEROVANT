"""Remediation templates and structured explanation generator for Phase 5.

Provides What / Why / How explanations for all 30 detection rules and
detailed narratives, step-by-step attack paths, and 'break the chain' guidance
for all 10 correlated attack chains.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from app.correlation.chains import Chain, ChainType
from app.explain.fixes import generate_fix_diff
from app.rules.base import Finding


@dataclass
class Explanation:
    """Explainable finding remediation guidance."""

    finding_id: str
    what: str
    why: str
    how: str
    fix_diff: str = ""
    source: str = "template"  # 'template' or 'llm'

    def to_dict(self) -> dict[str, Any]:
        """Convert explanation to JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class ChainExplanation:
    """Explainable attack chain narrative and remediation guidance."""

    chain_id: str
    chain_type: str
    narrative: str
    attack_path: list[str]
    break_the_chain: str
    source: str = "template"  # 'template' or 'llm'

    def to_dict(self) -> dict[str, Any]:
        """Convert chain explanation to JSON-serializable dictionary."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Rule Templates Catalog (All 30 Rules)
# ---------------------------------------------------------------------------

RULE_TEMPLATES: dict[str, dict[str, str]] = {
    "R001": {
        "what": "Action '{action}' is referenced by mutable tag/branch instead of an immutable 40-character commit SHA.",
        "why": "Mutable tags (like @v2 or @main) can be modified by repository owners or hijacked attackers. If upstream credentials are compromised, an attacker can push malicious code under the same tag, executing untrusted code directly in your CI pipeline.",
        "how": "Pin the action to an immutable 40-character commit SHA and record the original tag as a trailing comment (e.g. 'uses: {action_base}@<commit-sha> # {action_ref}').",
    },
    "R002": {
        "what": "Workflow or job omits explicit 'permissions:' configuration or grants overly broad default token privileges.",
        "why": "GitHub Actions grants default read/write permissions to the automatic GITHUB_TOKEN unless strictly constrained. Any compromised step or dependency can leverage this token to tamper with code, issues, or releases.",
        "how": "Declare explicit minimal permissions at the top of the workflow or job scope using 'permissions: contents: read'.",
    },
    "R003": {
        "what": "Workflow executes on 'pull_request_target' while checking out untrusted pull request code via head SHA.",
        "why": "The 'pull_request_target' trigger executes in the security context of the target repository, granting access to write tokens and secrets. Checking out the PR head from an untrusted fork allows untrusted build/test scripts to execute with repository write privileges.",
        "how": "Switch the trigger to 'pull_request' so untrusted forks execute in an unprivileged, read-only sandbox without repository secrets.",
    },
    "R004": {
        "what": "Untrusted context expression is directly interpolated into a 'run:' shell command via `${{ ... }}`.",
        "why": "GitHub Actions evaluates `${{ ... }}` template expressions prior to passing the command string to the shell. An attacker can submit an issue or PR with shell metacharacters (\"; curl ... #) to break out of quotes and execute arbitrary shell commands.",
        "how": "Pass the untrusted context variable into the step via an environment variable ('env:') and reference it as a quoted shell variable (e.g. '\"$TITLE\"').",
    },
    "R005": {
        "what": "Sensitive secret or credential appears hardcoded in plaintext within workflow YAML.",
        "why": "Hardcoded secrets are visible to anyone with read access to the repository and are permanently captured in git history. If the repository is public or cloned, these credentials can be extracted instantly.",
        "how": "Remove the plaintext secret and reference it securely via GitHub Actions Secrets (e.g. '${{ secrets.SECRET_NAME }}').",
    },
    "R006": {
        "what": "Workflow step prints, echoes, or logs sensitive credentials or environment variables.",
        "why": "Workflow run logs are visible to organization members and collaborators, and public repositories expose them to anyone. Logging credentials leads to permanent token exposure.",
        "how": "Do not echo or print secrets in shell commands. Use GitHub Actions secret masking ('::add-mask::') if values must be dynamically processed.",
    },
    "R007": {
        "what": "Workflow utilizes static, long-lived cloud credentials (such as AWS access keys or GCP service account keys).",
        "why": "Static credentials do not expire automatically and represent high-value targets. If leaked through build logs, artifacts, or compromised actions, they grant long-term access to cloud infrastructure.",
        "how": "Migrate to OpenID Connect (OIDC) federation with short-lived tokens using 'permissions: id-token: write' and cloud provider login actions.",
    },
    "R008": {
        "what": "Production deployment job executes without specifying a protected 'environment:'.",
        "why": "Deployments without environment protection lack manual approval gates, review timers, and branch restriction rules. Any commit or branch push can deploy to production without audit or verification.",
        "how": "Add an 'environment: <env-name>' configuration to the job and configure required reviewers and deployment branches in GitHub repository settings.",
    },
    "R009": {
        "what": "Self-hosted runner is invoked on untrusted or fork-driven workflows.",
        "why": "Self-hosted runners share the host operating system and network across executions. Untrusted pull request code can persist backdoors, escape containers, or pivot laterally into private internal network infrastructure.",
        "how": "Use GitHub-hosted runners ('runs-on: ubuntu-latest') for workflows that process external pull requests or untrusted input.",
    },
    "R010": {
        "what": "Workflow invokes an action from a non-verified third-party creator.",
        "why": "Third-party actions represent external software dependencies executed directly inside your build runner. If the creator's account is hijacked or abandoned, malicious updates can compromise your build pipeline.",
        "how": "Audit the third-party action, pin it to an immutable full-length commit SHA, or replace it with verified first-party actions.",
    },
    "persist-credentials": {
        "what": "Action 'actions/checkout' is used without explicitly setting 'persist-credentials: false'.",
        "why": "By default, actions/checkout persists the temporary GITHUB_TOKEN inside '.git/config' on disk. Subsequent steps, build scripts, or third-party actions can read this file and exfiltrate the token.",
        "how": "Add 'with: persist-credentials: false' to the actions/checkout step configuration.",
    },
    "secret-to-unpinned-action": {
        "what": "Repository secret is passed as an input or environment variable to an unpinned third-party action.",
        "why": "An unpinned action referenced by a tag can be updated upstream at any time. An attacker compromising the action can silently exfiltrate the secret passed into it.",
        "how": "Pin the third-party action to an immutable 40-character commit SHA before supplying sensitive secrets to it.",
    },
    "overprovisioned-secrets": {
        "what": "Multiple unrelated secrets are exposed to a job or step beyond what is strictly necessary.",
        "why": "Broadly exposing secrets increases the blast radius if any dependency or script in that job is compromised, violating the principle of least privilege.",
        "how": "Scope secret access strictly to the individual steps that require them rather than passing all secrets globally.",
    },
    "artifact-leak": {
        "what": "Build artifact upload targets directories that may contain credentials, '.git/' folders, or '.env' files.",
        "why": "Uploaded artifacts are stored by GitHub and downloadable by anyone with repository read access. Leaking workspace credentials compromises pipeline integrity.",
        "how": "Ensure artifact paths specifically target build output directories (e.g. 'dist/', 'build/') and never include '.git' or '.env' files.",
    },
    "secrets-inherit": {
        "what": "Reusable workflow invocation uses 'secrets: inherit' to pass all repository secrets down to the called workflow.",
        "why": "The called workflow receives all secrets in the repository, including production deployment keys it may not need, creating unnecessary supply-chain exposure.",
        "how": "Pass only the specific secrets needed by the reusable workflow explicitly (e.g. 'secrets: { API_KEY: ${{ secrets.API_KEY }} }').",
    },
    "github-env-injection": {
        "what": "Untrusted input is written to GITHUB_ENV or GITHUB_PATH without validation.",
        "why": "An attacker supplying newline characters can inject arbitrary environment variables (such as LD_PRELOAD or NODE_OPTIONS), achieving arbitrary code execution in subsequent steps.",
        "how": "Sanitize inputs, reject multi-line values, or write fixed constants rather than raw untrusted context values.",
    },
    "workflow-run-untrusted-artifact": {
        "what": "Privileged workflow triggered by 'workflow_run' downloads and executes artifacts produced by a fork.",
        "why": "Fork PRs cannot access secrets directly, but an attacker can place a malicious payload into a build artifact that the privileged workflow_run pipeline subsequently executes with write tokens.",
        "how": "Treat artifacts from workflow_run as untrusted user data. Do not execute scripts or load modules directly from downloaded artifacts.",
    },
    "comment-trigger-no-auth": {
        "what": "Workflow triggered on issue or PR comments executes privileged steps without checking author association.",
        "why": "Any user on GitHub can comment on a public issue. Without an author association check, any external user can trigger privileged automation.",
        "how": "Add an authorization guard check: 'if: github.event.comment.author_association == \"OWNER\" || github.event.comment.author_association == \"MEMBER\" || github.event.comment.author_association == \"COLLABORATOR\"'.",
    },
    "dispatch-input-injection": {
        "what": "Workflow dispatch manual inputs ('${{ inputs.* }}') are interpolated directly into shell execution strings.",
        "why": "Dispatch inputs can contain shell metacharacters or command substitutions. If passed directly into shell strings, they cause command injection.",
        "how": "Pass inputs into the step using 'env:' variables and reference them safely as quoted shell variables (e.g. '\"$INPUT_VAL\"').",
    },
    "bot-actor-spoofing": {
        "what": "Workflow relies on easily spoofed actor username checks (e.g. 'github.actor == \"dependabot[bot]\"').",
        "why": "Actor username checks alone can be bypassed in forks or spoofed via branch names or comment payloads in some configurations.",
        "how": "Use immutable identity verification such as 'github.actor_id' or verify commit signatures rather than checking username strings.",
    },
    "unpinned-reusable-workflow": {
        "what": "Reusable workflow ('uses: owner/repo/.github/workflows/name.yml@ref') is referenced by branch or mutable tag.",
        "why": "Upstream modifications to the reusable workflow will immediately execute in caller repositories without audit or version locking.",
        "how": "Pin the reusable workflow reference to an immutable 40-character commit SHA with a version comment.",
    },
    "unpinned-docker-image": {
        "what": "Job container or service references a mutable container tag (e.g. ':latest' or ':v1') instead of an image digest.",
        "why": "Container image tags can be pushed or overwritten in registries at any time, introducing backdoored tools or dependencies into build environments.",
        "how": "Pin the container image to an immutable digest (e.g. 'image: alpine@sha256:<digest>').",
    },
    "curl-pipe-shell": {
        "what": "Shell command downloads a remote script and pipes it directly into a shell interpreter (e.g. 'curl | bash').",
        "why": "Piping web content directly into bash allows MITM attacks, DNS tampering, or compromised remote servers to execute arbitrary unvetted code in your runner.",
        "how": "Download the script to a file first, verify its cryptographic hash (sha256sum), and only then execute it.",
    },
    "insecure-commands-enabled": {
        "what": "Workflow sets 'ACTIONS_ALLOW_UNSECURE_COMMANDS' to true.",
        "why": "This re-enables deprecated runner commands ('set-env', 'add-path') that are inherently vulnerable to script injection via stdout parsing.",
        "how": "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and use the modern '$GITHUB_ENV' and '$GITHUB_PATH' environment files.",
    },
    "cache-poisoning-risk": {
        "what": "Cache action uses broad or predictable keys in privileged or release workflows.",
        "why": "Because cache keys can be populated from pull request branches, an attacker can poison the cache with modified binaries that are restored during official releases.",
        "how": "Include exact lockfile hashes in cache keys (e.g. 'hashFiles(\"**/package-lock.json\")') and isolate caches from untrusted branches.",
    },
    "oidc-write-untrusted": {
        "what": "OpenID Connect write token permission ('id-token: write') is granted in a job with untrusted triggers or unpinned actions.",
        "why": "Malicious code or compromised actions running in the job can request an OIDC identity token and assume federated cloud roles in AWS, GCP, or Azure.",
        "how": "Restrict 'id-token: write' exclusively to protected default branches and ensure all actions in the job are pinned to full commit SHAs.",
    },
    "permissions-overbroad-job": {
        "what": "Job explicitly grants 'permissions: write-all' or requests multiple unnecessary write permissions.",
        "why": "Excessive permissions violate the principle of least privilege. If any step is compromised, the token can be used to modify all aspects of the repository.",
        "how": "Replace 'write-all' with specific minimal permissions (e.g. 'contents: write', 'pull-requests: write') required for that job.",
    },
    "continue-on-error-security-step": {
        "what": "A security scanning or audit step specifies 'continue-on-error: true'.",
        "why": "If the security scanner discovers a vulnerability or fails to execute, the failure is silently suppressed and subsequent build/deploy steps proceed anyway.",
        "how": "Remove 'continue-on-error: true' from the security step so detected vulnerabilities actively fail the build.",
    },
    "missing-timeout": {
        "what": "Job does not specify a 'timeout-minutes:' limit.",
        "why": "Without a timeout, GitHub Actions allows jobs to run for up to 6 hours (360 minutes), causing potential denial of service, hung runners, and excessive billable compute consumption.",
        "how": "Add 'timeout-minutes: 15' (or an appropriate project-specific duration) to the job definition.",
    },
    "known-vulnerable-action": {
        "what": "Action reference matches a version with a known security advisory or CVE vulnerability.",
        "why": "Known vulnerable actions have public exploits allowing arbitrary code execution, secret theft, or runner compromise.",
        "how": "Upgrade the action to the latest secure patched release and pin it to its immutable 40-character commit SHA.",
    },
}


# ---------------------------------------------------------------------------
# Chain Templates Catalog (All 10 Chains)
# ---------------------------------------------------------------------------

CHAIN_TEMPLATES: dict[str, dict[str, Any]] = {
    "pwn-request": {
        "narrative": "A workflow triggers on 'pull_request_target' (which runs in the privileged base repository context with access to write tokens and secrets) while checking out untrusted code from the pull request head SHA. When subsequent build or test steps run, untrusted code from an external fork executes with base repository write privileges, enabling unauthorized commits, secret theft, or release tampering.",
        "attack_path": [
            "1. Adversary forks the repository and creates a pull request containing malicious build scripts.",
            "2. 'pull_request_target' trigger fires in the context of the base repository.",
            "3. Workflow executes 'actions/checkout' with the untrusted pull request head SHA.",
            "4. Subsequent steps execute build/test commands (e.g. npm test, make) on the untrusted code.",
            "5. Attacker code inherits base repository write tokens or secrets, compromising the project.",
        ],
        "break_the_chain": "Fix R003 first: change the workflow trigger from 'pull_request_target' to 'pull_request' so untrusted code executes in an unprivileged, read-only sandbox without repository secrets. If write access is required, do not check out untrusted code in the same workflow.",
    },
    "injection-to-exfil": {
        "narrative": "An untrusted context variable (such as an issue title, pull request body, or branch name) is directly interpolated into a shell script step via ${{ ... }} in a job that has access to repository secrets. An attacker crafts a payload containing shell metacharacters to inject arbitrary commands and exfiltrate secrets to an external server.",
        "attack_path": [
            "1. Adversary submits an issue or pull request with a malicious title containing shell injection characters.",
            "2. Workflow trigger fires and passes the issue title to a 'run:' step via inline ${{ ... }} interpolation.",
            "3. Shell parses and executes the injected command sequence before running the intended command.",
            "4. Injected command accesses environment secrets or tokens reachable in the job scope.",
            "5. Attacker exfiltrates secrets via HTTP POST or curl to an attacker-controlled endpoint.",
        ],
        "break_the_chain": "Fix R004 first: pass untrusted context expressions into environment variables ('env:') and reference them safely as quoted shell variables (e.g. \"$TITLE\"), preventing command injection regardless of the input payload.",
    },
    "supply-chain-takeover": {
        "narrative": "The pipeline invokes an unpinned third-party action using a mutable git tag or branch name in a job that possesses write permissions or accessible repository secrets. If the third-party action maintainer account is compromised or the tag is updated upstream, malicious code executes inside the pipeline with full write access.",
        "attack_path": [
            "1. Pipeline relies on third-party GitHub Action referenced by a mutable tag (e.g. @v2 or @main).",
            "2. Upstream action author account is compromised or tag is retargeted to a malicious commit.",
            "3. Victim workflow triggers normally and fetches the backdoored action code.",
            "4. Malicious action executes with access to GITHUB_TOKEN write permissions and repository secrets.",
            "5. Attacker injects backdoors into production build artifacts, releases, or commits.",
        ],
        "break_the_chain": "Fix R001 first: pin the third-party action to an immutable 40-character commit SHA with a version comment. An attacker updating upstream tags cannot alter pinned commit code.",
    },
    "deploy-blast-radius": {
        "narrative": "A production deployment job executes without specifying a protected 'environment:' gate and accesses long-lived static cloud credentials. Any unreviewed commit or branch push can deploy directly to production infrastructure without human approval or branch verification.",
        "attack_path": [
            "1. Adversary or rogue branch push targets the repository without formal code review.",
            "2. Deployment workflow triggers automatically on branch update.",
            "3. Deployment job lacks 'environment:' protection gates and runs without required reviewers.",
            "4. Job authenticates using static, long-lived cloud keys (e.g. AWS access keys).",
            "5. Unauthorized or compromised build deploys directly into production infrastructure.",
        ],
        "break_the_chain": "Fix R008 first: configure an explicit 'environment:' block on the deployment job with required reviewers and restricted deployment branches in GitHub repository settings.",
    },
    "runner-persistence": {
        "narrative": "A workflow executes on a self-hosted runner and triggers on untrusted events such as pull requests. Because self-hosted runners persist their filesystem and network state across executions, untrusted code can install rootkits, steal credentials, or pivot into internal private corporate networks.",
        "attack_path": [
            "1. Adversary opens a pull request on a repository using self-hosted runners.",
            "2. Workflow executes on an internal self-hosted runner machine.",
            "3. Untrusted build script executes on the host with local filesystem access.",
            "4. Attacker code establishes persistent background access or rootkit on the runner host.",
            "5. Attacker pivots from the compromised runner into internal corporate networks.",
        ],
        "break_the_chain": "Fix R009 first: migrate public and untrusted PR workflows to GitHub-hosted runners ('runs-on: ubuntu-latest') or ensure self-hosted runners are ephemeral and destroyed after every single job.",
    },
    "artifact-poisoning": {
        "narrative": "A secondary privileged workflow triggered by 'workflow_run' downloads an unverified build artifact produced by an untrusted pull request fork. If the privileged workflow unpacks and executes code from the artifact, the untrusted PR author escalates privileges to the base repository.",
        "attack_path": [
            "1. Adversary submits a pull request with poisoned binaries or scripts in a build artifact.",
            "2. PR workflow runs in unprivileged context and uploads the malicious artifact.",
            "3. Privileged secondary workflow triggers via 'workflow_run' with write tokens and secrets.",
            "4. Privileged workflow downloads and unpacks the unverified artifact.",
            "5. Attacker code from the artifact executes in the privileged context, compromising the repository.",
        ],
        "break_the_chain": "Fix workflow-run-untrusted-artifact first: treat all downloaded artifacts as untrusted data. Validate cryptographic hashes and signatures before unpacking, and never execute scripts or binaries unpacked from fork artifacts.",
    },
    "comment-trigger-takeover": {
        "narrative": "A workflow triggers on issue or PR comments to perform automation (e.g. slash commands) without verifying that the commenter has write or triage access to the repository. Any GitHub user can post a comment to trigger privileged automation.",
        "attack_path": [
            "1. External user comments on a public repository issue with an automation command (e.g. /deploy).",
            "2. 'issue_comment' workflow triggers with GITHUB_TOKEN write access.",
            "3. Workflow lacks an author_association check and proceeds with execution.",
            "4. Privileged automation runs on behalf of the unverified commenter.",
            "5. Attacker executes unauthorized deployments or triggers unintended pipeline actions.",
        ],
        "break_the_chain": "Fix comment-trigger-no-auth first: add an 'if:' condition checking that 'github.event.comment.author_association' is 'OWNER', 'MEMBER', or 'COLLABORATOR' before executing any command.",
    },
    "credential-persistence": {
        "narrative": "The workflow uses 'actions/checkout' without setting 'persist-credentials: false', storing the GITHUB_TOKEN in '.git/config' on disk. Subsequent steps that invoke third-party actions or upload artifacts expose the stored token to external harvesting.",
        "attack_path": [
            "1. Workflow executes 'actions/checkout' with default settings.",
            "2. GITHUB_TOKEN is written in plaintext to '.git/config' on the runner disk.",
            "3. Subsequent step invokes an unpinned third-party action or uploads workspace artifacts.",
            "4. Third-party action reads '.git/config' or artifact downloader extracts the stored credentials.",
            "5. Attacker uses the harvested token to authenticate against the GitHub API.",
        ],
        "break_the_chain": "Fix persist-credentials first: add 'with: persist-credentials: false' to the actions/checkout step so credentials are never written to disk.",
    },
    "cache-poisoning-escalation": {
        "narrative": "A privileged release or deployment workflow restores build caches using broad or predictable keys. Because dependency caches can be populated from pull request branches, an attacker can poison the cache with modified binaries that are restored during official releases.",
        "attack_path": [
            "1. Adversary creates a branch with modified dependency binaries under a matching cache key.",
            "2. PR workflow saves the poisoned cache entry to GitHub cache storage.",
            "3. Official release or deployment workflow triggers on the main branch.",
            "4. Release workflow restores the poisoned cache without verifying integrity.",
            "5. Malicious binaries are packaged into the official production release.",
        ],
        "break_the_chain": "Fix cache-poisoning-risk first: include strict lockfile hashes (e.g. 'hashFiles(\"**/package-lock.json\")') in cache keys and do not restore caches in release pipelines without integrity checks.",
    },
    "oidc-abuse": {
        "narrative": "A workflow grants OpenID Connect write permissions ('id-token: write') to authenticate to cloud providers (AWS, GCP, Azure) while running unpinned third-party actions or executing on untrusted PR triggers. Malicious code can intercept the OIDC token exchange and assume cloud IAM roles.",
        "attack_path": [
            "1. Workflow configures 'permissions: id-token: write' to assume cloud IAM roles via OIDC.",
            "2. Job executes an unpinned third-party action or runs on an untrusted pull request event.",
            "3. Malicious code requests an OIDC token from the runner's internal token endpoint.",
            "4. Attacker exchanges the minted OIDC token with AWS STS or GCP STS for cloud credentials.",
            "5. Attacker accesses production cloud infrastructure through the federated role.",
        ],
        "break_the_chain": "Fix oidc-write-untrusted first: restrict 'id-token: write' strictly to protected default branch runs and pin all third-party actions in the job to immutable commit SHAs.",
    },
}


# ---------------------------------------------------------------------------
# Template Explainer Class
# ---------------------------------------------------------------------------


class TemplateExplainer:
    """Generates deterministic explanations for findings and attack chains."""

    def explain_finding(self, finding: Finding, raw_workflow: str = "") -> Explanation:
        """Generate structured What / Why / How explanation for a single finding."""
        tmpl = RULE_TEMPLATES.get(finding.rule_id)
        fix_diff = generate_fix_diff(finding, raw_workflow)
        if not tmpl:
            # Fallback for unregistered rule
            return Explanation(
                finding_id=finding.id,
                what=f"Security issue detected by rule {finding.rule_id} in {finding.file}:{finding.line}.",
                why="Misconfiguration in CI/CD pipeline violates least-privilege or secure execution principles.",
                how="Review the finding evidence and remediate the workflow according to security best practices.",
                fix_diff=fix_diff,
                source="template",
            )

        # Context interpolation dictionary
        action_name = finding.step or finding.evidence or "action"
        action_base = action_name.split("@")[0] if "@" in action_name else action_name
        action_ref = action_name.split("@")[1] if "@" in action_name else "v1"

        ctx = {
            "action": action_name,
            "action_base": action_base,
            "action_ref": action_ref,
            "file": finding.file,
            "job": finding.job or "job",
            "step": finding.step or "step",
            "line": str(finding.line),
            "evidence": finding.evidence,
        }

        def _render(text: str) -> str:
            res = text
            for k, v in ctx.items():
                res = res.replace(f"{{{k}}}", str(v))
            return res

        what = _render(tmpl["what"])
        why = _render(tmpl["why"])
        how = _render(tmpl["how"])

        return Explanation(
            finding_id=finding.id,
            what=what,
            why=why,
            how=how,
            fix_diff=fix_diff,
            source="template",
        )

    def explain(self, finding: Any, raw_workflow: str = "") -> Explanation:
        """Alias for explain_finding() for backward compatibility."""
        return self.explain_finding(finding, raw_workflow=raw_workflow)

    def explain_chain(
        self,
        chain: Chain,
        findings_by_id: dict[str, Finding] | None = None,
    ) -> ChainExplanation:
        """Generate structured narrative, attack path, and break-the-chain fix for a chain."""
        chain_type_val = (
            chain.chain_type.value
            if isinstance(chain.chain_type, ChainType)
            else str(chain.chain_type)
        )
        tmpl = CHAIN_TEMPLATES.get(chain_type_val)
        if not tmpl:
            return ChainExplanation(
                chain_id=chain.id,
                chain_type=chain_type_val,
                narrative=chain.narrative or f"Correlated attack chain {chain_type_val} detected.",
                attack_path=[f"Step {i+1}: Finding {fid}" for i, fid in enumerate(chain.finding_ids)],
                break_the_chain="Remediate the earliest finding in the chain to break the attack path.",
                source="template",
            )

        return ChainExplanation(
            chain_id=chain.id,
            chain_type=chain_type_val,
            narrative=tmpl["narrative"],
            attack_path=list(tmpl["attack_path"]),
            break_the_chain=tmpl["break_the_chain"],
            source="template",
        )

    @staticmethod
    def get_rule_template(rule_id: str) -> dict[str, str] | None:
        """Retrieve the raw template dictionary for a rule."""
        return RULE_TEMPLATES.get(rule_id)

    @staticmethod
    def get_chain_template(chain_type: str) -> dict[str, Any] | None:
        """Retrieve the raw template dictionary for an attack chain."""
        return CHAIN_TEMPLATES.get(chain_type)
