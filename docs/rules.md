# Security Rules Specification (30 Rules)

The CI/CD Pipeline Security Auditor implements 30 deterministic static security analysis rules covering GitHub Actions CI/CD supply chain risks, secret exfiltration, permission escalation, and operational hygiene.

---

## 1. Core Rules (R001 - R010)

| Rule ID | Rule Identifier | Category | Default Severity | Description | Remediated By |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **R001** | `unpinned_action` | Supply Chain | HIGH | Action ref is pinned to a mutable tag (`@v4`) or branch (`@main`) instead of an immutable 40-character commit SHA. | Pin to full SHA with comment tag e.g. `uses: actions/checkout@b4ffde... # v4.1.1` |
| **R002** | `excessive_permissions` | Access Control | HIGH | Workflow or job omits `permissions:` (defaulting to write-all) or explicitly specifies `write-all` or excessive write scopes. | Set top-level `permissions: contents: read` or `permissions: {}` and grant minimum permissions per job. |
| **R003** | `pr_target_checkout` | Supply Chain | CRITICAL | Workflow triggered by `pull_request_target` checks out PR head commit (`ref: ${{ github.event.pull_request.head.sha }}`). | Checkout base repository or use isolated `pull_request` workflow without secrets. |
| **R004** | `script_injection` | Code Injection | CRITICAL | Shell `run:` script contains inline interpolation of untrusted user context (e.g. `${{ github.event.issue.title }}`). | Pass untrusted context into an environment variable (`env:`) and reference via `$VAR`. |
| **R005** | `plaintext_secret` | Secret Exposure | HIGH | Hardcoded API keys, private keys, or static bearer tokens committed directly into workflow files. | Store in GitHub Encrypted Secrets and reference via `${{ secrets.MY_SECRET }}`. |
| **R006** | `secret_in_log` | Secret Exposure | MEDIUM | Step prints or echoes secrets directly into logs (`echo $TOKEN` or `${{ secrets.TOKEN }}`). | Avoid echoing secrets; rely on GitHub Actions secret masking. |
| **R007** | `long_lived_credentials` | Credentials | MEDIUM | Long-lived cloud credentials (static AWS keys, GCP service account JSON) passed to action steps. | Migrate to OpenID Connect (OIDC) identity federation. |
| **R008** | `deploy_environment` | Access Control | MEDIUM | Production deployment job executed without specifying a protected GitHub environment (`environment: production`). | Bind job to protected GitHub environment with required reviewers. |
| **R009** | `self_hosted_runner` | Infrastructure | HIGH | Workflows processing untrusted events (e.g. `pull_request`) execute on persistent `self-hosted` runners. | Run untrusted jobs on GitHub-hosted runners or ephemeral VMs. |
| **R010** | `third_party_action` | Supply Chain | MEDIUM | Use of third-party actions from unvetted repositories outside official organizations (`actions/*`, `github/*`). | Audit action repository, pin SHA, and review source code. |

---

## 2. Batch A: Credential and Secret Handling (Rules 11 - 15)

| Rule ID | Category | Severity | Description | Remediated By |
| :--- | :--- | :--- | :--- | :--- |
| **persist-credentials** | Credentials | HIGH | `actions/checkout` used without `persist-credentials: false` in jobs uploading artifacts or invoking third-party actions. | Add `with: persist-credentials: false` to all `actions/checkout` steps. |
| **secret-to-unpinned-action** | Credentials | HIGH | Secrets passed via `with:` or `env:` to third-party actions pinned to mutable tags or branches. | Pin the third-party action to an immutable full commit SHA. |
| **overprovisioned-secrets** | Credentials | MEDIUM | Dynamic dumping or indexing of secret contexts (e.g. `toJSON(secrets)` or `secrets[input]`). | Reference explicit, named secrets only (e.g. `${{ secrets.DEPLOY_KEY }}`). |
| **artifact-leak** | Secret Exposure | HIGH | `actions/upload-artifact` configured with path targeting workspace root (`.`, `./`), `.git`, or `.env`. | Restrict uploaded artifact paths to dedicated build directories (e.g. `dist/`, `build/`). |
| **secrets-inherit** | Credentials | MEDIUM | Caller job invokes reusable workflow with `secrets: inherit`, passing all repo secrets unconditionally. | Pass only explicitly required secrets via caller job `secrets:` mapping. |

---

## 3. Batch B: Untrusted Input and Trigger Abuse (Rules 16 - 20)

| Rule ID | Category | Severity | Description | Remediated By |
| :--- | :--- | :--- | :--- | :--- |
| **github-env-injection** | Injection | HIGH | Untrusted event context written directly into `$GITHUB_ENV`, `$GITHUB_PATH`, or `$GITHUB_OUTPUT`. | Sanitize input and pass through intermediate environment variables. |
| **workflow-run-untrusted-artifact** | Privilege Escalation | HIGH | Privileged `workflow_run` workflow downloads artifacts from upstream completed run without validation. | Validate artifact checksums or run untrusted steps in unprivileged workflows. |
| **comment-trigger-no-auth** | Access Control | HIGH | Workflow triggered by `issue_comment` or `pull_request_review_comment` without verifying `author_association`. | Add job gate: `if: github.event.comment.author_association == 'OWNER' \|\| ...`. |
| **dispatch-input-injection** | Injection | LOW | `inputs.*` interpolated directly into shell `run:` commands instead of mapped to environment variables. | Map input parameters into step `env:` block. |
| **bot-actor-spoofing** | Authentication Bypass | MEDIUM | Conditions relying on `github.actor == 'dependabot[bot]'` or username matching for authorization. | Check numeric account ID (`github.event.pull_request.user.id == 49699333`). |

---

## 4. Batch C: Supply Chain and Execution Hygiene (Rules 21 - 25)

| Rule ID | Category | Severity | Description | Remediated By |
| :--- | :--- | :--- | :--- | :--- |
| **unpinned-reusable-workflow** | Supply Chain | HIGH | Reusable workflow called via mutable git branch or tag instead of immutable commit SHA. | Pin reusable workflow reference to full 40-character commit SHA. |
| **unpinned-docker-image** | Supply Chain | HIGH | Job container or service image specified by tag or `:latest` without sha256 digest. | Pin image by immutable digest e.g. `image: node@sha256:...`. |
| **curl-pipe-shell** | Supply Chain | HIGH | Remote script downloaded via `curl` or `wget` piped directly into shell (`curl ... \| bash`). | Download script to file, verify SHA256 checksum, then execute. |
| **insecure-commands-enabled** | Injection | CRITICAL | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` enabled or deprecated `::set-env` / `::add-path` used. | Remove unsecure commands flag and migrate to `$GITHUB_ENV` files. |
| **cache-poisoning-risk** | Supply Chain | HIGH | `actions/cache` restored in privileged workflow with write permissions or release triggers. | Avoid restoring caches during privileged release packaging. |

---

## 5. Batch D: OIDC, Permissions, and Reliability Hygiene (Rules 26 - 30)

| Rule ID | Category | Severity | Description | Remediated By |
| :--- | :--- | :--- | :--- | :--- |
| **oidc-write-untrusted** | Access Control | HIGH | Workflow grants `id-token: write` on untrusted triggers (`pull_request`, `issue_comment`). | Restrict OIDC token minting to protected push/release workflows. |
| **permissions-overbroad-job** | Access Control | MEDIUM | Job requests write permissions while executing strictly read-only commands (e.g. unit tests, linting). | Restrict job permissions to `contents: read`. |
| **continue-on-error-security-step** | Reliability Hygiene | HIGH | Security scanner or signing step specifies `continue-on-error: true`, silencing failures. | Remove `continue-on-error: true` so failed security gates block the pipeline. |
| **missing-timeout** | Reliability Hygiene | LOW | Job omits `timeout-minutes`, allowing runaway jobs to lock runners for up to 6 hours. | Specify explicit `timeout-minutes: 15` on all execution jobs. |
| **known-vulnerable-action** | Supply Chain | CRITICAL | Action version matches verified published security advisory (e.g. CVE-2025-30066). | Upgrade action to patched release or pin to an audited commit SHA. |
