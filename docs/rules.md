# Security Rules Specification

The CI/CD Pipeline Security Auditor implements 10 static security analysis rules covering the most critical GitHub Actions supply chain attack vectors:

| Rule ID | Rule Identifier | Default Severity | Description | Remediated By |
| :--- | :--- | :--- | :--- | :--- |
| **R001** | `r_unpinned_action` | HIGH / MEDIUM | Action ref is pinned to a mutable tag (e.g. `@v4`) or branch (`@main`) instead of an immutable 40-character commit SHA. | Pin to full SHA with comment tag e.g. `uses: actions/checkout@b4ffde... # v4.1.1` |
| **R002** | `r_excessive_permissions` | HIGH | Workflow or job omits the `permissions:` block (defaulting to write-all) or explicitly specifies `write-all` or unneeded write scopes. | Set top-level `permissions: contents: read` or `permissions: {}` and grant minimum permissions per job. |
| **R003** | `r_pr_target_checkout` | CRITICAL | Workflow triggered by `pull_request_target` checks out the PR head commit (`ref: ${{ github.event.pull_request.head.sha }}`). | Checkout base repository or use untrusted code only in isolated `pull_request` workflow without secrets. |
| **R004** | `r_script_injection` | CRITICAL | Shell `run:` script contains direct inline interpolation of untrusted user context (e.g. `${{ github.event.issue.title }}`). | Pass untrusted context into an environment variable (`env:`) and reference safely via `$VAR`. |
| **R005** | `r_plaintext_secret` | HIGH | Hardcoded API keys, private keys, or static bearer tokens committed directly into workflow files. | Store in GitHub Encrypted Secrets and reference via `${{ secrets.MY_SECRET }}`. |
| **R006** | `r_secret_in_log` | MEDIUM | Step prints or echoes secrets directly into logs (`echo $TOKEN` or `${{ secrets.TOKEN }}`). | Avoid echoing secrets; rely on GitHub Actions secret masking or write to files with restricted permissions. |
| **R007** | `r_long_lived_credentials` | MEDIUM | Long-lived cloud credentials (e.g. static AWS keys, GCP service account JSON) stored as secrets. | Migrate to OpenID Connect (OIDC) identity federation with cloud providers. |
| **R008** | `r_deploy_environment` | MEDIUM | Production deployment job executed without specifying a protected GitHub environment (`environment: production`). | Bind job to protected GitHub environment with required reviewers and branch protections. |
| **R009** | `r_self_hosted_runner` | HIGH | Workflows processing untrusted events (e.g. pull requests) execute on persistent `self-hosted` runners. | Run untrusted jobs on GitHub-hosted runners or ephemeral, autoscaled virtual machines. |
| **R010** | `r_third_party_action` | MEDIUM | Use of third-party actions from unvetted repositories outside official organizations (`actions/*`, `github/*`). | Audit action repository, verify vendor reputation, pin SHA, and review source code. |

