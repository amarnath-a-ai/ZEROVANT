# System Architecture

## 1. High-Level Architecture

The CI/CD Pipeline Security Auditor is structured as a pipeline of independent, deterministic modules. It processes GitHub Actions workflow definitions without executing untrusted code or evaluating bash interpolations.

```
+-------------------------------------------------------------------------------+
| Ingestion Layer (app.ingest)                                                  |
| - GitHubClient (REST API with rate limit handling)                            |
| - LocalLoader (Local files and directory scanner)                             |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| Parser & Object Model (app.parser)                                            |
| - Line-preserving YAML safe loader                                            |
| - Typed Object Model (Workflow -> Job -> Step -> ActionRef)                   |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| Security Rule Engine (app.rules)                                              |
| - BaseRule interface & RuleRegistry                                          |
| - 10 Rule Implementations (R001 - R010)                                       |
| - Emits normalized Finding objects with immutable fingerprints                |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| Attack Chain Correlator (app.correlation)                                     |
| - Graph topology matcher (Chains: pwn-request, injection-to-exfil, etc.)       |
| - Cytoscape.js directed graph generator                                       |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| Risk Scorer & Explainability (app.scoring & app.explain)                      |
| - Deterministic multi-factor risk scoring formula                             |
| - What / Why / How explainers + unified YAML diff patches                     |
| - Optional AI enrichment with fallback                                        |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| Storage & Presentation (app.storage, app.api, app.web)                        |
| - SQLite relational persistence                                               |
| - Flask REST API & Interactive UI Dashboard                                   |
+-------------------------------------------------------------------------------+
```

## 2. Key Design Decisions

1. **Static Analysis Without Execution**: Workflows are never executed; variables and secrets are never evaluated in a shell.
2. **Deterministic Security Logic**: All vulnerability detections, attack path combinations, and risk scores are derived deterministically.
3. **Line-Level Fidelity**: All parsed entities maintain exact source line numbers to provide precise UI highlighting and unified diff patching.
4. **Stable Fingerprints**: Findings maintain stable cryptographic fingerprints (`sha256(rule_id:file:job:step:evidence)`) ensuring consistency across scans and upstream comment edits.
5. **Action Reference Classification Heuristic**:
   - `RefType.COMMIT_SHA`: 40-character hexadecimal commit hash representing immutable provenance.
   - `RefType.TAG`: Semantic versioning or release tags (e.g., `v3`, `v1.2.0`).
   - `RefType.BRANCH`: Mutable branch references (e.g., `main`, `master`, `release`).
   - `RefType.LOCAL`: Actions located in the repository itself (`./.github/actions/...`).
   - `RefType.DOCKER`: Docker container actions (`docker://...`).
   - `RefType.UNKNOWN`: Dynamic GitHub expressions (e.g., `uses: ${{ matrix.action }}`) or unrecognized formats, conservatively flagged to avoid blind assumptions.


