# System Limitations & Threat Model Boundaries

1. **Static Analysis Scope**:
   - The system analyzes static YAML workflow configurations. It does not dynamically execute containers, emulate bash environments, or monitor network sockets during workflow runs.
   - Dynamic bash logic (e.g. scripts downloaded via `curl | bash` during execution) cannot be fully inspected statically beyond identifying the unsafe execution pattern.

2. **Cross-Repository Workflows**:
   - Reusable workflows hosted in private external repositories require appropriate GitHub read tokens to fetch and resolve.

3. **Composite Action Deep Nesting**:
   - Custom composite actions referenced locally are parsed, but deeply nested multi-tier remote composite actions are evaluated based on their top-level references and SHA pinning.

4. **GitHub Expression Evaluation**:
   - Complex GitHub expression logic `${{ fromJSON(...) }}` is parsed syntactically but not dynamically evaluated, preserving safety and deterministic reproducibility.

5. **Action Reference Classification Heuristic (`RefType`)**:
   - `RefType.COMMIT_SHA`: Full 40-character hex string (immutable SHA-1).
   - `RefType.TAG`: Tag reference adhering to semver/release conventions (e.g. `v4`, `v2.1.0`).
   - `RefType.BRANCH`: Recognized branch names (e.g. `main`, `master`, `develop`).
   - `RefType.LOCAL`: Local repository paths starting with `./`.
   - `RefType.DOCKER`: Containerized action references (`docker://...`).
   - `RefType.UNKNOWN`: Dynamic GitHub expressions inside `uses:` (e.g. `uses: ${{ matrix.action }}`) or non-standard reference strings are safely categorized as `RefType.UNKNOWN` to avoid false assumptions.

6. **Current Milestone Status**:
   - **Explainability Engine**: Detailed LLM-enriched explanations and automatic unified YAML diff remediation will be fully implemented in Phase 5; current foundation provides structural template fallbacks.
   - **Web UI & REST API**: End-to-end web dashboard and complete REST API wiring will be integrated in Phase 7; current endpoints provide baseline health and rule registry access.

