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

