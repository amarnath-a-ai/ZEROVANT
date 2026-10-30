# Testing Strategy

## Test Levels

1. **Unit Tests**:
   - `test_parser.py`: YAML parsing, line mapping, schema validation, AST node structure.
   - `test_rules.py`: Independent testing of all 10 rules against positive and negative fixtures.
   - `test_correlation.py`: Graph building and attack chain pattern matching.
   - `test_scoring.py`: Deterministic scoring formulas, multipliers, and edge cases.
   - `test_explainability.py`: Template rendering, unified diff accuracy, and LLM fallback safety.
   - `test_storage.py`: SQLite schema creation, CRUD operations, and cascade constraints.
   - `test_api.py`: Flask endpoints, request schema validation, and HTTP response codes.

2. **Integration Tests**:
   - `test_integration.py`: End-to-end flow from raw workflow ingestion to database storage and API rendering.

3. **Fixture Corpus Validation**:
   - `test_fixtures.py`: Integrity of all hand-written and real-world fixtures and ground truth validation.

4. **Benchmark Evaluation**:
   - Precision, recall, and F1-score evaluation against `benchmark/ground_truth.json`.

