"""Unit tests for GitHub Actions workflow parser and object model (Phase 1)."""

from pathlib import Path

from app.parser import (
    ParsedUses,
    ParseError,
    ParseResult,
    RefType,
    Workflow,
    WorkflowLoader,
    load_workflows,
    parse_uses,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_parser_module_imports():
    """Verify parser module classes and functions are importable."""
    loader = WorkflowLoader()
    assert loader is not None
    assert Workflow is not None
    assert ParsedUses is not None
    assert ParseError is not None
    assert ParseResult is not None


def test_all_valid_fixtures_parse_successfully():
    """Verify that every valid fixture from Phase 0 parses into a valid Workflow model."""
    loader = WorkflowLoader()
    valid_count = 0

    for fixture_path in FIXTURES_DIR.rglob("*"):
        if not fixture_path.is_file() or fixture_path.suffix not in (".yml", ".yaml"):
            continue
        if "edge_malformed.yml" in fixture_path.name or "edge_empty.yml" in fixture_path.name:
            continue

        content = fixture_path.read_text(encoding="utf-8")
        result = loader.load_string(content, file_path=fixture_path.name)

        assert result.is_valid is True, f"Failed parsing fixture {fixture_path.name}: {result.errors}"
        assert result.workflow is not None
        assert isinstance(result.workflow.jobs, dict)
        assert len(result.workflow.jobs) > 0
        valid_count += 1

    # Should have parsed at least 85 valid fixtures
    assert valid_count >= 85, f"Expected >= 85 valid fixtures, parsed {valid_count}"


def test_trigger_normalization_string():
    """Verify single string trigger: on: push."""
    content = "name: T\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []"
    result = WorkflowLoader().load_string(content)
    assert result.is_valid
    assert result.workflow.triggers == {"push": {}}
    assert result.workflow.trigger_lines.get("push") == 2


def test_trigger_normalization_list():
    """Verify list of event strings: on: [push, pull_request]."""
    content = "name: T\non: [push, pull_request]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []"
    result = WorkflowLoader().load_string(content)
    assert result.is_valid
    assert "push" in result.workflow.triggers
    assert "pull_request" in result.workflow.triggers
    assert result.workflow.trigger_lines["push"] == 2


def test_trigger_normalization_mapping():
    """Verify detailed mapping trigger with branches and types."""
    content = """name: T
on:
  push:
    branches: [main, dev]
  pull_request_target:
    types: [opened, synchronize]
  workflow_dispatch:
jobs:
  j:
    runs-on: ubuntu-latest
    steps: []"""
    result = WorkflowLoader().load_string(content)
    assert result.is_valid
    wf = result.workflow
    assert "push" in wf.triggers
    assert wf.triggers["push"] == {"branches": ["main", "dev"]}
    assert wf.trigger_lines["push"] == 3
    assert wf.triggers["pull_request_target"] == {"types": ["opened", "synchronize"]}
    assert wf.trigger_lines["pull_request_target"] == 5
    assert wf.triggers["workflow_dispatch"] == {}
    assert wf.trigger_lines["workflow_dispatch"] == 7


def test_yaml_11_on_boolean_quirk():
    """Verify YAML 1.1 'on:' boolean tag quirk is parsed as trigger key."""
    # When YAML safe parser reads 'on:', YAML 1.1 resolves tag to bool
    content = "name: Quirk\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []"
    result = WorkflowLoader().load_string(content)
    assert result.is_valid
    assert "push" in result.workflow.triggers


def test_permissions_parsing_variations():
    """Verify permissions: missing vs empty vs string vs mapping."""
    loader = WorkflowLoader()

    # Missing permissions (None)
    res_none = loader.load_string("name: T\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []")
    assert res_none.workflow.permissions is None
    assert res_none.workflow.permissions_line is None

    # String write-all
    res_write = loader.load_string("name: T\non: push\npermissions: write-all\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []")
    assert res_write.workflow.permissions == "write-all"
    assert res_write.workflow.permissions_line == 3

    # Empty permissions mapping
    res_empty = loader.load_string("name: T\non: push\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []")
    assert res_empty.workflow.permissions == {}
    assert res_empty.workflow.permissions_line == 3

    # Scoped mapping
    res_scoped = loader.load_string("name: T\non: push\npermissions:\n  contents: read\n  issues: write\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []")
    assert res_scoped.workflow.permissions == {"contents": "read", "issues": "write"}
    assert res_scoped.workflow.permissions_line == 3

    # Job-level override
    res_job = loader.load_string("""name: T
on: push
permissions:
  contents: read
jobs:
  j1:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps: []
  j2:
    runs-on: ubuntu-latest
    steps: []""")
    j1 = res_job.workflow.jobs["j1"]
    j2 = res_job.workflow.jobs["j2"]
    assert j1.permissions == {"issues": "write"}
    assert j1.permissions_line == 8
    assert j2.permissions is None


def test_nested_jobs_steps_needs_runs_on():
    """Verify job needs, matrix runs_on, steps parameters and env."""
    content = """name: Complex Job
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - name: Linter Step
        run: flake8 .
  build:
    needs: [lint]
    runs-on: [self-hosted, linux, x64]
    environment:
      name: staging
      url: https://staging.example.com
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          submodules: recursive
        env:
          STEP_ENV: test_value
"""
    result = WorkflowLoader().load_string(content)
    assert result.is_valid
    wf = result.workflow

    assert "lint" in wf.jobs
    assert "build" in wf.jobs

    build_job = wf.jobs["build"]
    assert build_job.needs == ["lint"]
    assert build_job.runs_on == ["self-hosted", "linux", "x64"]
    assert build_job.runs_on_line == 11
    assert build_job.environment == {"name": "staging", "url": "https://staging.example.com"}
    assert build_job.environment_line == 12

    assert len(build_job.steps) == 1
    step = build_job.steps[0]
    assert step.name == "Checkout"
    assert step.uses == "actions/checkout@v4"
    assert step.with_params == {"submodules": "recursive"}
    assert step.env == {"STEP_ENV": "test_value"}
    assert step.action_ref is not None
    assert step.action_ref.owner == "actions"
    assert step.action_ref.repository == "checkout"
    assert step.action_ref.ref == "v4"
    assert step.action_ref.ref_type == RefType.TAG


def test_uses_parsing_comprehensive():
    """Verify parse_uses for sha, tag, branch, local, docker, and subpath actions."""
    # 40-char SHA
    sha_uses = parse_uses("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11")
    assert sha_uses.owner == "actions"
    assert sha_uses.repository == "checkout"
    assert sha_uses.ref_type == RefType.SHA
    assert sha_uses.ref == "b4ffde65f46336ab88eb53be808477a3936bae11"

    # Semantic Tag
    tag_uses = parse_uses("actions/setup-python@v5.1.0")
    assert tag_uses.owner == "actions"
    assert tag_uses.repository == "setup-python"
    assert tag_uses.ref_type == RefType.TAG
    assert tag_uses.ref == "v5.1.0"

    # Branch name
    branch_uses = parse_uses("actions/checkout@main")
    assert branch_uses.owner == "actions"
    assert branch_uses.repository == "checkout"
    assert branch_uses.ref_type == RefType.BRANCH
    assert branch_uses.ref == "main"

    # Action in subpath
    subpath_uses = parse_uses("github/codeql-action/init@v3")
    assert subpath_uses.owner == "github"
    assert subpath_uses.repository == "codeql-action"
    assert subpath_uses.path == "init"
    assert subpath_uses.ref == "v3"
    assert subpath_uses.ref_type == RefType.TAG

    # Local action
    local_uses = parse_uses("./.github/actions/my-action")
    assert local_uses.ref_type == RefType.LOCAL
    assert local_uses.path == "./.github/actions/my-action"

    # Docker action
    docker_uses = parse_uses("docker://alpine:3.18")
    assert docker_uses.ref_type == RefType.DOCKER
    assert docker_uses.repository == "alpine"
    assert docker_uses.ref == "3.18"

    # Reusable workflow call at job level
    reusable_uses = parse_uses("./.github/workflows/reusable.yml")
    assert reusable_uses.ref_type == RefType.LOCAL


def test_malformed_yaml_returns_error_not_exception():
    """Verify malformed YAML returns a structured ParseError instead of raising an unhandled exception."""
    malformed_content = """name: Malformed
on: [push
jobs:
  test:
    runs-on: ubuntu-latest
"""
    result = WorkflowLoader().load_string(malformed_content, file_path="broken.yml")
    assert result.is_valid is False
    assert result.workflow is None
    assert len(result.errors) > 0
    err = result.errors[0]
    assert err.error_code == "YAML_SYNTAX_ERROR"
    assert err.line is not None
    assert err.file_path == "broken.yml"


def test_empty_yaml_returns_error_not_exception():
    """Verify empty workflow file returns a structured EMPTY_WORKFLOW error."""
    result = WorkflowLoader().load_string("   \n\n   ", file_path="empty.yml")
    assert result.is_valid is False
    assert result.workflow is None
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "EMPTY_WORKFLOW"


def test_non_mapping_root_returns_error():
    """Verify non-mapping root (e.g. sequence) returns NON_MAPPING_ROOT error."""
    result = WorkflowLoader().load_string("- step 1\n- step 2", file_path="list.yml")
    assert result.is_valid is False
    assert result.errors[0].error_code == "NON_MAPPING_ROOT"


def test_missing_jobs_returns_error():
    """Verify missing jobs section returns MISSING_JOBS error."""
    result = WorkflowLoader().load_string("name: No Jobs\non: push\n", file_path="no_jobs.yml")
    assert result.is_valid is False
    assert result.errors[0].error_code == "MISSING_JOBS"


def test_source_line_accuracy_against_fixtures():
    """Verify exact source line accuracy for workflow, job, and steps against fixture files."""
    loader = WorkflowLoader()

    # Test vuln_r001_unpinned.yml
    f1_path = FIXTURES_DIR / "vulnerable" / "vuln_r001_unpinned.yml"
    res1 = loader.load_string(f1_path.read_text(encoding="utf-8"), file_path="vuln_r001_unpinned.yml")
    assert res1.is_valid
    wf1 = res1.workflow
    assert wf1.line == 1
    assert "build" in wf1.jobs
    build_job = wf1.jobs["build"]
    assert build_job.line == 5
    assert build_job.runs_on_line == 6
    assert len(build_job.steps) == 2
    assert build_job.steps[0].line == 8
    assert build_job.steps[1].line == 10

    # Test safe_r001_pinned.yml
    f2_path = FIXTURES_DIR / "safe" / "safe_r001_pinned.yml"
    res2 = loader.load_string(f2_path.read_text(encoding="utf-8"), file_path="safe_r001_pinned.yml")
    assert res2.is_valid
    wf2 = res2.workflow
    assert wf2.permissions == {"contents": "read"}
    assert wf2.permissions_line == 6
    job2 = wf2.jobs["build"]
    assert job2.line == 10
    assert job2.steps[0].line == 13
    assert job2.steps[1].line == 15


def test_load_workflows_helper():
    """Verify public load_workflows helper functions on files, directories, and strings."""
    # Test loading raw YAML string
    raw = "name: Helper\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []"
    res_str = load_workflows(raw)
    assert len(res_str) == 1
    assert res_str[0].is_valid
    assert res_str[0].workflow.name == "Helper"

    # Test loading single file path
    single_file = FIXTURES_DIR / "safe" / "safe_r001_pinned.yml"
    res_file = load_workflows(single_file)
    assert len(res_file) == 1
    assert res_file[0].is_valid
    assert res_file[0].workflow.name == "Safe Pinned Actions"

    # Test loading directory path
    safe_dir = FIXTURES_DIR / "safe"
    res_dir = load_workflows(safe_dir)
    assert len(res_dir) >= 8
    for r in res_dir:
        assert r.is_valid


def test_extension_fixtures_exact_line_accuracy():
    """Verify exact line accuracy for representative extension fixtures."""
    loader = WorkflowLoader()

    # Test ext_r11_persist_credentials.yml
    f11_path = FIXTURES_DIR / "extension" / "vulnerable" / "ext_r11_persist_credentials.yml"
    res11 = loader.load_string(f11_path.read_text(encoding="utf-8"), file_path="ext_r11_persist_credentials.yml")
    assert res11.is_valid
    wf11 = res11.workflow
    assert wf11.line == 1
    assert "build" in wf11.jobs
    job11 = wf11.jobs["build"]
    assert job11.line == 8
    assert len(job11.steps) == 3
    assert job11.steps[0].line == 12

    # Test ext_r21_unpinned_reusable_workflow.yml (reusable workflow call at job level)
    f21_path = FIXTURES_DIR / "extension" / "vulnerable" / "ext_r21_unpinned_reusable_workflow.yml"
    res21 = loader.load_string(f21_path.read_text(encoding="utf-8"), file_path="ext_r21_unpinned_reusable_workflow.yml")
    assert res21.is_valid
    wf21 = res21.workflow
    assert "shared-build" in wf21.jobs
    job21 = wf21.jobs["shared-build"]
    assert job21.line == 8
    assert job21.uses == "acme-corp/shared-workflows/.github/workflows/build.yml@main"
    assert job21.action_ref is not None
    assert job21.action_ref.ref_type == RefType.BRANCH
    assert job21.action_ref.ref == "main"

    # Test ext_r23_curl_pipe_shell.yml
    f23_path = FIXTURES_DIR / "extension" / "vulnerable" / "ext_r23_curl_pipe_shell.yml"
    res23 = loader.load_string(f23_path.read_text(encoding="utf-8"), file_path="ext_r23_curl_pipe_shell.yml")
    assert res23.is_valid
    wf23 = res23.workflow
    assert "setup" in wf23.jobs
    job23 = wf23.jobs["setup"]
    assert job23.steps[0].line == 12
    assert "curl -sSL https://example.com/install.sh | bash" in job23.steps[0].run

