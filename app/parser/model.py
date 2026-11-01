"""Workflow object model preserving source line numbers and structured syntax."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RefType(str, Enum):
    """Reference type for an external GitHub Action or reusable workflow."""

    SHA = "sha"
    TAG = "tag"
    BRANCH = "branch"
    LOCAL = "local"
    DOCKER = "docker"
    UNKNOWN = "unknown"


@dataclass
class ParsedUses:
    """Parsed action or workflow reference from a 'uses' clause.

    Supports:
      - actions/checkout@v4 (owner, repo, tag)
      - actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 (owner, repo, sha)
      - owner/repo/path/to/action@main (owner, repo, subpath, branch)
      - ./.github/actions/custom (local action)
      - docker://alpine:3.18 (container action)
    """

    raw: str
    owner: str = ""
    repository: str = ""
    path: str = ""
    ref: str = ""
    ref_type: RefType = RefType.UNKNOWN


# Alias ActionRef for backwards compatibility
ActionRef = ParsedUses


@dataclass
class Step:
    """A single execution step within a job."""

    name: str = ""
    uses: str = ""
    run: str = ""
    with_params: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    line: int = 1
    action_ref: ParsedUses | None = None
    step_index: int = 0
    uses_line: int | None = None
    run_line: int | None = None


@dataclass
class Job:
    """A single job execution unit within a workflow."""

    id: str
    name: str = ""
    runs_on: Any = None
    runs_on_line: int | None = None
    permissions: Any = None
    permissions_line: int | None = None
    environment: Any = None
    environment_line: int | None = None
    needs: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)
    line: int = 1
    uses: str = ""
    action_ref: ParsedUses | None = None
    secrets: Any = None
    secrets_line: int | None = None
    timeout_minutes: int | None = None
    timeout_minutes_line: int | None = None


@dataclass
class Workflow:
    """Top-level GitHub Actions workflow representation."""

    name: str
    file_path: str
    triggers: dict[str, Any] = field(default_factory=dict)
    trigger_lines: dict[str, int] = field(default_factory=dict)
    permissions: Any = None
    permissions_line: int | None = None
    env: dict[str, Any] = field(default_factory=dict)
    jobs: dict[str, Job] = field(default_factory=dict)
    line: int = 1
    raw_content: str = ""


@dataclass
class ParseError:
    """Structured representation of a YAML or workflow parsing error."""

    message: str
    line: int | None = None
    column: int | None = None
    file_path: str = ""
    error_code: str = "PARSE_ERROR"


@dataclass
class ParseResult:
    """Outcome of loading and parsing a workflow."""

    workflow: Workflow | None = None
    errors: list[ParseError] = field(default_factory=list)
    file_path: str = ""

    @property
    def is_valid(self) -> bool:
        """Returns True if the workflow parsed cleanly without errors."""
        return len(self.errors) == 0 and self.workflow is not None
