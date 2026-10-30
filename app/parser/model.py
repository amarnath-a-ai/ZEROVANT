"""Workflow object model preserving source line numbers and structured syntax."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RefType(str, Enum):
    """Reference type for an external GitHub Action."""

    SHA = "sha"
    TAG = "tag"
    BRANCH = "branch"
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass
class ActionRef:
    """Parsed action reference from a step's 'uses' clause."""

    raw: str
    owner: str = ""
    repository: str = ""
    path: str = ""
    ref: str = ""
    ref_type: RefType = RefType.UNKNOWN


@dataclass
class Step:
    """A single step within a job."""

    name: str = ""
    uses: str = ""
    run: str = ""
    with_params: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    line: int = 1
    action_ref: ActionRef | None = None
    step_index: int = 0


@dataclass
class Job:
    """A single job within a workflow."""

    id: str
    name: str = ""
    runs_on: Any = None
    permissions: Any = None
    environment: Any = None
    needs: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)
    line: int = 1


@dataclass
class Workflow:
    """Top-level GitHub Actions workflow representation."""

    name: str
    file_path: str
    triggers: Any = field(default_factory=dict)
    permissions: Any = None
    env: dict[str, Any] = field(default_factory=dict)
    jobs: dict[str, Job] = field(default_factory=dict)
    line: int = 1
    raw_content: str = ""

