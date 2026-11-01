"""Safe YAML Loader preserving source line numbers and converting AST to Workflow object model."""

import logging
import re
from typing import Any

import yaml

from app.parser.model import (
    Job,
    ParsedUses,
    ParseError,
    ParseResult,
    RefType,
    Step,
    Workflow,
)

logger = logging.getLogger(__name__)

# Heuristic patterns for action and ref classification
HEX_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
TAG_VERSION_PATTERN = re.compile(r"^v?[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9_.-]+)?$", re.IGNORECASE)
COMMON_BRANCH_NAMES = {
    "main",
    "master",
    "trunk",
    "dev",
    "develop",
    "development",
    "staging",
    "prod",
    "production",
    "beta",
    "canary",
    "nightly",
    "head",
}


def parse_uses(raw_uses: str) -> ParsedUses:
    """Parse a step or job 'uses' string into structured components.

    Classification Heuristic:
      1. Local: Starts with './' or '../' -> RefType.LOCAL
      2. Docker: Starts with 'docker://' -> RefType.DOCKER
      3. Commit SHA: Exactly 40 hexadecimal characters -> RefType.SHA
      4. Tag: Matches version string patterns (e.g., 'v1', 'v4.1.2', '1.0.0') -> RefType.TAG
      5. Branch: Matches common branch identifiers ('main', 'master', etc.)
         or identifiers without semantic version numbers -> RefType.BRANCH
    """
    raw = (raw_uses or "").strip()
    if not raw:
        return ParsedUses(raw=raw, ref_type=RefType.UNKNOWN)

    # Local action or workflow
    if raw.startswith("./") or raw.startswith("../"):
        return ParsedUses(raw=raw, path=raw, ref_type=RefType.LOCAL)

    # Docker container action
    if raw.startswith("docker://"):
        remainder = raw[len("docker://") :]
        ref = ""
        image = remainder
        if "@" in remainder:
            image, ref = remainder.split("@", 1)
        elif ":" in remainder:
            image, ref = remainder.split(":", 1)

        ref_type = RefType.DOCKER
        if ref and HEX_SHA_PATTERN.match(ref):
            ref_type = RefType.SHA
        return ParsedUses(raw=raw, repository=image, ref=ref, ref_type=ref_type)

    # Standard GitHub Action or remote reusable workflow: owner/repo[/path]@ref
    if "@" not in raw:
        return ParsedUses(raw=raw, path=raw, ref_type=RefType.UNKNOWN)

    target, ref = raw.split("@", 1)
    target = target.strip()
    ref = ref.strip()

    parts = target.split("/")
    if len(parts) < 2:
        return ParsedUses(raw=raw, path=target, ref=ref, ref_type=RefType.UNKNOWN)

    owner = parts[0]
    repo = parts[1]
    subpath = "/".join(parts[2:]) if len(parts) > 2 else ""

    # Determine reference type
    if HEX_SHA_PATTERN.match(ref):
        ref_type = RefType.SHA
    elif ref.lower() in COMMON_BRANCH_NAMES or ref.startswith("feature/") or ref.startswith("release/"):
        ref_type = RefType.BRANCH
    elif TAG_VERSION_PATTERN.match(ref):
        ref_type = RefType.TAG
    elif any(char.isdigit() for char in ref) and "." in ref:
        ref_type = RefType.TAG
    else:
        ref_type = RefType.BRANCH

    return ParsedUses(
        raw=raw,
        owner=owner,
        repository=repo,
        path=subpath,
        ref=ref,
        ref_type=ref_type,
    )


def _node_to_python(node: yaml.Node) -> tuple[Any, int]:
    """Recursively convert a PyYAML AST node into Python structures while tracking line numbers.

    Returns:
        tuple[parsed_value, 1_indexed_start_line]
    """
    line = node.start_mark.line + 1

    if isinstance(node, yaml.ScalarNode):
        val = node.value
        # Preserve scalar types where appropriate
        if node.tag == "tag:yaml.org,2002:int":
            try:
                return int(val), line
            except ValueError:
                return val, line
        elif node.tag == "tag:yaml.org,2002:float":
            try:
                return float(val), line
            except ValueError:
                return val, line
        elif node.tag == "tag:yaml.org,2002:bool":
            # Handle YAML 1.1 boolean representations
            if val.lower() in ("true", "yes", "on"):
                return True, line
            elif val.lower() in ("false", "no", "off"):
                return False, line
        elif node.tag == "tag:yaml.org,2002:null" or val == "~" or val.lower() == "null":
            return None, line
        return val, line

    elif isinstance(node, yaml.SequenceNode):
        items = []
        for item_node in node.value:
            item_val, _ = _node_to_python(item_node)
            items.append(item_val)
        return items, line

    elif isinstance(node, yaml.MappingNode):
        mapping = {}
        for k_node, v_node in node.value:
            # Handle the YAML 1.1 quirk where 'on' resolves to bool tag
            k_val = k_node.value
            v_val, _ = _node_to_python(v_node)
            mapping[k_val] = v_val
        return mapping, line

    return None, line


class WorkflowLoader:
    """Safe, line-preserving YAML parser that constructs structured Workflow AST models."""

    def load_string(self, content: str, file_path: str = "workflow.yml") -> ParseResult:
        """Parse raw workflow YAML content into a structured ParseResult."""
        if not content or not content.strip():
            return ParseResult(
                workflow=None,
                errors=[
                    ParseError(
                        message="Workflow file is empty",
                        line=1,
                        column=1,
                        file_path=file_path,
                        error_code="EMPTY_WORKFLOW",
                    )
                ],
                file_path=file_path,
            )

        try:
            root_node = yaml.compose(content, Loader=yaml.SafeLoader)
        except yaml.YAMLError as exc:
            line = getattr(getattr(exc, "problem_mark", None), "line", 0) + 1
            col = getattr(getattr(exc, "problem_mark", None), "column", 0) + 1
            problem = getattr(exc, "problem", str(exc))
            return ParseResult(
                workflow=None,
                errors=[
                    ParseError(
                        message=f"YAML parsing syntax error: {problem}",
                        line=line,
                        column=col,
                        file_path=file_path,
                        error_code="YAML_SYNTAX_ERROR",
                    )
                ],
                file_path=file_path,
            )

        if root_node is None:
            return ParseResult(
                workflow=None,
                errors=[
                    ParseError(
                        message="Workflow file contains no valid YAML documents",
                        line=1,
                        column=1,
                        file_path=file_path,
                        error_code="EMPTY_WORKFLOW",
                    )
                ],
                file_path=file_path,
            )

        if not isinstance(root_node, yaml.MappingNode):
            return ParseResult(
                workflow=None,
                errors=[
                    ParseError(
                        message="Root of GitHub Actions workflow must be a mapping dictionary",
                        line=root_node.start_mark.line + 1,
                        column=root_node.start_mark.column + 1,
                        file_path=file_path,
                        error_code="NON_MAPPING_ROOT",
                    )
                ],
                file_path=file_path,
            )

        return self._build_workflow(root_node, content, file_path)

    def _build_workflow(
        self, root_node: yaml.MappingNode, raw_content: str, file_path: str
    ) -> ParseResult:
        """Build the Workflow object from the root AST MappingNode."""
        workflow_line = root_node.start_mark.line + 1
        name = ""
        triggers: dict[str, Any] = {}
        trigger_lines: dict[str, int] = {}
        workflow_permissions: Any = None
        permissions_line: int | None = None
        workflow_env: dict[str, Any] = {}
        jobs_dict: dict[str, Job] = {}

        jobs_node: yaml.MappingNode | None = None
        has_jobs_key = False

        for k_node, v_node in root_node.value:
            key_raw = k_node.value
            key_line = k_node.start_mark.line + 1

            # Check for YAML 1.1 'on' key quirk
            is_on_key = (
                key_raw == "on"
                or k_node.tag == "tag:yaml.org,2002:bool"
                or str(key_raw).lower() in ("true", "on")
            )

            if key_raw == "name":
                name_val, _ = _node_to_python(v_node)
                name = str(name_val) if name_val is not None else ""

            elif is_on_key:
                triggers, trigger_lines = self._normalize_triggers(v_node)

            elif key_raw == "permissions":
                workflow_permissions, _ = _node_to_python(v_node)
                permissions_line = key_line

            elif key_raw == "env":
                env_val, _ = _node_to_python(v_node)
                if isinstance(env_val, dict):
                    workflow_env = env_val

            elif key_raw == "jobs":
                has_jobs_key = True
                if isinstance(v_node, yaml.MappingNode):
                    jobs_node = v_node

        if not has_jobs_key:
            return ParseResult(
                workflow=None,
                errors=[
                    ParseError(
                        message="Workflow missing required 'jobs' mapping section",
                        line=workflow_line,
                        column=1,
                        file_path=file_path,
                        error_code="MISSING_JOBS",
                    )
                ],
                file_path=file_path,
            )

        if jobs_node is None:
            return ParseResult(
                workflow=None,
                errors=[
                    ParseError(
                        message="'jobs' section must be a mapping of job identifiers to job configurations",
                        line=workflow_line,
                        column=1,
                        file_path=file_path,
                        error_code="INVALID_JOBS_STRUCTURE",
                    )
                ],
                file_path=file_path,
            )

        # Parse each individual job
        for job_id_node, job_def_node in jobs_node.value:
            job_id = str(job_id_node.value)
            job_line = job_id_node.start_mark.line + 1

            if not isinstance(job_def_node, yaml.MappingNode):
                # Job definition must be a mapping
                continue

            job = self._build_job(job_id, job_line, job_def_node)
            jobs_dict[job_id] = job

        workflow = Workflow(
            name=name,
            file_path=file_path,
            triggers=triggers,
            trigger_lines=trigger_lines,
            permissions=workflow_permissions,
            permissions_line=permissions_line,
            env=workflow_env,
            jobs=jobs_dict,
            line=workflow_line,
            raw_content=raw_content,
        )

        return ParseResult(workflow=workflow, errors=[], file_path=file_path)

    def _normalize_triggers(self, v_node: yaml.Node) -> tuple[dict[str, Any], dict[str, int]]:
        """Normalise GitHub Actions 'on' triggers into a standardized mapping with line numbers."""
        triggers: dict[str, Any] = {}
        trigger_lines: dict[str, int] = {}

        if isinstance(v_node, yaml.ScalarNode):
            # Single event string: on: push or on: 'pull_request'
            event_name = str(v_node.value).strip()
            if event_name:
                triggers[event_name] = {}
                trigger_lines[event_name] = v_node.start_mark.line + 1

        elif isinstance(v_node, yaml.SequenceNode):
            # List of event strings: on: [push, pull_request]
            for item in v_node.value:
                if isinstance(item, yaml.ScalarNode):
                    event_name = str(item.value).strip()
                    if event_name:
                        triggers[event_name] = {}
                        trigger_lines[event_name] = item.start_mark.line + 1

        elif isinstance(v_node, yaml.MappingNode):
            # Detailed event configuration mapping:
            # on:
            #   push:
            #     branches: [main]
            #   workflow_dispatch:
            for ev_k_node, ev_v_node in v_node.value:
                event_name = str(ev_k_node.value).strip()
                event_line = ev_k_node.start_mark.line + 1
                ev_cfg, _ = _node_to_python(ev_v_node)
                triggers[event_name] = ev_cfg if isinstance(ev_cfg, dict) else {}
                trigger_lines[event_name] = event_line

        return triggers, trigger_lines

    def _build_job(self, job_id: str, job_line: int, job_node: yaml.MappingNode) -> Job:
        """Construct a Job object from its AST MappingNode."""
        name = job_id
        runs_on: Any = None
        runs_on_line: int | None = None
        permissions: Any = None
        permissions_line: int | None = None
        environment: Any = None
        environment_line: int | None = None
        needs: list[str] = []
        steps: list[Step] = []
        job_env: dict[str, Any] = {}
        uses: str = ""
        action_ref: ParsedUses | None = None

        for k_node, v_node in job_node.value:
            k = str(k_node.value)
            k_line = k_node.start_mark.line + 1

            if k == "name":
                n_val, _ = _node_to_python(v_node)
                if n_val is not None:
                    name = str(n_val)

            elif k == "runs-on":
                runs_on, _ = _node_to_python(v_node)
                runs_on_line = k_line

            elif k == "permissions":
                permissions, _ = _node_to_python(v_node)
                permissions_line = k_line

            elif k == "environment":
                environment, _ = _node_to_python(v_node)
                environment_line = k_line

            elif k == "needs":
                needs_val, _ = _node_to_python(v_node)
                if isinstance(needs_val, list):
                    needs = [str(item) for item in needs_val]
                elif needs_val is not None:
                    needs = [str(needs_val)]

            elif k == "env":
                env_val, _ = _node_to_python(v_node)
                if isinstance(env_val, dict):
                    job_env = env_val

            elif k == "uses":
                # Reusable workflow call at job level
                u_val, _ = _node_to_python(v_node)
                if u_val is not None:
                    uses = str(u_val)
                    action_ref = parse_uses(uses)

            elif k == "steps":
                if isinstance(v_node, yaml.SequenceNode):
                    steps = self._build_steps(v_node)

        return Job(
            id=job_id,
            name=name,
            runs_on=runs_on,
            runs_on_line=runs_on_line,
            permissions=permissions,
            permissions_line=permissions_line,
            environment=environment,
            environment_line=environment_line,
            needs=needs,
            steps=steps,
            env=job_env,
            line=job_line,
            uses=uses,
            action_ref=action_ref,
        )

    def _build_steps(self, steps_node: yaml.SequenceNode) -> list[Step]:
        """Construct Step objects from a job steps sequence AST node."""
        steps: list[Step] = []

        for idx, step_node in enumerate(steps_node.value):
            step_line = step_node.start_mark.line + 1
            if not isinstance(step_node, yaml.MappingNode):
                continue

            name = ""
            uses = ""
            run = ""
            with_params: dict[str, Any] = {}
            step_env: dict[str, Any] = {}

            for k_node, v_node in step_node.value:
                k = str(k_node.value)
                if k == "name":
                    n_val, _ = _node_to_python(v_node)
                    if n_val is not None:
                        name = str(n_val)
                elif k == "uses":
                    u_val, _ = _node_to_python(v_node)
                    if u_val is not None:
                        uses = str(u_val)
                elif k == "run":
                    r_val, _ = _node_to_python(v_node)
                    if r_val is not None:
                        run = str(r_val)
                elif k == "with":
                    w_val, _ = _node_to_python(v_node)
                    if isinstance(w_val, dict):
                        with_params = w_val
                elif k == "env":
                    e_val, _ = _node_to_python(v_node)
                    if isinstance(e_val, dict):
                        step_env = e_val

            action_ref = parse_uses(uses) if uses else None

            steps.append(
                Step(
                    name=name,
                    uses=uses,
                    run=run,
                    with_params=with_params,
                    env=step_env,
                    line=step_line,
                    action_ref=action_ref,
                    step_index=idx,
                )
            )

        return steps
