"""Parser module for transforming GitHub Actions workflow YAML into structured object models."""

from pathlib import Path
from typing import Union

from app.parser.loader import WorkflowLoader, parse_uses
from app.parser.model import (
    ActionRef,
    Job,
    ParsedUses,
    ParseError,
    ParseResult,
    RefType,
    Step,
    Workflow,
)


def load_workflows(
    source: str | Path | list[str | Path],
) -> list[ParseResult]:
    """Unified entry point to ingest and parse workflows from a file, directory, or raw YAML string.

    Args:
        source: Path to file/directory, raw workflow YAML string, or list thereof.

    Returns:
        List of ParseResult objects containing valid Workflow ASTs or structured ParseErrors.
    """
    from app.ingest.local_loader import LocalLoader

    loader = WorkflowLoader()
    local_loader = LocalLoader()
    results: list[ParseResult] = []

    if isinstance(source, list):
        for item in source:
            results.extend(load_workflows(item))
        return results

    # Check if source is a filesystem path
    is_path = False
    try:
        path_obj = Path(source)
        if path_obj.exists():
            is_path = True
    except (OSError, ValueError):
        is_path = False

    if is_path:
        path_obj = Path(source)
        if path_obj.is_file():
            content = local_loader.load_from_file(path_obj)
            results.append(loader.load_string(content, file_path=str(path_obj)))
        elif path_obj.is_dir():
            discovered = local_loader.load_from_directory(path_obj)
            for fpath, content in discovered:
                results.append(loader.load_string(content, file_path=fpath))
    else:
        # Treat as raw YAML string
        results.append(loader.load_string(str(source), file_path="pasted.yml"))

    return results


__all__ = [
    "ActionRef",
    "Job",
    "ParsedUses",
    "ParseError",
    "ParseResult",
    "RefType",
    "Step",
    "Workflow",
    "WorkflowLoader",
    "load_workflows",
    "parse_uses",
]
