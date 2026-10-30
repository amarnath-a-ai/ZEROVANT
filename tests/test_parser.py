"""Tests for Workflow YAML Parser and Object Model (Phase 1)."""

from app.parser.loader import WorkflowLoader
from app.parser.model import Workflow


def test_parser_module_imports():
    """Verify parser module classes are importable."""
    loader = WorkflowLoader()
    assert loader is not None
    assert Workflow is not None

