"""YAML Loader with source line preservation."""

from app.parser.model import Workflow


class WorkflowLoader:
    """Safe YAML loader that maps AST nodes to their 1-indexed source line numbers."""

    def load_string(self, content: str, file_path: str = "workflow.yml") -> Workflow:
        """Parse workflow YAML string into a structured Workflow object.

        (Detailed implementation in Phase 1)
        """
        raise NotImplementedError("WorkflowLoader.load_string will be implemented in Phase 1.")

