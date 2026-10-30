"""Loader for reading workflow YAML files from local directory or raw string input."""

from pathlib import Path


class LocalLoader:
    """Loads workflow files from a local file path or directory."""

    def load_from_file(self, file_path: str | Path) -> str:
        """Load content from a single workflow file.

        (Detailed implementation in Phase 1)
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Workflow file not found: {file_path}")
        return path.read_text(encoding="utf-8")

    def load_from_directory(self, dir_path: str | Path) -> list[tuple[str, str]]:
        """Load all .yml and .yaml files under .github/workflows or the given directory.

        (Detailed implementation in Phase 1)
        """
        raise NotImplementedError("LocalLoader.load_from_directory will be implemented in Phase 1.")

