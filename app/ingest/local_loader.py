"""Local filesystem loader for discovering and safely reading GitHub Actions workflow files."""

from pathlib import Path

DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB limit


class LocalLoader:
    """Safely loads workflow definitions from local filesystem directories or single files.

    Features:
      - Symlink escape prevention (ensures resolved paths reside within the allowed directory)
      - File size limits to prevent Denial of Service via massive files
      - Extension validation (.yml and .yaml)
    """

    def __init__(self, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
        self.max_file_size = max_file_size

    def load_from_file(self, file_path: str | Path) -> str:
        """Load and return content from a single workflow file.

        Args:
            file_path: Path to the workflow file.

        Returns:
            The raw string content of the workflow file.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is not a regular file, has an invalid extension,
                        or exceeds the maximum file size.
        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Workflow file not found: {file_path}")
        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {file_path}")

        if path.suffix.lower() not in (".yml", ".yaml"):
            raise ValueError(
                f"Invalid workflow file extension '{path.suffix}'. Expected .yml or .yaml"
            )

        file_size = path.stat().st_size
        if file_size > self.max_file_size:
            raise ValueError(
                f"File size ({file_size} bytes) exceeds maximum allowed limit of {self.max_file_size} bytes: {file_path}"
            )

        return path.read_text(encoding="utf-8")

    def load_from_directory(
        self, dir_path: str | Path
    ) -> list[tuple[str, str]]:
        """Discover and load all workflow YAML files from a local directory or repository root.

        Checks:
          1. Searches inside `<dir_path>/.github/workflows/` for *.yml and *.yaml
          2. If dir_path is itself a workflows directory or contains direct workflow files,
             discovers those.
          3. Verifies that symlinks do not resolve outside the specified base directory.

        Args:
            dir_path: Base directory or repository path.

        Returns:
            List of tuples: (relative_or_normalized_path, file_content)

        Raises:
            FileNotFoundError: If dir_path does not exist.
            ValueError: If dir_path is not a directory or if a symlink escapes the base directory.
        """
        base_dir = Path(dir_path).resolve()
        if not base_dir.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")
        if not base_dir.is_dir():
            raise ValueError(f"Path is not a directory: {dir_path}")

        # Look in .github/workflows if it exists, otherwise scan the provided directory
        workflows_dir = base_dir / ".github" / "workflows"
        search_dir = workflows_dir if workflows_dir.is_dir() else base_dir

        discovered: list[tuple[str, str]] = []
        candidate_files: list[Path] = []

        # Find .yml and .yaml files
        for ext in ("*.yml", "*.yaml"):
            candidate_files.extend(search_dir.glob(ext))

        # Sort for deterministic processing order
        candidate_files.sort(key=lambda p: str(p))

        for file_path in candidate_files:
            # Validate symlink escape: the canonical resolved target must be within base_dir
            resolved_file = file_path.resolve()
            try:
                resolved_file.relative_to(base_dir)
            except ValueError as exc:
                raise ValueError(
                    f"Symlink traversal security violation: '{file_path}' points outside base directory '{base_dir}'"
                ) from exc

            # Check file size
            file_size = resolved_file.stat().st_size
            if file_size > self.max_file_size:
                raise ValueError(
                    f"File '{file_path.name}' ({file_size} bytes) exceeds maximum allowed size ({self.max_file_size} bytes)"
                )

            content = resolved_file.read_text(encoding="utf-8")
            # Present relative path for clean reporting
            try:
                rel_path = str(file_path.relative_to(base_dir)).replace("\\", "/")
            except ValueError:
                rel_path = file_path.name

            discovered.append((rel_path, content))

        return discovered

    def load(self, path: str | Path) -> list[tuple[str, str]]:
        """Convenience loader accepting either a single file or directory path."""
        p = Path(path)
        if p.is_file():
            content = self.load_from_file(p)
            return [(str(p).replace("\\", "/"), content)]
        elif p.is_dir():
            return self.load_from_directory(p)
        raise FileNotFoundError(f"Path does not exist: {path}")
