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

    def __init__(
        self,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        allowed_root: str | Path | None = None,
    ):
        self.max_file_size = max_file_size
        self.allowed_root = Path(allowed_root).resolve() if allowed_root is not None else None

    def load_from_file(
        self, file_path: str | Path, allowed_root: str | Path | None = None
    ) -> str:
        """Load and return content from a single workflow file.

        Args:
            file_path: Path to the workflow file.
            allowed_root: Optional directory root restricting file access.

        Returns:
            The raw string content of the workflow file.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is not a regular file, has an invalid extension,
                        violates allowed root boundaries, or exceeds max file size.
        """
        root = Path(allowed_root).resolve() if allowed_root is not None else self.allowed_root
        path = Path(file_path).resolve()

        if root is not None:
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise ValueError(
                    f"Path traversal security violation: '{file_path}' resolves outside allowed root '{root}'"
                ) from exc

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
        self, dir_path: str | Path, allowed_root: str | Path | None = None
    ) -> list[tuple[str, str]]:
        """Discover and load all workflow YAML files from a local directory or repository root.

        Checks:
          1. Verifies dir_path resolves within allowed_root if configured.
          2. Searches inside `<dir_path>/.github/workflows/` for *.yml and *.yaml
          3. If dir_path is itself a workflows directory or contains direct workflow files,
             discovers those.
          4. Verifies that symlinks do not resolve outside the specified base directory or allowed root.

        Args:
            dir_path: Base directory or repository path.
            allowed_root: Optional directory root restricting search directory.

        Returns:
            List of tuples: (relative_or_normalized_path, file_content)

        Raises:
            FileNotFoundError: If dir_path does not exist.
            ValueError: If dir_path is not a directory, escapes allowed root, or if a symlink escapes.
        """
        root = Path(allowed_root).resolve() if allowed_root is not None else self.allowed_root
        base_dir = Path(dir_path).resolve()

        if root is not None:
            try:
                base_dir.relative_to(root)
            except ValueError as exc:
                raise ValueError(
                    f"Path traversal security violation: '{dir_path}' resolves outside allowed root '{root}'"
                ) from exc

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

    def load(
        self, path: str | Path, allowed_root: str | Path | None = None
    ) -> list[tuple[str, str]]:
        """Convenience loader accepting either a single file or directory path."""
        root = Path(allowed_root).resolve() if allowed_root is not None else self.allowed_root
        p = Path(path)
        if root is not None:
            try:
                p.resolve().relative_to(root)
            except ValueError as exc:
                raise ValueError(
                    f"Path traversal security violation: '{path}' resolves outside allowed root '{root}'"
                ) from exc
        if p.is_file():
            content = self.load_from_file(p, allowed_root=root)
            return [(str(p).replace("\\", "/"), content)]
        elif p.is_dir():
            return self.load_from_directory(p, allowed_root=root)
        raise FileNotFoundError(f"Path does not exist: {path}")
